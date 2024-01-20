use super::{
    downcast_data, Address, AuthData, CacheData, Credential, CredentialCache, Ops, TicketTimes,
};
use crate::{Context, Enctype, Error, Keyblock, NameType, Principal};
use nom::number::Endianness;
use std::{
    fs::File,
    io::{BufReader, Read},
    marker::PhantomData,
    mem::size_of,
    path::Path,
    slice::Iter,
    sync::{Arc, Mutex},
};

const FILE_FIRST_BYTE: u8 = 5;
const FCC_TAG_DELTATIME: u16 = 1;

pub(super) const FCC_OPS: &Ops = &Ops {
    prefix: "FILE",
    resolve,
    get_principal,
    credentials_iter,
    credential_caches_iter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileFormatVersion {
    V1 = 1,
    V2,
    V3,
    V4,
}

impl TryFrom<u8> for FileFormatVersion {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            _ => Err(Error::KRB5_CCACHE_BADVNO)?,
        }
    }
}

#[derive(Debug)]
pub(super) struct FileData {
    pub(super) name: String,
}

impl FileData {
    fn credentials_iter(&mut self, context: &mut Context) -> anyhow::Result<CredentialsIter> {
        let path = Path::new(&self.name);
        let mut reader = BufReader::new(File::open(path)?);
        let (version, _) = Self::read_up_to_principal(context, &mut reader)?;
        Ok(CredentialsIter {
            reader,
            version,
            phantom: PhantomData,
        })
    }

    // There are four versions of the file format used by the FILE credential
    // cache type.
    // The first byte of the file always has the value 5, and the value of the
    // second byte contains the version number (1 through 4).
    fn read_version(reader: &mut BufReader<File>) -> anyhow::Result<FileFormatVersion> {
        if read_u8(reader)? != Some(FILE_FIRST_BYTE) {
            Err(Error::KRB5_CC_FORMAT)?
        }
        let version = read_u8(reader)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let version = FileFormatVersion::try_from(version)?;
        Ok(version)
    }

    // Versions 1 and 2 of the file format use native byte order for integer
    // representations.
    // Versions 3 and 4 always use big-endian byte order.
    fn endianness(version: FileFormatVersion) -> Endianness {
        match version {
            FileFormatVersion::V1 | FileFormatVersion::V2 => Endianness::Native,
            FileFormatVersion::V3 | FileFormatVersion::V4 => Endianness::Big,
        }
    }

    // After the two-byte version indicator, the file has three parts:
    // - the header (in version 4 only),
    // - the default principal name,
    // - and a sequence of credentials.
    fn read_up_to_principal(
        context: &mut Context,
        reader: &mut BufReader<File>,
    ) -> anyhow::Result<(FileFormatVersion, Option<Principal>)> {
        let version = Self::read_version(reader)?;
        if version == FileFormatVersion::V4 {
            Self::read_header(context, reader, Self::endianness(version))?;
        }
        let principal = Self::read_principal(reader, version)?;
        Ok((version, principal))
    }

    // The header appears only in format version 4.
    // It begins with a 16-bit integer giving the length of the entire header,
    // followed by a sequence of fields.
    // Each field consists of a 16-bit tag, a 16-bit length, and a value of the
    // given length.
    // A file format implementation should ignore fields with unknown tags.
    //
    // At this time there is only one defined header field.
    // Its tag value is 1, its length is always 8, and its contents are two
    // 32-bit integers giving the seconds and microseconds of the time offset of
    // the KDC relative to the client.
    // Adding this offset to the current time on the client should give the
    // current time on the KDC, if that offset has not changed since the initial
    // authentication.
    fn read_header(
        context: &mut Context,
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<()> {
        let mut header_size = read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        while header_size > 0 {
            if header_size < 4 {
                Err(Error::KRB5_CC_FORMAT)?
            }
            let tag = read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            let field_size = match read_u16(reader, endianness)? {
                Some(field_size) if field_size <= header_size - 4 => field_size,
                _ => Err(Error::KRB5_CC_FORMAT)?,
            };
            match tag {
                FCC_TAG_DELTATIME => {
                    if field_size != 8 {
                        Err(Error::KRB5_CC_FORMAT)?
                    }
                    let time_offset = read_i32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
                    let usec_offset = read_i32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
                    if context.sync_kdctime() && !context.os_context.time_offset_valid() {
                        context.os_context.time_offset = time_offset;
                        context.os_context.usec_offset = usec_offset;
                        context.os_context.set_time_offset_valid();
                    }
                }
                _ => {
                    reader.seek_relative(field_size.into())?;
                }
            }
            header_size -= 4 + field_size;
        }
        Ok(())
    }

    // The default principal is marshalled using the following informal grammar:
    //
    // principal ::=
    //     name type (32 bits) [omitted in version 1]
    //     count of components (32 bits) [includes realm in version 1]
    //     realm (data)
    //     component1 (data)
    //     component2 (data)
    //     ...
    // data ::=
    //     length (32 bits)
    //     value (length bytes)
    //
    // There is no external framing on the default principal, so it must be
    // parsed according to the above grammar in order to find the sequence of
    // credentials which follows.
    fn read_principal(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Option<Principal>> {
        let endianness = Self::endianness(version);

        let name_type = if version == FileFormatVersion::V1 {
            NameType::UNKNOWN
        } else {
            match read_i32(reader, endianness)? {
                Some(name_type) => NameType(name_type),
                None => return Ok(None),
            }
        };

        let mut component_count = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        if version == FileFormatVersion::V1 {
            component_count -= 1;
        }

        let realm = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;

        let mut components = vec![];
        for _ in 0..component_count {
            let component = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            components.push(component);
        }

        let principal = Principal {
            realm,
            components,
            name_type,
        };
        Ok(Some(principal))
    }

    fn read_data(
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let size = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)? as usize;
        let mut buf = vec![0; size];
        if reader.read(&mut buf)? == size {
            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }

    // The credential format uses the following informal grammar (referencing
    // the principal and data types from the previous section):
    //
    // credential ::=
    //     client (principal)
    //     server (principal)
    //     keyblock (keyblock)
    //     authtime (32 bits)
    //     starttime (32 bits)
    //     endtime (32 bits)
    //     renew_till (32 bits)
    //     is_skey (1 byte, 0 or 1)
    //     ticket_flags (32 bits)
    //     addresses (addresses)
    //     authdata (authdata)
    //     ticket (data)
    //     second_ticket (data)
    // keyblock ::=
    //     enctype (16 bits) [repeated twice in version 3]
    //     data
    // addresses ::=
    //     count (32 bits)
    //     address1
    //     address2
    //     ...
    // address ::=
    //     addrtype (16 bits)
    //     data
    // authdata ::=
    //     count (32 bits)
    //     authdata1
    //     authdata2
    //     ...
    // authdata ::=
    //     ad_type (16 bits)
    //     data
    //
    // There is no external framing on a marshalled credential, so it must be
    // parsed according to the above grammar in order to find the next
    // credential. There is also no count of credentials or marker at the end of
    // the sequence of credentials; the sequence ends when the file ends.
    fn read_credential(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Option<Credential>> {
        let endianness = Self::endianness(version);

        let client = match Self::read_principal(reader, version)? {
            Some(principal) => principal,
            None => return Ok(None),
        };

        let server = match Self::read_principal(reader, version)? {
            Some(principal) => principal,
            None => return Ok(None),
        };

        let keyblock = Self::read_keyblock(reader, version)?;

        let times = Self::read_ticket_times(reader, endianness)?;

        let is_skey = read_u8(reader)?.ok_or(Error::KRB5_CC_FORMAT)? > 0;

        let ticket_flags = read_i32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;

        let addresses = Self::read_addresses(reader, endianness)?;

        let authdata = Self::read_authdata(reader, endianness)?;

        let ticket = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;

        let second_ticket = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;

        let credential = Credential {
            client,
            server,
            keyblock,
            times,
            is_skey,
            ticket_flags,
            addresses,
            ticket,
            second_ticket,
            authdata,
        };
        Ok(Some(credential))
    }

    fn read_keyblock(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Keyblock> {
        let endianness = Self::endianness(version);
        let enctype = Enctype(read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)? as i32);
        if version == FileFormatVersion::V3 {
            read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        }
        let contents = FileData::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let keyblock = Keyblock { enctype, contents };
        Ok(keyblock)
    }

    fn read_ticket_times(
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<TicketTimes> {
        let authtime = read_i32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let starttime = read_i32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let endtime = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let renew_till = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let ticket_times = TicketTimes {
            authtime,
            starttime,
            endtime,
            renew_till,
        };
        Ok(ticket_times)
    }

    fn read_addresses(
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<Vec<Address>> {
        let count = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let mut addresses = vec![];
        for _ in 0..count {
            let addrtype = read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            let contents = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            let address = Address { addrtype, contents };
            addresses.push(address);
        }
        Ok(addresses)
    }

    fn read_authdata(
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<Vec<AuthData>> {
        let count = read_u32(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
        let mut authdata = vec![];
        for _ in 0..count {
            let ad_type = read_u16(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            let contents = Self::read_data(reader, endianness)?.ok_or(Error::KRB5_CC_FORMAT)?;
            let data = AuthData { ad_type, contents };
            authdata.push(data);
        }
        Ok(authdata)
    }
}

struct CredentialsIter<'a> {
    reader: BufReader<File>,
    version: FileFormatVersion,
    phantom: PhantomData<&'a ()>,
}

impl<'a> CredentialsIter<'a> {
    fn next_entry(&mut self) -> anyhow::Result<Option<Arc<Mutex<Credential>>>> {
        let credential = match FileData::read_credential(&mut self.reader, self.version)? {
            Some(credential) => credential,
            None => return Ok(None),
        };
        if credential.is_removed() {
            self.next_entry()
        } else {
            Ok(Some(Arc::new(Mutex::new(credential))))
        }
    }
}

impl<'a> Iterator for CredentialsIter<'a> {
    type Item = anyhow::Result<Arc<Mutex<Credential>>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

macro_rules! read_int {
    ($fn:ident, $type:ident) => {
        fn $fn(
            reader: &mut BufReader<File>,
            endianness: Endianness,
        ) -> anyhow::Result<Option<$type>> {
            let mut buf = [0; size_of::<$type>()];
            if reader.read(&mut buf)? != size_of::<$type>() {
                return Ok(None);
            }
            match endianness {
                Endianness::Big => Ok(Some($type::from_be_bytes(buf))),
                Endianness::Little => Ok(Some($type::from_le_bytes(buf))),
                Endianness::Native => Ok(Some($type::from_ne_bytes(buf))),
            }
        }
    };
}

read_int!(read_u16, u16);
read_int!(read_u32, u32);
read_int!(read_i32, i32);

fn read_u8(reader: &mut BufReader<File>) -> anyhow::Result<Option<u8>> {
    let mut buf = [0];
    if reader.read(&mut buf)? == 1 {
        Ok(Some(buf[0]))
    } else {
        Ok(None)
    }
}

fn resolve(_: &mut Context, name: &str) -> anyhow::Result<Arc<Mutex<CredentialCache>>> {
    let data = FileData {
        name: name.to_owned(),
    };
    let cache = CredentialCache {
        ops: FCC_OPS,
        data: CacheData::FileData(data),
    };
    Ok(Arc::new(Mutex::new(cache)))
}

fn get_principal(context: &mut Context, cache: &CredentialCache) -> anyhow::Result<Principal> {
    let path = Path::new(&downcast_data!(&cache.data, FileData).name);
    let mut reader = BufReader::new(File::open(path)?);
    let (_, principal) = FileData::read_up_to_principal(context, &mut reader)?;
    Ok(principal.ok_or(Error::KRB5_CC_FORMAT)?)
}

fn credentials_iter<'a>(
    context: &mut Context,
    cache: &'a mut CredentialCache,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<Credential>>>> + 'a>> {
    Ok(Box::new(
        downcast_data!(&mut cache.data, FileData).credentials_iter(context)?,
    ))
}

fn credential_caches_iter<'a>(
    context: &mut Context,
    _ops_iter: &Iter<'a, &Ops>,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<CredentialCache>>>> + 'a>> {
    let default_name = CredentialCache::default_name(context)?;
    let residual = if default_name.starts_with("FILE:") {
        &default_name[5..]
    } else if default_name.find(':').unwrap_or(0) < 2 {
        &default_name
    } else {
        return Ok(Box::new(vec![].into_iter()));
    };
    let path = Path::new(residual);
    if !path.try_exists()? {
        return Ok(Box::new(vec![].into_iter()));
    }
    let cache = CredentialCache::resolve(context, residual);
    Ok(Box::new(vec![cache].into_iter()))
}
