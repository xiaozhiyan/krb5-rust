use super::{downcast_data, Keytab, KeytabData, KeytabEntry, Ops};
use crate::{Enctype, Error, Keyblock, NameType, Principal};
use nom::number::Endianness;
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    marker::PhantomData,
    mem::size_of,
    path::Path,
    sync::{Arc, Mutex},
};

const FILE_FIRST_BYTE: u8 = 5;

pub(super) const KTF_OPS: &Ops = &Ops {
    prefix: "FILE",
    resolve,
    entries_iter,
};

pub(super) const KTF_WRITABLE_OPS: &Ops = &Ops {
    prefix: "WRFILE",
    resolve,
    entries_iter,
};

pub(super) const DFL_OPS: &Ops = &Ops {
    prefix: "FILE",
    resolve,
    entries_iter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileFormatVersion {
    V1 = 1,
    V2,
}

impl TryFrom<u8> for FileFormatVersion {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(Error::KRB5_KEYTAB_BADVNO)?,
        }
    }
}

#[derive(Debug)]
pub(super) struct FileData {
    pub(super) name: String,
}

impl FileData {
    fn entries_iter(&mut self) -> anyhow::Result<EntriesIter> {
        let path = Path::new(&self.name);
        if !path.try_exists()? {
            Err(anyhow::anyhow!("No such file or directory"))?;
        }
        let mut reader = BufReader::new(File::open(path)?);
        let version = Self::read_version(&mut reader)?;
        Ok(EntriesIter {
            reader,
            version,
            phantom: PhantomData,
        })
    }

    // There are two versions of the file format used by the FILE keytab type.
    // The first byte of the file always has the value 5, and the value of the
    // second byte contains the version number (1 or 2).
    fn read_version(reader: &mut BufReader<File>) -> anyhow::Result<FileFormatVersion> {
        if read_u8(reader)? != Some(FILE_FIRST_BYTE) {
            Err(Error::KRB5_KEYTAB_BADVNO)?
        }
        let version = read_u8(reader)?.ok_or(Error::KRB5_KEYTAB_BADVNO)?;
        let version = FileFormatVersion::try_from(version)?;
        Ok(version)
    }

    // Version 1 of the file format uses native byte order for integer
    // representations. Version 2 always uses big-endian byte order.
    fn endianness(version: FileFormatVersion) -> Endianness {
        match version {
            FileFormatVersion::V1 => Endianness::Native,
            FileFormatVersion::V2 => Endianness::Big,
        }
    }

    // After the two-byte version indicator, the file contains a sequence of
    // signed 32-bit record lengths followed by key records or holes. A positive
    // record length indicates a valid key entry whose size is equal to or less
    // than the record length. A negative length indicates a zero-filled hole
    // whose size is the inverse of the length. A length of 0 indicates the end
    // of the file.
    //
    // A key entry may be smaller in size than the record length which precedes
    // it, because it may have replaced a hole which is larger than the key
    // entry. Key entries use the following informal grammar:
    //
    // entry ::=
    //     principal
    //     timestamp (32 bits)
    //     key version (8 bits)
    //     enctype (16 bits)
    //     key length (16 bits)
    //     key contents
    //     key version (32 bits) [in release 1.14 and later]
    // principal ::=
    //     count of components (16 bits) [includes realm in version 1]
    //     realm (data)
    //     component1 (data)
    //     component2 (data)
    //     ...
    //     name type (32 bits) [omitted in version 1]
    // data ::=
    //     length (16 bits)
    //     value (length bytes)
    //
    // The 32-bit key version overrides the 8-bit key version. To determine if
    // it is present, the implementation must check that at least 4 bytes remain
    // in the record after the other fields are read, and that the value of the
    // 32-bit integer contained in those bytes is non-zero.
    fn read_entry(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Option<KeytabEntry>> {
        let endianness = Self::endianness(version);

        let size = match read_i32(reader, endianness)? {
            Some(size) if size > 0 => size,
            Some(size) if size < 0 => {
                if size == i32::MIN {
                    Err(Error::KRB5_KT_FORMAT)?
                }
                reader.seek(SeekFrom::Current(-size as i64))?;
                return Self::read_entry(reader, version);
            }
            _ => return Ok(None),
        };

        let start_position = reader.stream_position()?;

        let principal = match Self::read_principal(reader, version)? {
            Some(principal) => principal,
            None => return Ok(None),
        };

        let timestamp = match read_u32(reader, endianness)? {
            Some(timestamp) => timestamp,
            None => return Ok(None),
        };

        let mut vno = match read_u8(reader)? {
            Some(vno) => vno as u32,
            None => return Ok(None),
        };

        let key = match Self::read_keyblock(reader, version)? {
            Some(keyblock) => keyblock,
            None => return Ok(None),
        };

        let current_position = reader.stream_position()?;
        if current_position - start_position + 4 <= size as u64 {
            let vno32 = match read_u32(reader, endianness)? {
                Some(vno32) => vno32,
                None => return Ok(None),
            };
            if vno32 != 0 {
                vno = vno32;
            }
        }

        reader.seek(SeekFrom::Start(start_position + size as u64))?;

        let entry = KeytabEntry {
            principal,
            timestamp,
            vno,
            key,
        };
        Ok(Some(entry))
    }

    fn read_principal(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Option<Principal>> {
        let endianness = Self::endianness(version);

        let component_count = match (read_u16(reader, endianness)?, version) {
            (Some(count), FileFormatVersion::V1) if count > 1 => count - 1,
            (Some(count), FileFormatVersion::V2) if count > 0 => count,
            _ => return Ok(None),
        };

        let realm = match Self::read_data(reader, endianness)? {
            Some(realm) => realm,
            None => return Ok(None),
        };

        let mut components = vec![];
        for _ in 0..component_count {
            let component = match Self::read_data(reader, endianness)? {
                Some(component) => component,
                None => return Ok(None),
            };
            components.push(component);
        }

        let name_type = match version {
            FileFormatVersion::V1 => NameType::UNKNOWN,
            FileFormatVersion::V2 => match read_i32(reader, endianness)? {
                Some(name_type) => NameType(name_type),
                None => return Ok(None),
            },
        };

        let principal = Principal {
            realm,
            components,
            name_type,
        };
        Ok(Some(principal))
    }

    fn read_keyblock(
        reader: &mut BufReader<File>,
        version: FileFormatVersion,
    ) -> anyhow::Result<Option<Keyblock>> {
        let endianness = Self::endianness(version);

        let enctype = match read_i16(reader, endianness)? {
            Some(enctype) => Enctype(enctype.into()),
            None => return Ok(None),
        };

        let contents = match Self::read_data(reader, endianness)? {
            Some(contents) => contents,
            None => return Ok(None),
        };

        let keyblock = Keyblock { enctype, contents };
        Ok(Some(keyblock))
    }

    fn read_data(
        reader: &mut BufReader<File>,
        endianness: Endianness,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let size = match read_u16(reader, endianness)? {
            Some(size) if size > 0 => size as usize,
            _ => return Ok(None),
        };
        let mut buf = vec![0; size];
        if reader.read(&mut buf)? == size {
            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }
}

struct EntriesIter<'a> {
    reader: BufReader<File>,
    version: FileFormatVersion,
    phantom: PhantomData<&'a ()>,
}

impl<'a> Iterator for EntriesIter<'a> {
    type Item = anyhow::Result<Arc<KeytabEntry>>;

    fn next(&mut self) -> Option<Self::Item> {
        FileData::read_entry(&mut self.reader, self.version)
            .map(|entry| entry.map(Arc::new))
            .transpose()
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
read_int!(read_i16, i16);
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

fn resolve(name: &str) -> anyhow::Result<Arc<Mutex<Keytab>>> {
    let data = FileData {
        name: name.to_owned(),
    };
    let keytab = Keytab {
        ops: KTF_OPS,
        data: KeytabData::FileData(data),
    };
    Ok(Arc::new(Mutex::new(keytab)))
}

fn entries_iter<'a>(
    keytab: &'a mut Keytab,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<KeytabEntry>>> + 'a>> {
    Ok(Box::new(
        downcast_data!(&mut keytab.data, FileData).entries_iter()?,
    ))
}
