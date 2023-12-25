use super::{downcast_data, Keytab, KeytabData, KeytabEntry, Ops};
use crate::{error::KRB5_KEYTAB_BADVNO, Keyblock, Principal, Timestamp};
use std::{
    fs::File,
    io::{BufReader, Read, Seek},
    marker::PhantomData,
    mem::size_of,
    path::Path,
    sync::{Arc, Mutex},
};

type Vno = i16;
const KRB5_KT_VNO_1: Vno = 0x0501;
const KRB5_KT_VNO: Vno = 0x0502;

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

#[derive(Debug)]
pub(super) struct FileData {
    pub(super) name: String,
    version: Vno,
}

impl FileData {
    fn entries_iter(&mut self) -> anyhow::Result<EntriesIter> {
        let path = Path::new(&self.name);
        if !path.try_exists()? {
            return Err(anyhow::anyhow!("No such file or directory"));
        }

        let mut reader = BufReader::new(File::open(path)?);
        let mut buf = [0; size_of::<Vno>()];
        if reader.read(&mut buf)? != size_of::<Vno>() {
            return Err(KRB5_KEYTAB_BADVNO)?;
        }

        self.version = Vno::from_be_bytes(buf);
        if ![KRB5_KT_VNO, KRB5_KT_VNO_1].contains(&self.version) {
            return Err(KRB5_KEYTAB_BADVNO)?;
        }

        Ok(EntriesIter {
            reader,
            version: self.version,
            phantom: PhantomData,
        })
    }
}

struct EntriesIter<'a> {
    reader: BufReader<File>,
    version: Vno,
    phantom: PhantomData<&'a ()>,
}

macro_rules! read_int {
    ($fn:ident, $type:ident) => {
        fn $fn(&mut self) -> anyhow::Result<Option<$type>> {
            let mut buf = [0; size_of::<$type>()];
            if self.reader.read(&mut buf)? != size_of::<$type>() {
                return Ok(None);
            }
            if self.version == KRB5_KT_VNO_1 {
                Ok(Some($type::from_le_bytes(buf)))
            } else {
                Ok(Some($type::from_be_bytes(buf)))
            }
        }
    };
}

impl<'a> EntriesIter<'a> {
    read_int!(read_u8, u8);
    read_int!(read_i16, i16);
    read_int!(read_i32, i32);
    read_int!(read_u32, u32);
    read_int!(read_timestamp, Timestamp);

    fn read_exact_bytes(&mut self, size: usize) -> anyhow::Result<Option<Vec<u8>>> {
        let mut buf = vec![0; size];
        if self.reader.read(&mut buf)? != size {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    fn next_entry(&mut self) -> anyhow::Result<Option<Arc<KeytabEntry>>> {
        let size = match self.read_u32()? {
            Some(size) if size > 0 => size,
            _ => return Ok(None),
        };

        let start_position = self.reader.stream_position()?;

        let component_count = match (self.read_i16()?, self.version) {
            // V1 includes the realm in the count
            (Some(count), KRB5_KT_VNO_1) if count > 1 => count - 1,
            (Some(count), KRB5_KT_VNO) if count > 0 => count,
            _ => return Ok(None),
        };

        let realm_size = match self.read_i16()? {
            Some(size) if size > 0 => size,
            _ => return Ok(None),
        };

        let realm = match self.read_exact_bytes(realm_size as usize)? {
            Some(realm) => realm,
            _ => return Ok(None),
        };

        let mut components = vec![];
        for _ in 0..component_count {
            let component_size = match self.read_i16()? {
                Some(size) if size > 0 => size,
                _ => return Ok(None),
            };
            let component = match self.read_exact_bytes(component_size as usize)? {
                Some(component) => component,
                _ => return Ok(None),
            };
            components.push(component);
        }

        let r#type = match self.version {
            KRB5_KT_VNO_1 => 0,
            _ => match self.read_i32()? {
                Some(t) => t,
                _ => return Ok(None),
            },
        };

        let principal = Principal {
            realm,
            components,
            r#type,
        };

        let timestamp = match self.read_timestamp()? {
            Some(timestamp) => timestamp,
            _ => return Ok(None),
        };

        let vno = match self.read_u8()? {
            Some(vno) => vno,
            _ => return Ok(None),
        };

        let enctype = match self.read_i16()? {
            Some(enctype) => enctype,
            _ => return Ok(None),
        };

        let key_size = match self.read_i16()? {
            Some(size) if size > 0 => size,
            _ => return Ok(None),
        };

        let key_contents = match self.read_exact_bytes(key_size as usize)? {
            Some(key_contents) => key_contents,
            _ => return Ok(None),
        };

        let key = Keyblock {
            enctype: enctype.into(),
            contents: key_contents,
        };

        let mut entry = KeytabEntry {
            principal,
            timestamp,
            vno: vno.into(),
            key,
        };

        let current_position = self.reader.stream_position()?;
        if current_position - start_position + 4 <= size as u64 {
            let vno32 = match self.read_u32()? {
                Some(vno32) => vno32,
                _ => return Ok(None),
            };
            // If the value is 0, the bytes are just zero-fill.
            if vno32 != 0 {
                entry.vno = vno32;
            }
        }

        Ok(Some(Arc::new(entry)))
    }
}

impl<'a> Iterator for EntriesIter<'a> {
    type Item = anyhow::Result<Arc<KeytabEntry>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

fn resolve(name: &str) -> anyhow::Result<Arc<Mutex<Keytab>>> {
    let data = FileData {
        name: name.to_owned(),
        version: 0,
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
