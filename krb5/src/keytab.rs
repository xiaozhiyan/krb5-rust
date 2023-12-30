mod file_data;
mod keytab_entry;
mod memory_data;

pub use self::keytab_entry::{KeytabEntry, Kvno};
use self::{
    file_data::{FileData, DFL_OPS, KTF_OPS, KTF_WRITABLE_OPS},
    memory_data::{MemoryData, MKT_OPS},
};
use crate::Error;
use std::sync::{Arc, Mutex};

const OPS_LIST: [&Ops; 3] = [KTF_OPS, KTF_WRITABLE_OPS, MKT_OPS];

#[derive(Debug)]
pub struct Keytab {
    ops: &'static Ops,
    data: KeytabData,
}

impl Keytab {
    pub fn client_default_name() -> anyhow::Result<String> {
        // TODO
        todo!("Keytab::client_default_name")
    }

    pub fn default_name() -> anyhow::Result<String> {
        // TODO
        todo!("Keytab::default_name")
    }

    pub fn client_default() -> anyhow::Result<Arc<Mutex<Self>>> {
        Self::resolve(&Self::client_default_name()?)
    }

    pub fn default() -> anyhow::Result<Arc<Mutex<Self>>> {
        Self::resolve(&Self::default_name()?)
    }

    pub fn resolve(name: &str) -> anyhow::Result<Arc<Mutex<Self>>> {
        let (prefix, real_name) = match name.split_once(':') {
            None => return (DFL_OPS.resolve)(name),
            // Use `FILE` when prefix is a drive letter
            Some((p, _)) if p.len() == 1 && p.as_bytes()[0].is_ascii_alphabetic() => ("FILE", name),
            Some(_) if name.starts_with('/') => ("FILE", name),
            Some((prefix, real_name)) => (prefix, real_name),
        };
        match OPS_LIST.iter().filter(|ops| ops.prefix == prefix).next() {
            Some(ops) => (ops.resolve)(real_name),
            None => Err(Error::KRB5_KT_UNKNOWN_TYPE)?,
        }
    }

    pub fn get_name(&self, length: usize) -> anyhow::Result<String> {
        match format!("{}:{}", self.ops.prefix, self.data.name()) {
            name if name.len() > length => Err(Error::KRB5_KT_NAME_TOOLONG)?,
            name => Ok(name),
        }
    }

    pub fn entries_iter<'a>(
        &'a mut self,
    ) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<KeytabEntry>>> + 'a>> {
        (self.ops.entries_iter)(self)
    }
}

#[derive(Debug)]
struct Ops {
    prefix: &'static str,
    resolve: fn(&str) -> anyhow::Result<Arc<Mutex<Keytab>>>,
    entries_iter: for<'a> fn(
        &'a mut Keytab,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<Arc<KeytabEntry>>> + 'a>,
    >,
}

#[derive(Debug)]
enum KeytabData {
    FileData(FileData),
    MemoryData(MemoryData),
}

impl KeytabData {
    fn name(&self) -> &str {
        match self {
            Self::FileData(data) => &data.name,
            Self::MemoryData(data) => &data.name,
        }
    }
}

macro_rules! downcast_data {
    ($data:expr, $data_type:ident) => {
        match $data {
            KeytabData::$data_type(data) => data,
            _ => unreachable!(),
        }
    };
}

pub(self) use downcast_data;
