mod file_data;
mod keytab_entry;
mod memory_data;

pub use self::keytab_entry::{KeytabEntry, Kvno};
use self::{
    file_data::{FileData, DFL_OPS, KTF_OPS, KTF_WRITABLE_OPS},
    memory_data::{MemoryData, MKT_OPS},
};
use crate::{Conf, Context, Error};
use std::{
    env,
    sync::{Arc, Mutex},
};

const DEFKTNAME: &str = "FILE:/etc/krb5.keytab";
const DEFCKTNAME: &str = "FILE:/usr/local/var/krb5/user/%{euid}/client.keytab";
const OPS_LIST: [&Ops; 3] = [KTF_OPS, KTF_WRITABLE_OPS, MKT_OPS];

#[derive(Debug)]
pub struct Keytab {
    ops: &'static Ops,
    data: KeytabData,
}

impl Keytab {
    pub fn client_default_name(context: &Context) -> anyhow::Result<String> {
        match (context.profile_secure, env::var("KRB5_CLIENT_KTNAME")) {
            (false, Ok(name)) => return Ok(name),
            _ => (),
        }
        let name = context
            .profile
            .get_string(&format!(
                "{}.{}",
                Conf::LIBDEFAULTS,
                Conf::DEFAULT_CLIENT_KEYTAB_NAME
            ))
            .unwrap_or(DEFCKTNAME.to_owned());
        let name = Context::expand_path_tokens(&name)?;
        Ok(name)
    }

    pub fn default_name(context: &Context) -> anyhow::Result<String> {
        match (context.profile_secure, env::var("KRB5_KTNAME")) {
            (false, Ok(name)) => return Ok(name),
            _ => (),
        }
        let name = context
            .profile
            .get_string(&format!(
                "{}.{}",
                Conf::LIBDEFAULTS,
                Conf::DEFAULT_KEYTAB_NAME
            ))
            .unwrap_or(DEFKTNAME.to_owned());
        let name = Context::expand_path_tokens(&name)?;
        Ok(name)
    }

    pub fn client_default(context: &Context) -> anyhow::Result<Arc<Mutex<Self>>> {
        Self::resolve(&Self::client_default_name(context)?)
    }

    pub fn default(context: &Context) -> anyhow::Result<Arc<Mutex<Self>>> {
        Self::resolve(&Self::default_name(context)?)
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
