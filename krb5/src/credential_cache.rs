mod credential;
mod file_data;
mod memory_data;

pub use self::credential::{Address, AuthData, Credential, TicketTimes};
use self::{
    file_data::{FileData, FCC_OPS},
    memory_data::{MemoryData, MCC_OPS},
};
use crate::{Conf, Context, Error, Principal};
use std::{
    env,
    slice::Iter,
    sync::{Arc, Mutex},
};

const KRB5_ENV_CCNAME: &str = "KRB5CCNAME";
const DEFCCNAME: &str = "FILE:/tmp/krb5cc_%{uid}";
const DFL_OPS: &Ops = FCC_OPS;
const OPS_LIST: [&Ops; 2] = [FCC_OPS, MCC_OPS];

#[derive(Debug)]
pub struct CredentialCache {
    ops: &'static Ops,
    data: CacheData,
}

impl CredentialCache {
    fn default_name(context: &mut Context) -> anyhow::Result<String> {
        if let Some(name) = context.os_context.default_ccname.to_owned() {
            return Ok(name);
        }
        if let Ok(name) = env::var(KRB5_ENV_CCNAME) {
            context.set_default_ccname(&name);
            return Ok(name);
        }
        let key = format!("{}.{}", Conf::LIBDEFAULTS, Conf::DEFAULT_CCACHE_NAME);
        let name = Context::expand_path_tokens(
            context
                .profile
                .get_string(&key)
                .as_deref()
                .unwrap_or(DEFCCNAME),
        )?;
        context.set_default_ccname(&name);
        Ok(name)
    }

    pub fn default(context: &mut Context) -> anyhow::Result<Arc<Mutex<Self>>> {
        let default_name = Self::default_name(context)?;
        Self::resolve(context, &default_name)
    }

    pub fn resolve(context: &mut Context, name: &str) -> anyhow::Result<Arc<Mutex<Self>>> {
        let (prefix, residual) = match name.split_once(':') {
            None => return (DFL_OPS.resolve)(context, name),
            // Use `FILE` when prefix is a drive letter
            Some((p, _)) if p.len() == 1 && p.as_bytes()[0].is_ascii_alphabetic() => ("FILE", name),
            Some((prefix, residual)) => (prefix, residual),
        };
        if let Some(ops) = OPS_LIST.iter().filter(|ops| ops.prefix == prefix).next() {
            return (ops.resolve)(context, residual);
        }
        if DFL_OPS.prefix == prefix {
            return (DFL_OPS.resolve)(context, residual);
        }
        Err(Error::KRB5_CC_UNKNOWN_TYPE)?
    }

    pub fn get_type(&self) -> &str {
        self.ops.prefix
    }

    pub fn get_name(&self) -> &str {
        self.data.name()
    }

    pub fn get_full_name(&self) -> String {
        format!("{}:{}", self.get_type(), self.get_name())
    }

    pub fn get_principal(&self, context: &mut Context) -> anyhow::Result<Principal> {
        (self.ops.get_principal)(context, self)
    }

    pub fn credentials_iter<'a>(
        &'a mut self,
        context: &mut Context,
    ) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<Credential>>>> + 'a>> {
        (self.ops.credentials_iter)(context, self)
    }

    pub fn credential_caches_iter<'a>(
        context: &'a mut Context,
    ) -> Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<CredentialCache>>>> + 'a> {
        Box::new(CredentialCachesIter {
            context,
            ops_iter: OPS_LIST.iter(),
            credential_caches_iter: None,
        })
    }
}

struct CredentialCachesIter<'a> {
    context: &'a mut Context,
    ops_iter: Iter<'a, &'static Ops>,
    credential_caches_iter:
        Option<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<CredentialCache>>>> + 'a>>,
}

impl<'a> Iterator for CredentialCachesIter<'a> {
    type Item = anyhow::Result<Arc<Mutex<CredentialCache>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.credential_caches_iter.is_none() {
            let ops = self.ops_iter.next()?;
            self.credential_caches_iter =
                (ops.credential_caches_iter)(self.context, &self.ops_iter).ok();
        }

        if let Some(item) = self.credential_caches_iter.as_mut()?.next() {
            return Some(item);
        }

        let ops = self.ops_iter.next()?;
        self.credential_caches_iter =
            (ops.credential_caches_iter)(self.context, &self.ops_iter).ok();
        self.next()
    }
}

#[derive(Debug)]
struct Ops {
    prefix: &'static str,
    resolve: fn(&mut Context, &str) -> anyhow::Result<Arc<Mutex<CredentialCache>>>,
    get_principal: fn(&mut Context, &CredentialCache) -> anyhow::Result<Principal>,
    credentials_iter: for<'a> fn(
        &mut Context,
        &'a mut CredentialCache,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<Credential>>>> + 'a>,
    >,
    credential_caches_iter: for<'a> fn(
        &mut Context,
        &Iter<'a, &Ops>,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<CredentialCache>>>> + 'a>,
    >,
}

#[derive(Debug)]
enum CacheData {
    FileData(FileData),
    MemoryData(MemoryData),
}

impl CacheData {
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
            CacheData::$data_type(data) => data,
            _ => unreachable!(),
        }
    };
}

pub(self) use downcast_data;
