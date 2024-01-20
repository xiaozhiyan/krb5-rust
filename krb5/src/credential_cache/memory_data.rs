use super::{downcast_data, CacheData, Credential, CredentialCache, Ops};
use crate::{Context, Error, Principal};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    slice::Iter,
    sync::{Arc, Mutex},
};

pub(super) const MCC_OPS: &Ops = &Ops {
    prefix: "MEMORY",
    resolve,
    get_principal,
    credentials_iter,
    credential_caches_iter,
};

static MEMORY_CACHES: Lazy<Mutex<HashMap<String, Arc<Mutex<CredentialCache>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
pub(super) struct MemoryData {
    pub(super) name: String,
    pub(super) principal: Option<Principal>,
    pub(super) time_offset: i32,
    pub(super) usec_offset: i32,
    pub(super) credentials: Vec<Arc<Mutex<Credential>>>,
}

fn resolve(context: &mut Context, name: &str) -> anyhow::Result<Arc<Mutex<CredentialCache>>> {
    let cache = MEMORY_CACHES
        .lock()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .get(name)
        .map(Arc::clone);
    let cache = match cache {
        Some(cache) => cache,
        None => {
            let cache = Arc::new(Mutex::new(create_memory_cache(name)));
            MEMORY_CACHES
                .lock()
                .map_err(|e| anyhow::anyhow!("{}", e))?
                .insert(name.to_owned(), Arc::clone(&cache));
            cache
        }
    };
    if context.sync_kdctime() && context.os_context.time_offset_valid() {
        let cache = cache.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        let data = downcast_data!(&cache.data, MemoryData);
        context.os_context.time_offset = data.time_offset;
        context.os_context.usec_offset = data.usec_offset;
        context.os_context.set_time_offset_valid();
    }
    Ok(cache)
}

fn create_memory_cache(name: &str) -> CredentialCache {
    let data = MemoryData {
        name: name.to_owned(),
        principal: None,
        time_offset: 0,
        usec_offset: 0,
        credentials: vec![],
    };
    CredentialCache {
        ops: MCC_OPS,
        data: CacheData::MemoryData(data),
    }
}

fn get_principal(_: &mut Context, cache: &CredentialCache) -> anyhow::Result<Principal> {
    let principal = downcast_data!(&cache.data, MemoryData).principal.as_ref();
    match principal {
        Some(principal) => Ok(principal.to_owned()),
        None => Err(Error::KRB5_FCC_NOFILE)?,
    }
}

fn credentials_iter<'a>(
    _: &mut Context,
    cache: &'a mut CredentialCache,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<Credential>>>> + 'a>> {
    Ok(Box::new(
        downcast_data!(&cache.data, MemoryData)
            .credentials
            .iter()
            .map(|credential| Ok(Arc::clone(credential))),
    ))
}

fn credential_caches_iter<'a>(
    context: &mut Context,
    _ops_iter: &Iter<'a, &Ops>,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<Mutex<CredentialCache>>>> + 'a>> {
    let default_name = CredentialCache::default_name(context)?;
    if !default_name.starts_with("MEMORY:") {
        return Ok(Box::new(vec![].into_iter()));
    }
    let cache = CredentialCache::resolve(context, &default_name);
    Ok(Box::new(vec![cache].into_iter()))
}
