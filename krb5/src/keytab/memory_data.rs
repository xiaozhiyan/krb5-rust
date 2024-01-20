use super::{downcast_data, Keytab, KeytabData, KeytabEntry, Ops};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub(super) const MKT_OPS: &Ops = &Ops {
    prefix: "MEMORY",
    resolve,
    entries_iter,
};

static MEMORY_KEYTABS: Lazy<Mutex<HashMap<String, Arc<Mutex<Keytab>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
pub(super) struct MemoryData {
    pub(super) name: String,
    entries: Vec<Arc<KeytabEntry>>,
}

fn resolve(name: &str) -> anyhow::Result<Arc<Mutex<Keytab>>> {
    let keytab = MEMORY_KEYTABS
        .lock()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .get(name)
        .map(Arc::clone);
    let keytab = match keytab {
        Some(keytab) => keytab,
        None => {
            let keytab = Arc::new(Mutex::new(create_memory_keytab(name)));
            MEMORY_KEYTABS
                .lock()
                .map_err(|e| anyhow::anyhow!("{}", e))?
                .insert(name.to_owned(), Arc::clone(&keytab));
            keytab
        }
    };
    Ok(keytab)
}

fn create_memory_keytab(name: &str) -> Keytab {
    let data = MemoryData {
        name: name.to_owned(),
        entries: vec![],
    };
    Keytab {
        ops: MKT_OPS,
        data: KeytabData::MemoryData(data),
    }
}

fn entries_iter<'a>(
    keytab: &'a mut Keytab,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Arc<KeytabEntry>>> + 'a>> {
    Ok(Box::new(
        downcast_data!(&keytab.data, MemoryData)
            .entries
            .iter()
            .map(|entry| Ok(Arc::clone(entry))),
    ))
}
