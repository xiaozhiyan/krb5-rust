use super::{downcast_data, Keytab, KeytabData, KeytabEntry, Ops};
use std::sync::{Arc, Mutex};

pub(super) const MKT_OPS: &Ops = &Ops {
    prefix: "MEMORY",
    resolve,
    entries_iter,
};

static MEMORY_KEYTABS: Mutex<Vec<Arc<Mutex<Keytab>>>> = Mutex::new(vec![]);

#[derive(Debug)]
pub(super) struct MemoryData {
    pub(super) name: String,
    entries: Vec<Arc<KeytabEntry>>,
}

fn resolve(name: &str) -> anyhow::Result<Arc<Mutex<Keytab>>> {
    let keytab = MEMORY_KEYTABS
        .lock()
        .unwrap()
        .iter()
        .filter(|k| k.lock().unwrap().data.name() == name)
        .next()
        .map(Arc::clone);
    let keytab = keytab.unwrap_or_else(|| {
        let keytab = Arc::new(Mutex::new(create_memory_keytab(name)));
        MEMORY_KEYTABS
            .lock()
            .unwrap()
            .insert(0, Arc::clone(&keytab));
        keytab
    });
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
