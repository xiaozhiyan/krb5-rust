use crate::{Keyblock, Principal, Timestamp};

pub type Kvno = u32;

#[derive(Debug)]
pub struct KeytabEntry {
    pub principal: Principal,
    pub timestamp: Timestamp,
    pub vno: Kvno,
    pub key: Keyblock,
}
