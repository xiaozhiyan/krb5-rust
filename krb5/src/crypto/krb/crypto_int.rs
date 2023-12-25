use super::etypes::ENCTYPES_LIST;
use crate::{Enctype, Flags};

pub const MAX_ETYPE_ALIASES: usize = 2;
pub const ETYPE_WEAK: Flags = 1 << 0;
pub const ETYPE_DEPRECATED: Flags = 1 << 1;

pub struct Keytypes {
    pub etype: Enctype,
    pub name: &'static str,
    pub aliases: [Option<&'static str>; MAX_ETYPE_ALIASES],
    pub flags: Flags,
}

pub fn find_enctype(enctype: Enctype) -> Option<&'static Keytypes> {
    ENCTYPES_LIST.iter().filter(|t| t.etype == enctype).next()
}
