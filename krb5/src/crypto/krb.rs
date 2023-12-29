pub mod enctype_util;
mod keytypes;

use self::keytypes::KEYTYPES;
use crate::{Enctype, Flags};

const MAX_ENCTYPE_ALIASES: usize = 2;
const ENCTYPE_WEAK: Flags = 1 << 0;
const ENCTYPE_DEPRECATED: Flags = 1 << 1;

pub struct Keytype {
    pub enctype: Enctype,
    pub name: &'static str,
    pub aliases: [Option<&'static str>; MAX_ENCTYPE_ALIASES],
    pub flags: Flags,
}

impl Keytype {
    pub fn find_enctype(enctype: Enctype) -> Option<&'static Self> {
        KEYTYPES.iter().filter(|ktp| ktp.enctype == enctype).next()
    }
}
