use super::{Keytype, ENCTYPE_DEPRECATED};
use crate::{
    Enctype, ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD4, ENCTYPE_DES_CBC_MD5, ENCTYPE_DES_CBC_RAW,
    ENCTYPE_DES_HMAC_SHA1,
};

const UNSUPPORTED_ENCTYPES: [UnsupportedEnctype; 5] = [
    UnsupportedEnctype::new(ENCTYPE_DES_CBC_CRC, "des-cbc-crc"),
    UnsupportedEnctype::new(ENCTYPE_DES_CBC_MD4, "des-cbc-md4"),
    UnsupportedEnctype::new(ENCTYPE_DES_CBC_MD5, "des-cbc-md5"),
    UnsupportedEnctype::new(ENCTYPE_DES_CBC_RAW, "des-cbc-raw"),
    UnsupportedEnctype::new(ENCTYPE_DES_HMAC_SHA1, "des-hmac-sha1"),
];

struct UnsupportedEnctype {
    enctype: Enctype,
    name: &'static str,
}

impl UnsupportedEnctype {
    const fn new(enctype: Enctype, name: &'static str) -> Self {
        Self { enctype, name }
    }
}

pub fn deprecated_enctype(enctype: Enctype) -> bool {
    match Keytype::find_enctype(enctype) {
        Some(keytype) => keytype.flags & ENCTYPE_DEPRECATED != 0,
        None => true,
    }
}

pub fn enctype_to_name(enctype: Enctype, shortest: bool) -> anyhow::Result<&'static str> {
    if let Some(enctype) = UNSUPPORTED_ENCTYPES
        .iter()
        .filter(|e| e.enctype == enctype)
        .next()
    {
        return Ok(enctype.name);
    }

    let keytype = Keytype::find_enctype(enctype)
        .ok_or_else(|| anyhow::anyhow!("Invalid enctype: {}", enctype))?;
    let mut name = keytype.name;

    if shortest {
        keytype.aliases.iter().flatten().for_each(|alias| {
            if alias.len() < name.len() {
                name = alias
            }
        });
    }

    Ok(name)
}
