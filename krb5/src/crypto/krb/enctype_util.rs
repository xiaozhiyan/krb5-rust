use super::crypto_int::{find_enctype, ETYPE_DEPRECATED, MAX_ETYPE_ALIASES};
use crate::{
    Enctype, ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD4, ENCTYPE_DES_CBC_MD5, ENCTYPE_DES_CBC_RAW,
    ENCTYPE_DES_HMAC_SHA1,
};

const UNSUPPORTED_ETYPES: [UnsupportedEtype; 5] = [
    UnsupportedEtype::new(ENCTYPE_DES_CBC_CRC, "des-cbc-crc"),
    UnsupportedEtype::new(ENCTYPE_DES_CBC_MD4, "des-cbc-md4"),
    UnsupportedEtype::new(ENCTYPE_DES_CBC_MD5, "des-cbc-md5"),
    UnsupportedEtype::new(ENCTYPE_DES_CBC_RAW, "des-cbc-raw"),
    UnsupportedEtype::new(ENCTYPE_DES_HMAC_SHA1, "des-hmac-sha1"),
];

struct UnsupportedEtype {
    etype: Enctype,
    name: &'static str,
}

impl UnsupportedEtype {
    const fn new(etype: Enctype, name: &'static str) -> Self {
        Self { etype, name }
    }
}

pub fn deprecated_enctype(enctype: Enctype) -> bool {
    match find_enctype(enctype) {
        Some(ktp) => ktp.flags & ETYPE_DEPRECATED != 0,
        None => true,
    }
}

pub fn enctype_to_name(enctype: Enctype, shortest: bool) -> anyhow::Result<&'static str> {
    if let Some(etype) = UNSUPPORTED_ETYPES
        .iter()
        .filter(|e| e.etype == enctype)
        .next()
    {
        return Ok(etype.name);
    }

    let ktp = match find_enctype(enctype) {
        Some(ktp) => ktp,
        None => return Err(anyhow::anyhow!("Invalid enctype: {}", enctype)),
    };
    let mut name = ktp.name;

    if shortest {
        for i in 0..MAX_ETYPE_ALIASES {
            match ktp.aliases[i] {
                Some(alias) if alias.len() < name.len() => name = alias,
                _ => (),
            }
        }
    }

    Ok(name)
}
