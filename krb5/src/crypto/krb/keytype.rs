use super::Enctype;
use crate::Flags;

const MAX_ENCTYPE_ALIASES: usize = 2;
const ENCTYPE_WEAK: Flags = 1 << 0;
const ENCTYPE_DEPRECATED: Flags = 1 << 1;

const KEYTYPES: [Keytype; 10] = [
    Keytype {
        enctype: Enctype::DES3_CBC_RAW,
        name: "des3-cbc-raw",
        aliases: [None; MAX_ENCTYPE_ALIASES],
        flags: ENCTYPE_WEAK | ENCTYPE_DEPRECATED,
    },
    Keytype {
        enctype: Enctype::DES3_CBC_SHA1,
        name: "des3-cbc-sha1",
        aliases: [Some("des3-hmac-sha1"), Some("des3-cbc-sha1-kd")],
        flags: ENCTYPE_DEPRECATED,
    },
    Keytype {
        enctype: Enctype::ARCFOUR_HMAC,
        name: "arcfour-hmac",
        aliases: [Some("rc4-hmac"), Some("arcfour-hmac-md5")],
        flags: ENCTYPE_DEPRECATED,
    },
    Keytype {
        enctype: Enctype::ARCFOUR_HMAC_EXP,
        name: "arcfour-hmac-exp",
        aliases: [Some("rc4-hmac-exp"), Some("arcfour-hmac-md5-exp")],
        flags: ENCTYPE_WEAK | ENCTYPE_DEPRECATED,
    },
    Keytype {
        enctype: Enctype::AES128_CTS_HMAC_SHA1_96,
        name: "aes128-cts-hmac-sha1-96",
        aliases: [Some("aes128-cts"), Some("aes128-sha1")],
        flags: 0,
    },
    Keytype {
        enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
        name: "aes256-cts-hmac-sha1-96",
        aliases: [Some("aes256-cts"), Some("aes256-sha1")],
        flags: 0,
    },
    Keytype {
        enctype: Enctype::CAMELLIA128_CTS_CMAC,
        name: "camellia128-cts-cmac",
        aliases: [Some("camellia128-cts"), None],
        flags: 0,
    },
    Keytype {
        enctype: Enctype::CAMELLIA256_CTS_CMAC,
        name: "camellia256-cts-cmac",
        aliases: [Some("camellia256-cts"), None],
        flags: 0,
    },
    Keytype {
        enctype: Enctype::AES128_CTS_HMAC_SHA256_128,
        name: "aes128-cts-hmac-sha256-128",
        aliases: [Some("aes128-sha2"), None],
        flags: 0,
    },
    Keytype {
        enctype: Enctype::AES256_CTS_HMAC_SHA384_192,
        name: "aes256-cts-hmac-sha384-192",
        aliases: [Some("aes256-sha2"), None],
        flags: 0,
    },
];

pub struct Keytype {
    enctype: Enctype,
    name: &'static str,
    aliases: [Option<&'static str>; MAX_ENCTYPE_ALIASES],
    flags: Flags,
}

impl Keytype {
    pub fn find_enctype(enctype: Enctype) -> Option<&'static Self> {
        KEYTYPES.iter().filter(|ktp| ktp.enctype == enctype).next()
    }

    pub fn name(&self, shortest: bool) -> &'static str {
        let mut name = self.name;
        if shortest {
            self.aliases.iter().flatten().for_each(|alias| {
                if alias.len() < name.len() {
                    name = alias
                }
            });
        }
        name
    }

    pub fn is_deprecated(&self) -> bool {
        self.flags & ENCTYPE_DEPRECATED != 0
    }
}
