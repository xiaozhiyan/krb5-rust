use super::crypto_int::{Keytypes, ETYPE_DEPRECATED, ETYPE_WEAK, MAX_ETYPE_ALIASES};
use crate::{
    ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA256_128,
    ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES256_CTS_HMAC_SHA384_192, ENCTYPE_ARCFOUR_HMAC,
    ENCTYPE_ARCFOUR_HMAC_EXP, ENCTYPE_CAMELLIA128_CTS_CMAC, ENCTYPE_CAMELLIA256_CTS_CMAC,
    ENCTYPE_DES3_CBC_RAW, ENCTYPE_DES3_CBC_SHA1,
};

pub const ENCTYPES_LIST: [Keytypes; 10] = [
    Keytypes {
        etype: ENCTYPE_DES3_CBC_RAW,
        name: "des3-cbc-raw",
        aliases: [None; MAX_ETYPE_ALIASES],
        flags: ETYPE_WEAK | ETYPE_DEPRECATED,
    },
    Keytypes {
        etype: ENCTYPE_DES3_CBC_SHA1,
        name: "des3-cbc-sha1",
        aliases: [Some("des3-hmac-sha1"), Some("des3-cbc-sha1-kd")],
        flags: ETYPE_DEPRECATED,
    },
    Keytypes {
        etype: ENCTYPE_ARCFOUR_HMAC,
        name: "arcfour-hmac",
        aliases: [Some("rc4-hmac"), Some("arcfour-hmac-md5")],
        flags: ETYPE_DEPRECATED,
    },
    Keytypes {
        etype: ENCTYPE_ARCFOUR_HMAC_EXP,
        name: "arcfour-hmac-exp",
        aliases: [Some("rc4-hmac-exp"), Some("arcfour-hmac-md5-exp")],
        flags: ETYPE_WEAK | ETYPE_DEPRECATED,
    },
    Keytypes {
        etype: ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        name: "aes128-cts-hmac-sha1-96",
        aliases: [Some("aes128-cts"), Some("aes128-sha1")],
        flags: 0,
    },
    Keytypes {
        etype: ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        name: "aes256-cts-hmac-sha1-96",
        aliases: [Some("aes256-cts"), Some("aes256-sha1")],
        flags: 0,
    },
    Keytypes {
        etype: ENCTYPE_CAMELLIA128_CTS_CMAC,
        name: "camellia128-cts-cmac",
        aliases: [Some("camellia128-cts"), None],
        flags: 0,
    },
    Keytypes {
        etype: ENCTYPE_CAMELLIA256_CTS_CMAC,
        name: "camellia256-cts-cmac",
        aliases: [Some("camellia256-cts"), None],
        flags: 0,
    },
    Keytypes {
        etype: ENCTYPE_AES128_CTS_HMAC_SHA256_128,
        name: "aes128-cts-hmac-sha256-128",
        aliases: [Some("aes128-sha2"), None],
        flags: 0,
    },
    Keytypes {
        etype: ENCTYPE_AES256_CTS_HMAC_SHA384_192,
        name: "aes256-cts-hmac-sha384-192",
        aliases: [Some("aes256-sha2"), None],
        flags: 0,
    },
];
