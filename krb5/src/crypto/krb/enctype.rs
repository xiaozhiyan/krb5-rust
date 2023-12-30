use super::keytype::Keytype;

macro_rules! unsupported_enctype {
    ($enctype:ident, $name:expr) => {
        UnsupportedEnctype {
            enctype: Enctype::$enctype,
            name: $name,
        }
    };
}

const UNSUPPORTED_ENCTYPES: [UnsupportedEnctype; 5] = [
    unsupported_enctype!(DES_CBC_CRC, "des-cbc-crc"),
    unsupported_enctype!(DES_CBC_MD4, "des-cbc-md4"),
    unsupported_enctype!(DES_CBC_MD5, "des-cbc-md5"),
    unsupported_enctype!(DES_CBC_RAW, "des-cbc-raw"),
    unsupported_enctype!(DES_HMAC_SHA1, "des-hmac-sha1"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enctype(pub i32);

macro_rules! enctype {
    ($enctype:ident, $int:expr) => {
        pub const $enctype: Enctype = Enctype($int);
    };
}

impl Enctype {
    enctype!(NULL, 0x0000);
    // @deprecated no longer supported
    enctype!(DES_CBC_CRC, 0x0001);
    // @deprecated no longer supported
    enctype!(DES_CBC_MD4, 0x0002);
    // @deprecated no longer supported
    enctype!(DES_CBC_MD5, 0x0003);
    // @deprecated no longer supported
    enctype!(DES_CBC_RAW, 0x0004);
    // @deprecated DES-3 cbc with SHA1
    enctype!(DES3_CBC_SHA, 0x0005);
    // @deprecated DES-3 cbc mode raw
    enctype!(DES3_CBC_RAW, 0x0006);
    // @deprecated no longer supported
    enctype!(DES_HMAC_SHA1, 0x0008);

    // DSA with SHA1, CMS signature
    enctype!(DSA_SHA1_CMS, 0x0009);
    // MD5 with RSA, CMS signature
    enctype!(MD5_RSA_CMS, 0x000a);
    // SHA1 with RSA, CMS signature
    enctype!(SHA1_RSA_CMS, 0x000b);
    // RC2 cbc mode, CMS enveloped data
    enctype!(RC2_CBC_ENV, 0x000c);
    // RSA encryption, CMS enveloped data
    enctype!(RSA_ENV, 0x000d);
    // RSA w/OEAP encryption, CMS enveloped data
    enctype!(RSA_ES_OAEP_ENV, 0x000e);
    // DES-3 cbc mode, CMS enveloped data
    enctype!(DES3_CBC_ENV, 0x000f);

    enctype!(DES3_CBC_SHA1, 0x0010);
    // RFC 3962
    enctype!(AES128_CTS_HMAC_SHA1_96, 0x0011);
    // RFC 3962
    enctype!(AES256_CTS_HMAC_SHA1_96, 0x0012);
    // RFC 8009
    enctype!(AES128_CTS_HMAC_SHA256_128, 0x0013);
    // RFC 8009
    enctype!(AES256_CTS_HMAC_SHA384_192, 0x0014);
    // RFC 4757
    enctype!(ARCFOUR_HMAC, 0x0017);
    // RFC 4757
    enctype!(ARCFOUR_HMAC_EXP, 0x0018);
    // RFC 6803
    enctype!(CAMELLIA128_CTS_CMAC, 0x0019);
    // RFC 6803
    enctype!(CAMELLIA256_CTS_CMAC, 0x001a);
    enctype!(UNKNOWN, 0x01ff);

    pub fn is_deprecated(self) -> bool {
        Keytype::find_enctype(self)
            .map(|keytype| keytype.is_deprecated())
            .unwrap_or(true)
    }

    pub fn name(self, shortest: bool) -> anyhow::Result<&'static str> {
        UnsupportedEnctype::find_name(self)
            .or_else(|| Keytype::find_enctype(self).map(|keytype| keytype.name(shortest)))
            .ok_or_else(|| anyhow::anyhow!("Invalid enctype: {}", self.0))
    }

    pub fn deprecated_name(self, shortest: bool) -> anyhow::Result<String> {
        let name = self.name(shortest)?;
        if self.is_deprecated() {
            Ok(format!("DEPRECATED:{}", name))
        } else {
            Ok(name.to_owned())
        }
    }
}

struct UnsupportedEnctype {
    enctype: Enctype,
    name: &'static str,
}

impl UnsupportedEnctype {
    fn find_name(enctype: Enctype) -> Option<&'static str> {
        UNSUPPORTED_ENCTYPES
            .iter()
            .filter(|e| e.enctype == enctype)
            .next()
            .map(|e| e.name)
    }
}
