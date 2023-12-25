pub mod crypto;
pub mod error;
pub mod keytab;
pub mod krb;

use std::process::ExitCode;

pub const BUFSIZ: usize = 1024;

pub const ENCTYPE_NULL: Enctype = 0x0000;
/// @deprecated no longer supported
pub const ENCTYPE_DES_CBC_CRC: Enctype = 0x0001;
/// @deprecated no longer supported
pub const ENCTYPE_DES_CBC_MD4: Enctype = 0x0002;
/// @deprecated no longer supported
pub const ENCTYPE_DES_CBC_MD5: Enctype = 0x0003;
/// @deprecated no longer supported
pub const ENCTYPE_DES_CBC_RAW: Enctype = 0x0004;
/// @deprecated DES-3 cbc with SHA1
pub const ENCTYPE_DES3_CBC_SHA: Enctype = 0x0005;
/// @deprecated DES-3 cbc mode raw
pub const ENCTYPE_DES3_CBC_RAW: Enctype = 0x0006;
/// @deprecated no longer supported
pub const ENCTYPE_DES_HMAC_SHA1: Enctype = 0x0008;

/// DSA with SHA1, CMS signature
pub const ENCTYPE_DSA_SHA1_CMS: Enctype = 0x0009;
/// MD5 with RSA, CMS signature
pub const ENCTYPE_MD5_RSA_CMS: Enctype = 0x000a;
/// SHA1 with RSA, CMS signature
pub const ENCTYPE_SHA1_RSA_CMS: Enctype = 0x000b;
/// RC2 cbc mode, CMS enveloped data
pub const ENCTYPE_RC2_CBC_ENV: Enctype = 0x000c;
/// RSA encryption, CMS enveloped data
pub const ENCTYPE_RSA_ENV: Enctype = 0x000d;
/// RSA w/OEAP encryption, CMS enveloped data
pub const ENCTYPE_RSA_ES_OAEP_ENV: Enctype = 0x000e;
/// DES-3 cbc mode, CMS enveloped data
pub const ENCTYPE_DES3_CBC_ENV: Enctype = 0x000f;

pub const ENCTYPE_DES3_CBC_SHA1: Enctype = 0x0010;
/// RFC 3962
pub const ENCTYPE_AES128_CTS_HMAC_SHA1_96: Enctype = 0x0011;
/// RFC 3962
pub const ENCTYPE_AES256_CTS_HMAC_SHA1_96: Enctype = 0x0012;
/// RFC 8009
pub const ENCTYPE_AES128_CTS_HMAC_SHA256_128: Enctype = 0x0013;
/// RFC 8009
pub const ENCTYPE_AES256_CTS_HMAC_SHA384_192: Enctype = 0x0014;
/// RFC 4757
pub const ENCTYPE_ARCFOUR_HMAC: Enctype = 0x0017;
/// RFC 4757
pub const ENCTYPE_ARCFOUR_HMAC_EXP: Enctype = 0x0018;
/// RFC 6803
pub const ENCTYPE_CAMELLIA128_CTS_CMAC: Enctype = 0x0019;
/// RFC 6803
pub const ENCTYPE_CAMELLIA256_CTS_CMAC: Enctype = 0x001a;
pub const ENCTYPE_UNKNOWN: Enctype = 0x01ff;

type Kvno = u32;
pub type Enctype = i32;
pub type Flags = i32;
type Timestamp = u32;
pub type Data = Vec<u8>;

#[derive(Debug)]
pub struct Principal {
    pub realm: Data,
    pub components: Vec<Data>,
    pub r#type: i32,
}

#[derive(Debug)]
pub struct Keyblock {
    pub enctype: Enctype,
    pub contents: Data,
}

pub fn prefix_progname_to_error_if_needed(progname: &str, result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) if err.to_string().starts_with(&format!("Usage: {}", progname)) => {
            eprintln!("{:?}", err);
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("{}: {:?}", progname, err);
            ExitCode::FAILURE
        }
    }
}
