mod profile;

use self::profile::Profile;
use crate::{Error, Flags};
use nix::unistd::{Uid, User};

const DEFAULT_CLOCKSKEW: i32 = 300;
const KDC_OPT_RENEWABLE_OK: Flags = 0x00000010;
const DEFAULT_CCACHE_TYPE: i32 = 4;
const DEFAULT_KDC_TIMESYNC: i32 = 1;
const KRB5_LIBOPT_SYNC_KDCTIME: Flags = 0x0001;
const KRB5_OS_TOFFSET_VALID: Flags = 1;
const KRB5_OS_TOFFSET_TIME: Flags = 2;

#[derive(Debug)]
pub enum DnsCanonicalizeHostname {
    False,
    True,
    Fallback,
}

pub struct Conf;

macro_rules! conf {
    ($name:ident, $value:expr) => {
        pub const $name: &'static str = $value;
    };
}

impl Conf {
    conf!(ALLOW_DES3, "allow_des3");
    conf!(ALLOW_RC4, "allow_rc4");
    conf!(ALLOW_WEAK_CRYPTO, "allow_weak_crypto");
    conf!(CCACHE_TYPE, "ccache_type");
    conf!(CLOCKSKEW, "clockskew");
    conf!(DEFAULT_CCACHE_NAME, "default_ccache_name");
    conf!(DEFAULT_CLIENT_KEYTAB_NAME, "default_client_keytab_name");
    conf!(DEFAULT_KEYTAB_NAME, "default_keytab_name");
    conf!(DNS_CANONICALIZE_HOSTNAME, "dns_canonicalize_hostname");
    conf!(ENFORCE_OK_AS_DELEGATE, "enforce_ok_as_delegate");
    conf!(IGNORE_ACCEPTOR_HOSTNAME, "ignore_acceptor_hostname");
    conf!(KDC_DEFAULT_OPTIONS, "kdc_default_options");
    conf!(KDC_TIMESYNC, "kdc_timesync");
    conf!(LIBDEFAULTS, "libdefaults");
    conf!(REQUEST_TIMEOUT, "request_timeout");
}

#[derive(Debug)]
pub struct Context {
    pub os_context: OsContext,
    pub profile: Profile,
    pub clockskew: i32,
    pub req_timeout: i32,
    pub kdc_default_options: Flags,
    pub library_options: Flags,
    pub profile_secure: bool,
    pub fcc_default_format: i32,
    pub prompt_types: i32,
    pub udp_pref_limit: i32,
    pub use_conf_ktypes: bool,
    pub allow_weak_crypto: bool,
    pub allow_des3: bool,
    pub allow_rc4: bool,
    pub ignore_acceptor_hostname: bool,
    pub enforce_ok_as_delegate: bool,
    pub dns_canonicalize_hostname: DnsCanonicalizeHostname,
    pub default_realm: Vec<u8>,
}

impl Context {
    pub fn init() -> anyhow::Result<Self> {
        Self::new(false, false)
    }

    pub fn init_secure() -> anyhow::Result<Self> {
        Self::new(true, false)
    }

    pub fn init_kdc() -> anyhow::Result<Self> {
        Self::new(false, true)
    }

    pub fn new(secure: bool, kdc: bool) -> anyhow::Result<Self> {
        let os_context = OsContext::new();
        let profile = Profile::new(secure, kdc)?;

        let allow_weak_crypto = Self::get_bool(&profile, Conf::ALLOW_WEAK_CRYPTO, false);
        let allow_des3 = Self::get_bool(&profile, Conf::ALLOW_DES3, false);
        let allow_rc4 = Self::get_bool(&profile, Conf::ALLOW_RC4, false);
        let ignore_acceptor_hostname =
            Self::get_bool(&profile, Conf::IGNORE_ACCEPTOR_HOSTNAME, false);
        let enforce_ok_as_delegate = Self::get_bool(&profile, Conf::ENFORCE_OK_AS_DELEGATE, false);

        let dns_canonicalize_hostname = Self::get_dns_canonicalize_hostname(&profile)?;

        let clockskew = Self::get_int(&profile, Conf::CLOCKSKEW, DEFAULT_CLOCKSKEW);

        let req_timeout = 0;
        if let Some(_timeout_str) = Self::get_string(&profile, Conf::REQUEST_TIMEOUT) {
            // TODO: `krb5_string_to_deltat`
        }

        let kdc_default_options =
            Self::get_int(&profile, Conf::KDC_DEFAULT_OPTIONS, KDC_OPT_RENEWABLE_OK);

        let library_options =
            if Self::get_int(&profile, Conf::KDC_TIMESYNC, DEFAULT_KDC_TIMESYNC) > 0 {
                KRB5_LIBOPT_SYNC_KDCTIME
            } else {
                0
            };

        let fcc_default_format =
            Self::get_int(&profile, Conf::CCACHE_TYPE, DEFAULT_CCACHE_TYPE) + 0x0500;

        Ok(Self {
            os_context,
            profile,
            clockskew,
            req_timeout,
            kdc_default_options,
            library_options,
            profile_secure: secure,
            fcc_default_format,
            prompt_types: 0,
            udp_pref_limit: -1,
            use_conf_ktypes: false,
            allow_weak_crypto,
            allow_des3,
            allow_rc4,
            ignore_acceptor_hostname,
            enforce_ok_as_delegate,
            dns_canonicalize_hostname,
            default_realm: vec![],
        })
    }

    fn get_bool(profile: &Profile, name: &str, default: bool) -> bool {
        profile
            .get_bool(&format!("{}.{}", Conf::LIBDEFAULTS, name))
            .unwrap_or(default)
    }

    fn get_dns_canonicalize_hostname(profile: &Profile) -> anyhow::Result<DnsCanonicalizeHostname> {
        let key = format!("{}.{}", Conf::LIBDEFAULTS, Conf::DNS_CANONICALIZE_HOSTNAME);
        if profile.get_string(&key).is_none() {
            return Ok(DnsCanonicalizeHostname::True);
        }
        match profile.get_bool(&key) {
            Some(true) => return Ok(DnsCanonicalizeHostname::True),
            Some(false) => return Ok(DnsCanonicalizeHostname::False),
            None => (),
        }
        match profile.get_string(&key) {
            Some(value) if value.eq_ignore_ascii_case("fallback") => {
                Ok(DnsCanonicalizeHostname::Fallback)
            }
            _ => Err(anyhow::anyhow!("Invalid argument")),
        }
    }

    fn get_int(profile: &Profile, name: &str, default: i32) -> i32 {
        profile
            .get_int(&format!("{}.{}", Conf::LIBDEFAULTS, name))
            .map(|v| v as i32)
            .unwrap_or(default)
    }

    fn get_string(profile: &Profile, name: &str) -> Option<String> {
        profile.get_string(&format!("{}.{}", Conf::LIBDEFAULTS, name))
    }

    pub fn expand_path_tokens(path: &str) -> anyhow::Result<String> {
        let mut buf = vec![];
        let mut path_remained = &path[0..];
        while !path_remained.is_empty() {
            let token_begin = match path_remained.find("%{") {
                Some(token_begin) => {
                    buf.append(&mut path_remained[..token_begin].as_bytes().to_vec());
                    token_begin
                }
                None => {
                    buf.append(&mut path_remained.as_bytes().to_vec());
                    break;
                }
            };
            let token_end = match path_remained[token_begin..].find('}') {
                Some(token_end) => token_begin + token_end,
                None => Err(anyhow::anyhow!("Invalid argument"))?,
            };
            let token_value = Self::expand_token(&path_remained[token_begin + 2..token_end])?;
            buf.append(&mut token_value.as_bytes().to_vec());
            path_remained = &path_remained[token_end + 1..];
        }
        Ok(String::from_utf8(buf)?)
    }

    fn expand_token(token: &str) -> anyhow::Result<String> {
        let token_value = match token {
            "euid" => Uid::effective().to_string(),
            "username" => User::from_uid(Uid::effective())?
                .map(|u| u.name)
                .unwrap_or_else(|| Uid::effective().to_string()),
            "uid" | "USERID" => Uid::current().to_string(),
            _ => Err(anyhow::anyhow!("Invalid argument"))?,
        };
        Ok(token_value)
    }

    pub fn set_default_ccname(&mut self, name: &str) {
        self.os_context.default_ccname = Some(name.to_owned())
    }

    pub fn sync_kdctime(&self) -> bool {
        self.library_options & KRB5_LIBOPT_SYNC_KDCTIME > 0
    }

    pub fn get_default_realm(&mut self) -> anyhow::Result<Vec<u8>> {
        if !self.default_realm.is_empty() {
            return Ok(self.default_realm.to_owned());
        }
        // TODO: get from hostrealm modules
        Err(Error::KRB5_CONFIG_NODEFREALM)?
    }
}

#[derive(Debug)]
pub struct OsContext {
    pub time_offset: i32,
    pub usec_offset: i32,
    pub os_flags: Flags,
    pub default_ccname: Option<String>,
}

impl OsContext {
    pub fn new() -> Self {
        Self {
            time_offset: 0,
            usec_offset: 0,
            os_flags: 0,
            default_ccname: None,
        }
    }

    pub fn time_offset_valid(&self) -> bool {
        self.os_flags & KRB5_OS_TOFFSET_VALID > 1
    }

    pub fn set_time_offset_valid(&mut self) {
        self.os_flags = self.os_flags & !KRB5_OS_TOFFSET_TIME | KRB5_OS_TOFFSET_VALID;
    }
}
