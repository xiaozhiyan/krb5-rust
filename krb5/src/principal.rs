use crate::{Context, Error, Flags};

const REALM_SEP: u8 = b'@';
const COMPONENT_SEP: u8 = b'/';
const KRB5_TGS_NAME: &str = "krbtgt";
const KRB5_WELLKNOWN_NAMESTR: &str = "WELLKNOWN";

#[derive(Debug, Clone)]
pub struct Principal {
    pub realm: Vec<u8>,
    pub components: Vec<Vec<u8>>,
    pub name_type: NameType,
}

macro_rules! principal_flag {
    ($name:ident, $value:expr) => {
        pub const $name: Flags = $value;
    };
}

impl Principal {
    principal_flag!(PARSE_NO_REALM, 0x1);
    principal_flag!(PARSE_REQUIRE_REALM, 0x2);
    principal_flag!(PARSE_ENTERPRISE, 0x4);
    principal_flag!(PARSE_IGNORE_REALM, 0x8);
    principal_flag!(PARSE_NO_DEF_REALM, 0x10);

    principal_flag!(UNPARSE_SHORT, 0x1);
    principal_flag!(UNPARSE_NO_REALM, 0x2);
    principal_flag!(UNPARSE_DISPLAY, 0x4);

    principal_flag!(COMPARE_IGNORE_REALM, 1);
    principal_flag!(COMPARE_ENTERPRISE, 2);
    principal_flag!(COMPARE_CASEFOLD, 4);
    principal_flag!(COMPARE_UTF8, 8);

    pub fn parse_name(context: &mut Context, name: &str, flags: Flags) -> anyhow::Result<Self> {
        if name.ends_with("\\") {
            Err(Error::KRB5_PARSE_MALFORMED)?
        }
        let enterprise = flags & Self::PARSE_ENTERPRISE != 0;
        let require_realm = flags & Self::PARSE_REQUIRE_REALM != 0;
        let no_realm = flags & Self::PARSE_NO_REALM != 0;
        let ignore_realm = flags & Self::PARSE_IGNORE_REALM != 0;
        let no_def_realm = flags & Self::PARSE_NO_DEF_REALM != 0;

        let find_realm_from = if enterprise {
            name.find('@').map(|i| i + 1).unwrap_or_default()
        } else {
            0
        };
        let (components, realm) = match name[find_realm_from..].find('@') {
            None => (name, None),
            Some(i) => (
                &name[..find_realm_from + i],
                Some(&name[find_realm_from + i + 1..]),
            ),
        };

        let components = if enterprise {
            vec![components.as_bytes().to_owned()]
        } else {
            components
                .split('/')
                .map(|c| c.as_bytes().to_owned())
                .collect()
        };

        let realm = match realm {
            Some(realm) => {
                if no_realm || (!enterprise && realm.contains('/')) || realm.contains('@') {
                    Err(Error::KRB5_PARSE_MALFORMED)?
                }
                if ignore_realm {
                    vec![]
                } else {
                    realm.as_bytes().to_owned()
                }
            }
            None => {
                if require_realm {
                    Err(Error::KRB5_PARSE_MALFORMED)?
                }
                if no_realm || ignore_realm || no_def_realm {
                    vec![]
                } else {
                    context.get_default_realm()?
                }
            }
        };

        let name_type = if enterprise {
            NameType::ENTERPRISE_PRINCIPAL
        } else {
            Self::infer_principal_type(&components)
        };

        Ok(Principal {
            realm,
            components,
            name_type,
        })
    }

    fn infer_principal_type(components: &Vec<Vec<u8>>) -> NameType {
        if components.len() == 2 && components[0].eq(KRB5_TGS_NAME.as_bytes()) {
            NameType::SRV_INST
        } else if components.len() >= 2 && components[0].eq(KRB5_WELLKNOWN_NAMESTR.as_bytes()) {
            NameType::WELLKNOWN
        } else {
            NameType::PRINCIPAL
        }
    }

    pub fn unparse_name(&self, context: &mut Context, flags: Flags) -> anyhow::Result<String> {
        let mut flags = flags;
        if flags & Self::UNPARSE_SHORT != 0 {
            let default_realm = context.get_default_realm()?;
            if Self::compare_realm_with_flags(&default_realm, &self.realm, 0) {
                flags |= Self::UNPARSE_NO_REALM;
            }
        }
        let mut name = self
            .components
            .iter()
            .map(|component| component.clone())
            .collect::<Vec<Vec<u8>>>()
            .join(&COMPONENT_SEP);
        if flags & Self::UNPARSE_NO_REALM == 0 {
            name = vec![name, self.realm.clone()].join(&REALM_SEP);
        }
        Ok(String::from_utf8(name)?)
    }

    pub fn compare_with_flags(
        &self,
        context: &mut Context,
        other: &Self,
        flags: Flags,
    ) -> anyhow::Result<bool> {
        let utf8 = flags & Self::COMPARE_UTF8 != 0;
        let casefold = flags & Self::COMPARE_CASEFOLD != 0;
        let mut principal_1 = self.to_owned();
        let mut principal_2 = other.to_owned();
        if flags & Self::COMPARE_ENTERPRISE != 0 {
            if self.name_type == NameType::ENTERPRISE_PRINCIPAL {
                principal_1 = self.upn_to_principal(context)?;
            }
            if other.name_type == NameType::ENTERPRISE_PRINCIPAL {
                principal_2 = other.upn_to_principal(context)?;
            }
        }
        if principal_1.components.len() != principal_2.components.len() {
            return Ok(false);
        }
        if flags & Self::COMPARE_IGNORE_REALM == 0
            && !Self::compare_realm_with_flags(&principal_1.realm, &principal_2.realm, flags)
        {
            return Ok(false);
        }
        for i in 0..principal_1.components.len() {
            let component_1 = &principal_1.components[i];
            let component_2 = &principal_2.components[i];
            let equal = if casefold {
                if utf8 {
                    let component_1 = String::from_utf8(component_1.to_owned())?;
                    let component_2 = String::from_utf8(component_2.to_owned())?;
                    component_1.eq_ignore_ascii_case(&component_2)
                } else {
                    component_1.eq_ignore_ascii_case(component_2)
                }
            } else {
                component_1.eq(component_2)
            };
            if !equal {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn compare_realm_with_flags(realm_1: &Vec<u8>, realm_2: &Vec<u8>, flags: Flags) -> bool {
        if flags & Self::COMPARE_CASEFOLD != 0 {
            realm_1.eq_ignore_ascii_case(realm_2)
        } else {
            realm_1.eq(realm_2)
        }
    }

    fn upn_to_principal(&self, context: &mut Context) -> anyhow::Result<Self> {
        let unparsed_name = self.unparse_name(context, Self::UNPARSE_NO_REALM)?;
        Self::parse_name(context, &unparsed_name, 0)
    }

    pub fn is_local_tgt(&self, realm: &Vec<u8>) -> bool {
        self.components.len() == 2
            && self.realm.eq(realm)
            && self.components[0].eq(KRB5_TGS_NAME.as_bytes())
            && self.components[1].eq(realm)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameType(pub i32);

macro_rules! name_type {
    ($name_type:ident, $int:expr) => {
        pub const $name_type: NameType = NameType($int);
    };
}

impl NameType {
    // Name type not known
    name_type!(UNKNOWN, 0);
    // Just the name of the principal as in DCE, or for users
    name_type!(PRINCIPAL, 1);
    // Service and other unique instance (krbtgt)
    name_type!(SRV_INST, 2);
    // Service with host name as instance (telnet, rcommands)
    name_type!(SRV_HST, 3);
    // Service with host as remaining components
    name_type!(SRV_XHST, 4);
    // Unique ID
    name_type!(UID, 5);
    // PKINIT
    name_type!(X500_PRINCIPAL, 6);
    // Name in form of SMTP email name
    name_type!(SMTP_NAME, 7);
    // Windows 2000 UPN
    name_type!(ENTERPRISE_PRINCIPAL, 10);
    // Well-known (special) principal
    name_type!(WELLKNOWN, 11);
    // Windows 2000 UPN and SID
    name_type!(MS_PRINCIPAL, -128);
    // NT 4 style name
    name_type!(MS_PRINCIPAL_AND_ID, -129);
    // NT 4 style name and SID
    name_type!(ENT_PRINCIPAL_AND_ID, -130);
}
