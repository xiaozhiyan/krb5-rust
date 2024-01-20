use crate::{Flags, Keyblock, Principal, Ticket, Timestamp};

const CONF_REALM: &str = "X-CACHECONF:";
const CONF_NAME: &str = "krb5_ccache_conf_data";

type AddressType = u16;
type AuthDataType = u16;

#[derive(Debug)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub keyblock: Keyblock,
    pub times: TicketTimes,
    pub is_skey: bool,
    pub ticket_flags: Flags,
    pub addresses: Vec<Address>,
    pub ticket: Vec<u8>,
    pub second_ticket: Vec<u8>,
    pub authdata: Vec<AuthData>,
}

macro_rules! ticket_flag {
    ($name:ident, $value:expr) => {
        pub const $name: Flags = $value;
    };
}

impl Credential {
    ticket_flag!(TKT_FLG_FORWARDABLE, 0x40000000);
    ticket_flag!(TKT_FLG_FORWARDED, 0x20000000);
    ticket_flag!(TKT_FLG_PROXIABLE, 0x10000000);
    ticket_flag!(TKT_FLG_PROXY, 0x08000000);
    ticket_flag!(TKT_FLG_MAY_POSTDATE, 0x04000000);
    ticket_flag!(TKT_FLG_POSTDATED, 0x02000000);
    ticket_flag!(TKT_FLG_INVALID, 0x01000000);
    ticket_flag!(TKT_FLG_RENEWABLE, 0x00800000);
    ticket_flag!(TKT_FLG_INITIAL, 0x00400000);
    ticket_flag!(TKT_FLG_PRE_AUTH, 0x00200000);
    ticket_flag!(TKT_FLG_HW_AUTH, 0x00100000);
    ticket_flag!(TKT_FLG_TRANSIT_POLICY_CHECKED, 0x00080000);
    ticket_flag!(TKT_FLG_OK_AS_DELEGATE, 0x00040000);
    ticket_flag!(TKT_FLG_ENC_PA_REP, 0x00010000);
    ticket_flag!(TKT_FLG_ANONYMOUS, 0x00008000);

    #[inline]
    pub fn is_removed(&self) -> bool {
        self.times.endtime == 0 && self.times.authtime == -1
    }

    // Configuration entries are encoded as credential entries. The client
    // principal of the entry is the default principal of the cache. The server
    // principal has the realm X-CACHECONF: and two or three components, the
    // first of which is krb5_ccache_conf_data. The server principal’s second
    // component is the configuration key. The third component, if it exists, is
    // a principal to which the configuration key is associated. The
    // configuration value is stored in the ticket field of the entry. All other
    // entry fields are zeroed.
    pub fn is_config(&self) -> bool {
        if self.server.realm != CONF_REALM.as_bytes() {
            return false;
        }
        self.server
            .components
            .first()
            .is_some_and(|component| component == CONF_NAME.as_bytes())
    }

    pub fn get_config(&self) -> Option<(&Vec<u8>, Option<&Vec<u8>>, &Vec<u8>)> {
        if !self.is_config() {
            return None;
        }
        let components = &self.server.components;
        let key = &components[1];
        let principal = if components.len() > 2 {
            Some(&components[2])
        } else {
            None
        };
        let value = &self.ticket;
        Some((key, principal, value))
    }

    // The ticket field of a configuration entry is not (usually) a valid
    // encoding of a Kerberos ticket. An implementation must not treat the cache
    // file as malformed if it cannot decode the ticket field.
    pub fn get_ticket(&self) -> anyhow::Result<Option<Ticket>> {
        if self.is_config() {
            return Ok(None);
        }
        Some(Ticket::decode_from(&self.ticket)).transpose()
    }
}

#[derive(Debug)]
pub struct TicketTimes {
    pub authtime: i32,
    pub starttime: i32,
    pub endtime: Timestamp,
    pub renew_till: Timestamp,
}

#[derive(Debug)]
pub struct Address {
    pub addrtype: AddressType,
    pub contents: Vec<u8>,
}

macro_rules! address_type {
    ($name:ident, $value:expr) => {
        pub const $name: AddressType = $value;
    };
}

impl Address {
    address_type!(ADDRTYPE_INET, 0x0002);
    address_type!(ADDRTYPE_CHAOS, 0x0005);
    address_type!(ADDRTYPE_XNS, 0x0006);
    address_type!(ADDRTYPE_ISO, 0x0007);
    address_type!(ADDRTYPE_DDP, 0x0010);
    address_type!(ADDRTYPE_INET6, 0x0018);
    address_type!(ADDRTYPE_ADDRPORT, 0x0100);
    address_type!(ADDRTYPE_IPPORT, 0x0101);
}

#[derive(Debug)]
pub struct AuthData {
    pub ad_type: AuthDataType,
    pub contents: Vec<u8>,
}
