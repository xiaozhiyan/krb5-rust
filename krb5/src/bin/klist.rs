use chrono::{DateTime, TimeZone, Utc};
use clap::{CommandFactory, Parser};
use dns_lookup::lookup_addr;
use krb5::{
    prefix_progname_to_error_if_needed, Address, Context, Credential, CredentialCache, Enctype,
    Flags, Keytab, StrConv, BUFSIZ,
};
use once_cell::sync::Lazy;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::ExitCode,
};

const PROGNAME: &str = "klist";

static ARGS: Lazy<Args> = Lazy::new(Args::parse);
static NOW: Lazy<DateTime<Utc>> = Lazy::new(Utc::now);
static TIMESTAMP_WIDTH: Lazy<usize> = Lazy::new(|| StrConv::timestamp_to_sfstring(*NOW).len());

#[derive(Parser)]
#[command(name = PROGNAME, version)]
struct Args {
    /// specifies credentials cache (Default is credentials cache)
    #[arg(short = 'c', default_value_t = false)]
    ccache: bool,
    /// specifies keytab
    #[arg(short = 'k', default_value_t = false)]
    keytab: bool,

    /// uses default client keytab if no name given
    #[arg(short = 'i', default_value_t = false)]
    use_client_keytab: bool,
    /// lists credential caches in collection
    #[arg(short = 'l', default_value_t = false)]
    list_all: bool,
    /// shows content of all credential caches
    #[arg(short = 'A', default_value_t = false)]
    show_all: bool,
    /// shows the encryption type
    #[arg(short = 'e', default_value_t = false)]
    show_etype: bool,

    /// (for credential caches) shows the submitted authorization data types
    #[arg(short = 'd', default_value_t = false)]
    show_adtype: bool,
    /// (for credential caches) shows credentials flags
    #[arg(short = 'f', default_value_t = false)]
    show_flags: bool,
    /// (for credential caches) sets exit status based on valid tgt existence
    #[arg(short = 's', default_value_t = false)]
    status_only: bool,
    /// (for credential caches) displays the address list
    #[arg(short = 'a', default_value_t = false)]
    show_addresses: bool,
    /// (for credential caches) do not reverse-resolve
    #[arg(short = 'n', default_value_t = false)]
    no_resolve: bool,

    /// (for keytabs) shows keytab entry timestamps
    #[arg(short = 't', default_value_t = false)]
    show_time: bool,
    /// (for keytabs) shows keytab entry keys
    #[arg(short = 'K', default_value_t = false)]
    show_keys: bool,
    /// (for keytabs) includes configuration data entries
    #[arg(short = 'C', default_value_t = false)]
    show_config: bool,

    name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    DEFAULT,
    CCACHE,
    KEYTAB,
}

fn main() -> ExitCode {
    prefix_progname_to_error_if_needed(PROGNAME, run(), ARGS.status_only)
}

fn run() -> anyhow::Result<()> {
    let mode = match (ARGS.ccache, ARGS.keytab) {
        (false, false) => Mode::DEFAULT,
        (true, false) => Mode::CCACHE,
        (false, true) => Mode::KEYTAB,
        (true, true) => return usage(),
    };

    if ARGS.no_resolve && !ARGS.show_addresses {
        return usage();
    }

    match mode {
        Mode::DEFAULT | Mode::CCACHE => {
            if ARGS.show_time || ARGS.show_keys {
                return usage();
            }
            if (ARGS.show_all && ARGS.list_all) || (ARGS.status_only && ARGS.list_all) {
                return usage();
            }
        }
        Mode::KEYTAB => {
            if ARGS.show_flags
                || ARGS.status_only
                || ARGS.show_addresses
                || ARGS.show_all
                || ARGS.list_all
            {
                return usage();
            }
        }
    }

    // Forces the evaluation of lazy static value `NOW` to use current time
    let _ = *NOW;

    let mut context =
        Context::init().map_err(|e| anyhow::anyhow!("{} while initializing krb5", e))?;

    match (&ARGS.name, mode) {
        (Some(name), mode) if mode != Mode::KEYTAB => context.set_default_ccname(name),
        _ => (),
    }

    if ARGS.list_all {
        return list_all_ccaches(&mut context);
    }
    if ARGS.show_all {
        return show_all_ccaches(&mut context);
    }
    match mode {
        Mode::DEFAULT | Mode::CCACHE => {
            return do_ccache(&mut context);
        }
        Mode::KEYTAB => {
            return do_keytab(&mut context, ARGS.name.as_deref());
        }
    }
}

fn usage() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(Args::command().render_help()))
}

fn list_all_ccaches(context: &mut Context) -> anyhow::Result<()> {
    let mut credential_caches_iter = CredentialCache::credential_caches_iter(context);
    let mut caches = vec![];
    while let Some(cache) = credential_caches_iter.next().transpose()? {
        caches.push(cache);
    }
    drop(credential_caches_iter);
    println!("{:30} {}", "Principal name", "Cache name");
    println!("{:30} {}", "--------------", "----------");
    let mut exit_status = false;
    for cache in caches {
        let mut cache = cache.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        let status = list_ccache(context, &mut cache).is_ok();
        exit_status |= status;
    }
    if exit_status {
        Ok(())
    } else {
        Err(anyhow::anyhow!(""))
    }
}

fn list_ccache(context: &mut Context, cache: &mut CredentialCache) -> anyhow::Result<()> {
    let principal_name = cache
        .get_principal(context)?
        .unparse_name(context, 0)
        .map_err(|_| anyhow::anyhow!(""))?;
    let credential_cache_name = cache.get_full_name();
    print!("{:30} {}", principal_name, credential_cache_name);
    if check_ccache(context, cache).is_err() {
        print!(" (Expired)");
    }
    println!();
    Ok(())
}

fn show_all_ccaches(context: &mut Context) -> anyhow::Result<()> {
    let mut credential_caches_iter = CredentialCache::credential_caches_iter(context);
    let mut caches = vec![];
    while let Some(cache) = credential_caches_iter.next().transpose()? {
        caches.push(cache);
    }
    drop(credential_caches_iter);
    let mut exit_status = false;
    let mut first = true;
    for cache in caches {
        let mut cache = cache.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        if !ARGS.status_only && !first {
            println!();
        }
        first = false;
        let status = if ARGS.status_only {
            check_ccache(context, &mut cache).is_ok()
        } else {
            show_ccache(context, &mut cache).is_ok()
        };
        exit_status |= status;
    }
    if exit_status {
        Ok(())
    } else {
        Err(anyhow::anyhow!(""))
    }
}

fn do_ccache(context: &mut Context) -> anyhow::Result<()> {
    let cache = CredentialCache::default(context)
        .map_err(|e| anyhow::anyhow!("{} while resolving ccache", e))?;
    let mut cache = cache.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
    if ARGS.status_only {
        check_ccache(context, &mut cache)
    } else {
        show_ccache(context, &mut cache)
    }
}

fn check_ccache(context: &mut Context, cache: &mut CredentialCache) -> anyhow::Result<()> {
    let principal = cache.get_principal(context)?;
    let mut credentials_iter = cache.credentials_iter(context)?;
    let mut found_tgt = false;
    let mut found_current_tgt = false;
    let mut found_current_cred = false;
    while let Some(credential) = credentials_iter.next().transpose()? {
        let credential = credential.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        if credential.server.is_local_tgt(&principal.realm) {
            found_tgt = true;
            if credential.times.endtime as i64 > NOW.timestamp() {
                found_current_tgt = true;
            }
        } else if !credential.is_config() && credential.times.endtime as i64 > NOW.timestamp() {
            found_current_cred = true;
        }
    }
    if (found_tgt && found_current_tgt) || (!found_tgt && found_current_cred) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(""))
    }
}

fn show_ccache(context: &mut Context, cache: &mut CredentialCache) -> anyhow::Result<()> {
    let default_name = cache
        .get_principal(context)?
        .unparse_name(context, 0)
        .map_err(|e| anyhow::anyhow!("{} while unparsing principal name", e))?;
    println!("Ticket cache: {}:{}", cache.get_type(), cache.get_name());
    println!("Default principal: {}\n", default_name);
    println!(
        "Valid starting{}  Expires{}  Service principal",
        vec![" "; *TIMESTAMP_WIDTH - "Valid starting".len()].join(""),
        vec![" "; *TIMESTAMP_WIDTH - "Expires".len()].join("")
    );
    let mut credentials_iter = cache
        .credentials_iter(context)
        .map_err(|e| anyhow::anyhow!("{} while starting to retrieve tickets", e))?;
    while let Some(credential) = credentials_iter
        .next()
        .transpose()
        .map_err(|e| anyhow::anyhow!("{} while retrieving a ticket", e))?
    {
        let mut credential = credential.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        if ARGS.show_config || !credential.is_config() {
            show_credential(context, &mut credential, &default_name)?;
        }
    }
    Ok(())
}

fn show_credential(
    context: &mut Context,
    credential: &mut Credential,
    default_name: &str,
) -> anyhow::Result<()> {
    let name = credential
        .client
        .unparse_name(context, 0)
        .map_err(|e| anyhow::anyhow!("{} while unparsing client name", e))?;
    let sname = credential
        .server
        .unparse_name(context, 0)
        .map_err(|e| anyhow::anyhow!("{} while unparsing server name", e))?;
    let ticket = credential.get_ticket()?;
    if credential.times.starttime == 0 {
        credential.times.starttime = credential.times.authtime;
    }

    if let Some((key, principal, value)) = credential.get_config() {
        let mut buf = vec![];
        buf.push("config: ".to_owned());
        buf.push(String::from_utf8(key.to_owned())?);
        if let Some(principal) = principal {
            buf.push("(".to_owned());
            buf.push(String::from_utf8(principal.to_owned())?);
            buf.push(")".to_owned());
        }
        buf.push(" = ".to_owned());
        let output = buf.join("");
        print!("{}", output);
        let mut config_row_length = output.len();

        for byte in value {
            if config_row_length < 8 {
                print!("{}", vec![" "; 8 - config_row_length].join(""));
                config_row_length = 8;
            }
            if byte > &0x20 && byte < &0x7f {
                print!("{}", *byte as char);
                config_row_length += 1;
            } else {
                print!("\\{:0>3o}", byte);
                config_row_length += 4;
            }
            if config_row_length > 72 {
                println!();
                config_row_length = 0;
            }
        }
        if config_row_length > 0 {
            println!();
        }
    } else {
        let start_timestamp = Utc
            .timestamp_opt(credential.times.starttime.into(), 0)
            .unwrap();
        let end_timestamp = Utc
            .timestamp_opt(credential.times.endtime.into(), 0)
            .unwrap();
        println!(
            "{}  {}  {}",
            StrConv::timestamp_to_sfstring(start_timestamp),
            StrConv::timestamp_to_sfstring(end_timestamp),
            sname
        );
    }

    let mut extra_field = 0;
    let prefix = |extra_field: i32| if extra_field == 0 { "\t" } else { ", " };
    if name != default_name {
        print!("{}for client {}", prefix(extra_field), name);
        extra_field += 1;
    }
    if credential.times.renew_till != 0 {
        let renew_till_timestamp = Utc
            .timestamp_opt(credential.times.renew_till.into(), 0)
            .unwrap();
        print!(
            "{}renew until {}",
            prefix(extra_field),
            StrConv::timestamp_to_sfstring(renew_till_timestamp)
        );
        extra_field += 2;
    }
    if ARGS.show_flags {
        let flags = flags_string(credential.ticket_flags);
        if !flags.is_empty() {
            print!("{}Flags: {}", prefix(extra_field), flags);
            extra_field += 1;
        }
    }
    if extra_field > 2 {
        println!();
        extra_field = 0;
    }
    match (ARGS.show_etype, &ticket) {
        (true, Some(ticket)) => {
            print!(
                "{}Etype (skey, tkt): {}, {} ",
                prefix(extra_field),
                etype_string(credential.keyblock.enctype)?,
                etype_string(ticket.enc_part.enctype)?
            );
            extra_field += 1;
        }
        _ => (),
    }
    if ARGS.show_adtype {
        let ad_types: Vec<String> = credential
            .authdata
            .iter()
            .map(|ad| ad.ad_type.to_string())
            .collect();
        print!("{}AD types: {}", prefix(extra_field), ad_types.join(", "));
        extra_field += 1;
    }
    if extra_field > 0 {
        println!();
    }
    if ARGS.show_addresses {
        if credential.addresses.is_empty() {
            println!("\tAddresses: (none)");
        } else {
            let addresses: Vec<String> = credential.addresses.iter().map(one_addr).collect();
            println!("\tAddresses: {}", addresses.join(", "));
        }
    }
    if let Some(ticket) = ticket {
        if !credential
            .server
            .compare_with_flags(context, &ticket.server, 0)?
        {
            let ticket_sname = ticket
                .server
                .unparse_name(context, 0)
                .map_err(|e| anyhow::anyhow!("{} while unparsing ticket server name", e))?;
            println!("\tTicket server: {}", ticket_sname);
        }
    }
    Ok(())
}

fn do_keytab(context: &mut Context, name: Option<&str>) -> anyhow::Result<()> {
    let keytab = match (name, ARGS.use_client_keytab) {
        (None, true) => Keytab::client_default(context)
            .map_err(|e| anyhow::anyhow!("{} while getting default client keytab", e))?,
        (None, false) => Keytab::default(context)
            .map_err(|e| anyhow::anyhow!("{} while getting default keytab", e))?,
        (Some(name), _) => Keytab::resolve(name)
            .map_err(|e| anyhow::anyhow!("{} while resolving keytab {}", e, name))?,
    };
    let mut keytab = keytab.lock().map_err(|e| anyhow::anyhow!("{}", e))?;

    let name = keytab
        .get_name(BUFSIZ)
        .map_err(|e| anyhow::anyhow!("{} while getting keytab name", e))?;
    println!("Keytab name: {}", name);

    let mut entries_iter = keytab
        .entries_iter()
        .map_err(|e| anyhow::anyhow!("{} while starting keytab scan", e))?;

    if ARGS.show_time {
        println!(
            "KVNO Timestamp{} Principal",
            vec![" "; *TIMESTAMP_WIDTH - "Timestamp".len()].join("")
        );
        println!(
            "{} {} {}",
            ["-"; 4].join(""),
            vec!["-"; *TIMESTAMP_WIDTH].join(""),
            vec!["-"; 73 - *TIMESTAMP_WIDTH].join("")
        );
    } else {
        println!("KVNO Principal");
        println!("{} {}", ["-"; 4].join(""), ["-"; 74].join(""));
    }

    while let Some(entry) = entries_iter
        .next()
        .transpose()
        .map_err(|e| anyhow::anyhow!("{} while scanning keytab", e))?
    {
        let pname = entry
            .principal
            .unparse_name(context, 0)
            .map_err(|e| anyhow::anyhow!("{} while unparsing principal name", e))?;
        print!("{:>4} ", entry.vno);
        if ARGS.show_time {
            let timestamp = Utc.timestamp_opt(entry.timestamp.into(), 0).unwrap();
            print!("{} ", StrConv::timestamp_to_sfstring(timestamp));
        }
        print!("{}", pname);
        if ARGS.show_etype {
            print!(" ({}) ", etype_string(entry.key.enctype)?);
        }
        if ARGS.show_keys {
            let key = entry
                .key
                .contents
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join("");
            print!(" (0x{})", key);
        }
        println!();
    }

    Ok(())
}

fn etype_string(enctype: Enctype) -> anyhow::Result<String> {
    let mut name = enctype.deprecated_name(false)?;
    if name.len() > 100 {
        name = name[..100].to_owned()
    }
    Ok(name)
}

macro_rules! add_flag {
    ($flags:expr, $buf:expr, $flag:ident, $name:expr) => {
        if $flags & Credential::$flag > 0 {
            $buf.push($name);
        }
    };
}

fn flags_string(flags: Flags) -> String {
    let mut buf = vec![];
    add_flag!(flags, buf, TKT_FLG_FORWARDABLE, "F");
    add_flag!(flags, buf, TKT_FLG_FORWARDED, "f");
    add_flag!(flags, buf, TKT_FLG_PROXIABLE, "P");
    add_flag!(flags, buf, TKT_FLG_PROXY, "p");
    add_flag!(flags, buf, TKT_FLG_MAY_POSTDATE, "D");
    add_flag!(flags, buf, TKT_FLG_POSTDATED, "d");
    add_flag!(flags, buf, TKT_FLG_INVALID, "i");
    add_flag!(flags, buf, TKT_FLG_RENEWABLE, "R");
    add_flag!(flags, buf, TKT_FLG_INITIAL, "I");
    add_flag!(flags, buf, TKT_FLG_HW_AUTH, "H");
    add_flag!(flags, buf, TKT_FLG_PRE_AUTH, "A");
    add_flag!(flags, buf, TKT_FLG_TRANSIT_POLICY_CHECKED, "T");
    add_flag!(flags, buf, TKT_FLG_OK_AS_DELEGATE, "O");
    add_flag!(flags, buf, TKT_FLG_ANONYMOUS, "a");
    buf.join("")
}

fn one_addr(address: &Address) -> String {
    let ip_addr = match (address.addrtype, address.contents.len()) {
        (Address::ADDRTYPE_INET, 4) => match address.contents[0..4] {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            _ => unreachable!(),
        },
        (Address::ADDRTYPE_INET6, 16) => {
            let mut data = [0; 8];
            for i in 0..8 {
                data[i] =
                    u16::from_be_bytes([address.contents[2 * i], address.contents[2 * i + 1]]);
            }
            IpAddr::V6(Ipv6Addr::from(data))
        }
        (Address::ADDRTYPE_INET, length) | (Address::ADDRTYPE_INET6, length) => {
            return format!(
                "broken address (type {} length {})",
                address.addrtype, length
            );
        }
        (addrtype, _) => {
            return format!("unknown addrtype {}", addrtype);
        }
    };
    if ARGS.no_resolve {
        ip_addr.to_string()
    } else {
        lookup_addr(&ip_addr).unwrap_or_else(|_| ip_addr.to_string())
    }
}
