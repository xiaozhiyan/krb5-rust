use chrono::{DateTime, TimeZone, Utc};
use clap::{CommandFactory, Parser};
use krb5::{prefix_progname_to_error_if_needed, Enctype, Keytab, StrConv, BUFSIZ};
use once_cell::sync::Lazy;
use std::process::ExitCode;

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

#[derive(PartialEq, Eq)]
enum Mode {
    DEFAULT,
    CCACHE,
    KEYTAB,
}

fn main() -> ExitCode {
    prefix_progname_to_error_if_needed(PROGNAME, run())
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

    // TODO: `krb5_init_context`

    if ARGS.name.is_some() && mode != Mode::KEYTAB {
        // TODO: `krb5_cc_set_default_name`
    }

    if ARGS.list_all {
        return list_all_ccaches();
    }
    if ARGS.show_all {
        return show_all_ccaches();
    }
    match mode {
        Mode::DEFAULT | Mode::CCACHE => {
            return do_ccache();
        }
        Mode::KEYTAB => {
            return do_keytab(ARGS.name.as_deref());
        }
    }
}

fn usage() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(Args::command().render_help()))
}

fn list_all_ccaches() -> anyhow::Result<()> {
    // TODO
    todo!("klist::list_all_ccaches")
}

fn show_all_ccaches() -> anyhow::Result<()> {
    // TODO
    todo!("klist::show_all_ccaches")
}

fn do_ccache() -> anyhow::Result<()> {
    // TODO
    todo!("klist::do_ccache")
}

fn do_keytab(name: Option<&str>) -> anyhow::Result<()> {
    let keytab = match (name, ARGS.use_client_keytab) {
        (None, true) => Keytab::client_default()
            .map_err(|e| anyhow::anyhow!("{} while getting default client keytab", e))?,
        (None, false) => {
            Keytab::default().map_err(|e| anyhow::anyhow!("{} while getting default keytab", e))?
        }
        (Some(name), _) => Keytab::resolve(name)
            .map_err(|e| anyhow::anyhow!("{} while resolving keytab {}", e, name))?,
    };
    let mut keytab = keytab.lock().unwrap();

    let buf = keytab
        .get_name(BUFSIZ)
        .map_err(|e| anyhow::anyhow!("{} while getting keytab name", e))?;
    println!("Keytab name: {}", buf);

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
            .unparse_name()
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
