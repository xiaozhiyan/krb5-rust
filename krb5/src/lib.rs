mod context;
mod credential_cache;
mod crypto;
mod error;
mod keytab;
mod krb;
mod principal;
mod ticket;

pub use self::{
    context::{Conf, Context},
    credential_cache::{Address, AuthData, Credential, CredentialCache, TicketTimes},
    crypto::{Enctype, Keyblock},
    error::{Error, ErrorCode},
    keytab::{Keytab, KeytabEntry, Kvno},
    krb::StrConv,
    principal::{NameType, Principal},
    ticket::Ticket,
};
use std::process::ExitCode;

pub const BUFSIZ: usize = 1024;

pub type Flags = i32;
pub type Timestamp = u32;

pub fn prefix_progname_to_error_if_needed(
    progname: &str,
    result: anyhow::Result<()>,
    status_only: bool,
) -> ExitCode {
    match (result, status_only) {
        (Ok(_), _) => ExitCode::SUCCESS,
        (Err(_), true) => ExitCode::FAILURE,
        (Err(err), false) if err.to_string().is_empty() => ExitCode::FAILURE,
        (Err(err), false) if err.to_string().starts_with(&format!("Usage: {}", progname)) => {
            eprintln!("{:?}", err);
            ExitCode::FAILURE
        }
        (Err(err), false) => {
            eprintln!("{}: {:?}", progname, err);
            ExitCode::FAILURE
        }
    }
}
