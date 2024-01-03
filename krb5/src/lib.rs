mod context;
mod crypto;
mod error;
mod keytab;
mod krb;
mod principal;

pub use self::{
    context::{Conf, Context},
    crypto::{Enctype, Keyblock},
    error::{Error, ErrorCode},
    keytab::{Keytab, KeytabEntry, Kvno},
    krb::StrConv,
    principal::Principal,
};
use std::process::ExitCode;

pub const BUFSIZ: usize = 1024;

pub type Timestamp = u32;

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
