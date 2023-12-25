mod krb5_error;

pub use self::krb5_error::*;

pub type ErrorCode = i32;

#[derive(Debug)]
pub struct Error {
    pub code: ErrorCode,
    pub message: &'static str,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

macro_rules! error {
    ($error:ident, $code:expr, $message:expr) => {
        pub const $error: &Error = &Error {
            code: $code,
            message: $message,
        };
    };
}

pub(self) use error;
