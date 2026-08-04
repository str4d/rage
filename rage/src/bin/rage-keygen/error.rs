use std::fmt;
use std::io;

use age::IdentityFileConvertError;

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

#[derive(PartialEq, Eq)]
pub(crate) enum Error {
    FailedToOpenInput(io::ErrorKind, String),
    FailedToOpenOutput(io::ErrorKind, String),
    FailedToReadInput(io::ErrorKind, String),
    FailedToWriteOutput(io::ErrorKind, String),
    IdentityFileConvert(IdentityFileConvertError),
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FailedToOpenInput(_, message) => {
                wlnfl!(f, "err-failed-to-open-input", err = message.as_str())?
            }
            Error::FailedToOpenOutput(_, message) => {
                wlnfl!(f, "err-failed-to-open-output", err = message.as_str())?
            }
            Error::FailedToReadInput(_, message) => {
                wlnfl!(f, "err-failed-to-read-input", err = message.as_str())?
            }
            Error::FailedToWriteOutput(_, message) => {
                wlnfl!(f, "err-failed-to-write-output", err = message.as_str())?
            }
            Error::IdentityFileConvert(e) => writeln!(f, "{e}")?,
        }
        writeln!(f)?;
        writeln!(f, "[ {} ]", crate::fl!("err-ux-A"))?;
        write!(
            f,
            "[ {}: https://str4d.xyz/rage/report {} ]",
            crate::fl!("err-ux-B"),
            crate::fl!("err-ux-C")
        )
    }
}
