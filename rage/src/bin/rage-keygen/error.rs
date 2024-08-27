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

pub(crate) enum Error {
    FailedToOpenInput(io::Error),
    FailedToOpenOutput(io::Error),
    FailedToReadInput(io::Error),
    FailedToWriteOutput(io::Error),
    IdentityFileConvert(IdentityFileConvertError),
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FailedToOpenInput(e) => {
                wlnfl!(f, "err-failed-to-open-input", err = e.to_string())?
            }
            Error::FailedToOpenOutput(e) => {
                wlnfl!(f, "err-failed-to-open-output", err = e.to_string())?
            }
            Error::FailedToReadInput(e) => {
                wlnfl!(f, "err-failed-to-read-input", err = e.to_string())?
            }
            Error::FailedToWriteOutput(e) => {
                wlnfl!(f, "err-failed-to-write-output", err = e.to_string())?
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
