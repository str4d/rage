use std::fmt;
use std::io;

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

pub(crate) enum Error {
    FailedToOpenOutput(io::Error),
    FailedToWriteOutput(io::Error),
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FailedToOpenOutput(e) => {
                wlnfl!(f, "err-failed-to-open-output", err = e.to_string())?
            }
            Error::FailedToWriteOutput(e) => {
                wlnfl!(f, "err-failed-to-write-output", err = e.to_string())?
            }
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
