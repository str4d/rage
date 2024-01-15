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
    FailedToOpenInput(io::Error),
    FailedToOpenOutput(io::Error),
    FailedToReadInput(io::Error),
    FailedToWriteOutput(io::Error),
    IdentityFileContainsPlugin {
        filename: Option<String>,
        plugin_name: String,
    },
    NoIdentities {
        filename: Option<String>,
    },
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
            Error::IdentityFileContainsPlugin {
                filename,
                plugin_name,
            } => {
                wlnfl!(
                    f,
                    "err-identity-file-contains-plugin",
                    filename = filename.as_deref().unwrap_or_default(),
                    plugin_name = plugin_name.as_str(),
                )?;
                wlnfl!(
                    f,
                    "rec-identity-file-contains-plugin",
                    plugin_name = plugin_name.as_str(),
                )?
            }
            Error::NoIdentities { filename } => match filename {
                Some(filename) => {
                    wlnfl!(f, "err-no-identities-in-file", filename = filename.as_str())?
                }
                None => wlnfl!(f, "err-no-identities-in-stdin")?,
            },
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
