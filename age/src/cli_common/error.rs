use std::fmt;
use std::io;

use crate::{wfl, wlnfl};

/// Errors that can occur while reading identities.
#[derive(Debug)]
pub enum ReadError {
    /// An age identity was encrypted without a passphrase.
    IdentityEncryptedWithoutPassphrase(String),
    /// The given identity file could not be found.
    IdentityNotFound(String),
    /// An I/O error occurred while reading.
    Io(io::Error),
    /// A required plugin could not be found.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// The given identity file contains an SSH key that we know how to parse, but that we
    /// do not support.
    #[cfg(feature = "ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
    UnsupportedKey(String, crate::ssh::UnsupportedKey),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::IdentityEncryptedWithoutPassphrase(filename) => {
                wfl!(
                    f,
                    "err-read-identity-encrypted-without-passphrase",
                    filename = filename.as_str(),
                )
            }
            ReadError::IdentityNotFound(filename) => wfl!(
                f,
                "err-read-identity-not-found",
                filename = filename.as_str(),
            ),
            ReadError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "plugin")]
            ReadError::MissingPlugin { binary_name } => {
                wlnfl!(f, "err-missing-plugin", plugin_name = binary_name.as_str())?;
                wfl!(f, "rec-missing-plugin")
            }
            #[cfg(feature = "ssh")]
            ReadError::UnsupportedKey(filename, k) => k.display(f, Some(filename.as_str())),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(inner) => Some(inner),
            _ => None,
        }
    }
}
