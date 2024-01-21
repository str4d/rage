use std::fmt;
use std::io;

use crate::{wfl, wlnfl, DecryptError};

/// Errors that can occur while reading recipients or identities.
#[derive(Debug)]
pub enum ReadError {
    /// An error occured while decrypting passphrase-encrypted identities.
    EncryptedIdentities(DecryptError),
    /// An age identity was encrypted without a passphrase.
    IdentityEncryptedWithoutPassphrase(String),
    /// The given identity file could not be found.
    IdentityNotFound(String),
    /// The given recipient string is invalid.
    InvalidRecipient(String),
    /// A recipients file contains non-recipient data.
    InvalidRecipientsFile {
        /// The given recipients file.
        filename: String,
        /// The first line containing non-recipient data.
        line_number: usize,
    },
    /// An I/O error occurred while reading.
    Io(io::Error),
    /// A required plugin could not be found.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// The given recipients file could not be found.
    MissingRecipientsFile(String),
    /// Standard input was used by multiple files.
    MultipleStdin,
    /// A recipient is an `ssh-rsa`` public key with a modulus larger than we support.
    #[cfg(feature = "ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
    RsaModulusTooLarge,
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
            ReadError::EncryptedIdentities(e) => e.fmt(f),
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
            ReadError::InvalidRecipient(recipient) => wfl!(
                f,
                "err-read-invalid-recipient",
                recipient = recipient.as_str(),
            ),
            ReadError::InvalidRecipientsFile {
                filename,
                line_number,
            } => wfl!(
                f,
                "err-read-invalid-recipients-file",
                filename = filename.as_str(),
                line_number = line_number,
            ),
            ReadError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "plugin")]
            ReadError::MissingPlugin { binary_name } => {
                wlnfl!(f, "err-missing-plugin", plugin_name = binary_name.as_str())?;
                wfl!(f, "rec-missing-plugin")
            }
            ReadError::MissingRecipientsFile(filename) => wfl!(
                f,
                "err-read-missing-recipients-file",
                filename = filename.as_str(),
            ),
            ReadError::MultipleStdin => wfl!(f, "err-read-multiple-stdin"),
            #[cfg(feature = "ssh")]
            ReadError::RsaModulusTooLarge => {
                wfl!(f, "err-read-rsa-modulus-too-large", max_size = 4096)
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
