//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum Error {
    /// The age file failed to decrypt.
    DecryptionFailed,
    /// The age file used an excessive work factor for passphrase encryption.
    ExcessiveWork {
        /// The work factor required to decrypt.
        required: u8,
        /// The target work factor for this device (around 1 second of work).
        target: u8,
    },
    /// The age header was invalid.
    InvalidHeader,
    /// The MAC in the age header was invalid.
    InvalidMac,
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// Failed to decrypt an encrypted key.
    KeyDecryptionFailed,
    /// None of the provided keys could be used to decrypt the age file.
    NoMatchingKeys,
    /// An unknown age format, probably from a newer version.
    UnknownFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::ExcessiveWork { required, target } => {
                writeln!(f, "Excessive work parameter for passphrase.")?;
                write!(
                    f,
                    "Decryption would take around {} seconds.",
                    1 << (required - target)
                )
            }
            Error::InvalidHeader => write!(f, "Header is invalid"),
            Error::InvalidMac => write!(f, "Header MAC is invalid"),
            Error::Io(e) => e.fmt(f),
            Error::KeyDecryptionFailed => write!(f, "Failed to decrypt an encrypted key"),
            Error::NoMatchingKeys => write!(f, "No matching keys found"),
            Error::UnknownFormat => {
                writeln!(f, "Unknown age format.")?;
                write!(f, "Have you tried upgrading to the latest version?")
            }
        }
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Error::DecryptionFailed
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<hmac::crypto_mac::MacError> for Error {
    fn from(_: hmac::crypto_mac::MacError) -> Self {
        Error::InvalidMac
    }
}

#[cfg(feature = "ssh")]
impl From<rsa::errors::Error> for Error {
    fn from(_: rsa::errors::Error) -> Self {
        Error::DecryptionFailed
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(inner) => Some(inner),
            _ => None,
        }
    }
}
