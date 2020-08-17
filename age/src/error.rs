//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the encryption process.
#[derive(Debug)]
pub enum EncryptError {
    /// An I/O error occurred during decryption.
    Io(io::Error),
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::Io(e) => e.fmt(f),
        }
    }
}

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum DecryptError {
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

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::DecryptionFailed => write!(f, "Decryption failed"),
            DecryptError::ExcessiveWork { required, target } => {
                writeln!(f, "Excessive work parameter for passphrase.")?;
                write!(
                    f,
                    "Decryption would take around {} seconds.",
                    1 << (required - target)
                )
            }
            DecryptError::InvalidHeader => write!(f, "Header is invalid"),
            DecryptError::InvalidMac => write!(f, "Header MAC is invalid"),
            DecryptError::Io(e) => e.fmt(f),
            DecryptError::KeyDecryptionFailed => write!(f, "Failed to decrypt an encrypted key"),
            DecryptError::NoMatchingKeys => write!(f, "No matching keys found"),
            DecryptError::UnknownFormat => {
                writeln!(f, "Unknown age format.")?;
                write!(f, "Have you tried upgrading to the latest version?")
            }
        }
    }
}

impl From<chacha20poly1305::aead::Error> for DecryptError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        DecryptError::DecryptionFailed
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl From<hmac::crypto_mac::MacError> for DecryptError {
    fn from(_: hmac::crypto_mac::MacError) -> Self {
        DecryptError::InvalidMac
    }
}

#[cfg(feature = "ssh")]
impl From<rsa::errors::Error> for DecryptError {
    fn from(_: rsa::errors::Error) -> Self {
        DecryptError::DecryptionFailed
    }
}

impl std::error::Error for DecryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecryptError::Io(inner) => Some(inner),
            _ => None,
        }
    }
}
