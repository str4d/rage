//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum Error {
    /// Seeking was attempted on an ASCII-armored encrypted message, which is unsupported.
    ArmoredWhenSeeking,
    /// The message failed to decrypt.
    DecryptionFailed,
    /// The message used an excessive work parameter for passphrase encryption.
    ExcessiveWork,
    /// The MAC in the message header was invalid.
    InvalidMac,
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// Failed to decrypt an encrypted key.
    KeyDecryptionFailed,
    /// The provided message requires keys to decrypt.
    MessageRequiresKeys,
    /// The provided message requires a passphrase to decrypt.
    MessageRequiresPassphrase,
    /// None of the provided keys could be used to decrypt the message.
    NoMatchingKeys,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ArmoredWhenSeeking => write!(f, "Armored messages not supported for seeking"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::ExcessiveWork => write!(f, "Excessive work parameter for passphrase"),
            Error::InvalidMac => write!(f, "Header MAC is invalid"),
            Error::Io(e) => e.fmt(f),
            Error::KeyDecryptionFailed => write!(f, "Failed to decrypt an encrypted key"),
            Error::MessageRequiresKeys => write!(f, "This message requires keys to decrypt"),
            Error::MessageRequiresPassphrase => {
                write!(f, "This message requires a passphrase to decrypt")
            }
            Error::NoMatchingKeys => write!(f, "No matching keys found"),
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

#[cfg(feature = "unstable")]
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
