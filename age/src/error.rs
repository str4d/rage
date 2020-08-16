//! Error type.

use i18n_embed_fl::fl;
use std::fmt;
use std::io;

use crate::{wfl, wlnfl};

#[cfg(feature = "plugin")]
use age_core::format::Stanza;

/// Errors returned by a plugin.
#[cfg(feature = "plugin")]
#[derive(Debug)]
pub enum PluginError {
    /// An error caused by a specific identity.
    Identity {
        /// The plugin's binary name.
        binary_name: String,
        /// The error message.
        message: String,
    },
    /// An error caused by a specific recipient.
    Recipient {
        /// The plugin's binary name.
        binary_name: String,
        /// The recipient.
        recipient: String,
        /// The error message.
        message: String,
    },
    /// Some other error we don't know about.
    Other {
        /// The error kind.
        kind: String,
        /// Any metadata associated with the error.
        metadata: Vec<String>,
        /// The error message.
        message: String,
    },
}

#[cfg(feature = "plugin")]
impl From<Stanza> for PluginError {
    fn from(mut s: Stanza) -> Self {
        assert!(s.tag == "error");
        let kind = s.args.remove(0);
        PluginError::Other {
            kind,
            metadata: s.args,
            message: String::from_utf8_lossy(&s.body).to_string(),
        }
    }
}

#[cfg(feature = "plugin")]
impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::Identity {
                binary_name,
                message,
            } => write!(
                f,
                "{}",
                fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "err-plugin-identity",
                    plugin_name = binary_name.as_str(),
                    message = message.as_str()
                )
            ),
            PluginError::Recipient {
                binary_name,
                recipient,
                message,
            } => write!(
                f,
                "{}",
                fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "err-plugin-recipient",
                    plugin_name = binary_name.as_str(),
                    recipient = recipient.as_str(),
                    message = message.as_str()
                )
            ),
            PluginError::Other {
                kind,
                metadata,
                message,
            } => {
                write!(f, "({}", kind)?;
                for d in metadata {
                    write!(f, " {}", d)?;
                }
                write!(f, ")")?;
                if !message.is_empty() {
                    write!(f, " {}", message)?;
                }
                Ok(())
            }
        }
    }
}

/// The various errors that can be returned during the encryption process.
#[derive(Debug)]
pub enum EncryptError {
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// A required plugin could not be found.
    #[cfg(feature = "plugin")]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// Errors from a plugin.
    #[cfg(feature = "plugin")]
    Plugin(Vec<PluginError>),
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
            #[cfg(feature = "plugin")]
            EncryptError::MissingPlugin { binary_name } => {
                writeln!(
                    f,
                    "{}",
                    fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "err-missing-plugin",
                        plugin_name = binary_name.as_str()
                    )
                )?;
                wfl!(f, "rec-missing-plugin")
            }
            #[cfg(feature = "plugin")]
            EncryptError::Plugin(errors) => match &errors[..] {
                [] => unreachable!(),
                [e] => write!(f, "{}", e),
                _ => {
                    wlnfl!(f, "err-plugin-multiple")?;
                    for e in errors {
                        writeln!(f, "- {}", e)?;
                    }
                    Ok(())
                }
            },
        }
    }
}

impl std::error::Error for EncryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EncryptError::Io(inner) => Some(inner),
            #[cfg(feature = "plugin")]
            _ => None,
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
    /// A required plugin could not be found.
    #[cfg(feature = "plugin")]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// None of the provided keys could be used to decrypt the age file.
    NoMatchingKeys,
    /// Errors from a plugin.
    #[cfg(feature = "plugin")]
    Plugin(Vec<PluginError>),
    /// An unknown age format, probably from a newer version.
    UnknownFormat,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::DecryptionFailed => wfl!(f, "err-decryption-failed"),
            DecryptError::ExcessiveWork { required, target } => {
                wlnfl!(f, "err-excessive-work")?;
                write!(
                    f,
                    "{}",
                    fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "rec-excessive-work",
                        duration = (1 << (required - target))
                    )
                )
            }
            DecryptError::InvalidHeader => wfl!(f, "err-header-invalid"),
            DecryptError::InvalidMac => wfl!(f, "err-header-mac-invalid"),
            DecryptError::Io(e) => e.fmt(f),
            DecryptError::KeyDecryptionFailed => wfl!(f, "err-key-decryption"),
            #[cfg(feature = "plugin")]
            DecryptError::MissingPlugin { binary_name } => {
                writeln!(
                    f,
                    "{}",
                    fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "err-missing-plugin",
                        plugin_name = binary_name.as_str()
                    )
                )?;
                wfl!(f, "rec-missing-plugin")
            }
            DecryptError::NoMatchingKeys => wfl!(f, "err-no-matching-keys"),
            #[cfg(feature = "plugin")]
            DecryptError::Plugin(errors) => match &errors[..] {
                [] => unreachable!(),
                [e] => write!(f, "{}", e),
                _ => {
                    wlnfl!(f, "err-plugin-multiple")?;
                    for e in errors {
                        writeln!(f, "- {}", e)?;
                    }
                    Ok(())
                }
            },
            DecryptError::UnknownFormat => {
                wlnfl!(f, "err-unknown-format")?;
                wfl!(f, "rec-unknown-format")
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
