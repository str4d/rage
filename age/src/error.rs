//! Error type.

use std::collections::HashSet;
use std::fmt;
use std::io;

use crate::{wfl, wlnfl};

#[cfg(feature = "plugin")]
use age_core::format::Stanza;

/// Errors returned when converting an identity file to a recipients file.
#[derive(Debug)]
pub enum IdentityFileConvertError {
    /// An I/O error occurred while writing out a recipient corresponding to an identity
    /// in this file.
    FailedToWriteOutput(io::Error),
    /// The identity file contains a plugin identity, which can be converted to a
    /// recipient for encryption purposes, but not for writing a recipients file.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    IdentityFileContainsPlugin {
        /// The given identity file.
        filename: Option<String>,
        /// The name of the plugin.
        plugin_name: String,
    },
    /// The identity file contains no identities, and thus cannot be used to produce a
    /// recipients file.
    NoIdentities {
        /// The given identity file.
        filename: Option<String>,
    },
}

impl fmt::Display for IdentityFileConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityFileConvertError::FailedToWriteOutput(e) => {
                wfl!(f, "err-failed-to-write-output", err = e.to_string())
            }
            #[cfg(feature = "plugin")]
            IdentityFileConvertError::IdentityFileContainsPlugin {
                filename,
                plugin_name,
            } => {
                wlnfl!(
                    f,
                    "err-identity-file-contains-plugin",
                    filename = filename.as_deref().unwrap_or_default(),
                    plugin_name = plugin_name.as_str(),
                )?;
                wfl!(
                    f,
                    "rec-identity-file-contains-plugin",
                    plugin_name = plugin_name.as_str(),
                )
            }
            IdentityFileConvertError::NoIdentities { filename } => match filename {
                Some(filename) => {
                    wfl!(f, "err-no-identities-in-file", filename = filename.as_str())
                }
                None => wfl!(f, "err-no-identities-in-stdin"),
            },
        }
    }
}

impl std::error::Error for IdentityFileConvertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IdentityFileConvertError::FailedToWriteOutput(e) => Some(e),
            _ => None,
        }
    }
}

/// Errors returned by a plugin.
#[cfg(feature = "plugin")]
#[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
#[derive(Clone, Debug)]
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
            } => wfl!(
                f,
                "err-plugin-identity",
                plugin_name = binary_name.as_str(),
                message = message.as_str(),
            ),
            PluginError::Recipient {
                binary_name,
                recipient,
                message,
            } => wfl!(
                f,
                "err-plugin-recipient",
                plugin_name = binary_name.as_str(),
                recipient = recipient.as_str(),
                message = message.as_str(),
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
    /// An error occured while decrypting passphrase-encrypted identities.
    EncryptedIdentities(DecryptError),
    /// The encryptor was given recipients that declare themselves incompatible.
    IncompatibleRecipients {
        /// The set of labels from the first recipient provided to the encryptor.
        l_labels: HashSet<String>,
        /// The set of labels from the first non-matching recipient.
        r_labels: HashSet<String>,
    },
    /// One or more of the labels from the first recipient provided to the encryptor are
    /// invalid.
    ///
    /// Labels must be valid age "arbitrary string"s (`1*VCHAR` in ABNF).
    InvalidRecipientLabels(HashSet<String>),
    /// An I/O error occurred during encryption.
    Io(io::Error),
    /// A required plugin could not be found.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// The encryptor was not given any recipients.
    MissingRecipients,
    /// [`scrypt::Recipient`] was mixed with other recipient types.
    ///
    /// [`scrypt::Recipient`]: crate::scrypt::Recipient
    MixedRecipientAndPassphrase,
    /// Errors from a plugin.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    Plugin(Vec<PluginError>),
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl Clone for EncryptError {
    fn clone(&self) -> Self {
        match self {
            Self::EncryptedIdentities(e) => Self::EncryptedIdentities(e.clone()),
            Self::IncompatibleRecipients { l_labels, r_labels } => Self::IncompatibleRecipients {
                l_labels: l_labels.clone(),
                r_labels: r_labels.clone(),
            },
            Self::InvalidRecipientLabels(labels) => Self::InvalidRecipientLabels(labels.clone()),
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
            #[cfg(feature = "plugin")]
            Self::MissingPlugin { binary_name } => Self::MissingPlugin {
                binary_name: binary_name.clone(),
            },
            Self::MissingRecipients => Self::MissingRecipients,
            Self::MixedRecipientAndPassphrase => Self::MixedRecipientAndPassphrase,
            #[cfg(feature = "plugin")]
            Self::Plugin(e) => Self::Plugin(e.clone()),
        }
    }
}

fn print_labels(labels: &HashSet<String>) -> String {
    let mut s = String::new();
    for (i, label) in labels.iter().enumerate() {
        s.push_str(label);
        if i != 0 {
            s.push_str(", ");
        }
    }
    s
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::EncryptedIdentities(e) => e.fmt(f),
            EncryptError::IncompatibleRecipients { l_labels, r_labels } => {
                match (l_labels.is_empty(), r_labels.is_empty()) {
                    (true, true) => unreachable!("labels are compatible"),
                    (false, true) => {
                        wfl!(
                            f,
                            "err-incompatible-recipients-oneway",
                            labels = print_labels(l_labels),
                        )
                    }
                    (true, false) => {
                        wfl!(
                            f,
                            "err-incompatible-recipients-oneway",
                            labels = print_labels(r_labels),
                        )
                    }
                    (false, false) => wfl!(
                        f,
                        "err-incompatible-recipients-twoway",
                        left = print_labels(l_labels),
                        right = print_labels(r_labels),
                    ),
                }
            }
            EncryptError::InvalidRecipientLabels(labels) => wfl!(
                f,
                "err-invalid-recipient-labels",
                labels = print_labels(labels),
            ),
            EncryptError::Io(e) => e.fmt(f),
            #[cfg(feature = "plugin")]
            EncryptError::MissingPlugin { binary_name } => {
                wlnfl!(f, "err-missing-plugin", plugin_name = binary_name.as_str())?;
                wfl!(f, "rec-missing-plugin")
            }
            EncryptError::MissingRecipients => wfl!(f, "err-missing-recipients"),
            EncryptError::MixedRecipientAndPassphrase => {
                wfl!(f, "err-mixed-recipient-passphrase")
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
            EncryptError::EncryptedIdentities(inner) => Some(inner),
            EncryptError::Io(inner) => Some(inner),
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
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    MissingPlugin {
        /// The plugin's binary name.
        binary_name: String,
    },
    /// None of the provided keys could be used to decrypt the age file.
    NoMatchingKeys,
    /// Errors from a plugin.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    Plugin(Vec<PluginError>),
    /// An unknown age format, probably from a newer version.
    UnknownFormat,
}

impl Clone for DecryptError {
    fn clone(&self) -> Self {
        match self {
            Self::DecryptionFailed => Self::DecryptionFailed,
            Self::ExcessiveWork { required, target } => Self::ExcessiveWork {
                required: *required,
                target: *target,
            },
            Self::InvalidHeader => Self::InvalidHeader,
            Self::InvalidMac => Self::InvalidMac,
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
            Self::KeyDecryptionFailed => Self::KeyDecryptionFailed,
            #[cfg(feature = "plugin")]
            Self::MissingPlugin { binary_name } => Self::MissingPlugin {
                binary_name: binary_name.clone(),
            },
            Self::NoMatchingKeys => Self::NoMatchingKeys,
            #[cfg(feature = "plugin")]
            Self::Plugin(e) => Self::Plugin(e.clone()),
            Self::UnknownFormat => Self::UnknownFormat,
        }
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::DecryptionFailed => wfl!(f, "err-decryption-failed"),
            DecryptError::ExcessiveWork { required, target } => {
                wlnfl!(f, "err-excessive-work")?;
                wfl!(
                    f,
                    "rec-excessive-work",
                    duration = (1 << (required - target)),
                )
            }
            DecryptError::InvalidHeader => wfl!(f, "err-header-invalid"),
            DecryptError::InvalidMac => wfl!(f, "err-header-mac-invalid"),
            DecryptError::Io(e) => e.fmt(f),
            DecryptError::KeyDecryptionFailed => wfl!(f, "err-key-decryption"),
            #[cfg(feature = "plugin")]
            DecryptError::MissingPlugin { binary_name } => {
                wlnfl!(f, "err-missing-plugin", plugin_name = binary_name.as_str())?;
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

impl From<hmac::digest::MacError> for DecryptError {
    fn from(_: hmac::digest::MacError) -> Self {
        DecryptError::InvalidMac
    }
}

#[cfg(feature = "ssh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
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
