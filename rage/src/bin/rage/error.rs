use i18n_embed_fl::fl;
use std::fmt;
use std::io;

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };
}

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };
}

pub(crate) enum EncryptError {
    Age(age::EncryptError),
    BrokenPipe { is_stdout: bool, source: io::Error },
    IdentityFlag,
    InvalidRecipient(String),
    Io(io::Error),
    Minreq(minreq::Error),
    MissingRecipients,
    MixedRecipientAndPassphrase,
    PassphraseTimedOut,
    PassphraseWithoutFileArgument,
    UnknownAlias(String),
}

impl From<age::EncryptError> for EncryptError {
    fn from(e: age::EncryptError) -> Self {
        match e {
            age::EncryptError::Io(e) => EncryptError::Io(e),
            _ => EncryptError::Age(e),
        }
    }
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl From<minreq::Error> for EncryptError {
    fn from(e: minreq::Error) -> Self {
        EncryptError::Minreq(e)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::Age(e) => write!(f, "{}", e),
            EncryptError::BrokenPipe { is_stdout, source } => {
                if *is_stdout {
                    writeln!(
                        f,
                        "{}",
                        fl!(
                            crate::LANGUAGE_LOADER,
                            "err-enc-broken-stdout",
                            err = source.to_string()
                        )
                    )?;
                    wfl!(f, "rec-enc-broken-stdout")
                } else {
                    write!(
                        f,
                        "{}",
                        fl!(
                            crate::LANGUAGE_LOADER,
                            "err-enc-broken-file",
                            err = source.to_string()
                        )
                    )
                }
            }
            EncryptError::IdentityFlag => {
                wlnfl!(f, "err-enc-identity")?;
                wfl!(f, "rec-enc-identity")
            }
            EncryptError::InvalidRecipient(recipient) => write!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-enc-invalid-recipient",
                    recipient = recipient.as_str()
                )
            ),
            EncryptError::Io(e) => write!(f, "{}", e),
            EncryptError::Minreq(e) => write!(f, "{}", e),
            EncryptError::MissingRecipients => {
                wlnfl!(f, "err-enc-missing-recipients")?;
                wfl!(f, "rec-enc-missing-recipients")
            }
            EncryptError::MixedRecipientAndPassphrase => {
                wfl!(f, "err-enc-mixed-recipient-passphrase")
            }
            EncryptError::PassphraseTimedOut => wfl!(f, "err-passphrase-timed-out"),
            EncryptError::PassphraseWithoutFileArgument => {
                wfl!(f, "err-enc-passphrase-without-file")
            }
            EncryptError::UnknownAlias(alias) => write!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-enc-unknown-alias",
                    alias = alias.as_str()
                )
            ),
        }
    }
}

pub(crate) enum DecryptError {
    Age(age::DecryptError),
    ArmorFlag,
    IdentityNotFound(String),
    Io(io::Error),
    MissingIdentities,
    PassphraseFlag,
    PassphraseTimedOut,
    #[cfg(not(unix))]
    PassphraseWithoutFileArgument,
    RecipientFlag,
    #[cfg(feature = "ssh")]
    UnsupportedKey(String, age::ssh::UnsupportedKey),
}

impl From<age::DecryptError> for DecryptError {
    fn from(e: age::DecryptError) -> Self {
        DecryptError::Age(e)
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::Age(e) => match e {
                age::DecryptError::ExcessiveWork { required, .. } => {
                    writeln!(f, "{}", e)?;
                    write!(
                        f,
                        "{}",
                        fl!(
                            crate::LANGUAGE_LOADER,
                            "rec-dec-excessive-work",
                            wf = required
                        )
                    )
                }
                _ => write!(f, "{}", e),
            },
            DecryptError::ArmorFlag => {
                wlnfl!(f, "err-dec-armor-flag")?;
                wfl!(f, "rec-dec-armor-flag")
            }
            DecryptError::IdentityNotFound(filename) => write!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-dec-identity-not-found",
                    filename = filename.as_str()
                )
            ),
            DecryptError::Io(e) => write!(f, "{}", e),
            DecryptError::MissingIdentities => {
                wlnfl!(f, "err-dec-missing-identities")?;
                wlnfl!(f, "rec-dec-missing-identities")
            }
            DecryptError::PassphraseFlag => {
                wlnfl!(f, "err-dec-passphrase-flag")?;
                wfl!(f, "rec-dec-passphrase-flag")
            }
            DecryptError::PassphraseTimedOut => wfl!(f, "err-passphrase-timed-out"),
            #[cfg(not(unix))]
            DecryptError::PassphraseWithoutFileArgument => {
                wfl!(f, "err-dec-passphrase-without-file-win")
            }
            DecryptError::RecipientFlag => {
                wlnfl!(f, "err-dec-recipient-flag")?;
                wfl!(f, "rec-dec-recipient-flag")
            }
            #[cfg(feature = "ssh")]
            DecryptError::UnsupportedKey(filename, k) => k.display(f, Some(filename.as_str())),
        }
    }
}

pub(crate) enum Error {
    Decryption(DecryptError),
    Encryption(EncryptError),
}

impl From<DecryptError> for Error {
    fn from(e: DecryptError) -> Self {
        Error::Decryption(e)
    }
}

impl From<EncryptError> for Error {
    fn from(e: EncryptError) -> Self {
        Error::Encryption(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption(e) => writeln!(f, "{}", e)?,
            Error::Encryption(e) => writeln!(f, "{}", e)?,
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
