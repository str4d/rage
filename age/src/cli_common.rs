//! Common helpers for CLI binaries.

use age_core::secrecy::{ExposeSecret, SecretString};
use pinentry::PassphraseInput;
use rand::{
    distributions::{Distribution, Uniform},
    rngs::OsRng,
    CryptoRng, RngCore,
};
use rpassword::prompt_password;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use subtle::ConstantTimeEq;

use crate::{fl, identity::IdentityFile, wfl, Callbacks, Identity};

#[cfg(feature = "armor")]
use crate::armor::ArmoredReader;

pub mod file_io;

const BIP39_WORDLIST: &str = include_str!("../assets/bip39-english.txt");

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
                write!(
                    f,
                    "{}",
                    i18n_embed_fl::fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "err-read-identity-encrypted-without-passphrase",
                        filename = filename.as_str()
                    )
                )
            }
            ReadError::IdentityNotFound(filename) => write!(
                f,
                "{}",
                i18n_embed_fl::fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "err-read-identity-not-found",
                    filename = filename.as_str()
                )
            ),
            ReadError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "plugin")]
            ReadError::MissingPlugin { binary_name } => {
                writeln!(
                    f,
                    "{}",
                    i18n_embed_fl::fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "err-missing-plugin",
                        plugin_name = binary_name.as_str()
                    )
                )?;
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

/// Reads identities from the provided files.
pub fn read_identities(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
) -> Result<Vec<Box<dyn Identity>>, ReadError> {
    let mut identities: Vec<Box<dyn Identity>> = vec![];

    for filename in filenames {
        #[cfg(feature = "armor")]
        // Try parsing as an encrypted age identity.
        if let Ok(identity) = crate::encrypted::Identity::from_buffer(
            ArmoredReader::new(BufReader::new(File::open(&filename)?)),
            Some(filename.clone()),
            UiCallbacks,
            max_work_factor,
        ) {
            if let Some(identity) = identity {
                identities.push(Box::new(identity));
                continue;
            } else {
                return Err(ReadError::IdentityEncryptedWithoutPassphrase(filename));
            }
        }

        // Try parsing as a single multi-line SSH identity.
        #[cfg(feature = "ssh")]
        match crate::ssh::Identity::from_buffer(
            BufReader::new(File::open(&filename)?),
            Some(filename.clone()),
        ) {
            Ok(crate::ssh::Identity::Unsupported(k)) => {
                return Err(ReadError::UnsupportedKey(filename, k))
            }
            Ok(identity) => {
                identities.push(Box::new(identity.with_callbacks(UiCallbacks)));
                continue;
            }
            Err(_) => (),
        }
        // IdentityFileEntry::into_identity will never return a MissingPlugin error
        // when plugin feature is not enabled.

        // Try parsing as multiple single-line age identities.
        let identity_file =
            IdentityFile::from_file(filename.clone()).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => ReadError::IdentityNotFound(filename),
                _ => e.into(),
            })?;

        for entry in identity_file.into_identities() {
            let entry = entry.into_identity(UiCallbacks);

            #[cfg(feature = "plugin")]
            let entry = entry.map_err(|e| match e {
                #[cfg(feature = "plugin")]
                crate::DecryptError::MissingPlugin { binary_name } => {
                    ReadError::MissingPlugin { binary_name }
                }
                // DecryptError::MissingPlugin is the only possible error kind returned by
                // IdentityFileEntry::into_identity.
                _ => unreachable!(),
            })?;

            #[cfg(not(feature = "plugin"))]
            let entry = entry.unwrap();

            identities.push(entry);
        }
    }

    Ok(identities)
}

/// Requests a secret from the user.
///
/// If a `pinentry` binary is available on the system, it is used to request the secret.
/// If not, we fall back to requesting directly in the CLI via a TTY.
///
/// This API does not take the secret directly from stdin, because it is specifically
/// intended to take the secret from a human.
///
/// # Parameters
///
/// - `description` is the primary information provided to the user about the secret
///   being requested. It is printed in all cases.
/// - `prompt` is a short phrase such as "Passphrase" or "PIN". It is printed in front of
///   the input field when `pinentry` is used.
/// - `confirm` is an optional short phrase such as "Confirm passphrase". Setting it
///   enables input confirmation.
/// - If `confirm.is_some()` then an empty secret is allowed.
pub fn read_secret(
    description: &str,
    prompt: &str,
    confirm: Option<&str>,
) -> pinentry::Result<SecretString> {
    if let Some(mut input) = PassphraseInput::with_default_binary() {
        // pinentry binary is available!
        let mismatch_error = fl!("cli-secret-input-mismatch");
        let empty_error = fl!("cli-secret-input-required");
        input
            .with_description(description)
            .with_prompt(prompt)
            .with_timeout(30);
        if let Some(confirm_prompt) = confirm {
            input.with_confirmation(confirm_prompt, &mismatch_error);
        } else {
            input.required(&empty_error);
        }
        input.interact()
    } else {
        // Fall back to CLI interface.
        let passphrase = prompt_password(format!("{}: ", description)).map(SecretString::new)?;
        if let Some(confirm_prompt) = confirm {
            let confirm_passphrase =
                prompt_password(format!("{}: ", confirm_prompt)).map(SecretString::new)?;

            if !bool::from(
                passphrase
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(confirm_passphrase.expose_secret().as_bytes()),
            ) {
                return Err(pinentry::Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    fl!("cli-secret-input-mismatch"),
                )));
            }
        } else if passphrase.expose_secret().is_empty() {
            return Err(pinentry::Error::Cancelled);
        }

        Ok(passphrase)
    }
}

/// Implementation of age callbacks that makes requests to the user via the UI.
#[derive(Clone, Copy)]
pub struct UiCallbacks;

impl Callbacks for UiCallbacks {
    fn display_message(&self, message: &str) {
        eprintln!("{}", message);
    }

    fn request_public_string(&self, description: &str) -> Option<String> {
        let term = console::Term::stderr();
        term.read_line_initial_text(description)
            .ok()
            .filter(|s| !s.is_empty())
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        read_secret(description, &fl!("cli-passphrase-prompt"), None).ok()
    }
}

/// A passphrase.
pub enum Passphrase {
    /// Typed by the user.
    Typed(SecretString),
    /// Generated.
    Generated(SecretString),
}

impl Passphrase {
    /// Generates a secure passphrase.
    pub fn random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let between = Uniform::from(0..2048);
        let new_passphrase = (0..10)
            .map(|_| {
                BIP39_WORDLIST
                    .lines()
                    .nth(between.sample(&mut rng))
                    .expect("index is in range")
            })
            .fold(String::new(), |acc, s| {
                if acc.is_empty() {
                    acc + s
                } else {
                    acc + "-" + s
                }
            });
        Passphrase::Generated(SecretString::new(new_passphrase))
    }
}

/// Reads a passphrase from stdin, or generates a secure one if none is provided.
pub fn read_or_generate_passphrase() -> pinentry::Result<Passphrase> {
    let res = read_secret(
        &fl!("cli-passphrase-desc"),
        &fl!("cli-passphrase-prompt"),
        Some(&fl!("cli-passphrase-confirm")),
    )?;

    if res.expose_secret().is_empty() {
        Ok(Passphrase::random(OsRng))
    } else {
        Ok(Passphrase::Typed(res))
    }
}
