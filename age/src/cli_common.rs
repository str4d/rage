//! Common helpers for CLI binaries.

use pinentry::PassphraseInput;
use rand::{
    distributions::{Distribution, Uniform},
    rngs::OsRng,
};
use rpassword::read_password_from_tty;
use secrecy::{ExposeSecret, SecretString};
use std::fs::File;
use std::io::{self, BufReader};
use subtle::ConstantTimeEq;

use crate::{armor::ArmoredReader, fl, identity::IdentityFile, Callbacks, Identity};

pub mod file_io;

const BIP39_WORDLIST: &str = include_str!("../assets/bip39-english.txt");

/// Reads identities from the provided files if given, or the default system
/// locations if no files are given.
pub fn read_identities<E, G, H>(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
    file_not_found: G,
    identity_encrypted_without_passphrase: H,
    #[cfg(feature = "ssh")] unsupported_ssh: impl Fn(String, crate::ssh::UnsupportedKey) -> E,
) -> Result<Vec<Box<dyn Identity>>, E>
where
    E: From<crate::DecryptError>,
    E: From<io::Error>,
    G: Fn(String) -> E,
    H: Fn(String) -> E,
{
    let mut identities: Vec<Box<dyn Identity>> = vec![];

    for filename in filenames {
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
                return Err(identity_encrypted_without_passphrase(filename));
            }
        }

        // Try parsing as a single multi-line SSH identity.
        #[cfg(feature = "ssh")]
        match crate::ssh::Identity::from_buffer(
            BufReader::new(File::open(&filename)?),
            Some(filename.clone()),
        ) {
            Ok(crate::ssh::Identity::Unsupported(k)) => return Err(unsupported_ssh(filename, k)),
            Ok(identity) => {
                identities.push(Box::new(identity.with_callbacks(UiCallbacks)));
                continue;
            }
            Err(_) => (),
        }

        // Try parsing as multiple single-line age identities.
        let identity_file =
            IdentityFile::from_file(filename.clone()).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => file_not_found(filename),
                _ => e.into(),
            })?;

        for entry in identity_file.into_identities() {
            identities.push(entry.into_identity(UiCallbacks)?);
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
        let passphrase =
            read_password_from_tty(Some(&format!("{}: ", description))).map(SecretString::new)?;
        if let Some(confirm_prompt) = confirm {
            let confirm_passphrase = read_password_from_tty(Some(&format!("{}: ", confirm_prompt)))
                .map(SecretString::new)?;

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

/// Reads a passphrase from stdin, or generates a secure one if none is provided.
pub fn read_or_generate_passphrase() -> pinentry::Result<Passphrase> {
    let res = read_secret(
        &fl!("cli-passphrase-desc"),
        &fl!("cli-passphrase-prompt"),
        Some(&fl!("cli-passphrase-confirm")),
    )?;

    if res.expose_secret().is_empty() {
        // Generate a secure passphrase
        let between = Uniform::from(0..2048);
        let mut rng = OsRng;
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
        Ok(Passphrase::Generated(SecretString::new(new_passphrase)))
    } else {
        Ok(Passphrase::Typed(res))
    }
}
