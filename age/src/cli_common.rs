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
use std::path::PathBuf;
use subtle::ConstantTimeEq;

use crate::{identity::IdentityFile, protocol::Callbacks, Identity};

pub mod file_io;

const BIP39_WORDLIST: &str = include_str!("../assets/bip39-english.txt");

/// Returns the age config directory.
///
/// Replicates the behaviour of [os.UserConfigDir] from Golang, which the
/// reference implementation uses. See [this issue] for more details.
///
/// [os.UserConfigDir]: https://golang.org/pkg/os/#UserConfigDir
/// [this issue]: https://github.com/FiloSottile/age/issues/15
pub fn get_config_dir() -> Option<PathBuf> {
    dirs::config_dir()
}

/// Reads identities from the provided files if given, or the default system
/// locations if no files are given.
#[rustfmt::skip]
pub fn read_identities<E, F, G>(
    filenames: Vec<String>,
    no_default: F,
    file_not_found: G,
    #[cfg(feature = "ssh")]
    unsupported_ssh: impl Fn(String, crate::ssh::UnsupportedKey) -> E,
) -> Result<Vec<Box<dyn Identity>>, E>
where
    E: From<io::Error>,
    F: FnOnce(&str) -> E,
    G: Fn(String) -> E,
{
    let mut identities: Vec<Box<dyn Identity>> = vec![];

    if filenames.is_empty() {
        let default_filename = get_config_dir()
            .map(|mut path| {
                path.push("age/keys.txt");
                path
            })
            .expect("an OS for which we know the default config directory");
        let f = File::open(&default_filename).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => no_default(default_filename.to_str().unwrap_or("")),
            _ => e.into(),
        })?;
        let buf = BufReader::new(f);
        identities.push(Box::new(IdentityFile::from_buffer(buf)?));
    } else {
        for filename in filenames {
            // Try parsing as a single multi-line SSH identity.
            #[cfg(feature = "ssh")]
            match crate::ssh::Identity::from_buffer(
                BufReader::new(File::open(&filename)?),
                Some(filename.clone()),
            ) {
                Ok(crate::ssh::Identity::Unsupported(k)) => {
                    return Err(unsupported_ssh(filename, k))
                }
                Ok(identity) => {
                    identities.push(Box::new(identity.with_callbacks(UiCallbacks)));
                    continue;
                }
                Err(_) => (),
            }

            // Try parsing as multiple single-line age identities.
            identities.push(Box::new(
                IdentityFile::from_file(filename.clone()).map_err(|e| match e.kind() {
                    io::ErrorKind::NotFound => file_not_found(filename),
                    _ => e.into(),
                })?,
            ));
        }
    }

    Ok(identities)
}

/// Requests a secret from the user.
///
/// If a `pinentry` binary is available on the system, it is used to request the secret.
/// If not, we fall back to requesting directly in the CLI via stdin.
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
        input
            .with_description(description)
            .with_prompt(prompt)
            .with_timeout(30);
        if let Some(confirm_prompt) = confirm {
            input.with_confirmation(confirm_prompt, "Inputs do not match");
        } else {
            input.required("Input is required");
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
                    "Inputs do not match",
                )));
            }
        } else if passphrase.expose_secret().is_empty() {
            return Err(pinentry::Error::Cancelled);
        }

        Ok(passphrase)
    }
}

/// Implementation of age callbacks that makes requests to the user via the UI.
pub struct UiCallbacks;

impl Callbacks for UiCallbacks {
    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        read_secret(description, "Passphrase", None).ok()
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
        "Type passphrase (leave empty to autogenerate a secure one)",
        "Passphrase",
        Some("Confirm passphrase"),
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
