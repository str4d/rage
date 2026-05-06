//! Common helpers for CLI binaries.

use age_core::secrecy::{ExposeSecret, SecretString};
use pinentry::{ConfirmationDialog, PassphraseInput};
use rand::{
    distributions::{Distribution, Uniform},
    rngs::OsRng,
    CryptoRng, RngCore,
};
use rpassword::prompt_password;

use std::io;
use std::process::Command;
use subtle::ConstantTimeEq;

use crate::{fl, Callbacks};

mod error;
pub use error::ReadError;

pub mod file_io;

mod identities;
pub use identities::read_identities;

mod recipients;
pub use recipients::read_recipients;

const BIP39_WORDLIST: &str = include_str!("../assets/bip39-english.txt");

/// A guard that helps to ensure that standard input is only used once.
pub struct StdinGuard {
    stdin_used: bool,
}

impl StdinGuard {
    /// Constructs a new `StdinGuard`.
    ///
    /// `input_is_stdin` should be set to `true` if standard input is being used for
    /// plaintext input during encryption, or ciphertext input during decryption.
    pub fn new(input_is_stdin: bool) -> Self {
        Self {
            stdin_used: input_is_stdin,
        }
    }

    fn open(&mut self, filename: String) -> Result<file_io::InputReader, ReadError> {
        let input = file_io::InputReader::new(Some(filename))?;
        if matches!(input, file_io::InputReader::Stdin(_)) {
            if self.stdin_used {
                return Err(ReadError::MultipleStdin);
            }
            self.stdin_used = true;
        }
        Ok(input)
    }
}

fn confirm(query: &str, ok: &str, cancel: Option<&str>) -> pinentry::Result<bool> {
    if let Some(mut input) = ConfirmationDialog::with_default_binary() {
        // pinentry binary is available!
        input.with_ok(ok).with_timeout(30);
        if let Some(cancel) = cancel {
            input.with_cancel(cancel);
        }
        input.confirm(query)
    } else {
        // Fall back to CLI interface.
        let term = console::Term::stderr();
        let initial = format!("{}: (y/n) ", query);
        loop {
            term.write_str(&initial)?;
            let response = term.read_line()?.to_lowercase();
            if ["y", "yes"].contains(&response.as_str()) {
                break Ok(true);
            } else if ["n", "no"].contains(&response.as_str()) {
                break Ok(false);
            }
        }
    }
}

/// Requests a secret via an external askpass program.
///
/// Follows the same convention as `SSH_ASKPASS`: the program receives the prompt as
/// its first argument, prints the secret to stdout, and exits 0 on success or non-zero
/// on cancel/failure.
fn read_secret_askpass(askpass: &str, description: &str) -> pinentry::Result<SecretString> {
    let output = Command::new(askpass)
        .arg(description)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| {
            pinentry::Error::Io(io::Error::new(
                e.kind(),
                format!("failed to run AGE_ASKPASS program '{}': {}", askpass, e),
            ))
        })?;

    if !output.status.success() {
        return Err(pinentry::Error::Cancelled);
    }

    let secret = String::from_utf8(output.stdout)
        .map_err(|_| {
            pinentry::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "AGE_ASKPASS program returned non-UTF-8 output",
            ))
        })?
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();

    if secret.is_empty() {
        return Err(pinentry::Error::Cancelled);
    }

    Ok(SecretString::from(secret))
}

/// Requests a secret from the user.
///
/// The secret is obtained using the following priority:
/// 1. If `AGE_ASKPASS` is set, the specified program is called with the prompt as its
///    first argument (following the `SSH_ASKPASS` convention).
/// 2. If a `pinentry` binary is available on the system, it is used to request the secret.
/// 3. Otherwise, we fall back to requesting directly in the CLI via a TTY.
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
    // First priority: AGE_ASKPASS external program (SSH_ASKPASS-style convention).
    if let Ok(askpass) = std::env::var("AGE_ASKPASS") {
        if !askpass.is_empty() {
            let secret = read_secret_askpass(&askpass, description)?;
            if let Some(confirm_prompt) = confirm {
                let confirmed = read_secret_askpass(&askpass, confirm_prompt)?;
                if !bool::from(
                    secret
                        .expose_secret()
                        .as_bytes()
                        .ct_eq(confirmed.expose_secret().as_bytes()),
                ) {
                    return Err(pinentry::Error::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        fl!("cli-secret-input-mismatch"),
                    )));
                }
            }
            return Ok(secret);
        }
    }

    // Second priority: pinentry binary.
    // Check for the pinentry environment variable. If it's not present try to use the default
    // binary.
    let input = if let Ok(pinentry) = std::env::var("PINENTRY_PROGRAM") {
        PassphraseInput::with_binary(pinentry)
    } else {
        PassphraseInput::with_default_binary()
    };

    if let Some(mut input) = input {
        // User-set or default pinentry binary is available!
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
        let passphrase = prompt_password(format!("{}: ", description)).map(SecretString::from)?;
        if let Some(confirm_prompt) = confirm {
            let confirm_passphrase =
                prompt_password(format!("{}: ", confirm_prompt)).map(SecretString::from)?;

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

    fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool> {
        confirm(message, yes_string, no_string).ok()
    }

    fn request_public_string(&self, description: &str) -> Option<String> {
        let term = console::Term::stderr();
        term.write_str(description).ok()?;
        term.read_line().ok().filter(|s| !s.is_empty())
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
        Passphrase::Generated(SecretString::from(new_passphrase))
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
