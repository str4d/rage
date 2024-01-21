//! Common helpers for CLI binaries.

use age_core::secrecy::{ExposeSecret, SecretString};
use pinentry::{ConfirmationDialog, PassphraseInput};
use rand::{
    distributions::{Distribution, Uniform},
    rngs::OsRng,
    CryptoRng, RngCore,
};
use rpassword::prompt_password;

use std::fs::File;
use std::io::{self, BufReader};
use subtle::ConstantTimeEq;

use crate::{fl, identity::IdentityFile, Callbacks, Identity};

#[cfg(feature = "armor")]
use crate::armor::ArmoredReader;

mod error;
pub use error::ReadError;

pub mod file_io;

const BIP39_WORDLIST: &str = include_str!("../assets/bip39-english.txt");

/// Reads identities from the provided files.
pub fn read_identities(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
) -> Result<Vec<Box<dyn Identity>>, ReadError> {
    let mut identities: Vec<Box<dyn Identity>> = Vec::with_capacity(filenames.len());

    parse_identity_files::<_, ReadError>(
        filenames,
        max_work_factor,
        &mut identities,
        |identities, identity| {
            identities.push(Box::new(identity));
            Ok(())
        },
        |identities, _, identity| {
            identities.push(Box::new(identity.with_callbacks(UiCallbacks)));
            Ok(())
        },
        |identities, entry| {
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

            // IdentityFileEntry::into_identity will never return a MissingPlugin error
            // when plugin feature is not enabled.
            #[cfg(not(feature = "plugin"))]
            let entry = entry.unwrap();

            identities.push(entry);

            Ok(())
        },
    )?;

    Ok(identities)
}

/// Parses the provided identity files.
pub fn parse_identity_files<Ctx, E: From<ReadError> + From<io::Error>>(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
    ctx: &mut Ctx,
    #[cfg(feature = "armor")] encrypted_identity: impl Fn(
        &mut Ctx,
        crate::encrypted::Identity<ArmoredReader<BufReader<File>>, UiCallbacks>,
    ) -> Result<(), E>,
    #[cfg(feature = "ssh")] ssh_identity: impl Fn(&mut Ctx, &str, crate::ssh::Identity) -> Result<(), E>,
    identity_file_entry: impl Fn(&mut Ctx, crate::IdentityFileEntry) -> Result<(), E>,
) -> Result<(), E> {
    for filename in filenames {
        let mut reader = PeekableReader::new(BufReader::new(File::open(&filename).map_err(
            |e| match e.kind() {
                io::ErrorKind::NotFound => ReadError::IdentityNotFound(filename.clone()),
                _ => e.into(),
            },
        )?));

        #[cfg(feature = "armor")]
        // Try parsing as an encrypted age identity.
        if crate::encrypted::Identity::from_buffer(
            ArmoredReader::new_buffered(&mut reader),
            Some(filename.clone()),
            UiCallbacks,
            max_work_factor,
        )
        .is_ok()
        {
            // Re-parse while taking ownership of the reader. This will always succeed
            // because the age ciphertext header size is less than the underlying buffer
            // size, but the manual reset here ensures this fails gracefully if for
            // whatever reason the underlying buffer size changes unexpectedly.
            reader.reset()?;
            let identity = crate::encrypted::Identity::from_buffer(
                ArmoredReader::new_buffered(reader.inner),
                Some(filename.clone()),
                UiCallbacks,
                max_work_factor,
            )
            .expect("already parsed the age ciphertext header");

            encrypted_identity(
                ctx,
                identity.ok_or(ReadError::IdentityEncryptedWithoutPassphrase(filename))?,
            )?;
            continue;
        }

        #[cfg(feature = "armor")]
        reader.reset()?;

        // Try parsing as a single multi-line SSH identity.
        #[cfg(feature = "ssh")]
        match crate::ssh::Identity::from_buffer(&mut reader, Some(filename.clone())) {
            Ok(crate::ssh::Identity::Unsupported(k)) => {
                return Err(ReadError::UnsupportedKey(filename, k).into())
            }
            Ok(identity) => {
                ssh_identity(ctx, &filename, identity)?;
                continue;
            }
            Err(_) => (),
        }

        #[cfg(feature = "ssh")]
        reader.reset()?;

        // Try parsing as multiple single-line age identities.
        let identity_file = IdentityFile::from_buffer(reader)?;

        for entry in identity_file.into_identities() {
            identity_file_entry(ctx, entry)?;
        }
    }

    Ok(())
}

enum PeekState {
    Peeking { consumed: usize },
    Reading,
}

pub(crate) struct PeekableReader<R: io::BufRead> {
    inner: R,
    state: PeekState,
}

impl<R: io::BufRead> PeekableReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: PeekState::Peeking { consumed: 0 },
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        match &mut self.state {
            PeekState::Peeking { consumed } => {
                *consumed = 0;
                Ok(())
            }
            PeekState::Reading => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tried to reset after the underlying buffer was exceeded.",
            )),
        }
    }
}

impl<R: io::BufRead> io::Read for PeekableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.state {
            PeekState::Peeking { .. } => {
                // Perform a read that will never exceed the size of the inner buffer.
                use std::io::BufRead;
                let nread = {
                    let mut rem = self.fill_buf()?;
                    rem.read(buf)?
                };
                self.consume(nread);
                Ok(nread)
            }
            PeekState::Reading => self.inner.read(buf),
        }
    }
}

impl<R: io::BufRead> io::BufRead for PeekableReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self.state {
            PeekState::Peeking { consumed } => {
                if consumed < self.inner.fill_buf()?.len() {
                    // Re-call so we aren't extending the lifetime of the mutable borrow
                    // on `self.inner` to outside the conditional, which would prevent us
                    // from performing other mutable operations on the other side.
                    Ok(&self.inner.fill_buf()?[consumed..])
                } else {
                    // We're done peeking.
                    self.inner.consume(consumed);
                    self.state = PeekState::Reading;
                    self.inner.fill_buf()
                }
            }
            PeekState::Reading => self.inner.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.state {
            PeekState::Peeking { consumed, .. } => *consumed += amt,
            PeekState::Reading => self.inner.consume(amt),
        }
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
