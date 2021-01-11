//! Recipient plugin helpers.

use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    plugin::{Connection, UnidirSend},
};
use std::convert::TryInto;
use std::io;

const ADD_RECIPIENT: &str = "add-recipient";
const WRAP_FILE_KEY: &str = "wrap-file-key";
const RECIPIENT_STANZA: &str = "recipient-stanza";

/// The interface that age implementations will use to interact with an age plugin.
pub trait RecipientPluginV1 {
    /// Stores recipients that the user would like to encrypt age files to.
    ///
    /// Each recipient string is Bech32-encoded with an HRP of `age1name` where `name` is
    /// the name of the plugin that resolved to this binary.
    ///
    /// Returns a list of errors if any of the recipients are unknown or invalid.
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<Error>>;

    /// Wraps `file_key` to all recipients previously added via `add_recipients`.
    ///
    /// Returns either one stanza per recipient, or any errors if one or more recipients
    /// could not be wrapped to.
    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<Error>>;
}

/// The kinds of errors that can occur within the recipient plugin state machine.
pub enum Error {
    /// An error caused by a specific recipient.
    Recipient {
        /// The index of the recipient.
        index: usize,
        /// The error message.
        message: String,
    },
    /// A general error that occured inside the state machine.
    Internal {
        /// The error message.
        message: String,
    },
}

impl Error {
    fn kind(&self) -> &str {
        match self {
            Error::Recipient { .. } => "recipient",
            Error::Internal { .. } => "internal",
        }
    }

    fn message(&self) -> &str {
        match self {
            Error::Recipient { message, .. } => &message,
            Error::Internal { message } => &message,
        }
    }

    fn send<R: io::Read, W: io::Write>(self, phase: &mut UnidirSend<R, W>) -> io::Result<()> {
        let index = match self {
            Error::Recipient { index, .. } => Some(index.to_string()),
            Error::Internal { .. } => None,
        };

        let metadata = match &index {
            Some(index) => vec![self.kind(), &index],
            None => vec![self.kind()],
        };

        phase.send("error", &metadata, self.message().as_bytes())
    }
}

/// Runs the recipient plugin v1 protocol.
pub(crate) fn run_v1<P: RecipientPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: collect recipients, and file keys to be wrapped
    let (recipients, file_keys) = {
        let (recipients, file_keys) = conn.unidir_receive(
            (ADD_RECIPIENT, |s| {
                if s.args.len() == 1 && s.body.is_empty() {
                    Ok(s)
                } else {
                    Err(Error::Internal {
                        message: format!(
                            "{} command must have exactly one metadata argument and no data",
                            ADD_RECIPIENT
                        ),
                    })
                }
            }),
            (WRAP_FILE_KEY, |s| {
                // TODO: Should we ignore file key commands with unexpected metadata args?
                TryInto::<[u8; FILE_KEY_BYTES]>::try_into(&s.body[..])
                    .map_err(|_| Error::Internal {
                        message: "invalid file key length".to_owned(),
                    })
                    .map(FileKey::from)
            }),
        )?;
        (
            match recipients {
                Ok(r) if r.is_empty() => Err(vec![Error::Internal {
                    message: format!("Need at least one {} command", ADD_RECIPIENT),
                }]),
                r => r,
            },
            match file_keys {
                Ok(f) if f.is_empty() => Err(vec![Error::Internal {
                    message: format!("Need at least one {} command", WRAP_FILE_KEY),
                }]),
                r => r,
            },
        )
    };

    // Phase 2: wrap the file keys or return errors
    conn.unidir_send(|mut phase| {
        let (recipients, file_keys) = match (recipients, file_keys) {
            (Ok(recipients), Ok(file_keys)) => (recipients, file_keys),
            (Err(errors1), Err(errors2)) => {
                for error in errors1.into_iter().chain(errors2.into_iter()) {
                    error.send(&mut phase)?;
                }
                return Ok(());
            }
            (Err(errors), _) | (_, Err(errors)) => {
                for error in errors {
                    error.send(&mut phase)?;
                }
                return Ok(());
            }
        };

        if let Err(errors) =
            plugin.add_recipients(recipients.iter().map(|s| s.args.first().unwrap().as_str()))
        {
            for error in errors {
                error.send(&mut phase)?;
            }
        } else {
            match file_keys
                .into_iter()
                .map(|file_key| plugin.wrap_file_key(&file_key))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(files) => {
                    for (file_index, stanzas) in files.into_iter().enumerate() {
                        // The plugin MUST generate an error if one or more
                        // recipients cannot be wrapped to. And it's a programming
                        // error to return more stanzas than recipients.
                        assert_eq!(stanzas.len(), recipients.len());

                        for stanza in stanzas {
                            phase.send_stanza(
                                RECIPIENT_STANZA,
                                &[&file_index.to_string()],
                                &stanza,
                            )?;
                        }
                    }
                }
                Err(errors) => {
                    for error in errors {
                        error.send(&mut phase)?;
                    }
                }
            }
        }

        Ok(())
    })
}
