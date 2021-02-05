//! Recipient plugin helpers.

use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    plugin::{self, BidirSend, Connection},
};
use secrecy::SecretString;
use std::convert::TryInto;
use std::io;

use crate::Callbacks;

const ADD_RECIPIENT: &str = "add-recipient";
const ADD_IDENTITY: &str = "add-identity";
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

    /// Stores identities that the user would like to encrypt age files to.
    ///
    /// Each identity string is Bech32-encoded with an HRP of `AGE-PLUGIN-NAME-` where
    /// `NAME` is the name of the plugin that resolved to this binary.
    ///
    /// Returns a list of errors if any of the identities are unknown or invalid.
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<Error>>;

    /// Wraps each `file_key` to all recipients and identities previously added via
    /// `add_recipients` and `add_identities`.
    ///
    /// Returns either one stanza per recipient and identity for each file key, or any
    /// errors if one or more recipients or identities could not be wrapped to.
    ///
    /// `callbacks` can be used to interact with the user, to have them take some physical
    /// action or request a secret value.
    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        callbacks: impl Callbacks<Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<Error>>>;
}

/// The interface that age plugins can use to interact with an age implementation.
struct BidirCallbacks<'a, 'b, R: io::Read, W: io::Write>(&'b mut BidirSend<'a, R, W>);

impl<'a, 'b, R: io::Read, W: io::Write> Callbacks<Error> for BidirCallbacks<'a, 'b, R, W> {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn message(&mut self, message: &str) -> plugin::Result<(), ()> {
        self.0
            .send("msg", &[], message.as_bytes())
            .map(|res| res.map(|_| ()))
    }

    fn request_public(&mut self, message: &str) -> plugin::Result<String, ()> {
        self.0
            .send("request-public", &[], message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => String::from_utf8(s.body)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "response is not UTF-8")
                    })
                    .map(Ok),
                Err(()) => Ok(Err(())),
            })
    }

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> plugin::Result<SecretString, ()> {
        self.0
            .send("request-secret", &[], message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => String::from_utf8(s.body)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret is not UTF-8"))
                    .map(|s| Ok(SecretString::new(s))),
                Err(()) => Ok(Err(())),
            })
    }

    fn error(&mut self, error: Error) -> plugin::Result<(), ()> {
        error.send(self.0).map(|()| Ok(()))
    }
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
    /// An error caused by a specific identity.
    Identity {
        /// The index of the identity.
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
            Error::Identity { .. } => "identity",
            Error::Internal { .. } => "internal",
        }
    }

    fn message(&self) -> &str {
        match self {
            Error::Recipient { message, .. } => &message,
            Error::Identity { message, .. } => &message,
            Error::Internal { message } => &message,
        }
    }

    fn send<R: io::Read, W: io::Write>(self, phase: &mut BidirSend<R, W>) -> io::Result<()> {
        let index = match self {
            Error::Recipient { index, .. } | Error::Identity { index, .. } => {
                Some(index.to_string())
            }
            Error::Internal { .. } => None,
        };

        let metadata = match &index {
            Some(index) => vec![self.kind(), &index],
            None => vec![self.kind()],
        };

        phase
            .send("error", &metadata, self.message().as_bytes())?
            .unwrap();

        Ok(())
    }
}

/// Runs the recipient plugin v1 protocol.
pub(crate) fn run_v1<P: RecipientPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: collect recipients, and file keys to be wrapped
    let ((recipients, identities), file_keys) = {
        let (recipients, identities, file_keys) = conn.unidir_receive(
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
            (ADD_IDENTITY, |s| {
                if s.args.len() == 1 && s.body.is_empty() {
                    Ok(s)
                } else {
                    Err(Error::Internal {
                        message: format!(
                            "{} command must have exactly one metadata argument and no data",
                            ADD_IDENTITY
                        ),
                    })
                }
            }),
            (Some(WRAP_FILE_KEY), |s| {
                // TODO: Should we ignore file key commands with unexpected metadata args?
                TryInto::<[u8; FILE_KEY_BYTES]>::try_into(&s.body[..])
                    .map_err(|_| Error::Internal {
                        message: "invalid file key length".to_owned(),
                    })
                    .map(FileKey::from)
            }),
        )?;
        (
            match (recipients, identities) {
                (Ok(r), Ok(i)) if r.is_empty() && i.is_empty() => (
                    Err(vec![Error::Internal {
                        message: format!(
                            "Need at least one {} or {} command",
                            ADD_RECIPIENT, ADD_IDENTITY
                        ),
                    }]),
                    Err(vec![]),
                ),
                r => r,
            },
            match file_keys.unwrap() {
                Ok(f) if f.is_empty() => Err(vec![Error::Internal {
                    message: format!("Need at least one {} command", WRAP_FILE_KEY),
                }]),
                r => r,
            },
        )
    };

    // Phase 2: wrap the file keys or return errors
    conn.bidir_send(|mut phase| {
        let (recipients, identities, file_keys) = match (recipients, identities, file_keys) {
            (Ok(recipients), Ok(identities), Ok(file_keys)) => (recipients, identities, file_keys),
            (recipients, identities, file_keys) => {
                for error in recipients
                    .err()
                    .into_iter()
                    .chain(identities.err())
                    .chain(file_keys.err())
                    .flatten()
                {
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
        } else if let Err(errors) =
            plugin.add_identities(identities.iter().map(|s| s.args.first().unwrap().as_str()))
        {
            for error in errors {
                error.send(&mut phase)?;
            }
        } else {
            match plugin.wrap_file_keys(file_keys, BidirCallbacks(&mut phase))? {
                Ok(files) => {
                    for (file_index, stanzas) in files.into_iter().enumerate() {
                        // The plugin MUST generate an error if one or more recipients or
                        // identities cannot be wrapped to. And it's a programming error
                        // to return more stanzas than recipients and identities.
                        assert_eq!(stanzas.len(), recipients.len() + identities.len());

                        for stanza in stanzas {
                            phase
                                .send_stanza(RECIPIENT_STANZA, &[&file_index.to_string()], &stanza)?
                                .unwrap();
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
