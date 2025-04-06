//! Identity plugin helpers.

use age_core::{
    format::{FileKey, Stanza},
    plugin::{self, BidirSend, Connection},
    secrecy::{ExposeSecret, SecretString},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::FromBase32;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;

use crate::{Callbacks, PLUGIN_IDENTITY_PREFIX};

const ADD_IDENTITY: &str = "add-identity";
const RECIPIENT_STANZA: &str = "recipient-stanza";

/// The interface that age implementations will use to interact with an age plugin.
///
/// Implementations of this trait will be used within the [`identity-v1`] state machine.
///
/// [`identity-v1`]: https://c2sp.org/age-plugin#unwrapping-with-identity-v1
pub trait IdentityPluginV1 {
    /// Stores an identity that the user would like to use for decrypting age files.
    ///
    /// `plugin_name` is the name of the binary that resolved to this plugin.
    ///
    /// Returns an error if the identity is unknown or invalid.
    fn add_identity(&mut self, index: usize, plugin_name: &str, bytes: &[u8]) -> Result<(), Error>;

    /// Attempts to unwrap the file keys contained within the given age recipient stanzas,
    /// using identities previously stored via [`add_identity`].
    ///
    /// Returns a `HashMap` containing the unwrapping results for each file:
    ///
    /// - A list of errors, if any stanzas for a file cannot be unwrapped that detectably
    ///   should be unwrappable.
    ///
    /// - A [`FileKey`], if any stanza for a file can be successfully unwrapped.
    ///
    /// Note that if all known and valid stanzas for a given file cannot be unwrapped, and
    /// none are expected to be unwrappable, that file has no entry in the `HashMap`. That
    /// is, file keys that cannot be unwrapped are implicit.
    ///
    /// `callbacks` can be used to interact with the user, to have them take some physical
    /// action or request a secret value.
    ///
    /// [`add_identity`]: IdentityPluginV1::add_identity
    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        callbacks: impl Callbacks<Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<Error>>>>;
}

impl IdentityPluginV1 for Infallible {
    fn add_identity(&mut self, _: usize, _: &str, _: &[u8]) -> Result<(), Error> {
        // This is never executed.
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        _: Vec<Vec<Stanza>>,
        _: impl Callbacks<Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<Error>>>> {
        // This is never executed.
        Ok(HashMap::new())
    }
}

/// The interface that age plugins can use to interact with an age implementation.
struct BidirCallbacks<'a, 'b, R: io::Read, W: io::Write>(&'b mut BidirSend<'a, R, W>);

impl<'a, 'b, R: io::Read, W: io::Write> Callbacks<Error> for BidirCallbacks<'a, 'b, R, W> {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn message(&mut self, message: &str) -> plugin::Result<()> {
        self.0
            .send("msg", &[], message.as_bytes())
            .map(|res| res.map(|_| ()))
    }

    fn confirm(
        &mut self,
        message: &str,
        yes_string: &str,
        no_string: Option<&str>,
    ) -> age_core::plugin::Result<bool> {
        let metadata: Vec<_> = Some(yes_string)
            .into_iter()
            .chain(no_string)
            .map(|s| BASE64_STANDARD_NO_PAD.encode(s))
            .collect();
        let metadata: Vec<_> = metadata.iter().map(|s| s.as_str()).collect();

        self.0
            .send("confirm", &metadata, message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => match &s.args[..] {
                    [x] if x == "yes" => Ok(Ok(true)),
                    [x] if x == "no" => Ok(Ok(false)),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid response to confirm command",
                    )),
                },
                Err(e) => Ok(Err(e)),
            })
    }

    fn request_public(&mut self, message: &str) -> plugin::Result<String> {
        self.0
            .send("request-public", &[], message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => String::from_utf8(s.body)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "response is not UTF-8")
                    })
                    .map(Ok),
                Err(e) => Ok(Err(e)),
            })
    }

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> plugin::Result<SecretString> {
        self.0
            .send("request-secret", &[], message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => String::from_utf8(s.body)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret is not UTF-8"))
                    .map(|s| Ok(SecretString::from(s))),
                Err(e) => Ok(Err(e)),
            })
    }

    fn error(&mut self, error: Error) -> plugin::Result<()> {
        error.send(self.0).map(|()| Ok(()))
    }
}

/// The kinds of errors that can occur within the identity plugin state machine.
pub enum Error {
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
    /// An error caused by a specific stanza.
    ///
    /// Note that unknown stanzas MUST be ignored by plugins; this error is only for
    /// stanzas that have a supported tag but are otherwise invalid (indicating an invalid
    /// age file).
    Stanza {
        /// The index of the file containing the stanza.
        file_index: usize,
        /// The index of the stanza within the file.
        stanza_index: usize,
        /// The error message.
        message: String,
    },
}

impl Error {
    fn kind(&self) -> &str {
        match self {
            Error::Identity { .. } => "identity",
            Error::Internal { .. } => "internal",
            Error::Stanza { .. } => "stanza",
        }
    }

    fn message(&self) -> &str {
        match self {
            Error::Identity { message, .. } => message,
            Error::Internal { message } => message,
            Error::Stanza { message, .. } => message,
        }
    }

    fn send<R: io::Read, W: io::Write>(self, phase: &mut BidirSend<R, W>) -> io::Result<()> {
        let index = match self {
            Error::Identity { index, .. } => Some((index.to_string(), None)),
            Error::Internal { .. } => None,
            Error::Stanza {
                file_index,
                stanza_index,
                ..
            } => Some((file_index.to_string(), Some(stanza_index.to_string()))),
        };

        let metadata = match &index {
            Some((file_index, Some(stanza_index))) => vec![self.kind(), file_index, stanza_index],
            Some((index, None)) => vec![self.kind(), index],
            None => vec![self.kind()],
        };

        phase
            .send("error", &metadata, self.message().as_bytes())?
            .unwrap();

        Ok(())
    }
}

/// Runs the identity plugin v1 protocol.
pub(crate) fn run_v1<P: IdentityPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: receive identities and stanzas
    let (identities, recipient_stanzas) = {
        let (identities, stanzas, _, _) = conn.unidir_receive(
            (ADD_IDENTITY, |s| match (&s.args[..], &s.body[..]) {
                ([identity], []) => Ok(identity.clone()),
                _ => Err(Error::Internal {
                    message: format!(
                        "{} command must have exactly one metadata argument and no data",
                        ADD_IDENTITY
                    ),
                }),
            }),
            (RECIPIENT_STANZA, |mut s| {
                if s.args.len() >= 2 {
                    let file_index = s.args.remove(0);
                    s.tag = s.args.remove(0);
                    file_index
                        .parse::<usize>()
                        .map(|i| (i, s))
                        .map_err(|_| Error::Internal {
                            message: format!(
                                "first metadata argument to {} must be an integer",
                                RECIPIENT_STANZA
                            ),
                        })
                } else {
                    Err(Error::Internal {
                        message: format!(
                            "{} command must have at least two metadata arguments",
                            RECIPIENT_STANZA
                        ),
                    })
                }
            }),
            (None, |_| Ok(())),
            (None, |_| Ok(())),
        )?;

        // Now that we have the full list of identities, parse them as Bech32 and add them
        // to the plugin.
        let identities = identities.and_then(|items| {
            let errors: Vec<_> = items
                .into_iter()
                .enumerate()
                .map(|(index, item)| {
                    bech32::decode(&item)
                        .ok()
                        .and_then(|(hrp, data, variant)| {
                            if hrp.starts_with(PLUGIN_IDENTITY_PREFIX)
                                && hrp.ends_with('-')
                                && variant == bech32::Variant::Bech32
                            {
                                Vec::from_base32(&data).ok().map(|data| (hrp, data))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| Error::Identity {
                            index,
                            message: "Invalid identity encoding".to_owned(),
                        })
                        .and_then(|(hrp, bytes)| {
                            plugin.add_identity(
                                index,
                                &hrp[PLUGIN_IDENTITY_PREFIX.len()..hrp.len() - 1],
                                &bytes,
                            )
                        })
                })
                .filter_map(|res| res.err())
                .collect();

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        });

        let stanzas = stanzas.and_then(|recipient_stanzas| {
            let mut stanzas: Vec<Vec<Stanza>> = Vec::new();
            let mut errors: Vec<Error> = vec![];
            for (file_index, stanza) in recipient_stanzas {
                if let Some(file) = stanzas.get_mut(file_index) {
                    file.push(stanza);
                } else if stanzas.len() == file_index {
                    stanzas.push(vec![stanza]);
                } else {
                    errors.push(Error::Internal {
                        message: format!(
                            "{} file indices are not ordered and monotonically increasing",
                            RECIPIENT_STANZA
                        ),
                    });
                }
            }
            if errors.is_empty() {
                Ok(stanzas)
            } else {
                Err(errors)
            }
        });

        (identities, stanzas)
    };

    // Phase 2: interactively unwrap
    conn.bidir_send(|mut phase| {
        let stanzas = match (identities, recipient_stanzas) {
            (Ok(()), Ok(stanzas)) => stanzas,
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

        let unwrapped = plugin.unwrap_file_keys(stanzas, BidirCallbacks(&mut phase))?;

        for (file_index, file_key) in unwrapped {
            match file_key {
                Ok(file_key) => {
                    phase
                        .send(
                            "file-key",
                            &[&format!("{}", file_index)],
                            file_key.expose_secret(),
                        )?
                        .unwrap();
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
