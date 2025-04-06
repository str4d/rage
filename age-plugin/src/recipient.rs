//! Recipient plugin helpers.

use age_core::{
    format::{is_arbitrary_string, FileKey, Stanza},
    plugin::{self, BidirSend, Connection},
    secrecy::SecretString,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::FromBase32;

use std::collections::HashSet;
use std::convert::Infallible;
use std::io;

use crate::{Callbacks, PLUGIN_IDENTITY_PREFIX, PLUGIN_RECIPIENT_PREFIX};

const ADD_RECIPIENT: &str = "add-recipient";
const ADD_IDENTITY: &str = "add-identity";
const WRAP_FILE_KEY: &str = "wrap-file-key";
const EXTENSION_LABELS: &str = "extension-labels";
const RECIPIENT_STANZA: &str = "recipient-stanza";
const LABELS: &str = "labels";

/// The interface that age implementations will use to interact with an age plugin.
///
/// Implementations of this trait will be used within the [`recipient-v1`] state machine.
///
/// The trait methods are always called in this order:
/// - [`Self::add_recipient`] / [`Self::add_identity`] (in any order, including
///   potentially interleaved).
/// - [`Self::labels`] (once all recipients and identities have been added).
/// - [`Self::wrap_file_keys`]
///
/// [`recipient-v1`]: https://c2sp.org/age-plugin#wrapping-with-recipient-v1
pub trait RecipientPluginV1 {
    /// Stores a recipient that the user would like to encrypt age files to.
    ///
    /// `plugin_name` is the name of the binary that resolved to this plugin.
    ///
    /// Returns an error if the recipient is unknown or invalid.
    fn add_recipient(&mut self, index: usize, plugin_name: &str, bytes: &[u8])
        -> Result<(), Error>;

    /// Stores an identity that the user would like to encrypt age files to.
    ///
    /// `plugin_name` is the name of the binary that resolved to this plugin.
    ///
    /// Returns an error if the identity is unknown or invalid.
    fn add_identity(&mut self, index: usize, plugin_name: &str, bytes: &[u8]) -> Result<(), Error>;

    /// Returns labels that constrain how the stanzas produced by [`Self::wrap_file_keys`]
    /// may be combined with those from other recipients.
    ///
    /// Encryption will succeed only if every recipient returns the same set of labels.
    /// Subsets or partial overlapping sets are not allowed; all sets must be identical.
    /// Labels are compared exactly, and are case-sensitive.
    ///
    /// Label sets can be used to ensure a recipient is only encrypted to alongside other
    /// recipients with equivalent properties, or to ensure a recipient is always used
    /// alone. A recipient with no particular properties to enforce should return an empty
    /// label set.
    ///
    /// Labels can have any value that is a valid arbitrary string (`1*VCHAR` in ABNF),
    /// but usually take one of several forms:
    ///   - *Common public label* - used by multiple recipients to permit their stanzas to
    ///     be used only together. Examples include:
    ///     - `postquantum` - indicates that the recipient stanzas being generated are
    ///       postquantum-secure, and that they can only be combined with other stanzas
    ///       that are also postquantum-secure.
    ///   - *Common private label* - used by recipients created by the same private entity
    ///     to permit their recipient stanzas to be used only together. For example,
    ///     private recipients used in a corporate environment could all send the same
    ///     private label in order to prevent compliant age clients from simultaneously
    ///     wrapping file keys with other recipients.
    ///   - *Random label* - used by recipients that want to ensure their stanzas are not
    ///     used with any other recipient stanzas. This can be used to produce a file key
    ///     that is only encrypted to a single recipient stanza, for example to preserve
    ///     its authentication properties.
    fn labels(&mut self) -> HashSet<String>;

    /// Wraps each `file_key` to all recipients and identities previously added via
    /// `add_recipient` and `add_identity`.
    ///
    /// Returns a set of stanzas per file key that wrap it to each recipient and identity.
    /// Plugins may return more than one stanza per "actual recipient", e.g. to support
    /// multiple formats, to build group aliases, or to act as a proxy.
    ///
    /// If one or more recipients or identities could not be wrapped to, no stanzas are
    /// returned for any of the file keys.
    ///
    /// `callbacks` can be used to interact with the user, to have them take some physical
    /// action or request a secret value.
    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        callbacks: impl Callbacks<Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<Error>>>;
}

impl RecipientPluginV1 for Infallible {
    fn add_recipient(&mut self, _: usize, _: &str, _: &[u8]) -> Result<(), Error> {
        // This is never executed.
        Ok(())
    }

    fn add_identity(&mut self, _: usize, _: &str, _: &[u8]) -> Result<(), Error> {
        // This is never executed.
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        // This is never executed.
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        _: Vec<FileKey>,
        _: impl Callbacks<Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<Error>>> {
        // This is never executed.
        Ok(Ok(vec![]))
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
            Error::Recipient { message, .. } => message,
            Error::Identity { message, .. } => message,
            Error::Internal { message } => message,
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
            Some(index) => vec![self.kind(), index],
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
    let ((recipients, identities), file_keys, labels_supported) = {
        let (recipients, identities, file_keys, labels_supported) = conn.unidir_receive(
            (ADD_RECIPIENT, |s| match (&s.args[..], &s.body[..]) {
                ([recipient], []) => Ok(recipient.clone()),
                _ => Err(Error::Internal {
                    message: format!(
                        "{} command must have exactly one metadata argument and no data",
                        ADD_RECIPIENT
                    ),
                }),
            }),
            (ADD_IDENTITY, |s| match (&s.args[..], &s.body[..]) {
                ([identity], []) => Ok(identity.clone()),
                _ => Err(Error::Internal {
                    message: format!(
                        "{} command must have exactly one metadata argument and no data",
                        ADD_IDENTITY
                    ),
                }),
            }),
            (Some(WRAP_FILE_KEY), |s| {
                // TODO: Should we ignore file key commands with unexpected metadata args?
                FileKey::try_init_with_mut(|file_key| {
                    if s.body.len() == file_key.len() {
                        file_key.copy_from_slice(&s.body);
                        Ok(())
                    } else {
                        Err(Error::Internal {
                            message: "invalid file key length".to_owned(),
                        })
                    }
                })
            }),
            (Some(EXTENSION_LABELS), |_| Ok(())),
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
            match &labels_supported.unwrap() {
                Ok(v) if v.is_empty() => Ok(false),
                Ok(v) if v.len() == 1 => Ok(true),
                _ => Err(vec![Error::Internal {
                    message: format!("Received more than one {} command", EXTENSION_LABELS),
                }]),
            },
        )
    };

    // Now that we have the full list of recipients and identities, parse them as Bech32
    // and add them to the plugin.
    fn parse_and_add(
        items: Result<Vec<String>, Vec<Error>>,
        plugin_name: impl Fn(&str) -> Option<&str>,
        error: impl Fn(usize) -> Error,
        mut adder: impl FnMut(usize, &str, Vec<u8>) -> Result<(), Error>,
    ) -> Result<usize, Vec<Error>> {
        items.and_then(|items| {
            let count = items.len();
            let errors: Vec<_> = items
                .into_iter()
                .enumerate()
                .map(|(index, item)| {
                    let decoded = bech32::decode(&item).ok();
                    decoded
                        .as_ref()
                        .and_then(|(hrp, data, variant)| match (plugin_name(hrp), variant) {
                            (Some(plugin_name), &bech32::Variant::Bech32) => {
                                Vec::from_base32(data).ok().map(|data| (plugin_name, data))
                            }
                            _ => None,
                        })
                        .ok_or_else(|| error(index))
                        .and_then(|(plugin_name, bytes)| adder(index, plugin_name, bytes))
                })
                .filter_map(|res| res.err())
                .collect();

            if errors.is_empty() {
                Ok(count)
            } else {
                Err(errors)
            }
        })
    }
    let recipients = parse_and_add(
        recipients,
        |hrp| hrp.strip_prefix(PLUGIN_RECIPIENT_PREFIX),
        |index| Error::Recipient {
            index,
            message: "Invalid recipient encoding".to_owned(),
        },
        |index, plugin_name, bytes| plugin.add_recipient(index, plugin_name, &bytes),
    );
    let identities = parse_and_add(
        identities,
        |hrp| {
            if hrp.starts_with(PLUGIN_IDENTITY_PREFIX) && hrp.ends_with('-') {
                Some(&hrp[PLUGIN_IDENTITY_PREFIX.len()..hrp.len() - 1])
            } else {
                None
            }
        },
        |index| Error::Identity {
            index,
            message: "Invalid identity encoding".to_owned(),
        },
        |index, plugin_name, bytes| plugin.add_identity(index, plugin_name, &bytes),
    );

    let required_labels = plugin.labels();

    let labels = match (labels_supported, required_labels.is_empty()) {
        (Ok(true), _) | (Ok(false), true) => {
            if required_labels.contains("") {
                Err(vec![Error::Internal {
                    message: "Plugin tried to use the empty string as a label".into(),
                }])
            } else if required_labels.iter().all(is_arbitrary_string) {
                Ok(required_labels)
            } else {
                Err(vec![Error::Internal {
                    message: "Plugin tried to use a label containing an invalid character".into(),
                }])
            }
        }
        (Ok(false), false) => Err(vec![Error::Internal {
            message: "Plugin requires labels but client does not support them".into(),
        }]),
        (Err(errors), true) => Err(errors),
        (Err(mut errors), false) => {
            errors.push(Error::Internal {
                message: "Plugin requires labels but client does not support them".into(),
            });
            Err(errors)
        }
    };

    // Phase 2: wrap the file keys or return errors
    conn.bidir_send(|mut phase| {
        let (expected_stanzas, file_keys, labels) =
            match (recipients, identities, file_keys, labels) {
                (Ok(recipients), Ok(identities), Ok(file_keys), Ok(labels)) => {
                    (recipients + identities, file_keys, labels)
                }
                (recipients, identities, file_keys, labels) => {
                    for error in recipients
                        .err()
                        .into_iter()
                        .chain(identities.err())
                        .chain(file_keys.err())
                        .chain(labels.err())
                        .flatten()
                    {
                        error.send(&mut phase)?;
                    }
                    return Ok(());
                }
            };

        let labels = labels.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        // We confirmed above that if `labels` is non-empty, the client supports labels.
        // So we can unconditionally send this, and will only get an `unsupported`
        // response if `labels` is empty (where it does not matter).
        let _ = phase.send(LABELS, &labels, &[])?;

        match plugin.wrap_file_keys(file_keys, BidirCallbacks(&mut phase))? {
            Ok(files) => {
                for (file_index, stanzas) in files.into_iter().enumerate() {
                    // The plugin MUST generate an error if one or more recipients or
                    // identities cannot be wrapped to. And it's a programming error
                    // to return more stanzas than recipients and identities.
                    assert_eq!(stanzas.len(), expected_stanzas);

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

        Ok(())
    })
}
