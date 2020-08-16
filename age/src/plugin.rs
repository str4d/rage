//! Support for the age plugin system.

use age_core::{
    format::{FileKey, Stanza},
    plugin::{Connection, RECIPIENT_V1},
};
use secrecy::ExposeSecret;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};

use crate::{
    error::{EncryptError, PluginError},
    util::parse_bech32,
};

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";

const CMD_ERROR: &str = "error";
const CMD_RECIPIENT_STANZA: &str = "recipient-stanza";

fn binary_name(plugin_name: &str) -> String {
    format!("age-plugin-{}", plugin_name)
}

/// A plugin-compatible recipient.
#[derive(Clone)]
pub struct Recipient {
    /// The plugin name, extracted from `recipient`.
    name: String,
    /// The recipient.
    recipient: String,
}

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a plugin recipient from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, _)| {
                if hrp.len() > PLUGIN_RECIPIENT_PREFIX.len()
                    && hrp.starts_with(PLUGIN_RECIPIENT_PREFIX)
                {
                    Ok(Recipient {
                        name: hrp.split_at(PLUGIN_RECIPIENT_PREFIX.len()).1.to_owned(),
                        recipient: s.to_owned(),
                    })
                } else {
                    Err("invalid HRP")
                }
            })
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.recipient)
    }
}

impl Recipient {
    /// Returns the plugin name for this recipient.
    pub fn plugin(&self) -> &str {
        &self.name
    }
}

/// An age plugin.
struct Plugin(PathBuf);

impl Plugin {
    /// Finds the age plugin with the given name in `$PATH`.
    ///
    /// On error, returns the binary name that could not be located.
    fn new(name: &str) -> Result<Self, String> {
        let binary_name = binary_name(name);
        which::which(&binary_name)
            .map(Plugin)
            .map_err(|_| binary_name)
    }

    fn connect(&self, state_machine: &str) -> io::Result<Connection<ChildStdout, ChildStdin>> {
        Connection::open(&self.0, state_machine)
    }
}

/// An age plugin with an associated set of recipients.
///
/// This struct implements [`Recipient`], enabling the plugin to encrypt a file to the
/// entire set of recipients.
pub struct RecipientPluginV1 {
    plugin: Plugin,
    recipients: Vec<Recipient>,
}

impl RecipientPluginV1 {
    /// Creates an age plugin from a plugin name and a list of recipients.
    ///
    /// The list of recipients will be filtered by the plugin name; recipients that don't
    /// match will be ignored.
    ///
    /// Returns an error if the plugin's binary cannot be found in `$PATH`.
    pub fn new(plugin_name: &str, recipients: &[Recipient]) -> Result<Self, EncryptError> {
        Plugin::new(plugin_name)
            .map_err(|binary_name| EncryptError::MissingPlugin { binary_name })
            .map(|plugin| RecipientPluginV1 {
                plugin,
                recipients: recipients
                    .iter()
                    .filter(|r| r.name == plugin_name)
                    .cloned()
                    .collect(),
            })
    }
}

impl crate::Recipient for RecipientPluginV1 {
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError> {
        let parse_errors = |errors: Vec<Stanza>| {
            Err(EncryptError::Plugin(
                errors
                    .into_iter()
                    .map(|s| {
                        if s.args.len() == 2 && s.args[0] == "recipient" {
                            let index: usize = s.args[1].parse().unwrap();
                            PluginError::Recipient {
                                binary_name: binary_name(&self.recipients[index].name),
                                recipient: self.recipients[index].recipient.clone(),
                                message: String::from_utf8_lossy(&s.body).to_string(),
                            }
                        } else {
                            PluginError::from(s)
                        }
                    })
                    .collect(),
            ))
        };

        // Open connection
        let mut conn = self.plugin.connect(RECIPIENT_V1)?;

        // Phase 1: add recipients, and file key to wrap
        conn.unidir_send(|mut phase| {
            for recipient in &self.recipients {
                phase.send("add-recipient", &[&recipient.recipient], &[])?;
            }
            phase.send("wrap-file-key", &[], file_key.expose_secret())
        })?;

        // Phase 2: collect either stanzas or errors
        let (stanzas, mut errors) = conn
            .unidir_receive(&[CMD_RECIPIENT_STANZA, CMD_ERROR])?
            .into_iter()
            .partition::<Vec<_>, _>(|s| s.tag == CMD_RECIPIENT_STANZA);
        match (stanzas.is_empty(), errors.is_empty()) {
            (false, true) => Ok(stanzas
                .into_iter()
                .map(|mut s| {
                    // We only requested one file key be wrapped.
                    assert_eq!(s.args.remove(0), "0");
                    s.tag = s.args.remove(0);
                    s
                })
                .collect()),
            (a, b) => {
                if a & b {
                    errors.push(Stanza {
                        tag: "internal".to_owned(),
                        args: vec![],
                        body: "Plugin returned neither stanzas nor errors"
                            .as_bytes()
                            .to_owned(),
                    });
                } else if !a & !b {
                    errors.push(Stanza {
                        tag: "internal".to_owned(),
                        args: vec![],
                        body: "Plugin returned both stanzas and errors"
                            .as_bytes()
                            .to_owned(),
                    });
                }
                parse_errors(errors)
            }
        }
    }
}
