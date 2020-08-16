//! Support for the age plugin system.

use age_core::{
    format::{FileKey, Stanza},
    plugin::Connection,
};
use secrecy::ExposeSecret;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};

use crate::{error::EncryptError, util::parse_bech32};

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";

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
    /// Finds the age plugin with the given name.
    fn new(name: &str) -> which::Result<Self> {
        let binary_name = format!("age-plugin-{}", name);
        which::which(binary_name).map(Plugin)
    }

    fn connect(&self, state_machine: &str) -> io::Result<Connection<ChildStdout, ChildStdin>> {
        Connection::open(&self.0, state_machine)
    }
}

/// TODO
pub struct RecipientPluginV1 {
    plugin: Plugin,
    recipients: Vec<Recipient>,
}

impl RecipientPluginV1 {
    /// TODO
    pub fn new(plugin_name: &str, recipients: &[Recipient]) -> which::Result<Self> {
        Plugin::new(plugin_name).map(|plugin| RecipientPluginV1 {
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
        // Open connection
        let mut conn = self.plugin.connect("--recipient-plugin-v1")?;

        // Phase 1: add-recipient
        conn.unidir_send(|mut phase| {
            for recipient in &self.recipients {
                phase.send("add-recipient", &[&recipient.recipient], &[])?;
            }
            Ok(())
        })?;

        // Phase 2: check for errors
        let errors = conn.unidir_receive()?;
        assert!(errors.is_empty());

        // Phase 3: request wrapping
        conn.unidir_send(|mut phase| phase.send("wrap-file-key", &[], file_key.expose_secret()))?;

        // Phase 4: collect either stanzas or errors
        let (stanzas, errors) = {
            let (stanzas, rest) = conn
                .unidir_receive()?
                .into_iter()
                .partition::<Vec<_>, _>(|s| s.tag == "recipient-stanza");
            (
                stanzas,
                rest.into_iter()
                    .filter(|s| s.tag == "error")
                    .collect::<Vec<_>>(),
            )
        };
        match (stanzas.is_empty(), errors.is_empty()) {
            (false, true) => Ok(stanzas
                .into_iter()
                .map(|mut s| {
                    s.args.remove(0);
                    s.tag = s.args.remove(0);
                    s
                })
                .collect()),
            (true, false) => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}
