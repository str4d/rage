//! Support for the age plugin system.

use age_core::{
    format::{FileKey, Stanza},
    plugin::Connection,
};
use secrecy::ExposeSecret;
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::iter;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};

use crate::{
    error::{DecryptError, EncryptError},
    protocol::decryptor::Callbacks,
    util::parse_bech32,
};

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
const PLUGIN_IDENTITY_PREFIX: &str = "age-plugin-";

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

/// A plugin-compatible identity.
#[derive(Clone)]
pub struct Identity {
    /// The plugin name, extracted from `identity`.
    name: String,
    /// The identity.
    identity: String,
}

impl std::str::FromStr for Identity {
    type Err = &'static str;

    /// Parses a plugin identity from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, _)| {
                if hrp.len() > PLUGIN_IDENTITY_PREFIX.len()
                    && hrp.starts_with(PLUGIN_IDENTITY_PREFIX)
                {
                    Ok(Identity {
                        name: hrp
                            .split_at(PLUGIN_IDENTITY_PREFIX.len())
                            .1
                            .trim_end_matches("-")
                            .to_owned(),
                        identity: s.to_owned(),
                    })
                } else {
                    Err("invalid HRP")
                }
            })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identity)
    }
}

impl Identity {
    /// Returns the plugin name for this identity.
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

/// TODO
pub struct IdentityPluginV1<C: Callbacks> {
    plugin: Plugin,
    identities: Vec<Identity>,
    callbacks: C,
}

impl<C: Callbacks> IdentityPluginV1<C> {
    /// TODO
    pub fn new(plugin_name: &str, identities: &[Identity], callbacks: C) -> which::Result<Self> {
        Plugin::new(plugin_name).map(|plugin| IdentityPluginV1 {
            plugin,
            identities: identities
                .iter()
                .filter(|r| r.name == plugin_name)
                .cloned()
                .collect(),
            callbacks,
        })
    }

    fn unwrap_stanzas<'a>(
        &self,
        stanzas: impl Iterator<Item = &'a Stanza>,
    ) -> Option<Result<FileKey, DecryptError>> {
        // Open connection
        let mut conn = self.plugin.connect("--identity-plugin-v1").unwrap();

        // Phase 1: add identities and stanza
        if let Err(e) = conn.unidir_send(|mut phase| {
            for identity in &self.identities {
                phase.send("add-identity", &[identity.identity.as_str()], &[])?;
            }
            for stanza in stanzas {
                phase.send_stanza("recipient-stanza", &["0"], stanza)?;
            }
            Ok(())
        }) {
            return Some(Err(e.into()));
        };

        // Phase 2: interactively unwrap
        let mut file_key = None;
        if let Err(e) = conn.bidir_receive(|command, reply| match command.tag.as_str() {
            "prompt" => {
                if let Ok(message) = std::str::from_utf8(&command.body) {
                    self.callbacks.prompt(message);
                    reply.ok(None)
                } else {
                    reply.fail()
                }
            }
            "request-secret" => {
                if let Ok(description) = std::str::from_utf8(&command.body) {
                    if let Some(secret) = self.callbacks.request_passphrase(description) {
                        reply.ok(Some(secret.expose_secret().as_bytes()))
                    } else {
                        reply.fail()
                    }
                } else {
                    reply.fail()
                }
            }
            "file-key" => {
                file_key = Some(
                    TryInto::<[u8; 16]>::try_into(&command.body[..])
                        .map_err(|_| DecryptError::DecryptionFailed)
                        .map(FileKey::from),
                );
                reply.ok(None)
            }
            "error" => reply.ok(None),
            _ => reply.unsupported(),
        }) {
            return Some(Err(e.into()));
        };

        file_key
    }
}

impl<C: Callbacks> crate::Identity for IdentityPluginV1<C> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        self.unwrap_stanzas(iter::once(stanza))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        self.unwrap_stanzas(stanzas.iter())
    }
}
