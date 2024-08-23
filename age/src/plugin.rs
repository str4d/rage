//! Support for the age plugin system.

use age_core::{
    format::{FileKey, Stanza},
    io::{DebugReader, DebugWriter},
    plugin::{Connection, Reply, Response, UnidirSend, IDENTITY_V1, RECIPIENT_V1},
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::Variant;

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::iter;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

use crate::{
    error::{DecryptError, EncryptError, PluginError},
    fl,
    util::parse_bech32,
    wfl, wlnfl, Callbacks,
};

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
const PLUGIN_IDENTITY_PREFIX: &str = "age-plugin-";

const CMD_ERROR: &str = "error";
const CMD_RECIPIENT_STANZA: &str = "recipient-stanza";
const CMD_LABELS: &str = "labels";
const CMD_MSG: &str = "msg";
const CMD_CONFIRM: &str = "confirm";
const CMD_REQUEST_PUBLIC: &str = "request-public";
const CMD_REQUEST_SECRET: &str = "request-secret";
const CMD_FILE_KEY: &str = "file-key";

const ONE_HUNDRED_MS: Duration = Duration::from_millis(100);
const TEN_SECONDS: Duration = Duration::from_secs(10);

fn binary_name(plugin_name: &str) -> String {
    format!("age-plugin-{}", plugin_name)
}

struct SlowPluginGuard(mpsc::Sender<()>);

impl SlowPluginGuard {
    /// Starts a thread to print out a progress message after 10 seconds if the plugin
    /// hasn't finished.
    ///
    /// Returns a guard that can be dropped once the plugin finishes to cancel the timer.
    fn new<C: Callbacks>(callbacks: C, plugin_binary_name: String) -> Self {
        // We use a channel to detect when the guard is dropped.
        let (send, recv) = mpsc::channel::<()>();

        thread::spawn(move || {
            let start = SystemTime::now();
            loop {
                // If the send side of the channel has been dropped, we've been cancelled.
                if matches!(recv.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                    break;
                }

                // If we've waited long enough, emit the progress message and exit.
                match SystemTime::now().duration_since(start) {
                    Ok(end) if end >= TEN_SECONDS => {
                        callbacks.display_message(&fl!(
                            "plugin-waiting-on-binary",
                            binary_name = plugin_binary_name,
                        ));
                        break;
                    }
                    _ => thread::sleep(ONE_HUNDRED_MS),
                }
            }
        });

        SlowPluginGuard(send)
    }
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
                            .trim_end_matches('-')
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
    /// Returns the identity corresponding to the given plugin name in its default mode.
    pub fn default_for_plugin(plugin_name: &str) -> Self {
        bech32::encode(
            &format!("{}{}-", PLUGIN_IDENTITY_PREFIX, plugin_name),
            [],
            Variant::Bech32,
        )
        .expect("HRP is valid")
        .to_uppercase()
        .parse()
        .unwrap()
    }

    /// Returns the plugin name for this identity.
    pub fn plugin(&self) -> &str {
        &self.name
    }
}

/// An age plugin.
struct Plugin {
    binary_name: String,
    path: PathBuf,
}

impl Plugin {
    /// Finds the age plugin with the given name in `$PATH`.
    ///
    /// On error, returns the binary name that could not be located.
    fn new(name: &str) -> Result<Self, String> {
        let binary_name = binary_name(name);
        match which::which(&binary_name).or_else(|e| {
            // If we are running in WSL, try appending `.exe`; plugins installed in
            // the Windows host are available to us, but `which` only trials PATHEXT
            // extensions automatically when compiled for Windows.
            if wsl::is_wsl() {
                which::which(format!("{}.exe", binary_name)).map_err(|_| e)
            } else {
                Err(e)
            }
        }) {
            Ok(path) => Ok(Plugin { binary_name, path }),
            Err(_) => Err(binary_name),
        }
    }

    fn connect(&self, state_machine: &str) -> io::Result<BlastFurnace> {
        let conn = Connection::open(&self.path, state_machine)?;
        Ok(BlastFurnace {
            binary_name: self.binary_name.clone(),
            conn,
        })
    }
}

/// Wraps a connection and gracefully handles plugin explosions.
struct BlastFurnace {
    binary_name: String,
    conn: Connection<DebugReader<ChildStdout>, DebugWriter<ChildStdin>>,
}

impl BlastFurnace {
    fn handle_errors(&self, res: io::Result<()>) -> io::Result<()> {
        res.map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => io::Error::new(
                io::ErrorKind::ConnectionAborted,
                PluginDiedError {
                    binary_name: self.binary_name.clone(),
                },
            ),
            _ => e,
        })
    }

    fn unidir_send<
        P: FnOnce(UnidirSend<DebugReader<ChildStdout>, DebugWriter<ChildStdin>>) -> io::Result<()>,
    >(
        &mut self,
        phase_steps: P,
    ) -> io::Result<()> {
        let res = self.conn.unidir_send(phase_steps);
        self.handle_errors(res)
    }

    fn bidir_receive<H>(&mut self, commands: &[&str], handler: H) -> io::Result<()>
    where
        H: FnMut(Stanza, Reply<DebugReader<ChildStdout>, DebugWriter<ChildStdin>>) -> Response,
    {
        let res = self.conn.bidir_receive(commands, handler);
        self.handle_errors(res)
    }
}

#[derive(Debug)]
struct PluginDiedError {
    binary_name: String,
}

impl fmt::Display for PluginDiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wlnfl!(
            f,
            "err-plugin-died",
            plugin_name = self.binary_name.as_str(),
        )?;
        wlnfl!(f, "rec-plugin-died-1", env_var = "AGEDEBUG=plugin")?;
        wfl!(f, "rec-plugin-died-2")
    }
}

impl std::error::Error for PluginDiedError {}

fn handle_confirm<R: io::Read, W: io::Write, C: Callbacks>(
    command: Stanza,
    reply: Reply<R, W>,
    errors: &mut Vec<PluginError>,
    callbacks: &C,
) -> Response {
    let message = String::from_utf8_lossy(&command.body);
    let mut strings = command
        .args
        .iter()
        .take(2)
        .map(|s| BASE64_STANDARD_NO_PAD.decode(s));
    let (yes_string, no_string) = match (strings.next(), strings.next()) {
        (None, _) => {
            errors.push(PluginError::Other {
                kind: "internal".to_owned(),
                metadata: vec![],
                message: format!(
                    "{} command must have at least one metadata argument",
                    CMD_CONFIRM
                ),
            });
            return reply.fail();
        }
        (Some(Err(_)), _) | (_, Some(Err(_))) => {
            errors.push(PluginError::Other {
                kind: "internal".to_owned(),
                metadata: vec![],
                message: format!(
                    "The first two metadata arguments to the {} command must be Base64-encoded",
                    CMD_CONFIRM
                ),
            });
            return reply.fail();
        }
        (Some(Ok(yes_string)), None) => (yes_string, None),
        (Some(Ok(yes_string)), Some(Ok(no_string))) => (yes_string, Some(no_string)),
    };
    if let Some(value) = callbacks.confirm(
        &message,
        &String::from_utf8_lossy(&yes_string),
        no_string
            .as_ref()
            .map(|s| String::from_utf8_lossy(s))
            .as_ref()
            .map(|s| s.borrow()),
    ) {
        reply.ok_with_metadata(&[if value { "yes" } else { "no" }], None)
    } else {
        reply.fail()
    }
}

/// An age plugin with an associated set of recipients.
///
/// This struct implements [`Recipient`], enabling the plugin to encrypt a file to the
/// entire set of recipients.
pub struct RecipientPluginV1<C: Callbacks> {
    plugin: Plugin,
    recipients: Vec<Recipient>,
    identities: Vec<Identity>,
    callbacks: C,
}

impl<C: Callbacks> RecipientPluginV1<C> {
    /// Creates an age plugin from a plugin name and lists of recipients and identities.
    ///
    /// The lists of recipients and identities will be filtered by the plugin name;
    /// recipients that don't match will be ignored.
    ///
    /// Returns an error if the plugin's binary cannot be found in `$PATH`.
    pub fn new(
        plugin_name: &str,
        recipients: &[Recipient],
        identities: &[Identity],
        callbacks: C,
    ) -> Result<Self, EncryptError> {
        Plugin::new(plugin_name)
            .map_err(|binary_name| EncryptError::MissingPlugin { binary_name })
            .map(|plugin| RecipientPluginV1 {
                plugin,
                recipients: recipients
                    .iter()
                    .filter(|r| r.name == plugin_name)
                    .cloned()
                    .collect(),
                identities: identities
                    .iter()
                    .filter(|r| r.name == plugin_name)
                    .cloned()
                    .collect(),
                callbacks,
            })
    }
}

impl<C: Callbacks> crate::Recipient for RecipientPluginV1<C> {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        // Open connection
        let mut conn = self.plugin.connect(RECIPIENT_V1)?;

        let _guard = SlowPluginGuard::new(self.callbacks.clone(), self.plugin.binary_name.clone());

        // Phase 1: add recipients, identities, and file key to wrap
        conn.unidir_send(|mut phase| {
            for recipient in &self.recipients {
                phase.send("add-recipient", &[&recipient.recipient], &[])?;
            }
            for identity in &self.identities {
                phase.send("add-identity", &[&identity.identity], &[])?;
            }
            phase.send("extension-labels", &[], &[])?;
            phase.send("wrap-file-key", &[], file_key.expose_secret())
        })?;

        // Phase 2: collect either stanzas or errors
        let mut stanzas = vec![];
        let mut labels = None;
        let mut errors = vec![];
        if let Err(e) = conn.bidir_receive(
            &[
                CMD_MSG,
                CMD_CONFIRM,
                CMD_REQUEST_PUBLIC,
                CMD_REQUEST_SECRET,
                CMD_RECIPIENT_STANZA,
                CMD_LABELS,
                CMD_ERROR,
            ],
            |mut command, reply| match command.tag.as_str() {
                CMD_MSG => {
                    self.callbacks
                        .display_message(&String::from_utf8_lossy(&command.body));
                    reply.ok(None)
                }
                CMD_CONFIRM => handle_confirm(command, reply, &mut errors, &self.callbacks),
                CMD_REQUEST_PUBLIC => {
                    if let Some(value) = self
                        .callbacks
                        .request_public_string(&String::from_utf8_lossy(&command.body))
                    {
                        reply.ok(Some(value.as_bytes()))
                    } else {
                        reply.fail()
                    }
                }
                CMD_REQUEST_SECRET => {
                    if let Some(secret) = self
                        .callbacks
                        .request_passphrase(&String::from_utf8_lossy(&command.body))
                    {
                        reply.ok(Some(secret.expose_secret().as_bytes()))
                    } else {
                        reply.fail()
                    }
                }
                CMD_RECIPIENT_STANZA => {
                    if command.args.len() >= 2 {
                        // We only requested one file key be wrapped.
                        if command.args.remove(0) == "0" {
                            command.tag = command.args.remove(0);
                            stanzas.push(command);
                        } else {
                            errors.push(PluginError::Other {
                                kind: "internal".to_owned(),
                                metadata: vec![],
                                message: "plugin wrapped file key to a file we didn't provide"
                                    .to_owned(),
                            });
                        }
                    } else {
                        errors.push(PluginError::Other {
                            kind: "internal".to_owned(),
                            metadata: vec![],
                            message: format!(
                                "{} command must have at least two metadata arguments",
                                CMD_RECIPIENT_STANZA
                            ),
                        });
                    }
                    reply.ok(None)
                }
                CMD_LABELS => {
                    if labels.is_none() {
                        let labels_count = command.args.len();
                        let label_set = command.args.into_iter().collect::<HashSet<_>>();
                        if label_set.len() == labels_count {
                            labels = Some(label_set);
                        } else {
                            errors.push(PluginError::Other {
                                kind: "internal".to_owned(),
                                metadata: vec![],
                                message: format!(
                                    "{} command must not contain duplicate labels",
                                    CMD_LABELS
                                ),
                            });
                        }
                    } else {
                        errors.push(PluginError::Other {
                            kind: "internal".to_owned(),
                            metadata: vec![],
                            message: format!(
                                "{} command must not be sent more than once",
                                CMD_LABELS
                            ),
                        });
                    }
                    reply.ok(None)
                }
                CMD_ERROR => {
                    if command.args.len() == 2 && command.args[0] == "recipient" {
                        let index: usize = command.args[1].parse().unwrap();
                        errors.push(PluginError::Recipient {
                            binary_name: binary_name(&self.recipients[index].name),
                            recipient: self.recipients[index].recipient.clone(),
                            message: String::from_utf8_lossy(&command.body).to_string(),
                        });
                    } else if command.args.len() == 2 && command.args[0] == "identity" {
                        let index: usize = command.args[1].parse().unwrap();
                        errors.push(PluginError::Identity {
                            binary_name: binary_name(&self.identities[index].name),
                            message: String::from_utf8_lossy(&command.body).to_string(),
                        });
                    } else {
                        errors.push(PluginError::from(command));
                    }
                    reply.ok(None)
                }
                _ => unreachable!(),
            },
        ) {
            return Err(e.into());
        };
        match (stanzas.is_empty(), errors.is_empty()) {
            (false, true) => Ok((stanzas, labels.unwrap_or_default())),
            (a, b) => {
                if a & b {
                    errors.push(PluginError::Other {
                        kind: "internal".to_owned(),
                        metadata: vec![],
                        message: "Plugin returned neither stanzas nor errors".to_owned(),
                    });
                } else if !a & !b {
                    errors.push(PluginError::Other {
                        kind: "internal".to_owned(),
                        metadata: vec![],
                        message: "Plugin returned both stanzas and errors".to_owned(),
                    });
                }
                Err(EncryptError::Plugin(errors))
            }
        }
    }
}

/// An age plugin with an associated set of identities.
///
/// This struct implements [`Identity`], enabling the plugin to decrypt a file with any
/// identity in the set of identities.
pub struct IdentityPluginV1<C: Callbacks> {
    plugin: Plugin,
    identities: Vec<Identity>,
    callbacks: C,
}

impl<C: Callbacks> IdentityPluginV1<C> {
    /// Creates an age plugin from a plugin name and a list of identities.
    ///
    /// The list of identities will be filtered by the plugin name; identities that don't
    /// match will be ignored.
    ///
    /// Returns an error if the plugin's binary cannot be found in `$PATH`.
    pub fn new(
        plugin_name: &str,
        identities: &[Identity],
        callbacks: C,
    ) -> Result<Self, DecryptError> {
        Plugin::new(plugin_name)
            .map_err(|binary_name| DecryptError::MissingPlugin { binary_name })
            .map(|plugin| IdentityPluginV1 {
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
        // Open connection. If the plugin doesn't know how to unwrap identities, skip it
        // by returning `None`.
        let mut conn = self.plugin.connect(IDENTITY_V1).ok()?;

        let _guard = SlowPluginGuard::new(self.callbacks.clone(), self.plugin.binary_name.clone());

        // Phase 1: add identities and stanzas
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
        let mut errors = vec![];
        if let Err(e) = conn.bidir_receive(
            &[
                CMD_MSG,
                CMD_CONFIRM,
                CMD_REQUEST_PUBLIC,
                CMD_REQUEST_SECRET,
                CMD_FILE_KEY,
                CMD_ERROR,
            ],
            |command, reply| match command.tag.as_str() {
                CMD_MSG => {
                    self.callbacks
                        .display_message(&String::from_utf8_lossy(&command.body));
                    reply.ok(None)
                }
                CMD_CONFIRM => handle_confirm(command, reply, &mut errors, &self.callbacks),
                CMD_REQUEST_PUBLIC => {
                    if let Some(value) = self
                        .callbacks
                        .request_public_string(&String::from_utf8_lossy(&command.body))
                    {
                        reply.ok(Some(value.as_bytes()))
                    } else {
                        reply.fail()
                    }
                }
                CMD_REQUEST_SECRET => {
                    if let Some(secret) = self
                        .callbacks
                        .request_passphrase(&String::from_utf8_lossy(&command.body))
                    {
                        reply.ok(Some(secret.expose_secret().as_bytes()))
                    } else {
                        reply.fail()
                    }
                }
                CMD_FILE_KEY => {
                    // We only support a single file.
                    assert!(command.args[0] == "0");
                    assert!(file_key.is_none());
                    file_key = Some(
                        TryInto::<[u8; 16]>::try_into(&command.body[..])
                            .map_err(|_| DecryptError::DecryptionFailed)
                            .map(FileKey::from),
                    );
                    reply.ok(None)
                }
                CMD_ERROR => {
                    if command.args.len() == 2 && command.args[0] == "identity" {
                        let index: usize = command.args[1].parse().unwrap();
                        errors.push(PluginError::Identity {
                            binary_name: binary_name(&self.identities[index].name),
                            message: String::from_utf8_lossy(&command.body).to_string(),
                        });
                    } else {
                        errors.push(PluginError::from(command));
                    }
                    reply.ok(None)
                }
                _ => unreachable!(),
            },
        ) {
            return Some(Err(e.into()));
        };

        if file_key.is_none() && !errors.is_empty() {
            Some(Err(DecryptError::Plugin(errors)))
        } else {
            file_key
        }
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

#[cfg(test)]
mod tests {
    use super::Identity;

    #[test]
    fn default_for_plugin() {
        assert_eq!(
            Identity::default_for_plugin("foobar").to_string(),
            "AGE-PLUGIN-FOOBAR-1QVHULF",
        );
    }
}
