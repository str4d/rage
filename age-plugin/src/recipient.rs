//! Recipient plugin helpers.

use age_core::{
    format::{FileKey, Stanza},
    plugin::Connection,
};
use std::convert::TryInto;
use std::io;

use super::Error;

/// The interface that age implementations will use to interact with an age plugin.
pub trait RecipientPluginV1 {
    /// Stores recipients that the user would like to encrypt age files.
    ///
    /// `plugin_name` identifies the plugin that generated this identity. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `identity`.
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<Error>>;

    /// Wraps `file_key` in an age recipient stanza that can be unwrapped by `recipient`.
    ///
    /// `plugin_name` identifies the plugin that generated this recipient. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `recipient`.
    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<Error>>;
}

/// Runs the recipient plugin v1 protocol.
///
/// This should be triggered if the `--recipient-plugin-v1` flag is provided as an
/// argument when starting the plugin.
pub fn run_v1<P: RecipientPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: collect recipients
    let recipients = conn
        .unidir_receive()?
        .into_iter()
        .filter(|s| s.tag == "add-recipient" && s.args.len() == 1)
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Need at least one add-recipient",
        ));
    }

    // Phase 2: return errors
    conn.unidir_send(|mut phase| {
        if let Err(errors) =
            plugin.add_recipients(recipients.iter().map(|s| s.args.first().unwrap().as_str()))
        {
            for error in errors {
                phase.send("error", &[&error.kind], error.message.as_bytes())?;
            }
        }
        Ok(())
    })?;

    // Phase 3: receive file key to be wrapped
    // TODO: How should errors about invalid state machine messages be returned?
    let file_key = {
        let mut res = conn
            .unidir_receive()?
            .into_iter()
            .filter(|s| s.tag == "wrap-file-key");
        match (res.next(), res.next()) {
            (Some(s), None) => TryInto::<[u8; 16]>::try_into(&s.body[..])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid file key length"))
                .map(FileKey::from),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "should receive a single wrap-file-key command",
                ))
            }
        }
    }?;

    // Phase 4: wrap the file key
    conn.unidir_send(|mut phase| {
        match plugin.wrap_file_key(&file_key) {
            Ok(stanzas) => {
                for stanza in stanzas {
                    phase.send_stanza("recipient-stanza", &["0"], &stanza)?;
                }
            }
            Err(errors) => {
                for e in errors {
                    phase.send("error", &[&e.kind], e.message.as_bytes())?;
                }
            }
        }
        Ok(())
    })?;

    Ok(())
}
