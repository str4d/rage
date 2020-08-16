//! Identity plugin helpers.

use age_core::{
    format::{FileKey, Stanza},
    plugin::{self, BidirSend, Connection},
};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io;

use super::Error;

/// The interface that age plugins can use to interact with an age implementation.
pub trait Callbacks {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn prompt(&mut self, message: &str) -> plugin::Result<(), ()>;

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> plugin::Result<SecretString, ()>;

    /// Sends an error.
    fn error(&mut self, kind: &str, message: &str) -> plugin::Result<(), ()>;
}

/// The interface that age implementations will use to interact with an age plugin.
pub trait IdentityPluginV1 {
    /// Stores an identity that the user would like to use for decrypting age files.
    ///
    /// `plugin_name` identifies the plugin that generated this identity. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `identity`.
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<Error>>;

    /// Attempts to unwrap the file key contained within the given age recipient stanza,
    /// using identities previously stored via [`add_identity`].
    ///
    /// `prompt` shows a message to the user. This can be used to prompt the user to take
    /// some physical action, such as inserting a hardware key.
    ///
    /// `request_secret` requests a secret value from the user, such as a passphrase. It
    /// takes a `message` will be displayed to the user, providing context for the
    /// request.
    ///
    /// [`add_identity`]: AgePlugin::add_identity
    fn unwrap_file_keys(
        &mut self,
        files: HashMap<usize, Vec<Stanza>>,
        callbacks: impl Callbacks,
    ) -> io::Result<HashMap<usize, FileKey>>;
}

/// The interface that age plugins can use to interact with an age implementation.
struct BidirCallbacks<'a, 'b, R: io::Read, W: io::Write>(&'b mut BidirSend<'a, R, W>);

impl<'a, 'b, R: io::Read, W: io::Write> Callbacks for BidirCallbacks<'a, 'b, R, W> {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn prompt(&mut self, message: &str) -> plugin::Result<(), ()> {
        self.0
            .send("prompt", &[], message.as_bytes())
            .map(|res| res.map(|_| ()))
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

    fn error(&mut self, kind: &str, message: &str) -> plugin::Result<(), ()> {
        self.0
            .send("error", &[kind], message.as_bytes())
            .map(|res| res.map(|_| ()))
    }
}

/// Runs the recipient plugin v1 protocol.
///
/// This should be triggered if the `--identity-plugin-v1` flag is provided as an argument
/// when starting the plugin.
pub fn run_v1<P: IdentityPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: receive identities and stanzas
    let (identities, recipient_stanzas) = {
        let (identities, rest) = conn
            .unidir_receive()?
            .into_iter()
            .partition::<Vec<_>, _>(|s| s.tag == "add-identity");
        (
            identities,
            rest.into_iter()
                .filter(|s| s.tag == "recipient-stanza")
                .map(|mut s| {
                    let file_index = s.args.remove(0);
                    s.tag = s.args.remove(0);
                    file_index.parse::<usize>().ok().map(|i| (i, s))
                })
                .collect::<Vec<_>>(),
        )
    };

    // Phase 2: interactively unwrap
    conn.bidir_send(|mut phase| {
        if let Err(errors) =
            plugin.add_identities(identities.iter().map(|s| s.args.first().unwrap().as_str()))
        {
            for e in errors {
                phase
                    .send("error", &[&e.kind], e.message.as_bytes())?
                    .unwrap();
            }
        } else {
            let mut stanzas = HashMap::new();
            for recipient_stanza in recipient_stanzas {
                if let Some((file_index, stanza)) = recipient_stanza {
                    stanzas
                        .entry(file_index)
                        .or_insert_with(Vec::new)
                        .push(stanza);
                } else {
                    phase
                        .send(
                            "error",
                            &["stanza"],
                            "Invalid recipient-stanza command".as_bytes(),
                        )?
                        .unwrap();
                }
            }

            for (file_index, file_key) in
                plugin.unwrap_file_keys(stanzas, BidirCallbacks(&mut phase))?
            {
                phase
                    .send(
                        "file-key",
                        &[&format!("{}", file_index)],
                        file_key.expose_secret(),
                    )?
                    .unwrap();
            }
        }
        Ok(())
    })?;

    Ok(())
}
