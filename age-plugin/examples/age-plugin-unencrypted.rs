use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, Callbacks, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    Error,
};
use gumdrop::Options;
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;

const PLUGIN_NAME: &str = "unencrypted";
const RECIPIENT_TAG: &str = PLUGIN_NAME;

struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<Error>> {
        let errors = recipients
            .filter_map(|recipient| {
                if recipient.contains(PLUGIN_NAME) {
                    // A real plugin would store the recipient here.
                    None
                } else {
                    Some(Error {
                        kind: "recipient".to_owned(),
                        message: "invalid recipient".to_owned(),
                    })
                }
            })
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<Error>> {
        // A real plugin would wrap the file key here.
        Ok(vec![Stanza {
            tag: RECIPIENT_TAG.to_owned(),
            args: vec!["does".to_owned(), "nothing".to_owned()],
            body: file_key.expose_secret().to_vec(),
        }])
    }
}

struct IdentityPlugin;

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<Error>> {
        let mut errors = vec![];
        for identity in identities {
            if identity.contains(&PLUGIN_NAME.to_uppercase()) {
                // A real plugin would store the identity.
            } else {
                errors.push(Error {
                    kind: "identity".to_owned(),
                    message: "invalid identity".to_owned(),
                });
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: HashMap<usize, Vec<Stanza>>,
        mut callbacks: impl Callbacks,
    ) -> io::Result<HashMap<usize, FileKey>> {
        let mut file_keys = HashMap::with_capacity(files.len());
        for (file_index, stanzas) in files {
            for stanza in stanzas {
                if stanza.tag == RECIPIENT_TAG {
                    // A real plugin would attempt to unwrap the file key with the stored
                    // identities.
                    let _ = callbacks.prompt("This identity does nothing!")?;
                    file_keys.entry(file_index).or_insert(FileKey::from(
                        TryInto::<[u8; 16]>::try_into(&stanza.body[..]).unwrap(),
                    ));
                    break;
                } else {
                    callbacks.error("stanza", "unsupported stanza")?.unwrap();
                }
            }
        }
        Ok(file_keys)
    }
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run as an age recipient plugin", no_short)]
    recipient_plugin_v1: bool,

    #[options(help = "run as an age identity plugin", no_short)]
    identity_plugin_v1: bool,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if opts.recipient_plugin_v1 {
        recipient::run_v1(RecipientPlugin)
    } else if opts.identity_plugin_v1 {
        identity::run_v1(IdentityPlugin)
    } else {
        // A real plugin would generate a new identity here.
        print_new_identity(PLUGIN_NAME, &[], &[]);
        Ok(())
    }
}
