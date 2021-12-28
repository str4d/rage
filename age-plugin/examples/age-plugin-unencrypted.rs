use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use gumdrop::Options;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;

const PLUGIN_NAME: &str = "unencrypted";
const RECIPIENT_TAG: &str = PLUGIN_NAME;

struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_recipient called");
        if plugin_name == PLUGIN_NAME {
            // A real plugin would store the recipient here.
            Ok(())
        } else {
            Err(recipient::Error::Recipient {
                index,
                message: "invalid recipient".to_owned(),
            })
        }
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_identity called");
        if plugin_name == PLUGIN_NAME {
            // A real plugin would store the identity.
            Ok(())
        } else {
            Err(recipient::Error::Identity {
                index,
                message: "invalid identity".to_owned(),
            })
        }
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::wrap_file_keys called");
        // A real plugin would wrap the file key here.
        let _ = callbacks
            .message("This plugin doesn't have any recipient-specific logic. It's unencrypted!")?;
        Ok(Ok(file_keys
            .into_iter()
            .map(|file_key| {
                // TODO: This should return one stanza per recipient and identity.
                vec![Stanza {
                    tag: RECIPIENT_TAG.to_owned(),
                    args: vec!["does".to_owned(), "nothing".to_owned()],
                    body: file_key.expose_secret().to_vec(),
                }]
            })
            .collect()))
    }
}

struct IdentityPlugin;

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), identity::Error> {
        eprintln!("age-plugin-unencrypted: IdentityPluginV1::add_identity called");
        if plugin_name == PLUGIN_NAME {
            // A real plugin would store the identity.
            Ok(())
        } else {
            Err(identity::Error::Identity {
                index,
                message: "invalid identity".to_owned(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        eprintln!("age-plugin-unencrypted: IdentityPluginV1::unwrap_file_keys called");
        let mut file_keys = HashMap::with_capacity(files.len());
        for (file_index, stanzas) in files.into_iter().enumerate() {
            for stanza in stanzas {
                if stanza.tag == RECIPIENT_TAG {
                    // A real plugin would attempt to unwrap the file key with the stored
                    // identities.
                    let _ = callbacks.message("This identity does nothing!")?;
                    file_keys.entry(file_index).or_insert(Ok(FileKey::from(
                        TryInto::<[u8; 16]>::try_into(&stanza.body[..]).unwrap(),
                    )));
                    break;
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

    #[options(help = "run the given age plugin state machine", no_short)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(&state_machine, || RecipientPlugin, || IdentityPlugin)
    } else {
        // A real plugin would generate a new identity here.
        print_new_identity(PLUGIN_NAME, &[], &[]);
        Ok(())
    }
}
