use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks, PluginHandler,
};
use clap::Parser;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::env;
use std::io;

const PLUGIN_NAME: &str = "unencrypted";
const RECIPIENT_TAG: &str = PLUGIN_NAME;

fn explode(location: &str) {
    if let Ok(s) = env::var("AGE_EXPLODES") {
        if s == location {
            panic!("Env variable AGE_EXPLODES={} is set. Boom! 💥", location);
        }
    }
}

struct FullHandler;

impl PluginHandler for FullHandler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin)
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin)
    }
}

struct RecipientHandler;

impl PluginHandler for RecipientHandler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = Infallible;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin)
    }
}

struct IdentityHandler;

impl PluginHandler for IdentityHandler {
    type RecipientV1 = Infallible;
    type IdentityV1 = IdentityPlugin;

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin)
    }
}

struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_recipient called");
        explode("recipient");
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
        explode("identity");
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

    fn labels(&mut self) -> HashSet<String> {
        let mut labels = HashSet::new();
        if let Ok(s) = env::var("AGE_PLUGIN_LABELS") {
            for label in s.split(',') {
                labels.insert(label.into());
            }
        }
        labels
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::wrap_file_keys called");
        explode("wrap");
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
        explode("identity");
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
        explode("unwrap");
        let mut file_keys = HashMap::with_capacity(files.len());
        for (file_index, stanzas) in files.into_iter().enumerate() {
            for stanza in stanzas {
                if stanza.tag == RECIPIENT_TAG {
                    // A real plugin would attempt to unwrap the file key with the stored
                    // identities.
                    let _ = callbacks.message("This identity does nothing!")?;
                    file_keys.entry(file_index).or_insert_with(|| {
                        FileKey::try_init_with_mut(|file_key| {
                            if stanza.body.len() == file_key.len() {
                                file_key.copy_from_slice(&stanza.body);
                                Ok(())
                            } else {
                                panic!("File key is wrong length")
                            }
                        })
                    });
                    break;
                }
            }
        }
        Ok(file_keys)
    }
}

#[derive(Debug, Parser)]
struct PluginOptions {
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse();

    if let Some(state_machine) = opts.age_plugin {
        if let Ok(s) = env::var("AGE_HALF_PLUGIN") {
            match s.as_str() {
                "recipient" => run_state_machine(&state_machine, RecipientHandler),
                "identity" => run_state_machine(&state_machine, IdentityHandler),
                _ => panic!("Env variable AGE_HALF_PLUGIN={s} has unknown value. Boom! 💥"),
            }
        } else {
            run_state_machine(&state_machine, FullHandler)
        }
    } else {
        // A real plugin would generate a new identity here.
        print_new_identity(PLUGIN_NAME, &[], &[]);
        Ok(())
    }
}
