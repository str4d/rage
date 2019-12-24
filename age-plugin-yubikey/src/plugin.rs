use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{Callbacks, IdentityPluginV1},
    recipient::RecipientPluginV1,
    Error,
};
use bech32::FromBase32;
use std::collections::HashMap;
use std::io;

use crate::{format, p256::PublicKey, yubikey, IDENTITY_PREFIX, RECIPIENT_PREFIX};

#[derive(Debug, Default)]
pub(crate) struct RecipientPlugin {
    recipients: Vec<PublicKey>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<Error>> {
        let errors: Vec<_> = recipients
            .filter_map(|recipient| {
                if let Some(pk) = bech32::decode(recipient)
                    .ok()
                    .and_then(|(hrp, data)| {
                        if hrp == RECIPIENT_PREFIX {
                            Some(data)
                        } else {
                            None
                        }
                    })
                    .and_then(|data| Vec::from_base32(&data).ok())
                    .and_then(|bytes| PublicKey::from_bytes(&bytes))
                {
                    self.recipients.push(pk);
                    None
                } else {
                    Some(Error {
                        kind: "recipient".to_owned(),
                        message: "Invalid recipient".to_owned(),
                    })
                }
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<Error>> {
        Ok(self
            .recipients
            .iter()
            .map(|pk| format::RecipientLine::wrap_file_key(file_key, &pk).into())
            .collect())
    }
}

#[derive(Debug, Default)]
pub(crate) struct IdentityPlugin {
    yubikeys: Vec<yubikey::Stub>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<Error>> {
        let errors: Vec<_> = identities
            .filter_map(|identity| {
                if let Some(stub) = bech32::decode(identity)
                    .ok()
                    .and_then(|(hrp, data)| {
                        if hrp == IDENTITY_PREFIX.to_lowercase() {
                            Some(data)
                        } else {
                            None
                        }
                    })
                    .and_then(|data| Vec::from_base32(&data).ok())
                    .and_then(|bytes| yubikey::Stub::from_bytes(&bytes))
                {
                    self.yubikeys.push(stub);
                    None
                } else {
                    Some(Error {
                        kind: "identity".to_owned(),
                        message: "Invalid Yubikey stub".to_owned(),
                    })
                }
            })
            .collect();
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
        // Filter to files / stanzas for which we have matching YubiKeys
        let mut candidate_stanzas: Vec<(
            &yubikey::Stub,
            HashMap<usize, Vec<format::RecipientLine>>,
        )> = self
            .yubikeys
            .iter()
            .map(|stub| (stub, HashMap::new()))
            .collect();

        for (file, stanzas) in &files {
            for stanza in stanzas {
                match format::RecipientLine::from_stanza(&stanza) {
                    Some(Ok(line)) => {
                        // A line will match at most one YubiKey.
                        if let Some(files) =
                            candidate_stanzas.iter_mut().find_map(|(stub, files)| {
                                if stub.matches(&line) {
                                    Some(files)
                                } else {
                                    None
                                }
                            })
                        {
                            files.entry(*file).or_default().push(line);
                        }
                    }
                    Some(Err(e)) => callbacks.error(&e.kind, &e.message)?.unwrap(),
                    None => (),
                }
            }
        }

        // Sort by effectiveness (YubiKey that can trial-decrypt the most stanzas)
        candidate_stanzas.sort_by_key(|(_, files)| {
            files
                .iter()
                .map(|(_, stanzas)| stanzas.len())
                .sum::<usize>()
        });
        candidate_stanzas.reverse();

        let mut file_keys = HashMap::with_capacity(files.len());
        for (stub, files) in candidate_stanzas.iter() {
            let mut conn = match stub.connect(&mut callbacks)? {
                Ok(conn) => conn,
                Err(e) => {
                    callbacks.error(&e.kind, &e.message)?.unwrap();
                    continue;
                }
            };

            for (&file_index, stanzas) in files {
                if file_keys.contains_key(&file_index) {
                    // We decrypted this file with an earlier YubiKey.
                    continue;
                }

                for line in stanzas {
                    match conn.unwrap_file_key(&line) {
                        Ok(file_key) => {
                            // We've managed to decrypt this file!
                            file_keys.entry(file_index).or_insert(file_key);
                            break;
                        }
                        Err(e) => callbacks.error(&e.kind, &e.message)?.unwrap(),
                    }
                }
            }
        }
        Ok(file_keys)
    }
}
