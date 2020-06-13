use age_core::format::AgeStanza;
use rand::rngs::OsRng;
use rsa::{padding::PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::{error::Error, keys::FileKey, util::read::base64_arg};

pub(super) const SSH_RSA_RECIPIENT_TAG: &str = "ssh-rsa";
const SSH_RSA_OAEP_LABEL: &str = "age-encryption.org/v1/ssh-rsa";

const TAG_LEN_BYTES: usize = 4;

fn ssh_tag(pubkey: &[u8]) -> [u8; TAG_LEN_BYTES] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; TAG_LEN_BYTES];
    tag.copy_from_slice(&tag_bytes[..TAG_LEN_BYTES]);
    tag
}

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) tag: [u8; TAG_LEN_BYTES],
    pub(crate) encrypted_file_key: Vec<u8>,
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SSH_RSA_RECIPIENT_TAG {
            return None;
        }

        let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;

        Some(RecipientStanza {
            tag,
            encrypted_file_key: stanza.body,
        })
    }

    pub(crate) fn wrap_file_key(file_key: &FileKey, ssh_key: &[u8], pk: &RSAPublicKey) -> Self {
        let mut rng = OsRng;

        let encrypted_file_key = pk
            .encrypt(
                &mut rng,
                PaddingScheme::new_oaep_with_label::<Sha256, _>(SSH_RSA_OAEP_LABEL),
                file_key.0.expose_secret(),
            )
            .expect("pubkey is valid and file key is not too long");

        RecipientStanza {
            tag: ssh_tag(&ssh_key),
            encrypted_file_key,
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        ssh_key: &[u8],
        sk: &RSAPrivateKey,
    ) -> Option<Result<FileKey, Error>> {
        if ssh_tag(&ssh_key) != self.tag {
            return None;
        }

        let mut rng = OsRng;

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        Some(
            sk.decrypt_blinded(
                &mut rng,
                PaddingScheme::new_oaep_with_label::<Sha256, _>(SSH_RSA_OAEP_LABEL),
                &self.encrypted_file_key,
            )
            .map_err(Error::from)
            .map(|pt| {
                // It's ours!
                let mut file_key = [0; 16];
                file_key.copy_from_slice(&pt);
                FileKey(Secret::new(file_key))
            }),
        )
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::*;

    pub(crate) fn recipient_stanza<'a, W: 'a + Write>(
        r: &'a RecipientStanza,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_tag = base64::encode_config(&r.tag, base64::STANDARD_NO_PAD);
            let args = &[encoded_tag.as_str()];
            let writer = age_stanza(SSH_RSA_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}
