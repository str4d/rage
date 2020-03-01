use age_core::{
    format::AgeStanza,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};
use curve25519_dalek::edwards::EdwardsPoint;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{
    error::Error, format::x25519::ENCRYPTED_FILE_KEY_BYTES, keys::FileKey, util::read::base64_arg,
};

pub(super) const SSH_ED25519_RECIPIENT_TAG: &str = "ssh-ed25519";
const SSH_ED25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";

const TAG_LEN_BYTES: usize = 4;

fn ssh_tag(pubkey: &[u8]) -> [u8; TAG_LEN_BYTES] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; TAG_LEN_BYTES];
    tag.copy_from_slice(&tag_bytes[..TAG_LEN_BYTES]);
    tag
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; TAG_LEN_BYTES],
    pub(crate) rest: super::x25519::RecipientLine,
}

impl RecipientLine {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SSH_ED25519_RECIPIENT_TAG {
            return None;
        }

        let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;
        let epk = base64_arg(stanza.args.get(1)?, [0; super::x25519::EPK_LEN_BYTES])?.into();

        Some(RecipientLine {
            tag,
            rest: super::x25519::RecipientLine {
                epk,
                encrypted_file_key: stanza.body[..].try_into().ok()?,
            },
        })
    }

    pub(crate) fn wrap_file_key(
        file_key: &FileKey,
        ssh_key: &[u8],
        ed25519_pk: &EdwardsPoint,
    ) -> Self {
        let pk: PublicKey = ed25519_pk.to_montgomery().to_bytes().into();

        let mut rng = OsRng;
        let esk = EphemeralSecret::new(&mut rng);
        let epk: PublicKey = (&esk).into();

        let tweak: StaticSecret = hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
        let shared_secret = tweak.diffie_hellman(&(*esk.diffie_hellman(&pk).as_bytes()).into());

        let mut salt = vec![];
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(
            &salt,
            SSH_ED25519_RECIPIENT_KEY_LABEL,
            shared_secret.as_bytes(),
        );
        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            tag: ssh_tag(&ssh_key),
            rest: super::x25519::RecipientLine {
                epk,
                encrypted_file_key,
            },
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        ssh_key: &[u8],
        privkey: &[u8; 64],
    ) -> Option<Result<FileKey, Error>> {
        if ssh_tag(&ssh_key) != self.tag {
            return None;
        }

        let sk: StaticSecret = {
            let mut sk = [0; 32];
            // privkey format is seed || pubkey
            sk.copy_from_slice(&Sha512::digest(&privkey[0..32])[0..32]);
            sk.into()
        };
        let pk = PublicKey::from(&sk);

        let tweak: StaticSecret = hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
        let shared_secret = tweak.diffie_hellman(&PublicKey::from(
            *sk.diffie_hellman(&self.rest.epk).as_bytes(),
        ));

        let mut salt = vec![];
        salt.extend_from_slice(self.rest.epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(
            &salt,
            SSH_ED25519_RECIPIENT_KEY_LABEL,
            shared_secret.as_bytes(),
        );

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        Some(
            aead_decrypt(&enc_key, &self.rest.encrypted_file_key)
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

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &'a RecipientLine,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_tag = base64::encode_config(&r.tag, base64::STANDARD_NO_PAD);
            let encoded_epk = base64::encode_config(r.rest.epk.as_bytes(), base64::STANDARD_NO_PAD);
            let args = &[encoded_tag.as_str(), encoded_epk.as_str()];
            let writer = age_stanza(SSH_ED25519_RECIPIENT_TAG, args, &r.rest.encrypted_file_key);
            writer(w)
        }
    }
}
