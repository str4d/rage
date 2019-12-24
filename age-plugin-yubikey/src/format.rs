use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, hkdf},
};
use bech32::ToBase32;
use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256},
    rand::SystemRandom,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use crate::{p256::PublicKey, RECIPIENT_PREFIX, RECIPIENT_TAG};

const RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/yubikey";

const TAG_BYTES: usize = 4;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

pub(crate) fn piv_to_str(pk: &PublicKey) -> String {
    bech32::encode(RECIPIENT_PREFIX, pk.as_bytes().to_base32()).expect("HRP is valid")
}

pub(crate) fn piv_tag(pk: &PublicKey) -> [u8; TAG_BYTES] {
    let tag = Sha256::digest(piv_to_str(pk).as_bytes());
    (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    epk: PublicKey,
    encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: RECIPIENT_TAG.to_owned(),
            args: vec![
                base64::encode_config(&r.tag, base64::STANDARD_NO_PAD),
                base64::encode_config(r.epk.as_bytes(), base64::STANDARD_NO_PAD),
            ],
            body: r.encrypted_file_key.to_vec(),
        }
    }
}

impl RecipientLine {
    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &PublicKey) -> Self {
        let rng = SystemRandom::new();

        let esk = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("TODO handle failing RNG");
        let epk = PublicKey::from_bytes(esk.compute_public_key().expect("TODO").as_ref())
            .expect("epk is valid");

        let pk_uncompressed = pk.decompress();
        let pk_ring = UnparsedPublicKey::new(&ECDH_P256, pk_uncompressed.as_bytes());

        let enc_key = agree_ephemeral(esk, &pk_ring, (), |shared_secret| {
            let mut salt = vec![];
            salt.extend_from_slice(epk.as_bytes());
            salt.extend_from_slice(pk.as_bytes());

            Ok(hkdf(&salt, RECIPIENT_KEY_LABEL, shared_secret))
        })
        .expect("keys are correct");

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientLine {
            tag: piv_tag(pk),
            epk,
            encrypted_file_key,
        }
        .into()
    }
}
