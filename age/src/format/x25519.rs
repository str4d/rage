use age_core::{
    format::AgeStanza,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use std::convert::TryInto;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{error::Error, keys::FileKey, util::read::base64_arg};

pub(super) const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub(super) const EPK_LEN_BYTES: usize = 32;
pub(super) const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) epk: PublicKey,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientLine {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return None;
        }

        let epk = base64_arg(stanza.args.get(0)?, [0; EPK_LEN_BYTES])?;

        Some(RecipientLine {
            epk: epk.into(),
            encrypted_file_key: stanza.body[..].try_into().ok()?,
        })
    }

    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &PublicKey) -> Self {
        let mut rng = OsRng;
        let esk = EphemeralSecret::new(&mut rng);
        let epk: PublicKey = (&esk).into();
        let shared_secret = esk.diffie_hellman(pk);

        let mut salt = vec![];
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, shared_secret.as_bytes());
        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            epk,
            encrypted_file_key,
        }
    }

    pub(crate) fn unwrap_file_key(&self, sk: &StaticSecret) -> Result<FileKey, Error> {
        let pk: PublicKey = sk.into();
        let shared_secret = sk.diffie_hellman(&self.epk);

        let mut salt = vec![];
        salt.extend_from_slice(self.epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, shared_secret.as_bytes());

        aead_decrypt(&enc_key, &self.encrypted_file_key)
            .map_err(Error::from)
            .map(|pt| {
                // It's ours!
                let mut file_key = [0; 16];
                file_key.copy_from_slice(&pt);
                FileKey(Secret::new(file_key))
            })
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::{RecipientLine, X25519_RECIPIENT_TAG};

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &'a RecipientLine,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_epk = base64::encode_config(r.epk.as_bytes(), base64::STANDARD_NO_PAD);
            let args = &[encoded_epk.as_str()];
            let writer = age_stanza(X25519_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use secrecy::{ExposeSecret, Secret};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::RecipientLine;
    use crate::keys::FileKey;

    #[quickcheck]
    fn wrap_and_unwrap(sk_bytes: Vec<u8>) -> TestResult {
        if sk_bytes.len() > 32 {
            return TestResult::discard();
        }

        let file_key = FileKey(Secret::new([7; 16]));
        let sk = {
            let mut tmp = [0; 32];
            tmp[..sk_bytes.len()].copy_from_slice(&sk_bytes);
            StaticSecret::from(tmp)
        };

        let line = RecipientLine::wrap_file_key(&file_key, &PublicKey::from(&sk));
        let res = line.unwrap_file_key(&sk);

        TestResult::from_bool(
            res.is_ok() && res.unwrap().0.expose_secret() == file_key.0.expose_secret(),
        )
    }
}
