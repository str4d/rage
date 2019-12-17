use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{
    error::Error,
    keys::FileKey,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};

const X25519_RECIPIENT_TAG: &[u8] = b"X25519 ";
pub(crate) const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-tool.com X25519";

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) epk: PublicKey,
    pub(crate) encrypted_file_key: [u8; 32],
}

impl RecipientLine {
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
            let mut key = [0; 32];
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

pub(super) mod read {
    use nom::{
        bytes::streaming::tag,
        combinator::map,
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    pub(crate) fn epk(input: &[u8]) -> IResult<&[u8], PublicKey> {
        map(encoded_data(32, [0; 32]), PublicKey::from)(input)
    }

    pub(crate) fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(X25519_RECIPIENT_TAG),
                map(
                    separated_pair(epk, line_ending, encoded_data(32, [0; 32])),
                    |(epk, encrypted_file_key)| RecipientLine {
                        epk,
                        encrypted_file_key,
                    },
                ),
            )(input)
        }
    }
}

pub(super) mod write {
    use cookie_factory::{
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(X25519_RECIPIENT_TAG),
            encoded_data(r.epk.as_bytes()),
            string(line_ending),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
