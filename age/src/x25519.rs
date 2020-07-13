//! The native age identity type.

use age_core::{
    format::AgeStanza,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};
use bech32::{FromBase32, ToBase32};
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use std::convert::TryInto;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{error::Error, keys::FileKey, util::read::base64_arg};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";
const PUBLIC_KEY_PREFIX: &str = "age";

pub(super) const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub(super) const EPK_LEN_BYTES: usize = 32;
pub(super) const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

fn parse_bech32(s: &str, expected_hrp: &str) -> Option<Result<[u8; 32], &'static str>> {
    bech32::decode(s).ok().map(|(hrp, data)| {
        if hrp == expected_hrp.to_lowercase() {
            if let Ok(bytes) = Vec::from_base32(&data) {
                bytes[..].try_into().map_err(|_| "incorrect pubkey length")
            } else {
                Err("incorrect Bech32 data padding")
            }
        } else {
            Err("incorrect HRP")
        }
    })
}

/// A secret key for decrypting an age file.
pub struct Identity(StaticSecret);

impl Identity {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Identity(StaticSecret::new(&mut rng))
    }

    /// Serializes this secret key as a string.
    pub fn to_string(&self) -> SecretString {
        let mut sk_bytes = self.0.to_bytes();
        let sk_base32 = sk_bytes.to_base32();
        let mut encoded = bech32::encode(SECRET_KEY_PREFIX, sk_base32).expect("HRP is valid");
        let ret = SecretString::new(encoded.to_uppercase());

        // Clear intermediates
        sk_bytes.zeroize();
        // TODO: bech32::u5 doesn't implement Zeroize
        // sk_base32.zeroize();
        encoded.zeroize();

        ret
    }

    /// Returns the recipient key for this secret key.
    pub fn to_public(&self) -> Recipient {
        Recipient((&self.0).into())
    }
}

impl crate::Identity for Identity {
    fn unwrap_file_key(
        &self,
        stanza: &crate::format::RecipientStanza,
    ) -> Option<Result<FileKey, Error>> {
        match stanza {
            crate::format::RecipientStanza::X25519(r) => {
                // A failure to decrypt is non-fatal (we try to decrypt the recipient
                // stanza with other X25519 keys), because we cannot tell which key
                // matches a particular stanza.
                r.unwrap_file_key(&self.0).ok().map(Ok)
            }
            _ => None,
        }
    }
}

/// The standard age public key.
#[derive(Clone)]
pub struct Recipient(PublicKey);

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s, PUBLIC_KEY_PREFIX)
            .ok_or("Invalid Bech32 encoding")?
            .map(PublicKey::from)
            .map(Recipient)
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            bech32::encode(PUBLIC_KEY_PREFIX, self.0.as_bytes().to_base32()).expect("HRP is valid")
        )
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(&self, file_key: &FileKey) -> crate::format::RecipientStanza {
        RecipientStanza::wrap_file_key(file_key, &self.0).into()
    }
}

/// TODO: Remove
#[derive(Debug)]
pub struct RecipientStanza {
    pub(crate) epk: PublicKey,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return None;
        }

        let epk = base64_arg(stanza.args.get(0)?, [0; EPK_LEN_BYTES])?;

        Some(RecipientStanza {
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
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientStanza {
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
            .map(|mut pt| {
                // It's ours!
                let file_key: [u8; 16] = pt[..].try_into().unwrap();
                pt.zeroize();
                file_key.into()
            })
    }
}

pub(crate) mod read {
    use nom::{
        bytes::streaming::take,
        combinator::{map_opt, map_res},
        IResult,
    };

    use super::*;

    pub(crate) fn age_secret_key(input: &str) -> IResult<&str, Identity> {
        map_res(
            map_opt(take(74u32), |buf| parse_bech32(buf, SECRET_KEY_PREFIX)),
            |pk| pk.map(StaticSecret::from).map(Identity),
        )(input)
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::{RecipientStanza, X25519_RECIPIENT_TAG};

    pub(crate) fn recipient_stanza<'a, W: 'a + Write>(
        r: &'a RecipientStanza,
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
pub(crate) mod tests {
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use secrecy::ExposeSecret;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{read::age_secret_key, Recipient, RecipientStanza};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    pub(crate) const TEST_PK: &str =
        "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";

    #[test]
    fn pubkey_encoding() {
        let pk: Recipient = TEST_PK.parse().unwrap();
        assert_eq!(pk.to_string(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        let (_, key) = age_secret_key(TEST_SK).unwrap();
        assert_eq!(key.to_public().to_string(), TEST_PK);
    }

    #[quickcheck]
    fn wrap_and_unwrap(sk_bytes: Vec<u8>) -> TestResult {
        if sk_bytes.len() > 32 {
            return TestResult::discard();
        }

        let file_key = [7; 16].into();
        let sk = {
            let mut tmp = [0; 32];
            tmp[..sk_bytes.len()].copy_from_slice(&sk_bytes);
            StaticSecret::from(tmp)
        };

        let stanza = RecipientStanza::wrap_file_key(&file_key, &PublicKey::from(&sk));
        let res = stanza.unwrap_file_key(&sk);

        TestResult::from_bool(
            res.is_ok() && res.unwrap().expose_secret() == file_key.expose_secret(),
        )
    }
}
