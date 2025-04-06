//! The "x25519" recipient type, native to age.

use std::collections::HashSet;
use std::fmt;

use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt, hkdf},
    secrecy::{ExposeSecret, SecretString},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::{ToBase32, Variant};
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    error::{DecryptError, EncryptError},
    util::{parse_bech32, read::base64_arg},
};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";
const PUBLIC_KEY_PREFIX: &str = "age";

pub(super) const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub(super) const EPK_LEN_BYTES: usize = 32;
pub(super) const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// The standard age identity type, which can decrypt files encrypted to the corresponding
/// [`Recipient`].
#[derive(Clone)]
pub struct Identity(StaticSecret);

impl std::str::FromStr for Identity {
    type Err = &'static str;

    /// Parses an X25519 identity from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, bytes)| {
                if hrp == SECRET_KEY_PREFIX {
                    TryInto::<[u8; 32]>::try_into(&bytes[..])
                        .map_err(|_| "incorrect identity length")
                        .map(StaticSecret::from)
                        .map(Identity)
                } else {
                    Err("incorrect HRP")
                }
            })
    }
}

impl Identity {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let rng = OsRng;
        Identity(StaticSecret::random_from_rng(rng))
    }

    /// Serializes this secret key as a string.
    pub fn to_string(&self) -> SecretString {
        let mut sk_bytes = self.0.to_bytes();
        let sk_base32 = sk_bytes.to_base32();
        let mut encoded =
            bech32::encode(SECRET_KEY_PREFIX, sk_base32, Variant::Bech32).expect("HRP is valid");
        let ret = SecretString::from(encoded.to_uppercase());

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
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return None;
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#x25519-recipient-stanza
        let ephemeral_share = match &stanza.args[..] {
            [arg] => match base64_arg::<_, EPK_LEN_BYTES, 33>(arg) {
                Some(ephemeral_share) => ephemeral_share,
                None => return Some(Err(DecryptError::InvalidHeader)),
            },
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let epk: PublicKey = ephemeral_share.into();
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .expect("Length should have been checked above");

        let pk: PublicKey = (&self.0).into();
        let shared_secret = self.0.diffie_hellman(&epk);
        // Replace with `SharedSecret::was_contributory` once x25519-dalek supports newer
        // zeroize (https://github.com/dalek-cryptography/x25519-dalek/issues/74#issuecomment-1159481280).
        if shared_secret
            .as_bytes()
            .iter()
            .fold(0, |acc, b| acc | b)
            .ct_eq(&0)
            .into()
        {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let mut salt = [0; 64];
        salt[..32].copy_from_slice(epk.as_bytes());
        salt[32..].copy_from_slice(pk.as_bytes());

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, shared_secret.as_bytes());

        // A failure to decrypt is non-fatal (we try to decrypt the recipient
        // stanza with other X25519 keys), because we cannot tell which key
        // matches a particular stanza.
        aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key)
            .ok()
            .map(|mut pt| {
                // It's ours!
                Ok(FileKey::init_with_mut(|file_key| {
                    file_key.copy_from_slice(&pt);
                    pt.zeroize();
                }))
            })
    }
}

/// The standard age recipient type. Files encrypted to this recipient can be decrypted
/// with the corresponding [`Identity`].
///
/// This recipient type is anonymous, in the sense that an attacker can't tell from the
/// age-encrypted file alone if it is encrypted to a certain recipient.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Recipient(PublicKey);

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, bytes)| {
                if hrp == PUBLIC_KEY_PREFIX {
                    TryInto::<[u8; 32]>::try_into(&bytes[..])
                        .map_err(|_| "incorrect pubkey length")
                        .map(PublicKey::from)
                        .map(Recipient)
                } else {
                    Err("incorrect HRP")
                }
            })
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            bech32::encode(
                PUBLIC_KEY_PREFIX,
                self.0.as_bytes().to_base32(),
                Variant::Bech32
            )
            .expect("HRP is valid")
        )
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let rng = OsRng;
        let esk = EphemeralSecret::random_from_rng(rng);
        let epk: PublicKey = (&esk).into();
        let shared_secret = esk.diffie_hellman(&self.0);

        // It is vanishingly unlikely that we generate the all-zero esk, so if we do then
        // it is likely that the RNG is bad, and we should fail loudly.
        // Replace with `SharedSecret::was_contributory` once x25519-dalek supports
        // newer zeroize (https://github.com/dalek-cryptography/x25519-dalek/issues/74#issuecomment-1159481280).
        if bool::from(
            shared_secret
                .as_bytes()
                .iter()
                .fold(0, |acc, b| acc | b)
                .ct_eq(&0),
        ) {
            panic!("Generated the all-zero esk; OS RNG is likely failing!");
        }

        let mut salt = [0; 64];
        salt[..32].copy_from_slice(epk.as_bytes());
        salt[32..].copy_from_slice(self.0.as_bytes());

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, shared_secret.as_bytes());
        let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

        let encoded_epk = BASE64_STANDARD_NO_PAD.encode(epk.as_bytes());

        Ok((
            vec![Stanza {
                tag: X25519_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_epk],
                body: encrypted_file_key,
            }],
            HashSet::new(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age_core::{format::FileKey, secrecy::ExposeSecret};
    use proptest::prelude::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{Identity, Recipient};
    use crate::{Identity as _, Recipient as _};

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
        let key = TEST_SK.parse::<Identity>().unwrap();
        assert_eq!(key.to_public().to_string(), TEST_PK);
    }

    proptest! {
        #[test]
        fn wrap_and_unwrap(sk_bytes in proptest::collection::vec(any::<u8>(), ..=32)) {
            let file_key = FileKey::new(Box::new([7; 16]));
            let sk = {
                let mut tmp = [0; 32];
                tmp[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                StaticSecret::from(tmp)
            };

            let res = Recipient(PublicKey::from(&sk))
                .wrap_file_key(&file_key);
            prop_assert!(res.is_ok());
            let (stanzas, labels) = res.unwrap();
            prop_assert!(labels.is_empty());

            let res = Identity(sk).unwrap_stanzas(&stanzas);
            prop_assert!(res.is_some());
            let res = res.unwrap();
            prop_assert!(res.is_ok());
            let res = res.unwrap();

            prop_assert_eq!(res.expose_secret(), file_key.expose_secret());
        }
    }
}
