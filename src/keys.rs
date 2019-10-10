//! Key structs and serialization.

use getrandom::getrandom;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::{
    format::RecipientLine,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};

const SECRET_KEY_PREFIX: &str = "AGE_SECRET_KEY_";
const PUBLIC_KEY_PREFIX: &str = "pubkey:";

const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-tool.com X25519";

/// A secret key for decrypting an age message.
pub enum SecretKey {
    /// An X25519 secret key.
    X25519([u8; 32]),
}

impl SecretKey {
    /// Generates a new secret key.
    pub fn new() -> Self {
        let mut sk = [0; 32];
        getrandom(&mut sk).expect("Should not fail");
        SecretKey::X25519(sk)
    }

    /// Parses a secret key from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.find(SECRET_KEY_PREFIX) {
            Some(0) => (),
            _ => return None,
        }

        base64::decode_config(&s[SECRET_KEY_PREFIX.len()..], base64::URL_SAFE_NO_PAD)
            .ok()
            .and_then(|buf| {
                if buf.len() == 32 {
                    let mut sk = [0; 32];
                    sk.copy_from_slice(&buf);
                    Some(SecretKey::X25519(sk))
                } else {
                    None
                }
            })
    }

    /// Serializes this secret key as a string.
    pub fn to_str(&self) -> String {
        match self {
            SecretKey::X25519(sk) => format!(
                "{}{}",
                SECRET_KEY_PREFIX,
                base64::encode_config(&sk, base64::URL_SAFE_NO_PAD)
            ),
        }
    }

    /// Returns the recipient key for this secret key.
    pub fn to_public(&self) -> RecipientKey {
        match self {
            SecretKey::X25519(sk) => RecipientKey::X25519(x25519(*sk, X25519_BASEPOINT_BYTES)),
        }
    }

    pub(crate) fn unwrap(&self, line: &RecipientLine) -> Option<[u8; 16]> {
        match (self, line) {
            (_, RecipientLine::Scrypt(_)) => None,
            (SecretKey::X25519(sk), RecipientLine::X25519(r)) => {
                let pk = x25519(*sk, X25519_BASEPOINT_BYTES);
                let shared_secret = x25519(*sk, r.epk);

                let mut salt = vec![];
                salt.extend_from_slice(&r.epk);
                salt.extend_from_slice(&pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                aead_decrypt(&enc_key, &r.encrypted_file_key).map(|pt| {
                    // It's ours!
                    let mut file_key = [0; 16];
                    file_key.copy_from_slice(&pt);
                    file_key
                })
            }
        }
    }
}

/// A key that can be used to encrypt an age message to a recipient.
pub enum RecipientKey {
    /// An X25519 recipient key.
    X25519([u8; 32]),
}

impl RecipientKey {
    /// Parses a recipient key from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.find(PUBLIC_KEY_PREFIX) {
            Some(0) => (),
            _ => return None,
        }

        base64::decode_config(&s[PUBLIC_KEY_PREFIX.len()..], base64::URL_SAFE_NO_PAD)
            .ok()
            .and_then(|buf| {
                if buf.len() == 32 {
                    let mut pk = [0; 32];
                    pk.copy_from_slice(&buf);
                    Some(RecipientKey::X25519(pk))
                } else {
                    println!("Invalid decoded length");
                    None
                }
            })
    }

    /// Serializes this recipient key as a string.
    pub fn to_str(&self) -> String {
        match self {
            RecipientKey::X25519(pk) => format!(
                "{}{}",
                PUBLIC_KEY_PREFIX,
                base64::encode_config(&pk, base64::URL_SAFE_NO_PAD)
            ),
        }
    }

    pub(crate) fn wrap(&self, file_key: &[u8; 16]) -> RecipientLine {
        match self {
            RecipientKey::X25519(pk) => {
                let mut esk = [0; 32];
                getrandom(&mut esk).expect("Should not fail");
                let epk = x25519(esk, X25519_BASEPOINT_BYTES);
                let shared_secret = x25519(esk, *pk);

                let mut salt = vec![];
                salt.extend_from_slice(&epk);
                salt.extend_from_slice(pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                let encrypted_file_key = aead_encrypt(&enc_key, file_key).unwrap();

                RecipientLine::x25519(epk, encrypted_file_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RecipientKey, SecretKey};

    const TEST_SK: &str = "AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg";
    const TEST_PK: &str = "pubkey:X4ZiZYoURuOqC2_GPISYiWbJn1-j_HECyac7BpD6kHU";

    #[test]
    fn secret_key_encoding() {
        assert_eq!(SecretKey::from_str(TEST_SK).unwrap().to_str(), TEST_SK);
    }

    #[test]
    fn pubkey_encoding() {
        assert_eq!(RecipientKey::from_str(TEST_PK).unwrap().to_str(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        assert_eq!(
            SecretKey::from_str(TEST_SK).unwrap().to_public().to_str(),
            TEST_PK
        );
    }
}
