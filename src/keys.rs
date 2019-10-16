//! Key structs and serialization.

use curve25519_dalek::edwards::CompressedEdwardsY;
use getrandom::getrandom;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::{
    format::RecipientLine,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};

const SECRET_KEY_PREFIX: &str = "AGE_SECRET_KEY_";
const PUBLIC_KEY_PREFIX: &str = "pubkey:";

const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-tool.com X25519";
const SSH_RSA_OAEP_LABEL: &str = "age-tool.com ssh-rsa";
const SSH_ED25519_TWEAK_LABEL: &[u8] = b"age-tool.com ssh-ed25519";

fn convert_ed25519_to_x25519(ed: &[u8; 32]) -> [u8; 32] {
    CompressedEdwardsY::from_slice(ed)
        .decompress()
        .expect("we only deal in valid points")
        .to_montgomery()
        .to_bytes()
}

fn ssh_tag(pubkey: &[u8]) -> [u8; 4] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; 4];
    tag.copy_from_slice(&tag_bytes[..4]);
    tag
}

/// A secret key for decrypting an age message.
pub enum SecretKey {
    /// An X25519 secret key.
    X25519([u8; 32]),
}

impl SecretKey {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let mut sk = [0; 32];
        getrandom(&mut sk).expect("Should not fail");
        SecretKey::X25519(sk)
    }

    /// Parses a secret key from a string.
    pub fn from_data<R: BufRead>(data: R) -> io::Result<Vec<Self>> {
        // Try parsing as a list of age keys
        let mut keys = vec![];
        for line in data.lines() {
            let line = line?;

            // Skip empty lines and comments
            if !(line.is_empty() || line.starts_with('#')) {
                if let Ok((_, pk)) = read::secret_key(&line) {
                    keys.push(pk);
                }
            }
        }
        Ok(keys)
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
            _ => None,
        }
    }
}

/// A key that can be used to encrypt an age message to a recipient.
pub enum RecipientKey {
    /// An X25519 recipient key.
    X25519([u8; 32]),
    /// An ssh-rsa public key.
    SshRsa(Vec<u8>, rsa::RSAPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, [u8; 32]),
}

impl std::str::FromStr for RecipientKey {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as an age pubkey
        if let Ok((_, pk)) = read::recipient_key(s) {
            return Ok(pk);
        }

        Err("invalid recipient key")
    }
}

impl RecipientKey {
    /// Serializes this recipient key as a string.
    pub fn to_str(&self) -> String {
        match self {
            RecipientKey::X25519(pk) => format!(
                "{}{}",
                PUBLIC_KEY_PREFIX,
                base64::encode_config(&pk, base64::URL_SAFE_NO_PAD)
            ),
            RecipientKey::SshRsa(_, _) => unimplemented!(),
            RecipientKey::SshEd25519(_, _) => unimplemented!(),
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
            RecipientKey::SshRsa(ssh_key, pk) => {
                let mut rng = rand::rngs::OsRng::new().expect("should have RNG");
                let mut h = Sha256::default();

                let encrypted_file_key = rsa::oaep::encrypt(
                    &mut rng,
                    &pk,
                    file_key,
                    &mut h,
                    Some(SSH_RSA_OAEP_LABEL.to_owned()),
                )
                .unwrap();

                RecipientLine::ssh_rsa(ssh_tag(&ssh_key), encrypted_file_key)
            }
            RecipientKey::SshEd25519(ssh_key, ed25519_pk) => {
                let tweak = hkdf(&ssh_key, SSH_ED25519_TWEAK_LABEL, &[]);
                let pk = x25519(tweak, convert_ed25519_to_x25519(ed25519_pk));

                let mut esk = [0; 32];
                getrandom(&mut esk).expect("Should not fail");
                let epk = x25519(esk, X25519_BASEPOINT_BYTES);
                let shared_secret = x25519(esk, pk);

                let mut salt = vec![];
                salt.extend_from_slice(&epk);
                salt.extend_from_slice(&pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                let encrypted_file_key = aead_encrypt(&enc_key, file_key).unwrap();

                RecipientLine::ssh_ed25519(ssh_tag(&ssh_key), epk, encrypted_file_key)
            }
        }
    }
}

mod read {
    use nom::{branch::alt, bytes::streaming::tag, sequence::preceded, IResult};

    use super::*;
    use crate::{openssh::ssh_recipient_key, util::read_encoded_str};

    fn age_secret_key(input: &str) -> IResult<&str, SecretKey> {
        let (i, buf) = preceded(
            tag(SECRET_KEY_PREFIX),
            read_encoded_str(32, base64::URL_SAFE_NO_PAD),
        )(input)?;

        let mut pk = [0; 32];
        pk.copy_from_slice(&buf);
        Ok((i, SecretKey::X25519(pk)))
    }

    pub(super) fn secret_key(input: &str) -> IResult<&str, SecretKey> {
        age_secret_key(input)
    }

    fn age_recipient_key(input: &str) -> IResult<&str, RecipientKey> {
        let (i, buf) = preceded(
            tag(PUBLIC_KEY_PREFIX),
            read_encoded_str(32, base64::URL_SAFE_NO_PAD),
        )(input)?;

        let mut pk = [0; 32];
        pk.copy_from_slice(&buf);
        Ok((i, RecipientKey::X25519(pk)))
    }

    pub(super) fn recipient_key(input: &str) -> IResult<&str, RecipientKey> {
        alt((age_recipient_key, ssh_recipient_key))(input)
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::{RecipientKey, SecretKey};

    const TEST_SK: &str = "AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg";
    const TEST_PK: &str = "pubkey:X4ZiZYoURuOqC2_GPISYiWbJn1-j_HECyac7BpD6kHU";

    #[test]
    fn secret_key_encoding() {
        let buf = BufReader::new(TEST_SK.as_bytes());
        let keys = SecretKey::from_data(buf).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_str(), TEST_SK);
    }

    #[test]
    fn pubkey_encoding() {
        let pk: RecipientKey = TEST_PK.parse().unwrap();
        assert_eq!(pk.to_str(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        let buf = BufReader::new(TEST_SK.as_bytes());
        let keys = SecretKey::from_data(buf).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_public().to_str(), TEST_PK);
    }
}
