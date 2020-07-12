//! Key structs and serialization.

use age_core::primitives::hkdf;
use bech32::{FromBase32, ToBase32};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, Secret, SecretString};
use std::convert::TryInto;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    error::Error,
    format::{x25519, HeaderV1, RecipientStanza},
    primitives::{stream::PayloadKey, HmacKey},
    protocol::Nonce,
    ssh,
};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";
const PUBLIC_KEY_PREFIX: &str = "age";

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

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

/// A file key for encrypting or decrypting an age file.
pub struct FileKey(Secret<[u8; 16]>);

impl From<[u8; 16]> for FileKey {
    fn from(file_key: [u8; 16]) -> Self {
        FileKey(Secret::new(file_key))
    }
}

impl ExposeSecret<[u8; 16]> for FileKey {
    fn expose_secret(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

impl FileKey {
    pub(crate) fn generate() -> Self {
        let mut file_key = [0; 16];
        OsRng.fill_bytes(&mut file_key);
        file_key.into()
    }

    pub(crate) fn mac_key(&self) -> HmacKey {
        HmacKey(Secret::new(hkdf(
            &[],
            HEADER_KEY_LABEL,
            self.0.expose_secret(),
        )))
    }

    pub(crate) fn v1_payload_key(
        &self,
        header: &HeaderV1,
        nonce: &Nonce,
    ) -> Result<PayloadKey, Error> {
        // Verify the MAC
        header.verify_mac(self.mac_key())?;

        // Return the payload key
        Ok(PayloadKey(
            hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, self.0.expose_secret()).into(),
        ))
    }
}

/// A secret key for decrypting an age file.
pub struct SecretKey(StaticSecret);

impl SecretKey {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        SecretKey(StaticSecret::new(&mut rng))
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
    pub fn to_public(&self) -> RecipientKey {
        RecipientKey::X25519((&self.0).into())
    }
}

impl crate::Identity for SecretKey {
    fn unwrap_file_key(&self, stanza: &RecipientStanza) -> Option<Result<FileKey, Error>> {
        match stanza {
            RecipientStanza::X25519(r) => {
                // A failure to decrypt is non-fatal (we try to decrypt the recipient
                // stanza with other X25519 keys), because we cannot tell which key
                // matches a particular stanza.
                r.unwrap_file_key(&self.0).ok().map(Ok)
            }
            _ => None,
        }
    }
}

/// A key that can be used to encrypt a file to a recipient.
#[derive(Clone, Debug)]
pub enum RecipientKey {
    /// An X25519 recipient key.
    X25519(PublicKey),
    /// An SSH recipient.
    Ssh(ssh::Recipient),
}

impl From<ssh::Recipient> for RecipientKey {
    fn from(key: ssh::Recipient) -> Self {
        RecipientKey::Ssh(key)
    }
}

/// Error conditions when parsing a recipient key.
#[derive(Debug)]
pub enum ParseRecipientKeyError {
    /// The string is a parseable value that should be ignored. This case is for handling
    /// OpenSSH pubkey types that may occur in files we want to be able to parse, but that
    /// we do not directly support.
    Ignore,
    /// The string is not a valid recipient key.
    Invalid(&'static str),
}

impl std::str::FromStr for RecipientKey {
    type Err = ParseRecipientKeyError;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as an age pubkey
        if let Some(pk) = parse_bech32(s, PUBLIC_KEY_PREFIX) {
            return pk
                .map_err(ParseRecipientKeyError::Invalid)
                .map(PublicKey::from)
                .map(RecipientKey::X25519);
        }

        // Try parsing as an OpenSSH pubkey
        Ok(RecipientKey::Ssh(s.parse().map_err(|e| match e {
            ssh::recipient::ParseRecipientKeyError::Ignore => Self::Err::Ignore,
            ssh::recipient::ParseRecipientKeyError::Invalid(e) => Self::Err::Invalid(e),
        })?))
    }
}

impl fmt::Display for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecipientKey::X25519(pk) => write!(
                f,
                "{}",
                bech32::encode(PUBLIC_KEY_PREFIX, pk.as_bytes().to_base32()).expect("HRP is valid")
            ),
            RecipientKey::Ssh(r) => write!(f, "{}", r),
        }
    }
}

impl RecipientKey {
    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientStanza {
        match self {
            RecipientKey::X25519(pk) => x25519::RecipientStanza::wrap_file_key(file_key, pk).into(),
            RecipientKey::Ssh(r) => r.wrap_file_key(file_key).into(),
        }
    }
}

pub(crate) mod read {
    use nom::{
        bytes::streaming::take,
        combinator::{map_opt, map_res},
        IResult,
    };

    use super::*;

    pub(crate) fn age_secret_key(input: &str) -> IResult<&str, SecretKey> {
        map_res(
            map_opt(take(74u32), |buf| parse_bech32(buf, SECRET_KEY_PREFIX)),
            |pk| pk.map(StaticSecret::from).map(SecretKey),
        )(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{read::age_secret_key, RecipientKey};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    pub(crate) const TEST_PK: &str =
        "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";

    #[test]
    fn pubkey_encoding() {
        let pk: RecipientKey = TEST_PK.parse().unwrap();
        assert_eq!(pk.to_string(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        let (_, key) = age_secret_key(TEST_SK).unwrap();
        assert_eq!(key.to_public().to_string(), TEST_PK);
    }
}
