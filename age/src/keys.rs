//! Key structs and serialization.

use age_core::primitives::hkdf;
use bech32::{FromBase32, ToBase32};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, Secret, SecretString};
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    error::Error,
    format::{x25519, HeaderV1, RecipientStanza},
    primitives::{stream::PayloadKey, HmacKey},
    protocol::{Callbacks, Nonce},
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

pub(crate) struct FileKey(pub(crate) Secret<[u8; 16]>);

impl FileKey {
    pub(crate) fn generate() -> Self {
        let mut file_key = [0; 16];
        OsRng.fill_bytes(&mut file_key);
        FileKey(Secret::new(file_key))
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

    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the [`RecipientStanza`] does not match this key.
    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
    ) -> Option<Result<FileKey, Error>> {
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

/// An key that has been parsed from some input.
pub enum IdentityKey {
    /// An X25519 age key.
    X25519(SecretKey),
    /// An SSH private key.
    Ssh(ssh::Identity),
}

/// An identity that has been parsed from some input.
pub struct Identity {
    filename: Option<String>,
    key: IdentityKey,
}

impl From<SecretKey> for Identity {
    fn from(key: SecretKey) -> Self {
        Identity {
            filename: None,
            key: IdentityKey::X25519(key),
        }
    }
}

impl From<ssh::Identity> for Identity {
    fn from(key: ssh::Identity) -> Self {
        Identity {
            filename: None,
            key: IdentityKey::Ssh(key),
        }
    }
}

impl Identity {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Vec<Self>> {
        let buf = BufReader::new(File::open(filename.clone())?);
        let mut keys = Identity::from_buffer(buf)?;

        // We have context here about the filename.
        for key in &mut keys {
            key.filename = Some(filename.clone());
        }

        Ok(keys)
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: BufRead>(mut data: R) -> io::Result<Vec<Self>> {
        let mut buf = String::new();
        loop {
            match read::age_secret_keys(&buf) {
                Ok((_, keys)) => {
                    // Ensure we've found all keys in the file
                    if data.read_line(&mut buf)? == 0 {
                        break Ok(keys);
                    }
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(_))) => {
                    if data.read_line(&mut buf)? == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "incomplete secret keys in file",
                        ));
                    };
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid secret key file",
                    ));
                }
            }
        }
    }

    /// Returns the key corresponding to this identity.
    pub fn key(&self) -> &IdentityKey {
        &self.key
    }

    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
        callbacks: &dyn Callbacks,
    ) -> Option<Result<FileKey, Error>> {
        match &self.key {
            IdentityKey::X25519(key) => key.unwrap_file_key(stanza),
            IdentityKey::Ssh(key) => key.unwrap_file_key(stanza, callbacks),
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

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::complete::{line_ending, not_line_ending},
        combinator::{all_consuming, iterator, map, map_opt, map_parser, map_res, rest},
        sequence::{terminated, tuple},
        IResult,
    };

    use super::*;

    fn age_secret_key(input: &str) -> IResult<&str, Identity> {
        map_res(
            map_opt(take(74u32), |buf| parse_bech32(buf, SECRET_KEY_PREFIX)),
            |pk| {
                pk.map(StaticSecret::from)
                    .map(SecretKey)
                    .map(Identity::from)
            },
        )(input)
    }

    fn age_secret_keys_line(input: &str) -> IResult<&str, Option<Identity>> {
        alt((
            // Skip empty lines
            map(all_consuming(tag("")), |_| None),
            // Skip comments
            map(all_consuming(tuple((tag("#"), rest))), |_| None),
            // All other lines must be valid age secret keys.
            map(all_consuming(age_secret_key), Some),
        ))(input)
    }

    pub(super) fn age_secret_keys(input: &str) -> IResult<&str, Vec<Identity>> {
        // Parse all lines that have line endings.
        let mut it = iterator(
            input,
            terminated(
                map_parser(not_line_ending, age_secret_keys_line),
                line_ending,
            ),
        );
        let mut keys: Vec<_> = it.filter_map(|x| x).collect();

        it.finish().and_then(|(i, _)| {
            // Handle the last line, which does not have a line ending.
            age_secret_keys_line(i).map(|(i, res)| {
                if let Some(k) = res {
                    keys.push(k);
                }
                (i, keys)
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::{Identity, IdentityKey, RecipientKey};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    pub(crate) const TEST_PK: &str =
        "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";

    fn valid_secret_key_encoding(keydata: &str, num_keys: usize) {
        let buf = BufReader::new(keydata.as_bytes());
        let keys = Identity::from_buffer(buf).unwrap();
        assert_eq!(keys.len(), num_keys);
        let key = match keys[0].key() {
            IdentityKey::X25519(key) => key,
            _ => panic!("key should be X25519"),
        };
        assert_eq!(key.to_string().expose_secret(), TEST_SK);
    }

    #[test]
    fn secret_key_encoding() {
        valid_secret_key_encoding(TEST_SK, 1);
    }

    #[test]
    fn secret_key_lf() {
        valid_secret_key_encoding(&format!("{}\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_lf() {
        valid_secret_key_encoding(&format!("{}\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_lf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_lf() {
        valid_secret_key_encoding(&format!("\n\n{}", TEST_SK), 1);
    }

    #[test]
    fn secret_key_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_crlf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\r\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\r\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_crlf() {
        valid_secret_key_encoding(&format!("\r\n\r\n{}", TEST_SK), 1);
    }

    #[test]
    fn incomplete_secret_key_encoding() {
        let buf = BufReader::new(&TEST_SK.as_bytes()[..4]);
        assert!(Identity::from_buffer(buf).is_err());
    }

    #[test]
    fn pubkey_encoding() {
        let pk: RecipientKey = TEST_PK.parse().unwrap();
        assert_eq!(pk.to_string(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        let buf = BufReader::new(TEST_SK.as_bytes());
        let keys = Identity::from_buffer(buf).unwrap();
        assert_eq!(keys.len(), 1);
        let key = match keys[0].key() {
            IdentityKey::X25519(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        assert_eq!(key.to_public().to_string(), TEST_PK);
    }
}
