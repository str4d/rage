use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, hkdf},
    secrecy::ExposeSecret,
};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
    Engine,
};
use curve25519_dalek::edwards::EdwardsPoint;
use nom::{
    branch::alt,
    bytes::streaming::{is_not, tag},
    combinator::map_opt,
    sequence::{pair, preceded, separated_pair},
    IResult,
};
use rand::rngs::OsRng;
use rsa::{traits::PublicKeyParts, Oaep};
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use super::{
    identity::{Identity, UnencryptedKey},
    read_ssh, ssh_tag, EncryptedKey, UnsupportedKey, SSH_ED25519_KEY_PREFIX,
    SSH_ED25519_RECIPIENT_KEY_LABEL, SSH_ED25519_RECIPIENT_TAG, SSH_RSA_KEY_PREFIX,
    SSH_RSA_OAEP_LABEL, SSH_RSA_RECIPIENT_TAG,
};
use crate::{
    error::EncryptError,
    util::read::{encoded_str, str_while_encoded},
};

/// A key that can be used to encrypt a file to a recipient.
#[derive(Clone, Debug)]
pub enum Recipient {
    /// An ssh-rsa public key.
    SshRsa(Vec<u8>, rsa::RsaPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, EdwardsPoint),
}

pub(crate) enum ParsedRecipient {
    Supported(Recipient),
    RsaModulusTooLarge,
    RsaModulusTooSmall,
    Unsupported(String),
}

/// Error conditions when parsing an SSH recipient.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseRecipientKeyError {
    /// The string is a parseable value that should be ignored. This case is for handling
    /// SSH recipient types that may occur in files we want to be able to parse, but that
    /// we do not directly support.
    Ignore,
    /// The string is not a valid SSH recipient.
    Invalid(&'static str),
    /// The string is an `ssh-rsa` public key with a modulus larger than we support.
    RsaModulusTooLarge,
    /// The string is a weak `ssh-rsa` public key with a modulus smaller than 2048 bits.
    RsaModulusTooSmall,
    /// The string is a parseable value that corresponds to an unsupported SSH key type.
    Unsupported(String),
}

impl std::str::FromStr for Recipient {
    type Err = ParseRecipientKeyError;

    /// Parses an SSH recipient from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ssh_recipient(rsa::RsaPublicKey::MAX_SIZE)(s) {
            Ok((_, ParsedRecipient::Supported(pk))) => Ok(pk),
            Ok((_, ParsedRecipient::RsaModulusTooLarge)) => {
                Err(ParseRecipientKeyError::RsaModulusTooLarge)
            }
            Ok((_, ParsedRecipient::RsaModulusTooSmall)) => {
                Err(ParseRecipientKeyError::RsaModulusTooSmall)
            }
            Ok((_, ParsedRecipient::Unsupported(key_type))) => {
                Err(ParseRecipientKeyError::Unsupported(key_type))
            }
            _ => Err(ParseRecipientKeyError::Invalid("invalid SSH recipient")),
        }
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Recipient::SshRsa(ssh_key, _) => {
                write!(
                    f,
                    "{} {}",
                    SSH_RSA_KEY_PREFIX,
                    BASE64_STANDARD.encode(ssh_key)
                )
            }
            Recipient::SshEd25519(ssh_key, _) => {
                write!(
                    f,
                    "{} {}",
                    SSH_ED25519_KEY_PREFIX,
                    BASE64_STANDARD.encode(ssh_key)
                )
            }
        }
    }
}

impl TryFrom<Identity> for Recipient {
    type Error = ParseRecipientKeyError;

    fn try_from(identity: Identity) -> Result<Self, Self::Error> {
        match identity {
            Identity::Unencrypted(UnencryptedKey::SshRsa(ssh_key, _))
            | Identity::Unencrypted(UnencryptedKey::SshEd25519(ssh_key, _))
            | Identity::Encrypted(EncryptedKey { ssh_key, .. }) => {
                if let Ok((_, pk)) = read_ssh::rsa_pubkey(rsa::RsaPublicKey::MAX_SIZE)(&ssh_key) {
                    if let Some(pk) = pk {
                        Ok(Recipient::SshRsa(ssh_key, pk))
                    } else {
                        Err(ParseRecipientKeyError::RsaModulusTooLarge)
                    }
                } else if let Ok((_, pk)) = read_ssh::ed25519_pubkey(&ssh_key) {
                    Ok(Recipient::SshEd25519(ssh_key, pk))
                } else if let Ok((_, key_type)) = read_ssh::string(&ssh_key) {
                    Err(ParseRecipientKeyError::Unsupported(
                        String::from_utf8_lossy(key_type).to_string(),
                    ))
                } else {
                    Err(ParseRecipientKeyError::Invalid(
                        "Invalid SSH pubkey in SSH privkey",
                    ))
                }
            }
            Identity::Unsupported(
                UnsupportedKey::Hardware(key_type) | UnsupportedKey::Type(key_type),
            ) => Err(ParseRecipientKeyError::Unsupported(key_type)),
            Identity::Unsupported(_) => Err(ParseRecipientKeyError::Ignore),
        }
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError> {
        let mut rng = OsRng;

        match self {
            Recipient::SshRsa(ssh_key, pk) => {
                let encrypted_file_key = pk
                    .encrypt(
                        &mut rng,
                        Oaep::new_with_label::<Sha256, _>(SSH_RSA_OAEP_LABEL),
                        file_key.expose_secret(),
                    )
                    .expect("pubkey is valid and file key is not too long");

                let encoded_tag = BASE64_STANDARD_NO_PAD.encode(ssh_tag(ssh_key));

                Ok(vec![Stanza {
                    tag: SSH_RSA_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag],
                    body: encrypted_file_key,
                }])
            }
            Recipient::SshEd25519(ssh_key, ed25519_pk) => {
                let pk: X25519PublicKey = ed25519_pk.to_montgomery().to_bytes().into();

                let esk = EphemeralSecret::random_from_rng(rng);
                let epk: X25519PublicKey = (&esk).into();

                let tweak: StaticSecret =
                    hkdf(ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
                let shared_secret =
                    tweak.diffie_hellman(&(*esk.diffie_hellman(&pk).as_bytes()).into());

                let mut salt = [0; 64];
                salt[..32].copy_from_slice(epk.as_bytes());
                salt[32..].copy_from_slice(pk.as_bytes());

                let enc_key = hkdf(
                    &salt,
                    SSH_ED25519_RECIPIENT_KEY_LABEL,
                    shared_secret.as_bytes(),
                );
                let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

                let encoded_tag = BASE64_STANDARD_NO_PAD.encode(ssh_tag(ssh_key));
                let encoded_epk = BASE64_STANDARD_NO_PAD.encode(epk.as_bytes());

                Ok(vec![Stanza {
                    tag: SSH_ED25519_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag, encoded_epk],
                    body: encrypted_file_key,
                }])
            }
        }
    }
}

fn ssh_rsa_pubkey(max_size: usize) -> impl Fn(&str) -> IResult<&str, ParsedRecipient> {
    move |input: &str| {
        preceded(
            pair(tag(SSH_RSA_KEY_PREFIX), tag(" ")),
            map_opt(
                str_while_encoded(BASE64_STANDARD_NO_PAD),
                |ssh_key| match read_ssh::rsa_pubkey(max_size)(&ssh_key) {
                    Ok((_, Some(pk))) => Some(if pk.n().bits() < 2048 {
                        ParsedRecipient::RsaModulusTooSmall
                    } else {
                        ParsedRecipient::Supported(Recipient::SshRsa(ssh_key, pk))
                    }),
                    Ok((_, None)) => Some(ParsedRecipient::RsaModulusTooLarge),
                    Err(_) => None,
                },
            ),
        )(input)
    }
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, ParsedRecipient> {
    preceded(
        pair(tag(SSH_ED25519_KEY_PREFIX), tag(" ")),
        map_opt(
            encoded_str(51, BASE64_STANDARD_NO_PAD),
            |ssh_key| match read_ssh::ed25519_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(ParsedRecipient::Supported(Recipient::SshEd25519(
                    ssh_key, pk,
                ))),
                Err(_) => None,
            },
        ),
    )(input)
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, ParsedRecipient> {
    // We rely on the invariant that SSH public keys are always of the form
    // `key_type Base64(string(key_type) || ...)` to detect valid pubkeys.
    map_opt(
        separated_pair(
            is_not(" "),
            tag(" "),
            str_while_encoded(BASE64_STANDARD_NO_PAD),
        ),
        |(key_type, ssh_key)| {
            read_ssh::string_tag(key_type)(&ssh_key)
                .map(|_| ParsedRecipient::Unsupported(key_type.to_string()))
                .ok()
        },
    )(input)
}

pub(crate) fn ssh_recipient(max_size: usize) -> impl Fn(&str) -> IResult<&str, ParsedRecipient> {
    move |input| {
        alt((
            ssh_rsa_pubkey(max_size),
            ssh_ed25519_pubkey,
            ssh_ignore_pubkey,
        ))(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{ParseRecipientKeyError, Recipient};

    pub(crate) const TEST_SSH_RSA_PK: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE7nIXTGNuaRBN9toI/wNALuQec8mvlt0iJ7o3OaD2UvoKHJ7S8rmIn4FiQDUed/Vac3OhUibei1k+TBmm16u2Rj3klgWZOIDgi8d4vXKI5N3YBhxr3jsQ+kz1c+iZ4z/tTtz306+4K46XViVMWwyyg9j82Jn41mOAy9vdeDIfQ5fLeaGqn5KwlT61GNkZ+ozWK/ZNlQIlNCcoXxhJULIs9XrtczWyVBAea1nlDo0WHODePxoJjmsNHrpQXn5mf9O83xs10qfTUjnRUt48jRmedFy4tcra3QGmSTQ3KZne+wXXSb0cIpXLGvZjQSPHgG1hc4r3uBpiSzvesGLv79XL alice@rust";
    pub(crate) const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const TEST_SSH_UNSUPPORTED_PK: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHFliOyIZs1gxGF3fmDxFykQhE88wy6AKDGFBfn0R6ZuvRmENABZQa9+pj9hMki+LX0qDJbmHTiWDbYv/cmFt/Q=";
    const TEST_SSH_INVALID_PK: &str = "ecdsa-sha2-nistp256 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

    #[test]
    fn ssh_rsa_encoding() {
        let pk: Recipient = TEST_SSH_RSA_PK.parse().unwrap();
        assert_eq!(pk.to_string() + " alice@rust", TEST_SSH_RSA_PK);
    }

    #[test]
    fn ssh_ed25519_encoding() {
        let pk: Recipient = TEST_SSH_ED25519_PK.parse().unwrap();
        assert_eq!(pk.to_string() + " alice@rust", TEST_SSH_ED25519_PK);
    }

    #[test]
    fn ssh_unsupported_key_type() {
        let pk: Result<Recipient, ParseRecipientKeyError> = TEST_SSH_UNSUPPORTED_PK.parse();
        assert_eq!(
            pk.unwrap_err(),
            ParseRecipientKeyError::Unsupported("ecdsa-sha2-nistp256".to_string()),
        );
    }

    #[test]
    fn ssh_invalid_encoding() {
        let pk: Result<Recipient, ParseRecipientKeyError> = TEST_SSH_INVALID_PK.parse();
        assert_eq!(
            pk.unwrap_err(),
            ParseRecipientKeyError::Invalid("invalid SSH recipient")
        );
    }
}
