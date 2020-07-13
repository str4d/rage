use age_core::primitives::{aead_encrypt, hkdf};
use curve25519_dalek::edwards::EdwardsPoint;
use nom::{
    branch::alt,
    bytes::streaming::tag,
    combinator::{map, map_opt},
    sequence::{pair, preceded},
    IResult,
};
use rand::rngs::OsRng;
use rsa::{padding::PaddingScheme, PublicKey};
use secrecy::ExposeSecret;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use super::{
    read_ssh, ssh_tag, SSH_ED25519_KEY_PREFIX, SSH_ED25519_RECIPIENT_KEY_LABEL,
    SSH_ED25519_RECIPIENT_TAG, SSH_RSA_KEY_PREFIX, SSH_RSA_OAEP_LABEL, SSH_RSA_RECIPIENT_TAG,
};
use crate::{
    format::RecipientStanza,
    keys::FileKey,
    util::read::{encoded_str, str_while_encoded},
};

/// A key that can be used to encrypt a file to a recipient.
#[derive(Clone, Debug)]
pub enum Recipient {
    /// An ssh-rsa public key.
    SshRsa(Vec<u8>, rsa::RSAPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, EdwardsPoint),
}

/// Error conditions when parsing an SSH recipient.
#[derive(Debug)]
pub enum ParseRecipientKeyError {
    /// The string is a parseable value that should be ignored. This case is for handling
    /// SSH recipient types that may occur in files we want to be able to parse, but that
    /// we do not directly support.
    Ignore,
    /// The string is not a valid SSH recipient.
    Invalid(&'static str),
}

impl std::str::FromStr for Recipient {
    type Err = ParseRecipientKeyError;

    /// Parses an SSH recipient from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ssh_recipient(s) {
            Ok((_, Some(pk))) => Ok(pk),
            Ok((_, None)) => Err(ParseRecipientKeyError::Ignore),
            _ => Err(ParseRecipientKeyError::Invalid("invalid SSH recipient")),
        }
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Recipient::SshRsa(ssh_key, _) => {
                write!(f, "{} {}", SSH_RSA_KEY_PREFIX, base64::encode(&ssh_key))
            }
            Recipient::SshEd25519(ssh_key, _) => {
                write!(f, "{} {}", SSH_ED25519_KEY_PREFIX, base64::encode(&ssh_key))
            }
        }
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(&self, file_key: &FileKey) -> RecipientStanza {
        match self {
            Recipient::SshRsa(ssh_key, pk) => {
                let mut rng = OsRng;

                let encrypted_file_key = pk
                    .encrypt(
                        &mut rng,
                        PaddingScheme::new_oaep_with_label::<Sha256, _>(SSH_RSA_OAEP_LABEL),
                        file_key.expose_secret(),
                    )
                    .expect("pubkey is valid and file key is not too long");

                let encoded_tag =
                    base64::encode_config(&ssh_tag(&ssh_key), base64::STANDARD_NO_PAD);

                RecipientStanza {
                    tag: SSH_RSA_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag],
                    body: encrypted_file_key,
                }
            }
            Recipient::SshEd25519(ssh_key, ed25519_pk) => {
                let pk: X25519PublicKey = ed25519_pk.to_montgomery().to_bytes().into();

                let mut rng = OsRng;
                let esk = EphemeralSecret::new(&mut rng);
                let epk: X25519PublicKey = (&esk).into();

                let tweak: StaticSecret =
                    hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
                let shared_secret =
                    tweak.diffie_hellman(&(*esk.diffie_hellman(&pk).as_bytes()).into());

                let mut salt = vec![];
                salt.extend_from_slice(epk.as_bytes());
                salt.extend_from_slice(pk.as_bytes());

                let enc_key = hkdf(
                    &salt,
                    SSH_ED25519_RECIPIENT_KEY_LABEL,
                    shared_secret.as_bytes(),
                );
                let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

                let encoded_tag =
                    base64::encode_config(&ssh_tag(&ssh_key), base64::STANDARD_NO_PAD);
                let encoded_epk = base64::encode_config(epk.as_bytes(), base64::STANDARD_NO_PAD);

                RecipientStanza {
                    tag: SSH_ED25519_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag, encoded_epk],
                    body: encrypted_file_key,
                }
            }
        }
    }
}

fn ssh_rsa_pubkey(input: &str) -> IResult<&str, Option<Recipient>> {
    preceded(
        pair(tag(SSH_RSA_KEY_PREFIX), tag(" ")),
        map_opt(
            str_while_encoded(base64::STANDARD_NO_PAD),
            |ssh_key| match read_ssh::rsa_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(Recipient::SshRsa(ssh_key, pk))),
                Err(_) => None,
            },
        ),
    )(input)
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, Option<Recipient>> {
    preceded(
        pair(tag(SSH_ED25519_KEY_PREFIX), tag(" ")),
        map_opt(
            encoded_str(51, base64::STANDARD_NO_PAD),
            |ssh_key| match read_ssh::ed25519_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(Recipient::SshEd25519(ssh_key, pk))),
                Err(_) => None,
            },
        ),
    )(input)
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, Option<Recipient>> {
    // Key types we want to ignore in SSH pubkey files
    preceded(
        pair(tag("ecdsa-sha2-nistp256"), tag(" ")),
        map(str_while_encoded(base64::STANDARD_NO_PAD), |_| None),
    )(input)
}

pub(crate) fn ssh_recipient(input: &str) -> IResult<&str, Option<Recipient>> {
    alt((ssh_rsa_pubkey, ssh_ed25519_pubkey, ssh_ignore_pubkey))(input)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Recipient;

    pub(crate) const TEST_SSH_RSA_PK: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE7nIXTGNuaRBN9toI/wNALuQec8mvlt0iJ7o3OaD2UvoKHJ7S8rmIn4FiQDUed/Vac3OhUibei1k+TBmm16u2Rj3klgWZOIDgi8d4vXKI5N3YBhxr3jsQ+kz1c+iZ4z/tTtz306+4K46XViVMWwyyg9j82Jn41mOAy9vdeDIfQ5fLeaGqn5KwlT61GNkZ+ozWK/ZNlQIlNCcoXxhJULIs9XrtczWyVBAea1nlDo0WHODePxoJjmsNHrpQXn5mf9O83xs10qfTUjnRUt48jRmedFy4tcra3QGmSTQ3KZne+wXXSb0cIpXLGvZjQSPHgG1hc4r3uBpiSzvesGLv79XL alice@rust";
    pub(crate) const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

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
}
