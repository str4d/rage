use nom::{
    branch::alt,
    bytes::streaming::{is_not, tag},
    character::streaming::newline,
    combinator::{map_opt, opt},
    sequence::{pair, preceded, terminated, tuple},
    IResult,
};
use secrecy::{ExposeSecret, Secret};
use std::fmt;

use super::{read_asn1, read_ssh, write_ssh, EncryptedKey};
use crate::{
    error::Error, format::RecipientStanza, keys::FileKey, protocol::Callbacks,
    util::read::wrapped_str_while_encoded,
};

/// An SSH private key for decrypting an age file.
pub enum UnencryptedKey {
    /// An ssh-rsa private key.
    SshRsa(Vec<u8>, Box<rsa::RSAPrivateKey>),
    /// An ssh-ed25519 key pair.
    SshEd25519(Vec<u8>, Secret<[u8; 64]>),
}

impl UnencryptedKey {
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the [`RecipientStanza`] does not match this key.
    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
    ) -> Option<Result<FileKey, Error>> {
        match (self, stanza) {
            (UnencryptedKey::SshRsa(ssh_key, sk), RecipientStanza::SshRsa(r)) => {
                r.unwrap_file_key(ssh_key, sk)
            }
            (UnencryptedKey::SshEd25519(ssh_key, privkey), RecipientStanza::SshEd25519(r)) => {
                r.unwrap_file_key(ssh_key, privkey.expose_secret())
            }
            _ => None,
        }
    }
}

/// A key that we know how to parse, but that we do not support.
///
/// The Display impl provides details for each unsupported key as to why we don't support
/// it, and how a user can migrate to a supported key.
#[derive(Clone, Debug)]
pub enum UnsupportedKey {
    /// An encrypted `PEM` key.
    EncryptedPem,
    /// An encrypted SSH key using a specific cipher.
    EncryptedSsh(String),
}

impl fmt::Display for UnsupportedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UnsupportedKey::EncryptedPem => {
                let message = [
                    "Insecure Encrypted Key Format",
                    "-----------------------------",
                    "Prior to OpenSSH version 7.8, if a password was set when generating a new",
                    "DSA, ECDSA, or RSA key, ssh-keygen would encrypt the key using the encrypted",
                    "PEM format. This encryption format is insecure and should no longer be used.",
                    "",
                    "You can migrate your key to the encrypted SSH private key format (which has",
                    "been supported by OpenSSH since version 6.5, released in January 2014) by",
                    "changing its passphrase with the following command:",
                    "",
                    "    ssh-keygen -o -p",
                    "",
                    "If you are using an OpenSSH version between 6.5 and 7.7 (such as the default",
                    "OpenSSH provided on Ubuntu 18.04 LTS), you can use the following command to",
                    "force keys to be generated using the new format:",
                    "",
                    "    ssh-keygen -o",
                ];
                for line in &message {
                    writeln!(f, "{}", line)?;
                }
            }
            UnsupportedKey::EncryptedSsh(cipher) => {
                let currently_unsupported = format!("currently-unsupported cipher ({}).", cipher);
                let new_issue = format!(
                    "https://github.com/str4d/rage/issues/new?title=Support%20OpenSSH%20key%20encryption%20cipher%20{}",
                    cipher,
                );
                let message = [
                    "Unsupported Cipher for Encrypted SSH Key",
                    "----------------------------------------",
                    "OpenSSH internally supports several different ciphers for encrypted keys,",
                    "but it has only ever directly generated a few of them. rage supports all",
                    "ciphers that ssh-keygen might generate, and is being updated on a",
                    "case-by-case basis with support for non-standard ciphers. Your key uses a",
                    &currently_unsupported,
                    "",
                    "If you would like support for this key type, please open an issue here:",
                    "",
                    &new_issue,
                ];
                for line in &message {
                    writeln!(f, "{}", line)?;
                }
            }
        }
        Ok(())
    }
}

/// An SSH private key for decrypting an age file.
pub enum Identity {
    /// An unencrypted key.
    Unencrypted(UnencryptedKey),
    /// An encrypted key.
    Encrypted(EncryptedKey),
    /// A key that we know how to parse, but that we do not support.
    Unsupported(UnsupportedKey),
}

impl From<UnencryptedKey> for Identity {
    fn from(key: UnencryptedKey) -> Self {
        Identity::Unencrypted(key)
    }
}

impl From<EncryptedKey> for Identity {
    fn from(key: EncryptedKey) -> Self {
        Identity::Encrypted(key)
    }
}

impl From<UnsupportedKey> for Identity {
    fn from(key: UnsupportedKey) -> Self {
        Identity::Unsupported(key)
    }
}

impl Identity {
    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
        callbacks: &dyn Callbacks,
        filename: Option<&str>,
    ) -> Option<Result<FileKey, Error>> {
        match self {
            Identity::Unencrypted(key) => key.unwrap_file_key(stanza),
            Identity::Encrypted(enc) => {
                let passphrase = callbacks.request_passphrase(&format!(
                    "Type passphrase for OpenSSH key '{}'",
                    filename.unwrap_or_default()
                ))?;
                let decrypted = match enc.decrypt(passphrase) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                decrypted.unwrap_file_key(stanza)
            }
            Identity::Unsupported(_) => None,
        }
    }
}

fn rsa_pem_encryption_header(input: &str) -> IResult<&str, &str> {
    preceded(
        tuple((tag("Proc-Type: 4,ENCRYPTED"), newline, tag("DEK-Info: "))),
        terminated(is_not("\n"), newline),
    )(input)
}

fn rsa_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN RSA PRIVATE KEY-----"), newline),
        terminated(
            map_opt(
                pair(
                    opt(terminated(rsa_pem_encryption_header, newline)),
                    wrapped_str_while_encoded(base64::STANDARD),
                ),
                |(enc_header, privkey)| {
                    if enc_header.is_some() {
                        Some(UnsupportedKey::EncryptedPem.into())
                    } else {
                        read_asn1::rsa_privkey(&privkey).ok().map(|(_, privkey)| {
                            let mut ssh_key = vec![];
                            cookie_factory::gen(
                                write_ssh::rsa_pubkey(&privkey.to_public_key()),
                                &mut ssh_key,
                            )
                            .expect("can write into a Vec");
                            UnencryptedKey::SshRsa(ssh_key, Box::new(privkey)).into()
                        })
                    }
                },
            ),
            pair(newline, tag("-----END RSA PRIVATE KEY-----")),
        ),
    )(input)
}

fn openssh_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), newline),
        terminated(
            map_opt(wrapped_str_while_encoded(base64::STANDARD), |privkey| {
                read_ssh::openssh_privkey(&privkey).ok().map(|(_, key)| key)
            }),
            pair(newline, tag("-----END OPENSSH PRIVATE KEY-----")),
        ),
    )(input)
}

pub(crate) fn ssh_identity(input: &str) -> IResult<&str, Identity> {
    alt((rsa_privkey, openssh_privkey))(input)
}
