use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, hkdf},
};
use i18n_embed_fl::fl;
use nom::{
    branch::alt,
    bytes::streaming::{is_not, tag},
    character::streaming::{line_ending, newline},
    combinator::{map_opt, opt},
    sequence::{pair, preceded, terminated, tuple},
    IResult,
};
use rand::rngs::OsRng;
use rsa::padding::PaddingScheme;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;
use std::fmt;
use std::io;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::{
    read_asn1, read_ssh, ssh_tag, write_ssh, EncryptedKey, SSH_ED25519_RECIPIENT_KEY_LABEL,
    SSH_ED25519_RECIPIENT_TAG, SSH_RSA_OAEP_LABEL, SSH_RSA_RECIPIENT_TAG, TAG_LEN_BYTES,
};
use crate::{
    error::DecryptError,
    util::read::{base64_arg, wrapped_str_while_encoded},
    Callbacks,
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
    /// - `None` if the [`Stanza`] does not match this key.
    pub(crate) fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        match (self, stanza.tag.as_str()) {
            (UnencryptedKey::SshRsa(ssh_key, sk), SSH_RSA_RECIPIENT_TAG) => {
                let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;
                if ssh_tag(&ssh_key) != tag {
                    return None;
                }

                let mut rng = OsRng;

                // A failure to decrypt is fatal, because we assume that we won't
                // encounter 32-bit collisions on the key tag embedded in the header.
                Some(
                    sk.decrypt_blinded(
                        &mut rng,
                        PaddingScheme::new_oaep_with_label::<Sha256, _>(SSH_RSA_OAEP_LABEL),
                        &stanza.body,
                    )
                    .map_err(DecryptError::from)
                    .map(|mut pt| {
                        // It's ours!
                        let file_key: [u8; 16] = pt[..].try_into().unwrap();
                        pt.zeroize();
                        file_key.into()
                    }),
                )
            }
            (UnencryptedKey::SshEd25519(ssh_key, privkey), SSH_ED25519_RECIPIENT_TAG) => {
                let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;
                if ssh_tag(&ssh_key) != tag {
                    return None;
                }
                if stanza.body.len() != crate::x25519::ENCRYPTED_FILE_KEY_BYTES {
                    return Some(Err(DecryptError::InvalidHeader));
                }

                let epk =
                    base64_arg(stanza.args.get(1)?, [0; crate::x25519::EPK_LEN_BYTES])?.into();

                let sk: StaticSecret = {
                    let mut sk = [0; 32];
                    // privkey format is seed || pubkey
                    sk.copy_from_slice(&Sha512::digest(&privkey.expose_secret()[0..32])[0..32]);
                    sk.into()
                };
                let pk = X25519PublicKey::from(&sk);

                let tweak: StaticSecret =
                    hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
                let shared_secret = tweak
                    .diffie_hellman(&X25519PublicKey::from(*sk.diffie_hellman(&epk).as_bytes()));

                let mut salt = vec![];
                salt.extend_from_slice(epk.as_bytes());
                salt.extend_from_slice(pk.as_bytes());

                let enc_key = hkdf(
                    &salt,
                    SSH_ED25519_RECIPIENT_KEY_LABEL,
                    shared_secret.as_bytes(),
                );

                // A failure to decrypt is fatal, because we assume that we won't
                // encounter 32-bit collisions on the key tag embedded in the header.
                Some(
                    aead_decrypt(&enc_key, FILE_KEY_BYTES, &stanza.body)
                        .map_err(DecryptError::from)
                        .map(|mut pt| {
                            // It's ours!
                            let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                            pt.zeroize();
                            file_key.into()
                        }),
                )
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

impl UnsupportedKey {
    /// Prints details about this unsupported identity.
    pub fn display(&self, f: &mut fmt::Formatter, filename: Option<&str>) -> fmt::Result {
        if let Some(name) = filename {
            writeln!(
                f,
                "{}",
                fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "ssh-unsupported-identity",
                    name = name
                )
            )?;
            writeln!(f)?;
        }
        match self {
            UnsupportedKey::EncryptedPem => writeln!(
                f,
                "{}",
                fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "ssh-insecure-key-format",
                    change_passphrase = "ssh-keygen -o -p",
                    gen_new = "ssh-keygen -o"
                )
            )?,
            UnsupportedKey::EncryptedSsh(cipher) => {
                let new_issue = format!(
                    "https://github.com/str4d/rage/issues/new?title=Support%20OpenSSH%20key%20encryption%20cipher%20{}",
                    cipher,
                );
                writeln!(
                    f,
                    "{}",
                    fl!(
                        crate::i18n::LANGUAGE_LOADER,
                        "ssh-unsupported-cipher",
                        cipher = cipher.as_str(),
                        new_issue = new_issue.as_str()
                    )
                )?;
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
    /// Parses one or more identities from a buffered input containing valid UTF-8.
    ///
    /// `filename` is the path to the file that the input is reading from, if any.
    pub fn from_buffer<R: io::BufRead>(mut data: R, filename: Option<String>) -> io::Result<Self> {
        let mut buf = String::new();
        loop {
            match ssh_identity(&buf) {
                Ok((_, mut identity)) => {
                    // If we know the filename, cache it.
                    if let Identity::Encrypted(key) = &mut identity {
                        key.filename = filename;
                    }

                    break Ok(identity);
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(_))) => {
                    if data.read_line(&mut buf)? == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "incomplete SSH identity in file",
                        ));
                    };
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SSH identity",
                    ));
                }
            }
        }
    }

    /// Wraps this identity with the provided callbacks, so that if this is an encrypted
    /// identity, it can potentially be decrypted.
    pub fn with_callbacks<C: Callbacks>(self, callbacks: C) -> impl crate::Identity {
        DecryptableIdentity {
            identity: self,
            callbacks,
        }
    }
}

impl crate::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        match self {
            Identity::Unencrypted(key) => key.unwrap_stanza(stanza),
            Identity::Encrypted(_) | Identity::Unsupported(_) => None,
        }
    }
}

struct DecryptableIdentity<C: Callbacks> {
    identity: Identity,
    callbacks: C,
}

impl<C: Callbacks> crate::Identity for DecryptableIdentity<C> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        match &self.identity {
            Identity::Unencrypted(key) => key.unwrap_stanza(stanza),
            Identity::Encrypted(enc) => {
                let passphrase = self.callbacks.request_passphrase(&fl!(
                    crate::i18n::LANGUAGE_LOADER,
                    "ssh-passphrase-prompt",
                    filename = enc.filename.as_deref().unwrap_or_default()
                ))?;
                let decrypted = match enc.decrypt(passphrase) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                decrypted.unwrap_stanza(stanza)
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
        pair(tag("-----BEGIN RSA PRIVATE KEY-----"), line_ending),
        terminated(
            map_opt(
                pair(
                    opt(terminated(rsa_pem_encryption_header, line_ending)),
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
            pair(line_ending, tag("-----END RSA PRIVATE KEY-----")),
        ),
    )(input)
}

fn openssh_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), line_ending),
        terminated(
            map_opt(wrapped_str_while_encoded(base64::STANDARD), |privkey| {
                read_ssh::openssh_privkey(&privkey).ok().map(|(_, key)| key)
            }),
            pair(line_ending, tag("-----END OPENSSH PRIVATE KEY-----")),
        ),
    )(input)
}

pub(crate) fn ssh_identity(input: &str) -> IResult<&str, Identity> {
    alt((rsa_privkey, openssh_privkey))(input)
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::Identity;
    use crate::{
        ssh::recipient::{
            tests::{TEST_SSH_ED25519_PK, TEST_SSH_RSA_PK},
            Recipient,
        },
        Identity as _, Recipient as _,
    };

    pub(crate) const TEST_SSH_RSA_SK: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxO5yF0xjbmkQTfbaCP8DQC7kHnPJr5bdIie6Nzmg9lL6Chye
0vK5iJ+BYkA1Hnf1WnNzoVIm3otZPkwZptertkY95JYFmTiA4IvHeL1yiOTd2AYc
a947EPpM9XPomeM/7U7c99OvuCuOl1YlTFsMsoPY/NiZ+NZjgMvb3XgyH0OXy3mh
qp+SsJU+tRjZGfqM1iv2TZUCJTQnKF8YSVCyLPV67XM1slQQHmtZ5Q6NFhzg3j8a
CY5rDR66UF5+Zn/TvN8bNdKn01I50VLePI0ZnnRcuLXK2t0Bpkk0NymZ3vsF10m9
HCKVyxr2Y0Ejx4BtYXOK97gaYks73rBi7+/VywIDAQABAoIBADGsf8TWtOH9yGoS
ES9hu90ttsbjqAUNhdv+r18Mv0hC5+UzEPDe3uPScB1rWrrDwXS+WHVhtoI+HhWz
tmi6UArbLvOA0Aq1EPUS7Q7Mop5bNIYwDG09EiMXL+BeC1b91nsygFRW5iULf502
0pOvB8XjshEdRcFZuqGbSmtTzTjLLxYS/aboBtZLHrH4cRlFMpHWCSuJng8Psahp
SnJbkjL7fHG81dlH+M3qm5EwdDJ1UmNkBfoSfGRs2pupk2cSJaL+SPkvNX+6Xyoy
yvfnbJzKUTcV6rf+0S0P0yrWK3zRK9maPJ1N60lFui9LvFsunCLkSAluGKiMwEjb
fm40F4kCgYEA+QzIeIGMwnaOQdAW4oc7hX5MgRPXJ836iALy56BCkZpZMjZ+VKpk
8P4E1HrEywpgqHMox08hfCTGX3Ph6fFIlS1/mkLojcgkrqmg1IrRvh8vvaZqzaAf
GKEhxxRta9Pvm44E2nUY97iCKzE3Vfh+FIyQLRuc+0COu49Me4HPtBUCgYEAym1T
vNZKPfC/eTMh+MbWMsQArOePdoHQyRC38zeWrLaDFOUVzwzEvCQ0IzSs0PnLWkZ4
xx60wBg5ZdU4iH4cnOYgjavQrbRFrCmZ1KDUm2+NAMw3avcLQqu41jqzyAlkktUL
fZzyqHIBmKYLqut5GslkGnQVg6hB4psutHhiel8CgYA3yy9WH9/C6QBxqgaWdSlW
fLby69j1p+WKdu6oCXUgXW3CHActPIckniPC3kYcHpUM58+o5wdfYnW2iKWB3XYf
RXQiwP6MVNwy7PmE5Byc9Sui1xdyPX75648/pEnnMDGrraNUtYsEZCd1Oa9l6SeF
vv/Fuzvt5caUKkQ+HxTDCQKBgFhqUiXr7zeIvQkiFVeE+a/ovmbHKXlYkCoSPFZm
VFCR00VAHjt2V0PaCE/MRSNtx61hlIVcWxSAQCnDbNLpSnQZa+SVRCtqzve4n/Eo
YlSV75+GkzoMN4XiXXRs5XOc7qnXlhJCiBac3Segdv4rpZTWm/uV8oOz7TseDtNS
tai/AoGAC0CiIJAzmmXscXNS/stLrL9bb3Yb+VZi9zN7Cb/w7B0IJ35N5UOFmKWA
QIGpMU4gh6p52S1eLttpIf2+39rEDzo8pY6BVmEp3fKN3jWmGS4mJQ31tWefupC+
fGNu+wyKxPnSU3svsuvrOdwwDKvfqCNyYK878qKAAaBqbGT1NJ8=
-----END RSA PRIVATE KEY-----";

    pub(crate) const TEST_SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(TEST_SSH_RSA_SK.as_bytes());
        let identity = Identity::from_buffer(buf, None).unwrap();
        match &identity {
            Identity::Unencrypted(_) => (),
            _ => panic!("key should be unencrypted"),
        };
        let pk: Recipient = TEST_SSH_RSA_PK.parse().unwrap();

        let file_key = [12; 16].into();

        let wrapped = pk.wrap_file_key(&file_key).unwrap();
        let unwrapped = identity.unwrap_stanzas(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().expose_secret(),
            file_key.expose_secret()
        );
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(TEST_SSH_ED25519_SK.as_bytes());
        let identity = Identity::from_buffer(buf, None).unwrap();
        match &identity {
            Identity::Unencrypted(_) => (),
            _ => panic!("key should be unencrypted"),
        };
        let pk: Recipient = TEST_SSH_ED25519_PK.parse().unwrap();

        let file_key = [12; 16].into();

        let wrapped = pk.wrap_file_key(&file_key).unwrap();
        let unwrapped = identity.unwrap_stanzas(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().expose_secret(),
            file_key.expose_secret()
        );
    }
}
