//! Key structs and serialization.

use curve25519_dalek::edwards::EdwardsPoint;
use getrandom::getrandom;
use sha2::{Digest, Sha256, Sha512};
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
    /// An ssh-rsa private key.
    SshRsa(Vec<u8>, Box<rsa::RSAPrivateKey>),
    /// An ssh-ed25519 key pair.
    SshEd25519(Vec<u8>, [u8; 64]),
}

impl SecretKey {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let mut sk = [0; 32];
        getrandom(&mut sk).expect("Should not fail");
        SecretKey::X25519(sk)
    }

    /// Parses a list of secret keys from a string.
    pub fn from_data<R: BufRead>(mut data: R) -> io::Result<Vec<Self>> {
        let mut buf = String::new();
        loop {
            match read::secret_keys(&buf) {
                Ok((_, keys)) => {
                    // Ensure we've found all keys in the file
                    if data.read_line(&mut buf)? == 0 {
                        break Ok(keys);
                    }
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(_))) => {
                    data.read_line(&mut buf)?;
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

    /// Serializes this secret key as a string.
    pub fn to_str(&self) -> String {
        match self {
            SecretKey::X25519(sk) => format!(
                "{}{}",
                SECRET_KEY_PREFIX,
                base64::encode_config(&sk, base64::URL_SAFE_NO_PAD)
            ),
            SecretKey::SshRsa(_, _) => unimplemented!(),
            SecretKey::SshEd25519(_, _) => unimplemented!(),
        }
    }

    /// Returns the recipient key for this secret key.
    pub fn to_public(&self) -> RecipientKey {
        match self {
            SecretKey::X25519(sk) => RecipientKey::X25519(x25519(*sk, X25519_BASEPOINT_BYTES)),
            SecretKey::SshRsa(_, _) => unimplemented!(),
            SecretKey::SshEd25519(_, _) => unimplemented!(),
        }
    }

    pub(crate) fn unwrap_file_key(&self, line: &RecipientLine) -> Option<[u8; 16]> {
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
            (SecretKey::SshRsa(ssh_key, sk), RecipientLine::SshRsa(r)) => {
                if ssh_tag(&ssh_key) != r.tag {
                    return None;
                }

                let mut rng = rand::rngs::OsRng::new().expect("should have RNG");
                let mut h = Sha256::default();

                rsa::oaep::decrypt(
                    Some(&mut rng),
                    &sk,
                    &r.encrypted_file_key,
                    &mut h,
                    Some(SSH_RSA_OAEP_LABEL.to_owned()),
                )
                .ok()
                .map(|pt| {
                    // It's ours!
                    let mut file_key = [0; 16];
                    file_key.copy_from_slice(&pt);
                    file_key
                })
            }
            (SecretKey::SshEd25519(ssh_key, privkey), RecipientLine::SshEd25519(r)) => {
                if ssh_tag(&ssh_key) != r.tag {
                    return None;
                }

                let sk = {
                    let mut sk = [0; 32];
                    // privkey format is seed || pubkey
                    sk.copy_from_slice(&Sha512::digest(&privkey[0..32])[0..32]);
                    sk
                };

                let tweak = hkdf(&ssh_key, SSH_ED25519_TWEAK_LABEL, &[]);
                let pk = x25519(tweak, x25519(sk, X25519_BASEPOINT_BYTES));

                let shared_secret = x25519(tweak, x25519(sk, r.rest.epk));

                let mut salt = vec![];
                salt.extend_from_slice(&r.rest.epk);
                salt.extend_from_slice(&pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                aead_decrypt(&enc_key, &r.rest.encrypted_file_key).map(|pt| {
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
#[derive(Debug)]
pub enum RecipientKey {
    /// An X25519 recipient key.
    X25519([u8; 32]),
    /// An ssh-rsa public key.
    SshRsa(Vec<u8>, rsa::RSAPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, EdwardsPoint),
}

#[derive(Debug)]
pub enum ParseRecipientKeyError {
    Ignore,
    Invalid(&'static str),
}

impl std::str::FromStr for RecipientKey {
    type Err = ParseRecipientKeyError;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as an age pubkey
        if let Ok((_, pk)) = read::age_recipient_key(s) {
            return Ok(pk);
        }

        // Try parsing as an OpenSSH pubkey
        match crate::openssh::ssh_recipient_key(s) {
            Ok((_, Some(pk))) => Ok(pk),
            Ok((_, None)) => Err(ParseRecipientKeyError::Ignore),
            _ => Err(ParseRecipientKeyError::Invalid("invalid recipient key")),
        }
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

    pub(crate) fn wrap_file_key(&self, file_key: &[u8; 16]) -> RecipientLine {
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
                let encrypted_file_key = {
                    let mut key = [0; 32];
                    key.copy_from_slice(&aead_encrypt(&enc_key, file_key).unwrap());
                    key
                };

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
                let pk = x25519(tweak, ed25519_pk.to_montgomery().to_bytes());

                let mut esk = [0; 32];
                getrandom(&mut esk).expect("Should not fail");
                let epk = x25519(esk, X25519_BASEPOINT_BYTES);
                let shared_secret = x25519(esk, pk);

                let mut salt = vec![];
                salt.extend_from_slice(&epk);
                salt.extend_from_slice(&pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                let encrypted_file_key = {
                    let mut key = [0; 32];
                    key.copy_from_slice(&aead_encrypt(&enc_key, file_key).unwrap());
                    key
                };

                RecipientLine::ssh_ed25519(ssh_tag(&ssh_key), epk, encrypted_file_key)
            }
        }
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_until},
        character::streaming::newline,
        combinator::map,
        sequence::preceded,
        IResult,
    };

    use super::*;
    use crate::{openssh::ssh_secret_keys, util::read_encoded_str};

    fn age_secret_key(input: &str) -> IResult<&str, SecretKey> {
        preceded(
            tag(SECRET_KEY_PREFIX),
            map(read_encoded_str(32, base64::URL_SAFE_NO_PAD), |buf| {
                let mut pk = [0; 32];
                pk.copy_from_slice(&buf);
                SecretKey::X25519(pk)
            }),
        )(input)
    }

    fn age_secret_keys(mut input: &str) -> IResult<&str, Vec<SecretKey>> {
        let mut keys = vec![];
        while !input.is_empty() {
            // Skip comments
            let i = if input.starts_with('#') {
                take_until("\n")(input)?.0
            } else {
                input
            };

            // Skip empty lines
            let i = if i.starts_with('\n') {
                i
            } else {
                let (i, sk) = age_secret_key(i)?;
                keys.push(sk);
                i
            };

            input = if i.is_empty() { i } else { newline(i)?.0 };
        }

        Ok((input, keys))
    }

    pub(super) fn secret_keys(input: &str) -> IResult<&str, Vec<SecretKey>> {
        alt((ssh_secret_keys, age_secret_keys))(input)
    }

    pub(super) fn age_recipient_key(input: &str) -> IResult<&str, RecipientKey> {
        preceded(
            tag(PUBLIC_KEY_PREFIX),
            map(read_encoded_str(32, base64::URL_SAFE_NO_PAD), |buf| {
                let mut pk = [0; 32];
                pk.copy_from_slice(&buf);
                RecipientKey::X25519(pk)
            }),
        )(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::BufReader;

    use super::{RecipientKey, SecretKey};

    const TEST_SK: &str = "AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg";
    const TEST_PK: &str = "pubkey:X4ZiZYoURuOqC2_GPISYiWbJn1-j_HECyac7BpD6kHU";

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
    pub(crate) const TEST_SSH_RSA_PK: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE7nIXTGNuaRBN9toI/wNALuQec8mvlt0iJ7o3OaD2UvoKHJ7S8rmIn4FiQDUed/Vac3OhUibei1k+TBmm16u2Rj3klgWZOIDgi8d4vXKI5N3YBhxr3jsQ+kz1c+iZ4z/tTtz306+4K46XViVMWwyyg9j82Jn41mOAy9vdeDIfQ5fLeaGqn5KwlT61GNkZ+ozWK/ZNlQIlNCcoXxhJULIs9XrtczWyVBAea1nlDo0WHODePxoJjmsNHrpQXn5mf9O83xs10qfTUjnRUt48jRmedFy4tcra3QGmSTQ3KZne+wXXSb0cIpXLGvZjQSPHgG1hc4r3uBpiSzvesGLv79XL alice@rust";

    pub(crate) const TEST_SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";
    pub(crate) const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

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

    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(TEST_SSH_RSA_SK.as_bytes());
        let sk = SecretKey::from_data(buf).unwrap();
        let pk: RecipientKey = TEST_SSH_RSA_PK.parse().unwrap();

        let file_key = [12; 16];

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk[0].unwrap_file_key(&wrapped);
        assert_eq!(unwrapped, Some(file_key));
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(TEST_SSH_ED25519_SK.as_bytes());
        let sk = SecretKey::from_data(buf).unwrap();
        let pk: RecipientKey = TEST_SSH_ED25519_PK.parse().unwrap();

        let file_key = [12; 16];

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk[0].unwrap_file_key(&wrapped);
        assert_eq!(unwrapped, Some(file_key));
    }
}
