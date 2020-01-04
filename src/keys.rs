//! Key structs and serialization.

use bech32::{FromBase32, ToBase32};
use curve25519_dalek::edwards::EdwardsPoint;
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
    format::{ssh_ed25519, x25519, RecipientLine},
    openssh::EncryptedOpenSshKey,
};

#[cfg(feature = "unstable")]
use crate::format::ssh_rsa;

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";
const PUBLIC_KEY_PREFIX: &str = "age";

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
}

/// A secret key for decrypting an age message.
pub enum SecretKey {
    /// An X25519 secret key.
    X25519(StaticSecret),
    /// An ssh-rsa private key.
    #[cfg(feature = "unstable")]
    SshRsa(Vec<u8>, Box<rsa::RSAPrivateKey>),
    /// An ssh-ed25519 key pair.
    SshEd25519(Vec<u8>, Secret<[u8; 64]>),
}

impl SecretKey {
    /// Generates a new secret key.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        SecretKey::X25519(StaticSecret::new(&mut rng))
    }

    /// Serializes this secret key as a string.
    pub fn to_string(&self) -> SecretString {
        match self {
            SecretKey::X25519(sk) => {
                let mut sk_bytes = sk.to_bytes();
                let sk_base32 = sk_bytes.to_base32();
                let mut encoded =
                    bech32::encode(SECRET_KEY_PREFIX, sk_base32).expect("HRP is valid");
                let ret = SecretString::new(encoded.to_uppercase());

                // Clear intermediates
                sk_bytes.zeroize();
                // TODO: bech32::u5 doesn't implement Zeroize
                // sk_base32.zeroize();
                encoded.zeroize();

                ret
            }
            #[cfg(feature = "unstable")]
            SecretKey::SshRsa(_, _) => unimplemented!(),
            SecretKey::SshEd25519(_, _) => unimplemented!(),
        }
    }

    /// Returns the recipient key for this secret key.
    pub fn to_public(&self) -> RecipientKey {
        match self {
            SecretKey::X25519(sk) => RecipientKey::X25519(sk.into()),
            #[cfg(feature = "unstable")]
            SecretKey::SshRsa(_, _) => unimplemented!(),
            SecretKey::SshEd25519(_, _) => unimplemented!(),
        }
    }

    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the [`RecipientLine`] does not match this key.
    pub(crate) fn unwrap_file_key(&self, line: &RecipientLine) -> Option<Result<FileKey, Error>> {
        match (self, line) {
            (SecretKey::X25519(sk), RecipientLine::X25519(r)) => {
                // A failure to decrypt is non-fatal (we try to decrypt the recipient line
                // with other X25519 keys), because we cannot tell which key matches a
                // particular line.
                r.unwrap_file_key(sk).ok().map(Ok)
            }
            #[cfg(feature = "unstable")]
            (SecretKey::SshRsa(ssh_key, sk), RecipientLine::SshRsa(r)) => {
                r.unwrap_file_key(ssh_key, sk)
            }
            (SecretKey::SshEd25519(ssh_key, privkey), RecipientLine::SshEd25519(r)) => {
                r.unwrap_file_key(ssh_key, privkey.expose_secret())
            }
            _ => None,
        }
    }
}

/// An encrypted secret key.
pub enum EncryptedKey {
    /// An encrypted OpenSSH private key.
    OpenSsh(EncryptedOpenSshKey),
}

impl EncryptedKey {
    pub(crate) fn unwrap_file_key<P: Fn(&str) -> Option<SecretString>>(
        &self,
        line: &RecipientLine,
        request_passphrase: P,
        filename: Option<&str>,
    ) -> Option<Result<FileKey, Error>> {
        match self {
            EncryptedKey::OpenSsh(enc) => {
                let passphrase = request_passphrase(&format!(
                    "Type passphrase for OpenSSH key '{}'",
                    filename.unwrap_or_default()
                ))?;
                let decrypted = match enc.decrypt(passphrase) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                decrypted.unwrap_file_key(line)
            }
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
    /// An encrypted OpenSSH key using a specific cipher.
    EncryptedOpenSsh(String),
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
                    "You can migrate your key to the encrypted OpenSSH private key format (which",
                    "has been supported by OpenSSH since version 6.5, released in January 2014)",
                    "by changing its passphrase with the following command:",
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
            UnsupportedKey::EncryptedOpenSsh(cipher) => {
                let currently_unsupported = format!("currently-unsupported cipher ({}).", cipher);
                let new_issue = format!(
                    "https://github.com/str4d/rage/issues/new?title=Support%20OpenSSH%20key%20encryption%20cipher%20{}",
                    cipher,
                );
                let message = [
                    "Unsupported Cipher for Encrypted OpenSSH Key",
                    "--------------------------------------------",
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

/// An key that has been parsed from some input.
pub enum IdentityKey {
    /// An unencrypted key.
    Unencrypted(SecretKey),
    /// An encrypted key.
    Encrypted(EncryptedKey),
    /// An unsupported key.
    Unsupported(UnsupportedKey),
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
            key: IdentityKey::Unencrypted(key),
        }
    }
}

impl From<EncryptedKey> for Identity {
    fn from(key: EncryptedKey) -> Self {
        Identity {
            filename: None,
            key: IdentityKey::Encrypted(key),
        }
    }
}

impl From<UnsupportedKey> for Identity {
    fn from(key: UnsupportedKey) -> Self {
        Identity {
            filename: None,
            key: IdentityKey::Unsupported(key),
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
            match read::secret_keys(&buf) {
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

    /// Returns the filename this identity was parsed from, if known.
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_ref().map(|s| s.as_str())
    }

    /// Returns the key corresponding to this identity.
    pub fn key(&self) -> &IdentityKey {
        &self.key
    }

    pub(crate) fn unwrap_file_key<P: Fn(&str) -> Option<SecretString>>(
        &self,
        line: &RecipientLine,
        request_passphrase: P,
    ) -> Option<Result<FileKey, Error>> {
        match &self.key {
            IdentityKey::Unencrypted(key) => key.unwrap_file_key(line),
            IdentityKey::Encrypted(key) => {
                key.unwrap_file_key(line, request_passphrase, self.filename())
            }
            IdentityKey::Unsupported(_) => None,
        }
    }
}

/// A key that can be used to encrypt an age message to a recipient.
#[derive(Clone, Debug)]
pub enum RecipientKey {
    /// An X25519 recipient key.
    X25519(PublicKey),
    /// An ssh-rsa public key.
    #[cfg(feature = "unstable")]
    SshRsa(Vec<u8>, rsa::RSAPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, EdwardsPoint),
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
            RecipientKey::X25519(pk) => {
                bech32::encode(PUBLIC_KEY_PREFIX, pk.as_bytes().to_base32()).expect("HRP is valid")
            }
            #[cfg(feature = "unstable")]
            RecipientKey::SshRsa(_, _) => unimplemented!(),
            RecipientKey::SshEd25519(_, _) => unimplemented!(),
        }
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        match self {
            RecipientKey::X25519(pk) => x25519::RecipientLine::wrap_file_key(file_key, pk).into(),
            #[cfg(feature = "unstable")]
            RecipientKey::SshRsa(ssh_key, pk) => {
                ssh_rsa::RecipientLine::wrap_file_key(file_key, ssh_key, pk).into()
            }
            RecipientKey::SshEd25519(ssh_key, ed25519_pk) => {
                ssh_ed25519::RecipientLine::wrap_file_key(file_key, ssh_key, ed25519_pk).into()
            }
        }
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{take, take_until},
        character::streaming::newline,
        combinator::{map, map_opt, map_res},
        IResult,
    };

    use super::*;
    use crate::openssh::ssh_secret_keys;

    fn age_secret_key(input: &str) -> IResult<&str, Identity> {
        map_res(
            map_opt(take(74u32), |buf| parse_bech32(buf, SECRET_KEY_PREFIX)),
            |pk| {
                pk.map(StaticSecret::from)
                    .map(SecretKey::X25519)
                    .map(Identity::from)
            },
        )(input)
    }

    fn age_secret_keys(mut input: &str) -> IResult<&str, Vec<Identity>> {
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

    pub(super) fn secret_keys(input: &str) -> IResult<&str, Vec<Identity>> {
        // We try parsing the string as a single multi-line SSH key.
        // If that fails, we parse as multiple single-line age keys.
        //
        // TODO: Support "proper" PEM format, where the file is allowed to contain
        // anything before the "-----BEGIN" tag.
        alt((map(ssh_secret_keys, |key| vec![key]), age_secret_keys))(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::{ExposeSecret, Secret};
    use std::io::BufReader;

    use super::{FileKey, Identity, IdentityKey, RecipientKey};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    pub(crate) const TEST_PK: &str =
        "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";

    #[cfg(feature = "unstable")]
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
    #[cfg(feature = "unstable")]
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
        let keys = Identity::from_buffer(buf).unwrap();
        assert_eq!(keys.len(), 1);
        let key = match keys[0].key() {
            IdentityKey::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        assert_eq!(key.to_string().expose_secret(), TEST_SK);
    }

    #[test]
    fn incomplete_secret_key_encoding() {
        let buf = BufReader::new(&TEST_SK.as_bytes()[..4]);
        assert!(Identity::from_buffer(buf).is_err());
    }

    #[test]
    fn pubkey_encoding() {
        let pk: RecipientKey = TEST_PK.parse().unwrap();
        assert_eq!(pk.to_str(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        let buf = BufReader::new(TEST_SK.as_bytes());
        let keys = Identity::from_buffer(buf).unwrap();
        assert_eq!(keys.len(), 1);
        let key = match keys[0].key() {
            IdentityKey::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        assert_eq!(key.to_public().to_str(), TEST_PK);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(TEST_SSH_RSA_SK.as_bytes());
        let keys = Identity::from_buffer(buf).unwrap();
        let sk = match keys[0].key() {
            IdentityKey::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        let pk: RecipientKey = TEST_SSH_RSA_PK.parse().unwrap();

        let file_key = FileKey(Secret::new([12; 16]));

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk.unwrap_file_key(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().0.expose_secret(),
            file_key.0.expose_secret()
        );
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(TEST_SSH_ED25519_SK.as_bytes());
        let keys = Identity::from_buffer(buf).unwrap();
        let sk = match keys[0].key() {
            IdentityKey::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        let pk: RecipientKey = TEST_SSH_ED25519_PK.parse().unwrap();

        let file_key = FileKey(Secret::new([12; 16]));

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk.unwrap_file_key(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().0.expose_secret(),
            file_key.0.expose_secret()
        );
    }
}
