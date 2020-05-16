//! Encryption and decryption routines for age.

use age_core::primitives::hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, BufReader, Read, Write};
use std::iter;

use crate::{
    error::Error,
    format::{oil_the_joint, scrypt, Header, HeaderV1, RecipientStanza},
    keys::{FileKey, RecipientKey},
    primitives::{
        armor::{ArmoredReader, ArmoredWriter},
        stream::{Stream, StreamWriter},
    },
    Format,
};

pub mod decryptor;

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

fn v1_payload_key(
    header: &HeaderV1,
    file_key: FileKey,
    nonce: [u8; 16],
) -> Result<[u8; 32], Error> {
    // Verify the MAC
    header.verify_mac(hkdf(&[], HEADER_KEY_LABEL, file_key.0.expose_secret()))?;

    // Return the payload key
    Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
}

/// Callbacks that might be triggered during decryption.
pub trait Callbacks {
    /// Requests a passphrase to decrypt a key.
    fn request_passphrase(&self, description: &str) -> Option<SecretString>;
}

struct NoCallbacks;

impl Callbacks for NoCallbacks {
    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        None
    }
}

/// Handles the various types of age encryption.
enum EncryptorType {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<RecipientKey>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

impl EncryptorType {
    fn wrap_file_key(self, file_key: &FileKey) -> Vec<RecipientStanza> {
        match self {
            EncryptorType::Keys(recipients) => recipients
                .iter()
                .map(|key| key.wrap_file_key(file_key))
                // Keep the joint well oiled!
                .chain(iter::once(oil_the_joint()))
                .collect(),
            EncryptorType::Passphrase(passphrase) => {
                vec![scrypt::RecipientStanza::wrap_file_key(file_key, &passphrase).into()]
            }
        }
    }
}

/// Encryptor for creating an age file.
pub struct Encryptor(EncryptorType);

impl Encryptor {
    /// Returns an `Encryptor` that will create an age file encrypted to a list of
    /// recipients.
    pub fn with_recipients(recipients: Vec<RecipientKey>) -> Self {
        Encryptor(EncryptorType::Keys(recipients))
    }

    /// Returns an `Encryptor` that will create an age file encrypted with a passphrase.
    ///
    /// This API should only be used with a passphrase that was provided by (or generated
    /// for) a human. For programmatic use cases, instead generate a [`SecretKey`] and
    /// then use [`Encryptor::with_recipients`].
    ///
    /// [`SecretKey`]: crate::keys::SecretKey
    pub fn with_user_passphrase(passphrase: SecretString) -> Self {
        Encryptor(EncryptorType::Passphrase(passphrase))
    }

    /// Creates a wrapper around a writer that will encrypt its input, and optionally
    /// ASCII armor the output.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`StreamWriter::finish`] when you are done writing, in order to
    /// finish the encryption process. Failing to call [`StreamWriter::finish`] will
    /// result in a truncated file that will fail to decrypt.
    pub fn wrap_output<W: Write>(self, output: W, format: Format) -> io::Result<StreamWriter<W>> {
        let mut output = ArmoredWriter::wrap_output(output, format)?;

        let file_key = FileKey::generate();

        let header = Header::new(
            self.0.wrap_file_key(&file_key),
            hkdf(&[], HEADER_KEY_LABEL, file_key.0.expose_secret()),
        );
        header.write(&mut output)?;

        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        output.write_all(&nonce)?;

        let payload_key = hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret());
        Ok(Stream::encrypt(&payload_key, output))
    }
}

/// Decryptor for an age file.
pub enum Decryptor<R> {
    /// Decryption with a list of identities.
    Recipients(decryptor::RecipientsDecryptor<R>),
    /// Decryption with a passphrase.
    Passphrase(decryptor::PassphraseDecryptor<R>),
}

impl<R> From<decryptor::RecipientsDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::RecipientsDecryptor<R>) -> Self {
        Decryptor::Recipients(decryptor)
    }
}

impl<R> From<decryptor::PassphraseDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::PassphraseDecryptor<R>) -> Self {
        Decryptor::Passphrase(decryptor)
    }
}

impl<R: Read> Decryptor<BufReader<R>> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub fn new(input: R) -> Result<Self, Error> {
        let mut input = ArmoredReader::from_reader(input);
        let header = Header::read(&mut input)?;

        match &header {
            Header::V1(v1_header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                // Enforce structural requirements on the v1 header.
                let any_scrypt = v1_header.recipients.iter().any(|r| {
                    if let RecipientStanza::Scrypt(_) = r {
                        true
                    } else {
                        false
                    }
                });

                if any_scrypt && v1_header.recipients.len() == 1 {
                    Ok(decryptor::PassphraseDecryptor::new(input, header, nonce).into())
                } else if !any_scrypt {
                    Ok(decryptor::RecipientsDecryptor::new(input, header, nonce).into())
                } else {
                    Err(Error::InvalidHeader)
                }
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use std::io::{BufReader, Read, Write};

    use super::{Decryptor, Encryptor};
    use crate::keys::{Identity, RecipientKey};
    use crate::Format;

    #[test]
    fn x25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Recipients(d)) => d,
            _ => panic!(),
        };
        let mut r = d.decrypt(&sk).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_user_passphrase(SecretString::new("passphrase".to_string()));
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Passphrase(d)) => d,
            _ => panic!(),
        };
        let mut r = d
            .decrypt(&SecretString::new("passphrase".to_string()), None)
            .unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_RSA_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Recipients(d)) => d,
            _ => panic!(),
        };
        let mut r = d.decrypt(&sk).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_ED25519_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Recipients(d)) => d,
            _ => panic!(),
        };
        let mut r = d.decrypt(&sk).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }
}
