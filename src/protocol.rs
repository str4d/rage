//! Encryption and decryption routines for age.

use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, Read, Seek, Write};

use crate::{
    error::Error,
    format::{scrypt, Header, RecipientLine},
    keys::{FileKey, Identity, RecipientKey},
    primitives::{
        armor::{ArmoredReader, ArmoredWriter},
        hkdf,
        stream::{Stream, StreamReader, StreamWriter},
    },
    Format,
};

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

/// Handles the various types of age encryption.
pub enum Encryptor {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<RecipientKey>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

impl Encryptor {
    fn wrap_file_key(&self, file_key: &FileKey) -> Vec<RecipientLine> {
        match self {
            Encryptor::Keys(recipients) => recipients
                .iter()
                .map(|key| key.wrap_file_key(file_key))
                .collect(),
            Encryptor::Passphrase(passphrase) => {
                vec![scrypt::RecipientLine::wrap_file_key(file_key, passphrase).into()]
            }
        }
    }

    /// Creates a wrapper around a writer that will encrypt its input, and optionally
    /// ASCII armor the output.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call `finish()` when you are done writing, in order to finish the
    /// encryption process. Failing to call `finish()` will result in a truncated message
    /// that will fail to decrypt.
    pub fn wrap_output<W: Write>(&self, output: W, format: Format) -> io::Result<StreamWriter<W>> {
        let mut output = ArmoredWriter::wrap_output(output, format)?;

        let file_key = FileKey::generate();

        let header = Header::new(
            self.wrap_file_key(&file_key),
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

/// Handles the various types of age decryption.
pub enum Decryptor {
    /// Trial decryption against a list of secret keys.
    Keys(Vec<Identity>),
    /// Decryption with a passphrase.
    Passphrase {
        /// The passphrase to decrypt with.
        passphrase: SecretString,
        /// The maximum accepted work factor. If `None`, the default maximum is adjusted
        /// to around 16 seconds of work.
        max_work_factor: Option<u8>,
    },
}

impl Decryptor {
    /// Creates a decryptor with a passphrase and the default max work factor.
    pub fn with_passphrase(passphrase: SecretString) -> Self {
        Decryptor::Passphrase {
            passphrase,
            max_work_factor: None,
        }
    }

    fn unwrap_file_key<P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        line: &RecipientLine,
        request_passphrase: P,
    ) -> Result<Option<FileKey>, Error> {
        match (self, line) {
            (Decryptor::Keys(_), RecipientLine::Scrypt(_)) => Err(Error::MessageRequiresPassphrase),
            (Decryptor::Keys(keys), _) => keys
                .iter()
                .find_map(|key| key.unwrap_file_key(line, request_passphrase))
                .transpose(),
            (
                Decryptor::Passphrase {
                    passphrase,
                    max_work_factor,
                },
                RecipientLine::Scrypt(s),
            ) => s.unwrap_file_key(passphrase, *max_work_factor),
            (Decryptor::Passphrase { .. }, _) => Err(Error::MessageRequiresKeys),
        }
    }

    /// Attempts to decrypt a message from the given reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn trial_decrypt<R: Read, P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        input: R,
        request_passphrase: P,
    ) -> Result<impl Read, Error> {
        let mut input = ArmoredReader::from_reader(input);

        match Header::read(&mut input)? {
            Header::V1(header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                header
                    .recipients
                    .iter()
                    .find_map(|r| {
                        self.unwrap_file_key(r, request_passphrase)
                            .transpose()
                            .map(|res| {
                                res.and_then(|file_key| {
                                    // Verify the MAC
                                    header.verify_mac(hkdf(
                                        &[],
                                        HEADER_KEY_LABEL,
                                        file_key.0.expose_secret(),
                                    ))?;

                                    // Return the payload key
                                    Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
                                })
                            })
                    })
                    .unwrap_or(Err(Error::NoMatchingKeys))
                    .map(|payload_key| Stream::decrypt(&payload_key, input))
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }

    /// Attempts to decrypt a message from the given seekable reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a seekable reader that will provide the plaintext.
    pub fn trial_decrypt_seekable<R: Read + Seek, P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        mut input: R,
        request_passphrase: P,
    ) -> Result<StreamReader<R>, Error> {
        match Header::read(&mut input)? {
            Header::V1(header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                header
                    .recipients
                    .iter()
                    .find_map(|r| {
                        self.unwrap_file_key(r, request_passphrase)
                            .transpose()
                            .map(|res| {
                                res.and_then(|file_key| {
                                    // Verify the MAC
                                    header.verify_mac(hkdf(
                                        &[],
                                        HEADER_KEY_LABEL,
                                        file_key.0.expose_secret(),
                                    ))?;

                                    // Return the payload key
                                    Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
                                })
                            })
                    })
                    .unwrap_or(Err(Error::NoMatchingKeys))
                    .and_then(|payload_key| {
                        Stream::decrypt_seekable(&payload_key, input).map_err(Error::from)
                    })
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
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::Keys(sk);
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Passphrase(SecretString::new("passphrase".to_string()));
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::with_passphrase(SecretString::new("passphrase".to_string()));
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
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
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::Keys(sk);
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
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
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::Keys(sk);
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }
}
