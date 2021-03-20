//! Encryption and decryption routines for age.

use age_core::format::grease_the_joint;
use rand::{rngs::OsRng, RngCore};
use secrecy::SecretString;
use std::io::{self, Read, Write};

use crate::{
    error::{DecryptError, EncryptError},
    format::{Header, HeaderV1},
    keys::{mac_key, new_file_key, v1_payload_key},
    primitives::stream::{PayloadKey, Stream, StreamWriter},
    scrypt, Recipient,
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod decryptor;

pub(crate) struct Nonce([u8; 16]);

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Nonce {
    fn random() -> Self {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        Nonce(nonce)
    }

    fn read<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce)?;
        Ok(Nonce(nonce))
    }

    #[cfg(feature = "async")]
    async fn read_async<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce).await?;
        Ok(Nonce(nonce))
    }
}

/// Handles the various types of age encryption.
enum EncryptorType {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<Box<dyn Recipient>>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

/// Encryptor for creating an age file.
pub struct Encryptor(EncryptorType);

impl Encryptor {
    /// Returns an `Encryptor` that will create an age file encrypted to a list of
    /// recipients.
    pub fn with_recipients(recipients: Vec<Box<dyn Recipient>>) -> Self {
        Encryptor(EncryptorType::Keys(recipients))
    }

    /// Returns an `Encryptor` that will create an age file encrypted with a passphrase.
    /// Anyone with the passphrase can decrypt the file.
    ///
    /// This API should only be used with a passphrase that was provided by (or generated
    /// for) a human. For programmatic use cases, instead generate an [`x25519::Identity`]
    /// and then use [`Encryptor::with_recipients`].
    ///
    /// [`x25519::Identity`]: crate::x25519::Identity
    pub fn with_user_passphrase(passphrase: SecretString) -> Self {
        Encryptor(EncryptorType::Passphrase(passphrase))
    }

    /// Creates the header for this age file.
    fn prepare_header(self) -> Result<(Header, Nonce, PayloadKey), EncryptError> {
        let file_key = new_file_key();

        let recipients = match self.0 {
            EncryptorType::Keys(recipients) => {
                let mut stanzas = Vec::with_capacity(recipients.len() + 1);
                for recipient in recipients {
                    stanzas.append(&mut recipient.wrap_file_key(&file_key)?);
                }
                // Keep the joint well oiled!
                stanzas.push(grease_the_joint());
                stanzas
            }
            EncryptorType::Passphrase(passphrase) => {
                scrypt::Recipient { passphrase }.wrap_file_key(&file_key)?
            }
        };

        let header = HeaderV1::new(recipients, mac_key(&file_key));
        let nonce = Nonce::random();
        let payload_key = v1_payload_key(&file_key, &header, &nonce).expect("MAC is correct");

        Ok((Header::V1(header), nonce, payload_key))
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`StreamWriter::finish`] when you are done writing, in order to
    /// finish the encryption process. Failing to call [`StreamWriter::finish`] will
    /// result in a truncated file that will fail to decrypt.
    pub fn wrap_output<W: Write>(self, mut output: W) -> Result<StreamWriter<W>, EncryptError> {
        let (header, nonce, payload_key) = self.prepare_header()?;
        header.write(&mut output)?;
        output.write_all(nonce.as_ref())?;
        Ok(Stream::encrypt(payload_key, output))
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`AsyncWrite::poll_close`] when you are done writing, in order
    /// to finish the encryption process. Failing to call [`AsyncWrite::poll_close`]
    /// will result in a truncated file that will fail to decrypt.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn wrap_async_output<W: AsyncWrite + Unpin>(
        self,
        mut output: W,
    ) -> Result<StreamWriter<W>, EncryptError> {
        let (header, nonce, payload_key) = self.prepare_header()?;
        header.write_async(&mut output).await?;
        output.write_all(nonce.as_ref()).await?;
        Ok(Stream::encrypt_async(payload_key, output))
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

impl<R> Decryptor<R> {
    fn from_v1_header(input: R, header: HeaderV1, nonce: Nonce) -> Result<Self, DecryptError> {
        // Enforce structural requirements on the v1 header.
        let any_scrypt = header
            .recipients
            .iter()
            .any(|r| r.tag == scrypt::SCRYPT_RECIPIENT_TAG);

        if any_scrypt && header.recipients.len() == 1 {
            Ok(decryptor::PassphraseDecryptor::new(input, Header::V1(header), nonce).into())
        } else if !any_scrypt {
            Ok(decryptor::RecipientsDecryptor::new(input, Header::V1(header), nonce).into())
        } else {
            Err(DecryptError::InvalidHeader)
        }
    }
}

impl<R: Read> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub fn new(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read(&mut input)?;

        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read(&mut input)?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(DecryptError::UnknownFormat),
        }
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub async fn new_async(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read_async(&mut input).await?;

        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read_async(&mut input).await?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(DecryptError::UnknownFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use std::io::{BufReader, Read, Write};
    use std::iter;

    use super::{Decryptor, Encryptor};
    use crate::{identity::IdentityFile, x25519, Identity, Recipient};

    #[cfg(feature = "async")]
    use futures::{
        io::{AsyncRead, AsyncWrite},
        pin_mut,
        task::Poll,
        Future,
    };
    #[cfg(feature = "async")]
    use futures_test::task::noop_context;

    fn recipient_round_trip<'a>(
        recipients: Vec<Box<dyn Recipient>>,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients);
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Recipients(d)) => d,
            _ => panic!(),
        };
        let mut r = d.decrypt(identities).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "async")]
    fn recipient_async_round_trip<'a>(
        recipients: Vec<Box<dyn Recipient>>,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) {
        let test_msg = b"This is a test message. For testing.";
        let mut cx = noop_context();

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients);
        {
            let w = {
                let f = e.wrap_async_output(&mut encrypted);
                pin_mut!(f);

                loop {
                    match f.as_mut().poll(&mut cx) {
                        Poll::Ready(Ok(w)) => break w,
                        Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                        Poll::Pending => panic!("Unexpected Pending"),
                    }
                }
            };
            pin_mut!(w);

            let mut tmp = &test_msg[..];
            loop {
                match w.as_mut().poll_write(&mut cx, &tmp) {
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(written)) => tmp = &tmp[written..],
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
            loop {
                match w.as_mut().poll_close(&mut cx) {
                    Poll::Ready(Ok(())) => break,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        }

        let d = match {
            let f = Decryptor::new_async(&encrypted[..]);
            pin_mut!(f);

            loop {
                match f.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(w)) => break w,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        } {
            Decryptor::Recipients(d) => d,
            _ => panic!(),
        };

        let decrypted = {
            let mut buf = vec![];
            let r = d.decrypt_async(identities).unwrap();
            pin_mut!(r);

            let mut tmp = [0; 4096];
            loop {
                match r.as_mut().poll_read(&mut cx, &mut tmp) {
                    Poll::Ready(Ok(0)) => break buf,
                    Poll::Ready(Ok(read)) => buf.extend_from_slice(&tmp[..read]),
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        };

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn x25519_round_trip() {
        let buf = BufReader::new(crate::x25519::tests::TEST_SK.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        recipient_round_trip(
            vec![Box::new(pk)],
            f.into_identities().iter().map(|sk| sk as &dyn Identity),
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn x25519_async_round_trip() {
        let buf = BufReader::new(crate::x25519::tests::TEST_SK.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        recipient_async_round_trip(
            vec![Box::new(pk)],
            f.into_identities().iter().map(|sk| sk as &dyn Identity),
        );
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_user_passphrase(SecretString::new("passphrase".to_string()));
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
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

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_RSA_PK
            .parse()
            .unwrap();
        recipient_round_trip(vec![Box::new(pk)], iter::once(&sk as &dyn Identity));
    }

    #[cfg(all(feature = "ssh", feature = "async"))]
    #[test]
    fn ssh_rsa_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_RSA_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(vec![Box::new(pk)], iter::once(&sk as &dyn Identity));
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_round_trip(vec![Box::new(pk)], iter::once(&sk as &dyn Identity));
    }

    #[cfg(all(feature = "ssh", feature = "async"))]
    #[test]
    fn ssh_ed25519_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(vec![Box::new(pk)], iter::once(&sk as &dyn Identity));
    }
}
