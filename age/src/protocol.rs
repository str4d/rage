//! Encryption and decryption routines for age.

use age_core::{format::is_arbitrary_string, secrecy::SecretString};
use rand::{rngs::OsRng, RngCore};

use std::io::{self, BufRead, Read, Write};
use std::iter;

use crate::{
    error::{DecryptError, EncryptError},
    format::{Header, HeaderV1},
    keys::{mac_key, new_file_key, v1_payload_key},
    primitives::stream::{PayloadKey, Stream, StreamReader, StreamWriter},
    scrypt, Identity, Recipient,
};

#[cfg(feature = "async")]
use futures::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    async fn read_async<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce).await?;
        Ok(Nonce(nonce))
    }
}

/// Encryptor for creating an age file.
pub struct Encryptor {
    header: Header,
    nonce: Nonce,
    payload_key: PayloadKey,
}

impl Encryptor {
    /// Returns an `Encryptor` that will create an age file encrypted with a passphrase.
    /// Anyone with the passphrase can decrypt the file.
    ///
    /// This API should only be used with a passphrase that was provided by (or generated
    /// for) a human. For programmatic use cases, instead generate an [`x25519::Identity`]
    /// and then use [`Encryptor::with_recipients`].
    ///
    /// [`x25519::Identity`]: crate::x25519::Identity
    pub fn with_user_passphrase(passphrase: SecretString) -> Self {
        Self::with_recipients(iter::once(&scrypt::Recipient::new(passphrase) as _))
            .expect("no errors can occur with this recipient set")
    }

    /// Constructs an `Encryptor` that will create an age file encrypted to a list of
    /// recipients.
    pub fn with_recipients<'a>(
        recipients: impl Iterator<Item = &'a dyn Recipient>,
    ) -> Result<Self, EncryptError> {
        let file_key = new_file_key();

        let recipients = {
            let mut control = None;

            let mut stanzas = vec![];
            let mut have_recipients = false;
            for recipient in recipients {
                have_recipients = true;
                let (mut r_stanzas, r_labels) = recipient.wrap_file_key(&file_key)?;

                if let Some(l_labels) = control.take() {
                    if l_labels != r_labels {
                        // Improve error message.
                        let err = if stanzas
                            .iter()
                            .chain(&r_stanzas)
                            .any(|stanza| stanza.tag == crate::scrypt::SCRYPT_RECIPIENT_TAG)
                        {
                            EncryptError::MixedRecipientAndPassphrase
                        } else {
                            EncryptError::IncompatibleRecipients { l_labels, r_labels }
                        };
                        return Err(err);
                    }
                    control = Some(l_labels);
                } else if r_labels.iter().all(is_arbitrary_string) {
                    control = Some(r_labels);
                } else {
                    return Err(EncryptError::InvalidRecipientLabels(r_labels));
                }

                stanzas.append(&mut r_stanzas);
            }
            if !have_recipients {
                return Err(EncryptError::MissingRecipients);
            }
            stanzas
        };

        let header = HeaderV1::new(recipients, mac_key(&file_key))?;
        let nonce = Nonce::random();
        let payload_key = v1_payload_key(&file_key, &header, &nonce).expect("MAC is correct");

        Ok(Self {
            header: Header::V1(header),
            nonce,
            payload_key,
        })
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`StreamWriter::finish`] when you are done writing, in order to
    /// finish the encryption process. Failing to call [`StreamWriter::finish`] will
    /// result in a truncated file that will fail to decrypt.
    pub fn wrap_output<W: Write>(self, mut output: W) -> io::Result<StreamWriter<W>> {
        let Self {
            header,
            nonce,
            payload_key,
        } = self;
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
    ) -> io::Result<StreamWriter<W>> {
        let Self {
            header,
            nonce,
            payload_key,
        } = self;
        header.write_async(&mut output).await?;
        output.write_all(nonce.as_ref()).await?;
        Ok(Stream::encrypt_async(payload_key, output))
    }
}

/// Decryptor for an age file.
pub struct Decryptor<R> {
    /// The age file.
    input: R,
    /// The age file's header.
    header: Header,
    /// The age file's AEAD nonce
    nonce: Nonce,
}

impl<R> Decryptor<R> {
    fn from_v1_header(input: R, header: HeaderV1, nonce: Nonce) -> Result<Self, DecryptError> {
        // Enforce structural requirements on the v1 header.
        if header.is_valid() {
            Ok(Self {
                input,
                header: Header::V1(header),
                nonce,
            })
        } else {
            Err(DecryptError::InvalidHeader)
        }
    }

    /// Returns `true` if the age file is encrypted to a passphrase.
    pub fn is_scrypt(&self) -> bool {
        match &self.header {
            Header::V1(header) => header.valid_scrypt(),
            Header::Unknown(_) => false,
        }
    }

    fn obtain_payload_key<'a>(
        &self,
        mut identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<PayloadKey, DecryptError> {
        match &self.header {
            Header::V1(header) => identities
                .find_map(|key| key.unwrap_stanzas(&header.recipients))
                .unwrap_or(Err(DecryptError::NoMatchingKeys))
                .and_then(|file_key| v1_payload_key(&file_key, header, &self.nonce)),
            Header::Unknown(_) => unreachable!(),
        }
    }
}

impl<R: Read> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor will work with any type implementing [`io::Read`], and uses a
    /// slower parser and internal buffering to ensure no overreading occurs. Consider
    /// using [`Decryptor::new_buffered`] for types implementing `std::io::BufRead`, which
    /// includes `&[u8]` slices.
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

    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt<'a>(
        self,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(identities)
            .map(|payload_key| Stream::decrypt(payload_key, self.input))
    }
}

impl<R: BufRead> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor is more performant than [`Decryptor::new`] for types implementing
    /// [`io::BufRead`], which includes `&[u8]` slices.
    pub fn new_buffered(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read_buffered(&mut input)?;

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
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + Unpin> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor will work with any type implementing [`AsyncRead`], and uses a
    /// slower parser and internal buffering to ensure no overreading occurs. Consider
    /// using [`Decryptor::new_async_buffered`] for types implementing [`AsyncBufRead`],
    /// which includes `&[u8]` slices.
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

    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async<'a>(
        self,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(identities)
            .map(|payload_key| Stream::decrypt_async(payload_key, self.input))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncBufRead + Unpin> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor is more performant than [`Decryptor::new_async`] for types
    /// implementing [`AsyncBufRead`], which includes `&[u8]` slices.
    pub async fn new_async_buffered(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read_async_buffered(&mut input).await?;

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
    use std::collections::HashSet;
    use std::io::{BufReader, Read, Write};

    use age_core::secrecy::SecretString;

    #[cfg(feature = "ssh")]
    use std::iter;

    use super::{Decryptor, Encryptor};
    use crate::{identity::IdentityFile, scrypt, x25519, EncryptError, Identity, Recipient};

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
        recipients: impl Iterator<Item = &'a dyn Recipient>,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients).unwrap();
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::new(&encrypted[..]).unwrap();
        let mut r = d.decrypt(identities).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "async")]
    fn recipient_async_round_trip<'a>(
        recipients: impl Iterator<Item = &'a dyn Recipient>,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) {
        let test_msg = b"This is a test message. For testing.";
        let mut cx = noop_context();

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients).unwrap();
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
                match w.as_mut().poll_write(&mut cx, tmp) {
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

        let d = {
            let f = Decryptor::new_async(&encrypted[..]);
            pin_mut!(f);

            loop {
                match f.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(w)) => break w,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
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
            iter::once(&pk as _),
            f.into_identities().unwrap().iter().map(|i| i.as_ref()),
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn x25519_async_round_trip() {
        let buf = BufReader::new(crate::x25519::tests::TEST_SK.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        recipient_async_round_trip(
            iter::once(&pk as _),
            f.into_identities().unwrap().iter().map(|i| i.as_ref()),
        );
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut recipient = scrypt::Recipient::new(SecretString::from("passphrase".to_string()));
        // Override to something very fast for testing.
        recipient.set_work_factor(2);

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(iter::once(&recipient as _)).unwrap();
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::new(&encrypted[..]).unwrap();
        let mut r = d
            .decrypt(
                Some(&scrypt::Identity::new(SecretString::from("passphrase".to_string())) as _)
                    .into_iter(),
            )
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
        recipient_round_trip(iter::once(&pk as _), iter::once(&sk as &dyn Identity));
    }

    #[cfg(all(feature = "ssh", feature = "async"))]
    #[test]
    fn ssh_rsa_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_RSA_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(iter::once(&pk as _), iter::once(&sk as &dyn Identity));
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_round_trip(iter::once(&pk as _), iter::once(&sk as &dyn Identity));
    }

    #[cfg(all(feature = "ssh", feature = "async"))]
    #[test]
    fn ssh_ed25519_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: crate::ssh::Recipient = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(iter::once(&pk as _), iter::once(&sk as &dyn Identity));
    }

    #[test]
    fn mixed_recipient_and_passphrase() {
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        let passphrase =
            crate::scrypt::Recipient::new(SecretString::from("passphrase".to_string()));

        let recipients = [&pk as &dyn Recipient, &passphrase as _];

        assert!(matches!(
            Encryptor::with_recipients(recipients.into_iter()),
            Err(EncryptError::MixedRecipientAndPassphrase),
        ));
    }

    struct IncompatibleRecipient(crate::x25519::Recipient);

    impl Recipient for IncompatibleRecipient {
        fn wrap_file_key(
            &self,
            file_key: &age_core::format::FileKey,
        ) -> Result<(Vec<age_core::format::Stanza>, HashSet<String>), EncryptError> {
            self.0.wrap_file_key(file_key).map(|(stanzas, mut labels)| {
                labels.insert("incompatible".into());
                (stanzas, labels)
            })
        }
    }

    #[test]
    fn incompatible_recipients() {
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        let incompatible = IncompatibleRecipient(pk.clone());

        let recipients = [&pk as &dyn Recipient, &incompatible as _];

        assert!(matches!(
            Encryptor::with_recipients(recipients.into_iter()),
            Err(EncryptError::IncompatibleRecipients { .. }),
        ));
    }
}
