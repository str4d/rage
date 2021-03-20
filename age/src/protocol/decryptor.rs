//! Decryptors for age.

use age_core::format::{FileKey, Stanza};
use secrecy::SecretString;
use std::io::Read;

use super::Nonce;
use crate::{
    error::DecryptError,
    format::Header,
    keys::v1_payload_key,
    primitives::stream::{PayloadKey, Stream, StreamReader},
    scrypt, Identity,
};

#[cfg(feature = "async")]
use futures::io::AsyncRead;

struct BaseDecryptor<R> {
    /// The age file.
    input: R,
    /// The age file's header.
    header: Header,
    /// The age file's AEAD nonce
    nonce: Nonce,
}

impl<R> BaseDecryptor<R> {
    fn obtain_payload_key<F>(&self, mut filter: F) -> Result<PayloadKey, DecryptError>
    where
        F: FnMut(&[Stanza]) -> Option<Result<FileKey, DecryptError>>,
    {
        match &self.header {
            Header::V1(header) => filter(&header.recipients)
                .unwrap_or(Err(DecryptError::NoMatchingKeys))
                .and_then(|file_key| v1_payload_key(&file_key, header, &self.nonce)),
            Header::Unknown(_) => unreachable!(),
        }
    }
}

/// Decryptor for an age file encrypted to a list of recipients.
pub struct RecipientsDecryptor<R>(BaseDecryptor<R>);

impl<R> RecipientsDecryptor<R> {
    pub(super) fn new(input: R, header: Header, nonce: Nonce) -> Self {
        RecipientsDecryptor(BaseDecryptor {
            input,
            header,
            nonce,
        })
    }

    fn obtain_payload_key<'a>(
        &self,
        mut identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<PayloadKey, DecryptError> {
        self.0
            .obtain_payload_key(|r| identities.find_map(|key| key.unwrap_stanzas(r)))
    }
}

impl<R: Read> RecipientsDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt<'a>(
        self,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(identities)
            .map(|payload_key| Stream::decrypt(payload_key, self.0.input))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + Unpin> RecipientsDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async<'a>(
        self,
        identities: impl Iterator<Item = &'a dyn Identity>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(identities)
            .map(|payload_key| Stream::decrypt_async(payload_key, self.0.input))
    }
}

/// Decryptor for an age file encrypted with a passphrase.
pub struct PassphraseDecryptor<R>(BaseDecryptor<R>);

impl<R> PassphraseDecryptor<R> {
    pub(super) fn new(input: R, header: Header, nonce: Nonce) -> Self {
        PassphraseDecryptor(BaseDecryptor {
            input,
            header,
            nonce,
        })
    }

    fn obtain_payload_key(
        &self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<PayloadKey, DecryptError> {
        let identity = scrypt::Identity {
            passphrase,
            max_work_factor,
        };

        self.0.obtain_payload_key(|r| identity.unwrap_stanzas(r))
    }
}

impl<R: Read> PassphraseDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt(
        self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(passphrase, max_work_factor)
            .map(|payload_key| Stream::decrypt(payload_key, self.0.input))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + Unpin> PassphraseDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async(
        self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<StreamReader<R>, DecryptError> {
        self.obtain_payload_key(passphrase, max_work_factor)
            .map(|payload_key| Stream::decrypt_async(payload_key, self.0.input))
    }
}
