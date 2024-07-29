//! Decryptors for age.

use age_core::format::{FileKey, Stanza};
use std::io::Read;

use super::Nonce;
use crate::{
    error::DecryptError,
    format::Header,
    keys::v1_payload_key,
    primitives::stream::{PayloadKey, Stream, StreamReader},
    Identity,
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

    /// Returns `true` if the age file is encrypted to a passphrase.
    pub fn is_scrypt(&self) -> bool {
        match &self.0.header {
            Header::V1(header) => header.valid_scrypt(),
            Header::Unknown(_) => false,
        }
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
