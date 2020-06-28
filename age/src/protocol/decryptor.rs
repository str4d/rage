//! Decryptors for age.

use secrecy::SecretString;
use std::io::Read;

use super::{Callbacks, NoCallbacks, Nonce};
use crate::{
    error::Error,
    format::{Header, RecipientStanza},
    keys::{FileKey, Identity},
    primitives::stream::{PayloadKey, Stream, StreamReader},
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
    fn obtain_payload_key<F>(&self, filter: F) -> Result<PayloadKey, Error>
    where
        F: FnMut(&RecipientStanza) -> Option<Result<FileKey, Error>>,
    {
        match &self.header {
            Header::V1(header) => header
                .recipients
                .iter()
                .find_map(filter)
                .unwrap_or(Err(Error::NoMatchingKeys))
                .and_then(|file_key| file_key.v1_payload_key(header, &self.nonce)),
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

    fn obtain_payload_key(
        &self,
        mut identities: impl Iterator<Item = Identity>,
        callbacks: &dyn Callbacks,
    ) -> Result<PayloadKey, Error> {
        self.0
            .obtain_payload_key(|r| identities.find_map(|key| key.unwrap_file_key(r, callbacks)))
    }
}

impl<R: Read> RecipientsDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// The decryptor will have no callbacks registered, so it will be unable to use
    /// identities that require e.g. a passphrase to decrypt.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt(
        self,
        identities: impl Iterator<Item = Identity>,
    ) -> Result<StreamReader<R>, Error> {
        self.decrypt_with_callbacks(identities, &NoCallbacks)
    }

    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_with_callbacks(
        self,
        identities: impl Iterator<Item = Identity>,
        callbacks: &dyn Callbacks,
    ) -> Result<StreamReader<R>, Error> {
        self.obtain_payload_key(identities, callbacks)
            .map(|payload_key| Stream::decrypt(payload_key, self.0.input))
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> RecipientsDecryptor<R> {
    /// Attempts to decrypt the age file.
    ///
    /// The decryptor will have no callbacks registered, so it will be unable to use
    /// identities that require e.g. a passphrase to decrypt.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async(
        self,
        identities: impl Iterator<Item = Identity>,
    ) -> Result<StreamReader<R>, Error> {
        self.decrypt_async_with_callbacks(identities, &NoCallbacks)
    }

    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async_with_callbacks(
        self,
        identities: impl Iterator<Item = Identity>,
        callbacks: &dyn Callbacks,
    ) -> Result<StreamReader<R>, Error> {
        self.obtain_payload_key(identities, callbacks)
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
    ) -> Result<PayloadKey, Error> {
        self.0.obtain_payload_key(|r| {
            if let RecipientStanza::Scrypt(s) = r {
                s.unwrap_file_key(passphrase, max_work_factor).transpose()
            } else {
                None
            }
        })
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
    ) -> Result<StreamReader<R>, Error> {
        self.obtain_payload_key(passphrase, max_work_factor)
            .map(|payload_key| Stream::decrypt(payload_key, self.0.input))
    }
}

#[cfg(feature = "async")]
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
    ) -> Result<StreamReader<R>, Error> {
        self.obtain_payload_key(passphrase, max_work_factor)
            .map(|payload_key| Stream::decrypt_async(payload_key, self.0.input))
    }
}
