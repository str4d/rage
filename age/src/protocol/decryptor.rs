//! Decryptors for age.

use secrecy::SecretString;
use std::io::Read;

use super::{v1_payload_key, Callbacks, NoCallbacks};
use crate::{
    error::Error,
    format::{Header, RecipientStanza},
    keys::{FileKey, Identity},
    primitives::{
        armor::ArmoredReader,
        stream::{Stream, StreamReader},
    },
};

struct BaseDecryptor<R: Read> {
    /// The age file.
    input: ArmoredReader<R>,
    /// The age file's header.
    header: Header,
}

impl<R: Read> BaseDecryptor<R> {
    fn obtain_payload_key<F>(&mut self, filter: F) -> Result<[u8; 32], Error>
    where
        F: FnMut(&RecipientStanza) -> Option<Result<FileKey, Error>>,
    {
        match &self.header {
            Header::V1(header) => {
                let mut nonce = [0; 16];
                self.input.read_exact(&mut nonce)?;

                header
                    .recipients
                    .iter()
                    .find_map(filter)
                    .unwrap_or(Err(Error::NoMatchingKeys))
                    .and_then(|file_key| v1_payload_key(header, file_key, nonce))
            }
            Header::Unknown(_) => unreachable!(),
        }
    }
}

/// Decryptor for an age file encrypted to a list of recipients.
pub struct RecipientsDecryptor<R: Read>(BaseDecryptor<R>);

impl<R: Read> RecipientsDecryptor<R> {
    pub(super) fn new(input: ArmoredReader<R>, header: Header) -> Self {
        RecipientsDecryptor(BaseDecryptor { input, header })
    }

    /// Attempts to decrypt the age file.
    ///
    /// The decryptor will have no callbacks registered, so it will be unable to use
    /// identities that require e.g. a passphrase to decrypt.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt(self, identities: &[Identity]) -> Result<StreamReader<R>, Error> {
        self.decrypt_with_callbacks(identities, &NoCallbacks)
    }

    /// Attempts to decrypt the age file.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_with_callbacks(
        mut self,
        identities: &[Identity],
        callbacks: &dyn Callbacks,
    ) -> Result<StreamReader<R>, Error> {
        self.0
            .obtain_payload_key(|r| {
                identities
                    .iter()
                    .find_map(|key| key.unwrap_file_key(r, callbacks))
            })
            .map(|payload_key| Stream::decrypt(&payload_key, self.0.input))
    }
}

/// Decryptor for an age file encrypted with a passphrase.
pub struct PassphraseDecryptor<R: Read>(BaseDecryptor<R>);

impl<R: Read> PassphraseDecryptor<R> {
    pub(super) fn new(input: ArmoredReader<R>, header: Header) -> Self {
        PassphraseDecryptor(BaseDecryptor { input, header })
    }

    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt(
        mut self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<StreamReader<R>, Error> {
        self.0
            .obtain_payload_key(|r| {
                if let RecipientStanza::Scrypt(s) = r {
                    s.unwrap_file_key(passphrase, max_work_factor).transpose()
                } else {
                    None
                }
            })
            .map(|payload_key| Stream::decrypt(&payload_key, self.0.input))
    }
}
