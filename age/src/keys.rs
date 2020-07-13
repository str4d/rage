//! Key structs and serialization.

use age_core::primitives::hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};

use crate::{
    error::Error,
    format::HeaderV1,
    primitives::{stream::PayloadKey, HmacKey},
    protocol::Nonce,
};

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

/// A file key for encrypting or decrypting an age file.
pub struct FileKey(Secret<[u8; 16]>);

impl From<[u8; 16]> for FileKey {
    fn from(file_key: [u8; 16]) -> Self {
        FileKey(Secret::new(file_key))
    }
}

impl ExposeSecret<[u8; 16]> for FileKey {
    fn expose_secret(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

impl FileKey {
    pub(crate) fn generate() -> Self {
        let mut file_key = [0; 16];
        OsRng.fill_bytes(&mut file_key);
        file_key.into()
    }

    pub(crate) fn mac_key(&self) -> HmacKey {
        HmacKey(Secret::new(hkdf(
            &[],
            HEADER_KEY_LABEL,
            self.0.expose_secret(),
        )))
    }

    pub(crate) fn v1_payload_key(
        &self,
        header: &HeaderV1,
        nonce: &Nonce,
    ) -> Result<PayloadKey, Error> {
        // Verify the MAC
        header.verify_mac(self.mac_key())?;

        // Return the payload key
        Ok(PayloadKey(
            hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, self.0.expose_secret()).into(),
        ))
    }
}
