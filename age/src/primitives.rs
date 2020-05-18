//! Primitive cryptographic operations used by `age`.

use hmac::{
    crypto_mac::{generic_array::typenum::U32, MacError, MacResult},
    Hmac, Mac,
};
use scrypt::{errors::InvalidParams, scrypt as scrypt_inner, ScryptParams};
use sha2::Sha256;
use std::io::{self, Write};

pub mod armor;
pub mod stream;

/// `HMAC[key](message)`
///
/// HMAC from [RFC 2104] with SHA-256.
///
/// [RFC 2104]: https://tools.ietf.org/html/rfc2104
pub(crate) struct HmacWriter {
    inner: Hmac<Sha256>,
}

impl HmacWriter {
    /// Constructs a new writer to process input data.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        HmacWriter {
            inner: Hmac::new_varkey(&key).expect("key is the correct length"),
        }
    }

    /// Checks if `mac` is correct for the processed input.
    pub(crate) fn result(self) -> MacResult<U32> {
        self.inner.result()
    }

    /// Checks if `mac` is correct for the processed input.
    pub(crate) fn verify(self, mac: &[u8]) -> Result<(), MacError> {
        self.inner.verify(mac)
    }
}

impl Write for HmacWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.inner.input(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `scrypt[salt, N](password)`
///
/// scrypt from [RFC 7914] with r = 8 and P = 1. N must be a power of 2.
///
/// [RFC 7914]: https://tools.ietf.org/html/rfc7914
pub(crate) fn scrypt(salt: &[u8], log_n: u8, password: &str) -> Result<[u8; 32], InvalidParams> {
    let params = ScryptParams::new(log_n, 8, 1)?;

    let mut output = [0; 32];
    scrypt_inner(password.as_bytes(), salt, &params, &mut output)
        .expect("output is the correct length");
    Ok(output)
}
