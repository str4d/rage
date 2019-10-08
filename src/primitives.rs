//! Primitive cryptographic operations used by `age`.

use aead::{Aead, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{crypto_mac::MacError, Hmac, Mac};
use scrypt::{errors::InvalidParams, scrypt as scrypt_inner, ScryptParams};
use sha2::Sha256;
use std::io::{self, Write};

mod stream;
pub(crate) use stream::Stream;

/// `encrypt[key](plaintext)`
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub(crate) fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let c = ChaCha20Poly1305::new((*key).into());
    c.encrypt(&[0; 12].into(), plaintext)
        .map_err(|_| "Failed to encrypt")
}

/// `decrypt[key](ciphertext)`
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub(crate) fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let c = ChaCha20Poly1305::new((*key).into());
    c.decrypt(&[0; 12].into(), ciphertext).ok()
}

/// `HKDF[salt, label](key, 32)`
///
/// HKDF from [RFC 5869] with SHA-256.
///
/// [RFC 5869]: https://tools.ietf.org/html/rfc5869
pub(crate) fn hkdf(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut okm = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(label, &mut okm)
        .unwrap();
    okm
}

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
    pub(crate) fn new(key: &[u8]) -> Self {
        HmacWriter {
            inner: Hmac::new_varkey(key).unwrap(),
        }
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
pub(crate) fn scrypt(salt: &[u8], n: usize, password: &str) -> Result<[u8; 32], InvalidParams> {
    let mut log_n = 0;
    while (n >> log_n) > 1 {
        log_n += 1;
    }
    if (1 << log_n) != n {
        return Err(InvalidParams);
    }

    let params = ScryptParams::new(log_n, 8, 1)?;

    let mut output = [0; 32];
    scrypt_inner(password.as_bytes(), salt, &params, &mut output).unwrap();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use scrypt::errors::InvalidParams;

    use super::{aead_decrypt, aead_encrypt, scrypt};

    #[test]
    fn aead_round_trip() {
        let key = [14; 32];
        let plaintext = b"12345678";
        let encrypted = aead_encrypt(&key, plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn scrypt_rejects_non_pow2_n() {
        assert_eq!(scrypt(&[7; 16], 3, "password"), Err(InvalidParams));
        assert!(scrypt(&[7; 16], 2, "password").is_ok());
    }
}
