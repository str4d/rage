//! Primitive cryptographic operations used across various `age` components.

use chacha20poly1305::{
    aead::{self, Aead, NewAead},
    ChaChaPoly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// `encrypt[key](plaintext)`
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let c = ChaChaPoly1305::<c2_chacha::Ietf>::new((*key).into());
    c.encrypt(&[0; 12].into(), plaintext)
        .expect("we won't overflow the ChaCha20 block counter")
}

/// `decrypt[key](ciphertext)`
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let c = ChaChaPoly1305::<c2_chacha::Ietf>::new((*key).into());
    c.decrypt(&[0; 12].into(), ciphertext)
}

/// `HKDF[salt, label](key, 32)`
///
/// HKDF from [RFC 5869] with SHA-256.
///
/// [RFC 5869]: https://tools.ietf.org/html/rfc5869
pub fn hkdf(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut okm = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(label, &mut okm)
        .expect("okm is the correct length");
    okm
}

#[cfg(test)]
mod tests {
    use super::{aead_decrypt, aead_encrypt};

    #[test]
    fn aead_round_trip() {
        let key = [14; 32];
        let plaintext = b"12345678";
        let encrypted = aead_encrypt(&key, plaintext);
        let decrypted = aead_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
