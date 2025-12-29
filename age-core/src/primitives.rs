//! Primitive cryptographic operations used across various `age` components.

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305},
    error,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// `encrypt[key](plaintext)` - encrypts a message with a one-time key.
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let k = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).expect("byte length of key will match expected"),
    );
    let mut buffer = Vec::with_capacity(plaintext.len() + CHACHA20_POLY1305.tag_len());
    buffer.extend_from_slice(plaintext);
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::empty(),
        &mut buffer,
    )
    .expect("encryption won't fail");
    buffer
}

/// `decrypt[key](ciphertext)` - decrypts a message of an expected fixed size.
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// The message size is limited to mitigate multi-key attacks, where a ciphertext can be
/// crafted that decrypts successfully under multiple keys. Short ciphertexts can only
/// target two keys, which has limited impact.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub fn aead_decrypt(
    key: &[u8; 32],
    size: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, error::Unspecified> {
    if ciphertext.len() != size + CHACHA20_POLY1305.tag_len() {
        return Err(error::Unspecified);
    }

    let k = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).expect("byte length of key will match expected"),
    );
    let mut buffer = Vec::from(ciphertext);
    k.open_in_place(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::empty(),
        &mut buffer,
    )?;
    buffer.truncate(buffer.len() - CHACHA20_POLY1305.tag_len());
    Ok(buffer)
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
        let decrypted = aead_decrypt(&key, plaintext.len(), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
