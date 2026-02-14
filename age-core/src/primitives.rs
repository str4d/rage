//! Primitive cryptographic operations used across various `age` components.

use chacha20poly1305::{
    aead::{self, generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// `encrypt[key](plaintext)` - encrypts a message with a one-time key.
///
/// ChaCha20-Poly1305 from [RFC 7539] with a zero nonce.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let c = ChaCha20Poly1305::new(key.into());
    c.encrypt(&[0; 12].into(), plaintext)
        .expect("we won't overflow the ChaCha20 block counter")
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
) -> Result<Vec<u8>, aead::Error> {
    if ciphertext.len() != size + <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize() {
        return Err(aead::Error);
    }

    let c = ChaCha20Poly1305::new(key.into());
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

/// `HPKE.SealBase(pk_recip, info, aad = "", plaintext)`
///
/// HPKE from [RFC 9180] with:
/// - KDF: HKDF-SHA256
/// - AEAD: ChaCha20Poly1305
/// - `aad = ""` (empty)
///
/// # Panics
///
/// Panics if the configured `Kem` produces an error. The native age recipient types that
/// use HPKE are configured with parameters that ensure errors either cannot occur or are
/// cryptographically negligible. If you are using this method for an age plugin, ensure
/// that you choose a KEM with equivalent properties.
///
/// [RFC 9180]: https://tools.ietf.org/html/rfc9180
pub fn hpke_seal<Kem: hpke::Kem, R: rand::RngCore + rand::CryptoRng>(
    pk_recip: &Kem::PublicKey,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> (Kem::EncappedKey, Vec<u8>) {
    hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem, R>(
        &hpke::OpModeS::Base,
        pk_recip,
        info,
        plaintext,
        &[],
        rng,
    )
    .expect("no errors should occur with these HPKE parameters")
}

/// `HPKE.OpenBase(enc, sk_recip, info, aad = "", ciphertext)`
///
/// HPKE from [RFC 9180] with:
/// - KDF: HKDF-SHA256
/// - AEAD: ChaCha20Poly1305
/// - `aad = ""` (empty)
///
/// [RFC 9180]: https://tools.ietf.org/html/rfc9180
pub fn hpke_open<Kem: hpke::Kem>(
    encapped_key: &Kem::EncappedKey,
    sk_recip: &Kem::PrivateKey,
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, hpke::HpkeError> {
    hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem>(
        &hpke::OpModeR::Base,
        sk_recip,
        encapped_key,
        info,
        ciphertext,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use hpke::Kem;
    use rand::rngs::OsRng;

    use super::{aead_decrypt, aead_encrypt, hpke_open, hpke_seal};

    #[test]
    fn aead_round_trip() {
        let key = [14; 32];
        let plaintext = b"12345678";
        let encrypted = aead_encrypt(&key, plaintext);
        let decrypted = aead_decrypt(&key, plaintext.len(), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn hpke_round_trip() {
        type Kem = hpke::kem::DhP256HkdfSha256;
        let mut rng = OsRng;

        let (sk_recip, pk_recip) = Kem::gen_keypair(&mut rng);

        let info = b"foobar";
        let plaintext = b"12345678";

        let (encapped_key, ciphertext) = hpke_seal::<Kem, _>(&pk_recip, info, plaintext, &mut rng);
        let decrypted = hpke_open::<Kem>(&encapped_key, &sk_recip, info, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
