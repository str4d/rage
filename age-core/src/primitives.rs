//! Primitive cryptographic operations used across various `age` components.

use core::fmt;

use bech32::primitives::decode::CheckedHrpstring;
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

/// The bech32 checksum algorithm, defined in [BIP-173].
///
/// This is identical to [`bech32::Bech32`] except it does not enforce the length
/// restriction, allowing for a reduction in error-correcting properties.
///
/// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Bech32Long {}
impl bech32::Checksum for Bech32Long {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = bech32::Bech32::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = bech32::Bech32::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = bech32::Bech32::TARGET_RESIDUE;
}

/// Encodes data as a Bech32-encoded string with the given HRP.
///
/// This implements Bech32 as defined in [BIP-173], except it does not enforce the length
/// restriction, allowing for a reduction in error-correcting properties.
///
/// [BIP-173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
pub fn bech32_encode(hrp: bech32::Hrp, data: &[u8]) -> String {
    bech32::encode_lower::<Bech32Long>(hrp, data).expect("we don't enforce the Bech32 length limit")
}

/// Encodes data to a format writer as a Bech32-encoded string with the given HRP.
///
/// This implements Bech32 as defined in [BIP-173], except it does not enforce the length
/// restriction, allowing for a reduction in error-correcting properties.
///
/// [BIP-173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
pub fn bech32_encode_to_fmt(f: &mut impl fmt::Write, hrp: bech32::Hrp, data: &[u8]) -> fmt::Result {
    bech32::encode_lower_to_fmt::<Bech32Long, _>(f, hrp, data).map_err(|e| match e {
        bech32::EncodeError::Fmt(error) => error,
        bech32::EncodeError::TooLong(_) => unreachable!("we don't enforce the Bech32 length limit"),
        _ => panic!("Unexpected error: {e}"),
    })
}

/// Decodes a Bech32-encoded string, checks its HRP, and returns its contained data.
///
/// This implements Bech32 as defined in [BIP-173], except it does not enforce the length
/// restriction, allowing for a reduction in error-correcting properties.
///
/// [BIP-173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
pub fn bech32_decode<E, F, G, H, T>(
    s: &str,
    parse_err: F,
    hrp_filter: G,
    data_parse: H,
) -> Result<T, E>
where
    F: FnOnce(bech32::primitives::decode::CheckedHrpstringError) -> E,
    G: FnOnce(bech32::Hrp) -> Result<(), E>,
    H: FnOnce(bech32::Hrp, bech32::primitives::decode::ByteIter) -> Result<T, E>,
{
    CheckedHrpstring::new::<Bech32Long>(s)
        .map_err(parse_err)
        .and_then(|parsed| {
            hrp_filter(parsed.hrp()).and_then(|()| data_parse(parsed.hrp(), parsed.byte_iter()))
        })
}

#[cfg(test)]
mod tests {
    use super::{aead_decrypt, aead_encrypt, bech32_decode, bech32_encode};

    #[test]
    fn aead_round_trip() {
        let key = [14; 32];
        let plaintext = b"12345678";
        let encrypted = aead_encrypt(&key, plaintext);
        let decrypted = aead_decrypt(&key, plaintext.len(), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bech32_round_trip() {
        let hrp = bech32::Hrp::parse_unchecked("12345678");
        let data = [14; 32];
        let encoded = bech32_encode(hrp, &data);
        let decoded = bech32_decode(
            &encoded,
            |_| (),
            |parsed_hrp| (parsed_hrp == hrp).then_some(()).ok_or(()),
            |_, bytes| Ok(bytes.collect::<Vec<_>>()),
        )
        .unwrap();
        assert_eq!(decoded, data);
    }
}
