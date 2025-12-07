use hkdf::Hkdf;
use sha2::Sha256;

pub mod p256tag;
pub mod scrypt;
pub mod x25519;

/// Derives a tag for the tagged age recipient formats.
fn tag(ikm: &[u8], salt: &str) -> [u8; 4] {
    let (tag, _) = Hkdf::<Sha256>::extract(Some(salt.as_bytes()), ikm);
    tag[..4].try_into().expect("correct length")
}
