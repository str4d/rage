use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub mod scrypt;
pub mod tag;
pub mod x25519;

fn static_tag(pk: &[u8]) -> [u8; 4] {
    Sha256::digest(pk)[..4]
        .try_into()
        .expect("length is correct")
}

/// Derives a tag for the tagged age recipient formats.
fn stanza_tag(ikm: &[u8], salt: &str) -> [u8; 4] {
    let (tag, _) = Hkdf::<Sha256>::extract(Some(salt.as_bytes()), ikm);
    tag[..4].try_into().expect("correct length")
}
