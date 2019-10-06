use getrandom::getrandom;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const SECRET_KEY_PREFIX: &str = "AGE_SECRET_KEY_";
const PUBLIC_KEY_PREFIX: &str = "pubkey:";

pub enum SecretKey {
    X25519([u8; 32]),
}

impl SecretKey {
    pub fn new() -> Self {
        let mut sk = [0; 32];
        getrandom(&mut sk).expect("Should not fail");
        SecretKey::X25519(sk)
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.find(SECRET_KEY_PREFIX) {
            Some(0) => (),
            _ => return None,
        }

        base64::decode_config(&s[SECRET_KEY_PREFIX.len()..], base64::URL_SAFE_NO_PAD)
            .ok()
            .and_then(|buf| {
                if buf.len() == 32 {
                    let mut sk = [0; 32];
                    sk.copy_from_slice(&buf);
                    Some(SecretKey::X25519(sk))
                } else {
                    None
                }
            })
    }

    pub fn to_str(&self) -> String {
        match self {
            SecretKey::X25519(sk) => format!(
                "{}{}",
                SECRET_KEY_PREFIX,
                base64::encode_config(&sk, base64::URL_SAFE_NO_PAD)
            ),
        }
    }

    pub fn to_public(&self) -> PublicKey {
        match self {
            SecretKey::X25519(sk) => PublicKey::X25519(x25519(*sk, X25519_BASEPOINT_BYTES)),
        }
    }
}

pub enum PublicKey {
    X25519([u8; 32]),
}

impl PublicKey {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.find(PUBLIC_KEY_PREFIX) {
            Some(0) => (),
            _ => return None,
        }

        base64::decode_config(&s[PUBLIC_KEY_PREFIX.len()..], base64::URL_SAFE_NO_PAD)
            .ok()
            .and_then(|buf| {
                if buf.len() == 32 {
                    let mut pk = [0; 32];
                    pk.copy_from_slice(&buf);
                    Some(PublicKey::X25519(pk))
                } else {
                    println!("Invalid decoded length");
                    None
                }
            })
    }

    pub fn to_str(&self) -> String {
        match self {
            PublicKey::X25519(pk) => format!(
                "{}{}",
                PUBLIC_KEY_PREFIX,
                base64::encode_config(&pk, base64::URL_SAFE_NO_PAD)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicKey, SecretKey};

    const TEST_SK: &str = "AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg";
    const TEST_PK: &str = "pubkey:X4ZiZYoURuOqC2_GPISYiWbJn1-j_HECyac7BpD6kHU";

    #[test]
    fn secret_key_encoding() {
        assert_eq!(SecretKey::from_str(TEST_SK).unwrap().to_str(), TEST_SK);
    }

    #[test]
    fn pubkey_encoding() {
        assert_eq!(PublicKey::from_str(TEST_PK).unwrap().to_str(), TEST_PK);
    }

    #[test]
    fn pubkey_from_secret_key() {
        assert_eq!(
            SecretKey::from_str(TEST_SK).unwrap().to_public().to_str(),
            TEST_PK
        );
    }
}
