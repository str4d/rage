//! The "tag" recipient type, native to age.

use std::collections::HashSet;
use std::fmt;

use age_core::{
    format::{FileKey, Stanza},
    primitives::hpke_seal,
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::{Bech32, Hrp};
use hpke::{Deserializable, Serializable};
use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey,
};
use rand::rngs::OsRng;

use crate::{util::parse_bech32, EncryptError};

const RECIPIENT_PREFIX: &str = "age1tag";

const P256TAG_RECIPIENT_TAG: &str = "p256tag";
const P256TAG_SALT: &str = "age-encryption.org/p256tag";

type Kem = hpke::kem::DhP256HkdfSha256;

/// The non-hybrid tagged age recipient type, designed for hardware keys where decryption
/// potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Compressed encoding of the recipient public key.
    compressed: EncodedPoint,
    /// Cached in-memory representation, for HPKE.
    pk_recip: <Kem as hpke::Kem>::PublicKey,
}

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, bytes) = parse_bech32(s).ok_or("invalid Bech32 encoding")?;

        if hrp != RECIPIENT_PREFIX {
            return Err("incorrect HRP");
        }

        let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| "invalid SEC-1 encoding")?;
        if !encoded.is_compressed() {
            return Err("not a compressed SEC-1 encoding");
        }

        let point = PublicKey::from_encoded_point(&encoded)
            .into_option()
            .ok_or("invalid P-256 point")?;

        let pk_recip =
            <Kem as hpke::Kem>::PublicKey::from_bytes(point.to_encoded_point(false).as_bytes())
                .expect("valid");

        Ok(Self {
            compressed: encoded,
            pk_recip,
        })
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            bech32::encode::<Bech32>(
                Hrp::parse_unchecked(RECIPIENT_PREFIX),
                self.compressed.as_bytes(),
            )
            .expect("HRP is valid")
        )
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (enc, ct) = hpke_seal::<Kem, _>(
            &self.pk_recip,
            P256TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut OsRng,
        );

        let ikm = enc
            .to_bytes()
            .into_iter()
            .chain(super::static_tag(self.compressed.as_bytes()))
            .collect::<Vec<u8>>();
        let tag = super::stanza_tag(&ikm, P256TAG_SALT);

        let encoded_tag = BASE64_STANDARD_NO_PAD.encode(tag);
        let encoded_enc = BASE64_STANDARD_NO_PAD.encode(enc.to_bytes());

        Ok((
            vec![Stanza {
                tag: P256TAG_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_tag, encoded_enc],
                body: ct,
            }],
            HashSet::new(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Recipient;

    pub(crate) const TEST_RECIPIENT: &str =
        "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e";

    #[test]
    fn recipient_encoding() {
        let recipient: Recipient = TEST_RECIPIENT.parse().unwrap();
        assert_eq!(recipient.to_string(), TEST_RECIPIENT);
    }
}
