//! Structs for handling YubiKeys.

use age_core::{
    format::FileKey,
    primitives::{aead_decrypt, hkdf},
};
use age_plugin::{identity::Callbacks, Error};
use bech32::ToBase32;
use elliptic_curve::weierstrass::PublicKey as EcPublicKey;
use p256::NistP256;
use secrecy::ExposeSecret;
use std::convert::TryInto;
use std::hash;
use std::io;
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{decrypt_data, AlgorithmId, RetiredSlotId, SlotId},
    yubikey::Serial,
    YubiKey,
};

use crate::{
    format::{piv_tag, RecipientLine, RECIPIENT_KEY_LABEL},
    p256::PublicKey,
    IDENTITY_PREFIX,
};

/// A reference to an age key stored in a YubiKey.
#[derive(Debug, PartialEq)]
pub struct Stub {
    pub(crate) serial: Serial,
    pub(crate) slot: RetiredSlotId,
    pub(crate) tag: [u8; 4],
}

impl Eq for Stub {}

impl hash::Hash for Stub {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub(crate) fn new(
        serial: Serial,
        slot: RetiredSlotId,
        pubkey: &EcPublicKey<NistP256>,
    ) -> Option<(Self, PublicKey)> {
        PublicKey::from_pubkey(pubkey).map(|pk| {
            (
                Stub {
                    serial,
                    slot,
                    tag: piv_tag(&pk),
                },
                pk,
            )
        })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let serial = Serial::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
        let slot: RetiredSlotId = bytes[4].try_into().ok()?;
        Some(Stub {
            serial,
            slot,
            tag: bytes[5..9].try_into().unwrap(),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Serializes this YubiKey stub as a string.
    pub fn to_str(&self) -> String {
        bech32::encode(IDENTITY_PREFIX, self.to_bytes().to_base32())
            .expect("HRP is valid")
            .to_uppercase()
    }

    pub(crate) fn matches(&self, line: &RecipientLine) -> bool {
        self.tag == line.tag
    }

    pub(crate) fn connect(
        &self,
        callbacks: &mut dyn Callbacks,
    ) -> io::Result<Result<Connection, Error>> {
        let mut yubikey = match YubiKey::open_by_serial(self.serial) {
            Ok(yk) => yk,
            Err(_) => {
                return Ok(Err(Error {
                    kind: "identity".to_owned(),
                    message: format!("Could not open YubiKey with serial {}", self.serial),
                }))
            }
        };

        // Read the pubkey from the YubiKey slot and check it still matches.
        let pk = match Certificate::read(&mut yubikey, SlotId::Retired(self.slot))
            .ok()
            .and_then(|cert| match cert.subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => {
                    PublicKey::from_pubkey(pubkey).filter(|pk| piv_tag(&pk) == self.tag)
                }
                _ => None,
            }) {
            Some(pk) => pk,
            None => {
                return Ok(Err(Error {
                    kind: "identity".to_owned(),
                    message: "A YubiKey stub did not match the YubiKey".to_owned(),
                }))
            }
        };

        let pin = match callbacks.request_secret(&format!(
            "Enter PIN for YubiKey with serial {}",
            self.serial
        ))? {
            Ok(pin) => pin,
            Err(_) => {
                return Ok(Err(Error {
                    kind: "identity".to_owned(),
                    message: format!("A PIN is required for YubiKey with serial {}", self.serial),
                }))
            }
        };
        if let Err(_) = yubikey.verify_pin(pin.expose_secret().as_bytes()) {
            return Ok(Err(Error {
                kind: "identity".to_owned(),
                message: "Invalid YubiKey PIN".to_owned(),
            }));
        }

        Ok(Ok(Connection {
            yubikey,
            pk,
            slot: self.slot,
            tag: self.tag,
        }))
    }
}

pub(crate) struct Connection {
    yubikey: YubiKey,
    pk: PublicKey,
    slot: RetiredSlotId,
    tag: [u8; 4],
}

impl Connection {
    pub(crate) fn unwrap_file_key(&mut self, line: &RecipientLine) -> Result<FileKey, Error> {
        assert_eq!(self.tag, line.tag);

        let shared_secret = match decrypt_data(
            &mut self.yubikey,
            line.epk.decompress().as_bytes(),
            AlgorithmId::EccP256,
            SlotId::Retired(self.slot),
        ) {
            Ok(res) => res,
            Err(_) => {
                return Err(Error {
                    kind: "stanza".to_owned(),
                    message: "Failed to decrypt YubiKey stanza".to_owned(),
                })
            }
        };

        let mut salt = vec![];
        salt.extend_from_slice(line.epk.as_bytes());
        salt.extend_from_slice(self.pk.as_bytes());

        let enc_key = hkdf(&salt, RECIPIENT_KEY_LABEL, shared_secret.as_ref());

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        match aead_decrypt(&enc_key, &line.encrypted_file_key) {
            Ok(pt) => Ok(TryInto::<[u8; 16]>::try_into(&pt[..]).unwrap().into()),
            Err(_) => Err(Error {
                kind: "stanza".to_owned(),
                message: "Failed to decrypt YubiKey stanza".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use yubikey_piv::{key::RetiredSlotId, Serial};

    use super::Stub;

    #[test]
    fn stub_round_trip() {
        let stub = Stub {
            serial: Serial::from(42),
            slot: RetiredSlotId::R1,
            tag: [7; 4],
        };

        let encoded = stub.to_bytes();
        assert_eq!(Stub::from_bytes(&encoded), Some(stub));
    }
}
