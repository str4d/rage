use age_core::secrecy::zeroize::Zeroize;
use cipher::{
    consts::{U32, U65},
    typenum, Unsigned,
};
use hpke::{kem::SharedSecret, Deserializable, HpkeError, Serializable};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::{CryptoRng, RngCore};
use sha2::digest::XofReader;
use sha3::{
    digest::{ExtendableOutput, FixedOutput, OutputSizeUser, Update},
    Sha3_256, Shake256,
};

const LABEL: &[u8] = b"MLKEM768-P256";
type KemNct = <MlKem768 as KemCore>::CiphertextSize;
type KemNek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
type GroupNelem = U65;

#[derive(Clone)]
pub(super) struct PrivateKey {
    seed: [u8; 32],
    dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    dk_t: p256::SecretKey,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}
impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed = encoded.try_into().map_err(|_| {
            HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        let (_, _, dk_pq, dk_t) = expand_key(&seed);
        Ok(Self { seed, dk_pq, dk_t })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.seed);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PublicKey {
    pub(super) ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    pub(super) ek_t: p256::PublicKey,
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (encoded_pq, encoded_t) = encoded.split_at(KemNek::to_usize());

        let ek_pq = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            encoded_pq.try_into().expect("correct length"),
        );

        let ek_t =
            p256::EncodedPoint::from_bytes(encoded_t).map_err(|_| HpkeError::ValidationError)?;
        if ek_t.is_compressed() {
            return Err(HpkeError::ValidationError);
        }
        let ek_t = p256::PublicKey::from_encoded_point(&ek_t)
            .into_option()
            .ok_or(HpkeError::ValidationError)?;

        Ok(Self { ek_pq, ek_t })
    }
}

impl Serializable for PublicKey {
    type OutputSize = typenum::Sum<KemNek, GroupNelem>;

    fn write_exact(&self, buf: &mut [u8]) {
        let kem_neq = KemNek::to_usize();
        buf[..kem_neq].copy_from_slice(&self.ek_pq.as_bytes());
        buf[kem_neq..].copy_from_slice(self.ek_t.to_encoded_point(false).as_bytes());
    }
}

#[derive(Clone)]
pub(super) struct EncappedKey {
    ct_pq: Ciphertext<MlKem768>,
    ct_t: p256::EncodedPoint,
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (encoded_pq, encoded_t) = encoded.split_at(KemNct::to_usize());

        let ct_pq = <[u8; KemNct::USIZE]>::try_from(encoded_pq)
            .expect("correct length")
            .into();

        let ct_t =
            p256::EncodedPoint::from_bytes(encoded_t).map_err(|_| HpkeError::ValidationError)?;
        if ct_t.is_compressed() {
            return Err(HpkeError::ValidationError);
        }

        Ok(Self { ct_pq, ct_t })
    }
}

impl Serializable for EncappedKey {
    type OutputSize = typenum::Sum<KemNct, GroupNelem>;

    fn write_exact(&self, buf: &mut [u8]) {
        let kem_nct = KemNct::to_usize();
        buf[..kem_nct].copy_from_slice(&self.ct_pq.0);
        buf[kem_nct..].copy_from_slice(self.ct_t.as_bytes());
    }
}

pub(super) struct MlKem768P256;

impl hpke::Kem for MlKem768P256 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey {
            ek_pq: sk.dk_pq.encapsulation_key().clone(),
            ek_t: sk.dk_t.public_key(),
        }
    }

    type EncappedKey = EncappedKey;
    type NSecret = <sha3::Sha3_256 as OutputSizeUser>::OutputSize;
    const KEM_ID: u16 = 0x0050;

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = shake256_labeled_derive::<32>(ikm, Self::KEM_ID, b"DeriveKeyPair", b"");
        let (ek_pq, ek_t, dk_pq, dk_t) = expand_key(&seed);
        (PrivateKey { seed, dk_pq, dk_t }, PublicKey { ek_pq, ek_t })
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // TODO: Implement this if it is upstreamed.
        assert!(pk_sender_id.is_none());

        let ct_t = p256::PublicKey::from_encoded_point(&encapped_key.ct_t)
            .into_option()
            .ok_or(HpkeError::DecapError)?;

        let ss_pq = sk_recip
            .dk_pq
            .decapsulate(&encapped_key.ct_pq)
            .map_err(|()| HpkeError::DecapError)?;
        let ss_t = p256::ecdh::diffie_hellman(sk_recip.dk_t.to_nonzero_scalar(), ct_t.as_affine());

        let ss = ss(
            &ss_pq,
            ss_t.raw_secret_bytes(),
            encapped_key.ct_t.as_bytes(),
            sk_recip
                .dk_t
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        Ok(SharedSecret(ss))
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // TODO: Implement this if it is upstreamed.
        assert!(sender_id_keypair.is_none());

        let (ct_pq, ss_pq) = pk_recip
            .ek_pq
            .encapsulate(csprng)
            .map_err(|()| HpkeError::EncapError)?;

        let sk_e = p256::ecdh::EphemeralSecret::random(csprng);
        let ct_t = sk_e.public_key().to_encoded_point(false);
        let ss_t = sk_e.diffie_hellman(&pk_recip.ek_t);

        let ss = ss(
            &ss_pq,
            ss_t.raw_secret_bytes(),
            ct_t.as_bytes(),
            pk_recip.ek_t.to_encoded_point(false).as_bytes(),
        );

        Ok((SharedSecret(ss), EncappedKey { ct_pq, ct_t }))
    }
}

fn expand_key(
    seed: &[u8; 32],
) -> (
    <MlKem768 as KemCore>::EncapsulationKey,
    p256::PublicKey,
    <MlKem768 as KemCore>::DecapsulationKey,
    p256::SecretKey,
) {
    let mut seed_pq = [0; 64];
    let mut seed_t = [0; 128];
    let mut xof = Shake256::default().chain(seed).finalize_xof();
    xof.read(&mut seed_pq);
    xof.read(&mut seed_t);

    let (dk_pq, ek_pq) = super::expand_pq_key(&seed_pq);
    let dk_t = p256_random_scalar(&seed_t);
    let ek_t = dk_t.public_key();

    seed_pq.zeroize();
    seed_t.zeroize();

    (ek_pq, ek_t, dk_pq, dk_t)
}

fn p256_random_scalar(seed: &[u8; 128]) -> p256::SecretKey {
    for sk in seed.chunks_exact(32) {
        if let Ok(sk) = p256::SecretKey::from_bytes(sk.try_into().expect("correct length")) {
            return sk;
        }
    }
    // This happens with cryptographically negligible probability.
    // The chance of a single rejection is < 2^-32 for P-256.
    // The chance of reaching this is thus < 2^-128 for P-256.
    panic!("Rejection sampling failed");
}

fn shake256_labeled_derive<const L: usize>(
    ikm: &[u8],
    kem_id: u16,
    label: &[u8],
    context: &[u8],
) -> [u8; L] {
    let mut out = [0; L];
    Shake256::default()
        .chain(ikm)
        .chain(b"HPKE-v1")
        // suite_id
        .chain(b"KEM")
        .chain(kem_id.to_be_bytes())
        // prefixed_label
        .chain(
            u16::try_from(label.len())
                .expect("short enough")
                .to_be_bytes(),
        )
        .chain(label)
        .chain(u16::try_from(L).expect("short enough").to_be_bytes())
        .chain(context)
        .finalize_xof_into(&mut out);
    out
}

fn ss(ss_pq: &[u8], ss_t: &[u8], ct_t: &[u8], ek_t: &[u8]) -> sha3::digest::Output<Sha3_256> {
    let mut h = Sha3_256::default();
    h.update(ss_pq);
    h.update(ss_t);
    h.update(ct_t);
    h.update(ek_t);
    h.update(LABEL);
    h.finalize_fixed()
}

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod tests {
    use age_core::primitives::{hpke_open, hpke_seal};
    use hpke::{rand_core, Deserializable, Kem, Serializable};
    use rand::{rngs::OsRng, CryptoRng, RngCore};

    use super::{test_vectors::TEST_VECTORS, MlKem768P256, PrivateKey, PublicKey};

    #[test]
    fn hpke_round_trip() {
        type Kem = MlKem768P256;
        let mut rng = OsRng;

        let (sk_recip, pk_recip) = Kem::gen_keypair(&mut rng);

        let info = b"foobar";
        let plaintext = b"12345678";

        let (encapped_key, ciphertext) = hpke_seal::<Kem, _>(&pk_recip, info, plaintext, &mut rng);
        let decrypted = hpke_open::<Kem>(&encapped_key, &sk_recip, info, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vectors() {
        struct FakeCsprng<'a> {
            bytes: &'a [u8],
        }
        impl<'a> RngCore for FakeCsprng<'a> {
            fn next_u32(&mut self) -> u32 {
                rand_core::impls::next_u32_via_fill(self)
            }

            fn next_u64(&mut self) -> u64 {
                rand_core::impls::next_u64_via_fill(self)
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.try_fill_bytes(dest).unwrap()
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                if dest.len() > self.bytes.len() {
                    Err(rand::Error::new("ran out of randomness"))
                } else {
                    let (taken, rest) = self.bytes.split_at(dest.len());
                    dest.copy_from_slice(taken);
                    self.bytes = rest;
                    Ok(())
                }
            }
        }
        impl<'a> CryptoRng for FakeCsprng<'a> {}

        for tv in TEST_VECTORS {
            let dk = PrivateKey::from_bytes(&tv.dk).unwrap();
            assert_eq!(dk.dk_t.to_bytes().as_slice(), tv.dk_t.as_slice());

            let ek = PublicKey::from_bytes(tv.ek).unwrap();
            assert_eq!(MlKem768P256::sk_to_pk(&dk), ek);

            let mut csprng = FakeCsprng {
                bytes: &tv.randomness,
            };
            let (ss, ct) = MlKem768P256::encap(&ek, None, &mut csprng).unwrap();
            assert_eq!(ss.0.as_slice(), tv.ss.as_slice());
            assert_eq!(ct.to_bytes().as_slice(), tv.ct);

            let enc = super::EncappedKey::from_bytes(tv.ct).unwrap();
            let ss = MlKem768P256::decap(&dk, None, &enc).unwrap();
            assert_eq!(ss.0.as_slice(), tv.ss.as_slice());
        }
    }
}
