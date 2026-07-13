//! The "pq" recipient type, native to age.

use std::collections::HashSet;
use std::fmt;

use age_core::{
    format::{FILE_KEY_BYTES, FileKey, Stanza},
    primitives::{bech32_decode, bech32_encode, bech32_encode_to_fmt, hpke_open, hpke_seal},
    secrecy::{ExposeSecret, SecretString},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use hpke::{Deserializable, Kem as _, Serializable};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zeroize::Zeroize;

use crate::{
    error::{DecryptError, EncryptError},
    util::read::base64_arg,
};

const IDENTITY_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("AGE-SECRET-KEY-PQ-");
const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1pq");

const MLKEM768X25519_RECIPIENT_TAG: &str = "mlkem768x25519";
const MLKEM768X25519_SALT: &str = "age-encryption.org/mlkem768x25519";

const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

type Kem = hpke::kem::XWing;

/// The hybrid post-quantum age identity type, which can decrypt files encrypted to the
/// corresponding [`Recipient`].
#[derive(Clone)]
pub struct Identity(<Kem as hpke::Kem>::PrivateKey);

impl std::str::FromStr for Identity {
    type Err = &'static str;

    /// Parses an X25519 identity from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32_decode(
            s,
            |_| "invalid Bech32 encoding",
            |hrp| {
                (hrp == IDENTITY_PREFIX)
                    .then_some(())
                    .ok_or("incorrect HRP")
            },
            |_, bytes| {
                if bytes.len() != 32 {
                    Err("incorrect identity length")
                } else {
                    let mut buf = Box::new([0; 32]);
                    for (dest, src) in buf.iter_mut().zip(bytes) {
                        *dest = src;
                    }
                    let identity = <Kem as hpke::Kem>::PrivateKey::from_bytes(buf.as_slice())
                        .map_err(|_| "invalid identity")
                        .map(Self);

                    // Clear intermediates
                    buf.zeroize();

                    identity
                }
            },
        )
    }
}

impl Identity {
    /// Generates a new identity.
    pub fn generate() -> Self {
        let (identity, _) = <Kem as hpke::Kem>::gen_keypair_with_rng(&mut UnwrapErr(SysRng));
        Self(identity)
    }

    /// Serializes this identity as a string.
    pub fn to_string(&self) -> SecretString {
        let mut sk_bytes = self.0.to_bytes();
        let mut encoded = bech32_encode(IDENTITY_PREFIX, &sk_bytes);
        let ret = SecretString::from(encoded.to_uppercase());

        // Clear intermediates
        sk_bytes.zeroize();
        encoded.zeroize();

        ret
    }

    /// Returns the recipient key for this secret key.
    pub fn to_public(&self) -> Recipient {
        Recipient(Kem::sk_to_pk(&self.0))
    }
}

impl crate::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != MLKEM768X25519_RECIPIENT_TAG {
            return None;
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#mlkem768x25519-recipient-stanza
        let enc = match &stanza.args[..] {
            [arg] => match base64_arg::<_, 1120, 1120>(arg)
                .and_then(|encoded| <Kem as hpke::Kem>::EncappedKey::from_bytes(&encoded).ok())
            {
                Some(enc) => enc,
                None => return Some(Err(DecryptError::InvalidHeader)),
            },
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        // A failure to decrypt is non-fatal (we try to decrypt the recipient stanza with
        // other `pq` identities), because we cannot tell which identity matches a
        // particular stanza.
        hpke_open::<Kem>(&enc, &self.0, MLKEM768X25519_SALT.as_bytes(), &stanza.body)
            .ok()
            .map(|mut pt| {
                // It's ours!
                Ok(FileKey::init_with_mut(|file_key| {
                    file_key.copy_from_slice(&pt);
                    pt.zeroize();
                }))
            })
    }
}

/// The hybrid post-quantum age recipient type. Files encrypted to this recipient can be
/// decrypted with the corresponding [`Identity`].
///
/// This recipient is safe against future cryptographically-relevant quantum computers,
/// and can only be used along with other post-quantum recipients.
///
/// This recipient type is anonymous, in the sense that an attacker can't tell from the
/// age-encrypted file alone if it is encrypted to a certain recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient(<Kem as hpke::Kem>::PublicKey);

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32_decode(
            s,
            |_| "invalid Bech32 encoding",
            |hrp| {
                (hrp == RECIPIENT_PREFIX)
                    .then_some(())
                    .ok_or("incorrect HRP")
            },
            |_, bytes| {
                <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes.collect::<Vec<_>>())
                    .map_err(|_| "invalid recipient")
                    .map(Self)
            },
        )
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, &self.0.to_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (enc, ct) = hpke_seal::<Kem, _>(
            &self.0,
            MLKEM768X25519_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut UnwrapErr(SysRng),
        );

        let encoded_enc = BASE64_STANDARD_NO_PAD.encode(enc.to_bytes());

        Ok((
            vec![Stanza {
                tag: MLKEM768X25519_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_enc],
                body: ct,
            }],
            super::label_pq_only(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age_core::{format::FileKey, secrecy::ExposeSecret};
    use hpke::{Deserializable, Kem as _};
    use proptest::prelude::*;

    use super::{Identity, Kem, Recipient};
    use crate::{Identity as _, Recipient as _, native::label_pq_only};

    pub(crate) const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR";
    pub(crate) const TEST_RECIPIENT: &str = "age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrqtzdxz95paef6caq5aapdmwjjqpjfdyxnzr2zampc3uxy0dg4z2n2gm9su72p0pc3u0jvev55l694v78snxg3yzvcl7yda0eyytqj6a0ec477lnhcy5hzpz4zq3pxanve4cn62gqj3pjy5lqj9c6kyj4v2z8alktn8zh99970x79gjkv7522hv9kfz35zsnxhsx8wwtmu9cy3ftzjgwcp4sshn3llnylnpdsyz5jm72vefv4x5vfwytrefxg4wq3mv42wcrvkj742479zrxzpvp2p3e9fed9f0739vcu80r7ma28qfhnvlv4gfzel9q654dj3zmuvvz893azhxdvs9fxd0r7jzchzcfcs5mkyyjxhw0n2z6dvp9yn9qfdp29h0azxqyjw6v7fhyuzj7zel0uq6j9rd7wgrpz7mf5dnj43jwsgvrc8qcnhy7tu6dkdujuxzkp9xj43xe8h92ktre2a3u3s8mm5mrp9nr9pwkgtz4mdlq9hgn4fps4k57ff6wddn2fy23t47sm20r8km8sd2pcyyafnet8f0dajsrlyjeah4n3mssr6aseevuuskdvq5lzguyvpgwpta742c6698vgutzqgny8usfg0w2he7kq5vyxjd0f9hqg8xk26y9e4th0gezq92q4cpp5p2y9hf5f2cje5l0c3sa3a2qxmm38pxxvhxh99yzmfz0zk7r2s64nnwjhkfgfr3gf8xnmppcgmaykvh5sh6g7vk9790rf8ws0axmr2t7z8aae5fq2029uvcn2ghgt4fu4wgwdc0k0cz52qkvwmuzj8p8k5jgf3xzk5zmrkavjekjrpeq408xz3zxazwkc6tyfmhayrkfpjhwtz5mp8j8guqe43k2q6m2kte03vrw27y3wmqyu5etmt9dnkwcnnpmu9gz9dekfhdevf42ucshphnrk38ra6hx8w5f8q5ru0xdhrjxmwqf6cused7zc5xvq43r0zscjglpwlptpwydhqw64xz7ptjdyeyzpq2zkxtmzg29gzjpvzva4d3l0cenn9xs297wf4y4ukwrunf57xj6pm7nvrkwvtrt8hwcmgv8x7ajw7258ugf9wvkmk4052ekg87tw5vnx8nq2swyzv77v8yqlwsenvamr0zssknwts8rrhfuwj7ykysnq9jxy0uv3kuyt22djszjdtvpz6d0s0kwh8ryynddzud92emeyvvyqktd0jtj7rvvg5gch25v8smlvny3kvn5gagyz475ze2y6q466xqmz2n3hs77lddeqyta2nch5k2u5yacuk9ywnwfdzvyejnucz724hj77hrrmakm7pr3kxsrxq22ejexlud9fy2kdqmkg5yncz7jm5wv2qjk5w5kvcpqsry2yqffh2la52dxfjkjq5rzhjzeyn6dupn0qwtyv7s4lwg3xdarsdlwe2y3tujy480y7z39q259fzx6jhd2j0f5hagqpcpees7hzc2yrk5cy788uk3s7qvp5cpepx24gvws3m2g433exgwppnkjscec8qu4y9z9r7vccexjcjaen42245lmgmxmuavg9alej92322gvvyy2t6267v09ch64y0m53jff0vjj96s0ypk60hr3jw4myd6m5hpn3xjstx7tl2szhpr5qe8jj08ydjc4wy2rch2fhuy3pdfjax5awe9j99ly5hkntzz9fe5zatgjvzdd0kgtxs25njnajyf6ssekp7gelxquusn4pt25czh3scj68kq79wdn5tgm6yvm9nzavrg043x3msnygf8dweknw5jmqd0uvny6ttsn09508k0c55zfnegrm9efhxpfqdkmhh6gjtqmwze9pyyzk3tlhl53k2ykx3qheyty7saeq0d3fzv49zc0k";

    #[test]
    fn recipient_encoding() {
        let pk: Recipient = TEST_RECIPIENT.parse().unwrap();
        assert_eq!(pk.to_string(), TEST_RECIPIENT);
    }

    #[test]
    fn recipient_from_identity() {
        let key = TEST_IDENTITY.parse::<Identity>().unwrap();
        assert_eq!(key.to_public().to_string(), TEST_RECIPIENT);
    }

    proptest! {
        #[test]
        fn wrap_and_unwrap(sk_bytes in proptest::collection::vec(any::<u8>(), ..=32)) {
            let file_key = FileKey::new(Box::new([7; 16]));
            let sk = {
                let mut tmp = [0; 32];
                tmp[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                <Kem as hpke::Kem>::PrivateKey::from_bytes(&tmp).unwrap()
            };

            let res = Recipient(Kem::sk_to_pk(&sk))
                .wrap_file_key(&file_key);
            prop_assert!(res.is_ok());
            let (stanzas, labels) = res.unwrap();
            prop_assert!(labels == label_pq_only());

            let res = Identity(sk).unwrap_stanzas(&stanzas);
            prop_assert!(res.is_some());
            let res = res.unwrap();
            prop_assert!(res.is_ok());
            let res = res.unwrap();

            prop_assert_eq!(res.expose_secret(), file_key.expose_secret());
        }
    }
}
