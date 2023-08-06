//! The "ssh-rsa" and "ssh-ed25519" recipient types, which allow reusing existing SSH keys
//! for encryption with age-encryption.org/v1.
//!
//! These recipient types should only be used for compatibility with existing keys, and
//! native X25519 keys should be preferred otherwise.
//!
//! Note that these recipient types are not anonymous: the encrypted message will include
//! a short 32-bit ID of the public key.

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AeadCore, Aes256Gcm};
use age_core::secrecy::{ExposeSecret, SecretString};
use bcrypt_pbkdf::bcrypt_pbkdf;
use cipher::Unsigned;
use sha2::{Digest, Sha256};

use crate::error::DecryptError;

pub(crate) mod identity;
pub(crate) mod recipient;

pub use identity::{Identity, UnsupportedKey};
pub use recipient::{ParseRecipientKeyError, Recipient};

pub(crate) const SSH_RSA_KEY_PREFIX: &str = "ssh-rsa";
pub(crate) const SSH_ED25519_KEY_PREFIX: &str = "ssh-ed25519";

pub(super) const SSH_RSA_RECIPIENT_TAG: &str = "ssh-rsa";
const SSH_RSA_OAEP_LABEL: &str = "age-encryption.org/v1/ssh-rsa";

pub(super) const SSH_ED25519_RECIPIENT_TAG: &str = "ssh-ed25519";
const SSH_ED25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";

const TAG_LEN_BYTES: usize = 4;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes128Ctr = ctr::Ctr64BE<Aes128>;
type Aes192Ctr = ctr::Ctr64BE<Aes192>;
type Aes256Ctr = ctr::Ctr64BE<Aes256>;

fn ssh_tag(pubkey: &[u8]) -> [u8; TAG_LEN_BYTES] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; TAG_LEN_BYTES];
    tag.copy_from_slice(&tag_bytes[..TAG_LEN_BYTES]);
    tag
}

/// OpenSSH-supported ciphers.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug)]
enum OpenSshCipher {
    Aes256Cbc,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes256Gcm,
}

impl OpenSshCipher {
    /// Returns the length of the authenticating part of the cipher (the tag of an AEAD).
    fn auth_len(self) -> usize {
        match self {
            OpenSshCipher::Aes256Cbc
            | OpenSshCipher::Aes128Ctr
            | OpenSshCipher::Aes192Ctr
            | OpenSshCipher::Aes256Ctr => 0,
            OpenSshCipher::Aes256Gcm => <Aes256Gcm as AeadCore>::TagSize::USIZE,
        }
    }

    fn decrypt(
        self,
        kdf: &OpenSshKdf,
        p: SecretString,
        ct: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        match self {
            OpenSshCipher::Aes256Cbc => decrypt::aes_cbc::<Aes256CbcDec>(kdf, p, ct),
            OpenSshCipher::Aes128Ctr => Ok(decrypt::aes_ctr::<Aes128Ctr>(kdf, p, ct)),
            OpenSshCipher::Aes192Ctr => Ok(decrypt::aes_ctr::<Aes192Ctr>(kdf, p, ct)),
            OpenSshCipher::Aes256Ctr => Ok(decrypt::aes_ctr::<Aes256Ctr>(kdf, p, ct)),
            OpenSshCipher::Aes256Gcm => decrypt::aes_gcm::<Aes256Gcm>(kdf, p, ct),
        }
    }
}

/// OpenSSH-supported KDFs.
#[derive(Clone, Debug)]
enum OpenSshKdf {
    Bcrypt { salt: Vec<u8>, rounds: u32 },
}

impl OpenSshKdf {
    fn derive(&self, passphrase: SecretString, out_len: usize) -> Vec<u8> {
        match self {
            OpenSshKdf::Bcrypt { salt, rounds } => {
                let mut output = vec![0; out_len];
                bcrypt_pbkdf(passphrase.expose_secret(), salt, *rounds, &mut output)
                    .expect("parameters are valid");
                output
            }
        }
    }
}

/// An encrypted SSH private key.
#[derive(Clone)]
pub struct EncryptedKey {
    ssh_key: Vec<u8>,
    cipher: OpenSshCipher,
    kdf: OpenSshKdf,
    encrypted: Vec<u8>,
    filename: Option<String>,
}

impl EncryptedKey {
    /// Decrypts this private key.
    pub fn decrypt(
        &self,
        passphrase: SecretString,
    ) -> Result<identity::UnencryptedKey, DecryptError> {
        let decrypted = self
            .cipher
            .decrypt(&self.kdf, passphrase, &self.encrypted)?;

        let mut parser = read_ssh::openssh_unencrypted_privkey(&self.ssh_key);
        match parser(&decrypted)
            .map(|(_, sk)| sk)
            .map_err(|_| DecryptError::KeyDecryptionFailed)?
        {
            Identity::Unencrypted(key) => Ok(key),
            Identity::Unsupported(_) => Err(DecryptError::KeyDecryptionFailed),
            Identity::Encrypted(_) => unreachable!(),
        }
    }
}

mod decrypt {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit, StreamCipher};
    use aes_gcm::aead::{AeadMut, KeyInit};
    use age_core::secrecy::SecretString;
    use cipher::generic_array::{ArrayLength, GenericArray};

    use super::OpenSshKdf;
    use crate::error::DecryptError;

    fn derive_key_material<KeySize: ArrayLength<u8>, IvSize: ArrayLength<u8>>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
    ) -> (GenericArray<u8, KeySize>, GenericArray<u8, IvSize>) {
        let kdf_output = kdf.derive(passphrase, KeySize::USIZE + IvSize::USIZE);
        let (key, iv) = kdf_output.split_at(KeySize::USIZE);
        (
            GenericArray::from_exact_iter(key.iter().copied()).expect("key is correct length"),
            GenericArray::from_exact_iter(iv.iter().copied()).expect("iv is correct length"),
        )
    }

    pub(super) fn aes_cbc<C: BlockDecryptMut + KeyIvInit>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let (key, iv) = derive_key_material::<C::KeySize, C::IvSize>(kdf, passphrase);
        let cipher = C::new(&key, &iv);
        cipher
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|_| DecryptError::KeyDecryptionFailed)
    }

    pub(super) fn aes_ctr<C: StreamCipher + KeyIvInit>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let (key, iv) = derive_key_material::<C::KeySize, C::IvSize>(kdf, passphrase);
        let mut cipher = C::new(&key, &iv);
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        plaintext
    }

    pub(super) fn aes_gcm<C: AeadMut + KeyInit>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let (key, nonce) = derive_key_material::<C::KeySize, C::NonceSize>(kdf, passphrase);
        let mut cipher = C::new(&key);
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| DecryptError::KeyDecryptionFailed)
    }
}

mod read_ssh {
    use age_core::secrecy::Secret;
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use nom::{
        branch::alt,
        bytes::complete::{tag, take},
        combinator::{flat_map, map, map_opt, map_parser, map_res, recognize, rest, verify},
        multi::{length_data, length_value},
        number::complete::be_u32,
        sequence::{delimited, pair, preceded, terminated, tuple},
        IResult,
    };
    use num_traits::Zero;
    use rsa::BigUint;

    use super::{
        identity::{UnencryptedKey, UnsupportedKey},
        EncryptedKey, Identity, OpenSshCipher, OpenSshKdf, SSH_ED25519_KEY_PREFIX,
        SSH_RSA_KEY_PREFIX,
    };

    /// The SSH `string` [data type](https://tools.ietf.org/html/rfc4251#section-5).
    pub(crate) fn string(input: &[u8]) -> IResult<&[u8], &[u8]> {
        length_data(be_u32)(input)
    }

    /// Recognizes an SSH `string` matching a tag.
    #[allow(clippy::needless_lifetimes)] // false positive
    pub fn string_tag<'a>(value: &'a str) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
        move |input: &[u8]| length_value(be_u32, tag(value))(input)
    }

    /// The SSH `mpint` data type, restricted to non-negative integers.
    ///
    /// From [RFC 4251](https://tools.ietf.org/html/rfc4251#section-5):
    /// ```text
    /// Represents multiple precision integers in two's complement format,
    /// stored as a string, 8 bits per byte, MSB first.  Negative numbers
    /// have the value 1 as the most significant bit of the first byte of
    /// the data partition.  If the most significant bit would be set for
    /// a positive number, the number MUST be preceded by a zero byte.
    /// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    /// included.  The value zero MUST be stored as a string with zero
    /// bytes of data.
    /// ```
    fn mpint(input: &[u8]) -> IResult<&[u8], BigUint> {
        map_opt(string, |bytes| {
            if bytes.is_empty() {
                Some(BigUint::zero())
            } else {
                // Enforce canonicity
                let mut non_zero_bytes = bytes;
                while non_zero_bytes[0] == 0 {
                    non_zero_bytes = &non_zero_bytes[1..];
                }
                if non_zero_bytes.is_empty() {
                    // Non-canonical zero
                    return None;
                }
                if non_zero_bytes.len() + (non_zero_bytes[0] >> 7) as usize != bytes.len() {
                    // Negative number or non-canonical positive number
                    return None;
                }

                Some(BigUint::from_bytes_be(bytes))
            }
        })(input)
    }

    enum CipherResult {
        Supported(OpenSshCipher),
        Unsupported(String),
    }

    /// Parse a cipher and KDF.
    fn encryption_header(input: &[u8]) -> IResult<&[u8], Option<(CipherResult, OpenSshKdf)>> {
        alt((
            // If either cipher or KDF is None, both must be.
            map(
                tuple((string_tag("none"), string_tag("none"), string_tag(""))),
                |_| None,
            ),
            map(
                tuple((
                    alt((
                        map(string_tag("aes256-cbc"), |_| {
                            CipherResult::Supported(OpenSshCipher::Aes256Cbc)
                        }),
                        map(string_tag("aes128-ctr"), |_| {
                            CipherResult::Supported(OpenSshCipher::Aes128Ctr)
                        }),
                        map(string_tag("aes192-ctr"), |_| {
                            CipherResult::Supported(OpenSshCipher::Aes192Ctr)
                        }),
                        map(string_tag("aes256-ctr"), |_| {
                            CipherResult::Supported(OpenSshCipher::Aes256Ctr)
                        }),
                        map(string_tag("aes256-gcm@openssh.com"), |_| {
                            CipherResult::Supported(OpenSshCipher::Aes256Gcm)
                        }),
                        map(string, |s| {
                            CipherResult::Unsupported(String::from_utf8_lossy(s).into_owned())
                        }),
                    )),
                    map_opt(
                        preceded(
                            string_tag("bcrypt"),
                            map_parser(string, tuple((string, be_u32))),
                        ),
                        |(salt, rounds)| {
                            if salt.is_empty() || rounds == 0 {
                                // Invalid parameters
                                None
                            } else {
                                Some(OpenSshKdf::Bcrypt {
                                    salt: salt.into(),
                                    rounds,
                                })
                            }
                        },
                    ),
                )),
                Some,
            ),
        ))(input)
    }

    /// Parses the comment from an OpenSSH privkey and verifies its deterministic padding.
    fn comment_and_padding(input: &[u8]) -> IResult<&[u8], &[u8]> {
        terminated(
            // Comment
            string,
            // Deterministic padding
            verify(rest, |padding: &[u8]| {
                padding.iter().enumerate().all(|(i, b)| *b == (i + 1) as u8)
            }),
        )(input)
    }

    /// Internal OpenSSH encoding of an RSA private key.
    ///
    /// - [OpenSSH serialization code](https://github.com/openssh/openssh-portable/blob/4103a3ec7c68493dbc4f0994a229507e943a86d3/sshkey.c#L3187-L3198)
    fn openssh_rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RsaPrivateKey> {
        delimited(
            string_tag(SSH_RSA_KEY_PREFIX),
            map_res(
                tuple((mpint, mpint, mpint, mpint, mpint, mpint)),
                |(n, e, d, _iqmp, p, q)| rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]),
            ),
            comment_and_padding,
        )(input)
    }

    /// Internal OpenSSH encoding of an Ed25519 private key.
    ///
    /// - [OpenSSH serialization code](https://github.com/openssh/openssh-portable/blob/4103a3ec7c68493dbc4f0994a229507e943a86d3/sshkey.c#L3277-L3283)
    fn openssh_ed25519_privkey(input: &[u8]) -> IResult<&[u8], Secret<[u8; 64]>> {
        delimited(
            string_tag(SSH_ED25519_KEY_PREFIX),
            map_opt(tuple((string, string)), |(pubkey_bytes, privkey_bytes)| {
                if privkey_bytes.len() == 64 && pubkey_bytes == &privkey_bytes[32..64] {
                    let mut privkey = [0; 64];
                    privkey.copy_from_slice(privkey_bytes);
                    Some(Secret::new(privkey))
                } else {
                    None
                }
            }),
            comment_and_padding,
        )(input)
    }

    /// Unencrypted, padded list of private keys.
    ///
    /// From the [specification](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key):
    /// ```text
    /// uint32  checkint
    /// uint32  checkint
    /// string  privatekey1
    /// string  comment1
    /// string  privatekey2
    /// string  comment2
    /// ...
    /// string  privatekeyN
    /// string  commentN
    /// char    1
    /// char    2
    /// char    3
    /// ...
    /// char    padlen % 255
    /// ```
    ///
    /// Note however that the `string` type for the private keys is wrong; it should be
    /// an opaque type, or the composite type `(string, byte[])`.
    ///
    /// We only support a single key, like OpenSSH.
    #[allow(clippy::needless_lifetimes)]
    pub(super) fn openssh_unencrypted_privkey<'a>(
        ssh_key: &[u8],
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Identity> {
        // We need to own, move, and clone these in order to keep them alive.
        let ssh_key_rsa = ssh_key.to_vec();
        let ssh_key_ed25519 = ssh_key.to_vec();

        preceded(
            // Repeated checkint, intended for verifying correct decryption.
            // Don't copy this idea into a new protocol; use an AEAD instead.
            map_opt(pair(take(4usize), take(4usize)), |(c1, c2)| {
                if c1 == c2 {
                    Some(c1)
                } else {
                    None
                }
            }),
            alt((
                map(openssh_rsa_privkey, move |sk| {
                    UnencryptedKey::SshRsa(ssh_key_rsa.clone(), Box::new(sk)).into()
                }),
                map(openssh_ed25519_privkey, move |privkey| {
                    UnencryptedKey::SshEd25519(ssh_key_ed25519.clone(), privkey).into()
                }),
                map(string, |key_type| {
                    UnsupportedKey::Type(String::from_utf8_lossy(key_type).to_string()).into()
                }),
            )),
        )
    }

    /// An OpenSSH-formatted private key.
    ///
    /// - [Specification](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub(super) fn openssh_privkey(input: &[u8]) -> IResult<&[u8], Identity> {
        flat_map(
            pair(
                preceded(tag(b"openssh-key-v1\x00"), encryption_header),
                preceded(
                    // We only support a single key, like OpenSSH:
                    // https://github.com/openssh/openssh-portable/blob/4103a3ec/sshkey.c#L4171
                    tag(b"\x00\x00\x00\x01"),
                    string, // The public key in SSH format
                ),
            ),
            openssh_privkey_inner,
        )(input)
    }

    /// Encrypted, padded list of private keys.
    fn openssh_privkey_inner<'a>(
        (encryption, ssh_key): (Option<(CipherResult, OpenSshKdf)>, &'a [u8]),
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Identity> {
        // `PROTOCOL.key` specifies that the encrypted list of private keys is encoded as
        // a `string`, but this is incorrect when AEAD ciphertexts are used. For what I
        // can only assume are backwards-compatibility reasons, the `string` part encodes
        // the ciphertext without tag, and the tag is just appended to the encoding. So
        // you can only parse the full data structure by interpreting the encryption
        // header.
        let expected_remainder = encryption.as_ref().map_or(0, |(cipher_res, _)| {
            if let CipherResult::Supported(cipher) = cipher_res {
                cipher.auth_len()
            } else {
                0
            }
        });

        move |input: &[u8]| match &encryption {
            None => map_parser(string, openssh_unencrypted_privkey(ssh_key))(input),
            Some((cipher_res, kdf)) => map(
                map_parser(
                    recognize(pair(string, take(expected_remainder))),
                    preceded(be_u32, rest),
                ),
                |private| match cipher_res {
                    CipherResult::Supported(cipher) => EncryptedKey {
                        ssh_key: ssh_key.to_vec(),
                        cipher: *cipher,
                        kdf: kdf.clone(),
                        encrypted: private.to_vec(),
                        filename: None,
                    }
                    .into(),
                    CipherResult::Unsupported(cipher) => {
                        UnsupportedKey::EncryptedSsh(cipher.clone()).into()
                    }
                },
            )(input),
        }
    }

    /// An SSH-encoded RSA public key.
    ///
    /// From [RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6):
    /// ```text
    /// string    "ssh-rsa"
    /// mpint     e
    /// mpint     n
    /// ```
    pub(super) fn rsa_pubkey(input: &[u8]) -> IResult<&[u8], rsa::RsaPublicKey> {
        preceded(
            string_tag(SSH_RSA_KEY_PREFIX),
            map_res(tuple((mpint, mpint)), |(exponent, modulus)| {
                rsa::RsaPublicKey::new(modulus, exponent)
            }),
        )(input)
    }

    /// An SSH-encoded Ed25519 public key.
    ///
    /// From [draft-ietf-curdle-ssh-ed25519-02](https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-02#section-4):
    /// ```text
    /// string    "ssh-ed25519"
    /// string    key
    /// ```
    pub(super) fn ed25519_pubkey(input: &[u8]) -> IResult<&[u8], EdwardsPoint> {
        preceded(
            string_tag(SSH_ED25519_KEY_PREFIX),
            map_opt(string, |buf| {
                if buf.len() == 32 {
                    CompressedEdwardsY::from_slice(buf).decompress()
                } else {
                    None
                }
            }),
        )(input)
    }
}

mod write_ssh {
    use cookie_factory::{bytes::be_u32, combinator::slice, sequence::tuple, SerializeFn};
    use num_traits::identities::Zero;
    use rsa::{traits::PublicKeyParts, BigUint};
    use std::io::Write;

    use super::SSH_RSA_KEY_PREFIX;

    /// Writes the SSH `string` data type.
    fn string<S: AsRef<[u8]>, W: Write>(value: S) -> impl SerializeFn<W> {
        tuple((be_u32(value.as_ref().len() as u32), slice(value)))
    }

    /// Writes the SSH `mpint` data type.
    fn mpint<W: Write>(value: &BigUint) -> impl SerializeFn<W> {
        let mut bytes = value.to_bytes_be();

        // From RFC 4251 section 5:
        //     If the most significant bit would be set for a positive number,
        //     the number MUST be preceded by a zero byte. Unnecessary leading
        //     bytes with the value 0 or 255 MUST NOT be included. The value
        //     zero MUST be stored as a string with zero bytes of data.
        if value.is_zero() {
            // BigUint represents zero as vec![0]
            bytes = vec![];
        } else if bytes[0] >> 7 != 0 {
            bytes.insert(0, 0);
        }

        string(bytes)
    }

    /// Writes an SSH-encoded RSA public key.
    ///
    /// From [RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6):
    /// ```text
    /// string    "ssh-rsa"
    /// mpint     e
    /// mpint     n
    /// ```
    pub(super) fn rsa_pubkey<W: Write>(pubkey: &rsa::RsaPublicKey) -> impl SerializeFn<W> {
        tuple((
            string(SSH_RSA_KEY_PREFIX),
            mpint(pubkey.e()),
            mpint(pubkey.n()),
        ))
    }
}
