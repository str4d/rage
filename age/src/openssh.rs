//! Parser for OpenSSH public and private key formats.

use aes::Aes256;
use aes_ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
use bcrypt_pbkdf::bcrypt_pbkdf;
use nom::{
    branch::alt,
    bytes::streaming::tag,
    character::streaming::newline,
    combinator::{map, map_opt},
    sequence::{pair, preceded, terminated},
    IResult,
};
use secrecy::{ExposeSecret, SecretString};

#[cfg(feature = "unstable")]
use nom::{bytes::streaming::is_not, combinator::opt, sequence::tuple};

use crate::{
    error::Error,
    keys::{Identity, RecipientKey, SecretKey},
    util::read::{encoded_str, str_while_encoded, wrapped_str_while_encoded},
};

#[cfg(feature = "unstable")]
use crate::keys::UnsupportedKey;

#[cfg(feature = "unstable")]
pub(crate) const SSH_RSA_KEY_PREFIX: &str = "ssh-rsa";
pub(crate) const SSH_ED25519_KEY_PREFIX: &str = "ssh-ed25519";

/// OpenSSH-supported ciphers.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug)]
enum OpenSshCipher {
    Aes256Cbc,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
}

impl OpenSshCipher {
    fn decrypt(self, kdf: &OpenSshKdf, p: SecretString, ct: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            OpenSshCipher::Aes256Cbc => decrypt::aes_cbc::<Aes256>(kdf, p, ct, 32),
            OpenSshCipher::Aes128Ctr => Ok(decrypt::aes_ctr::<Aes128Ctr>(kdf, p, ct, 16)),
            OpenSshCipher::Aes192Ctr => Ok(decrypt::aes_ctr::<Aes192Ctr>(kdf, p, ct, 24)),
            OpenSshCipher::Aes256Ctr => Ok(decrypt::aes_ctr::<Aes256Ctr>(kdf, p, ct, 32)),
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
                bcrypt_pbkdf(passphrase.expose_secret(), &salt, *rounds, &mut output)
                    .expect("parameters are valid");
                output
            }
        }
    }
}

pub struct EncryptedOpenSshKey {
    ssh_key: Vec<u8>,
    cipher: OpenSshCipher,
    kdf: OpenSshKdf,
    encrypted: Vec<u8>,
}

impl EncryptedOpenSshKey {
    pub fn decrypt(&self, passphrase: SecretString) -> Result<SecretKey, Error> {
        let decrypted = self
            .cipher
            .decrypt(&self.kdf, passphrase, &self.encrypted)?;

        let parser = read_ssh::openssh_unencrypted_privkey(&self.ssh_key);
        parser(&decrypted)
            .map(|(_, sk)| sk)
            .map_err(|_| Error::KeyDecryptionFailed)
    }
}

mod decrypt {
    use aes_ctr::stream_cipher::{NewStreamCipher, StreamCipher};
    use block_cipher_trait::BlockCipher;
    use block_modes::{block_padding::NoPadding, BlockMode, Cbc};
    use secrecy::SecretString;

    use super::OpenSshKdf;
    use crate::error::Error;

    pub(super) fn aes_cbc<C: BlockCipher>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
        ciphertext: &[u8],
        key_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let kdf_output = kdf.derive(passphrase, key_len + 16);
        let (key, iv) = kdf_output.split_at(key_len);

        let cipher = Cbc::<C, NoPadding>::new_var(key, iv).expect("key and IV are correct length");
        cipher
            .decrypt_vec(&ciphertext)
            .map_err(|_| Error::KeyDecryptionFailed)
    }

    pub(super) fn aes_ctr<C: NewStreamCipher + StreamCipher>(
        kdf: &OpenSshKdf,
        passphrase: SecretString,
        ciphertext: &[u8],
        key_len: usize,
    ) -> Vec<u8> {
        let kdf_output = kdf.derive(passphrase, key_len + 16);
        let (key, nonce) = kdf_output.split_at(key_len);

        let mut cipher = C::new_var(key, nonce).expect("key and nonce are correct length");

        let mut plaintext = ciphertext.to_vec();
        cipher.decrypt(&mut plaintext);
        plaintext
    }
}

#[cfg(feature = "unstable")]
mod read_asn1 {
    use nom::{
        bytes::complete::{tag, take},
        combinator::{map, map_opt},
        error::{make_error, ErrorKind},
        multi::{length_data, length_value},
        sequence::{preceded, terminated, tuple},
        IResult,
    };
    use rsa::BigUint;

    fn der_type(class: u8, pc: u8, num: u8) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
        assert!(class < 4);
        assert!(pc < 2);
        assert!(num < 31);
        move |input: &[u8]| tag(&[(class << 6) | (pc << 5) | num])(input)
    }

    fn der_length(input: &[u8]) -> IResult<&[u8], usize> {
        let (mid, len_byte) = take(1usize)(input)?;
        let len_byte = len_byte[0];

        // Reject indefinite and reserved
        if len_byte == 128 || len_byte == 255 {
            return Err(nom::Err::Failure(make_error(input, ErrorKind::LengthValue)));
        }

        if (len_byte & 128) == 0 {
            // Definite, short
            Ok((mid, len_byte as usize))
        } else {
            // Definite, long
            let num_len_bytes = (len_byte & 127) as usize;
            let (i, len_bytes) = take(num_len_bytes)(mid)?;
            len_bytes
                .iter()
                .fold(Ok(0usize), |acc, x| {
                    acc.and_then(|acc| {
                        acc.checked_shl(8)
                            .ok_or_else(|| {
                                nom::Err::Failure(make_error(mid, ErrorKind::LengthValue))
                            })
                            .map(|acc| acc + (*x as usize))
                    })
                })
                .map(|result| (i, result))
        }
    }

    fn integer(input: &[u8]) -> IResult<&[u8], BigUint> {
        preceded(
            // Type: Universal | Primitive | INTEGER
            der_type(0, 0, 2),
            map(length_data(der_length), BigUint::from_bytes_be),
        )(input)
    }

    fn tag_version(ver: u8) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
        move |input: &[u8]| {
            preceded(
                // Type: Universal | Primitive | INTEGER
                der_type(0, 0, 2),
                length_value(
                    map_opt(der_length, |ver_len| match ver_len {
                        1 => Some(ver_len),
                        _ => None,
                    }),
                    tag(&[ver]),
                ),
            )(input)
        }
    }

    /// A PKCS#1-encoded RSA private key.
    ///
    /// From [RFC 8017](https://tools.ietf.org/html/rfc8017#appendix-A.1.2):
    /// ```text
    /// RSAPrivateKey ::= SEQUENCE {
    ///  version           Version,
    ///  modulus           INTEGER,  -- n
    ///  publicExponent    INTEGER,  -- e
    ///  privateExponent   INTEGER,  -- d
    ///  prime1            INTEGER,  -- p
    ///  prime2            INTEGER,  -- q
    ///  exponent1         INTEGER,  -- d mod (p-1)
    ///  exponent2         INTEGER,  -- d mod (q-1)
    ///  coefficient       INTEGER,  -- (inverse of q) mod p
    ///  otherPrimeInfos   OtherPrimeInfos OPTIONAL
    /// }
    /// ```
    ///
    /// We only support the two-prime encoding, where `version = 0` and `otherPrimeInfos`
    /// is omitted.
    pub(super) fn rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPrivateKey> {
        preceded(
            // Type: Universal | Constructed | SEQUENCE
            der_type(0, 1, 16),
            length_value(
                der_length,
                preceded(
                    tag_version(0),
                    terminated(
                        map(
                            tuple((integer, integer, integer, integer, integer)),
                            |(n, e, d, p, q)| {
                                rsa::RSAPrivateKey::from_components(n, e, d, vec![p, q])
                            },
                        ),
                        // d mod (p-1), d mod (q-1), iqmp
                        tuple((integer, integer, integer)),
                    ),
                ),
            ),
        )(input)
    }
}

mod read_ssh {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    #[cfg(feature = "unstable")]
    use nom::combinator::map_res;
    use nom::{
        branch::alt,
        bytes::complete::{tag, take},
        combinator::{map, map_opt, map_parser},
        multi::{length_data, length_value},
        number::complete::be_u32,
        sequence::{pair, preceded, terminated, tuple},
        IResult,
    };
    #[cfg(feature = "unstable")]
    use num_traits::Zero;
    #[cfg(feature = "unstable")]
    use rsa::BigUint;
    use secrecy::Secret;

    #[cfg(feature = "unstable")]
    use super::SSH_RSA_KEY_PREFIX;
    use super::{EncryptedOpenSshKey, OpenSshCipher, OpenSshKdf, SSH_ED25519_KEY_PREFIX};
    use crate::keys::{EncryptedKey, Identity, SecretKey, UnsupportedKey};

    /// The SSH `string` [data type](https://tools.ietf.org/html/rfc4251#section-5).
    fn string(input: &[u8]) -> IResult<&[u8], &[u8]> {
        length_data(be_u32)(input)
    }

    /// Recognizes an SSH `string` matching a tag.
    pub fn string_tag(value: &'static str) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
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
    #[cfg(feature = "unstable")]
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

    /// Internal OpenSSH encoding of an RSA private key.
    ///
    /// - [OpenSSH serialization code](https://github.com/openssh/openssh-portable/blob/4103a3ec7c68493dbc4f0994a229507e943a86d3/sshkey.c#L3187-L3198)
    #[cfg(feature = "unstable")]
    fn openssh_rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPrivateKey> {
        preceded(
            string_tag(SSH_RSA_KEY_PREFIX),
            map(
                tuple((mpint, mpint, mpint, mpint, mpint, mpint)),
                |(n, e, d, _iqmp, p, q)| rsa::RSAPrivateKey::from_components(n, e, d, vec![p, q]),
            ),
        )(input)
    }

    /// Internal OpenSSH encoding of an Ed25519 private key.
    ///
    /// - [OpenSSH serialization code](https://github.com/openssh/openssh-portable/blob/4103a3ec7c68493dbc4f0994a229507e943a86d3/sshkey.c#L3277-L3283)
    fn openssh_ed25519_privkey(input: &[u8]) -> IResult<&[u8], Secret<[u8; 64]>> {
        preceded(
            string_tag(SSH_ED25519_KEY_PREFIX),
            map_opt(tuple((string, string)), |(pubkey_bytes, privkey_bytes)| {
                if privkey_bytes.len() == 64 && pubkey_bytes == &privkey_bytes[32..64] {
                    let mut privkey = [0; 64];
                    privkey.copy_from_slice(&privkey_bytes);
                    Some(Secret::new(privkey))
                } else {
                    None
                }
            }),
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
        ssh_key: &'a [u8],
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], SecretKey> {
        move |input: &[u8]| {
            let (mut padding, key) = preceded(
                // Repeated checkint, intended for verifying correct decryption.
                // Don't copy this idea into a new protocol; use an AEAD instead.
                map_opt(pair(take(4usize), take(4usize)), |(c1, c2)| {
                    if c1 == c2 {
                        Some(c1)
                    } else {
                        None
                    }
                }),
                terminated(
                    #[cfg(feature = "unstable")]
                    alt((
                        map(openssh_rsa_privkey, |sk| {
                            SecretKey::SshRsa(ssh_key.to_vec(), Box::new(sk))
                        }),
                        map(openssh_ed25519_privkey, |privkey| {
                            SecretKey::SshEd25519(ssh_key.to_vec(), privkey)
                        }),
                    )),
                    #[cfg(not(feature = "unstable"))]
                    map(openssh_ed25519_privkey, |privkey| {
                        SecretKey::SshEd25519(ssh_key.to_vec(), privkey)
                    }),
                    // Comment
                    string,
                ),
            )(input)?;

            // Check deterministic padding
            let padlen = padding.len();
            for i in 1..=padlen {
                let (mid, _) = tag(&[i as u8])(padding)?;
                padding = mid;
            }

            Ok((padding, key))
        }
    }

    /// An OpenSSH-formatted private key.
    ///
    /// - [Specification](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub(super) fn openssh_privkey(input: &[u8]) -> IResult<&[u8], Identity> {
        let (i, encryption) = preceded(
            tag(b"openssh-key-v1\x00"),
            terminated(
                encryption_header,
                // We only support a single key, like OpenSSH:
                // https://github.com/openssh/openssh-portable/blob/4103a3ec/sshkey.c#L4171
                tag(b"\x00\x00\x00\x01"),
            ),
        )(input)?;

        // The public key in SSH format
        let (i, ssh_key) = string(i)?;

        match encryption {
            None => map(
                map_parser(string, openssh_unencrypted_privkey(ssh_key)),
                Identity::from,
            )(i),
            Some((CipherResult::Supported(cipher), kdf)) => map(string, |encrypted| {
                EncryptedKey::OpenSsh(EncryptedOpenSshKey {
                    ssh_key: ssh_key.to_vec(),
                    cipher,
                    kdf: kdf.clone(),
                    encrypted: encrypted.to_vec(),
                })
                .into()
            })(i),
            Some((CipherResult::Unsupported(cipher), _)) => {
                Ok((i, UnsupportedKey::EncryptedOpenSsh(cipher).into()))
            }
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
    #[cfg(feature = "unstable")]
    pub(super) fn rsa_pubkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPublicKey> {
        preceded(
            string_tag(SSH_RSA_KEY_PREFIX),
            map_res(tuple((mpint, mpint)), |(exponent, modulus)| {
                rsa::RSAPublicKey::new(modulus, exponent)
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

#[cfg(feature = "unstable")]
mod write_ssh {
    use cookie_factory::{bytes::be_u32, combinator::slice, sequence::tuple, SerializeFn};
    use num_traits::identities::Zero;
    use rsa::{BigUint, PublicKey};
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
    pub(super) fn rsa_pubkey<W: Write>(pubkey: &rsa::RSAPublicKey) -> impl SerializeFn<W> {
        tuple((
            string(SSH_RSA_KEY_PREFIX),
            mpint(pubkey.e()),
            mpint(pubkey.n()),
        ))
    }
}

#[cfg(feature = "unstable")]
fn rsa_pem_encryption_header(input: &str) -> IResult<&str, &str> {
    preceded(
        tuple((tag("Proc-Type: 4,ENCRYPTED"), newline, tag("DEK-Info: "))),
        terminated(is_not("\n"), newline),
    )(input)
}

#[cfg(feature = "unstable")]
fn rsa_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN RSA PRIVATE KEY-----"), newline),
        terminated(
            map_opt(
                pair(
                    opt(terminated(rsa_pem_encryption_header, newline)),
                    wrapped_str_while_encoded(base64::STANDARD),
                ),
                |(enc_header, privkey)| {
                    if enc_header.is_some() {
                        Some(UnsupportedKey::EncryptedPem.into())
                    } else {
                        read_asn1::rsa_privkey(&privkey).ok().map(|(_, privkey)| {
                            let mut ssh_key = vec![];
                            cookie_factory::gen(
                                write_ssh::rsa_pubkey(&privkey.to_public_key()),
                                &mut ssh_key,
                            )
                            .expect("can write into a Vec");
                            SecretKey::SshRsa(ssh_key, Box::new(privkey)).into()
                        })
                    }
                },
            ),
            pair(newline, tag("-----END RSA PRIVATE KEY-----")),
        ),
    )(input)
}

fn openssh_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), newline),
        terminated(
            map_opt(wrapped_str_while_encoded(base64::STANDARD), |privkey| {
                read_ssh::openssh_privkey(&privkey).ok().map(|(_, key)| key)
            }),
            pair(newline, tag("-----END OPENSSH PRIVATE KEY-----")),
        ),
    )(input)
}

pub(crate) fn ssh_secret_keys(input: &str) -> IResult<&str, Identity> {
    #[cfg(not(feature = "unstable"))]
    {
        openssh_privkey(input)
    }

    #[cfg(feature = "unstable")]
    alt((rsa_privkey, openssh_privkey))(input)
}

#[cfg(feature = "unstable")]
fn ssh_rsa_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    preceded(
        pair(tag(SSH_RSA_KEY_PREFIX), tag(" ")),
        map_opt(
            str_while_encoded(base64::STANDARD_NO_PAD),
            |ssh_key| match read_ssh::rsa_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(RecipientKey::SshRsa(ssh_key, pk))),
                Err(_) => None,
            },
        ),
    )(input)
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    preceded(
        pair(tag(SSH_ED25519_KEY_PREFIX), tag(" ")),
        map_opt(
            encoded_str(51, base64::STANDARD_NO_PAD),
            |ssh_key| match read_ssh::ed25519_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(RecipientKey::SshEd25519(ssh_key, pk))),
                Err(_) => None,
            },
        ),
    )(input)
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    // Key types we want to ignore in SSH pubkey files
    preceded(
        pair(tag("ecdsa-sha2-nistp256"), tag(" ")),
        map(str_while_encoded(base64::STANDARD_NO_PAD), |_| None),
    )(input)
}

pub(crate) fn ssh_recipient_key(input: &str) -> IResult<&str, Option<RecipientKey>> {
    alt((
        #[cfg(feature = "unstable")]
        ssh_rsa_pubkey,
        ssh_ed25519_pubkey,
        ssh_ignore_pubkey,
    ))(input)
}
