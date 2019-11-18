//! Parser for OpenSSH public and private key formats.

use nom::{
    branch::alt,
    bytes::streaming::tag,
    character::streaming::newline,
    combinator::{map, map_opt},
    sequence::{pair, preceded, terminated},
    IResult,
};

use crate::{
    keys::{RecipientKey, SecretKey},
    util::{read_encoded_str, read_str_while_encoded, read_wrapped_str_while_encoded},
};

const SSH_RSA_KEY_PREFIX: &str = "ssh-rsa";
const SSH_ED25519_KEY_PREFIX: &str = "ssh-ed25519";

mod read_asn1 {
    use nom::{
        bytes::complete::{tag, take},
        combinator::{map, map_opt},
        error::{make_error, ErrorKind},
        multi::{length_data, length_value},
        sequence::{preceded, terminated, tuple},
        IResult,
    };
    use num_bigint_dig::BigUint;

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
    use nom::{
        branch::alt,
        bytes::complete::{tag, take},
        combinator::{map, map_opt, map_res},
        multi::{length_data, length_value},
        number::complete::be_u32,
        sequence::{pair, preceded, terminated, tuple},
        IResult,
    };
    use num_bigint_dig::BigUint;

    use super::{SSH_ED25519_KEY_PREFIX, SSH_RSA_KEY_PREFIX};
    use crate::keys::SecretKey;

    /// The SSH `string` [data type](https://tools.ietf.org/html/rfc4251#section-5).
    fn string(input: &[u8]) -> IResult<&[u8], &[u8]> {
        length_data(be_u32)(input)
    }

    /// Recognizes an SSH `string` matching a tag.
    pub fn string_tag(value: &'static str) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
        move |input: &[u8]| length_value(be_u32, tag(value))(input)
    }

    /// The SSH `mpint` data type.
    ///
    /// From [RFC 4251](https://tools.ietf.org/html/rfc4251#section-5):
    /// ```text
    /// Represents multiple precision integers in two's complement format,
    /// stored as a string, 8 bits per byte, MSB first.
    /// ```
    fn mpint(input: &[u8]) -> IResult<&[u8], BigUint> {
        // This currently only supports positive numbers, and does not enforce the
        // canonical encoding. TODO: Fix this.
        map(string, BigUint::from_bytes_be)(input)
    }

    /// Internal OpenSSH encoding of an RSA private key.
    ///
    /// - [OpenSSH serialization code](https://github.com/openssh/openssh-portable/blob/4103a3ec7c68493dbc4f0994a229507e943a86d3/sshkey.c#L3187-L3198)
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
    fn openssh_ed25519_privkey(input: &[u8]) -> IResult<&[u8], [u8; 64]> {
        preceded(
            string_tag(SSH_ED25519_KEY_PREFIX),
            map_opt(tuple((string, string)), |(pubkey_bytes, privkey_bytes)| {
                if privkey_bytes.len() == 64 && pubkey_bytes == &privkey_bytes[32..64] {
                    let mut privkey = [0; 64];
                    privkey.copy_from_slice(&privkey_bytes);
                    Some(privkey)
                } else {
                    None
                }
            }),
        )(input)
    }

    /// An OpenSSH-formatted private key.
    ///
    /// - [Specification](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub(super) fn openssh_privkey(input: &[u8]) -> IResult<&[u8], Vec<SecretKey>> {
        let (mut mid, num_keys) = preceded(
            tuple((
                tag(b"openssh-key-v1\x00"),
                // Cipher name
                string_tag("none"),
                // KDF name
                string_tag("none"),
                // KDF options
                string_tag(""),
            )),
            be_u32,
        )(input)?;

        let mut keys = vec![];
        for _ in 0..num_keys {
            let (i, ssh_key) = string(mid)?;
            // This is an SSH string data type containing a private key
            let (i, key) = length_value(
                be_u32,
                preceded(
                    // Repeated checksum thing?
                    map_opt(pair(take(4usize), take(4usize)), |(c1, c2)| {
                        if c1 == c2 {
                            Some(c1)
                        } else {
                            None
                        }
                    }),
                    terminated(
                        alt((
                            map(openssh_rsa_privkey, |sk| {
                                SecretKey::SshRsa(ssh_key.to_vec(), Box::new(sk))
                            }),
                            map(openssh_ed25519_privkey, |privkey| {
                                SecretKey::SshEd25519(ssh_key.to_vec(), privkey)
                            }),
                        )),
                        // Comment
                        string,
                    ),
                ),
            )(i)?;
            keys.push(key);
            mid = i;
        }

        Ok((mid, keys))
    }

    /// An SSH-encoded RSA public key.
    ///
    /// From [RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6):
    /// ```text
    /// string    "ssh-rsa"
    /// mpint     e
    /// mpint     n
    /// ```
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

mod write_ssh {
    use cookie_factory::{
        bytes::be_u32,
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use rsa::PublicKey;
    use std::io::Write;

    use super::SSH_RSA_KEY_PREFIX;

    pub(super) fn rsa_pubkey<W: Write>(pubkey: &rsa::RSAPublicKey) -> impl SerializeFn<W> {
        let exponent = pubkey.e().to_bytes_be();
        let modulus = pubkey.n().to_bytes_be();
        tuple((
            be_u32(SSH_RSA_KEY_PREFIX.len() as u32),
            string(SSH_RSA_KEY_PREFIX),
            be_u32(exponent.len() as u32),
            slice(exponent),
            be_u32(modulus.len() as u32 + 1),
            // TODO: Why is this extra zero here???
            slice(&[0]),
            slice(modulus),
        ))
    }
}

fn rsa_privkey(input: &str) -> IResult<&str, Vec<SecretKey>> {
    preceded(
        pair(tag("-----BEGIN RSA PRIVATE KEY-----"), newline),
        terminated(
            map_opt(
                read_wrapped_str_while_encoded(base64::STANDARD),
                |privkey| {
                    read_asn1::rsa_privkey(&privkey).ok().map(|(_, privkey)| {
                        let mut ssh_key = vec![];
                        cookie_factory::gen(
                            write_ssh::rsa_pubkey(&privkey.to_public_key()),
                            &mut ssh_key,
                        )
                        .expect("can write into a Vec");
                        vec![SecretKey::SshRsa(ssh_key, Box::new(privkey))]
                    })
                },
            ),
            pair(newline, tag("-----END RSA PRIVATE KEY-----")),
        ),
    )(input)
}

fn openssh_privkey(input: &str) -> IResult<&str, Vec<SecretKey>> {
    preceded(
        pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), newline),
        terminated(
            map_opt(
                read_wrapped_str_while_encoded(base64::STANDARD),
                |privkey| {
                    read_ssh::openssh_privkey(&privkey)
                        .ok()
                        .map(|(_, keys)| keys)
                },
            ),
            pair(newline, tag("-----END OPENSSH PRIVATE KEY-----")),
        ),
    )(input)
}

pub(crate) fn ssh_secret_keys(input: &str) -> IResult<&str, Vec<SecretKey>> {
    alt((rsa_privkey, openssh_privkey))(input)
}

fn ssh_rsa_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    preceded(
        pair(tag(SSH_RSA_KEY_PREFIX), tag(" ")),
        map_opt(read_str_while_encoded(base64::STANDARD_NO_PAD), |ssh_key| {
            match read_ssh::rsa_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(RecipientKey::SshRsa(ssh_key, pk))),
                Err(_) => None,
            }
        }),
    )(input)
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    preceded(
        pair(tag(SSH_ED25519_KEY_PREFIX), tag(" ")),
        map_opt(read_encoded_str(51, base64::STANDARD_NO_PAD), |ssh_key| {
            match read_ssh::ed25519_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(Some(RecipientKey::SshEd25519(ssh_key, pk))),
                Err(_) => None,
            }
        }),
    )(input)
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    // Key types we want to ignore in SSH pubkey files
    preceded(
        pair(tag("ecdsa-sha2-nistp256"), tag(" ")),
        map(read_str_while_encoded(base64::STANDARD_NO_PAD), |_| None),
    )(input)
}

pub(crate) fn ssh_recipient_key(input: &str) -> IResult<&str, Option<RecipientKey>> {
    alt((ssh_rsa_pubkey, ssh_ed25519_pubkey, ssh_ignore_pubkey))(input)
}
