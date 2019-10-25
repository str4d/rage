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

mod read_binary {
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

    fn openssh_rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPrivateKey> {
        preceded(
            length_value(be_u32, tag(SSH_RSA_KEY_PREFIX)),
            map(
                tuple((
                    length_data(be_u32),
                    length_data(be_u32),
                    length_data(be_u32),
                    length_data(be_u32),
                    length_data(be_u32),
                    length_data(be_u32),
                )),
                |(n, e, d, _iqmp, p, q)| {
                    rsa::RSAPrivateKey::from_components(
                        BigUint::from_bytes_be(n),
                        BigUint::from_bytes_be(e),
                        BigUint::from_bytes_be(d),
                        vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
                    )
                },
            ),
        )(input)
    }

    fn openssh_ed25519_privkey(input: &[u8]) -> IResult<&[u8], [u8; 64]> {
        preceded(
            length_value(be_u32, tag(SSH_ED25519_KEY_PREFIX)),
            map_opt(
                tuple((length_data(be_u32), length_data(be_u32))),
                |(pubkey_bytes, privkey_bytes)| {
                    if privkey_bytes.len() == 64 && pubkey_bytes == &privkey_bytes[32..64] {
                        let mut privkey = [0; 64];
                        privkey.copy_from_slice(&privkey_bytes);
                        Some(privkey)
                    } else {
                        None
                    }
                },
            ),
        )(input)
    }

    pub(super) fn openssh_privkey(input: &[u8]) -> IResult<&[u8], Vec<SecretKey>> {
        let (mut mid, num_keys) = preceded(
            tuple((
                tag(b"openssh-key-v1\x00"),
                // Cipher name
                length_value(be_u32, tag(b"none")),
                // KDF name
                length_value(be_u32, tag(b"none")),
                // KDF
                length_value(be_u32, tag(b"")),
            )),
            be_u32,
        )(input)?;

        let mut keys = vec![];
        for _ in 0..num_keys {
            let (i, ssh_key) = length_data(be_u32)(mid)?;
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
                        length_data(be_u32),
                    ),
                ),
            )(i)?;
            keys.push(key);
            mid = i;
        }

        Ok((mid, keys))
    }

    pub(super) fn ssh_rsa_pubkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPublicKey> {
        preceded(
            length_value(be_u32, tag(SSH_RSA_KEY_PREFIX)),
            map_res(
                tuple((length_data(be_u32), length_data(be_u32))),
                |(exponent, modulus)| {
                    rsa::RSAPublicKey::new(
                        BigUint::from_bytes_be(modulus),
                        BigUint::from_bytes_be(exponent),
                    )
                },
            ),
        )(input)
    }

    pub(super) fn ssh_ed25519_pubkey(input: &[u8]) -> IResult<&[u8], EdwardsPoint> {
        preceded(
            length_value(be_u32, tag(SSH_ED25519_KEY_PREFIX)),
            map_opt(length_data(be_u32), |buf| {
                if buf.len() == 32 {
                    CompressedEdwardsY::from_slice(buf).decompress()
                } else {
                    None
                }
            }),
        )(input)
    }
}

mod write_binary {
    use cookie_factory::{
        bytes::be_u32,
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use rsa::PublicKey;
    use std::io::Write;

    use super::SSH_RSA_KEY_PREFIX;

    pub(super) fn ssh_rsa_pubkey<W: Write>(pubkey: &rsa::RSAPublicKey) -> impl SerializeFn<W> {
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
                            write_binary::ssh_rsa_pubkey(&privkey.to_public_key()),
                            &mut ssh_key,
                        )
                        .unwrap();
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
                    read_binary::openssh_privkey(&privkey)
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
            match read_binary::ssh_rsa_pubkey(&ssh_key) {
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
            match read_binary::ssh_ed25519_pubkey(&ssh_key) {
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
