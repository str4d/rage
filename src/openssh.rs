//! Parser for OpenSSH public and private key formats.

use nom::{
    branch::alt,
    bytes::streaming::tag,
    character::streaming::newline,
    error::{make_error, ErrorKind},
    sequence::{pair, terminated},
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
        error::{make_error, ErrorKind},
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
        // Type: Universal | Primitive | INTEGER
        let (i, _) = der_type(0, 0, 2)(input)?;
        let (i, integer_len) = der_length(i)?;
        let (i, integer_bytes) = take(integer_len)(i)?;

        Ok((i, BigUint::from_bytes_be(integer_bytes)))
    }

    fn tag_version(ver: u8) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
        move |input: &[u8]| {
            // Type: Universal | Primitive | INTEGER
            let (mid, _) = der_type(0, 0, 2)(input)?;
            match der_length(mid)? {
                (i, integer_len) if integer_len == 1 => tag(&[ver])(i),
                _ => Err(nom::Err::Failure(make_error(mid, ErrorKind::Tag))),
            }
        }
    }

    pub(super) fn rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPrivateKey> {
        // Type: Universal | Constructed | SEQUENCE
        let (mid, _) = der_type(0, 1, 16)(input)?;
        let (i, _seq_len) = der_length(mid)?;

        let (i, _) = tag_version(0)(i)?;
        let (i, modulus) = integer(i)?;
        let (i, public_exponent) = integer(i)?;
        let (i, private_exponent) = integer(i)?;
        let (i, prime_p) = integer(i)?;
        let (i, prime_q) = integer(i)?;
        let (i, _d_mod_pm1) = integer(i)?;
        let (i, _d_mod_qm1) = integer(i)?;
        let (i, _iqmp) = integer(i)?;

        let sk = rsa::RSAPrivateKey::from_components(
            modulus,
            public_exponent,
            private_exponent,
            vec![prime_p, prime_q],
        );

        Ok((i, sk))
    }
}

mod read_binary {
    use nom::{
        bytes::complete::{tag, take},
        error::{make_error, ErrorKind},
        multi::{length_data, length_value},
        number::complete::be_u32,
        IResult,
    };
    use num_bigint_dig::BigUint;

    use super::{SSH_ED25519_KEY_PREFIX, SSH_RSA_KEY_PREFIX};
    use crate::keys::SecretKey;

    fn openssh_rsa_privkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPrivateKey> {
        let (i, modulus) = length_data(be_u32)(input)?;
        let (i, e) = length_data(be_u32)(i)?;
        let (i, d) = length_data(be_u32)(i)?;
        let (i, _iqmp) = length_data(be_u32)(i)?;
        let (i, prime_p) = length_data(be_u32)(i)?;
        let (i, prime_q) = length_data(be_u32)(i)?;

        let sk = rsa::RSAPrivateKey::from_components(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(e),
            BigUint::from_bytes_be(d),
            vec![
                BigUint::from_bytes_be(prime_p),
                BigUint::from_bytes_be(prime_q),
            ],
        );

        Ok((i, sk))
    }

    fn openssh_ed25519_privkey(input: &[u8]) -> IResult<&[u8], [u8; 64]> {
        let (mid, pubkey_bytes) = length_data(be_u32)(input)?;
        let (i, privkey_bytes) = length_data(be_u32)(mid)?;
        if privkey_bytes.len() != 64 {
            return Err(nom::Err::Failure(make_error(mid, ErrorKind::LengthValue)));
        }
        if pubkey_bytes != &privkey_bytes[32..64] {
            return Err(nom::Err::Failure(make_error(mid, ErrorKind::Tag)));
        }

        let mut privkey = [0; 64];
        privkey.copy_from_slice(&privkey_bytes);

        Ok((i, privkey))
    }

    pub(super) fn openssh_privkey(input: &[u8]) -> IResult<&[u8], Vec<SecretKey>> {
        let (i, _) = tag(b"openssh-key-v1\x00")(input)?;
        let (i, _cipher_name) = length_value(be_u32, tag(b"none"))(i)?;
        let (i, _kdf_name) = length_value(be_u32, tag(b"none"))(i)?;
        let (i, _kdf) = length_value(be_u32, tag(b""))(i)?;
        let (mut mid, num_keys) = be_u32(i)?;

        let mut keys = vec![];
        for _ in 0..num_keys {
            let (i, ssh_key) = length_data(be_u32)(mid)?;
            let (i, _sk_len) = be_u32(i)?;
            let (i, checksum) = take(4usize)(i)?;
            let (key_type_i, _) = tag(checksum)(i)?;
            let (i, key_type) = length_data(be_u32)(key_type_i)?;
            let i = if key_type == SSH_RSA_KEY_PREFIX.as_bytes() {
                let (i, sk) = openssh_rsa_privkey(i)?;
                keys.push(SecretKey::SshRsa(ssh_key.to_vec(), sk));
                i
            } else if key_type == SSH_ED25519_KEY_PREFIX.as_bytes() {
                let (i, privkey) = openssh_ed25519_privkey(i)?;
                keys.push(SecretKey::SshEd25519(ssh_key.to_vec(), privkey));
                i
            } else {
                eprintln!("{:?}", key_type);
                return Err(nom::Err::Failure(make_error(key_type_i, ErrorKind::Tag)));
            };
            let (i, _comment) = length_data(be_u32)(i)?;
            mid = i;
        }

        Ok((i, keys))
    }

    pub(super) fn ssh_rsa_pubkey(input: &[u8]) -> IResult<&[u8], rsa::RSAPublicKey> {
        let (i, _) = length_value(be_u32, tag(SSH_RSA_KEY_PREFIX))(input)?;
        let (i, exponent) = length_data(be_u32)(i)?;
        let (i, modulus) = length_data(be_u32)(i)?;

        let pk = rsa::RSAPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent),
        )
        .unwrap();

        Ok((i, pk))
    }

    pub(super) fn ssh_ed25519_pubkey(input: &[u8]) -> IResult<&[u8], [u8; 32]> {
        let (mid, _) = length_value(be_u32, tag(SSH_ED25519_KEY_PREFIX))(input)?;
        let (i, buf) = length_data(be_u32)(mid)?;
        if buf.len() != 32 {
            return Err(nom::Err::Failure(make_error(mid, ErrorKind::LengthValue)));
        }

        let mut pk = [0; 32];
        pk.copy_from_slice(&buf);
        Ok((i, pk))
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
    let (mid, _) = pair(tag("-----BEGIN RSA PRIVATE KEY-----"), newline)(input)?;
    let (i, privkey) = terminated(
        read_wrapped_str_while_encoded(base64::STANDARD),
        pair(newline, tag("-----END RSA PRIVATE KEY-----")),
    )(mid)?;

    match read_asn1::rsa_privkey(&privkey) {
        Ok((_, privkey)) => {
            let mut ssh_key = vec![];
            cookie_factory::gen(
                write_binary::ssh_rsa_pubkey(&privkey.to_public_key()),
                &mut ssh_key,
            )
            .unwrap();
            Ok((i, vec![SecretKey::SshRsa(ssh_key, privkey)]))
        }
        Err(_) => Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof))),
    }
}

fn openssh_privkey(input: &str) -> IResult<&str, Vec<SecretKey>> {
    let (mid, _) = pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), newline)(input)?;
    let (i, privkey) = terminated(
        read_wrapped_str_while_encoded(base64::STANDARD),
        pair(newline, tag("-----END OPENSSH PRIVATE KEY-----")),
    )(mid)?;

    match read_binary::openssh_privkey(&privkey) {
        Ok((_, keys)) => Ok((i, keys)),
        Err(e) => {
            eprintln!("{:?}", e);
            Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof)))
        }
    }
}

pub(crate) fn ssh_secret_keys(input: &str) -> IResult<&str, Vec<SecretKey>> {
    alt((rsa_privkey, openssh_privkey))(input)
}

fn ssh_rsa_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    let (mid, _) = pair(tag(SSH_RSA_KEY_PREFIX), tag(" "))(input)?;
    let (i, ssh_key) = terminated(read_str_while_encoded(base64::STANDARD_NO_PAD), tag(" "))(mid)?;

    let (_, pk) = match read_binary::ssh_rsa_pubkey(&ssh_key) {
        Ok(pk) => pk,
        Err(_) => return Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof))),
    };

    Ok((i, Some(RecipientKey::SshRsa(ssh_key, pk))))
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    let (mid, _) = pair(tag(SSH_ED25519_KEY_PREFIX), tag(" "))(input)?;
    let (i, ssh_key) = terminated(read_encoded_str(51, base64::STANDARD_NO_PAD), tag(" "))(mid)?;

    let (_, pk) = match read_binary::ssh_ed25519_pubkey(&ssh_key) {
        Ok(pk) => pk,
        Err(_) => return Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof))),
    };

    Ok((i, Some(RecipientKey::SshEd25519(ssh_key, pk))))
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, Option<RecipientKey>> {
    // Key types we want to ignore in SSH pubkey files
    let (mid, _) = pair(tag("ecdsa-sha2-nistp256"), tag(" "))(input)?;
    let (i, _) = terminated(read_str_while_encoded(base64::STANDARD_NO_PAD), tag(" "))(mid)?;

    Ok((i, None))
}

pub(crate) fn ssh_recipient_key(input: &str) -> IResult<&str, Option<RecipientKey>> {
    alt((ssh_rsa_pubkey, ssh_ed25519_pubkey, ssh_ignore_pubkey))(input)
}
