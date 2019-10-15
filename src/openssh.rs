//! Parser for OpenSSH public and private key formats.

use nom::{
    branch::alt,
    bytes::streaming::tag,
    error::{make_error, ErrorKind},
    sequence::{pair, terminated},
    IResult,
};

use crate::{
    keys::RecipientKey,
    util::{read_encoded_str, read_str_while_encoded},
};

const SSH_RSA_KEY_PREFIX: &str = "ssh-rsa";
const SSH_ED25519_KEY_PREFIX: &str = "ssh-ed25519";

mod read_binary {
    use nom::{
        bytes::complete::tag,
        error::{make_error, ErrorKind},
        multi::{length_data, length_value},
        number::complete::be_u32,
        IResult,
    };
    use num_bigint_dig::BigUint;

    use super::{SSH_ED25519_KEY_PREFIX, SSH_RSA_KEY_PREFIX};

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

fn ssh_rsa_pubkey(input: &str) -> IResult<&str, RecipientKey> {
    let (mid, _) = pair(tag(SSH_RSA_KEY_PREFIX), tag(" "))(input)?;
    let (i, ssh_key) = terminated(read_str_while_encoded(base64::STANDARD_NO_PAD), tag(" "))(mid)?;

    let (_, pk) = match read_binary::ssh_rsa_pubkey(&ssh_key) {
        Ok(pk) => pk,
        Err(_) => return Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof))),
    };

    Ok((i, RecipientKey::SshRsa(ssh_key, pk)))
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, RecipientKey> {
    let (mid, _) = pair(tag(SSH_ED25519_KEY_PREFIX), tag(" "))(input)?;
    let (i, ssh_key) = terminated(read_encoded_str(51, base64::STANDARD_NO_PAD), tag(" "))(mid)?;

    let (_, pk) = match read_binary::ssh_ed25519_pubkey(&ssh_key) {
        Ok(pk) => pk,
        Err(_) => return Err(nom::Err::Failure(make_error(mid, ErrorKind::Eof))),
    };

    Ok((i, RecipientKey::SshEd25519(ssh_key, pk)))
}

pub(crate) fn ssh_recipient_key(input: &str) -> IResult<&str, RecipientKey> {
    alt((ssh_rsa_pubkey, ssh_ed25519_pubkey))(input)
}
