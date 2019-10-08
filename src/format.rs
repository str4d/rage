//! The age message format.

use std::io::Read;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::{
    keys::SecretKey,
    primitives::{aead_decrypt, hkdf, HmacWriter, Stream},
};

const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-tool.com X25519";
const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

const V1_MAGIC: &[u8] = b"This is a file encrypted with age-tool.com, version 1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const X25519_RECIPIENT_TAG: &[u8] = b"X25519 ";
const SCRYPT_RECIPIENT_TAG: &[u8] = b"scrypt ";
const MAC_TAG: &[u8] = b"---";

struct X25519Recipient {
    epk: [u8; 32],
    encrypted_file_key: Vec<u8>,
}

struct ScryptRecipient {
    salt: [u8; 16],
    n: usize,
    encrypted_file_key: Vec<u8>,
}

enum Recipient {
    X25519(X25519Recipient),
    Scrypt(ScryptRecipient),
}

impl Recipient {
    fn decrypt(&self, key: &SecretKey) -> Option<[u8; 16]> {
        match (self, key) {
            (Recipient::X25519(r), SecretKey::X25519(sk)) => {
                let pk = x25519(*sk, X25519_BASEPOINT_BYTES);
                let shared_secret = x25519(*sk, r.epk);

                let mut salt = vec![];
                salt.extend_from_slice(&r.epk);
                salt.extend_from_slice(&pk);

                let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);
                aead_decrypt(&enc_key, &r.encrypted_file_key).map(|pt| {
                    // It's ours!
                    let mut file_key = [0; 16];
                    file_key.copy_from_slice(&pt);
                    file_key
                })
            }
            _ => None,
        }
    }
}

pub struct Header {
    recipients: Vec<Recipient>,
    mac: Vec<u8>,
}

/// Attempts to decrypt a message from the given reader with a set of keys.
///
/// If successful, returns a reader that will provide the plaintext.
pub fn decrypt_message<R: Read>(
    mut input: R,
    keys: &[SecretKey],
) -> Result<impl Read, &'static str> {
    let mut data = vec![];
    let header = loop {
        match read::header(&data) {
            Ok((_, header)) => break header,
            Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                // Read the needed additional bytes
                let m = data.len();
                data.resize(m + n, 0);
                input
                    .read_exact(&mut data[m..m + n])
                    .map_err(|_| "failed to read header")?;
            }
            Err(e) => {
                eprintln!("{:?}", e);
                return Err("invalid header");
            }
        }
    };

    let mut nonce = [0; 16];
    input
        .read_exact(&mut nonce)
        .map_err(|_| "failed to read nonce")?;

    keys.iter()
        .find_map(|key| {
            header.recipients.iter().find_map(|r| {
                r.decrypt(key).and_then(|file_key| {
                    // Verify the MAC
                    let mac_key = hkdf(&[], HEADER_KEY_LABEL, &file_key);
                    let mut mac = HmacWriter::new(&mac_key);
                    cookie_factory::gen(write::header_minus_mac(&header), &mut mac).unwrap();
                    mac.verify(&header.mac).ok()?;

                    // Return the payload key
                    Some(hkdf(&nonce, PAYLOAD_KEY_LABEL, &file_key))
                })
            })
        })
        .map(|payload_key| Stream::decrypt(&payload_key, input))
        .ok_or("no matching keys")
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::streaming::{digit1, newline},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, separated_pair, terminated},
        IResult,
    };

    use super::*;

    fn encoded_data(count: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<u8>> {
        // Unpadded encoded length
        let encoded_count = ((4 * count) + 2) / 3;

        move |input: &[u8]| {
            // TODO handle newlines
            let (i, data) = take(encoded_count)(input)?;

            match base64::decode_config(data, base64::URL_SAFE_NO_PAD) {
                Ok(decoded) => Ok((i, decoded)),
                Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
            }
        }
    }

    fn x25519_epk(input: &[u8]) -> IResult<&[u8], [u8; 32]> {
        let (i, epk_vec) = encoded_data(32)(input)?;

        let mut epk = [0; 32];
        epk.copy_from_slice(&epk_vec);

        Ok((i, epk))
    }

    fn x25519_recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        let (i, (epk, encrypted_file_key)) = preceded(
            tag(X25519_RECIPIENT_TAG),
            separated_pair(x25519_epk, newline, encoded_data(32)),
        )(input)?;

        Ok((
            i,
            Recipient::X25519(X25519Recipient {
                epk,
                encrypted_file_key,
            }),
        ))
    }

    fn scrypt_salt(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
        let (i, salt_vec) = encoded_data(16)(input)?;

        let mut salt = [0; 16];
        salt.copy_from_slice(&salt_vec);

        Ok((i, salt))
    }

    fn scrypt_n(input: &[u8]) -> IResult<&[u8], usize> {
        let (i, n_str) = digit1(input)?;

        // digit1 will only return valid ASCII bytes
        let n_str = std::str::from_utf8(n_str).unwrap();

        match usize::from_str_radix(n_str, 10) {
            Ok(n) => Ok((i, n)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Digit))),
        }
    }

    fn scrypt_recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        let (i, ((salt, n), encrypted_file_key)) = preceded(
            tag(SCRYPT_RECIPIENT_TAG),
            separated_pair(
                separated_pair(scrypt_salt, tag(" "), scrypt_n),
                newline,
                encoded_data(32),
            ),
        )(input)?;

        Ok((
            i,
            Recipient::Scrypt(ScryptRecipient {
                salt,
                n,
                encrypted_file_key,
            }),
        ))
    }

    fn recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        preceded(
            tag(RECIPIENT_TAG),
            alt((x25519_recipient, scrypt_recipient)),
        )(input)
    }

    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        let (i, _) = terminated(tag(V1_MAGIC), newline)(input)?;
        let (i, recipients) = terminated(separated_nonempty_list(newline, recipient), newline)(i)?;
        let (i, mac) = terminated(
            preceded(pair(tag(MAC_TAG), tag(b" ")), encoded_data(32)),
            newline,
        )(i)?;

        Ok((i, Header { recipients, mac }))
    }
}

mod write {
    use cookie_factory::{
        combinator::{slice, string},
        multi::separated_list,
        sequence::tuple,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::*;

    fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);
        string(encoded)
    }

    fn x25519_recipient<W: Write>(r: &X25519Recipient) -> impl SerializeFn<W> {
        tuple((
            slice(X25519_RECIPIENT_TAG),
            encoded_data(&r.epk),
            string("\n"),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn scrypt_recipient<W: Write>(r: &ScryptRecipient) -> impl SerializeFn<W> {
        tuple((
            slice(SCRYPT_RECIPIENT_TAG),
            encoded_data(&r.salt),
            string(format!(" {}\n", r.n)),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn recipient<'a, W: 'a + Write>(r: &'a Recipient) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                Recipient::X25519(r) => x25519_recipient(r)(out),
                Recipient::Scrypt(r) => scrypt_recipient(r)(out),
            }
        }
    }

    pub(super) fn header_minus_mac<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(V1_MAGIC),
            string("\n"),
            separated_list(string("\n"), h.recipients.iter().map(recipient)),
            string("\n"),
            slice(MAC_TAG),
        ))
    }

    pub(super) fn header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            header_minus_mac(h),
            string(" "),
            encoded_data(&h.mac),
            string("\n"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::decrypt_message;
    use crate::keys::SecretKey;

    #[test]
    fn message_decryption() {
        let test_key = "AGE_SECRET_KEY_KWoIxSwdk-ClrgOHIdVFsku8roB3hZRA3xO7BnJfvEY";
        let test_msg_1 = b"This is a file encrypted with age-tool.com, version 1
-> X25519 8wBndPxeTabOgA0sw54InE8rJ3nmu_OligUpX5DCOEY
zbr2uOfVU47gBMC1XgYUtf2dILYR3Cb42lWgdV8oJ1k
--- 3-WbKsFc00oygch1_sbsreKSClVeCNt1DX_07wcJT-w
\xc1D\x19\r\xe4\xef\xe7>\xe9E<s*\"5w]f\xe6! \xe1b\x9c\x7f+\xb2?Htt\xa0\xa0\x9e\xb7b\xd6\xef\xachU\x1a\xbc&h|\x95\xbb+5`\xd7C\x1a\xc8\xbd";
        let test_msg_2 = b"This is a file encrypted with age-tool.com, version 1
-> X25519 vzquGLRW47PBkSfeiMDbOJeJO6mR9zMhcRljFTcIRT8
_vLg6QnGTU5UQSVs3cUJDmVMJ1Qj07oSXntDpsqi0Zw
--- GSJyv5JBG1FyMQJ5F7sV8CsmfWPwRPsblxXjoF-imV0
\xfbM84W\x98#\x0bj\xc8\x96\x95\xa7\x9ac\xb9\xaa-\xd5\xd0&aM\xba#H~\xbc\x97\xc8i\x1f\x14\x08\xba&4\xb2\x87\x9d\x80Sb\xed\xbe0\xda\x93\xc7\xab^o";

        let keys = &[SecretKey::from_str(test_key).unwrap()];
        let mut r1 = decrypt_message(&test_msg_1[..], keys).unwrap();
        let mut r2 = decrypt_message(&test_msg_2[..], keys).unwrap();

        let mut msg1 = String::new();
        r1.read_to_string(&mut msg1).unwrap();
        assert_eq!(msg1, "hello Rust from Go! \\o/\n");

        let mut msg2 = String::new();
        r2.read_to_string(&mut msg2).unwrap();
        assert_eq!(msg2, "*hyped crab noises*\n");
    }
}
