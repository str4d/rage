use rand::rngs::OsRng;
use rsa::{RSAPrivateKey, RSAPublicKey};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::{error::Error, keys::FileKey};

const SSH_RSA_RECIPIENT_TAG: &[u8] = b"ssh-rsa ";
const SSH_RSA_OAEP_LABEL: &str = "age-encryption.org/v1/ssh-rsa";

fn ssh_tag(pubkey: &[u8]) -> [u8; 4] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; 4];
    tag.copy_from_slice(&tag_bytes[..4]);
    tag
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) encrypted_file_key: Vec<u8>,
}

impl RecipientLine {
    pub(crate) fn wrap_file_key(file_key: &FileKey, ssh_key: &[u8], pk: &RSAPublicKey) -> Self {
        let mut rng = OsRng;
        let mut h = Sha256::default();

        let encrypted_file_key = rsa::oaep::encrypt(
            &mut rng,
            &pk,
            file_key.0.expose_secret(),
            &mut h,
            Some(SSH_RSA_OAEP_LABEL.to_owned()),
        )
        .expect("pubkey is valid and message is not too long");

        RecipientLine {
            tag: ssh_tag(&ssh_key),
            encrypted_file_key,
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        ssh_key: &[u8],
        sk: &RSAPrivateKey,
    ) -> Option<Result<FileKey, Error>> {
        if ssh_tag(&ssh_key) != self.tag {
            return None;
        }

        let mut rng = OsRng;
        let mut h = Sha256::default();

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        Some(
            rsa::oaep::decrypt(
                Some(&mut rng),
                &sk,
                &self.encrypted_file_key,
                &mut h,
                Some(SSH_RSA_OAEP_LABEL.to_owned()),
            )
            .map_err(Error::from)
            .map(|pt| {
                // It's ours!
                let mut file_key = [0; 16];
                file_key.copy_from_slice(&pt);
                FileKey(Secret::new(file_key))
            }),
        )
    }
}

pub(super) mod read {
    use nom::{
        bytes::streaming::tag,
        character::streaming::newline,
        combinator::{map, map_opt},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    fn ssh_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        encoded_data(4, [0; 4])(input)
    }

    /// Returns the slice of input up to (but not including) the first CR or LF
    /// character, if that slice is entirely Base64 characters
    ///
    /// # Errors
    ///
    /// - Returns Failure on an empty slice.
    /// - Returns Incomplete(1) if a CR or LF is not found.
    fn take_b64_line(config: base64::Config) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
        move |input: &[u8]| {
            let mut end = 0;
            while end < input.len() {
                let c = input[end];

                if c == b'\r' || c == b'\n' {
                    break;
                }

                // Substitute the character in twice after AA, so that padding
                // characters will also be detected as a valid if allowed.
                if base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_err() {
                    end = 0;
                    break;
                }

                end += 1;
            }

            if !input.is_empty() && end == 0 {
                Err(nom::Err::Error(make_error(input, ErrorKind::Eof)))
            } else if end < input.len() {
                Ok((&input[end..], &input[..end]))
            } else {
                Err(nom::Err::Incomplete(nom::Needed::Size(1)))
            }
        }
    }

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        map_opt(
            separated_nonempty_list(newline, take_b64_line(base64::STANDARD_NO_PAD)),
            |chunks| {
                // Enforce that the only chunk allowed to be shorter than 64 characters
                // is the last chunk.
                if chunks.iter().rev().skip(1).any(|s| s.len() != 64)
                    || chunks.last().map(|s| s.len() > 64) == Some(true)
                {
                    None
                } else {
                    let data: Vec<u8> = chunks.into_iter().flatten().cloned().collect();
                    base64::decode_config(&data, base64::STANDARD_NO_PAD).ok()
                }
            },
        )(input)
    }

    pub(crate) fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(SSH_RSA_RECIPIENT_TAG),
            map(
                separated_pair(ssh_tag, newline, wrapped_encoded_data),
                |(tag, encrypted_file_key)| RecipientLine {
                    tag,
                    encrypted_file_key,
                },
            ),
        )(input)
    }
}

pub(super) mod write {
    use cookie_factory::{
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::{encoded_data, wrapped_encoded_data};

    pub(crate) fn recipient_line<'a, W: 'a + Write>(r: &RecipientLine) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SSH_RSA_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string("\n"),
            wrapped_encoded_data(&r.encrypted_file_key),
        ))
    }
}
