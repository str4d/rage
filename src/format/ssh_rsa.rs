use rand::rngs::OsRng;
use rsa::{RSAPrivateKey, RSAPublicKey};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::{error::Error, keys::FileKey};

const SSH_RSA_RECIPIENT_TAG: &[u8] = b"ssh-rsa ";
const SSH_RSA_OAEP_LABEL: &str = "age-tool.com ssh-rsa";

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
        combinator::map,
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::{encoded_data, wrapped_encoded_data};

    fn ssh_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        encoded_data(4, [0; 4])(input)
    }

    pub(crate) fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(SSH_RSA_RECIPIENT_TAG),
                map(
                    separated_pair(ssh_tag, line_ending, wrapped_encoded_data(line_ending)),
                    |(tag, encrypted_file_key)| RecipientLine {
                        tag,
                        encrypted_file_key,
                    },
                ),
            )(input)
        }
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

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SSH_RSA_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(line_ending),
            wrapped_encoded_data(&r.encrypted_file_key, line_ending),
        ))
    }
}
