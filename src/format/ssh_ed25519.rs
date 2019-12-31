use curve25519_dalek::edwards::EdwardsPoint;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{
    error::Error,
    keys::FileKey,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
};

const SSH_ED25519_RECIPIENT_TAG: &[u8] = b"ssh-ed25519 ";
const SSH_ED25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";

fn ssh_tag(pubkey: &[u8]) -> [u8; 4] {
    let tag_bytes = Sha256::digest(pubkey);
    let mut tag = [0; 4];
    tag.copy_from_slice(&tag_bytes[..4]);
    tag
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) rest: super::x25519::RecipientLine,
}

impl RecipientLine {
    pub(crate) fn wrap_file_key(
        file_key: &FileKey,
        ssh_key: &[u8],
        ed25519_pk: &EdwardsPoint,
    ) -> Self {
        let pk: PublicKey = ed25519_pk.to_montgomery().to_bytes().into();

        let mut rng = OsRng;
        let esk = EphemeralSecret::new(&mut rng);
        let epk: PublicKey = (&esk).into();

        let tweak: StaticSecret = hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
        let shared_secret = tweak.diffie_hellman(&(*esk.diffie_hellman(&pk).as_bytes()).into());

        let mut salt = vec![];
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(
            &salt,
            SSH_ED25519_RECIPIENT_KEY_LABEL,
            shared_secret.as_bytes(),
        );
        let encrypted_file_key = {
            let mut key = [0; 32];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            tag: ssh_tag(&ssh_key),
            rest: super::x25519::RecipientLine {
                epk,
                encrypted_file_key,
            },
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        ssh_key: &[u8],
        privkey: &[u8; 64],
    ) -> Option<Result<FileKey, Error>> {
        if ssh_tag(&ssh_key) != self.tag {
            return None;
        }

        let sk: StaticSecret = {
            let mut sk = [0; 32];
            // privkey format is seed || pubkey
            sk.copy_from_slice(&Sha512::digest(&privkey[0..32])[0..32]);
            sk.into()
        };
        let pk = PublicKey::from(&sk);

        let tweak: StaticSecret = hkdf(&ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
        let shared_secret = tweak.diffie_hellman(&PublicKey::from(
            *sk.diffie_hellman(&self.rest.epk).as_bytes(),
        ));

        let mut salt = vec![];
        salt.extend_from_slice(self.rest.epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());

        let enc_key = hkdf(
            &salt,
            SSH_ED25519_RECIPIENT_KEY_LABEL,
            shared_secret.as_bytes(),
        );

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        Some(
            aead_decrypt(&enc_key, &self.rest.encrypted_file_key)
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
        combinator::map,
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::{format::x25519, util::read::encoded_data};

    fn ssh_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        encoded_data(4, [0; 4])(input)
    }

    pub(crate) fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(SSH_ED25519_RECIPIENT_TAG),
            map(
                separated_pair(
                    separated_pair(ssh_tag, tag(" "), x25519::read::epk),
                    newline,
                    encoded_data(32, [0; 32]),
                ),
                |((tag, epk), encrypted_file_key)| RecipientLine {
                    tag,
                    rest: x25519::RecipientLine {
                        epk,
                        encrypted_file_key,
                    },
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
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SSH_ED25519_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(" "),
            encoded_data(r.rest.epk.as_bytes()),
            string(line_ending),
            encoded_data(&r.rest.encrypted_file_key),
        ))
    }
}
