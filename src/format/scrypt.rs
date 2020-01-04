use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, Secret, SecretString};
use std::time::{Duration, SystemTime};

use crate::{
    error::Error,
    keys::FileKey,
    primitives::{aead_decrypt, aead_encrypt, scrypt},
};

const SCRYPT_RECIPIENT_TAG: &[u8] = b"scrypt ";
const SCRYPT_SALT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const ONE_SECOND: Duration = Duration::from_secs(1);

/// Pick an scrypt work factor that will take around 1 second on this device.
///
/// Guaranteed to return a valid work factor (less than 64).
fn target_scrypt_work_factor() -> u8 {
    // Time a work factor that should always be fast.
    let mut log_n = 10;

    let start = SystemTime::now();
    scrypt(&[], log_n, "").expect("log_n < 64");
    let duration = SystemTime::now().duration_since(start);

    duration
        .map(|mut d| {
            // Use duration as a proxy for CPU usage, which scales linearly with N.
            while d < ONE_SECOND && log_n < 63 {
                log_n += 1;
                d *= 2;
            }
            log_n
        })
        .unwrap_or({
            // Couldn't measure, so guess. This is roughly 1 second on a modern machine.
            18
        })
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) salt: [u8; 16],
    pub(crate) log_n: u8,
    pub(crate) encrypted_file_key: [u8; 32],
}

impl RecipientLine {
    pub(crate) fn wrap_file_key(file_key: &FileKey, passphrase: &SecretString) -> Self {
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);

        let mut inner_salt = vec![];
        inner_salt.extend_from_slice(SCRYPT_SALT_LABEL);
        inner_salt.extend_from_slice(&salt);

        let log_n = target_scrypt_work_factor();

        let enc_key = scrypt(&inner_salt, log_n, passphrase.expose_secret()).expect("log_n < 64");
        let encrypted_file_key = {
            let mut key = [0; 32];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            salt,
            log_n,
            encrypted_file_key,
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<Option<FileKey>, Error> {
        // Place bounds on the work factor we will accept (roughly 16 seconds).
        let target = target_scrypt_work_factor();
        if self.log_n > max_work_factor.unwrap_or_else(|| target + 4) {
            return Err(Error::ExcessiveWork {
                required: self.log_n,
                target,
            });
        }

        let mut inner_salt = vec![];
        inner_salt.extend_from_slice(SCRYPT_SALT_LABEL);
        inner_salt.extend_from_slice(&self.salt);

        let enc_key =
            scrypt(&inner_salt, self.log_n, passphrase.expose_secret()).map_err(|_| {
                Error::ExcessiveWork {
                    required: self.log_n,
                    target,
                }
            })?;
        aead_decrypt(&enc_key, &self.encrypted_file_key)
            .map(|pt| {
                // It's ours!
                let mut file_key = [0; 16];
                file_key.copy_from_slice(&pt);
                Some(FileKey(Secret::new(file_key)))
            })
            .map_err(Error::from)
    }
}

pub(super) mod read {
    use nom::{
        bytes::streaming::tag,
        character::streaming::{digit1, newline},
        combinator::{map, map_res},
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    fn salt(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
        encoded_data(16, [0; 16])(input)
    }

    fn log_n(input: &[u8]) -> IResult<&[u8], u8> {
        map_res(digit1, |log_n_str| {
            let log_n_str =
                std::str::from_utf8(log_n_str).expect("digit1 only returns valid ASCII bytes");
            u8::from_str_radix(log_n_str, 10)
        })(input)
    }

    pub(crate) fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(SCRYPT_RECIPIENT_TAG),
            map(
                separated_pair(
                    separated_pair(salt, tag(" "), log_n),
                    newline,
                    encoded_data(32, [0; 32]),
                ),
                |((salt, log_n), encrypted_file_key)| RecipientLine {
                    salt,
                    log_n,
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
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(r: &RecipientLine) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SCRYPT_RECIPIENT_TAG),
            encoded_data(&r.salt),
            string(format!(" {}{}", r.log_n, "\n")),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
