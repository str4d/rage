use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt},
};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use std::convert::TryInto;
use std::time::Duration;
use zeroize::Zeroize;

use crate::{
    error::{DecryptError, EncryptError},
    primitives::scrypt,
    util::read::base64_arg,
};

pub(super) const SCRYPT_RECIPIENT_TAG: &str = "scrypt";
const SCRYPT_SALT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const ONE_SECOND: Duration = Duration::from_secs(1);

const SALT_LEN: usize = 16;
const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// Pick an scrypt work factor that will take around 1 second on this device.
///
/// Guaranteed to return a valid work factor (less than 64).
fn target_scrypt_work_factor() -> u8 {
    // Time a work factor that should always be fast.
    let mut log_n = 10;

    let duration: Option<Duration> = {
        // Platforms that have a functional SystemTime::now():
        #[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
        {
            use std::time::SystemTime;
            let start = SystemTime::now();
            scrypt(&[], log_n, "").expect("log_n < 64");
            SystemTime::now().duration_since(start).ok()
        }

        // Platforms that can use Performance timer
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi"), feature = "web-sys"))]
        {
            web_sys::window().and_then(|window| {
                { window.performance() }.map(|performance| {
                    let start = performance.now();
                    scrypt(&[], log_n, "").expect("log_n < 64");
                    Duration::from_secs_f64((performance.now() - start) / 1_000e0)
                })
            })
        }

        // Platforms where SystemTime::now() panics:
        #[cfg(all(
            target_arch = "wasm32",
            not(target_os = "wasi"),
            not(feature = "web-sys")
        ))]
        {
            None
        }
    };

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

pub(crate) struct Recipient {
    pub(crate) passphrase: SecretString,
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError> {
        let mut salt = [0; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let mut inner_salt = vec![];
        inner_salt.extend_from_slice(SCRYPT_SALT_LABEL);
        inner_salt.extend_from_slice(&salt);

        let log_n = target_scrypt_work_factor();

        let enc_key =
            scrypt(&inner_salt, log_n, self.passphrase.expose_secret()).expect("log_n < 64");
        let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

        let encoded_salt = base64::encode_config(&salt, base64::STANDARD_NO_PAD);

        Ok(vec![Stanza {
            tag: SCRYPT_RECIPIENT_TAG.to_owned(),
            args: vec![encoded_salt, format!("{}", log_n)],
            body: encrypted_file_key,
        }])
    }
}

pub(crate) struct Identity<'a> {
    pub(crate) passphrase: &'a SecretString,
    pub(crate) max_work_factor: Option<u8>,
}

impl<'a> crate::Identity for Identity<'a> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != SCRYPT_RECIPIENT_TAG {
            return None;
        }
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let salt = base64_arg(stanza.args.get(0)?, [0; SALT_LEN])?;
        let log_n = u8::from_str_radix(stanza.args.get(1)?, 10).ok()?;

        // Place bounds on the work factor we will accept (roughly 16 seconds).
        let target = target_scrypt_work_factor();
        if log_n > self.max_work_factor.unwrap_or_else(|| target + 4) {
            return Some(Err(DecryptError::ExcessiveWork {
                required: log_n,
                target,
            }));
        }

        let mut inner_salt = vec![];
        inner_salt.extend_from_slice(SCRYPT_SALT_LABEL);
        inner_salt.extend_from_slice(&salt);

        let enc_key = match scrypt(&inner_salt, log_n, self.passphrase.expose_secret()) {
            Ok(k) => k,
            Err(_) => {
                return Some(Err(DecryptError::ExcessiveWork {
                    required: log_n,
                    target,
                }));
            }
        };

        // This AEAD is not robust, so an attacker could craft a message that decrypts
        // under two different keys (meaning two different passphrases) and then use an
        // error side-channel in an online decryption oracle to learn if either key is
        // correct. This is deemed acceptable because the use case (an online decryption
        // oracle) is not recommended, and the security loss is only one bit. This also
        // does not bypass any scrypt work, but that work can be precomputed in an online
        // oracle scenario.
        Some(
            aead_decrypt(&enc_key, FILE_KEY_BYTES, &stanza.body)
                .map(|mut pt| {
                    // It's ours!
                    let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                    pt.zeroize();
                    file_key.into()
                })
                .map_err(DecryptError::from),
        )
    }
}
