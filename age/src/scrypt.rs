//! The "scrypt" passphrase-based recipient type, native to age.

use std::collections::HashSet;
use std::iter;
use std::time::Duration;

use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt},
    secrecy::{ExposeSecret, SecretString},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
    RngCore,
};
use zeroize::Zeroize;

use crate::{
    error::{DecryptError, EncryptError},
    primitives::scrypt,
    util::read::{base64_arg, decimal_digit_arg},
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
    let measure_duration = |log_n| {
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

    // Time a work factor that should always be fast.
    let mut log_n = 10;
    let mut duration: Option<Duration> = measure_duration(log_n);
    while duration.map(|d| d.is_zero()).unwrap_or(false) {
        // On some newer platforms, the work factor may be so fast that it is cannot be
        // measured. Increase the work factor until we can measure something.
        log_n += 1;
        duration = measure_duration(log_n);
    }

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

/// A passphrase-based recipient. Anyone with the passphrase can decrypt the file.
///
/// If an `scrypt::Recipient` is used, it must be the only recipient for the file: it
/// can't be mixed with other recipient types and can't be used multiple times for the
/// same file.
///
/// This API should only be used with a passphrase that was provided by (or generated
/// for) a human. For programmatic use cases, instead generate an [`x25519::Identity`].
///
/// [`x25519::Identity`]: crate::x25519::Identity
pub struct Recipient {
    passphrase: SecretString,
    log_n: u8,
}

impl Recipient {
    /// Constructs a new `Recipient` with the given passphrase.
    ///
    /// The scrypt work factor is picked to target about 1 second for encryption or
    /// decryption on this device. Override it with [`Self::set_work_factor`].
    pub fn new(passphrase: SecretString) -> Self {
        Self {
            passphrase,
            log_n: target_scrypt_work_factor(),
        }
    }

    /// Sets the scrypt work factor to `N = 2^log_n`.
    ///
    /// This method must be called before [`Self::wrap_file_key`] to have an effect.
    ///
    /// [`Self::wrap_file_key`]: crate::Recipient::wrap_file_key
    ///
    /// # Panics
    ///
    /// Panics if `log_n == 0` or `log_n >= 64`.
    pub fn set_work_factor(&mut self, log_n: u8) {
        assert!(0 < log_n && log_n < 64);
        self.log_n = log_n;
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut rng = OsRng;

        let mut salt = [0; SALT_LEN];
        rng.fill_bytes(&mut salt);

        let mut inner_salt = [0; SCRYPT_SALT_LABEL.len() + SALT_LEN];
        inner_salt[..SCRYPT_SALT_LABEL.len()].copy_from_slice(SCRYPT_SALT_LABEL);
        inner_salt[SCRYPT_SALT_LABEL.len()..].copy_from_slice(&salt);

        let enc_key =
            scrypt(&inner_salt, self.log_n, self.passphrase.expose_secret()).expect("log_n < 64");
        let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

        let encoded_salt = BASE64_STANDARD_NO_PAD.encode(salt);

        let label = Alphanumeric.sample_string(&mut rng, 32);

        Ok((
            vec![Stanza {
                tag: SCRYPT_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_salt, format!("{}", self.log_n)],
                body: encrypted_file_key,
            }],
            iter::once(label).collect(),
        ))
    }
}

/// A passphrase-based identity. Anyone with the passphrase can decrypt the file.
///
/// The identity caps the amount of work that the [`Decryptor`] might have to do to
/// process received files. A fairly high default is used (targeting roughly 16 seconds of
/// work per stanza on the current machine), which might not be suitable for systems
/// processing untrusted files.
///
/// [`Decryptor`]: crate::Decryptor
pub struct Identity {
    passphrase: SecretString,
    target_work_factor: u8,
    max_work_factor: u8,
}

impl Identity {
    /// Constructs a new `Identity` with the given passphrase.
    pub fn new(passphrase: SecretString) -> Self {
        let target_work_factor = target_scrypt_work_factor();

        // Place bounds on the work factor we will accept (roughly 16 seconds).
        let max_work_factor = target_work_factor + 4;

        Self {
            passphrase,
            target_work_factor,
            max_work_factor,
        }
    }

    /// Sets the maximum accepted scrypt work factor to `N = 2^max_log_n`.
    ///
    /// This method must be called before [`Self::unwrap_stanza`] to have an effect.
    ///
    /// [`Self::unwrap_stanza`]: crate::Identity::unwrap_stanza
    pub fn set_max_work_factor(&mut self, max_log_n: u8) {
        self.max_work_factor = max_log_n;
    }
}

impl crate::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != SCRYPT_RECIPIENT_TAG {
            return None;
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#scrypt-recipient-stanza
        let (salt, log_n) = match &stanza.args[..] {
            [salt, log_n] => match (
                base64_arg::<_, SALT_LEN, 18>(salt),
                decimal_digit_arg(log_n),
            ) {
                (Some(salt), Some(log_n)) => (salt, log_n),
                _ => return Some(Err(DecryptError::InvalidHeader)),
            },
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        if log_n > self.max_work_factor {
            return Some(Err(DecryptError::ExcessiveWork {
                required: log_n,
                target: self.target_work_factor,
            }));
        }

        let mut inner_salt = [0; SCRYPT_SALT_LABEL.len() + SALT_LEN];
        inner_salt[..SCRYPT_SALT_LABEL.len()].copy_from_slice(SCRYPT_SALT_LABEL);
        inner_salt[SCRYPT_SALT_LABEL.len()..].copy_from_slice(&salt);

        let enc_key = match scrypt(&inner_salt, log_n, self.passphrase.expose_secret()) {
            Ok(k) => k,
            Err(_) => {
                return Some(Err(DecryptError::ExcessiveWork {
                    required: log_n,
                    target: self.target_work_factor,
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
