//! The "encrypted age identity file" identity type.

use std::{cell::Cell, io};

use crate::{fl, scrypt, Callbacks, DecryptError, Decryptor, EncryptError, IdentityFile};

/// The state of the encrypted age identity.
enum IdentityState<R: io::Read, C: Callbacks> {
    Encrypted {
        decryptor: Decryptor<R>,
        max_work_factor: Option<u8>,
        callbacks: C,
    },
    Decrypted(IdentityFile<C>),

    /// The file was not correctly encrypted, or did not contain age identities. We cache
    /// this error in case the caller tries to use this identity again. The `Option` is to
    /// enable implementing `Default` so we can use `Cell::take`, but we don't ever allow
    /// the `None` case to persist.
    Poisoned(Option<DecryptError>),
}

impl<R: io::Read, C: Callbacks> Default for IdentityState<R, C> {
    fn default() -> Self {
        Self::Poisoned(None)
    }
}

impl<R: io::Read, C: Callbacks> IdentityState<R, C> {
    /// Decrypts this encrypted identity if necessary.
    ///
    /// Returns the (possibly cached) identities, and a boolean marking if the identities
    /// were not cached (and we just asked the user for a passphrase).
    fn decrypt(self, filename: Option<&str>) -> Result<(IdentityFile<C>, bool), DecryptError> {
        match self {
            Self::Encrypted {
                decryptor,
                max_work_factor,
                callbacks,
            } => {
                let passphrase = match callbacks.request_passphrase(&fl!(
                    "encrypted-passphrase-prompt",
                    filename = filename.unwrap_or_default()
                )) {
                    Some(passphrase) => passphrase,
                    None => todo!(),
                };

                let mut identity = scrypt::Identity::new(passphrase);
                if let Some(max_work_factor) = max_work_factor {
                    identity.set_max_work_factor(max_work_factor);
                }

                decryptor
                    .decrypt(Some(&identity as _).into_iter())
                    .map_err(|e| {
                        if matches!(e, DecryptError::DecryptionFailed) {
                            DecryptError::KeyDecryptionFailed
                        } else {
                            e
                        }
                    })
                    .and_then(|stream| {
                        let file = IdentityFile::from_buffer(io::BufReader::new(stream))?
                            .with_callbacks(callbacks);
                        Ok((file, true))
                    })
            }
            Self::Decrypted(identity_file) => Ok((identity_file, false)),
            // `IdentityState::decrypt` is only ever called with `Some`.
            Self::Poisoned(e) => Err(e.unwrap()),
        }
    }
}

/// An encrypted age identity file.
pub struct Identity<R: io::Read, C: Callbacks> {
    state: Cell<IdentityState<R, C>>,
    filename: Option<String>,
}

impl<R: io::Read, C: Callbacks> Identity<R, C> {
    /// Parses an encrypted identity from an input containing valid UTF-8.
    ///
    /// `filename` is the path to the file that the input is reading from, if any.
    ///
    /// Returns `Ok(None)` if the input contains an age ciphertext that is not encrypted
    /// to a passphrase.
    pub fn from_buffer(
        data: R,
        filename: Option<String>,
        callbacks: C,
        max_work_factor: Option<u8>,
    ) -> Result<Option<Self>, DecryptError> {
        let decryptor = Decryptor::new(data)?;
        Ok(decryptor.is_scrypt().then_some(Identity {
            state: Cell::new(IdentityState::Encrypted {
                decryptor,
                max_work_factor,
                callbacks,
            }),
            filename,
        }))
    }

    /// Returns the recipients contained within this encrypted identity.
    ///
    /// If this encrypted identity has not been decrypted yet, calling this method will
    /// trigger a passphrase request.
    pub fn recipients(&self) -> Result<Vec<Box<dyn crate::Recipient + Send>>, EncryptError> {
        match self.state.take().decrypt(self.filename.as_deref()) {
            Ok((identity_file, _)) => {
                let recipients = identity_file.to_recipients();
                self.state.set(IdentityState::Decrypted(identity_file));
                recipients
            }
            Err(e) => {
                self.state.set(IdentityState::Poisoned(Some(e.clone())));
                Err(EncryptError::EncryptedIdentities(e))
            }
        }
    }

    /// Attempts to unwrap stanzas with the identities contained within this encrypted
    /// identity.
    ///
    /// We don't want to ask the user for the passphrase on every stanza decryption, and
    /// we don't want to store the entire encrypted age identity file in memory. Instead,
    /// the first time that an encrypted identity is decrypted with, we ask the caller for
    /// the passphrase, and perform validity checks on the decrypted data. We then cache
    /// the decrypted identities for subsequent calls.
    ///
    /// Because the `age::Identity` trait requires immutable references, this means that
    /// we need to use interior mutability here.
    fn unwrap_stanzas_base<F>(
        &self,
        filter: F,
    ) -> Option<Result<age_core::format::FileKey, DecryptError>>
    where
        F: Fn(
            Result<Box<dyn crate::Identity>, DecryptError>,
        ) -> Option<Result<age_core::format::FileKey, DecryptError>>,
    {
        match self.state.take().decrypt(self.filename.as_deref()) {
            Ok((identity_file, requested_passphrase)) => {
                let result = identity_file.to_identities().find_map(filter);

                // If we requested a passphrase to decrypt, and none of the identities
                // matched, warn the user.
                if requested_passphrase && result.is_none() {
                    identity_file.callbacks.display_message(&fl!(
                        "encrypted-warn-no-match",
                        filename = self.filename.as_deref().unwrap_or_default()
                    ));
                }

                self.state.set(IdentityState::Decrypted(identity_file));
                result
            }
            Err(e) => {
                self.state.set(IdentityState::Poisoned(Some(e.clone())));
                Some(Err(e))
            }
        }
    }
}

impl<R: io::Read, C: Callbacks> crate::Identity for Identity<R, C> {
    fn unwrap_stanza(
        &self,
        stanza: &age_core::format::Stanza,
    ) -> Option<Result<age_core::format::FileKey, DecryptError>> {
        self.unwrap_stanzas_base(|identity| match identity {
            Ok(i) => i.unwrap_stanza(stanza),
            Err(e) => Some(Err(e)),
        })
    }

    fn unwrap_stanzas(
        &self,
        stanzas: &[age_core::format::Stanza],
    ) -> Option<Result<age_core::format::FileKey, DecryptError>> {
        self.unwrap_stanzas_base(|identity| match identity {
            Ok(i) => i.unwrap_stanzas(stanzas),
            Err(e) => Some(Err(e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use age_core::secrecy::{ExposeSecret, SecretString};

    use super::Identity;
    use crate::{x25519, Callbacks, DecryptError, Identity as _, Recipient as _};

    #[cfg(feature = "armor")]
    use crate::armor::ArmoredReader;

    const TEST_ENCRYPTED_IDENTITY_PASSPHRASE: &str = "foobar";

    const TEST_ENCRYPTED_IDENTITY: &str = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBza2I4R0t6L2NLT2s4cGlI
TTRGRjFRIDEwCnVodTdORmZjcCtjRmdnYU54bm8rZEJ5NWlrVHZLY1hyRzZEN2JE
ZVpwWnMKLS0tIEZTcDlSL3oyRC9NQ3JZa3ZvUzNaNlk4bnhBSUdJRTFrMmE4QzMr
UVNETlkK34fdtpwZz+qQaGuirGHEdodVe4JvnSG3ANQpWhkDcsRzoe/+OuHXNdnv
zhBhaKdthstzGXbd2yJbLrTH1A3YbWO+/3zTIZENzKU9XbibLLQ4M/TXwKMzoObY
oiMf5/+8GiQVREtHmm24wsc/479cVwnGVTdH7DL+wANmyf6S9Vc2FYQmXjLDxsJ0
LMF6Cpgcg09C2gg4pcb4TFUWmDuxnZrfggrptOtyzC8O8aRuKPZqCGnzoWNOWl86
fOrxrKTj7xCdNS3+OrCdnBC8Z9cKDxjCGWW3fkjLsYha0Jo=
-----END AGE ENCRYPTED FILE-----
";

    const TEST_RECIPIENT: &str = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe";

    #[derive(Clone)]
    struct MockCallbacks(Arc<Mutex<Option<&'static str>>>);

    impl MockCallbacks {
        fn new(passphrase: &'static str) -> Self {
            MockCallbacks(Arc::new(Mutex::new(Some(passphrase))))
        }
    }

    impl Callbacks for MockCallbacks {
        fn display_message(&self, _: &str) {
            unimplemented!()
        }

        fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
            unimplemented!()
        }

        fn request_public_string(&self, _: &str) -> Option<String> {
            unimplemented!()
        }

        /// This intentionally panics if called twice.
        fn request_passphrase(&self, _: &str) -> Option<SecretString> {
            Some(SecretString::new(
                self.0.lock().unwrap().take().unwrap().to_owned(),
            ))
        }
    }

    #[test]
    #[cfg(feature = "armor")]
    fn round_trip() {
        let pk: x25519::Recipient = TEST_RECIPIENT.parse().unwrap();
        let file_key = [12; 16].into();
        let (wrapped, labels) = pk.wrap_file_key(&file_key).unwrap();
        assert!(labels.is_empty());

        // Unwrapping with the wrong passphrase fails.
        {
            let buf = ArmoredReader::new(TEST_ENCRYPTED_IDENTITY.as_bytes());
            let identity =
                Identity::from_buffer(buf, None, MockCallbacks::new("wrong passphrase"), None)
                    .unwrap()
                    .unwrap();

            if let Err(e) = identity.unwrap_stanzas(&wrapped).unwrap() {
                assert!(matches!(e, DecryptError::KeyDecryptionFailed));
            } else {
                panic!("Should have failed");
            }
        }

        let buf = ArmoredReader::new(TEST_ENCRYPTED_IDENTITY.as_bytes());
        let identity = Identity::from_buffer(
            buf,
            None,
            MockCallbacks::new(TEST_ENCRYPTED_IDENTITY_PASSPHRASE),
            None,
        )
        .unwrap()
        .unwrap();
        let unwrapped = identity.unwrap_stanzas(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().expose_secret(),
            file_key.expose_secret()
        );

        // Unwrapping a second time doesn't re-decrypt.
        identity.unwrap_stanzas(&wrapped);
    }
}
