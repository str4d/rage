//! Encryption and decryption routines for age.

use getrandom::getrandom;
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, Read, Seek, Write};
use std::time::{Duration, SystemTime};

use crate::{
    error::Error,
    format::{Header, RecipientLine},
    keys::{Identity, RecipientKey},
    primitives::{
        aead_decrypt, aead_encrypt, hkdf, scrypt,
        stream::{Stream, StreamReader},
    },
    util::{ArmoredReader, ArmoredWriter},
};

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

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

/// Handles the various types of age encryption.
pub enum Encryptor {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<RecipientKey>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

impl Encryptor {
    fn wrap_file_key(&self, file_key: &[u8; 16]) -> Vec<RecipientLine> {
        match self {
            Encryptor::Keys(recipients) => recipients
                .iter()
                .map(|key| key.wrap_file_key(file_key))
                .collect(),
            Encryptor::Passphrase(passphrase) => {
                let mut salt = [0; 16];
                getrandom(&mut salt).expect("Should not fail");

                let log_n = target_scrypt_work_factor();

                let enc_key = scrypt(&salt, log_n, passphrase.expose_secret()).expect("log_n < 64");
                let encrypted_file_key = {
                    let mut key = [0; 32];
                    key.copy_from_slice(&aead_encrypt(&enc_key, file_key));
                    key
                };

                vec![RecipientLine::scrypt(salt, log_n, encrypted_file_key)]
            }
        }
    }

    /// Creates a wrapper around a writer that will encrypt its input, and optionally
    /// ASCII armor the output.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call `flush()` when you are done writing, in order to finish the
    /// encryption process. Failing to call `flush()` will result in a truncated message
    /// that will fail to decrypt.
    pub fn wrap_output<W: Write>(&self, mut output: W, armored: bool) -> io::Result<impl Write> {
        let mut file_key = [0; 16];
        getrandom(&mut file_key).expect("Should not fail");

        let header = Header::new(
            armored,
            self.wrap_file_key(&file_key),
            hkdf(&[], HEADER_KEY_LABEL, &file_key),
        );
        header.write(&mut output)?;

        let mut output = ArmoredWriter::wrap_output(output, armored);

        let mut nonce = [0; 16];
        getrandom(&mut nonce).expect("Should not fail");
        output.write_all(&nonce)?;

        let payload_key = hkdf(&nonce, PAYLOAD_KEY_LABEL, &file_key);
        Ok(Stream::encrypt(&payload_key, output))
    }
}

/// Handles the various types of age decryption.
pub enum Decryptor {
    /// Trial decryption against a list of secret keys.
    Keys(Vec<Identity>),
    /// Decryption with a passphrase.
    Passphrase(SecretString),
}

impl Decryptor {
    fn unwrap_file_key<P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        line: &RecipientLine,
        request_passphrase: P,
    ) -> Result<Option<[u8; 16]>, Error> {
        match (self, line) {
            (Decryptor::Keys(_), RecipientLine::Scrypt(_)) => Err(Error::MessageRequiresPassphrase),
            (Decryptor::Keys(keys), _) => keys
                .iter()
                .find_map(|key| key.unwrap_file_key(line, request_passphrase))
                .transpose(),
            (Decryptor::Passphrase(passphrase), RecipientLine::Scrypt(s)) => {
                // Place bounds on the work factor we will accept (roughly 16 seconds).
                if s.log_n > (target_scrypt_work_factor() + 4) {
                    return Err(Error::ExcessiveWork);
                }

                let enc_key = scrypt(&s.salt, s.log_n, passphrase.expose_secret())
                    .map_err(|_| Error::ExcessiveWork)?;
                aead_decrypt(&enc_key, &s.encrypted_file_key)
                    .map(|pt| {
                        // It's ours!
                        let mut file_key = [0; 16];
                        file_key.copy_from_slice(&pt);
                        Some(file_key)
                    })
                    .map_err(Error::from)
            }
            (Decryptor::Passphrase(_), _) => Err(Error::MessageRequiresKeys),
        }
    }

    /// Attempts to decrypt a message from the given reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn trial_decrypt<R: Read, P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        mut input: R,
        request_passphrase: P,
    ) -> Result<impl Read, Error> {
        let header = Header::read(&mut input)?;

        let mut input = ArmoredReader::from_reader(input, header.armored);

        let mut nonce = [0; 16];
        input.read_exact(&mut nonce)?;

        header
            .recipients
            .iter()
            .find_map(|r| {
                self.unwrap_file_key(r, request_passphrase)
                    .transpose()
                    .map(|res| {
                        res.and_then(|file_key| {
                            // Verify the MAC
                            header.verify_mac(hkdf(&[], HEADER_KEY_LABEL, &file_key))?;

                            // Return the payload key
                            Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, &file_key))
                        })
                    })
            })
            .unwrap_or(Err(Error::NoMatchingKeys))
            .map(|payload_key| Stream::decrypt(&payload_key, input))
    }

    /// Attempts to decrypt a message from the given seekable reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a seekable reader that will provide the plaintext.
    pub fn trial_decrypt_seekable<R: Read + Seek, P: Fn(&str) -> Option<SecretString> + Copy>(
        &self,
        mut input: R,
        request_passphrase: P,
    ) -> Result<StreamReader<R>, Error> {
        let header = Header::read(&mut input)?;
        if header.armored {
            return Err(Error::ArmoredWhenSeeking);
        }

        let mut nonce = [0; 16];
        input.read_exact(&mut nonce)?;

        header
            .recipients
            .iter()
            .find_map(|r| {
                self.unwrap_file_key(r, request_passphrase)
                    .transpose()
                    .map(|res| {
                        res.and_then(|file_key| {
                            // Verify the MAC
                            header.verify_mac(hkdf(&[], HEADER_KEY_LABEL, &file_key))?;

                            // Return the payload key
                            Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, &file_key))
                        })
                    })
            })
            .unwrap_or(Err(Error::NoMatchingKeys))
            .and_then(|payload_key| {
                Stream::decrypt_seekable(&payload_key, input).map_err(Error::from)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read, Write};

    use super::{Decryptor, Encryptor};
    use crate::keys::{Identity, RecipientKey};

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

        let buf = BufReader::new(test_key.as_bytes());
        let d = Decryptor::Keys(Identity::from_buffer(buf).unwrap());
        let mut r1 = d.trial_decrypt(&test_msg_1[..], |_| None).unwrap();
        let mut r2 = d.trial_decrypt(&test_msg_2[..], |_| None).unwrap();

        let mut msg1 = String::new();
        r1.read_to_string(&mut msg1).unwrap();
        assert_eq!(msg1, "hello Rust from Go! \\o/\n");

        let mut msg2 = String::new();
        r2.read_to_string(&mut msg2).unwrap();
        assert_eq!(msg2, "*hyped crab noises*\n");
    }

    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_RSA_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, false).unwrap();
            w.write_all(test_msg).unwrap();
            w.flush().unwrap();
        }

        let d = Decryptor::Keys(sk);
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_ED25519_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, false).unwrap();
            w.write_all(test_msg).unwrap();
            w.flush().unwrap();
        }

        let d = Decryptor::Keys(sk);
        let mut r = d.trial_decrypt(&encrypted[..], |_| None).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }
}
