//! Encryption and decryption routines for age.

use getrandom::getrandom;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime};

use crate::{
    format::{Header, RecipientLine},
    keys::{RecipientKey, SecretKey},
    primitives::{aead_decrypt, aead_encrypt, hkdf, scrypt, Stream},
};

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

const ONE_SECOND: Duration = Duration::from_secs(1);

/// Pick an scrypt work factor that will take around 1 second on this device.
fn target_scrypt_work_factor() -> u8 {
    // Time a work factor that should always be fast.
    let mut log_n = 10;

    let start = SystemTime::now();
    scrypt(&[], log_n, "").unwrap();
    let duration = SystemTime::now().duration_since(start);

    duration
        .map(|mut d| {
            // Use duration as a proxy for CPU usage, which scales linearly with N.
            while d < ONE_SECOND {
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
    Passphrase(String),
}

impl Encryptor {
    fn wrap(&self, file_key: &[u8; 16]) -> Vec<RecipientLine> {
        match self {
            Encryptor::Keys(recipients) => {
                recipients.iter().map(|key| key.wrap(file_key)).collect()
            }
            Encryptor::Passphrase(passphrase) => {
                let mut salt = [0; 16];
                getrandom(&mut salt).expect("Should not fail");

                let log_n = target_scrypt_work_factor();

                let enc_key = scrypt(&salt, log_n, passphrase).unwrap();
                let encrypted_file_key = aead_encrypt(&enc_key, file_key).unwrap();

                vec![RecipientLine::scrypt(salt, log_n, encrypted_file_key)]
            }
        }
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call `flush()` when you are done writing, in order to finish the
    /// encryption process. Failing to call `flush()` will result in a truncated message
    /// that will fail to decrypt.
    pub fn wrap_output<W: Write>(&self, mut output: W) -> io::Result<impl Write> {
        let mut file_key = [0; 16];
        getrandom(&mut file_key).expect("Should not fail");

        let header = Header::new(self.wrap(&file_key), hkdf(&[], HEADER_KEY_LABEL, &file_key));
        header.write(&mut output)?;

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
    Keys(Vec<SecretKey>),
    /// Decryption with a passphrase.
    Passphrase(String),
}

impl Decryptor {
    fn unwrap(&self, line: &RecipientLine) -> Option<[u8; 16]> {
        match (self, line) {
            (Decryptor::Keys(keys), _) => keys.iter().find_map(|key| key.unwrap(line)),
            (Decryptor::Passphrase(passphrase), RecipientLine::Scrypt(s)) => {
                // Place bounds on the work factor we will accept (roughly 16 seconds).
                if s.log_n > (target_scrypt_work_factor() + 4) {
                    return None;
                }

                let enc_key = scrypt(&s.salt, s.log_n, &passphrase).unwrap();
                aead_decrypt(&enc_key, &s.encrypted_file_key).map(|pt| {
                    // It's ours!
                    let mut file_key = [0; 16];
                    file_key.copy_from_slice(&pt);
                    file_key
                })
            }
            _ => None,
        }
    }

    /// Attempts to decrypt a message from the given reader.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn trial_decrypt<R: Read>(&self, mut input: R) -> Result<impl Read, &'static str> {
        let header = Header::read(&mut input).map_err(|_| "failed to read header")?;

        let mut nonce = [0; 16];
        input
            .read_exact(&mut nonce)
            .map_err(|_| "failed to read nonce")?;

        header
            .recipients
            .iter()
            .find_map(|r| {
                self.unwrap(r).and_then(|file_key| {
                    // Verify the MAC
                    header.verify_mac(hkdf(&[], HEADER_KEY_LABEL, &file_key))?;

                    // Return the payload key
                    Some(hkdf(&nonce, PAYLOAD_KEY_LABEL, &file_key))
                })
            })
            .map(|payload_key| Stream::decrypt(&payload_key, input))
            .ok_or("no matching keys")
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    use super::Decryptor;
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

        let buf = BufReader::new(test_key.as_bytes());
        let d = Decryptor::Keys(SecretKey::from_data(buf).unwrap());
        let mut r1 = d.trial_decrypt(&test_msg_1[..]).unwrap();
        let mut r2 = d.trial_decrypt(&test_msg_2[..]).unwrap();

        let mut msg1 = String::new();
        r1.read_to_string(&mut msg1).unwrap();
        assert_eq!(msg1, "hello Rust from Go! \\o/\n");

        let mut msg2 = String::new();
        r2.read_to_string(&mut msg2).unwrap();
        assert_eq!(msg2, "*hyped crab noises*\n");
    }
}
