use std::io::{Read, Write};
use std::iter;

use crate::{
    error::{DecryptError, EncryptError},
    Decryptor, Encryptor, Identity, Recipient,
};

#[cfg(feature = "armor")]
use crate::armor::{ArmoredReader, ArmoredWriter, Format};

/// Encrypts the given plaintext to the given recipient.
///
/// To encrypt to more than one recipient, use [`Encryptor::with_recipients`].
///
/// This function returns binary ciphertext. To obtain an ASCII-armored text string, use
/// [`encrypt_and_armor`].
pub fn encrypt(recipient: &impl Recipient, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let encryptor =
        Encryptor::with_recipients(iter::once(recipient as _)).expect("we provided a recipient");

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(plaintext)?;
    writer.finish()?;

    Ok(ciphertext)
}

/// Encrypts the given plaintext to the given recipient, and wraps the ciphertext in ASCII
/// armor.
///
/// To encrypt to more than one recipient, use [`Encryptor::with_recipients`] along with
/// [`ArmoredWriter`].
#[cfg(feature = "armor")]
#[cfg_attr(docsrs, doc(cfg(feature = "armor")))]
pub fn encrypt_and_armor(
    recipient: &impl Recipient,
    plaintext: &[u8],
) -> Result<String, EncryptError> {
    let encryptor =
        Encryptor::with_recipients(iter::once(recipient as _)).expect("we provided a recipient");

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor.wrap_output(ArmoredWriter::wrap_output(
        &mut ciphertext,
        Format::AsciiArmor,
    )?)?;
    writer.write_all(plaintext)?;
    writer.finish()?.finish()?;

    Ok(String::from_utf8(ciphertext).expect("is armored"))
}

/// Decrypts the given ciphertext with the given identity.
///
/// If the `armor` feature flag is enabled, this will also handle armored age ciphertexts.
///
/// To attempt decryption with more than one identity, use [`Decryptor`] (as well as
/// [`ArmoredReader`] if the `armor` feature flag is enabled).
pub fn decrypt(identity: &impl Identity, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    #[cfg(feature = "armor")]
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(ciphertext))?;

    #[cfg(not(feature = "armor"))]
    let decryptor = Decryptor::new_buffered(ciphertext)?;

    let mut plaintext = vec![];
    let mut reader = decryptor.decrypt(iter::once(identity as _))?;
    reader.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use crate::x25519;

    #[cfg(feature = "armor")]
    use super::encrypt_and_armor;

    #[test]
    fn x25519_round_trip() {
        let sk: x25519::Identity = crate::x25519::tests::TEST_SK.parse().unwrap();
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        let test_msg = b"This is a test message. For testing.";

        let encrypted = encrypt(&pk, test_msg).unwrap();
        let decrypted = decrypt(&sk, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "armor")]
    #[test]
    fn x25519_round_trip_armor() {
        let sk: x25519::Identity = crate::x25519::tests::TEST_SK.parse().unwrap();
        let pk: x25519::Recipient = crate::x25519::tests::TEST_PK.parse().unwrap();
        let test_msg = b"This is a test message. For testing.";

        let encrypted = encrypt_and_armor(&pk, test_msg).unwrap();
        assert!(encrypted.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let decrypted = decrypt(&sk, encrypted.as_bytes()).unwrap();
        assert_eq!(&decrypted[..], &test_msg[..]);
    }
}
