use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    str::FromStr,
};

use age::{
    armor::{ArmoredReadError, ArmoredReader},
    secrecy::SecretString,
    x25519, DecryptError, Decryptor, Identity,
};
use futures::AsyncReadExt;
use sha2::{Digest, Sha256};
use test_case::test_case;

#[test_case("armor")]
#[test_case("armor_crlf")]
#[test_case("armor_empty_line_begin")]
#[test_case("armor_empty_line_end")]
#[test_case("armor_eol_between_padding")]
#[test_case("armor_full_last_line")]
#[test_case("armor_garbage_encoded")]
#[test_case("armor_garbage_leading")]
#[test_case("armor_garbage_trailing")]
#[test_case("armor_header_crlf")]
#[test_case("armor_headers")]
#[test_case("armor_invalid_character_header")]
#[test_case("armor_invalid_character_payload")]
#[test_case("armor_long_line")]
#[test_case("armor_lowercase")]
#[test_case("armor_no_end_line")]
#[test_case("armor_no_eol")]
#[test_case("armor_no_match")]
#[test_case("armor_no_padding")]
#[test_case("armor_not_canonical")]
#[test_case("armor_pgp_checksum")]
#[test_case("armor_short_line")]
#[test_case("armor_whitespace_begin")]
#[test_case("armor_whitespace_end")]
#[test_case("armor_whitespace_eol")]
#[test_case("armor_whitespace_last_line")]
#[test_case("armor_whitespace_line_start")]
#[test_case("armor_whitespace_outside")]
#[test_case("armor_wrong_type")]
#[test_case("header_crlf")]
#[test_case("hmac_bad")]
#[test_case("hmac_extra_space")]
#[test_case("hmac_garbage")]
#[test_case("hmac_missing")]
#[test_case("hmac_no_space")]
#[test_case("hmac_not_canonical")]
#[test_case("hmac_trailing_space")]
#[test_case("hmac_truncated")]
#[test_case("scrypt")]
#[test_case("scrypt_and_x25519")]
#[test_case("scrypt_bad_tag")]
#[test_case("scrypt_double")]
#[test_case("scrypt_extra_argument")]
#[test_case("scrypt_long_file_key")]
#[test_case("scrypt_no_match")]
#[test_case("scrypt_not_canonical_body")]
#[test_case("scrypt_not_canonical_salt")]
#[test_case("scrypt_salt_long")]
#[test_case("scrypt_salt_missing")]
#[test_case("scrypt_salt_short")]
#[test_case("scrypt_uppercase")]
#[test_case("scrypt_work_factor_23")]
#[test_case("scrypt_work_factor_hex")]
#[test_case("scrypt_work_factor_leading_garbage")]
#[test_case("scrypt_work_factor_leading_plus")]
#[test_case("scrypt_work_factor_leading_zero_decimal")]
#[test_case("scrypt_work_factor_leading_zero_octal")]
#[test_case("scrypt_work_factor_missing")]
#[test_case("scrypt_work_factor_negative")]
#[test_case("scrypt_work_factor_overflow")]
#[test_case("scrypt_work_factor_trailing_garbage")]
#[test_case("scrypt_work_factor_wrong")]
#[test_case("scrypt_work_factor_zero")]
#[test_case("stanza_bad_start")]
#[test_case("stanza_base64_padding")]
#[test_case("stanza_empty_argument")]
#[test_case("stanza_empty_body")]
#[test_case("stanza_empty_last_line")]
#[test_case("stanza_invalid_character")]
#[test_case("stanza_long_line")]
#[test_case("stanza_missing_body")]
#[test_case("stanza_missing_final_line")]
#[test_case("stanza_multiple_short_lines")]
#[test_case("stanza_no_arguments")]
#[test_case("stanza_not_canonical")]
#[test_case("stanza_spurious_cr")]
#[test_case("stanza_valid_characters")]
#[test_case("stream_bad_tag")]
#[test_case("stream_bad_tag_second_chunk")]
#[test_case("stream_bad_tag_second_chunk_full")]
#[test_case("stream_empty_payload")]
#[test_case("stream_last_chunk_empty")]
#[test_case("stream_last_chunk_full")]
#[test_case("stream_last_chunk_full_second")]
#[test_case("stream_missing_tag")]
#[test_case("stream_no_chunks")]
#[test_case("stream_no_final")]
#[test_case("stream_no_final_full")]
#[test_case("stream_no_final_two_chunks")]
#[test_case("stream_no_final_two_chunks_full")]
#[test_case("stream_no_nonce")]
#[test_case("stream_short_chunk")]
#[test_case("stream_short_nonce")]
#[test_case("stream_short_second_chunk")]
#[test_case("stream_three_chunks")]
#[test_case("stream_trailing_garbage_long")]
#[test_case("stream_trailing_garbage_short")]
#[test_case("stream_two_chunks")]
#[test_case("stream_two_final_chunks")]
#[test_case("version_unsupported")]
#[test_case("x25519")]
#[test_case("x25519_bad_tag")]
#[test_case("x25519_extra_argument")]
#[test_case("x25519_grease")]
#[test_case("x25519_identity")]
#[test_case("x25519_long_file_key")]
#[test_case("x25519_long_share")]
#[test_case("x25519_lowercase")]
#[test_case("x25519_low_order")]
#[test_case("x25519_multiple_recipients")]
#[test_case("x25519_no_match")]
#[test_case("x25519_not_canonical_body")]
#[test_case("x25519_not_canonical_share")]
#[test_case("x25519_short_share")]
fn testkit(filename: &str) {
    let testfile = TestFile::parse(filename);
    let comment = format_testkit_comment(&testfile);

    match Decryptor::new(ArmoredReader::new(&testfile.age_file[..])).and_then(|d| match d {
        Decryptor::Recipients(d) => {
            let identities = get_testkit_identities(filename, &testfile);
            d.decrypt(identities.iter().map(|i| i as &dyn Identity))
        }
        Decryptor::Passphrase(d) => {
            let passphrase = get_testkit_passphrase(&testfile, &comment);
            d.decrypt(&passphrase, Some(16))
        }
    }) {
        Ok(mut r) => {
            let mut payload = vec![];
            let res = r.read_to_end(&mut payload);
            check_decrypt_success(filename, testfile, &comment, res, &payload);
        }
        Err(e) => check_decrypt_error(filename, testfile, e),
    }
}

#[test_case("armor")]
#[test_case("armor_crlf")]
#[test_case("armor_empty_line_begin")]
#[test_case("armor_empty_line_end")]
#[test_case("armor_eol_between_padding")]
#[test_case("armor_full_last_line")]
#[test_case("armor_garbage_encoded")]
#[test_case("armor_garbage_leading")]
#[test_case("armor_garbage_trailing")]
#[test_case("armor_header_crlf")]
#[test_case("armor_headers")]
#[test_case("armor_invalid_character_header")]
#[test_case("armor_invalid_character_payload")]
#[test_case("armor_long_line")]
#[test_case("armor_lowercase")]
#[test_case("armor_no_end_line")]
#[test_case("armor_no_eol")]
#[test_case("armor_no_match")]
#[test_case("armor_no_padding")]
#[test_case("armor_not_canonical")]
#[test_case("armor_pgp_checksum")]
#[test_case("armor_short_line")]
#[test_case("armor_whitespace_begin")]
#[test_case("armor_whitespace_end")]
#[test_case("armor_whitespace_eol")]
#[test_case("armor_whitespace_last_line")]
#[test_case("armor_whitespace_line_start")]
#[test_case("armor_whitespace_outside")]
#[test_case("armor_wrong_type")]
#[test_case("header_crlf")]
#[test_case("hmac_bad")]
#[test_case("hmac_extra_space")]
#[test_case("hmac_garbage")]
#[test_case("hmac_missing")]
#[test_case("hmac_no_space")]
#[test_case("hmac_not_canonical")]
#[test_case("hmac_trailing_space")]
#[test_case("hmac_truncated")]
#[test_case("scrypt")]
#[test_case("scrypt_and_x25519")]
#[test_case("scrypt_bad_tag")]
#[test_case("scrypt_double")]
#[test_case("scrypt_extra_argument")]
#[test_case("scrypt_long_file_key")]
#[test_case("scrypt_no_match")]
#[test_case("scrypt_not_canonical_body")]
#[test_case("scrypt_not_canonical_salt")]
#[test_case("scrypt_salt_long")]
#[test_case("scrypt_salt_missing")]
#[test_case("scrypt_salt_short")]
#[test_case("scrypt_uppercase")]
#[test_case("scrypt_work_factor_23")]
#[test_case("scrypt_work_factor_hex")]
#[test_case("scrypt_work_factor_leading_garbage")]
#[test_case("scrypt_work_factor_leading_plus")]
#[test_case("scrypt_work_factor_leading_zero_decimal")]
#[test_case("scrypt_work_factor_leading_zero_octal")]
#[test_case("scrypt_work_factor_missing")]
#[test_case("scrypt_work_factor_negative")]
#[test_case("scrypt_work_factor_overflow")]
#[test_case("scrypt_work_factor_trailing_garbage")]
#[test_case("scrypt_work_factor_wrong")]
#[test_case("scrypt_work_factor_zero")]
#[test_case("stanza_bad_start")]
#[test_case("stanza_base64_padding")]
#[test_case("stanza_empty_argument")]
#[test_case("stanza_empty_body")]
#[test_case("stanza_empty_last_line")]
#[test_case("stanza_invalid_character")]
#[test_case("stanza_long_line")]
#[test_case("stanza_missing_body")]
#[test_case("stanza_missing_final_line")]
#[test_case("stanza_multiple_short_lines")]
#[test_case("stanza_no_arguments")]
#[test_case("stanza_not_canonical")]
#[test_case("stanza_spurious_cr")]
#[test_case("stanza_valid_characters")]
#[test_case("stream_bad_tag")]
#[test_case("stream_bad_tag_second_chunk")]
#[test_case("stream_bad_tag_second_chunk_full")]
#[test_case("stream_empty_payload")]
#[test_case("stream_last_chunk_empty")]
#[test_case("stream_last_chunk_full")]
#[test_case("stream_last_chunk_full_second")]
#[test_case("stream_missing_tag")]
#[test_case("stream_no_chunks")]
#[test_case("stream_no_final")]
#[test_case("stream_no_final_full")]
#[test_case("stream_no_final_two_chunks")]
#[test_case("stream_no_final_two_chunks_full")]
#[test_case("stream_no_nonce")]
#[test_case("stream_short_chunk")]
#[test_case("stream_short_nonce")]
#[test_case("stream_short_second_chunk")]
#[test_case("stream_three_chunks")]
#[test_case("stream_trailing_garbage_long")]
#[test_case("stream_trailing_garbage_short")]
#[test_case("stream_two_chunks")]
#[test_case("stream_two_final_chunks")]
#[test_case("version_unsupported")]
#[test_case("x25519")]
#[test_case("x25519_bad_tag")]
#[test_case("x25519_extra_argument")]
#[test_case("x25519_grease")]
#[test_case("x25519_identity")]
#[test_case("x25519_long_file_key")]
#[test_case("x25519_long_share")]
#[test_case("x25519_lowercase")]
#[test_case("x25519_low_order")]
#[test_case("x25519_multiple_recipients")]
#[test_case("x25519_no_match")]
#[test_case("x25519_not_canonical_body")]
#[test_case("x25519_not_canonical_share")]
#[test_case("x25519_short_share")]
fn testkit_buffered(filename: &str) {
    let testfile = TestFile::parse(filename);
    let comment = format_testkit_comment(&testfile);

    match Decryptor::new_buffered(ArmoredReader::new(&testfile.age_file[..])).and_then(
        |d| match d {
            Decryptor::Recipients(d) => {
                let identities = get_testkit_identities(filename, &testfile);
                d.decrypt(identities.iter().map(|i| i as &dyn Identity))
            }
            Decryptor::Passphrase(d) => {
                let passphrase = get_testkit_passphrase(&testfile, &comment);
                d.decrypt(&passphrase, Some(16))
            }
        },
    ) {
        Ok(mut r) => {
            let mut payload = vec![];
            let res = io::Read::read_to_end(&mut r, &mut payload);
            check_decrypt_success(filename, testfile, &comment, res, &payload);
        }
        Err(e) => check_decrypt_error(filename, testfile, e),
    }
}

#[test_case("armor")]
#[test_case("armor_crlf")]
#[test_case("armor_empty_line_begin")]
#[test_case("armor_empty_line_end")]
#[test_case("armor_eol_between_padding")]
#[test_case("armor_full_last_line")]
#[test_case("armor_garbage_encoded")]
#[test_case("armor_garbage_leading")]
#[test_case("armor_garbage_trailing")]
#[test_case("armor_header_crlf")]
#[test_case("armor_headers")]
#[test_case("armor_invalid_character_header")]
#[test_case("armor_invalid_character_payload")]
#[test_case("armor_long_line")]
#[test_case("armor_lowercase")]
#[test_case("armor_no_end_line")]
#[test_case("armor_no_eol")]
#[test_case("armor_no_match")]
#[test_case("armor_no_padding")]
#[test_case("armor_not_canonical")]
#[test_case("armor_pgp_checksum")]
#[test_case("armor_short_line")]
#[test_case("armor_whitespace_begin")]
#[test_case("armor_whitespace_end")]
#[test_case("armor_whitespace_eol")]
#[test_case("armor_whitespace_last_line")]
#[test_case("armor_whitespace_line_start")]
#[test_case("armor_whitespace_outside")]
#[test_case("armor_wrong_type")]
#[test_case("header_crlf")]
#[test_case("hmac_bad")]
#[test_case("hmac_extra_space")]
#[test_case("hmac_garbage")]
#[test_case("hmac_missing")]
#[test_case("hmac_no_space")]
#[test_case("hmac_not_canonical")]
#[test_case("hmac_trailing_space")]
#[test_case("hmac_truncated")]
#[test_case("scrypt")]
#[test_case("scrypt_and_x25519")]
#[test_case("scrypt_bad_tag")]
#[test_case("scrypt_double")]
#[test_case("scrypt_extra_argument")]
#[test_case("scrypt_long_file_key")]
#[test_case("scrypt_no_match")]
#[test_case("scrypt_not_canonical_body")]
#[test_case("scrypt_not_canonical_salt")]
#[test_case("scrypt_salt_long")]
#[test_case("scrypt_salt_missing")]
#[test_case("scrypt_salt_short")]
#[test_case("scrypt_uppercase")]
#[test_case("scrypt_work_factor_23")]
#[test_case("scrypt_work_factor_hex")]
#[test_case("scrypt_work_factor_leading_garbage")]
#[test_case("scrypt_work_factor_leading_plus")]
#[test_case("scrypt_work_factor_leading_zero_decimal")]
#[test_case("scrypt_work_factor_leading_zero_octal")]
#[test_case("scrypt_work_factor_missing")]
#[test_case("scrypt_work_factor_negative")]
#[test_case("scrypt_work_factor_overflow")]
#[test_case("scrypt_work_factor_trailing_garbage")]
#[test_case("scrypt_work_factor_wrong")]
#[test_case("scrypt_work_factor_zero")]
#[test_case("stanza_bad_start")]
#[test_case("stanza_base64_padding")]
#[test_case("stanza_empty_argument")]
#[test_case("stanza_empty_body")]
#[test_case("stanza_empty_last_line")]
#[test_case("stanza_invalid_character")]
#[test_case("stanza_long_line")]
#[test_case("stanza_missing_body")]
#[test_case("stanza_missing_final_line")]
#[test_case("stanza_multiple_short_lines")]
#[test_case("stanza_no_arguments")]
#[test_case("stanza_not_canonical")]
#[test_case("stanza_spurious_cr")]
#[test_case("stanza_valid_characters")]
#[test_case("stream_bad_tag")]
#[test_case("stream_bad_tag_second_chunk")]
#[test_case("stream_bad_tag_second_chunk_full")]
#[test_case("stream_empty_payload")]
#[test_case("stream_last_chunk_empty")]
#[test_case("stream_last_chunk_full")]
#[test_case("stream_last_chunk_full_second")]
#[test_case("stream_missing_tag")]
#[test_case("stream_no_chunks")]
#[test_case("stream_no_final")]
#[test_case("stream_no_final_full")]
#[test_case("stream_no_final_two_chunks")]
#[test_case("stream_no_final_two_chunks_full")]
#[test_case("stream_no_nonce")]
#[test_case("stream_short_chunk")]
#[test_case("stream_short_nonce")]
#[test_case("stream_short_second_chunk")]
#[test_case("stream_three_chunks")]
#[test_case("stream_trailing_garbage_long")]
#[test_case("stream_trailing_garbage_short")]
#[test_case("stream_two_chunks")]
#[test_case("stream_two_final_chunks")]
#[test_case("version_unsupported")]
#[test_case("x25519")]
#[test_case("x25519_bad_tag")]
#[test_case("x25519_extra_argument")]
#[test_case("x25519_grease")]
#[test_case("x25519_identity")]
#[test_case("x25519_long_file_key")]
#[test_case("x25519_long_share")]
#[test_case("x25519_lowercase")]
#[test_case("x25519_low_order")]
#[test_case("x25519_multiple_recipients")]
#[test_case("x25519_no_match")]
#[test_case("x25519_not_canonical_body")]
#[test_case("x25519_not_canonical_share")]
#[test_case("x25519_short_share")]
#[tokio::test]
async fn testkit_async(filename: &str) {
    let testfile = TestFile::parse(filename);
    let comment = format_testkit_comment(&testfile);

    match Decryptor::new_async(ArmoredReader::from_async_reader(&testfile.age_file[..]))
        .await
        .and_then(|d| match d {
            Decryptor::Recipients(d) => {
                let identities = get_testkit_identities(filename, &testfile);
                d.decrypt_async(identities.iter().map(|i| i as &dyn Identity))
            }
            Decryptor::Passphrase(d) => {
                let passphrase = get_testkit_passphrase(&testfile, &comment);
                d.decrypt_async(&passphrase, Some(16))
            }
        }) {
        Ok(mut r) => {
            let mut payload = vec![];
            let res = r.read_to_end(&mut payload).await;
            check_decrypt_success(filename, testfile, &comment, res, &payload);
        }
        Err(e) => check_decrypt_error(filename, testfile, e),
    }
}

fn format_testkit_comment(testfile: &TestFile) -> String {
    testfile
        .comment
        .as_ref()
        .map(|c| format!(" ({})", c))
        .unwrap_or_default()
}

fn get_testkit_identities(filename: &str, testfile: &TestFile) -> Vec<x25519::Identity> {
    assert_eq!(
        testfile.passphrases.len(),
        // `scrypt_uppercase` uses the stanza tag `Scrypt` instead of `scrypt`, so
        // even though there is a valid passphrase, the decryptor treats it as a
        // different recipient stanza kind.
        if filename == "scrypt_uppercase" { 1 } else { 0 }
    );
    testfile
        .identities
        .iter()
        .map(|s| s.as_str())
        .map(x25519::Identity::from_str)
        .collect::<Result<_, _>>()
        .unwrap()
}

fn get_testkit_passphrase(testfile: &TestFile, comment: &str) -> SecretString {
    assert_eq!(testfile.identities.len(), 0);
    match testfile.passphrases.len() {
        0 => panic!("Test file is missing passphrase{}", comment),
        1 => testfile.passphrases.get(0).cloned().unwrap().into(),
        n => panic!("Too many passphrases ({}){}", n, comment),
    }
}

fn check_decrypt_success(
    filename: &str,
    testfile: TestFile,
    comment: &str,
    res: io::Result<usize>,
    payload: &[u8],
) {
    match (res, testfile.expect) {
        (Ok(_), Expect::Success { payload_sha256 }) => {
            assert_eq!(Sha256::digest(&payload)[..], payload_sha256);
        }
        // These testfile failures are expected, because we maintains support for
        // parsing legacy age stanzas without an explicit short final line.
        (Ok(_), Expect::HeaderFailure)
            if ["stanza_missing_body", "stanza_missing_final_line"].contains(&filename) => {}
        (Err(e), Expect::ArmorFailure) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                e.into_inner().map(|inner| inner.is::<ArmoredReadError>()),
                Some(true)
            );
        }
        (Err(e), Expect::PayloadFailure { payload_sha256 }) => {
            assert_eq!(
                e.kind(),
                if [
                    "stream_no_chunks",
                    "stream_no_final_full",
                    "stream_no_final_two_chunks_full",
                ]
                .contains(&filename)
                {
                    io::ErrorKind::UnexpectedEof
                } else {
                    io::ErrorKind::InvalidData
                }
            );
            // The tests with this expectation are checking that no partial STREAM
            // blocks are written to the payload.
            assert_eq!(Sha256::digest(&payload)[..], payload_sha256);
        }
        (actual, expected) => panic!(
            "Expected {:?}, got {}{}",
            expected,
            if actual.is_ok() {
                format!("payload '{}'", String::from_utf8_lossy(payload))
            } else {
                format!("{:?}", actual)
            },
            comment,
        ),
    }
}

fn check_decrypt_error(filename: &str, testfile: TestFile, e: DecryptError) {
    match e {
        DecryptError::InvalidHeader => {
            // `ArmoredReader` is a transparent wrapper around an `io::Read` and
            // only runs de-armoring if it detects the expected begin marker.
            // This leaves a hole in error detection: if the begin marker is invalid,
            // then the test case will be rejected by the inner age header parsing
            // with `DecryptError::InvalidHeader`. However, we can't simply treat
            // these as "armor failed" because there are test cases where the armor is
            // valid but the contained age file is invalid. We hard-code the list of
            // test cases with invalid begin markers to cover this hole.
            if testfile.armored
                && [
                    "armor_garbage_leading",
                    "armor_lowercase",
                    "armor_whitespace_begin",
                    "armor_wrong_type",
                ]
                .contains(&filename)
            {
                assert_eq!(testfile.expect, Expect::ArmorFailure);
            } else if testfile.armored && ["armor_whitespace_outside"].contains(&filename) {
                // This decryption error is expected, because we do not support parsing
                // armored files with leading whitespace (due to how we detect armoring).
            } else {
                assert_eq!(testfile.expect, Expect::HeaderFailure);
            }
        }
        DecryptError::Io(e) => {
            let kind = e.kind();
            if e.into_inner().map(|inner| inner.is::<ArmoredReadError>()) == Some(true) {
                assert_eq!(kind, io::ErrorKind::InvalidData);
                assert_eq!(testfile.expect, Expect::ArmorFailure);
            } else {
                assert_eq!(testfile.expect, Expect::HeaderFailure);
            }
        }
        DecryptError::ExcessiveWork { .. } | DecryptError::UnknownFormat => {
            assert_eq!(testfile.expect, Expect::HeaderFailure)
        }
        DecryptError::InvalidMac => assert_eq!(testfile.expect, Expect::HmacFailure),
        DecryptError::DecryptionFailed | DecryptError::NoMatchingKeys => {
            assert_eq!(testfile.expect, Expect::NoMatch)
        }
        DecryptError::KeyDecryptionFailed => todo!(),
        #[cfg(feature = "plugin")]
        DecryptError::MissingPlugin { .. } => todo!(),
        #[cfg(feature = "plugin")]
        DecryptError::Plugin(_) => todo!(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Success { payload_sha256: [u8; 32] },
    ArmorFailure,
    HeaderFailure,
    HmacFailure,
    NoMatch,
    PayloadFailure { payload_sha256: [u8; 32] },
}

struct TestFile {
    expect: Expect,
    identities: Vec<String>,
    passphrases: Vec<String>,
    armored: bool,
    comment: Option<String>,
    age_file: Vec<u8>,
}

impl TestFile {
    fn parse(filename: &str) -> Self {
        let file = File::open(format!("./tests/testdata/testkit/{}", filename)).unwrap();
        let mut r = BufReader::new(file);
        let mut line = String::new();

        fn data<'l>(line: &'l str, prefix: &str) -> &'l str {
            line.strip_prefix(prefix).unwrap().trim()
        }

        let expect = {
            r.read_line(&mut line).unwrap();
            match data(&line, "expect:") {
                "success" => {
                    line.clear();
                    r.read_line(&mut line).unwrap();
                    let payload = data(&line, "payload:");
                    Expect::Success {
                        payload_sha256: hex::decode(payload).unwrap().try_into().unwrap(),
                    }
                }
                "armor failure" => Expect::ArmorFailure,
                "header failure" => Expect::HeaderFailure,
                "payload failure" => {
                    line.clear();
                    r.read_line(&mut line).unwrap();
                    let payload = data(&line, "payload:");
                    Expect::PayloadFailure {
                        payload_sha256: hex::decode(payload).unwrap().try_into().unwrap(),
                    }
                }
                "HMAC failure" => Expect::HmacFailure,
                "no match" => Expect::NoMatch,
                e => panic!("Unknown testkit failure '{}'", e),
            }
        };

        let _file_key = {
            line.clear();
            r.read_line(&mut line).unwrap();
            hex::decode(data(&line, "file key: ")).unwrap()
        };

        let mut identities = vec![];
        let mut passphrases = vec![];
        let mut armored = false;
        let mut comment = None;
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }

            let (prefix, data) = line.trim().split_once(": ").unwrap();
            match prefix {
                "identity" => identities.push(data.to_owned()),
                "passphrase" => passphrases.push(data.to_owned()),
                "armored" => armored = data == "yes",
                "comment" => comment = Some(data.to_owned()),
                _ => panic!("Unknown testkit metadata '{}'", prefix),
            }
        }

        let mut age_file = vec![];
        r.read_to_end(&mut age_file).unwrap();

        Self {
            expect,
            identities,
            passphrases,
            armored,
            comment,
            age_file,
        }
    }
}
