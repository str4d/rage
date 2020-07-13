use std::fs::File;
use std::io;

use crate::{error::Error, format::RecipientStanza, keys::FileKey, x25519, Identity};

/// A list of identities that has been parsed from some input file.
pub struct IdentityFile {
    /// The name of the identity file, if known.
    filename: Option<String>,
    identities: Vec<x25519::Identity>,
}

impl IdentityFile {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Self> {
        let buf = io::BufReader::new(File::open(filename.clone())?);
        let mut keys = IdentityFile::from_buffer(buf)?;

        // We have context here about the filename.
        keys.filename = Some(filename.clone());

        Ok(keys)
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: io::BufRead>(mut data: R) -> io::Result<Self> {
        let mut buf = String::new();
        loop {
            match read::age_secret_keys(&buf) {
                Ok((_, identities)) => {
                    // Ensure we've found all identities in the file
                    if data.read_line(&mut buf)? == 0 {
                        break Ok(IdentityFile {
                            filename: None,
                            identities,
                        });
                    }
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(_))) => {
                    if data.read_line(&mut buf)? == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "incomplete secret keys in file",
                        ));
                    };
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid secret key file",
                    ));
                }
            }
        }
    }
}

impl Identity for IdentityFile {
    fn unwrap_file_key(&self, stanza: &RecipientStanza) -> Option<Result<FileKey, Error>> {
        self.identities
            .iter()
            .find_map(|identity| identity.unwrap_file_key(stanza))
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::tag,
        character::complete::{line_ending, not_line_ending},
        combinator::{all_consuming, iterator, map, map_parser, rest},
        sequence::{terminated, tuple},
        IResult,
    };

    use crate::x25519;

    fn age_secret_keys_line(input: &str) -> IResult<&str, Option<x25519::Identity>> {
        alt((
            // Skip empty lines
            map(all_consuming(tag("")), |_| None),
            // Skip comments
            map(all_consuming(tuple((tag("#"), rest))), |_| None),
            // All other lines must be valid age secret keys.
            map(all_consuming(x25519::read::age_secret_key), Some),
        ))(input)
    }

    pub(super) fn age_secret_keys(input: &str) -> IResult<&str, Vec<x25519::Identity>> {
        // Parse all lines that have line endings.
        let mut it = iterator(
            input,
            terminated(
                map_parser(not_line_ending, age_secret_keys_line),
                line_ending,
            ),
        );
        let mut keys: Vec<_> = it.filter_map(|x| x).collect();

        it.finish().and_then(|(i, _)| {
            // Handle the last line, which does not have a line ending.
            age_secret_keys_line(i).map(|(i, res)| {
                if let Some(k) = res {
                    keys.push(k);
                }
                (i, keys)
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::IdentityFile;

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn valid_secret_key_encoding(keydata: &str, num_keys: usize) {
        let buf = BufReader::new(keydata.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        assert_eq!(f.identities.len(), num_keys);
        assert_eq!(f.identities[0].to_string().expose_secret(), TEST_SK);
    }

    #[test]
    fn secret_key_encoding() {
        valid_secret_key_encoding(TEST_SK, 1);
    }

    #[test]
    fn secret_key_lf() {
        valid_secret_key_encoding(&format!("{}\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_lf() {
        valid_secret_key_encoding(&format!("{}\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_lf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_lf() {
        valid_secret_key_encoding(&format!("\n\n{}", TEST_SK), 1);
    }

    #[test]
    fn secret_key_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_crlf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\r\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\r\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_crlf() {
        valid_secret_key_encoding(&format!("\r\n\r\n{}", TEST_SK), 1);
    }

    #[test]
    fn incomplete_secret_key_encoding() {
        let buf = BufReader::new(&TEST_SK.as_bytes()[..4]);
        assert!(IdentityFile::from_buffer(buf).is_err());
    }
}
