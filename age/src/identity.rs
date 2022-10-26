use std::fs::File;
use std::io;

use crate::{x25519, Callbacks, DecryptError, EncryptError};

#[cfg(feature = "plugin")]
use crate::plugin;

/// The supported kinds of identities within an [`IdentityFile`].
#[derive(Clone)]
pub enum IdentityFileEntry {
    /// The standard age identity type.
    Native(x25519::Identity),
    /// A plugin-compatible identity.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    Plugin(plugin::Identity),
}

impl IdentityFileEntry {
    #[allow(unused_variables)]
    pub(crate) fn into_identity(
        self,
        callbacks: impl Callbacks,
    ) -> Result<Box<dyn crate::Identity>, DecryptError> {
        match self {
            IdentityFileEntry::Native(i) => Ok(Box::new(i)),
            #[cfg(feature = "plugin")]
            IdentityFileEntry::Plugin(i) => Ok(Box::new(crate::plugin::IdentityPluginV1::new(
                i.plugin(),
                &[i.clone()],
                callbacks,
            )?)),
        }
    }

    #[allow(unused_variables)]
    pub(crate) fn to_recipient(
        &self,
        callbacks: impl Callbacks,
    ) -> Result<Box<dyn crate::Recipient + Send>, EncryptError> {
        match self {
            IdentityFileEntry::Native(i) => Ok(Box::new(i.to_public())),
            #[cfg(feature = "plugin")]
            IdentityFileEntry::Plugin(i) => Ok(Box::new(crate::plugin::RecipientPluginV1::new(
                i.plugin(),
                &[],
                &[i.clone()],
                callbacks,
            )?)),
        }
    }
}

/// A list of identities that has been parsed from some input file.
pub struct IdentityFile {
    identities: Vec<IdentityFileEntry>,
}

impl IdentityFile {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Self> {
        File::open(&filename)
            .map(io::BufReader::new)
            .and_then(|data| IdentityFile::parse_identities(Some(filename), data))
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: io::BufRead>(data: R) -> io::Result<Self> {
        Self::parse_identities(None, data)
    }

    fn parse_identities<R: io::BufRead>(filename: Option<String>, data: R) -> io::Result<Self> {
        let mut identities = vec![];

        for (line_number, line) in data.lines().enumerate() {
            let line = line?;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(identity) = line.parse::<x25519::Identity>() {
                identities.push(IdentityFileEntry::Native(identity));
            } else if let Some(identity) = {
                #[cfg(feature = "plugin")]
                {
                    line.parse::<plugin::Identity>().ok()
                }

                #[cfg(not(feature = "plugin"))]
                None
            } {
                #[cfg(feature = "plugin")]
                {
                    identities.push(IdentityFileEntry::Plugin(identity));
                }

                // Add a binding to provide a type when plugins are disabled.
                #[cfg(not(feature = "plugin"))]
                let _: () = identity;
            } else {
                // Return a line number in place of the line, so we don't leak the file
                // contents in error messages.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    if let Some(filename) = filename {
                        format!(
                            "identity file {} contains non-identity data on line {}",
                            filename,
                            line_number + 1
                        )
                    } else {
                        format!(
                            "identity file contains non-identity data on line {}",
                            line_number + 1
                        )
                    },
                ));
            }
        }

        Ok(IdentityFile { identities })
    }

    /// Returns the identities in this file.
    pub fn into_identities(self) -> Vec<IdentityFileEntry> {
        self.identities
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age_core::secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::{IdentityFile, IdentityFileEntry};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn valid_secret_key_encoding(keydata: &str, num_keys: usize) {
        let buf = BufReader::new(keydata.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        assert_eq!(f.identities.len(), num_keys);
        match &f.identities[0] {
            IdentityFileEntry::Native(identity) => {
                assert_eq!(identity.to_string().expose_secret(), TEST_SK)
            }
            #[cfg(feature = "plugin")]
            IdentityFileEntry::Plugin(_) => panic!(),
        }
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
