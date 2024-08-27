use std::fs::File;
use std::io;

use crate::{x25519, Callbacks, DecryptError, EncryptError, IdentityFileConvertError, NoCallbacks};

#[cfg(feature = "cli-common")]
use crate::cli_common::file_io::InputReader;

#[cfg(feature = "plugin")]
use crate::plugin;

/// The supported kinds of identities within an [`IdentityFile`].
#[derive(Clone)]
enum IdentityFileEntry {
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
            IdentityFileEntry::Plugin(i) => Ok(Box::new(
                crate::plugin::Plugin::new(i.plugin())
                    .map_err(|binary_name| DecryptError::MissingPlugin { binary_name })
                    .map(|plugin| {
                        crate::plugin::IdentityPluginV1::from_parts(plugin, vec![i], callbacks)
                    })?,
            )),
        }
    }
}

/// A list of identities that has been parsed from some input file.
pub struct IdentityFile<C: Callbacks> {
    filename: Option<String>,
    identities: Vec<IdentityFileEntry>,
    pub(crate) callbacks: C,
}

impl IdentityFile<NoCallbacks> {
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

    /// Parses one or more identities from an [`InputReader`];
    #[cfg(feature = "cli-common")]
    pub fn from_input_reader(reader: InputReader) -> io::Result<Self> {
        let filename = reader.filename().map(String::from);
        Self::parse_identities(filename, io::BufReader::new(reader))
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

        Ok(IdentityFile {
            filename,
            identities,
            callbacks: NoCallbacks,
        })
    }
}

impl<C: Callbacks> IdentityFile<C> {
    /// Sets the provided callbacks on this identity file, so that if this is an encrypted
    /// identity, it can potentially be decrypted.
    pub fn with_callbacks<D: Callbacks>(self, callbacks: D) -> IdentityFile<D> {
        IdentityFile {
            filename: self.filename,
            identities: self.identities,
            callbacks,
        }
    }

    /// Writes a recipients file containing the recipients corresponding to the identities
    /// in this file.
    ///
    /// Returns an error if this file is empty, or if it contains plugin identities (which
    /// can only be converted by the plugin binary itself).
    pub fn write_recipients_file<W: io::Write>(
        &self,
        mut output: W,
    ) -> Result<(), IdentityFileConvertError> {
        if self.identities.is_empty() {
            return Err(IdentityFileConvertError::NoIdentities {
                filename: self.filename.clone(),
            });
        }

        for identity in &self.identities {
            match identity {
                IdentityFileEntry::Native(sk) => writeln!(output, "{}", sk.to_public())
                    .map_err(IdentityFileConvertError::FailedToWriteOutput)?,
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(id) => {
                    return Err(IdentityFileConvertError::IdentityFileContainsPlugin {
                        filename: self.filename.clone(),
                        plugin_name: id.plugin().to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Returns recipients for the identities in this file.
    ///
    /// Plugin identities will be merged into one [`Recipient`] per unique plugin.
    ///
    /// [`Recipient`]: crate::Recipient
    pub fn to_recipients(&self) -> Result<Vec<Box<dyn crate::Recipient + Send>>, EncryptError> {
        let mut recipients = RecipientsAccumulator::new();
        recipients.with_identities_ref(self);
        recipients.build(
            #[cfg(feature = "plugin")]
            self.callbacks.clone(),
        )
    }

    /// Returns the identities in this file.
    pub(crate) fn to_identities(
        &self,
    ) -> impl Iterator<Item = Result<Box<dyn crate::Identity>, DecryptError>> + '_ {
        self.identities
            .iter()
            .map(|entry| entry.clone().into_identity(self.callbacks.clone()))
    }

    /// Returns the identities in this file.
    pub fn into_identities(self) -> Result<Vec<Box<dyn crate::Identity>>, DecryptError> {
        self.identities
            .into_iter()
            .map(|entry| entry.into_identity(self.callbacks.clone()))
            .collect()
    }
}

pub(crate) struct RecipientsAccumulator {
    recipients: Vec<Box<dyn crate::Recipient + Send>>,
    #[cfg(feature = "plugin")]
    plugin_recipients: Vec<plugin::Recipient>,
    #[cfg(feature = "plugin")]
    plugin_identities: Vec<plugin::Identity>,
}

impl RecipientsAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            recipients: vec![],
            #[cfg(feature = "plugin")]
            plugin_recipients: vec![],
            #[cfg(feature = "plugin")]
            plugin_identities: vec![],
        }
    }

    #[cfg(feature = "cli-common")]
    pub(crate) fn push(&mut self, recipient: Box<dyn crate::Recipient + Send>) {
        self.recipients.push(recipient);
    }

    #[cfg(feature = "plugin")]
    pub(crate) fn push_plugin(&mut self, recipient: plugin::Recipient) {
        self.plugin_recipients.push(recipient);
    }

    #[cfg(feature = "armor")]
    pub(crate) fn extend(
        &mut self,
        iter: impl IntoIterator<Item = Box<dyn crate::Recipient + Send>>,
    ) {
        self.recipients.extend(iter);
    }

    #[cfg(feature = "cli-common")]
    pub(crate) fn with_identities<C: Callbacks>(&mut self, identity_file: IdentityFile<C>) {
        for entry in identity_file.identities {
            match entry {
                IdentityFileEntry::Native(i) => self.recipients.push(Box::new(i.to_public())),
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(i) => self.plugin_identities.push(i),
            }
        }
    }

    pub(crate) fn with_identities_ref<C: Callbacks>(&mut self, identity_file: &IdentityFile<C>) {
        for entry in &identity_file.identities {
            match entry {
                IdentityFileEntry::Native(i) => self.recipients.push(Box::new(i.to_public())),
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(i) => self.plugin_identities.push(i.clone()),
            }
        }
    }

    #[cfg_attr(not(feature = "plugin"), allow(unused_mut))]
    pub(crate) fn build(
        mut self,
        #[cfg(feature = "plugin")] callbacks: impl Callbacks,
    ) -> Result<Vec<Box<dyn crate::Recipient + Send>>, EncryptError> {
        #[cfg(feature = "plugin")]
        {
            // Collect the names of the required plugins.
            let mut plugin_names = self
                .plugin_recipients
                .iter()
                .map(|r| r.plugin())
                .chain(self.plugin_identities.iter().map(|i| i.plugin()))
                .collect::<Vec<_>>();
            plugin_names.sort_unstable();
            plugin_names.dedup();

            // Find the required plugins.
            for plugin_name in plugin_names {
                self.recipients
                    .push(Box::new(plugin::RecipientPluginV1::new(
                        plugin_name,
                        &self.plugin_recipients,
                        &self.plugin_identities,
                        callbacks.clone(),
                    )?))
            }
        }

        Ok(self.recipients)
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
