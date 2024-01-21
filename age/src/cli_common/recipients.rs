use std::fs::File;
use std::io::{self, BufReader};

use super::{identities::parse_identity_files, ReadError, UiCallbacks};
use crate::{x25519, EncryptError, IdentityFileEntry, Recipient};

#[cfg(feature = "plugin")]
use crate::plugin;

#[cfg(feature = "ssh")]
use crate::ssh;

/// Handles error mapping for the given SSH recipient parser.
///
/// Returns `Ok(None)` if the parser finds a parseable value that should be ignored. This
/// case is for handling SSH recipient types that may occur in files we want to be able to
/// parse, but that we do not directly support.
#[cfg(feature = "ssh")]
fn parse_ssh_recipient<F, G>(
    parser: F,
    invalid: G,
    filename: &str,
) -> Result<Option<Box<dyn Recipient + Send>>, ReadError>
where
    F: FnOnce() -> Result<ssh::Recipient, ssh::ParseRecipientKeyError>,
    G: FnOnce() -> Result<Option<Box<dyn Recipient + Send>>, ReadError>,
{
    use ssh::{ParseRecipientKeyError, UnsupportedKey};

    match parser() {
        Ok(pk) => Ok(Some(Box::new(pk))),
        Err(e) => match e {
            ParseRecipientKeyError::Ignore => Ok(None),
            ParseRecipientKeyError::Invalid(_) => invalid(),
            ParseRecipientKeyError::RsaModulusTooLarge => Err(ReadError::RsaModulusTooLarge),
            ParseRecipientKeyError::Unsupported(key_type) => Err(ReadError::UnsupportedKey(
                filename.to_string(),
                UnsupportedKey::Type(key_type),
            )),
        },
    }
}

/// Parses a recipient from a string.
fn parse_recipient(
    filename: &str,
    s: String,
    recipients: &mut Vec<Box<dyn Recipient + Send>>,
    plugin_recipients: &mut Vec<plugin::Recipient>,
) -> Result<(), ReadError> {
    if let Ok(pk) = s.parse::<x25519::Recipient>() {
        recipients.push(Box::new(pk));
    } else if let Some(pk) = {
        #[cfg(feature = "ssh")]
        {
            parse_ssh_recipient(|| s.parse::<ssh::Recipient>(), || Ok(None), filename)?
        }

        #[cfg(not(feature = "ssh"))]
        None
    } {
        recipients.push(pk);
    } else if let Ok(recipient) = s.parse::<plugin::Recipient>() {
        plugin_recipients.push(recipient);
    } else {
        return Err(ReadError::InvalidRecipient(s));
    }

    Ok(())
}

/// Reads file contents as a list of recipients
fn read_recipients_list<R: io::BufRead>(
    filename: &str,
    buf: R,
    recipients: &mut Vec<Box<dyn Recipient + Send>>,
    plugin_recipients: &mut Vec<plugin::Recipient>,
) -> Result<(), ReadError> {
    for (line_number, line) in buf.lines().enumerate() {
        let line = line?;

        // Skip empty lines and comments
        if line.is_empty() || line.find('#') == Some(0) {
            continue;
        } else if let Err(e) = parse_recipient(filename, line, recipients, plugin_recipients) {
            #[cfg(feature = "ssh")]
            if matches!(e, ReadError::UnsupportedKey(_, _)) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()).into());
            }

            // Return a line number in place of the line, so we don't leak the file
            // contents in error messages.
            return Err(ReadError::InvalidRecipientsFile {
                filename: filename.to_owned(),
                line_number: line_number + 1,
            });
        }
    }

    Ok(())
}

/// Reads recipients from the provided arguments.
pub fn read_recipients(
    recipient_strings: Vec<String>,
    recipients_file_strings: Vec<String>,
    identity_strings: Vec<String>,
    max_work_factor: Option<u8>,
) -> Result<Vec<Box<dyn Recipient + Send>>, ReadError> {
    let mut recipients: Vec<Box<dyn Recipient + Send>> = vec![];
    let mut plugin_recipients: Vec<plugin::Recipient> = vec![];
    let mut plugin_identities: Vec<plugin::Identity> = vec![];

    for arg in recipient_strings {
        parse_recipient("", arg, &mut recipients, &mut plugin_recipients)?;
    }

    for arg in recipients_file_strings {
        let f = File::open(&arg).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ReadError::MissingRecipientsFile(arg.clone()),
            _ => e.into(),
        })?;
        let buf = BufReader::new(f);
        read_recipients_list(&arg, buf, &mut recipients, &mut plugin_recipients)?;
    }

    parse_identity_files::<_, ReadError>(
        identity_strings,
        max_work_factor,
        &mut (&mut recipients, &mut plugin_identities),
        |(recipients, _), identity| {
            recipients.extend(identity.recipients().map_err(|e| {
                // Only one error can occur here.
                if let EncryptError::EncryptedIdentities(e) = e {
                    ReadError::EncryptedIdentities(e)
                } else {
                    unreachable!()
                }
            })?);
            Ok(())
        },
        |(recipients, _), filename, identity| {
            let recipient = parse_ssh_recipient(
                || ssh::Recipient::try_from(identity),
                || Err(ReadError::InvalidRecipient(filename.to_owned())),
                filename,
            )?
            .expect("unsupported identities were already handled");
            recipients.push(recipient);
            Ok(())
        },
        |(recipients, plugin_identities), entry| {
            match entry {
                IdentityFileEntry::Native(i) => recipients.push(Box::new(i.to_public())),
                IdentityFileEntry::Plugin(i) => plugin_identities.push(i),
            }
            Ok(())
        },
    )?;

    // Collect the names of the required plugins.
    let mut plugin_names = plugin_recipients
        .iter()
        .map(|r| r.plugin())
        .chain(plugin_identities.iter().map(|i| i.plugin()))
        .collect::<Vec<_>>();
    plugin_names.sort_unstable();
    plugin_names.dedup();

    // Find the required plugins.
    for plugin_name in plugin_names {
        recipients.push(Box::new(
            plugin::RecipientPluginV1::new(
                plugin_name,
                &plugin_recipients,
                &plugin_identities,
                UiCallbacks,
            )
            .map_err(|e| {
                // Only one error can occur here.
                if let EncryptError::MissingPlugin { binary_name } = e {
                    ReadError::MissingPlugin { binary_name }
                } else {
                    unreachable!()
                }
            })?,
        ))
    }

    Ok(recipients)
}
