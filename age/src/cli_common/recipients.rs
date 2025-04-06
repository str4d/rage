use std::io::{self, BufReader};

use super::StdinGuard;
use super::{identities::parse_identity_files, ReadError};
use crate::identity::RecipientsAccumulator;
use crate::{x25519, Recipient};

#[cfg(feature = "plugin")]
use crate::{cli_common::UiCallbacks, plugin};

#[cfg(not(feature = "plugin"))]
use std::convert::Infallible;

#[cfg(feature = "ssh")]
use crate::ssh;

#[cfg(any(feature = "armor", feature = "plugin"))]
use crate::EncryptError;

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
            ParseRecipientKeyError::RsaModulusTooSmall => Err(ReadError::RsaModulusTooSmall),
            ParseRecipientKeyError::Unsupported(key_type) => Err(ReadError::UnsupportedKey(
                filename.to_string(),
                UnsupportedKey::from_key_type(key_type),
            )),
        },
    }
}

/// Parses a recipient from a string.
fn parse_recipient(
    _filename: &str,
    s: String,
    recipients: &mut RecipientsAccumulator,
) -> Result<(), ReadError> {
    if let Ok(pk) = s.parse::<x25519::Recipient>() {
        recipients.push(Box::new(pk));
    } else if let Some(pk) = {
        #[cfg(feature = "ssh")]
        {
            parse_ssh_recipient(|| s.parse::<ssh::Recipient>(), || Ok(None), _filename)?
        }

        #[cfg(not(feature = "ssh"))]
        None
    } {
        recipients.push(pk);
    } else if let Some(_recipient) = {
        #[cfg(feature = "plugin")]
        {
            // TODO Do something with the error?
            s.parse::<plugin::Recipient>().ok()
        }

        #[cfg(not(feature = "plugin"))]
        None::<Infallible>
    } {
        #[cfg(feature = "plugin")]
        recipients.push_plugin(_recipient);
    } else {
        return Err(ReadError::InvalidRecipient(s));
    }

    Ok(())
}

/// Reads file contents as a list of recipients
fn read_recipients_list<R: io::BufRead>(
    filename: &str,
    buf: R,
    recipients: &mut RecipientsAccumulator,
) -> Result<(), ReadError> {
    for (line_number, line) in buf.lines().enumerate() {
        let line = line?;

        // Skip empty lines and comments
        if line.is_empty() || line.find('#') == Some(0) {
            continue;
        } else if let Err(_e) = parse_recipient(filename, line, recipients) {
            #[cfg(feature = "ssh")]
            match _e {
                ReadError::RsaModulusTooLarge
                | ReadError::RsaModulusTooSmall
                | ReadError::UnsupportedKey(_, _) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, _e.to_string()).into());
                }
                _ => (),
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
///
/// `recipients_file_strings` and `identity_strings` may collectively contain at most one
/// entry of `"-"`, which will be interpreted as reading from standard input. An error
/// will be returned if `stdin_guard` is guarding an existing usage of standard input.
pub fn read_recipients(
    recipient_strings: Vec<String>,
    recipients_file_strings: Vec<String>,
    identity_strings: Vec<String>,
    max_work_factor: Option<u8>,
    stdin_guard: &mut StdinGuard,
) -> Result<Vec<Box<dyn Recipient + Send>>, ReadError> {
    let mut recipients = RecipientsAccumulator::new();

    for arg in recipient_strings {
        parse_recipient("", arg, &mut recipients)?;
    }

    for arg in recipients_file_strings {
        let f = stdin_guard.open(arg.clone()).map_err(|e| match e {
            ReadError::Io(e) if matches!(e.kind(), io::ErrorKind::NotFound) => {
                ReadError::MissingRecipientsFile(arg.clone())
            }
            _ => e,
        })?;
        let buf = BufReader::new(f);
        read_recipients_list(&arg, buf, &mut recipients)?;
    }

    parse_identity_files::<_, ReadError>(
        identity_strings,
        max_work_factor,
        stdin_guard,
        &mut recipients,
        #[cfg(feature = "armor")]
        |recipients, identity| {
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
        #[cfg(feature = "ssh")]
        |recipients, filename, identity| {
            let recipient = parse_ssh_recipient(
                || ssh::Recipient::try_from(identity),
                || Err(ReadError::InvalidRecipient(filename.to_owned())),
                filename,
            )?
            .expect("unsupported identities were already handled");
            recipients.push(recipient);
            Ok(())
        },
        |recipients, identity_file| {
            recipients.with_identities(identity_file);
            Ok(())
        },
    )?;

    recipients
        .build(
            #[cfg(feature = "plugin")]
            UiCallbacks,
        )
        .map_err(|_e| {
            // Only one error can occur here.
            #[cfg(feature = "plugin")]
            {
                if let EncryptError::MissingPlugin { binary_name } = _e {
                    ReadError::MissingPlugin { binary_name }
                } else {
                    unreachable!()
                }
            }

            #[cfg(not(feature = "plugin"))]
            unreachable!()
        })
}
