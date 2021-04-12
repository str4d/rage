#![forbid(unsafe_code)]

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    cli_common::{
        file_io, read_identities, read_or_generate_passphrase, read_secret, Passphrase, UiCallbacks,
    },
    plugin, Identity, IdentityFile, Recipient,
};
use gumdrop::{Options, ParsingStyle};
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use secrecy::ExposeSecret;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

mod error;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Translations;

const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};
}

/// Parses a recipient from a string.
fn parse_recipient(
    s: String,
    recipients: &mut Vec<Box<dyn Recipient>>,
    plugin_recipients: &mut Vec<plugin::Recipient>,
) -> Result<(), error::EncryptError> {
    if let Ok(pk) = s.parse::<age::x25519::Recipient>() {
        recipients.push(Box::new(pk));
    } else if let Some(pk) = {
        #[cfg(feature = "ssh")]
        {
            s.parse::<age::ssh::Recipient>().ok().map(Box::new)
        }

        #[cfg(not(feature = "ssh"))]
        None
    } {
        recipients.push(pk);
    } else if let Ok(recipient) = s.parse::<plugin::Recipient>() {
        plugin_recipients.push(recipient);
    } else {
        return Err(error::EncryptError::InvalidRecipient(s));
    }

    Ok(())
}

/// Reads file contents as a list of recipients
fn read_recipients_list<R: BufRead>(
    filename: &str,
    buf: R,
    recipients: &mut Vec<Box<dyn Recipient>>,
    plugin_recipients: &mut Vec<plugin::Recipient>,
) -> io::Result<()> {
    for (line_number, line) in buf.lines().enumerate() {
        let line = line?;

        // Skip empty lines and comments
        if line.is_empty() || line.find('#') == Some(0) {
            continue;
        } else if parse_recipient(line, recipients, plugin_recipients).is_err() {
            // Return a line number in place of the line, so we don't leak the file
            // contents in error messages.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "recipients file {} contains non-recipient data on line {}",
                    filename,
                    line_number + 1
                ),
            ));
        }
    }

    Ok(())
}

/// Reads recipients from the provided arguments.
fn read_recipients(
    recipient_strings: Vec<String>,
    recipients_file_strings: Vec<String>,
    identity_strings: Vec<String>,
) -> Result<Vec<Box<dyn Recipient>>, error::EncryptError> {
    let mut recipients: Vec<Box<dyn Recipient>> = vec![];
    let mut plugin_recipients: Vec<plugin::Recipient> = vec![];
    let mut plugin_identities: Vec<plugin::Identity> = vec![];

    for arg in recipient_strings {
        parse_recipient(arg, &mut recipients, &mut plugin_recipients)?;
    }

    for arg in recipients_file_strings {
        let f = File::open(&arg)?;
        let buf = BufReader::new(f);
        read_recipients_list(&arg, buf, &mut recipients, &mut plugin_recipients)?;
    }

    for filename in identity_strings {
        // Try parsing as a single multi-line SSH identity.
        #[cfg(feature = "ssh")]
        match age::ssh::Identity::from_buffer(
            BufReader::new(File::open(&filename)?),
            Some(filename.clone()),
        ) {
            Ok(age::ssh::Identity::Unsupported(k)) => {
                return Err(error::EncryptError::UnsupportedKey(filename, k))
            }
            Ok(identity) => {
                if let Ok(recipient) = age::ssh::Recipient::try_from(identity) {
                    recipients.push(Box::new(recipient));
                    continue;
                }
            }
            Err(_) => (),
        }

        // Try parsing as multiple single-line age identities.
        let identity_file =
            IdentityFile::from_file(filename.clone()).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => error::EncryptError::IdentityNotFound(filename),
                _ => e.into(),
            })?;
        let (new_ids, new_plugin_ids) = identity_file.split_into();
        for identity in new_ids {
            recipients.push(Box::new(identity.to_public()));
        }
        plugin_identities.extend(new_plugin_ids);
    }

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
        recipients.push(Box::new(plugin::RecipientPluginV1::new(
            plugin_name,
            &plugin_recipients,
            &plugin_identities,
            UiCallbacks,
        )?))
    }

    Ok(recipients)
}

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(free, help = "Path to a file to read from.")]
    input: Option<String>,

    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(help = "Encrypt the input (the default).")]
    encrypt: bool,

    #[options(help = "Decrypt the input.")]
    decrypt: bool,

    #[options(help = "Encrypt with a passphrase instead of recipients.")]
    passphrase: bool,

    #[options(
        help = "Maximum work factor to allow for passphrase decryption.",
        meta = "WF",
        no_short
    )]
    max_work_factor: Option<u8>,

    #[options(help = "Encrypt to a PEM encoded format.")]
    armor: bool,

    #[options(help = "Encrypt to the specified RECIPIENT. May be repeated.")]
    recipient: Vec<String>,

    #[options(
        help = "Encrypt to the recipients listed at PATH. May be repeated.",
        meta = "PATH"
    )]
    recipients_file: Vec<String>,

    #[options(help = "Use the identity file at IDENTITY. May be repeated.")]
    identity: Vec<String>,

    #[options(help = "Write the result to the file at path OUTPUT.")]
    output: Option<String>,
}

fn encrypt(opts: AgeOptions) -> Result<(), error::EncryptError> {
    let encryptor = if opts.passphrase {
        if !opts.identity.is_empty() {
            return Err(error::EncryptError::MixedIdentityAndPassphrase);
        }
        if !opts.recipient.is_empty() {
            return Err(error::EncryptError::MixedRecipientAndPassphrase);
        }
        if !opts.recipients_file.is_empty() {
            return Err(error::EncryptError::MixedRecipientsFileAndPassphrase);
        }

        if opts.input.is_none() {
            return Err(error::EncryptError::PassphraseWithoutFileArgument);
        }

        match read_or_generate_passphrase() {
            Ok(Passphrase::Typed(passphrase)) => age::Encryptor::with_user_passphrase(passphrase),
            Ok(Passphrase::Generated(new_passphrase)) => {
                eprintln!("{}", fl!("autogenerated-passphrase"));
                eprintln!("    {}", new_passphrase.expose_secret());
                age::Encryptor::with_user_passphrase(new_passphrase)
            }
            Err(pinentry::Error::Cancelled) => return Ok(()),
            Err(pinentry::Error::Timeout) => return Err(error::EncryptError::PassphraseTimedOut),
            Err(pinentry::Error::Encoding(e)) => {
                // Pretend it is an I/O error
                return Err(error::EncryptError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e,
                )));
            }
            Err(pinentry::Error::Gpg(e)) => {
                // Pretend it is an I/O error
                return Err(error::EncryptError::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{}", e),
                )));
            }
            Err(pinentry::Error::Io(e)) => return Err(error::EncryptError::Io(e)),
        }
    } else {
        if opts.recipient.is_empty() && opts.recipients_file.is_empty() && opts.identity.is_empty()
        {
            return Err(error::EncryptError::MissingRecipients);
        }

        age::Encryptor::with_recipients(read_recipients(
            opts.recipient,
            opts.recipients_file,
            opts.identity,
        )?)
    };

    let mut input = file_io::InputReader::new(opts.input)?;

    let (format, output_format) = if opts.armor {
        (Format::AsciiArmor, file_io::OutputFormat::Text)
    } else {
        (Format::Binary, file_io::OutputFormat::Binary)
    };

    // Create an output to the user-requested location.
    let output = file_io::OutputWriter::new(opts.output, output_format, 0o666)?;
    let is_stdout = match output {
        file_io::OutputWriter::File(..) => false,
        file_io::OutputWriter::Stdout(..) => true,
    };

    let mut output = encryptor.wrap_output(ArmoredWriter::wrap_output(output, format)?)?;

    // Give more useful errors specifically when writing to the output.
    let map_io_errors = |e: io::Error| match e.kind() {
        io::ErrorKind::BrokenPipe => error::EncryptError::BrokenPipe {
            is_stdout,
            source: e,
        },
        _ => e.into(),
    };

    io::copy(&mut input, &mut output).map_err(map_io_errors)?;
    output
        .finish()
        .and_then(|armor| armor.finish())
        .map_err(map_io_errors)?;

    Ok(())
}

fn write_output<R: io::Read>(
    mut input: R,
    output: Option<String>,
) -> Result<(), error::DecryptError> {
    let mut output = file_io::OutputWriter::new(output, file_io::OutputFormat::Unknown, 0o666)?;

    io::copy(&mut input, &mut output)?;

    Ok(())
}

fn decrypt(opts: AgeOptions) -> Result<(), error::DecryptError> {
    if opts.armor {
        return Err(error::DecryptError::ArmorFlag);
    }
    if opts.passphrase {
        return Err(error::DecryptError::PassphraseFlag);
    }

    if !opts.recipient.is_empty() {
        return Err(error::DecryptError::RecipientFlag);
    }
    if !opts.recipients_file.is_empty() {
        return Err(error::DecryptError::RecipientsFileFlag);
    }

    let output = opts.output;

    #[cfg(not(unix))]
    let has_file_argument = opts.input.is_some();

    match age::Decryptor::new(ArmoredReader::new(file_io::InputReader::new(opts.input)?))? {
        age::Decryptor::Passphrase(decryptor) => {
            // The `rpassword` crate opens `/dev/tty` directly on Unix, so we don't have
            // any conflict with stdin.
            #[cfg(not(unix))]
            {
                if !has_file_argument {
                    return Err(error::DecryptError::PassphraseWithoutFileArgument);
                }
            }

            match read_secret(&fl!("type-passphrase"), &fl!("prompt-passphrase"), None) {
                Ok(passphrase) => decryptor
                    .decrypt(&passphrase, opts.max_work_factor)
                    .map_err(|e| e.into())
                    .and_then(|input| write_output(input, output)),
                Err(pinentry::Error::Cancelled) => Ok(()),
                Err(pinentry::Error::Timeout) => Err(error::DecryptError::PassphraseTimedOut),
                Err(pinentry::Error::Encoding(e)) => {
                    // Pretend it is an I/O error
                    Err(error::DecryptError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e,
                    )))
                }
                Err(pinentry::Error::Gpg(e)) => {
                    // Pretend it is an I/O error
                    Err(error::DecryptError::Io(io::Error::new(
                        io::ErrorKind::Other,
                        format!("{}", e),
                    )))
                }
                Err(pinentry::Error::Io(e)) => Err(error::DecryptError::Io(e)),
            }
        }
        age::Decryptor::Recipients(decryptor) => {
            let identities = read_identities(
                opts.identity,
                error::DecryptError::IdentityNotFound,
                #[cfg(feature = "ssh")]
                error::DecryptError::UnsupportedKey,
            )?;

            if identities.is_empty() {
                return Err(error::DecryptError::MissingIdentities);
            }

            decryptor
                .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
                .map_err(|e| e.into())
                .and_then(|input| write_output(input, output))
        }
    }
}

fn main() -> Result<(), error::Error> {
    use std::env::args;

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n_embed::select(&*LANGUAGE_LOADER, &TRANSLATIONS, &requested_languages).unwrap();
    age::localizer().select(&requested_languages).unwrap();
    // Unfortunately the common Windows terminals don't support Unicode Directionality
    // Isolation Marks, so we disable them for now.
    LANGUAGE_LOADER.set_use_isolating(false);

    let args = args().collect::<Vec<_>>();

    let opts = AgeOptions::parse_args(&args[1..], ParsingStyle::default()).unwrap_or_else(|e| {
        eprintln!("{}: {}", args[0], e);
        std::process::exit(2);
    });

    // If you are piping input with no other args, this will not allow
    // it.
    if (console::user_attended() && args.len() == 1) || opts.help_requested() {
        let binary_name = args[0].as_str();
        let keygen_name = format!("{}-keygen", binary_name);
        let usage_a = format!(
            "{} [--encrypt] -r RECIPIENT [-i IDENTITY] [-a] [-o OUTPUT] [INPUT]",
            binary_name
        );
        let usage_b = format!(
            "{} --decrypt [-i IDENTITY] [-o OUTPUT] [INPUT]",
            binary_name
        );
        let example_a = format!("$ {} -o key.txt", keygen_name);
        let example_a_output = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let example_b = format!(
            "$ tar cvz ~/data | {} -r {} > data.tar.gz.age",
            binary_name, example_a_output
        );
        let example_c = format!(
            "$ {} -d -i key.txt -o data.tar.gz data.tar.gz.age",
            binary_name
        );

        println!(
            "{}",
            i18n_embed_fl::fl!(
                LANGUAGE_LOADER,
                "rage-usage",
                usage_a = usage_a,
                usage_b = usage_b,
                flags = AgeOptions::usage(),
                keygen_name = keygen_name,
                example_a = example_a,
                example_a_output = example_a_output,
                example_b = example_b,
                example_c = example_c,
            )
        );

        return Ok(());
    }

    if opts.version {
        println!("rage {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else {
        if opts.encrypt && opts.decrypt {
            return Err(error::Error::MixedEncryptAndDecrypt);
        }
        if !(opts.identity.is_empty() || opts.encrypt || opts.decrypt) {
            return Err(error::Error::IdentityFlagAmbiguous);
        }

        if let (Some(in_file), Some(out_file)) = (&opts.input, &opts.output) {
            // Check that the given filenames do not correspond to the same file.
            let in_path = Path::new(&in_file);
            let out_path = Path::new(&out_file);
            match (in_path.canonicalize(), out_path.canonicalize()) {
                (Ok(in_abs), Ok(out_abs)) if in_abs == out_abs => {
                    return Err(error::Error::SameInputAndOutput(out_file.clone()));
                }
                _ => (),
            }
        }

        if opts.decrypt {
            decrypt(opts).map_err(error::Error::from)
        } else {
            encrypt(opts).map_err(error::Error::from)
        }
    }
}
