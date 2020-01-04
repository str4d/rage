use age::{
    cli_common::{
        file_io, get_config_dir, read_identities, read_or_generate_passphrase, read_secret,
        Passphrase,
    },
    Format,
};
use gumdrop::Options;
use log::{error, warn};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{self, BufRead, BufReader};

mod error;

const ALIAS_PREFIX: &str = "alias:";
const GITHUB_PREFIX: &str = "github:";

/// Load map of aliases from the given file, or the default system location
/// otherwise.
///
/// Returns an error if a filename is given that does not exist. A missing
/// aliases file at the default system location is ignored.
fn load_aliases(filename: Option<String>) -> io::Result<HashMap<String, Vec<String>>> {
    let buf = if let Some(f) = filename {
        read_to_string(f)?
    } else {
        // If the default aliases file doesn't exist, ignore it.
        get_config_dir()
            .map(|mut path| {
                path.push("age/aliases.txt");
                read_to_string(path).unwrap_or_default()
            })
            .unwrap_or_default()
    };

    let mut aliases = HashMap::new();

    for line in buf.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() > 1 && parts[0].ends_with(':') {
            aliases.insert(
                parts[0][..parts[0].len() - 1].to_owned(),
                parts[1..].iter().map(|s| String::from(*s)).collect(),
            );
        }
    }

    Ok(aliases)
}

/// Reads file contents as a list of recipients
fn read_recipients_list<R: BufRead>(
    filename: &str,
    buf: R,
) -> io::Result<Vec<age::keys::RecipientKey>> {
    let mut recipients = vec![];

    for line in buf.lines() {
        let line = line?;

        // Skip empty lines and comments
        if !(line.is_empty() || line.find('#') == Some(0)) {
            match line.parse() {
                Ok(key) => recipients.push(key),
                Err(<age::keys::RecipientKey as std::str::FromStr>::Err::Ignore) => (),
                Err(e) => {
                    error!("{:?}", e);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("recipients file {} contains non-recipient data", filename),
                    ));
                }
            }
        }
    }

    Ok(recipients)
}

/// Reads recipients from the provided arguments.
///
/// Supported arguments:
/// - Recipient keys
/// - Path to a file containing a list of recipient keys
fn read_recipients(
    mut arguments: Vec<String>,
    aliases: Option<String>,
) -> Result<Vec<age::keys::RecipientKey>, error::EncryptError> {
    let mut aliases = load_aliases(aliases)?;
    let mut seen_aliases: Vec<String> = vec![];

    let mut recipients = vec![];
    while !arguments.is_empty() {
        let arg = arguments.pop().expect("arguments is not empty");

        if let Ok(pk) = arg.parse() {
            recipients.push(pk);
        } else if arg.starts_with(ALIAS_PREFIX) {
            #[cfg(not(feature = "unstable"))]
            {
                eprintln!("Aliases are unstable.");
                eprintln!("To test this, build rage with --features unstable");
            }

            if seen_aliases.contains(&arg) {
                warn!("Duplicate {}", arg);
            } else {
                // Replace the alias in the arguments list with its expansion
                if let Some(new_arg) = aliases.remove(&arg[ALIAS_PREFIX.len()..]) {
                    arguments.extend(new_arg);
                    seen_aliases.push(arg);
                } else {
                    return Err(error::EncryptError::UnknownAlias(arg));
                }
            }
        } else if arg.starts_with(GITHUB_PREFIX) {
            #[cfg(not(feature = "unstable"))]
            {
                eprintln!("GitHub lookups are unstable, ignoring recipient.");
                eprintln!("To test this, build rage with --features unstable");
                continue;
            }

            #[cfg(feature = "unstable")]
            arguments.push(format!(
                "https://github.com/{}.keys",
                &arg[GITHUB_PREFIX.len()..],
            ));
        } else if arg.starts_with("https://") {
            let response = minreq::get(&arg).send()?;
            match response.status_code {
                200 => recipients.extend(read_recipients_list(
                    &arg,
                    BufReader::new(response.body.as_bytes()),
                )?),
                404 => {
                    return Err(error::EncryptError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} not found", arg),
                    )))
                }
                code => {
                    return Err(error::EncryptError::Io(io::Error::new(
                        io::ErrorKind::Other,
                        format!("{} returned an unexpected code ({})", arg, code),
                    )))
                }
            }
        } else if let Ok(f) = File::open(&arg) {
            let buf = BufReader::new(f);
            recipients.extend(read_recipients_list(&arg, buf)?);
        } else {
            return Err(error::EncryptError::InvalidRecipient(arg));
        }
    }

    Ok(recipients)
}

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(free, help = "file to read input from (default stdin)")]
    input: Option<String>,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "decrypt the input (default is to encrypt)")]
    decrypt: bool,

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,

    #[options(help = "create ASCII armored output (default is age binary format)")]
    armor: bool,

    #[options(help = "recipient to encrypt to (may be repeated)")]
    recipient: Vec<String>,

    #[options(help = "identity to decrypt with (may be repeated)")]
    identity: Vec<String>,

    #[options(help = "output to OUTPUT (default stdout)")]
    output: Option<String>,

    #[cfg(feature = "unstable")]
    #[options(help = "load the aliases list from ALIASES", no_short)]
    aliases: Option<String>,
}

fn encrypt(opts: AgeOptions) -> Result<(), error::EncryptError> {
    if !opts.identity.is_empty() {
        return Err(error::EncryptError::IdentityFlag);
    }

    let encryptor = if opts.passphrase {
        if !opts.recipient.is_empty() {
            return Err(error::EncryptError::MixedRecipientAndPassphrase);
        }

        if opts.input.is_none() {
            return Err(error::EncryptError::PassphraseWithoutFileArgument);
        }

        match read_or_generate_passphrase() {
            Ok(Passphrase::Typed(passphrase)) => age::Encryptor::Passphrase(passphrase),
            Ok(Passphrase::Generated(new_passphrase)) => {
                eprintln!(
                    "Using the autogenerated passphrase '{}'.",
                    new_passphrase.expose_secret()
                );
                age::Encryptor::Passphrase(new_passphrase)
            }
            Err(_) => return Ok(()),
        }
    } else {
        if opts.recipient.is_empty() {
            return Err(error::EncryptError::MissingRecipients);
        }

        #[cfg(feature = "unstable")]
        let aliases = opts.aliases;

        #[cfg(not(feature = "unstable"))]
        let aliases = None;

        age::Encryptor::Keys(read_recipients(opts.recipient, aliases)?)
    };

    let mut input = file_io::InputReader::new(opts.input)?;

    let (format, output_format) = if opts.armor {
        (Format::AsciiArmor, file_io::OutputFormat::Text)
    } else {
        (Format::Binary, file_io::OutputFormat::Binary)
    };

    let mut output = encryptor.wrap_output(
        file_io::OutputWriter::new(opts.output, output_format, 0o666)?,
        format,
    )?;

    io::copy(&mut input, &mut output)?;
    output.finish()?;

    Ok(())
}

fn decrypt(opts: AgeOptions) -> Result<(), error::DecryptError> {
    if opts.armor {
        return Err(error::DecryptError::ArmorFlag);
    }

    if !opts.recipient.is_empty() {
        return Err(error::DecryptError::RecipientFlag);
    }

    let decryptor = if opts.passphrase {
        if !opts.identity.is_empty() {
            return Err(error::DecryptError::MixedIdentityAndPassphrase);
        }

        if opts.input.is_none() {
            return Err(error::DecryptError::PassphraseWithoutFileArgument);
        }

        match read_secret("Type passphrase", None) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return Ok(()),
        }
    } else {
        let identities = read_identities(opts.identity, |default_filename| {
            error::DecryptError::MissingIdentities(default_filename.to_string())
        })?;

        // Check for unsupported keys and alert the user
        for identity in &identities {
            if let age::keys::IdentityKey::Unsupported(k) = identity.key() {
                return Err(error::DecryptError::UnsupportedKey(
                    identity.filename().unwrap_or_default().to_string(),
                    k.clone(),
                ));
            }
        }

        age::Decryptor::Keys(identities)
    };

    let input = file_io::InputReader::new(opts.input)?;
    let mut output =
        file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Unknown, 0o666)?;

    let mut input = decryptor.trial_decrypt(input, |prompt| read_secret(prompt, None).ok())?;

    io::copy(&mut input, &mut output)?;

    Ok(())
}

fn main() -> Result<(), error::Error> {
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.decrypt {
        decrypt(opts).map_err(error::Error::from)
    } else {
        encrypt(opts).map_err(error::Error::from)
    }
}
