#![forbid(unsafe_code)]

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    cli_common::{
        file_io, get_config_dir, read_identities, read_or_generate_passphrase, read_secret,
        Passphrase,
    },
    plugin, Recipient,
};
use gumdrop::{Options, ParsingStyle};
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
fn read_recipients_list<R: BufRead>(filename: &str, buf: R) -> io::Result<Vec<Box<dyn Recipient>>> {
    let mut recipients: Vec<Box<dyn Recipient>> = vec![];

    for line in buf.lines() {
        let line = line?;

        // Skip empty lines and comments
        if !(line.is_empty() || line.find('#') == Some(0)) {
            match line.parse::<age::x25519::Recipient>() {
                Ok(key) => recipients.push(Box::new(key)),
                Err(_e) => {
                    #[cfg(feature = "ssh")]
                    let _e = match line.parse::<age::ssh::Recipient>() {
                        Ok(key) => {
                            recipients.push(Box::new(key));
                            continue;
                        }
                        Err(e) => e,
                    };

                    error!("{:?}", _e);
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
) -> Result<Vec<Box<dyn Recipient>>, error::EncryptError> {
    let mut aliases = load_aliases(aliases)?;
    let mut seen_aliases: Vec<String> = vec![];

    let mut recipients: Vec<Box<dyn Recipient>> = vec![];
    let mut plugin_recipients: Vec<plugin::Recipient> = vec![];
    while !arguments.is_empty() {
        let arg = arguments.pop().expect("arguments is not empty");

        if let Ok(pk) = arg.parse::<age::x25519::Recipient>() {
            recipients.push(Box::new(pk));
        } else if let Some(pk) = {
            #[cfg(feature = "ssh")]
            {
                arg.parse::<age::ssh::Recipient>().ok().map(Box::new)
            }

            #[cfg(not(feature = "ssh"))]
            None
        } {
            recipients.push(pk);
        } else if let Ok(recipient) = arg.parse::<plugin::Recipient>() {
            plugin_recipients.push(recipient);
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
                    BufReader::new(response.as_bytes()),
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

    // Collect the names of the required plugins.
    let mut plugin_names = plugin_recipients
        .iter()
        .map(|r| r.plugin())
        .collect::<Vec<_>>();
    plugin_names.sort();
    plugin_names.dedup();

    // Find the required plugins.
    for plugin_name in plugin_names {
        recipients.push(Box::new(
            plugin::RecipientPluginV1::new(plugin_name, &plugin_recipients)
                .map_err(|_| error::EncryptError::MissingPlugin(plugin_name.to_owned()))?,
        ))
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

    #[options(help = "Use the private key file at IDENTITY. May be repeated.")]
    identity: Vec<String>,

    #[options(help = "Write the result to the file at path OUTPUT.")]
    output: Option<String>,

    #[cfg(feature = "unstable")]
    #[options(help = "Load the aliases list from ALIASES.", no_short)]
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
            Ok(Passphrase::Typed(passphrase)) => age::Encryptor::with_user_passphrase(passphrase),
            Ok(Passphrase::Generated(new_passphrase)) => {
                eprintln!("Using an autogenerated passphrase:");
                eprintln!("    {}", new_passphrase.expose_secret());
                age::Encryptor::with_user_passphrase(new_passphrase)
            }
            Err(pinentry::Error::Cancelled) => return Ok(()),
            Err(pinentry::Error::Timeout) => {
                return Err(error::EncryptError::TimedOut("passphrase input".to_owned()))
            }
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
        if opts.recipient.is_empty() {
            return Err(error::EncryptError::MissingRecipients);
        }

        #[cfg(feature = "unstable")]
        let aliases = opts.aliases;

        #[cfg(not(feature = "unstable"))]
        let aliases = None;

        age::Encryptor::with_recipients(read_recipients(opts.recipient, aliases)?)
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

            match read_secret("Type passphrase", "Passphrase", None) {
                Ok(passphrase) => decryptor
                    .decrypt(&passphrase, opts.max_work_factor)
                    .map_err(|e| e.into())
                    .and_then(|input| write_output(input, output)),
                Err(pinentry::Error::Cancelled) => Ok(()),
                Err(pinentry::Error::Timeout) => {
                    Err(error::DecryptError::TimedOut("passphrase input".to_owned()))
                }
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
                |default_filename| {
                    error::DecryptError::MissingIdentities(default_filename.to_string())
                },
                error::DecryptError::IdentityNotFound,
                error::DecryptError::MissingPlugin,
                #[cfg(feature = "ssh")]
                error::DecryptError::UnsupportedKey,
            )?;

            decryptor
                .decrypt(identities.into_iter())
                .map_err(|e| e.into())
                .and_then(|input| write_output(input, output))
        }
    }
}

fn main() -> Result<(), error::Error> {
    use std::env::args;

    env_logger::builder().format_timestamp(None).init();

    let args = args().collect::<Vec<_>>();

    let opts = AgeOptions::parse_args(&args[1..], ParsingStyle::default()).unwrap_or_else(|e| {
        eprintln!("{}: {}", args[0], e);
        std::process::exit(2);
    });

    // If you are piping input with no other args, this will not allow
    // it.
    if (console::user_attended() && args.len() == 1) || opts.help_requested() {
        println!("Usage:");
        println!("  {} -r RECIPIENT [-a] [-o OUTPUT] [INPUT]", args[0]);
        println!("  {} --decrypt [-i IDENTITY] [-o OUTPUT] [INPUT]", args[0]);
        println!();
        println!("{}", AgeOptions::usage());
        println!();
        println!("INPUT defaults to standard input, and OUTPUT defaults to standard output.");
        println!();
        println!("RECIPIENT can be:");
        println!(
            "- An age public key, as generated by {}-keygen (\"age1...\").",
            args[0]
        );
        println!("- An SSH public key (\"ssh-ed25519 AAAA...\", \"ssh-rsa AAAA...\").");
        println!("- A path or HTTPS URL to a file containing age recipients, one per line");
        println!("  (ignoring \"#\" prefixed comments and empty lines).");
        println!();
        println!("IDENTITY is a path to a file with age identities, one per line");
        println!("(ignoring \"#\" prefixed comments and empty lines), or to an SSH key file.");
        println!("Multiple identities may be provided, and any unused ones will be ignored.");
        println!();
        println!("Example:");
        println!("    $ {}-keygen -o key.txt", args[0]);
        println!("    Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p");
        println!("    $ tar cvz ~/data | {} -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age", args[0]);
        println!(
            "    $ {} -d -i key.txt -o data.tar.gz data.tar.gz.age",
            args[0]
        );

        return Ok(());
    }

    if opts.version {
        println!("rage {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else if opts.decrypt {
        decrypt(opts).map_err(error::Error::from)
    } else {
        encrypt(opts).map_err(error::Error::from)
    }
}
