use age::cli_common::{file_io, get_config_dir, read_identities, read_passphrase};
use gumdrop::Options;
use log::{error, warn};
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{self, BufRead, BufReader};

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
fn read_recipients_list<R: BufRead>(filename: &str, buf: R) -> io::Result<Vec<age::RecipientKey>> {
    let mut recipients = vec![];

    for line in buf.lines() {
        let line = line?;

        // Skip empty lines and comments
        if !(line.is_empty() || line.find('#') == Some(0)) {
            match line.parse() {
                Ok(key) => recipients.push(key),
                Err(<age::RecipientKey as std::str::FromStr>::Err::Ignore) => (),
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
) -> io::Result<Vec<age::RecipientKey>> {
    if arguments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing recipients",
        ));
    }

    let mut aliases = load_aliases(aliases)?;
    let mut seen_aliases = vec![];

    let mut recipients = vec![];
    while !arguments.is_empty() {
        let arg = arguments.pop().expect("arguments is not empty");

        if let Ok(f) = File::open(&arg) {
            let buf = BufReader::new(f);
            recipients.extend(read_recipients_list(&arg, buf)?);
        } else if let Ok(pk) = arg.parse() {
            recipients.push(pk);
        } else if arg.starts_with(ALIAS_PREFIX) {
            if seen_aliases.contains(&arg) {
                warn!("Duplicate {}", arg);
            } else {
                // Replace the alias in the arguments list with its expansion
                arguments.extend(aliases.remove(&arg[ALIAS_PREFIX.len()..]).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("unknown {}", arg))
                })?);
                seen_aliases.push(arg);
            }
        } else if arg.starts_with(GITHUB_PREFIX) {
            arguments.push(format!(
                "https://github.com/{}.keys",
                &arg[GITHUB_PREFIX.len()..],
            ));
        } else if arg.starts_with("https://") {
            match minreq::get(&arg).send() {
                Ok(response) => match response.status_code {
                    200 => recipients.extend(read_recipients_list(
                        &arg,
                        BufReader::new(response.body.as_bytes()),
                    )?),
                    404 => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("{} not found", arg),
                        ))
                    }
                    code => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("{} returned an unexpected code ({})", arg, code),
                        ))
                    }
                },
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to fetch {}: {}", arg, e),
                    ))
                }
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid recipient",
            ));
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

    #[options(help = "load the aliases list from ALIASES", no_short)]
    aliases: Option<String>,
}

fn encrypt(opts: AgeOptions) {
    if !opts.identity.is_empty() {
        error!("-i/--identity can't be used in encryption mode.");
        error!("Did you forget to specify -d/--decrypt?");
        return;
    }

    let encryptor = if opts.passphrase {
        if !opts.recipient.is_empty() {
            error!("-r/--recipient can't be used with -p/--passphrase");
            return;
        }

        if opts.input.is_none() {
            error!("File to encrypt must be passed as an argument when using -p/--passphrase");
            return;
        }

        match read_passphrase("Type passphrase", true) {
            Ok(passphrase) => age::Encryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        if opts.recipient.is_empty() {
            error!("Missing recipients.");
            error!("Did you forget to specify -r/--recipient?");
            return;
        }

        match read_recipients(opts.recipient, opts.aliases) {
            Ok(recipients) => age::Encryptor::Keys(recipients),
            Err(e) => {
                error!("Error while reading recipients: {}", e);
                return;
            }
        }
    };

    let mut input = match file_io::InputReader::new(opts.input) {
        Ok(input) => input,
        Err(e) => {
            error!("Failed to open input: {}", e);
            return;
        }
    };

    let output = match file_io::OutputWriter::new(opts.output, true) {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to open output: {}", e);
            return;
        }
    };

    match encryptor.wrap_output(output, opts.armor) {
        Ok(mut w) => {
            if let Err(e) = io::copy(&mut input, &mut w) {
                error!("Error while encrypting: {}", e);
                return;
            }
            if let Err(e) = w.finish() {
                error!("Error while encrypting: {}", e);
                return;
            }
        }
        Err(e) => {
            error!("Failed to encrypt: {}", e);
        }
    }
}

fn decrypt(opts: AgeOptions) {
    if opts.armor {
        error!("-a/--armor can't be used with -d/--decrypt.");
        error!("Note that armored files are detected automatically.");
        return;
    }

    if !opts.recipient.is_empty() {
        error!("-r/--recipient can't be used with -d/--decrypt.");
        error!("Did you mean to use -i/--identity to specify a private key?");
        return;
    }

    let decryptor = if opts.passphrase {
        if !opts.identity.is_empty() {
            error!("-i/--identity can't be used with -p/--passphrase");
            return;
        }

        if opts.input.is_none() {
            error!("File to decrypt must be passed as an argument when using -p/--passphrase");
            return;
        }

        match read_passphrase("Type passphrase", false) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        if opts.identity.is_empty() {
            error!("Missing identities.");
            error!("Did you forget to specify -i/--identity?");
            return;
        }

        match read_identities(opts.identity) {
            Ok(identities) => {
                // Check for unsupported keys and alert the user
                for identity in &identities {
                    if let age::IdentityKey::Unsupported(k) = identity.key() {
                        error!(
                            "Unsupported key: {}",
                            identity.filename().unwrap_or_default()
                        );
                        error!("");
                        error!("{}", k);
                        return;
                    }
                }
                age::Decryptor::Keys(identities)
            }
            Err(e) => {
                error!("Error while reading identities: {}", e);
                return;
            }
        }
    };

    let input = match file_io::InputReader::new(opts.input) {
        Ok(input) => input,
        Err(e) => {
            error!("Failed to open input: {}", e);
            return;
        }
    };

    let mut output = match file_io::OutputWriter::new(opts.output, false) {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to open output: {}", e);
            return;
        }
    };

    let maybe_decrypted =
        decryptor.trial_decrypt(input, |prompt| read_passphrase(prompt, false).ok());

    match maybe_decrypted {
        Ok(mut r) => {
            if let Err(e) = io::copy(&mut r, &mut output) {
                error!("Error while decrypting: {}", e);
            }
        }
        Err(e) => error!("Failed to decrypt: {}", e),
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.decrypt {
        decrypt(opts);
    } else {
        encrypt(opts);
    }
}
