use dialoguer::PasswordInput;
use gumdrop::Options;
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{self, BufRead, BufReader, Write};

mod file_io;

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
        dirs::config_dir()
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
            if let Some(key) = age::RecipientKey::from_str(&line) {
                recipients.push(key);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("recipients file {} contains non-recipient data", filename),
                ));
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
        let arg = arguments.pop().unwrap();

        if let Ok(f) = File::open(&arg) {
            let buf = BufReader::new(f);
            recipients.extend(read_recipients_list(&arg, buf)?);
        } else if let Some(pk) = age::RecipientKey::from_str(&arg) {
            recipients.push(pk);
        } else if arg.starts_with(ALIAS_PREFIX) {
            if seen_aliases.contains(&arg) {
                eprintln!("Warning: duplicate {}", arg);
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

/// Reads keys from the provided files if given, or the default system locations
/// if no files are given.
fn read_keys(filenames: Vec<String>) -> io::Result<Vec<age::SecretKey>> {
    let mut keys = vec![];

    if filenames.is_empty() {
        let default_filename = dirs::config_dir()
            .map(|mut path| {
                path.push("age/keys.txt");
                path
            })
            .expect("an OS for which we know the default config directory");
        let f = File::open(&default_filename).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no keys specified as arguments, and default file {} does not exist",
                    default_filename.to_str().unwrap()
                ),
            ),
            _ => e,
        })?;
        let buf = BufReader::new(f);

        for line in buf.lines() {
            let line = line?;

            // Skip empty lines and comments
            if !(line.is_empty() || line.find('#') == Some(0)) {
                if let Some(key) = age::SecretKey::from_str(&line) {
                    keys.push(key);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "key file contains non-key data",
                    ));
                }
            }
        }
    } else {
        for filename in filenames {
            let buf = BufReader::new(File::open(filename)?);

            for line in buf.lines() {
                let line = line?;

                // Skip empty lines and comments
                if !(line.is_empty() || line.find('#') == Some(0)) {
                    if let Some(key) = age::SecretKey::from_str(&line) {
                        keys.push(key);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "key file contains non-key data",
                        ));
                    }
                }
            }
        }
    }

    Ok(keys)
}

fn read_passphrase(confirm: bool) -> io::Result<String> {
    let mut input = PasswordInput::new();
    input.with_prompt("Type passphrase");
    if confirm {
        input.with_confirmation("Confirm passphrase", "Passphrases mismatching");
    }
    input.interact()
}

fn generate_new_key() {
    let sk = age::SecretKey::generate();

    println!(
        "# created: {}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    println!("# {}", sk.to_public().to_str());
    println!("{}", sk.to_str());
}

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(free, help = "recipients for encryption, or key files for decryption")]
    arguments: Vec<String>,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "generate a new key")]
    generate: bool,

    #[options(help = "decrypt a file")]
    decrypt: bool,

    #[options(help = "input file")]
    input: Option<String>,

    #[options(help = "output file")]
    output: Option<String>,

    #[options(help = "aliases file")]
    aliases: Option<String>,

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,
}

fn encrypt(opts: AgeOptions) {
    let encryptor = if opts.passphrase {
        if !opts.arguments.is_empty() {
            eprintln!("Positional arguments are not accepted when using a passphrase");
            return;
        }

        if opts.input.is_none() {
            eprintln!("File to encrypt must be passed in with --input when using a passphrase");
            return;
        }

        match read_passphrase(true) {
            Ok(passphrase) => age::Encryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        match read_recipients(opts.arguments, opts.aliases) {
            Ok(recipients) => age::Encryptor::Keys(recipients),
            Err(e) => {
                eprintln!("Error while reading recipients: {}", e);
                return;
            }
        }
    };

    let mut input = match file_io::InputReader::new(opts.input) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Failed to open input: {}", e);
            return;
        }
    };

    let output = match file_io::OutputWriter::new(opts.output, true) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to open output: {}", e);
            return;
        }
    };

    match encryptor.wrap_output(output) {
        Ok(mut w) => {
            if let Err(e) = io::copy(&mut input, &mut w) {
                eprintln!("Error while encrypting: {}", e);
                return;
            }
            if let Err(e) = w.flush() {
                eprintln!("Error while encrypting: {}", e);
                return;
            }
        }
        Err(e) => {
            eprintln!("Failed to encrypt: {}", e);
        }
    }
}

fn decrypt(opts: AgeOptions) {
    let decryptor = if opts.passphrase {
        if !opts.arguments.is_empty() {
            eprintln!("Positional arguments are not accepted when using a passphrase");
            return;
        }

        if opts.input.is_none() {
            eprintln!("File to decrypt must be passed in with --input when using a passphrase");
            return;
        }

        match read_passphrase(false) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        match read_keys(opts.arguments) {
            Ok(keys) => age::Decryptor::Keys(keys),
            Err(e) => {
                eprintln!("Error while reading keys: {}", e);
                return;
            }
        }
    };

    let input = match file_io::InputReader::new(opts.input) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Failed to open input: {}", e);
            return;
        }
    };

    let mut output = match file_io::OutputWriter::new(opts.output, false) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to open output: {}", e);
            return;
        }
    };

    let maybe_decrypted = decryptor.trial_decrypt(input);

    match maybe_decrypted {
        Ok(mut r) => {
            if let Err(e) = io::copy(&mut r, &mut output) {
                eprintln!("Error while decrypting: {}", e);
            }
        }
        Err(e) => eprintln!("Failed to decrypt: {}", e),
    }
}

fn main() {
    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.generate {
        generate_new_key();
    } else if opts.decrypt {
        decrypt(opts);
    } else {
        encrypt(opts);
    }
}
