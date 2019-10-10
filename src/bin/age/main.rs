use gumdrop::Options;
use std::fs::File;
use std::io::{self, Read, Write};

mod file_io;

/// Reads a recipient from a command-line argument.
fn read_recipient(arg: String) -> io::Result<age::RecipientKey> {
    if let Some(pk) = age::RecipientKey::from_str(&arg) {
        Ok(pk)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recipient",
        ))
    }
}

/// Reads recipients from the provided arguments.
fn read_recipients(arguments: Vec<String>) -> io::Result<Vec<age::RecipientKey>> {
    if arguments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing recipients",
        ));
    }

    arguments
        .into_iter()
        .map(read_recipient)
        .collect::<Result<_, _>>()
}

/// Reads keys from the provided files if given, or the default system locations
/// if no files are given.
fn read_keys(filenames: Vec<String>) -> io::Result<Vec<age::SecretKey>> {
    let mut keys = vec![];

    if filenames.is_empty() {
        // TODO: Read keys from default system locations
    } else {
        let mut buf = String::new();
        for filename in filenames {
            buf.clear();

            let mut f = File::open(filename)?;
            f.read_to_string(&mut buf)?;

            for line in buf.lines() {
                // Skip empty lines and comments
                if !(line.is_empty() || line.find('#') == Some(0)) {
                    if let Some(key) = age::SecretKey::from_str(line) {
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

fn read_passphrase() -> io::Result<String> {
    // TODO: Require a TTY
    eprint!("Type passphrase: ");

    // TODO: Hide passphrase in TTY
    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;

    Ok(passphrase)
}

fn generate_new_key() {
    let sk = age::SecretKey::new();

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

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,
}

fn encrypt(opts: AgeOptions) {
    let recipients = if opts.passphrase {
        if !opts.arguments.is_empty() {
            eprintln!("Positional arguments are not accepted when using a passphrase");
            return;
        }

        match read_passphrase() {
            Ok(passphrase) => vec![age::RecipientKey::Scrypt(passphrase)],
            Err(_) => return,
        }
    } else {
        match read_recipients(opts.arguments) {
            Ok(recipients) => recipients,
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

    let output = match file_io::OutputWriter::new(opts.output) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to open output: {}", e);
            return;
        }
    };

    match age::encrypt_message(output, &recipients) {
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
    let keys = if opts.passphrase {
        if !opts.arguments.is_empty() {
            eprintln!("Positional arguments are not accepted when using a passphrase");
            return;
        }

        match read_passphrase() {
            Ok(passphrase) => vec![age::SecretKey::Scrypt(passphrase)],
            Err(_) => return,
        }
    } else {
        match read_keys(opts.arguments) {
            Ok(keys) => keys,
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

    let mut output = match file_io::OutputWriter::new(opts.output) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to open output: {}", e);
            return;
        }
    };

    let maybe_decrypted = age::decrypt_message(input, &keys);

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
