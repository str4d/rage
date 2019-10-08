use gumdrop::Options;
use std::fs::File;
use std::io::{self, Read, Write};

mod format;
mod keys;
mod primitives;

/// Reads a recipient from a command-line argument.
fn read_recipient(arg: String) -> io::Result<keys::RecipientKey> {
    if let Some(pk) = keys::RecipientKey::from_str(&arg) {
        Ok(pk)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recipient",
        ))
    }
}

/// Reads recipients from the provided arguments.
fn read_recipients(arguments: Vec<String>) -> io::Result<Vec<keys::RecipientKey>> {
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
fn read_keys(filenames: Vec<String>) -> io::Result<Vec<keys::SecretKey>> {
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
                    if let Some(key) = keys::SecretKey::from_str(line) {
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

/// Reads input from the given filename, or standard input if `None`.
fn read_input(input: Option<String>) -> io::Result<Vec<u8>> {
    let mut buf = vec![];

    if let Some(filename) = input {
        let mut f = File::open(filename)?;
        f.read_to_end(&mut buf)?;
    } else {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        handle.read_to_end(&mut buf)?;
    };

    Ok(buf)
}

/// Writes output to the given filename, or standard output if `None`.
fn write_output(data: &[u8], output: Option<String>) -> io::Result<()> {
    if let Some(filename) = output {
        let mut f = File::create(filename)?;
        f.write_all(&data)
    } else {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(&data)
    }
}

fn generate_new_key() {
    let sk = keys::SecretKey::new();

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
            Ok(passphrase) => vec![keys::RecipientKey::Scrypt(passphrase)],
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

    let plaintext = match read_input(opts.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error while reading input: {}", e);
            return;
        }
    };

    let mut encrypted = vec![];
    match format::encrypt_message(&mut encrypted, &recipients) {
        Ok(mut w) => {
            if let Err(e) = w.write_all(&plaintext) {
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
            return;
        }
    }

    if let Err(e) = write_output(&encrypted, opts.output) {
        eprintln!("Error while writing output: {}", e);
    }
}

fn decrypt(opts: AgeOptions) {
    let keys = if opts.passphrase {
        if !opts.arguments.is_empty() {
            eprintln!("Positional arguments are not accepted when using a passphrase");
            return;
        }

        match read_passphrase() {
            Ok(passphrase) => vec![keys::SecretKey::Scrypt(passphrase)],
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

    let input = match read_input(opts.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error while reading input: {}", e);
            return;
        }
    };

    let maybe_decrypted = format::decrypt_message(&input[..], &keys);

    match maybe_decrypted {
        Ok(mut r) => {
            let mut plaintext = vec![];
            if let Err(e) = r.read_to_end(&mut plaintext) {
                eprintln!("Error while decrypting: {}", e);
            } else if let Err(e) = write_output(&plaintext, opts.output) {
                eprintln!("Error while writing output: {}", e);
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
