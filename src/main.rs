use gumdrop::Options;
use std::fs::File;
use std::io::{self, Read, Write};

mod format;
mod keys;

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
}

fn encrypt(opts: AgeOptions) {
    let plaintext = match read_input(opts.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error while reading input: {}", e);
            return;
        }
    };

    // TODO: Real encryption!
    let encrypted = plaintext;

    if let Err(e) = write_output(&encrypted, opts.output) {
        eprintln!("Error while writing output: {}", e);
    }
}

fn decrypt(opts: AgeOptions) {
    let keys = match read_keys(opts.arguments) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Error while reading keys: {}", e);
            return;
        }
    };

    let input = match read_input(opts.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error while reading input: {}", e);
            return;
        }
    };

    let message = match format::EncryptedMessage::read(&input) {
        Ok(res) => res,
        Err(_) => {
            eprintln!("Invalid header");
            return;
        }
    };

    // TODO: Real decryption!
    let plaintext = &b"TODO: Real decryption!\n"[..];

    if let Err(e) = write_output(&plaintext, opts.output) {
        eprintln!("Error while writing output: {}", e);
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
