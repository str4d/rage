use dialoguer::PasswordInput;
use gumdrop::Options;
use log::{error, info};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;

mod zip;

/// Returns the age config directory.ALIAS_PREFIX
///
/// Replicates the behaviour of [os.UserConfigDir] from Golang, which the
/// reference implementation uses. See [this issue] for more details.
///
/// [os.UserConfigDir]: https://golang.org/pkg/os/#UserConfigDir
/// [this issue]: https://github.com/FiloSottile/age/issues/15
fn get_config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::data_dir()
    }

    #[cfg(not(target_os = "macos"))]
    {
        dirs::config_dir()
    }
}

/// Reads keys from the provided files if given, or the default system locations
/// if no files are given.
fn read_keys(filenames: Vec<String>) -> io::Result<Vec<age::SecretKey>> {
    let mut keys = vec![];

    if filenames.is_empty() {
        let default_filename = get_config_dir()
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
        keys.extend(age::SecretKey::from_data(buf)?);
    } else {
        for filename in filenames {
            let buf = BufReader::new(File::open(filename)?);
            keys.extend(age::SecretKey::from_data(buf)?);
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

#[derive(Debug, Options)]
struct AgeMountOptions {
    #[options(free, help = "The encrypted ZIP file to mount")]
    filename: String,

    #[options(free, help = "The directory to mount the file at")]
    mountpoint: String,

    #[options(free, help = "key files for decryption")]
    keys: Vec<String>,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,
}

fn main() {
    env_logger::init();

    let opts = AgeMountOptions::parse_args_default_or_exit();

    if opts.filename.is_empty() {
        error!("Missing filename");
        return;
    }
    if opts.mountpoint.is_empty() {
        error!("Missing mountpoint");
        return;
    }

    let decryptor = if opts.passphrase {
        if !opts.keys.is_empty() {
            error!("Keys are not accepted when using a passphrase");
            return;
        }

        match read_passphrase(false) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        match read_keys(opts.keys) {
            Ok(keys) => age::Decryptor::Keys(keys),
            Err(e) => {
                error!("Error while reading keys: {}", e);
                return;
            }
        }
    };

    info!("Decrypting {}", opts.filename);
    let filesystem = match crate::zip::AgeZipFs::open(opts.filename, decryptor) {
        Ok(fs) => fs,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };

    let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("ro,auto_unmount")];

    info!("Mounting as FUSE filesystem");
    fuse_mt::mount(
        fuse_mt::FuseMT::new(filesystem, 1),
        &opts.mountpoint,
        &fuse_args,
    )
    .unwrap();
}
