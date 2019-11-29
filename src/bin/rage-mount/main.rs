use age::cli_common::{read_keys, read_passphrase};
use fuse_mt::FilesystemMT;
use gumdrop::Options;
use log::{error, info};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

mod tar;
mod zip;

#[derive(Debug, Options)]
struct AgeMountOptions {
    #[options(free, help = "The encrypted filesystem to mount")]
    filename: String,

    #[options(free, help = "The directory to mount the filesystem at")]
    mountpoint: String,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "indicates the filesystem type (one of \"tar\", \"zip\")")]
    types: String,

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,

    #[options(help = "identity to decrypt with (may be repeated)")]
    identity: Vec<String>,
}

fn mount_fs<T: FilesystemMT + Send + Sync + 'static, F>(open: F, mountpoint: String)
where
    F: FnOnce() -> io::Result<T>,
{
    let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("ro,auto_unmount")];

    match open().map(|fs| fuse_mt::FuseMT::new(fs, 1)) {
        Ok(fs) => {
            info!("Mounting as FUSE filesystem");
            if let Err(e) = fuse_mt::mount(fs, &mountpoint, &fuse_args) {
                error!("{}", e);
            }
        }
        Err(e) => {
            error!("{}", e);
        }
    }
}

fn main() {
    env_logger::init();

    let opts = AgeMountOptions::parse_args_default_or_exit();

    if opts.filename.is_empty() {
        error!("Error: Missing filename");
        return;
    }
    if opts.mountpoint.is_empty() {
        error!("Error: Missing mountpoint");
        return;
    }
    if opts.types.is_empty() {
        error!("Error: Missing -t/--types");
        return;
    }

    let decryptor = if opts.passphrase {
        if !opts.identity.is_empty() {
            eprintln!("Error: -i/--identity can't be used with -p/--passphrase");
            return;
        }

        match read_passphrase("Type passphrase", false) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return,
        }
    } else {
        if opts.identity.is_empty() {
            eprintln!("Error: missing identities.");
            eprintln!("Did you forget to specify -i/--identity?");
            return;
        }

        match read_keys(opts.identity) {
            Ok(keys) => {
                // Check for unsupported keys and alert the user
                for key in &keys {
                    if let age::Identity::Unsupported(k) = key {
                        eprintln!("Unsupported key: {}", "TODO: key path here");
                        eprintln!();
                        eprintln!("{}", k);
                        return;
                    }
                }
                age::Decryptor::Keys(keys)
            }
            Err(e) => {
                error!("Error while reading keys: {}", e);
                return;
            }
        }
    };

    info!("Decrypting {}", opts.filename);
    let file = match File::open(opts.filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let stream = match decryptor
        .trial_decrypt_seekable(file, |prompt| read_passphrase(prompt, false).ok())
    {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to decrypt file: {}", e);
            return;
        }
    };

    match opts.types.as_str() {
        "tar" => mount_fs(|| crate::tar::AgeTarFs::open(stream), opts.mountpoint),
        "zip" => mount_fs(|| crate::zip::AgeZipFs::open(stream), opts.mountpoint),
        t => {
            error!("Unknown filesystem type \"{}\"", t);
        }
    };
}
