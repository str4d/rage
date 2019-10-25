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

    #[options(free, help = "key files for decryption")]
    keys: Vec<String>,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "indicates the filesystem type (one of \"tar\", \"zip\")")]
    types: String,

    #[options(help = "use a passphrase instead of public keys")]
    passphrase: bool,
}

fn mount_fs<T: FilesystemMT + Send + Sync + 'static, F>(open: F, mountpoint: String)
where
    F: FnOnce() -> io::Result<T>,
{
    let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("ro,auto_unmount")];

    match open().map(|fs| fuse_mt::FuseMT::new(fs, 1)) {
        Ok(fs) => {
            info!("Mounting as FUSE filesystem");
            fuse_mt::mount(fs, &mountpoint, &fuse_args).unwrap();
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
        error!("Missing filename");
        return;
    }
    if opts.mountpoint.is_empty() {
        error!("Missing mountpoint");
        return;
    }
    if opts.types.is_empty() {
        error!("Missing filesystem type");
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
    let file = match File::open(opts.filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let stream = match decryptor.trial_decrypt_seekable(file) {
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
            return;
        }
    };
}
