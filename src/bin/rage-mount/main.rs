use age::cli_common::{read_keys, read_passphrase};
use gumdrop::Options;
use log::{error, info};
use std::ffi::OsStr;

mod zip;

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
