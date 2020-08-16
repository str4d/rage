#![forbid(unsafe_code)]

use age::{
    armor::ArmoredReader,
    cli_common::{read_identities, read_secret},
    stream::StreamReader,
};
use fuse_mt::FilesystemMT;
use gumdrop::Options;
use log::{error, info};
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;

mod tar;
mod zip;

enum Error {
    Age(age::DecryptError),
    IdentityNotFound(String),
    Io(io::Error),
    MissingFilename,
    MissingIdentities(String),
    MissingMountpoint,
    MissingPlugin(String),
    MissingType,
    UnknownType(String),
    UnsupportedKey(String, age::ssh::UnsupportedKey),
}

impl From<age::DecryptError> for Error {
    fn from(e: age::DecryptError) -> Self {
        Error::Age(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Age(e) => match e {
                age::DecryptError::ExcessiveWork { required, .. } => {
                    writeln!(f, "{}", e)?;
                    write!(f, "To decrypt, retry with --max-work-factor {}", required)
                }
                _ => write!(f, "{}", e),
            },
            Error::IdentityNotFound(filename) => write!(f, "Identity file not found: {}", filename),
            Error::Io(e) => writeln!(f, "{}", e),
            Error::MissingFilename => writeln!(f, "Missing filename"),
            Error::MissingIdentities(default_filename) => {
                writeln!(f, "Missing identities.")?;
                writeln!(f, "Did you forget to specify -i/--identity?")?;
                writeln!(f, "You can also store default identities in this file:")?;
                write!(f, "    {}", default_filename)
            }
            Error::MissingMountpoint => writeln!(f, "Missing mountpoint"),
            Error::MissingPlugin(name) => {
                writeln!(f, "Could not find '{}' on the PATH.", name)?;
                write!(f, "Have you installed the plugin?")
            }
            Error::MissingType => writeln!(f, "Missing -t/--types"),
            Error::UnknownType(t) => writeln!(f, "Unknown filesystem type \"{}\"", t),
            Error::UnsupportedKey(filename, k) => k.display(f, Some(filename.as_str())),
        }?;
        writeln!(f)?;
        writeln!(
            f,
            "[ Did rage not do what you expected? Could an error be more useful? ]"
        )?;
        write!(
            f,
            "[ Tell us: https://str4d.xyz/rage/report                            ]"
        )
    }
}

#[derive(Debug, Options)]
struct AgeMountOptions {
    #[options(free, help = "The encrypted filesystem to mount.")]
    filename: String,

    #[options(free, help = "The directory to mount the filesystem at.")]
    mountpoint: String,

    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(help = "Indicates the filesystem type (one of \"tar\", \"zip\").")]
    types: String,

    #[options(
        help = "Maximum work factor to allow for passphrase decryption.",
        meta = "WF",
        no_short
    )]
    max_work_factor: Option<u8>,

    #[options(help = "Use the private key file at IDENTITY. May be repeated.")]
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

fn mount_stream(
    stream: StreamReader<ArmoredReader<io::BufReader<File>>>,
    types: String,
    mountpoint: String,
) -> Result<(), Error> {
    match types.as_str() {
        "tar" => mount_fs(|| crate::tar::AgeTarFs::open(stream), mountpoint),
        "zip" => mount_fs(|| crate::zip::AgeZipFs::open(stream), mountpoint),
        _ => {
            return Err(Error::UnknownType(types));
        }
    };

    Ok(())
}

fn main() -> Result<(), Error> {
    use std::env::args;

    env_logger::builder().format_timestamp(None).init();

    let args = args().collect::<Vec<_>>();

    if console::user_attended() && args.len() == 1 {
        // If gumdrop ever merges that PR, that can be used here
        // instead.
        println!("Usage: {} [OPTIONS]", args[0]);
        println!();
        println!("{}", AgeMountOptions::usage());

        return Ok(());
    }

    let opts = AgeMountOptions::parse_args_default_or_exit();

    if opts.version {
        println!("rage-mount {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if opts.filename.is_empty() {
        return Err(Error::MissingFilename);
    }
    if opts.mountpoint.is_empty() {
        return Err(Error::MissingMountpoint);
    }
    if opts.types.is_empty() {
        return Err(Error::MissingType);
    }

    info!("Decrypting {}", opts.filename);
    let file = File::open(opts.filename)?;

    let types = opts.types;
    let mountpoint = opts.mountpoint;

    match age::Decryptor::new(ArmoredReader::new(file))? {
        age::Decryptor::Passphrase(decryptor) => {
            match read_secret("Type passphrase", "Passphrase", None) {
                Ok(passphrase) => decryptor
                    .decrypt(&passphrase, opts.max_work_factor)
                    .map_err(|e| e.into())
                    .and_then(|stream| mount_stream(stream, types, mountpoint)),
                Err(_) => Ok(()),
            }
        }
        age::Decryptor::Recipients(decryptor) => {
            let identities = read_identities(
                opts.identity,
                |default_filename| Error::MissingIdentities(default_filename.to_string()),
                |filename| Error::IdentityNotFound(filename),
                Error::MissingPlugin,
                Error::UnsupportedKey,
            )?;

            decryptor
                .decrypt(identities.into_iter())
                .map_err(|e| e.into())
                .and_then(|stream| mount_stream(stream, types, mountpoint))
        }
    }
}
