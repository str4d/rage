use age::cli_common::{read_identities, read_passphrase};
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
    Age(age::Error),
    Io(io::Error),
    MissingFilename,
    MissingIdentities,
    MissingMountpoint,
    MissingType,
    MixedIdentityAndPassphrase,
    UnknownType(String),
    UnsupportedKey(String, age::keys::UnsupportedKey),
}

impl From<age::Error> for Error {
    fn from(e: age::Error) -> Self {
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
            Error::Age(e) => writeln!(f, "{}", e),
            Error::Io(e) => writeln!(f, "{}", e),
            Error::MissingFilename => writeln!(f, "Missing filename"),
            Error::MissingIdentities => {
                writeln!(f, "Missing identities.")?;
                writeln!(f, "Did you forget to specify -i/--identity?")
            }
            Error::MissingMountpoint => writeln!(f, "Missing mountpoint"),
            Error::MissingType => writeln!(f, "Missing -t/--types"),
            Error::MixedIdentityAndPassphrase => {
                writeln!(f, "-i/--identity can't be used with -p/--passphrase")
            }
            Error::UnknownType(t) => writeln!(f, "Unknown filesystem type \"{}\"", t),
            Error::UnsupportedKey(filename, k) => {
                writeln!(f, "Unsupported key: {}", filename)?;
                writeln!(f)?;
                writeln!(f, "{}", k)
            }
        }?;
        writeln!(f)?;
        writeln!(
            f,
            "[ Did rage not do what you expected? Could an error be more useful? ]"
        )?;
        write!(
            f,
            "[ Tell us: https://github.com/str4d/rage/issues/new/choose          ]"
        )
    }
}

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

fn main() -> Result<(), Error> {
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeMountOptions::parse_args_default_or_exit();

    if opts.filename.is_empty() {
        return Err(Error::MissingFilename);
    }
    if opts.mountpoint.is_empty() {
        return Err(Error::MissingMountpoint);
    }
    if opts.types.is_empty() {
        return Err(Error::MissingType);
    }

    let decryptor = if opts.passphrase {
        if !opts.identity.is_empty() {
            return Err(Error::MixedIdentityAndPassphrase);
        }

        match read_passphrase("Type passphrase", false) {
            Ok(passphrase) => age::Decryptor::Passphrase(passphrase),
            Err(_) => return Ok(()),
        }
    } else {
        if opts.identity.is_empty() {
            return Err(Error::MissingIdentities);
        }

        let identities = read_identities(opts.identity)?;

        // Check for unsupported keys and alert the user
        for identity in &identities {
            if let age::keys::IdentityKey::Unsupported(k) = identity.key() {
                return Err(Error::UnsupportedKey(
                    identity.filename().unwrap_or_default().to_string(),
                    k.clone(),
                ));
            }
        }

        age::Decryptor::Keys(identities)
    };

    info!("Decrypting {}", opts.filename);
    let file = File::open(opts.filename)?;

    let stream =
        decryptor.trial_decrypt_seekable(file, |prompt| read_passphrase(prompt, false).ok())?;

    match opts.types.as_str() {
        "tar" => mount_fs(|| crate::tar::AgeTarFs::open(stream), opts.mountpoint),
        "zip" => mount_fs(|| crate::zip::AgeZipFs::open(stream), opts.mountpoint),
        _ => {
            return Err(Error::UnknownType(opts.types));
        }
    };

    Ok(())
}
