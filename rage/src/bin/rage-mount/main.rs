#![forbid(unsafe_code)]

use age::{
    armor::ArmoredReader,
    cli_common::{read_identities, read_secret},
    stream::StreamReader,
};
use fuse_mt::FilesystemMT;
use gumdrop::Options;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use log::info;
use rust_embed::RustEmbed;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;

mod tar;
mod zip;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Translations;

const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!(LANGUAGE_LOADER, $message_id)
    }};
}

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", fl!($message_id))
    };
}

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", fl!($message_id))
    };
}

enum Error {
    Age(age::DecryptError),
    IdentityNotFound(String),
    Io(io::Error),
    MissingFilename,
    MissingIdentities,
    MissingMountpoint,
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
                    write!(
                        f,
                        "{}",
                        i18n_embed_fl::fl!(
                            LANGUAGE_LOADER,
                            "rec-dec-excessive-work",
                            wf = required
                        )
                    )
                }
                _ => write!(f, "{}", e),
            },
            Error::IdentityNotFound(filename) => write!(
                f,
                "{}",
                i18n_embed_fl::fl!(
                    LANGUAGE_LOADER,
                    "err-dec-identity-not-found",
                    filename = filename.as_str()
                )
            ),
            Error::Io(e) => write!(f, "{}", e),
            Error::MissingFilename => wfl!(f, "err-mnt-missing-filename"),
            Error::MissingIdentities => {
                wlnfl!(f, "err-dec-missing-identities")?;
                wlnfl!(f, "rec-dec-missing-identities")
            }
            Error::MissingMountpoint => wfl!(f, "err-mnt-missing-mountpoint"),
            Error::MissingType => wfl!(f, "err-mnt-missing-types"),
            Error::UnknownType(t) => write!(
                f,
                "{}",
                i18n_embed_fl::fl!(
                    LANGUAGE_LOADER,
                    "err-mnt-unknown-type",
                    fs_type = t.as_str()
                )
            ),
            Error::UnsupportedKey(filename, k) => k.display(f, Some(filename.as_str())),
        }?;
        writeln!(f)?;
        writeln!(f, "[ {} ]", fl!("err-ux-A"))?;
        write!(
            f,
            "[ {}: https://str4d.xyz/rage/report {} ]",
            fl!("err-ux-B"),
            fl!("err-ux-C")
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

fn mount_fs<T: FilesystemMT + Send + Sync + 'static, F>(
    open: F,
    mountpoint: String,
) -> Result<(), Error>
where
    F: FnOnce() -> io::Result<T>,
{
    let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("ro,auto_unmount")];

    let fs = open().map(|fs| fuse_mt::FuseMT::new(fs, 1))?;
    info!("{}", fl!("info-mounting-as-fuse"));
    fuse_mt::mount(fs, &mountpoint, &fuse_args)?;
    Ok(())
}

fn mount_stream(
    stream: StreamReader<ArmoredReader<io::BufReader<File>>>,
    types: String,
    mountpoint: String,
) -> Result<(), Error> {
    match types.as_str() {
        "tar" => mount_fs(|| crate::tar::AgeTarFs::open(stream), mountpoint),
        "zip" => mount_fs(|| crate::zip::AgeZipFs::open(stream), mountpoint),
        _ => Err(Error::UnknownType(types)),
    }
}

fn main() -> Result<(), Error> {
    use std::env::args;

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n_embed::select(&*LANGUAGE_LOADER, &TRANSLATIONS, &requested_languages).unwrap();
    age::localizer().select(&requested_languages).unwrap();
    // Unfortunately the common Windows terminals don't support Unicode Directionality
    // Isolation Marks, so we disable them for now.
    LANGUAGE_LOADER.set_use_isolating(false);

    let args = args().collect::<Vec<_>>();

    if console::user_attended() && args.len() == 1 {
        // If gumdrop ever merges that PR, that can be used here
        // instead.
        println!("{} {} [OPTIONS]", fl!("usage-header"), args[0]);
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

    info!(
        "{}",
        i18n_embed_fl::fl!(
            LANGUAGE_LOADER,
            "info-decrypting",
            filename = opts.filename.as_str()
        )
    );
    let file = File::open(opts.filename)?;

    let types = opts.types;
    let mountpoint = opts.mountpoint;

    match age::Decryptor::new(ArmoredReader::new(file))? {
        age::Decryptor::Passphrase(decryptor) => {
            match read_secret(&fl!("type-passphrase"), &fl!("prompt-passphrase"), None) {
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
                Error::IdentityNotFound,
                Error::UnsupportedKey,
            )?;

            if identities.is_empty() {
                return Err(Error::MissingIdentities);
            }

            decryptor
                .decrypt(identities.iter().map(|i| &**i))
                .map_err(|e| e.into())
                .and_then(|stream| mount_stream(stream, types, mountpoint))
        }
    }
}
