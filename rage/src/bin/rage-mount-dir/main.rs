use age::cli_common::read_identities;
use fuse_mt::FilesystemMT;
use gumdrop::Options;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use log::{error, info};
use rust_embed::RustEmbed;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::PathBuf;

mod overlay;
mod reader;
mod util;
mod wrapper;

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
    IdentityEncryptedWithoutPassphrase(String),
    IdentityNotFound(String),
    Io(io::Error),
    MissingIdentities,
    MissingMountpoint,
    MissingSource,
    MountpointMustBeDir,
    Nix(nix::Error),
    SourceMustBeDir,
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

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        Error::Nix(e)
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
            Error::IdentityEncryptedWithoutPassphrase(filename) => {
                write!(
                    f,
                    "{}",
                    i18n_embed_fl::fl!(
                        LANGUAGE_LOADER,
                        "err-dec-identity-encrypted-without-passphrase",
                        filename = filename.as_str()
                    )
                )
            }
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
            Error::MissingIdentities => {
                wlnfl!(f, "err-dec-missing-identities")?;
                wlnfl!(f, "rec-dec-missing-identities")
            }
            Error::MissingMountpoint => wfl!(f, "err-mnt-missing-mountpoint"),
            Error::MissingSource => wfl!(f, "err-mnt-missing-source"),
            Error::MountpointMustBeDir => wfl!(f, "err-mnt-must-be-dir"),
            Error::Nix(e) => write!(f, "{}", e),
            Error::SourceMustBeDir => wfl!(f, "err-mnt-source-must-be-dir"),
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
    #[options(free, help = "The directory to mount.")]
    directory: String,

    #[options(free, help = "The path to mount at.")]
    mountpoint: String,

    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(
        help = "Maximum work factor to allow for passphrase decryption.",
        meta = "WF",
        no_short
    )]
    max_work_factor: Option<u8>,

    #[options(help = "Use the identity file at IDENTITY. May be repeated.")]
    identity: Vec<String>,
}

fn mount_fs<T: FilesystemMT + Send + Sync + 'static, F>(open: F, mountpoint: PathBuf)
where
    F: FnOnce() -> io::Result<T>,
{
    let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("ro,auto_unmount")];

    match open().map(|fs| fuse_mt::FuseMT::new(fs, 1)) {
        Ok(fs) => {
            info!("{}", fl!("info-mounting-as-fuse"));
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
    use std::env::args;

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n_embed::select(&*LANGUAGE_LOADER, &TRANSLATIONS, &requested_languages).unwrap();
    age::localizer().select(&requested_languages).unwrap();

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
        println!("rage-mount-dir {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if opts.directory.is_empty() {
        return Err(Error::MissingSource);
    }
    if opts.mountpoint.is_empty() {
        return Err(Error::MissingMountpoint);
    }

    let directory = PathBuf::from(opts.directory);
    if !directory.is_dir() {
        return Err(Error::SourceMustBeDir);
    }
    let mountpoint = PathBuf::from(opts.mountpoint);
    if !mountpoint.is_dir() {
        return Err(Error::MountpointMustBeDir);
    }

    let identities = read_identities(
        opts.identity,
        opts.max_work_factor,
        Error::IdentityNotFound,
        Error::IdentityEncryptedWithoutPassphrase,
        Error::UnsupportedKey,
    )?;

    if identities.is_empty() {
        return Err(Error::MissingIdentities);
    }

    mount_fs(
        || crate::overlay::AgeOverlayFs::new(directory.into(), identities),
        mountpoint,
    );
    Ok(())
}
