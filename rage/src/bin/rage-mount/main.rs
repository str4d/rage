#![forbid(unsafe_code)]

use age::{
    armor::ArmoredReader,
    cli_common::{read_identities, read_secret},
    stream::StreamReader,
};
use clap::{CommandFactory, Parser};
use fuse_mt::FilesystemMT;
use fuser::MountOption;
use i18n_embed::DesktopLanguageRequester;
use log::info;

use std::fmt;
use std::fs::File;
use std::io;
use std::sync::mpsc;

mod cli;
mod tar;
mod zip;

mod i18n {
    include!("../rage/i18n.rs");
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id)
    }};

    ($message_id:literal, $($args:expr),* $(,)?) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        write!($f, "{}", fl!($message_id, $($args), *))
    };
}

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", fl!($message_id, $($args), *))
    };
}

enum Error {
    Age(age::DecryptError),
    IdentityRead(age::cli_common::ReadError),
    Io(io::Error),
    MissingFilename,
    MissingIdentities,
    MissingMountpoint,
    MissingType,
    UnknownType(String),
}

impl From<age::DecryptError> for Error {
    fn from(e: age::DecryptError) -> Self {
        Error::Age(e)
    }
}

impl From<age::cli_common::ReadError> for Error {
    fn from(e: age::cli_common::ReadError) -> Self {
        Error::IdentityRead(e)
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
                    wfl!(f, "rec-dec-excessive-work", wf = required)
                }
                _ => write!(f, "{}", e),
            },
            Error::IdentityRead(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "{}", e),
            Error::MissingFilename => wfl!(f, "err-mnt-missing-filename"),
            Error::MissingIdentities => {
                wlnfl!(f, "err-dec-missing-identities")?;
                wlnfl!(f, "rec-dec-missing-identities")
            }
            Error::MissingMountpoint => wfl!(f, "err-mnt-missing-mountpoint"),
            Error::MissingType => wfl!(f, "err-mnt-missing-types"),
            Error::UnknownType(t) => wfl!(f, "err-mnt-unknown-type", fs_type = t.as_str()),
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

fn mount_fs<T: FilesystemMT + Send + Sync + 'static, F>(
    open: F,
    mountpoint: String,
    finished: mpsc::Receiver<()>,
) -> Result<(), Error>
where
    F: FnOnce() -> io::Result<T>,
{
    let fs = open().map(|fs| fuse_mt::FuseMT::new(fs, 1))?;
    info!("{}", fl!("info-mounting-as-fuse"));

    // Mount the filesystem.
    let handle = fuser::spawn_mount2(fs, mountpoint, &[MountOption::RO])?;

    // Wait until we are done.
    finished.recv().expect("Could not receive from channel.");

    // Ensure the filesystem is unmounted.
    handle.join();

    Ok(())
}

fn mount_stream(
    stream: StreamReader<ArmoredReader<io::BufReader<File>>>,
    types: String,
    mountpoint: String,
) -> Result<(), Error> {
    // We want to block until either Ctrl-C, or the filesystem is unmounted externally.
    // Set up a channel for notifying the main thread that we should exit.
    let (tx, finished) = mpsc::sync_channel(2);
    let destroy_tx = tx.clone();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");

    match types.as_str() {
        "tar" => mount_fs(
            || crate::tar::AgeTarFs::open(stream, destroy_tx),
            mountpoint,
            finished,
        ),
        "zip" => mount_fs(
            || crate::zip::AgeZipFs::open(stream, destroy_tx),
            mountpoint,
            finished,
        ),
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

    let supported_languages =
        i18n::load_languages(&DesktopLanguageRequester::requested_languages());
    age::localizer().select(&supported_languages).unwrap();

    if console::user_attended() && args().len() == 1 {
        cli::AgeMountOptions::command().print_help()?;
        return Ok(());
    }

    let opts = cli::AgeMountOptions::parse();

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
        fl!("info-decrypting", filename = opts.filename.as_str()),
    );
    let file = File::open(opts.filename)?;

    let types = opts.types;
    let mountpoint = opts.mountpoint;

    match age::Decryptor::new_buffered(ArmoredReader::new(file))? {
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
            let identities = read_identities(opts.identity, opts.max_work_factor)?;

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
