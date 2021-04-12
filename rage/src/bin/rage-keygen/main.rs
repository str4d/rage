#![forbid(unsafe_code)]

use age::cli_common::file_io;
use gumdrop::Options;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use log::error;
use rust_embed::RustEmbed;
use secrecy::ExposeSecret;
use std::io::Write;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Translations;

const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};
}

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(help = "Write the result to the file at path OUTPUT. Defaults to standard output.")]
    output: Option<String>,
}

fn main() {
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

    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.version {
        println!("rage-keygen {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut output =
        match file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Text, 0o600) {
            Ok(output) => output,
            Err(e) => {
                error!(
                    "{}",
                    i18n_embed_fl::fl!(
                        LANGUAGE_LOADER,
                        "err-failed-to-open-output",
                        err = e.to_string()
                    )
                );
                return;
            }
        };

    let sk = age::x25519::Identity::generate();
    let pk = sk.to_public();

    if let Err(e) = (|| {
        if !output.is_terminal() {
            eprintln!("{}: {}", fl!("tty-pubkey"), pk);
        }

        writeln!(
            output,
            "# {}: {}",
            fl!("identity-file-created"),
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# {}: {}", fl!("identity-file-pubkey"), pk)?;
        writeln!(output, "{}", sk.to_string().expose_secret())
    })() {
        error!(
            "{}",
            i18n_embed_fl::fl!(
                LANGUAGE_LOADER,
                "err-failed-to-write-output",
                err = e.to_string()
            )
        );
    }
}
