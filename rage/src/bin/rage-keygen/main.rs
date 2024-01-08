#![forbid(unsafe_code)]

use age::{cli_common::file_io, secrecy::ExposeSecret};
use clap::{builder::Styles, ArgAction, Parser};
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use std::io::Write;

mod error;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

lazy_static! {
    static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};

    ($message_id:literal, $($args:expr),* $(,)?) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

#[derive(Debug, Parser)]
#[command(display_name = "rage-keygen")]
#[command(name = "rage-keygen")]
#[command(version)]
#[command(help_template = format!("\
{{before-help}}{{about-with-newline}}
{}{}:{} {{usage}}

{{all-args}}{{after-help}}\
    ",
    Styles::default().get_usage().render(),
    fl!("usage-header"),
    Styles::default().get_usage().render_reset()))]
#[command(next_help_heading = fl!("flags-header"))]
#[command(disable_help_flag(true))]
#[command(disable_version_flag(true))]
struct AgeOptions {
    #[arg(action = ArgAction::Help, short, long)]
    #[arg(help = fl!("help-flag-help"))]
    help: Option<bool>,

    #[arg(action = ArgAction::Version, short = 'V', long)]
    #[arg(help = fl!("help-flag-version"))]
    version: Option<bool>,

    #[arg(short, long)]
    #[arg(value_name = fl!("output"))]
    #[arg(help = fl!("keygen-help-flag-output"))]
    output: Option<String>,
}

fn main() -> Result<(), error::Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n_embed::select(&*LANGUAGE_LOADER, &Localizations, &requested_languages).unwrap();
    age::localizer().select(&requested_languages).unwrap();
    // Unfortunately the common Windows terminals don't support Unicode Directionality
    // Isolation Marks, so we disable them for now.
    LANGUAGE_LOADER.set_use_isolating(false);

    let opts = AgeOptions::parse();

    let mut output = file_io::OutputWriter::new(
        opts.output,
        false,
        file_io::OutputFormat::Text,
        0o600,
        false,
    )
    .map_err(error::Error::FailedToOpenOutput)?;

    let sk = age::x25519::Identity::generate();
    let pk = sk.to_public();

    (|| {
        writeln!(
            output,
            "# {}: {}",
            fl!("identity-file-created"),
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# {}: {}", fl!("identity-file-pubkey"), pk)?;
        writeln!(output, "{}", sk.to_string().expose_secret())?;

        if !output.is_terminal() {
            eprintln!("{}: {}", fl!("tty-pubkey"), pk);
        }

        Ok(())
    })()
    .map_err(error::Error::FailedToWriteOutput)
}
