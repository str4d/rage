#![forbid(unsafe_code)]

use age::{cli_common::file_io, secrecy::ExposeSecret};
use clap::Parser;

use std::io::Write;

mod cli;
mod error;

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

fn main() -> Result<(), error::Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = i18n::load_languages();
    age::localizer().select(&requested_languages).unwrap();

    let opts = cli::AgeOptions::parse();

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
