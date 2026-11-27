#![forbid(unsafe_code)]

use age::{cli_common::file_io, secrecy::ExposeSecret};
use clap::Parser;
use i18n_embed::DesktopLanguageRequester;

use std::io::{self, Write};

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

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n::load_languages(&requested_languages);
    age::localizer().select(&requested_languages).unwrap();

    let opts = cli::AgeOptions::parse();

    let output = file_io::OutputWriter::new(
        // The `pq` identity file format is large enough (due to the recipient encoding)
        // that it triggers the truncation logic. Force explicit stdout so that the
        // identity output is never truncated in the TTY (unlike file decryption, the
        // output is not reproducible across calls).
        opts.output.or_else(|| Some("-".into())),
        false,
        file_io::OutputFormat::Text,
        0o600,
        false,
    )
    .map_err(error::Error::FailedToOpenOutput)?;

    if opts.convert {
        convert(opts.input, output)
    } else {
        generate(opts.pq, output).map_err(error::Error::FailedToWriteOutput)
    }
}

fn generate(pq: bool, mut output: file_io::OutputWriter) -> io::Result<()> {
    let (sk, pk) = if pq {
        let sk = age::pq::Identity::generate();
        let pk = sk.to_public();
        (sk.to_string(), pk.to_string())
    } else {
        #[allow(deprecated)]
        let sk = age::x25519::Identity::generate();
        let pk = sk.to_public();
        (sk.to_string(), pk.to_string())
    };

    writeln!(
        output,
        "# {}: {}",
        fl!("identity-file-created"),
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    )?;
    writeln!(output, "# {}: {}", fl!("identity-file-pubkey"), pk)?;
    writeln!(output, "{}", sk.expose_secret())?;

    if !output.is_terminal() {
        eprintln!("{}: {}", fl!("tty-pubkey"), pk);
    }

    Ok(())
}

fn convert(filename: Option<String>, output: file_io::OutputWriter) -> Result<(), error::Error> {
    let file = age::IdentityFile::from_input_reader(
        file_io::InputReader::new(filename).map_err(error::Error::FailedToOpenInput)?,
    )
    .map_err(error::Error::FailedToReadInput)?;

    file.write_recipients_file(output)
        .map_err(error::Error::IdentityFileConvert)?;

    Ok(())
}
