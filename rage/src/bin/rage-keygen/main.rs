#![forbid(unsafe_code)]

use age::{cli_common::file_io, secrecy::ExposeSecret};
use clap::Parser;

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

    let requested_languages = i18n::load_languages();
    age::localizer().select(&requested_languages).unwrap();

    let opts = cli::AgeOptions::parse();

    let output = file_io::OutputWriter::new(
        opts.output,
        false,
        file_io::OutputFormat::Text,
        0o600,
        false,
    )
    .map_err(error::Error::FailedToOpenOutput)?;

    if opts.convert {
        convert(opts.input, output)
    } else {
        generate(output).map_err(error::Error::FailedToWriteOutput)
    }
}

fn generate(mut output: file_io::OutputWriter) -> io::Result<()> {
    let sk = age::x25519::Identity::generate();
    let pk = sk.to_public();

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
}

fn convert(
    filename: Option<String>,
    mut output: file_io::OutputWriter,
) -> Result<(), error::Error> {
    let file = age::IdentityFile::from_input_reader(
        file_io::InputReader::new(filename.clone()).map_err(error::Error::FailedToOpenInput)?,
    )
    .map_err(error::Error::FailedToReadInput)?;

    let identities = file.into_identities();
    if identities.is_empty() {
        return Err(error::Error::NoIdentities { filename });
    }

    for identity in identities {
        match identity {
            age::IdentityFileEntry::Native(sk) => {
                writeln!(output, "{}", sk.to_public()).map_err(error::Error::FailedToWriteOutput)?
            }
            age::IdentityFileEntry::Plugin(id) => {
                return Err(error::Error::IdentityFileContainsPlugin {
                    filename,
                    plugin_name: id.plugin().to_string(),
                });
            }
        }
    }

    Ok(())
}
