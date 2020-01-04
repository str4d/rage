use age::cli_common::file_io;
use gumdrop::Options;
use log::error;
use secrecy::ExposeSecret;
use std::io::Write;

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "output to OUTPUT (default stdout)")]
    output: Option<String>,
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeOptions::parse_args_default_or_exit();

    let mut output =
        match file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Text, 0o600) {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to open output: {}", e);
                return;
            }
        };

    let sk = age::keys::SecretKey::generate();

    if let Err(e) = (|| {
        writeln!(
            output,
            "# created: {}",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# public key: {}", sk.to_public())?;
        writeln!(output, "{}", sk.to_string().expose_secret())
    })() {
        error!("Failed to write to output: {}", e);
    }
}
