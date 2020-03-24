use age::cli_common::file_io;
use gumdrop::Options;
use log::error;
use secrecy::ExposeSecret;
use std::io::Write;

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
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.version {
        println!("rage-keygen {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut output =
        match file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Text, 0o600) {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to open output: {}", e);
                return;
            }
        };

    let sk = age::keys::SecretKey::generate();
    let pk = sk.to_public();

    if let Err(e) = (|| {
        if !output.is_terminal() {
            eprintln!("Public key: {}", pk);
        }

        writeln!(
            output,
            "# created: {}",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# public key: {}", pk)?;
        writeln!(output, "{}", sk.to_string().expose_secret())
    })() {
        error!("Failed to write to output: {}", e);
    }
}
