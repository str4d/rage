use age::cli_common::file_io;
use gumdrop::Options;
use std::io::Write;

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "output to OUTPUT (default stdout)")]
    output: Option<String>,
}

fn main() {
    let opts = AgeOptions::parse_args_default_or_exit();

    let mut output = match file_io::OutputWriter::new(opts.output, false) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to open output: {}", e);
            return;
        }
    };

    let sk = age::SecretKey::generate();

    if let Err(e) = (|| {
        writeln!(
            output,
            "# created: {}",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# {}", sk.to_public().to_str())?;
        writeln!(output, "{}", sk.to_str())
    })() {
        eprintln!("Failed to write to output: {}", e);
    }
}
