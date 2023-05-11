#![forbid(unsafe_code)]

use age::{cli_common::file_io, secrecy::ExposeSecret};
use gumdrop::Options;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use log::error;
use rust_embed::RustEmbed;
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

    #[cfg(feature = "vanity")]
    #[options(
        help = "Find a public key matching this regular expression in the part after \"age1\"."
    )]
    vanity: Option<String>,
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
        match file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Text, 0o600, false) {
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

    #[cfg(feature = "vanity")]
    let (count, sk, pk) = if let Some(vanity) = opts.vanity {
        let (count, found) = keypair_matching(&vanity);
        if let Some((sk, pk)) = found {
            (count, sk, pk)
        } else {
            error!(
                "{}",
                i18n_embed_fl::fl!(
                    LANGUAGE_LOADER,
                    "err-vanity-search-interrupted",
                    count = count
                ),
            );
            return;
        }
    } else {
        let (sk, pk) = keypair();
        (1, sk, pk)
    };

    #[cfg(not(feature = "vanity"))]
    let (sk, pk) = keypair();
    #[cfg(not(feature = "vanity"))]
    let count = 1;

    if let Err(e) = (|| {
        if !output.is_terminal() {
            eprintln!("{}: {}", fl!("tty-pubkey"), pk);
        }

        writeln!(
            output,
            "# {}: {}{}",
            fl!("identity-file-created"),
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            if count > 1 {
                format!("\n# {}: {}", fl!("identity-file-vanity-count"), count)
            } else {
                "".to_string()
            }
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

fn keypair() -> (age::x25519::Identity, age::x25519::Recipient) {
    let sk = age::x25519::Identity::generate();
    let pk: age::x25519::Recipient = sk.to_public();
    (sk, pk)
}

#[cfg(feature = "vanity")]
fn keypair_matching(
    vanity: &str,
) -> (u64, Option<(age::x25519::Identity, age::x25519::Recipient)>) {
    use std::{
        fmt::Write,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    // Precompile the regex
    let vanity = regex::Regex::new(vanity).unwrap();

    // Flag to stop all the threads once the first match is found
    let stop = Arc::new(AtomicBool::new(false));

    if let Err(err) = ctrlc::set_handler({
        let stop = stop.clone();
        move || stop.store(true, Ordering::Relaxed)
    }) {
        error!(
            "{}",
            i18n_embed_fl::fl!(
                LANGUAGE_LOADER,
                "err-failed-to-set-ctrlc-handler",
                err = err.to_string()
            )
        );
        return (0, None);
    }

    let inner_loop = move |_, _| {
        let mut pk_string = String::with_capacity(58 + 4);
        let mut count: u64 = 0;
        loop {
            if stop.load(Ordering::Relaxed) {
                return (count, None);
            }
            let (sk, pk) = keypair();
            write!(pk_string, "{}", pk).unwrap();
            if vanity.is_match(&pk_string[4..]) {
                stop.store(true, Ordering::Relaxed);
                return (count, Some((sk, pk)));
            }
            pk_string.clear();
            count += 1;
        }
    };

    // Spawn a thread on each CPU, waiting for the first to finish
    let results = parallel(inner_loop);

    let count = results.iter().map(|(count, _)| count).sum::<u64>();
    (count, results.into_iter().find_map(|(_, found)| found))
}

#[cfg(feature = "vanity")]
fn parallel<T: Send>(task: impl FnMut(usize, usize) -> T + Clone + Send) -> Vec<T> {
    use std::thread::{scope, ScopedJoinHandle};

    scope(move |scope| {
        let total = num_cpus::get();
        (0..total)
            .map(move |n| {
                let mut task = task.clone();
                scope.spawn(move || task(n, total))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(ScopedJoinHandle::join)
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    })
}
