use clap::{App, Arg};
use clap_generate::{generate, generators, Generator};
use std::fs::{create_dir_all, File};

const COMPLETIONS_DIR: &str = "./target/completions";

fn generate_completion<G: Generator, S: Into<String>>(
    app: &mut App,
    bin_name: S,
    file_name: String,
) {
    let mut file = File::create(format!("{}/{}", COMPLETIONS_DIR, file_name))
        .expect("Should be able to open file in target directory");
    generate::<G, _>(app, bin_name, &mut file);
}

fn generate_completions(mut app: App, bin_name: &str) {
    generate_completion::<generators::Bash, _>(&mut app, bin_name, format!("{}.bash", bin_name));
    generate_completion::<generators::Elvish, _>(&mut app, bin_name, format!("{}.elv", bin_name));
    generate_completion::<generators::Fish, _>(&mut app, bin_name, format!("{}.fish", bin_name));
    generate_completion::<generators::PowerShell, _>(
        &mut app,
        format!("{}.exe", bin_name),
        format!("{}.ps1", bin_name),
    );
    generate_completion::<generators::Zsh, _>(&mut app, bin_name, format!("{}.zsh", bin_name));
}

fn rage_completions() {
    let app = App::new("rage")
        .arg(Arg::new("input"))
        .arg(Arg::new("encrypt").short('e').long("encrypt"))
        .arg(Arg::new("decrypt").short('d').long("decrypt"))
        .arg(Arg::new("passphrase").short('p').long("passphrase"))
        .arg(
            Arg::new("max-work-factor")
                .takes_value(true)
                .long("max-work-factor"),
        )
        .arg(Arg::new("armor").short('a').long("armor"))
        .arg(
            Arg::new("recipient")
                .takes_value(true)
                .multiple(true)
                .short('r')
                .long("recipient"),
        )
        .arg(
            Arg::new("recipients-file")
                .takes_value(true)
                .multiple(true)
                .short('R')
                .long("recipients-file"),
        )
        .arg(
            Arg::new("identity")
                .takes_value(true)
                .multiple(true)
                .short('i')
                .long("identity"),
        )
        .arg(
            Arg::new("output")
                .takes_value(true)
                .short('o')
                .long("output"),
        );

    generate_completions(app, "rage");
}

fn rage_keygen_completions() {
    let app = App::new("rage-keygen").arg(
        Arg::new("output")
            .takes_value(true)
            .short('o')
            .long("output"),
    );

    generate_completions(app, "rage-keygen");
}

fn rage_mount_completions() {
    let app = App::new("rage-mount")
        .arg(Arg::new("filename"))
        .arg(Arg::new("mountpoint"))
        .arg(Arg::new("types").short('t').long("types"))
        .arg(
            Arg::new("max-work-factor")
                .takes_value(true)
                .long("max-work-factor"),
        )
        .arg(
            Arg::new("identity")
                .takes_value(true)
                .multiple(true)
                .short('i')
                .long("identity"),
        );

    generate_completions(app, "rage-mount");
}

fn main() {
    // Create the target directory if it does not exist.
    let _ = create_dir_all(COMPLETIONS_DIR);

    rage_completions();
    rage_keygen_completions();
    rage_mount_completions();
}
