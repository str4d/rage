use std::path::Path;

use clap::{builder::Styles, ArgAction, Parser};

use crate::fl;

fn binary_name() -> String {
    if let Some(arg) = std::env::args_os().next() {
        Path::new(&arg)
            .file_name()
            .expect("is not directory")
            .to_string_lossy()
            .to_string()
    } else {
        "rage".into()
    }
}

fn usage() -> String {
    let binary_name = binary_name();
    let recipient = fl!("recipient");
    let identity = fl!("identity");
    let input = fl!("input");
    let output = fl!("output");

    format!(
        "{binary_name} [--encrypt] -r {recipient} [-i {identity}] [-a] [-o {output}] [{input}]\n       \
        {binary_name} --decrypt [-i {identity}] [-o {output}] [{input}]",
    )
}

pub(crate) fn after_help_content(keygen_name: &str) -> String {
    fl!(
        "rage-after-help-content",
        keygen_name = keygen_name,
        example_age_pubkey = "\"age1...\"",
        example_ssh_pubkey = "\"ssh-ed25519 AAAA...\", \"ssh-rsa AAAA...\"",
    )
}

fn after_help() -> String {
    let binary_name = binary_name();
    let keygen_name = format!("{}-keygen", binary_name);
    let example_a = format!("$ {} -o key.txt", keygen_name);
    let example_a_output = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    let example_b = format!(
        "$ tar cvz ~/data | {} -r {} > data.tar.gz.age",
        binary_name, example_a_output,
    );
    let example_c = format!(
        "$ {} -d -i key.txt -o data.tar.gz data.tar.gz.age",
        binary_name,
    );

    format!(
        "{}\n\n{}",
        after_help_content(&keygen_name),
        fl!(
            "rage-after-help-example",
            example_a = example_a,
            example_a_output = example_a_output,
            example_b = example_b,
            example_c = example_c,
        ),
    )
}

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(help_template = format!("\
{{before-help}}{{about-with-newline}}
{}{}:{} {{usage}}

{{all-args}}{{after-help}}\
    ",
    Styles::default().get_usage().render(),
    fl!("usage-header"),
    Styles::default().get_usage().render_reset()))]
#[command(override_usage(usage()))]
#[command(next_help_heading = fl!("flags-header"))]
#[command(disable_help_flag(true))]
#[command(disable_version_flag(true))]
#[command(after_help(after_help()))]
pub(crate) struct AgeOptions {
    #[arg(help_heading = fl!("args-header"))]
    #[arg(value_name = fl!("input"))]
    #[arg(help = fl!("help-arg-input"))]
    pub(crate) input: Option<String>,

    #[arg(action = ArgAction::Help, short, long)]
    #[arg(help = fl!("help-flag-help"))]
    pub(crate) help: Option<bool>,

    #[arg(action = ArgAction::Version, short = 'V', long)]
    #[arg(help = fl!("help-flag-version"))]
    pub(crate) version: Option<bool>,

    #[arg(short, long)]
    #[arg(help = fl!("help-flag-encrypt"))]
    pub(crate) encrypt: bool,

    #[arg(short, long)]
    #[arg(help = fl!("help-flag-decrypt"))]
    pub(crate) decrypt: bool,

    #[arg(short, long)]
    #[arg(help = fl!("help-flag-passphrase"))]
    pub(crate) passphrase: bool,

    #[arg(long, value_name = "WF")]
    #[arg(help = fl!("help-flag-max-work-factor"))]
    pub(crate) max_work_factor: Option<u8>,

    #[arg(short, long)]
    #[arg(help = fl!("help-flag-armor"))]
    pub(crate) armor: bool,

    #[arg(short, long)]
    #[arg(value_name = fl!("recipient"))]
    #[arg(help = fl!("help-flag-recipient"))]
    pub(crate) recipient: Vec<String>,

    #[arg(short = 'R', long)]
    #[arg(value_name = fl!("recipients-file"))]
    #[arg(help = fl!("help-flag-recipients-file"))]
    pub(crate) recipients_file: Vec<String>,

    #[arg(short, long)]
    #[arg(value_name = fl!("identity"))]
    #[arg(help = fl!("help-flag-identity"))]
    pub(crate) identity: Vec<String>,

    #[arg(short = 'j')]
    #[arg(value_name = fl!("plugin-name"))]
    #[arg(help = fl!("help-flag-plugin-name"))]
    pub(crate) plugin_name: Option<String>,

    #[arg(short, long)]
    #[arg(value_name = fl!("output"))]
    #[arg(help = fl!("help-flag-output"))]
    pub(crate) output: Option<String>,
}
