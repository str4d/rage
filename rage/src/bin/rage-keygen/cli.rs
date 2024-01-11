use clap::{builder::Styles, ArgAction, Parser};

use crate::fl;

#[derive(Debug, Parser)]
#[command(display_name = "rage-keygen")]
#[command(name = "rage-keygen")]
#[command(author, version)]
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
pub(crate) struct AgeOptions {
    #[arg(action = ArgAction::Help, short, long)]
    #[arg(help = fl!("help-flag-help"))]
    pub(crate) help: Option<bool>,

    #[arg(action = ArgAction::Version, short = 'V', long)]
    #[arg(help = fl!("help-flag-version"))]
    pub(crate) version: Option<bool>,

    #[arg(short, long)]
    #[arg(value_name = fl!("output"))]
    #[arg(help = fl!("keygen-help-flag-output"))]
    pub(crate) output: Option<String>,
}
