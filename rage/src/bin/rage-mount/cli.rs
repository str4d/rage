use clap::{builder::Styles, ArgAction, Parser};

use crate::fl;

#[derive(Debug, Parser)]
#[command(display_name = "rage-mount")]
#[command(name = "rage-mount")]
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
pub(crate) struct AgeMountOptions {
    #[arg(help_heading = fl!("args-header"))]
    #[arg(value_name = fl!("mnt-filename"))]
    #[arg(help = fl!("help-arg-mnt-filename"))]
    pub(crate) filename: String,

    #[arg(help_heading = fl!("args-header"))]
    #[arg(value_name = fl!("mnt-mountpoint"))]
    #[arg(help = fl!("help-arg-mnt-mountpoint"))]
    pub(crate) mountpoint: String,

    #[arg(action = ArgAction::Help, short, long)]
    #[arg(help = fl!("help-flag-help"))]
    pub(crate) help: Option<bool>,

    #[arg(action = ArgAction::Version, short = 'V', long)]
    #[arg(help = fl!("help-flag-version"))]
    pub(crate) version: Option<bool>,

    #[arg(short, long)]
    #[arg(value_name = fl!("mnt-types"))]
    #[arg(help = fl!("help-arg-mnt-types", types = "\"tar\", \"zip\""))]
    pub(crate) types: String,

    #[arg(long, value_name = "WF")]
    #[arg(help = fl!("help-flag-max-work-factor"))]
    pub(crate) max_work_factor: Option<u8>,

    #[arg(short, long)]
    #[arg(value_name = fl!("identity"))]
    #[arg(help = fl!("help-flag-identity"))]
    pub(crate) identity: Vec<String>,
}
