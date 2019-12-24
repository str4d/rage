use age_plugin::recipient;
use gumdrop::Options;
use std::io;

mod format;
mod p256;
mod plugin;

const RECIPIENT_PREFIX: &str = "age1yubikey";
const RECIPIENT_TAG: &str = "yubikey";

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run as an age recipient plugin", no_short)]
    recipient_plugin_v1: bool,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if opts.recipient_plugin_v1 {
        recipient::run_v1(plugin::RecipientPlugin::default())
    } else {
        // TODO: Key generation
        Ok(())
    }
}
