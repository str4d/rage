use age_plugin::{identity, recipient};
use gumdrop::Options;
use std::io;

mod format;
mod p256;
mod plugin;
mod yubikey;

const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const RECIPIENT_TAG: &str = "yubikey";

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run as an age recipient plugin", no_short)]
    recipient_plugin_v1: bool,

    #[options(help = "run as an age identity plugin", no_short)]
    identity_plugin_v1: bool,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if opts.recipient_plugin_v1 {
        recipient::run_v1(plugin::RecipientPlugin::default())
    } else if opts.identity_plugin_v1 {
        identity::run_v1(plugin::IdentityPlugin::default())
    } else {
        // TODO: Key generation
        Ok(())
    }
}
