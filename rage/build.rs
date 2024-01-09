use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use clap::{Command, CommandFactory, ValueEnum};
use clap_complete::{generate_to, Shell};

mod i18n {
    include!("src/bin/rage/i18n.rs");
}
mod rage {
    include!("src/bin/rage/cli.rs");
}
mod rage_keygen {
    include!("src/bin/rage-keygen/cli.rs");
}
mod rage_mount {
    include!("src/bin/rage-mount/cli.rs");
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id)
    }};

    ($message_id:literal, $($args:expr),* $(,)?) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

#[derive(Clone)]
struct Cli {
    rage: Command,
    rage_keygen: Command,
    rage_mount: Command,
}

impl Cli {
    fn build() -> Self {
        Self {
            rage: rage::AgeOptions::command(),
            rage_keygen: rage_keygen::AgeOptions::command(),
            rage_mount: rage_mount::AgeMountOptions::command(),
        }
    }

    fn generate_completions(&mut self, out_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(out_dir)?;

        for &shell in Shell::value_variants() {
            generate_to(shell, &mut self.rage, "rage", out_dir)?;
            generate_to(shell, &mut self.rage_keygen, "rage-keygen", out_dir)?;
            generate_to(shell, &mut self.rage_mount, "rage-mount", out_dir)?;
        }

        Ok(())
    }
}

fn main() -> io::Result<()> {
    i18n::load_languages();

    // `OUT_DIR` is "intentionally opaque as it is only intended for `rustc` interaction"
    // (https://github.com/rust-lang/cargo/issues/9858). Peek into the black box and use
    // it to figure out where the target directory is.
    let out_dir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(out_dir) => PathBuf::from(out_dir)
            .ancestors()
            .nth(3)
            .expect("should be absolute path")
            .to_path_buf(),
    };

    let mut cli = Cli::build();
    cli.generate_completions(&out_dir.join("completions"))?;

    Ok(())
}
