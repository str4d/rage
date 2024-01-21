use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use clap::{Command, CommandFactory, ValueEnum};
use clap_complete::{generate_to, Shell};
use clap_mangen::{
    roff::{Inline, Roff},
    Man,
};
use flate2::{write::GzEncoder, Compression};
use i18n_embed::unic_langid::LanguageIdentifier;

mod i18n {
    include!("src/bin/rage/i18n.rs");
}
mod rage {
    include!("src/bin/rage/cli.rs");
}
mod rage_keygen {
    include!("src/bin/rage-keygen/cli.rs");
}
#[cfg(feature = "mount")]
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

struct Example {
    text: String,
    cmd: &'static str,
    output: Vec<String>,
}

impl Example {
    const fn new(text: String, cmd: &'static str, output: Vec<String>) -> Self {
        Self { text, cmd, output }
    }
}

struct Examples<const N: usize>([Example; N]);

impl<const N: usize> Examples<N> {
    fn render(self, w: &mut impl io::Write) -> io::Result<()> {
        let mut roff = Roff::default();
        roff.control("SH", ["EXAMPLES"]);
        for example in self.0 {
            roff.control("TP", []);
            roff.text(
                [
                    Inline::Roman(format!("{}:", example.text)),
                    Inline::LineBreak,
                    Inline::Bold(format!("$ {}", example.cmd)),
                    Inline::LineBreak,
                ]
                .into_iter()
                .chain(
                    example
                        .output
                        .into_iter()
                        .flat_map(|output| [Inline::Roman(output), Inline::LineBreak]),
                )
                .collect::<Vec<_>>(),
            );
        }
        roff.to_writer(w)
    }
}

#[derive(Clone)]
struct Cli {
    rage: Command,
    rage_keygen: Command,
    #[cfg(feature = "mount")]
    rage_mount: Command,
}

impl Cli {
    fn build() -> Self {
        Self {
            rage: rage::AgeOptions::command(),
            rage_keygen: rage_keygen::AgeOptions::command(),
            #[cfg(feature = "mount")]
            rage_mount: rage_mount::AgeMountOptions::command(),
        }
    }

    fn generate_completions(&mut self, out_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(out_dir)?;

        for &shell in Shell::value_variants() {
            generate_to(shell, &mut self.rage, "rage", out_dir)?;
            generate_to(shell, &mut self.rage_keygen, "rage-keygen", out_dir)?;
            #[cfg(feature = "mount")]
            generate_to(shell, &mut self.rage_mount, "rage-mount", out_dir)?;
        }

        Ok(())
    }

    fn generate_manpages(self, out_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(out_dir)?;

        fn generate_manpage(
            out_dir: &Path,
            name: &str,
            cmd: Command,
            custom: impl FnOnce(&Man, &mut GzEncoder<fs::File>) -> io::Result<()>,
        ) -> io::Result<()> {
            let file = fs::File::create(out_dir.join(format!("{}.1.gz", name)))?;
            let mut w = GzEncoder::new(file, Compression::best());

            let man = Man::new(cmd);
            man.render_title(&mut w)?;
            man.render_name_section(&mut w)?;
            man.render_synopsis_section(&mut w)?;
            man.render_options_section(&mut w)?;
            custom(&man, &mut w)?;
            man.render_version_section(&mut w)?;
            man.render_authors_section(&mut w)
        }

        generate_manpage(
            out_dir,
            "rage",
            self.rage
                .about(fl!("man-rage-about"))
                .after_help(rage::after_help_content("rage-keygen")),
            |man, w| {
                man.render_extra_section(w)?;
                Examples([
                    Example::new(
                        fl!("man-rage-example-enc-single"),
                        "echo \"_o/\" | rage -o hello.age -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-rage-example-enc-multiple"),
                        "echo \"_o/\" | rage -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u \
                                -r age1ex4ty8ppg02555at009uwu5vlk5686k3f23e7mac9z093uvzfp8sxr5jum > hello.age",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-rage-example-enc-password"),
                        "rage -p -o hello.txt.age hello.txt",
                        vec![format!("{}:", fl!("type-passphrase"))],
                    ),
                    Example::new(
                        fl!("man-rage-example-enc-list"),
                        "tar cv ~/xxx | rage -R recipients.txt > xxx.tar.age",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-rage-example-enc-identities"),
                        "tar cv ~/xxx | rage -e -i keyA.txt -i keyB.txt > xxx.tar.age",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-rage-example-enc-url"),
                        "echo \"_o/\" | rage -o hello.age -R <(curl https://github.com/str4d.keys)",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-rage-example-dec-identities"),
                        "rage -d -o hello -i keyA.txt -i keyB.txt hello.age",
                        vec![],
                    ),
                ])
                .render(w)
            },
        )?;
        generate_manpage(
            out_dir,
            "rage-keygen",
            self.rage_keygen.about(fl!("man-keygen-about")),
            |_, w| {
                Examples([
                    Example::new(
                        fl!("man-keygen-example-stdout"),
                        "rage-keygen",
                        vec![
                            format!(
                                "# {}: 2021-01-02T15:30:45+01:00",
                                fl!("identity-file-created"),
                            ),
                            format!(
                                "# {}: age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z",
                                fl!("identity-file-pubkey"),
                            ),
                            "AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9".to_owned(),
                        ],
                    ),
                    Example::new(
                        fl!("man-keygen-example-file"),
                        "rage-keygen -o key.txt",
                        vec![format!(
                            "{}: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
                            fl!("tty-pubkey")
                        )],
                    ),
                    Example::new(
                        fl!("man-keygen-example-convert"),
                        "rage-keygen -y key.txt",
                        vec![
                            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
                                .to_owned(),
                        ],
                    ),
                ])
                .render(w)
            },
        )?;
        #[cfg(feature = "mount")]
        generate_manpage(
            out_dir,
            "rage-mount",
            self.rage_mount.about(fl!("man-mount-about")),
            |_, w| {
                Examples([
                    Example::new(
                        fl!("man-mount-example-identity"),
                        "rage-mount -t tar -i key.txt encrypted.tar.age ./tmp",
                        vec![],
                    ),
                    Example::new(
                        fl!("man-mount-example-passphrase"),
                        "rage-mount -t zip encrypted.zip.age ./tmp",
                        vec![format!("{}:", fl!("type-passphrase"))],
                    ),
                ])
                .render(w)
            },
        )?;

        Ok(())
    }
}

fn main() -> io::Result<()> {
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

    // Generate the completions in English, because these aren't easily localizable.
    i18n::load_languages(&[]);
    Cli::build().generate_completions(&out_dir.join("completions"))?;

    // Generate manpages for all supported languages.
    let manpage_dir = out_dir.join("manpages");
    for lang_dir in fs::read_dir("./i18n")? {
        let lang_dir = lang_dir?.file_name();
        let lang: LanguageIdentifier = lang_dir
            .to_str()
            .expect("should be valid Unicode")
            .parse()
            .expect("should be valid language identifier");

        // Render the manpages into the correct folder structure, so that local checks can
        // be performed with `man -M target/debug/manpages BINARY_NAME`.
        let mut out_dir = if lang.language.as_str() == "en" {
            manpage_dir.clone()
        } else {
            let mut lang_str = lang.language.as_str().to_owned();
            if let Some(region) = lang.region {
                // Locales for manpages use the POSIX format with underscores.
                lang_str += "_";
                lang_str += region.as_str();
            }
            manpage_dir.join(lang_str)
        };
        out_dir.push("man1");

        i18n::load_languages(&[lang]);
        Cli::build().generate_manpages(&out_dir)?;
    }

    Ok(())
}
