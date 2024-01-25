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

/// Formats localized text.
///
/// We only support one kind of formatting: italics via `the _underscore_ method`.
fn format_localized(content: String) -> Vec<Inline> {
    if let Some((l, r)) = content.split_once(" _") {
        Some(Inline::Roman(l.into()))
            .into_iter()
            .chain(r.split(" _").flat_map(|s| {
                let (l, r) = s
                    .split_once("_ ")
                    .expect("italics should always be terminated");
                [
                    Inline::Roman(" ".into()),
                    Inline::Italic(l.into()),
                    Inline::Roman(format!(" {r}")),
                ]
            }))
            .collect()
    } else {
        vec![Inline::Roman(content)]
    }
}

struct ManpageSection(Roff);

impl ManpageSection {
    fn new(heading: String) -> Self {
        let mut roff = Roff::default();
        roff.control("SH", [heading.as_str()]);
        Self(roff)
    }

    fn subheading(mut self, subheading: String) -> Self {
        self.0.control("SS", [subheading.as_str()]);
        self
    }

    fn paragraph(mut self, content: String) -> Self {
        self.0.text(format_localized(content));
        self
    }

    fn render(self, w: &mut impl io::Write) -> io::Result<()> {
        self.0.to_writer(w)
    }
}

struct Example {
    text: String,
    commands: Vec<ExampleCommand>,
}

struct ExampleCommand {
    cmd: &'static str,
    output: Vec<String>,
}

impl Example {
    const fn new(text: String) -> Self {
        Self {
            text,
            commands: vec![],
        }
    }

    fn cmd(self, cmd: &'static str) -> Self {
        self.cmd_out(cmd, vec![])
    }

    fn cmd_out(mut self, cmd: &'static str, output: Vec<String>) -> Self {
        self.commands.push(ExampleCommand { cmd, output });
        self
    }
}

struct Examples<const N: usize>([Example; N]);

impl<const N: usize> Examples<N> {
    fn render(self, w: &mut impl io::Write) -> io::Result<()> {
        let mut roff = Roff::default();
        roff.control("SH", [fl!("man-examples-heading").as_str()]);
        for example in self.0 {
            roff.control("TP", []);
            roff.text(
                [
                    Inline::Roman(format!("{}:", example.text)),
                    Inline::LineBreak,
                ]
                .into_iter()
                .chain(example.commands.into_iter().flat_map(|example| {
                    example
                        .cmd
                        .lines()
                        .enumerate()
                        .flat_map(|(i, line)| {
                            // For all lines except the last, append a `\` to concatenate.
                            // As `str::lines` is not an `ExactSizeIterator`, we "prepend"
                            // to the line after, prior to the separating line break.
                            (i != 0)
                                .then(|| [Inline::Bold(" \\".into()), Inline::LineBreak])
                                .into_iter()
                                .flatten()
                                .chain(Some(Inline::Bold(format!(
                                    "{} {}",
                                    if i == 0 { '$' } else { ' ' },
                                    line
                                ))))
                        })
                        .chain(Some(Inline::LineBreak))
                        .chain(
                            example
                                .output
                                .into_iter()
                                .flat_map(|output| [Inline::Roman(output), Inline::LineBreak]),
                        )
                        .chain(Some(Inline::LineBreak))
                }))
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
            see_also: &str,
            cmd: Command,
            custom: impl FnOnce(&Man, &mut GzEncoder<fs::File>) -> io::Result<()>,
        ) -> io::Result<()> {
            let file = fs::File::create(out_dir.join(format!("{}.1.gz", name)))?;
            let mut w = GzEncoder::new(file, Compression::best());

            let man = Man::new(cmd);
            man.render_title(&mut w)?;
            man.render_name_section(&mut w)?;
            man.render_synopsis_section(&mut w)?;
            man.render_description_section(&mut w)?;
            man.render_options_section(&mut w)?;
            custom(&man, &mut w)?;
            ManpageSection::new(fl!("man-see-also-heading"))
                .paragraph(see_also.into())
                .render(&mut w)?;
            man.render_version_section(&mut w)?;
            man.render_authors_section(&mut w)
        }

        #[cfg(feature = "mount")]
        let (rage_see_also, rage_keygen_see_also) =
            ("rage-keygen(1), rage-mount(1)", "rage(1), rage-mount(1)");

        #[cfg(not(feature = "mount"))]
        let (rage_see_also, rage_keygen_see_also) = ("rage-keygen(1)", "rage(1)");

        generate_manpage(
            out_dir,
            "rage",
            rage_see_also,
            self.rage
                .about(fl!("man-rage-about"))
                .long_about(fl!("man-rage-description"))
                .mut_arg("output", |a| a.long_help(fl!("man-rage-flag-output")))
                .mut_arg("encrypt", |a| a.long_help(fl!("man-rage-flag-encrypt")))
                .mut_arg("recipient", |a| a.long_help(fl!("man-rage-flag-recipient")))
                .mut_arg("recipients_file", |a| {
                    a.long_help(fl!("man-rage-flag-recipients-file"))
                })
                .mut_arg("passphrase", |a| {
                    a.long_help(fl!("man-rage-flag-passphrase"))
                })
                .mut_arg("armor", |a| a.long_help(fl!("man-rage-flag-armor")))
                .mut_arg("decrypt", |a| a.long_help(fl!("man-rage-flag-decrypt")))
                .mut_arg("identity", |a| {
                    a.long_help(fl!("man-rage-flag-identity-decrypt"))
                })
                .mut_arg("plugin_name", |a| {
                    a.long_help(fl!("man-rage-flag-plugin-decrypt"))
                })
                .after_help(rage::after_help_content("rage-keygen")),
            |_, w| {
                ManpageSection::new(fl!("man-rage-recipients-and-identities-heading"))
                    .paragraph(fl!("man-rage-recipients-and-identities"))
                    .subheading(fl!("man-rage-native-x25519-keys-heading"))
                    .paragraph(fl!(
                        "man-rage-native-x25519-keys",
                        example_age_recipient = "age1gde3ncmahlqd9gg50tanl99r960llztrhfapnmx853s4tjum03uqfssgdh",
                        example_age_identity =
                            "AGE-SECRET-KEY-1KTYK6RVLN5TAPE7VF6FQQSKZ9HWWCDSKUGXXNUQDWZ7XXT5YK5LSF3UTKQ",
                    ))
                    .subheading(fl!("man-rage-ssh-keys-heading"))
                    .paragraph(fl!(
                        "man-rage-ssh-keys",
                        example_ssh_rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDULTit0KUehbi[...]GU4BtElAbzh8=",
                        example_ssh_ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9pO5pz22JZEas[...]l1uZc31FGYMXa",
                    ))
                    .subheading(fl!("man-rage-plugins-heading"))
                    .paragraph(fl!("man-rage-plugins"))
                    .render(w)?;

                Examples([
                    Example::new(fl!("man-rage-example-single"))
                        .cmd_out(
                            "rage-keygen -o key.txt",
                            vec![format!(
                                "{}: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
                                fl!("tty-pubkey")
                            )],
                        )
                        .cmd("tar cvz ~/data | rage -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age")
                        .cmd("rage -d -o data.tar.gz -i key.txt data.tar.gz.age"),
                    Example::new(fl!(
                        "man-rage-example-enc-multiple",
                        input = "example.jpg",
                        output = "example.jpg.age"
                    ))
                    .cmd(
                        "rage -o example.jpg.age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n     \
                              -r age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg example.jpg",
                    ),
                    Example::new(fl!("man-rage-example-enc-list"))
                        .cmd_out(
                            "cat > recipients.txt",
                            vec![
                                "# Alice".into(),
                                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".into(),
                                "# Bob".into(),
                                "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg".into(),
                            ],
                        )
                        .cmd("rage -R recipients.txt example.jpg > example.jpg.age"),
                    Example::new(fl!("man-rage-example-password"))
                        .cmd_out(
                            "rage -p secrets.txt > secrets.txt.age",
                            vec![
                                fl!("autogenerated-passphrase"),
                                "    release-response-step-brand-wrap-ankle-pair-unusual-sword-train".into(),
                            ],
                        )
                        .cmd_out(
                            "rage -d secrets.txt.age > secrets.txt",
                            vec![format!("{}:", fl!("type-passphrase"))],
                        ),
                    Example::new(fl!("man-rage-example-identity-passphrase"))
                        .cmd_out(
                            "rage -p <(rage-keygen) > key.age",
                            vec![
                                format!(
                                    "{}: age1yhm4gctwfmrpz87tdslm550wrx6m79y9f2hdzt0lndjnehwj0ukqrjpyx5",
                                    fl!("tty-pubkey")
                                ),
                                fl!("autogenerated-passphrase"),
                                "    hip-roast-boring-snake-mention-east-wasp-honey-input-actress".into(),
                            ],
                        )
                        .cmd("rage -r age1yhm4gctwfmrpz87tdslm550wrx6m79y9f2hdzt0lndjnehwj0ukqrjpyx5 secrets.txt > secrets.txt.age")
                        .cmd_out(
                            "rage -d -i key.age secrets.txt.age > secrets.txt",
                            vec![format!("{}:", fl!("type-passphrase"))],
                        ),
                    Example::new(fl!("man-rage-example-ssh"))
                        .cmd("rage -R ~/.ssh/id_ed25519.pub example.jpg > example.jpg.age")
                        .cmd("rage -d -i ~/.ssh/id_ed25519 example.jpg.age > example.jpg"),
                    Example::new(fl!("man-rage-example-yubikey"))
                        .cmd_out("age-plugin-yubikey", vec![format!("# {}", fl!("man-rage-example-yubikey-setup"))])
                        .cmd(
                            "rage -r age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t secrets.txt > secrets.txt.age",
                        )
                        .cmd("rage -d -i age-yubikey-identity-388178f3.txt secrets.txt.age"),
                    Example::new(fl!("man-rage-example-enc-github"))
                        .cmd("curl https://github.com/benjojo.keys | rage -R - example.jpg > example.jpg.age"),
                ])
                .render(w)
            },
        )?;
        generate_manpage(
            out_dir,
            "rage-keygen",
            rage_keygen_see_also,
            self.rage_keygen
                .about(fl!("man-keygen-about"))
                .long_about(fl!("man-keygen-description"))
                .mut_arg("output", |a| a.long_help(fl!("man-keygen-flag-output")))
                .mut_arg("convert", |a| a.long_help(fl!("man-keygen-flag-convert"))),
            |_, w| {
                Examples([
                    Example::new(fl!("man-keygen-example-stdout")).cmd_out(
                        "rage-keygen",
                        vec![
                            format!("# {}: 2021-01-02T15:30:45+01:00", fl!("identity-file-created")),
                            format!(
                                "# {}: age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z",
                                fl!("identity-file-pubkey"),
                            ),
                            "AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9".to_owned(),
                        ],
                    ),
                    Example::new(fl!("man-keygen-example-file", filename = "key.txt")).cmd_out(
                        "rage-keygen -o key.txt",
                        vec![format!(
                            "{}: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
                            fl!("tty-pubkey")
                        )],
                    ),
                    Example::new(fl!("man-keygen-example-convert")).cmd_out(
                        "rage-keygen -y key.txt",
                        vec!["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned()],
                    ),
                ])
                .render(w)
            },
        )?;
        #[cfg(feature = "mount")]
        generate_manpage(
            out_dir,
            "rage-mount",
            "rage-keygen(1), rage(1)",
            self.rage_mount
                .about(fl!("man-mount-about"))
                .long_about(fl!("man-mount-description"))
                .mut_arg("types", |a| {
                    a.long_help(fl!(
                        "man-mount-flag-types",
                        types = crate::rage_mount::TYPES,
                    ))
                })
                .mut_arg("identity", |a| {
                    a.long_help(fl!("man-rage-flag-identity-decrypt"))
                }),
            |_, w| {
                Examples([
                    Example::new(fl!("man-mount-example-identity"))
                        .cmd("rage-mount -t tar -i key.txt encrypted.tar.age ./tmp"),
                    Example::new(fl!("man-mount-example-passphrase")).cmd_out(
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
