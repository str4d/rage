use flate2::{write::GzEncoder, Compression};
use man::prelude::*;
use std::fs::{create_dir_all, File};
use std::io::prelude::*;

const MANPAGES_DIR: &str = "./target/manpages";

fn generate_manpage(page: String, name: &str) {
    let file = File::create(format!("{}/{}.1.gz", MANPAGES_DIR, name))
        .expect("Should be able to open file in target directory");
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
}

fn rage_page() {
    let builder = Manual::new("rage")
        .about("A simple, secure, and modern encryption tool")
        .author(Author::new("Jack Grigg").email("thestr4d@gmail.com"))
        .flag(
            Flag::new()
                .short("-h")
                .long("--help")
                .help("Display help text and exit"),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version and exit"),
        )
        .flag(
            Flag::new()
                .short("-d")
                .long("--decrypt")
                .help("Decrypt the input (default is to encrypt)"),
        )
        .flag(
            Flag::new()
                .short("-p")
                .long("--passphrase")
                .help("Use a passphrase instead of public keys"),
        )
        .flag(
            Flag::new()
                .short("-a")
                .long("--armor")
                .help("Create ASCII armored output (default is age binary format)"),
        )
        .option(
            Opt::new("recipient")
                .short("-r")
                .long("--recipient")
                .help("A recipient to encrypt to (can be repeated)"),
        )
        .option(
            Opt::new("identity")
                .short("-i")
                .long("--identity")
                .help("An identity to decrypt with (can be repeated)"),
        )
        .option(
            Opt::new("output")
                .short("-o")
                .long("--output")
                .help("The file path to write output to (defaults to stdout)"),
        )
        .option(
            Opt::new("WF")
                .long("--max-work-factor")
                .help("The maximum work factor to allow for passphrase decryption"),
        )
        .arg(Arg::new("[INPUT_FILE (defaults to stdin)]"))
        .example(Example::new().text("Encryption to a public key").command(
            "echo \"_o/\" | rage -o hello.age -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u",
        ))
        .example(
            Example::new()
                .text("Encryption to multiple public keys (with default output to stdout)")
                .command(
                    "echo \"_o/\" | rage -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u \
                     -r age1ex4ty8ppg02555at009uwu5vlk5686k3f23e7mac9z093uvzfp8sxr5jum > hello.age",
                ),
        )
        .example(
            Example::new()
                .text("Encryption with a password (interactive only, use public keys for batch!)")
                .command("rage -p -o hello.txt.age hello.txt")
                .output("Type passphrase:"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of recipients in a file")
                .command("tar cv ~/xxx | rage -r recipients.txt > xxx.tar.age"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of recipients at an HTTPS URL")
                .command(
                    "echo \"_o/\" | rage -o hello.age \
                     -r https://filippo.io/.well-known/age.keys > hello.age",
                ),
        )
        .example(
            Example::new()
                .text("Decryption with keys at ~/.config/age/keys.txt")
                .command("rage --decrypt hello.age")
                .output("_o/"),
        )
        .example(
            Example::new()
                .text("Decryption with custom keys")
                .command("rage -d -o hello -i keyA.txt -i keyB.txt hello.age"),
        );
    #[cfg(feature = "unstable")]
    let builder = builder
        .option(
            Opt::new("aliases")
                .long("--aliases")
                .help("The list of aliases to load (defaults to ~/.config/age/aliases.txt)"),
        )
        .example(
            Example::new()
                .text(
                    "Encryption to a GitHub user \
                     (equivalent to https://github.com/str4d.keys)",
                )
                .command("echo \"_o/\" | rage -r github:str4d | nc 192.0.2.0 1234"),
        )
        .example(
            Example::new()
                .text("Encryption to an alias")
                .command("tar cv ~/xxx | rage -r alias:str4d > xxx.tar.age"),
        );
    let page = builder.render();

    generate_manpage(page, "rage");
}

fn rage_keygen_page() {
    let page = Manual::new("rage-keygen")
        .about("Generate age-compatible encryption key pairs")
        .author(Author::new("Jack Grigg").email("thestr4d@gmail.com"))
        .flag(
            Flag::new()
                .short("-h")
                .long("--help")
                .help("Display help text and exit"),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version and exit"),
        )
        .option(
            Opt::new("output")
                .short("-o")
                .long("--output")
                .help("The file path to write the key pair to (defaults to stdout)"),
        )
        .example(
            Example::new()
                .text("Generate a new key pair")
                .command("rage-keygen"),
        )
        .example(
            Example::new()
                .text("Generate a new key pair and save it to a file")
                .command("rage-keygen -o key.txt"),
        )
        .render();

    generate_manpage(page, "rage-keygen");
}

fn rage_mount_page() {
    let page = Manual::new("rage-mount")
        .about("Mount an age-encrypted filesystem")
        .author(Author::new("Jack Grigg").email("thestr4d@gmail.com"))
        .flag(
            Flag::new()
                .short("-h")
                .long("--help")
                .help("Display help text and exit"),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version and exit"),
        )
        .flag(
            Flag::new()
                .short("-t")
                .long("--types")
                .help("The type of the filesystem (one of \"tar\", \"zip\")"),
        )
        .option(
            Opt::new("identity")
                .short("-i")
                .long("--identity")
                .help("An identity to decrypt with (can be repeated)"),
        )
        .arg(Arg::new("filename"))
        .arg(Arg::new("mountpoint"))
        .example(
            Example::new()
                .text("Mounting an archive with keys at ~/.config/age/keys.txt")
                .command("rage-mount -t zip encrypted.zip.age ./tmp"),
        )
        .example(
            Example::new()
                .text("Mounting an archive with custom keys")
                .command("rage-mount -t tar -i key.txt encrypted.tar.age ./tmp"),
        )
        .example(
            Example::new()
                .text("Mounting an archive encrypted with a passphrase")
                .command("rage-mount -t zip encrypted.zip.age ./tmp")
                .output("Type passphrase:"),
        )
        .render();

    generate_manpage(page, "rage-mount");
}

fn main() {
    // Create the target directory if it does not exist.
    let _ = create_dir_all(MANPAGES_DIR);

    rage_page();
    rage_keygen_page();
    rage_mount_page();
}
