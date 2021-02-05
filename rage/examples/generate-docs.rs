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
                .help("Display help text and exit."),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version info and exit."),
        )
        .flag(
            Flag::new()
                .short("-e")
                .long("--encrypt")
                .help("Encrypt the input. By default, the input is encrypted."),
        )
        .flag(
            Flag::new()
                .short("-d")
                .long("--decrypt")
                .help("Decrypt the input. By default, the input is encrypted."),
        )
        .flag(
            Flag::new()
                .short("-p")
                .long("--passphrase")
                .help("Encrypt with a passphrase instead of recipients."),
        )
        .flag(
            Flag::new()
                .short("-a")
                .long("--armor")
                .help("Encrypt to a PEM encoded format."),
        )
        .option(
            Opt::new("RECIPIENT")
                .short("-r")
                .long("--recipient")
                .help("Encrypt to the specified RECIPIENT. May be repeated."),
        )
        .option(
            Opt::new("PATH")
                .short("-R")
                .long("--recipients-file")
                .help("Encrypt to the recipients listed at PATH. May be repeated."),
        )
        .option(
            Opt::new("IDENTITY")
                .short("-i")
                .long("--identity")
                .help("Use the identity file at IDENTITY. May be repeated."),
        )
        .option(
            Opt::new("OUTPUT")
                .short("-o")
                .long("--output")
                .help("Write the result to the file at path OUTPUT. Defaults to standard output."),
        )
        .option(
            Opt::new("WF")
                .long("--max-work-factor")
                .help("The maximum work factor to allow for passphrase decryption."),
        )
        .arg(Arg::new("[INPUT_FILE (defaults to stdin)]"))
        .example(Example::new().text("Encryption to a recipient").command(
            "echo \"_o/\" | rage -o hello.age -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u",
        ))
        .example(
            Example::new()
                .text("Encryption to multiple recipients (with default output to stdout)")
                .command(
                    "echo \"_o/\" | rage -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u \
                     -r age1ex4ty8ppg02555at009uwu5vlk5686k3f23e7mac9z093uvzfp8sxr5jum > hello.age",
                ),
        )
        .example(
            Example::new()
                .text("Encryption with a password (interactive only, use recipients for batch!)")
                .command("rage -p -o hello.txt.age hello.txt")
                .output("Type passphrase:"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of recipients in a file")
                .command("tar cv ~/xxx | rage -R recipients.txt > xxx.tar.age"),
        )
        .example(
            Example::new()
                .text("Encryption to several identities")
                .command("tar cv ~/xxx | rage -e -i keyA.txt -i keyB.txt > xxx.tar.age"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of recipients at an HTTPS URL")
                .command(
                    "echo \"_o/\" | rage -o hello.age -R <(curl https://github.com/str4d.keys)",
                ),
        )
        .example(
            Example::new()
                .text("Decryption with identities")
                .command("rage -d -o hello -i keyA.txt -i keyB.txt hello.age"),
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
                .help("Display help text and exit."),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version info and exit."),
        )
        .option(
            Opt::new("OUTPUT").short("-o").long("--output").help(
                "Write the key pair to the file at path OUTPUT. Defaults to standard output.",
            ),
        )
        .example(
            Example::new()
                .text("Generate a new key pair")
                .command("rage-keygen"),
        )
        .example(
            Example::new()
                .text("Generate a new key pair and save it to a file")
                .command("rage-keygen -o key.txt")
                .output(
                    "Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
                ),
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
                .help("Display help text and exit."),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version info and exit."),
        )
        .flag(
            Flag::new()
                .short("-t")
                .long("--types")
                .help("The type of the filesystem (one of \"tar\", \"zip\")."),
        )
        .option(
            Opt::new("IDENTITY")
                .short("-i")
                .long("--identity")
                .help("Use the private key file at IDENTITY. May be repeated."),
        )
        .arg(Arg::new("filename"))
        .arg(Arg::new("mountpoint"))
        .example(
            Example::new()
                .text("Mounting an archive encrypted to a recipient")
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
