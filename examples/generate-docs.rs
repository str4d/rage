use flate2::{write::GzEncoder, Compression};
use man::prelude::*;
use std::fs::File;
use std::io::prelude::*;

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
        .arg(Arg::new("[INPUT_FILE (defaults to stdin)]"))
        .example(Example::new().text("Encryption to a public key").command(
            "echo \"_o/\" | rage -o hello.age -r pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I",
        ))
        .example(
            Example::new()
                .text("Encryption to multiple public keys (with default output to stdout)")
                .command(
                    "echo \"_o/\" | rage -r pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I \
                     -r pubkey:jqmfMHBjlb7HoIjjTsCQ9NHIk_q53Uy_ZxmXBhdIpx4 > hello.age",
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

    let file = File::create("./target/rage.1.gz")
        .expect("Should be able to open file in target directory");
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
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

    let file = File::create("./target/rage-keygen.1.gz")
        .expect("Should be able to open file in target directory");
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
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
                .short("-t")
                .long("--types")
                .help("The type of the filesystem (one of \"tar\", \"zip\")"),
        )
        .flag(
            Flag::new()
                .short("-p")
                .long("--passphrase")
                .help("Use a passphrase instead of public keys"),
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
                .command("rage-mount -t tar encrypted.tar.age ./tmp key.txt"),
        )
        .example(
            Example::new()
                .text("Mounting an archive encrypted with a passphrase")
                .command("rage-mount -t zip -p encrypted.zip.age ./tmp")
                .output("Type passphrase:"),
        )
        .render();

    let file = File::create("./target/rage-mount.1.gz")
        .expect("Should be able to open file in target directory");
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
}

fn main() {
    rage_page();
    rage_keygen_page();
    rage_mount_page();
}
