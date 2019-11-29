use man::prelude::*;
use std::fs::File;
use std::io::prelude::*;

fn rage_page() {
    let page = Manual::new("rage")
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
            Opt::new("input")
                .short("-i")
                .long("--input")
                .help("The file path to read input from (defaults to stdin)"),
        )
        .option(
            Opt::new("output")
                .short("-o")
                .long("--output")
                .help("The file path to write output to (defaults to stdout)"),
        )
        .option(
            Opt::new("aliases")
                .long("--aliases")
                .help("The list of aliases to load (defaults to ~/.config/age/aliases.txt)"),
        )
        .arg(Arg::new("[arguments...]"))
        .example(Example::new().text("Encryption to a public key").command(
            "echo \"_o/\" | rage -o hello.age pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I",
        ))
        .example(
            Example::new()
                .text("Encryption to multiple public keys (with default output to stdout)")
                .command(
                    "echo \"_o/\" | rage pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I \
                     pubkey:jqmfMHBjlb7HoIjjTsCQ9NHIk_q53Uy_ZxmXBhdIpx4 > hello.age",
                ),
        )
        .example(
            Example::new()
                .text("Encryption with a password (interactive only, use public keys for batch!)")
                .command("rage -i hello.txt -o hello.txt.age -p")
                .output("Type passphrase:"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of recipients in a file")
                .command("tar cv ~/xxx | rage recipients.txt > xxx.tar.age"),
        )
        .example(
            Example::new()
                .text("Encryption to a list of age recipients at a URL")
                .command(
                    "echo \"_o/\" | rage -o hello.age \
                     https://filippo.io/.well-known/age.keys > hello.age",
                ),
        )
        .example(
            Example::new()
                .text(
                    "Encryption to a GitHub user \
                     (equivalent to https://github.com/str4d.keys)",
                )
                .command("echo \"_o/\" | rage github:str4d | nc 192.0.2.0 1234"),
        )
        .example(
            Example::new()
                .text("Encryption to an alias")
                .command("tar cv ~/xxx | rage alias:str4d > xxx.tar.age"),
        )
        .example(
            Example::new()
                .text("Decryption with keys at ~/.config/age/keys.txt")
                .command("rage --decrypt -i hello.age")
                .output("_o/"),
        )
        .example(
            Example::new()
                .text("Decryption with custom keys")
                .command("rage -d -o hello -i hello.age keyA.txt keyB.txt"),
        )
        .render();

    let mut file =
        File::create("./target/rage.1").expect("Should be able to open file in target directory");
    file.write_all(page.as_bytes())
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

    let mut file = File::create("./target/rage-keygen.1")
        .expect("Should be able to open file in target directory");
    file.write_all(page.as_bytes())
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
        .arg(Arg::new("filename"))
        .arg(Arg::new("mountpoint"))
        .arg(Arg::new("[keys...]"))
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

    let mut file = File::create("./target/rage-mount.1")
        .expect("Should be able to open file in target directory");
    file.write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
}

fn main() {
    rage_page();
    rage_keygen_page();
    rage_mount_page();
}
