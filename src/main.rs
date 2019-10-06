use gumdrop::Options;

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(free, help = "key files")]
    keys: Vec<String>,

    #[options(help = "print help message")]
    help: bool,

    #[options(help = "generate a new key")]
    generate: bool,

    #[options(help = "decrypt a file")]
    decrypt: bool,

    #[options(help = "input file")]
    input: Option<String>,

    #[options(help = "output file")]
    output: Option<String>,
}

fn main() {
    let opts = AgeOptions::parse_args_default_or_exit();

    if opts.generate {
        println!("TODO: generate");
    } else if opts.decrypt {
        println!("TODO: decrypt");
    } else {
        println!("TODO: encrypt");
    }
}
