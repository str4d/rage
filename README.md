# rage: Rust implementation of age

age is a simple, secure and modern encryption tool with small explicit keys, no
config options, and UNIX-style composability.

- The spec is at https://age-encryption.org/v1.
- The reference implementation is https://filippo.io/age.

rage is a Rust implementation of the age tool. It is pronounced like the Japanese
[らげ](https://translate.google.com/#view=home&op=translate&sl=ja&tl=en&text=%E3%82%89%E3%81%92)
(with a hard g).

To discuss the spec or other age related topics, please email the mailing list
at age-dev@googlegroups.com. Subscribe at
[groups.google.com/d/forum/age-dev](https://groups.google.com/d/forum/age-dev)
or by emailing age-dev+subscribe@googlegroups.com.

## Usage

```
Usage: rage [OPTIONS] [INPUT]

Positional arguments:
  INPUT                      file to read input from (default stdin)

Optional arguments:
  -h, --help                 print help message
  -d, --decrypt              decrypt the input (default is to encrypt)
  -p, --passphrase           use a passphrase instead of public keys
  -a, --armor                create ASCII armored output (default is age binary format)
  -r, --recipient RECIPIENT  recipient to encrypt to (may be repeated)
  -i, --identity IDENTITY    identity to decrypt with (may be repeated)
  -o, --output OUTPUT        output to OUTPUT (default stdout)
```

### Multiple recipients

Files can be encrypted to multiple recipients by repeating `-r/--recipient`.
Every recipient will be able to decrypt the file.

```bash
$ rage -o example.png.age -r age1uvscypafkkxt6u2gkguxet62cenfmnpc0smzzlyun0lzszfatawq4kvf2u \
    -r age1ex4ty8ppg02555at009uwu5vlk5686k3f23e7mac9z093uvzfp8sxr5jum example.png
```

### Passphrases

Files can be encrypted with a passphrase by using `-p/--passphrase`.

```bash
$ rage -p -o example.png.age example.png
Type passphrase: [hidden]
Confirm passphrase:
$ rage -d -p example.png.age >example.png
Type passphrase: [hidden]
```

## Installation

On Windows, Linux, and macOS, you can use the
[pre-built binaries](https://github.com/str4d/rage/releases).

The `rage` suite of tools are provided in the `age` Rust crate. If your system
has Rust 1.37+ installed (either via `rustup` or a system package), you can
build directly from source:

```
cargo install age
```

You can also use the `age` crate directly as a library, by adding this line to
your `Cargo.toml` (which disables the CLI tools):

```
age = { version = "0.1", default-features = false }
```

### Feature flags

- `cli` enables the `rage` and `rage-keygen` tools, and is enabled by default.

- `mount` enables the `rage-mount` tool, which can mount age-encrypted TAR or
  ZIP archives as read-only. It is currently only usable on Unix systems, as it
  relies on `libfuse`.

- `unstable` enables in-development functionality. Anything behind this feature
  flag has no stability or interoperability guarantees.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

