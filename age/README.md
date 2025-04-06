<p align="center"><img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://user-images.githubusercontent.com/1225294/132245842-fda4da6a-1cea-4738-a3da-2dc860861c98.png"></p>

# age Rust library

age is a simple, modern, and secure file encryption library. It features small
explicit keys, no config options, and UNIX-style composability.

This crate provides a set of Rust APIs that can be used to build more complex
tools based on the age format. The primary consumers of these APIs are the
[`rage`](https://crates.io/crates/rage) CLI tools, which provide straightforward
encryption and decryption of files or streams (e.g. in shell scripts), as well
as additional features such as mounting an encrypted archive.

The format specification is at [age-encryption.org/v1](https://age-encryption.org/v1).
The age format was designed by [@Benjojo](https://benjojo.co.uk/) and
[@FiloSottile](https://bsky.app/profile/did:plc:x2nsupeeo52oznrmplwapppl).

The reference interoperable Go implementation is available at
[filippo.io/age](https://filippo.io/age).

## Usage

Add this line to your `Cargo.toml`:

```
age = "0.11"
```

See the [documentation](https://docs.rs/age) for examples.

### Feature flags

- `armor` enables the `age::armor` module, which provides support for
  ASCII-armored age files.

- `async` enables asynchronous APIs for encryption and decryption.

- `cli-common` enables common helper functions for building age CLI tools.

- `ssh` enables the `age::ssh` module, which allows for reusing existing SSH key
  files for age encryption.

- `web-sys` enables calculating the work factor for passphrase encryption with the
  [Performance timer](https://developer.mozilla.org/en-US/docs/Web/API/Performance)
  via the `web-sys` crate, when compiling for a WebAssembly target such as
  `wasm32-unknown-unknown`. This feature is ignored for the `wasm32-wasi` target,
  which supports [`std::time::SystemTime`](https://doc.rust-lang.org/stable/std/time/struct.SystemTime.html#underlying-system-calls).

- `unstable` enables in-development functionality. Anything behind this feature
  flag has no stability or interoperability guarantees.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
