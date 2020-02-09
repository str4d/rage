# age Rust library

age is a simple, secure and modern encryption tool with small explicit keys, no
config options, and UNIX-style composability. The format specification is at
[age-encryption.org/v1](https://age-encryption.org/v1).

To discuss the spec or other age related topics, please email
[the mailing list](https://groups.google.com/d/forum/age-dev) at
age-dev@googlegroups.com. age was designed by
[@Benjojo12](https://twitter.com/Benjojo12) and
[@FiloSottile](https://twitter.com/FiloSottile).

The reference interoperable Golang implementation is available at
[filippo.io/age](https://filippo.io/age).

## Usage

Add this line to your `Cargo.toml`:

```
age = "0.3"
```

See the [documentation](https://docs.rs/age) for examples.

### Feature flags

- `cli-common` enables common helper functions for building age CLI tools.

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

