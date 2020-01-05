# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- The library crate can be compiled to WASM.
- When encrypting to a passphrase, rage will generate a secure passphrase if the
  user does not provide one.
- `SecretKey::to_string -> secrecy::SecretString`, which zeroizes most internal
  state. (Zeroizing all internal state requires changes to the `bech32` crate.)
- `RecipientKey` implements `Display`, and can be converted to a string using
  `recipient.to_string()`.
- `Decryptor::with_passphrase` constructor.
- `--max-work-factor WF` argument for rage and rage-mount, to enable overriding
  the default maximum (which is around 16 seconds of work).

### Changed
- `age::Encryptor::wrap_output` now takes an `age::Format` enum argument instead
  of a boolean flag.
- Recipients are now parsed as filenames last instead of first. If a filename
  happens to also be a valid recipient format, the file will be ignored. This
  can be overridden by using an absolute file path.
- The filename `-` (hyphen) is now treated as an explicit request to read from
  standard input or write to standard output when used as an input or output
  filename.
- `-o -` will override protections for terminals when standard output is not
  being piped elsewhere: output will not be truncated, and binary data will be
  printed directly to the terminal.
- Armored encrypted output can now be printed to the terminal. Large files will
  be truncated (to protect the terminal), corrupting the encryption. This can be
  overriden with `-o -`.
- The `Decryptor::Passphrase` enum case has been altered to store an optional
  maximum work factor.

### Removed
- `SecretKey::to_str` (replaced by `SecretKey::to_string`).
- `RecipientKey::to_str` (replaced by `Display` implementation and
  `recipient.to_string()`).

### Fixed
- Corrected encoding of example recipients in manpages.
- Re-enabled the default identities file (#41).
- Fixed parser to reject encrypted OpenSSH keys if they contain invalid
  `bcrypt_pbkdf` parameters.
- [Unix] `rage-keygen -o filename` now creates files with mode `600` (i.e. the
  output file is no longer world-readable).
- Unknown recipient lines are now parsed and ignored during decryption, instead
  of causing a hard failure.

## [0.1.1] - 2019-12-29
### Added
- Debian packaging support via `cargo deb`. See [docs/debian.md](docs/debian.md)
  for details.

### Changed
- Moved the `num_traits` dependency behind the `unstable` feature flag.
- The `generate-docs` example now generates (the equivalent of ) `gzip -9`
  manpages, for ease of use in Debian packaging.

### Fixed
- Decrypted chunks inside the STREAM implementation are now zeroized after use.

## [0.1.0] - 2019-12-27

Initial beta release!
