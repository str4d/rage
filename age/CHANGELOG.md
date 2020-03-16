# Changelog
All notable changes to the age crate will be documented in this file. Changes
to the [age-core crate](../age-core/CHANGELOG.md) also apply to the age crate,
and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- `age::Decryptor::new(R: Read)`, which parses an age file header and returns
  a context-specific decryptor.
- `age::decryptor` module containing the context-specific decryptors.
  - Their decryption methods return the concrete type `StreamReader<R>`,
    enabling them to handle seekable readers.

### Changed
- `age::Decryptor` has been refactored to auto-detect the decryption type. As a
  result, both identity-based and passphrase-based decryption need to be
  handled.
- `age::StreamReader` has been moved into the `age::stream` module, along with
  `StreamWriter` which was previously public but has now been formally exposed
  in the API for documentation purposes.

### Removed
- `age::Decryptor::trial_decrypt` (replaced by context-specific decryptors).
- `age::Decryptor::trial_decrypt_seekable` (merged into the context-specific
  decryptors).

### Fixed
- Key files with Windows line endings are now correctly parsed.

## [0.3.1] - 2020-02-11
### Fixed
- Bumped dependencies to `cookie-factory ^0.3.1` to fix nightly builds.

## [0.3.0] - 2020-02-09
### Added
- `age::Callbacks`, which encapsulates any requests that might be necessary
  during the decryption process.
- `age::cli_common::UiCallbacks`, which implements `Callbacks` with requests to
  the user via `age::cli_common::read_secret`.
- `age::Decryptor::with_identities(Vec<Identity>)`
- `age::Decryptor::with_identities_and_callbacks(Vec<Identity>, Box<dyn Callbacks>)`
- `age::Encryptor` will insert a random recipient stanza into the header, to
  keep age's joint well oiled.

### Changed
- The CLI tools have been moved into the `rage` crate.
- The `age::Decryptor::Keys` enum case has been renamed to `Identities` and
  altered to store a `Box<dyn Callbacks>` internally.
- `age::Decryptor::trial_decrypt` and `age::Decryptor::trial_decrypt_seekable`
  both no longer take a `request_passphrase` argument.
- `age::cli_common::read_secret`:
  - Takes an additional `prompt` parameter.
  - Uses the system `pinentry` binary for requesting secrets if available.
  - Returns `pinentry::Error` instead of `io::Error`.
- `age::cli_common::read_or_generate_passphrase` now returns `pinentry::Error`
  instead of `io::Error`.
- Core age parsers and serializers have been moved into the `age-core` crate.

### Fixed
- Fixed several crashes in the armored format reader, found by fuzzing. The
  reader also now correctly enforces a canonical armor marker and line lengths.
- Recipient stanzas with empty bodies are correctly parsed.

## [0.2.0] - 2020-01-10
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
- Debian packaging support via `cargo deb`. See [docs/debian.md](../docs/debian.md)
  for details.

### Changed
- Moved the `num_traits` dependency behind the `unstable` feature flag.
- The `generate-docs` example now generates (the equivalent of ) `gzip -9`
  manpages, for ease of use in Debian packaging.

### Fixed
- Decrypted chunks inside the STREAM implementation are now zeroized after use.

## [0.1.0] - 2019-12-27

Initial beta release!
