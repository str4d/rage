# Changelog
All notable changes to the age crate will be documented in this file. Changes
to the [age-core crate](../age-core/CHANGELOG.md) also apply to the age crate,
and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Security
- `StreamReader::seek(SeekFrom::End(offset))` did not previously authenticate
  the ciphertext length; if the ciphertext had been truncated or extended by
  `adversary_offset`, it would instead seek to `offset + adversary_offset`. This
  allowed an adversary with temporary control of an encrypted age file to
  control the location of a plaintext read following a seek-from-end. `age` now
  returns an error if the last chunk is invalid.
  - `rage` was not affected by this security issue, as it does not use `Seek`.
  - `rage-mount` may have been affected; it does not use `SeekFrom::End`
    directly, but the `tar` or `zip` crates might do so.

### Added
- Plugin support, enabled by the `plugin` feature flag:
  - `age::plugin::{Identity, Recipient}` structs for parsing plugin recipients
    and identities from strings.
  - `age::plugin::RecipientPluginV1`, which implements `age::Recipient` and runs
    the V1 recipient plugin protocol.
  - `age::plugin::IdentityPluginV1`, which implements `age::Identity` and runs
    the V1 identity plugin protocol.
- The `web-sys` feature flag, which enables calculating the work factor for
  passphrase encryption with the
  [Performance timer](https://developer.mozilla.org/en-US/docs/Web/API/Performance)
  via the `web-sys` crate, when compiling for a WebAssembly target such as
  `wasm32-unknown-unknown`. This feature is ignored for the `wasm32-wasi`
  target, which supports
  [`std::time::SystemTime`](https://doc.rust-lang.org/stable/std/time/struct.SystemTime.html#underlying-system-calls).
- `age::Callbacks::request_public_string` to request non-private input from the
  user (which will not trigger any OS-level passphrase-style prompt, unlike
  `Callbacks::request_passphrase`).

### Changed
- MSRV is now 1.47.0.
- Files encrypted with this version of `age` might not decrypt with previous
  beta versions, due to changes in how stanza bodies are canonically encoded.
  This should only affect a small fraction of files (if grease that triggers the
  change is added, which has a 3% chance per file).
- `age::decryptor::RecipientsDecryptor` now takes
  `impl Iterator<Item = &'a dyn Identity>` in its decryption methods, to make
  decrypting multiple files with the same identities easier.
- `age::cli_common::file_io::OutputWriter::File` now wraps a `LazyFile` struct
  (instead of wrapping `std::io::File` directly), which does not open the file
  until it is first written to.
- `age::decryptor::Callbacks` has been moved to `age::Callbacks`, as it is no
  longer decryption-specific.

### Fixed
- `age::cli_common::read_identities` now allows either kind of line ending in
  SSH identity files.
- Default `en-US` language strings are now always loaded, even if translations
  are not loaded by calling `age::localizer().select(&requested_languages)`.
- `StreamReader::seek(SeekFrom::End(0))` now seeks to the correct position when
  the plaintext is an exact multiple of the chunk size.

## [0.5.1] - 2021-02-13
### Fixed
- Bumped dependencies to `i18n-embed-fl 0.3` and `i18n-embed 0.10.2` to fix a
  transient dependency breakage, that broke `cargo install rage` because
  [`cargo install` ignores `Cargo.lock`](https://github.com/rust-lang/cargo/issues/7169).

## [0.5.0] - 2020-11-22
### Added
- Italian, Spanish, and Chinese translations!
- New core traits, implemented by all relevant `age` types:
  - `age::Identity`, representing an identity that can decrypt an age file.
  - `age::Recipient`, representing a potential recipient of an age file.
- Separate modules and structs for different recipient types:
  - `age::x25519`
  - `age::ssh` (behind the `ssh` feature flag).
- `age::EncryptError`, representing errors that can occur during encryption.
- `age::IdentityFile` struct, for parsing a list of native age identities
  (currently only `age::x25519::Identity`) from a file.
- Asynchronous APIs for encryption and decryption, enabled by the `async`
  feature flag:
  - `age::Encryptor::wrap_async_output()`
  - `age::Decryptor::new_async()`
  - `age::decryptor::RecipientsDecryptor::decrypt_async()`
  - `age::decryptor::PassphraseDecryptor::decrypt_async()`
- Explicit armoring support, enabled by the `armor` feature flag:
  - `age::armor::ArmoredReader`, which can be wrapped around an input to handle
    a potentially-armored age file.
  - `age::armor::ArmoredWriter`, which can be wrapped around an output to
    optionally apply the armored age format.

### Changed
- MSRV is now 1.45.0.
- Changes due to the new core traits:
  - `age::Encryptor::with_recipients` now takes `Vec<Box<dyn Recipient>>`.
  - `age::decryptor::RecipientsDecryptor` now takes
    `impl Iterator<Item = Box<dyn Identity>>` in its decryption methods.
  - `age::cli_common::read_identities` now returns `Vec<Box<dyn Identity>>`, as
    it abstracts over `age::IdentityFile` and `age::ssh::Identity`. When the
    `ssh` feature flag is enabled, it also takes an `unsupported_ssh` argument
    for handling unsupported SSH identities.
  - `age::Error` has been renamed to `age::DecryptError`.
- Changes due to explicit armoring support:
  - `age::Encryptor::wrap_output` now only generates the non-malleable binary
    age format. To optionally generate armored age files, use
    `encryptor.wrap_output(ArmoredWriter::wrap_output(output, format))`.
  - `age::Decryptor` now only decrypts the non-malleable binary age format. To
    handle age files that are potentially armored, use
    `Decryptor::new(ArmoredReader::new(input))`.
  - `age::Format` has been moved to `age::armor::Format`.
- SSH support is now disabled by default, behind the `ssh` feature flag.
  `ssh-rsa` keys are now supported without the `unstable` feature flag.
- `age::Callbacks` has been moved to `age::decryptor::Callbacks`.

### Removed
- `age::SecretKey` (replaced by `age::x25519::Identity` and
  `age::ssh::Identity`).
- `age::keys::RecipientKey` (replaced by `age::x25519::Recipient` and
  `age::ssh::Recipient`).
- `age::keys::{Identity, IdentityKey}` (replaced by `age::Identity` trait on
  individual identities, and `age::IdentityFile` for parsing identities).
- `age::decryptor::RecipientsDecryptor::decrypt_with_callbacks()` (identities
  are now expected to handle their own callbacks, and
  `age::cli_common::read_identities` now adds callbacks to SSH identities).
- Default identity path:
  - `age::cli_common::get_config_dir`.
  - The `no_default` parameter for `age::cli_common::read_identities`.

## [0.4.0] - 2020-03-25
### Added
- `age::Decryptor::new(R: Read)`, which parses an age file header and returns
  a context-specific decryptor.
- `age::decryptor` module containing the context-specific decryptors.
  - Their decryption methods return the concrete type `StreamReader<R>`,
    enabling them to handle seekable readers.
- `age::Encryptor::with_recipients(Vec<RecipientKey>)`
- `age::Encryptor::with_user_passphrase(SecretString)`
- Support for encrypted OpenSSH keys created with `ssh-keygen` prior to OpenSSH
  7.6.
- `age::cli_common::file_io::OutputWriter::is_terminal`

### Changed
- `age::Decryptor` has been refactored to auto-detect the decryption type. As a
  result, both identity-based and passphrase-based decryption need to be
  handled.
- `age::StreamReader` has been moved into the `age::stream` module, along with
  `StreamWriter` which was previously public but has now been formally exposed
  in the API for documentation purposes.
- `age::Encryptor` is now an opaque struct, and must be created via its new
  constructors.
- `age::Encryptor::wrap_output` now consumes `self`, making it harder to
  accidentally reuse a passphrase for multiple encrypted files.
- `age::cli_common::read_identities` now takes an additional `file_not_found`
  parameter for customising the error when an identity filename is not found.

### Removed
- `age::Decryptor::trial_decrypt` (replaced by context-specific decryptors).
- `age::Decryptor::trial_decrypt_seekable` (merged into the context-specific
  decryptors).
- `age::Error::ArmoredWhenSeeking`
- `age::Error::MessageRequiresKeys`
- `age::Error::MessageRequiresPassphrase`

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
