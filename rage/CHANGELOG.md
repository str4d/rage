# Changelog
All notable changes to the rage CLI tools themselves will be documented in this
file. Changes to the [age crate](../age/CHANGELOG.md) also apply to the rage CLI
tools, and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- Plugin support!
  - The new [`age-plugin`](https://crates.io/crates/age-plugin) crate provides
    a Rust API for building age plugins.
  - See https://hackmd.io/@str4d/age-plugin-spec for the beta specification.
- The `-R/--recipients-file` flag, which accepts a path to a file containing age
  recipients, one per line (ignoring "#" prefixed comments and empty lines).
- The `-e/--encrypt` flag, to allow encryption to be an explicit choice (instead
  of relying on `-d/--decrypt` not being present).

### Changed
- MSRV is now 1.47.0.
- Files encrypted with this version of `rage` might not decrypt with previous
  beta versions, due to changes in how stanza bodies are canonically encoded.
  This should only affect a small fraction of files (if grease that triggers the
  change is added, which has a 3% chance per file).
- `-r/--recipient` now has the specific type "recipient" which better reflects
  its name, rather than the ambiguous "source of recipients" it was previously.
- `-i/--identity` can now be used when encrypting files. This requires the
  `-e/--encrypt` flag (to prevent ambiguity, e.g. if the user wants to decrypt
  but forgets the `-d/--decrypt` flag).

### Removed
- Recipients file support from `-r/--recipient` (use `-R/--recipients-file`
  instead).
- HTTPS support. This added otherwise-unnecessary networking dependencies to
  `rage`, and there are many decisions that need to be made when downloading a
  file (e.g. what roots to trust?) that go beyond the APIs we want to focus on
  here. Users should use a tool like `curl` or `wget` to download a recipients
  file, and then pass it to `rage`.
- The unstable GitHub feature (which relied on HTTPS support).
- The unstable aliases feature.

### Fixed
- Log output is now disabled by default, to prevent non-fatal error messages
  (such as an unset or invalid `LANG` variable) being printed to stderr while
  the program succeeds (which is confusing for users). The previous behaviour
  can be configured by setting the environment variable `RUST_LOG=error`.
- Output files are now opened lazily, which avoids leaving behind an empty file
  when an error occurs before we write the header.

## [0.5.1] - 2021-02-13
### Fixed
- Bumped dependencies to `i18n-embed-fl 0.3` and `i18n-embed 0.10.2` to fix a
  transient dependency breakage, that broke `cargo install rage` because
  [`cargo install` ignores `Cargo.lock`](https://github.com/rust-lang/cargo/issues/7169).

## [0.5.0] - 2020-11-22
### Added
- Italian, Spanish, and Chinese translations!
- `ssh` feature flag, enabled by default. It can be disabled to remove support
  for `ssh-rsa` and `ssh-ed25519` recipients and identities. `ssh-rsa` keys are
  now supported without the `unstable` feature flag.

### Changed
- MSRV is now 1.45.0.

### Removed
- Default identity path (identities should instead be set per-use).
- Default alias path (for unstable aliases feature).

## [0.4.0] - 2020-03-25
### Added
- `rage-mount` can now mount ASCII-armored age files.

### Changed
- [`rage`] `-p/--passphrase` flag can no longer be used with `-d/--decrypt`
  (passphrase-encrypted files are now detected automatically).

### Removed
- `-p/--passphrase` flag from `rage-mount` (passphrase-encrypted files are now
  detected automatically).

### Fixed
- [Unix] Files encrypted with a passphrase can now be decrypted with `rage` when
  piped over stdin.

## [0.3.1] - 2020-02-11
### Fixed
- Bumped dependencies to `cookie-factory ^0.3.1` to fix nightly builds.

## [0.3.0] - 2020-02-09
(relative to the CLI tools in `age 0.2.0`)

### Added
- `-V / --version` flags to all binaries.
- Completion files for Bash, Elvish, Fish, PowerShell, and Zsh can be generated
  with `cargo run --example generate-completions`.
- The Debian package will install completion files for Bash, Fish, and Zsh.

### Changed
- If a `pinentry` binary is available, it will be used preferentially to request
  secrets such as passphrases. The previous CLI input will be used if `pinentry`
  is not available.
