# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- The library crate can be compiled to WASM.

### Changed
- `age::Encryptor::wrap_output` now takes an `age::Format` enum argument instead
  of a boolean flag.
- Recipients are now parsed as filenames last instead of first. If a filename
  happens to also be a valid recipient format, the file will be ignored. This
  can be overridden by using an absolute file path.

### Fixed
- Corrected encoding of example recipients in manpages.
- Re-enabled the default identities file (#41).

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
