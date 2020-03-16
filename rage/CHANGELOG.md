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
- `rage-mount` can now mount ASCII-armored age files.

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
