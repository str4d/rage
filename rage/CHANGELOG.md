# Changelog
All notable changes to the rage CLI tools themselves will be documented in this
file. Changes to the [age crate](../age/CHANGELOG.md) also apply to the rage CLI
tools, and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]

## [0.6.1, 0.7.2, 0.8.2, 0.9.3, 0.10.1, 0.11.1] - 2024-12-18
### Security
- Fixed a security vulnerability that could allow an attacker to execute an
  arbitrary binary under certain conditions. See GHSA-4fg7-vxc8-qx5w. Plugin
  names are now required to only contain alphanumeric characters or the four
  special characters `+-._`. Thanks to ⬡-49016 for reporting this issue.

## [0.11.0] - 2024-11-03
### Added
- Partial French translation!

### Fixed
- [Unix] Files can now be encrypted with `rage --passphrase` when piped over
  stdin, without requiring an explicit `-` argument as `INPUT`.

## [0.10.0] - 2024-02-04
### Added
- Russian translation!
- `rage-keygen -y IDENTITY_FILE` to convert identity files to recipients.
- Elvish completions to the Debian package. These are not automatically
  discovered; Elvish users will need to manually import them.
- Localized manpages to the Debian package.

### Changed
- MSRV is now 1.65.0.
- Migrated from `gumdrop` to `clap` for argument parsing.
- `-R/--recipients-file` and `-i/--identity` now support "read-once" files, like
  those used by process substitution (`-i <(other_binary get-age-identity)`) and
  named pipes.
- The filename `-` (hyphen) is now treated as an explicit request to read from
  standard input when used with `-R/--recipients-file` or `-i/--identity`. It
  must only occur once across the `-R/--recipients-file` and `-i/--identity`
  flags, and the input file. It cannot be used if the input file is omitted.

### Fixed
- OpenSSH private keys passed to `-i/--identity` that contain invalid public
  keys are no longer ignored when encrypting, and instead cause an error.
- Weak `ssh-rsa` public keys that are smaller than 2048 bits are now rejected.
- `rage-keygen` no longer overwrites existing key files with the `-o/--output`
  flag. This was its behaviour prior to 0.6.0, but was unintentionally changed
  when `rage` was modified to overwrite existing files. Key file overwriting can
  still be achieved by omitting `-o/--output` and instead piping stdout to the
  file.
- `rage-keygen` now prints fatal errors directly instead of them being hidden
  behind the `RUST_LOG=error` environment variable. It also now sets its return
  code appropriately instead of always returning 0.
- The Debian package now uses the correct installation paths for fish and Zsh
  completions.

## [0.9.2] - 2023-06-12
### Changed
- Increased parsing speed of age file headers. For single-recipient encrypted
  files, decryption throughput increases by 6% for medium (< 1MiB) files, and
  over 40% for small (< 10kiB) files.
- The `pinentry` binary used to request passphrases can now be set manually with
  the `PINENTRY_PROGRAM` environment variable. It accepts either a binary name
  or a path. Setting this to the empty string will disable `pinentry` usage and
  fall back to the CLI interface.
- Linux release binaries are now built using Ubuntu 20.04.

## [0.9.1] - 2023-03-24
### Added
- Support for encrypted OpenSSH keys exported from 1Password.

## [0.9.0] - 2022-10-27
### Changed
- MSRV is now 1.59.0.

### Fixed
- Encryption now returns an error if the file would be encrypted to no
  recipients. This can occur if only `-R/--recipients-file` flags are provided,
  and they all point to files that contain only "#" prefixed comments and empty
  lines.

## [0.8.1] - 2022-06-18
### Security
- Require `age 0.8.1`. See the [`age` crate changelog](../age/CHANGELOG.md) for
  details.

## [0.8.0] - 2022-05-02
### Changed
- MSRV is now 1.56.0.
- When both reading input from the terminal (e.g. if the user is typing the
  plaintext to be encrypted) and writing output to the terminal, `rage` now
  buffers the output until the input is finished, so the output doesn't get in
  the way of typing.
- A warning is now displayed if `rage` detects that the file being encrypted
  starts with the age magic string or armor begin marker (indicating that an
  age-encrypted file is being double-encrypted). The file is still encrypted.
- A message is now printed if a plugin takes longer than 10 seconds to encrypt
  or decrypt its header entry (for example, if the plugin is waiting on some
  user interaction that hasn't occurred yet).

### Fixed
- Decryption now returns an error when given a passphrase-encrypted file if
  `-i/--identity` is present. Previously this could result in scripts hanging
  forever (given that passphrase decryption is intentionally not scriptable).

## [0.7.1] - 2021-12-27
### Fixed
- Fixed a bug in 0.7.0 where non-canonical recipient stanza bodies in an age
  file header would cause `rage` to crash instead of being rejected.

## [0.7.0] - 2021-10-18
### Added
- `-i/--identity` now accepts passphrase-encrypted age identity files.
- The `-j PLUGIN_NAME` flag, which allows decrypting with a plugin using its
  "default mode" (in which no identity-specific information is required). This
  flag is equivalent to using `-i/--identity` with an identity file containing
  the default plugin identity (containing no data).

### Changed
- MSRV is now 1.51.0.
- `*-linux.tar.gz` release binaries are now built with Ubuntu 18.04, and require
  a system with a minimum of `glibc 2.27`.

## [0.6.0] - 2021-05-02
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
- `-o/--output` will now *overwrite* existing files instead of returning an
  error. This makes the behaviour consistent with most UNIX tools, as well as
  when using pipes.
- Files encrypted with this version of `rage` might not decrypt with previous
  beta versions, due to changes in how stanza bodies are canonically encoded.
  This should only affect a small fraction of files (if grease that triggers the
  change is added, which has a 3% chance per file).
- `-r/--recipient` now has the specific type "recipient" which better reflects
  its name, rather than the ambiguous "source of recipients" it was previously.
- `-i/--identity` can now be used when encrypting files. This requires the
  `-e/--encrypt` flag (to prevent ambiguity, e.g. if the user wants to decrypt
  but forgets the `-d/--decrypt` flag).
- `*-linux.tar.gz` release binaries are now built with Ubuntu 16.04, enabling
  them to be used on systems with a minimum of `glibc 2.23`.
- Debian packages are now built with Ubuntu 18.04, enabling them to be used on
  Debian/Ubuntu systems with a minimum of `glibc 2.27`.

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
