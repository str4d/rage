# Changelog
All notable changes to the age-core crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Changed
- The stanza prefix `-> ` is now a formal part of the age stanza; it will be
  included in the output of `age_core::format::write::age_stanza`, and expected
  by `age_core::format::read::age_stanza`.

## [0.5.0] - 2020-11-22
### Added
- Several structs used when implementing the `age::Identity` and
  `age::Recipient` traits:
  - `age_core::format::FileKey`
  - `age_core::format::Stanza`
- `age_core::format::grease_the_joint`, for generating a random valid recipient
  stanza. No other guarantees are made about the stanza's fields.
- `age_core::primitives::{aead_decrypt, aead_encrypt, hkdf}`, to enable these
  common primitives to be reused in plugins.

### Changed
- MSRV is now 1.41.0.
- `age_core::format::write::age_stanza` now takes `args: &[impl AsRef<str>]`.

## [0.4.0] - 2020-03-25
No changes; version bumped to keep it in sync with `age`.

## [0.3.1] - 2020-02-11
### Fixed
- Bumped dependencies to `cookie-factory ^0.3.1` to fix nightly builds.

## [0.3.0] - 2020-02-09
(relative to `age 0.2.0`)

### Fixed
- Base64 padding is now correctly rejected by the age stanza parser.
