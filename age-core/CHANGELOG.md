# Changelog
All notable changes to the age-core crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- `age_core::format::FILE_KEY_BYTES` constant.
- `age_core::plugin` module, which contains common backend logic used by both
  the `age` library (to implement client support for plugins) and the
  `age-plugin` library.

### Changed
- The stanza prefix `-> ` and trailing newline are now formal parts of the age
  stanza; `age_core::format::write::age_stanza` now includes them in its output,
  and `age_core::format::read::age_stanza` expects them to be present.
- Stanza bodies are now canonically serialized with a short (empty if necessary)
  last line. `age_core::format::write::age_stanza` outputs the new encoding, and
  `age_core::format::read::age_stanza` accepts only the new encoding. The new
  API `age_core::format::read::legacy_age_stanza` accepts either kind of stanza
  body encoding (the legacy minimal encoding, and the new explicit encoding).

### Security
- `age_core::primitives::aead_decrypt` now takes a `size` argument, checked
  against the plaintext length. This is to mitigate multi-key attacks, where a
  ciphertext can be crafted that decrypts successfully under multiple keys.
  Short ciphertexts can only target two keys, which has limited impact. See
  [this commit message](https://github.com/FiloSottile/age/commit/2194f6962c8bb3bca8a55f313d5b9302596b593b)
  for more details.

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
