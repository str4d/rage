# Changelog
All notable changes to the age crate will be documented in this file. Changes
to the [age-core crate](../age-core/CHANGELOG.md) also apply to the age-plugin
crate, and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- `age_plugin::PluginHandler`
- `impl age_plugin::identity::IdentityPluginV1 for std::convert::Infallible`
- `impl age_plugin::recipient::RecipientPluginV1 for std::convert::Infallible`

### Fixed
- `age_plugin::run_state_machine` now takes an `impl age_plugin::PluginHandler`
  argument, instead of its previous arguments.
  - This fixes the change from the previous release, because the type parameters
    were basically impossible to set correctly when attempting to pass `None`.

## [0.5.0] - 2024-02-04
### Changed
- MSRV is now 1.65.0.
- Migrated to `age-core 0.10`.
- `age_plugin::run_state_machine` now takes optional arguments, to enable the
  creation of recipient-only or identity-only plugins.

## [0.4.0] - 2022-10-27
### Changed
- MSRV is now 1.59.0.
- Migrated to `age-core 0.9`.

## [0.3.0] - 2022-05-02
### Added
- `age_plugin::Callbacks::confirm`

### Changed
- MSRV is now 1.56.0.

## [0.2.1] - 2021-12-27
### Fixed
- Bumped `age-core` to 0.7.1 to fix a bug where non-canonical recipient stanza
  bodies in an age file header would cause a panic instead of being rejected.

## [0.2.0] - 2021-10-18
### Changed
- MSRV is now 1.51.0.
- `age_plugin::Callbacks` methods now return `age_core::plugin::Error` instead
  of `()` for internal errors, following changes to `age_core::plugin::Result`.

## [0.1.0] - 2021-05-02
Initial beta release!
