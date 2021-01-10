# age-plugin Rust library

This crate provides an API for building age plugins.

## Introduction

The [age file encryption format] follows the "one well-oiled joint" design philosophy.
The mechanism for extensibility (within a particular format version) is the recipient
stanzas within the age header: file keys can be wrapped in any number of ways, and age
clients are required to ignore stanzas that they do not understand.

The core APIs that exercise this mechanism are:
- A recipient that wraps a file key and returns a stanza.
- An identity that unwraps a stanza and returns a file key.

The age plugin system provides a mechanism for exposing these core APIs across process
boundaries. It has two main components:

- A map from recipients and identities to plugin binaries.
- State machines for wrapping and unwrapping file keys.

With this composable design, you can implement a recipient or identity that you might
use directly with the [`age`] library crate, and also deploy it as a plugin binary for
use with clients like [`rage`].

[age file encryption format]: https://age-encryption.org/v1
[`age`]: https://crates.io/crates/age
[`rage`]: https://crates.io/crates/rage

## Mapping recipients and identities to plugin binaries

age plugins are identified by an arbitrary case-insensitive string `NAME`. This string
is used in three places:

- Plugin-compatible recipients are encoded using Bech32 with the HRP `age1name`
  (lowercase).
- Plugin-compatible identities are encoded using Bech32 with the HRP
  `AGE-PLUGIN-NAME-` (uppercase).
- Plugin binaries (to be started by age clients) are named `age-plugin-name`.

Users interact with age clients by providing either recipients for file encryption, or
identities for file decryption. When a plugin recipient or identity is provided, the
age client searches the `PATH` for a binary with the corresponding plugin name.

Recipient stanza types are not required to be correlated to specific plugin names.
When decrypting, age clients will pass all recipient stanzas to every connected
plugin. Plugins MUST ignore stanzas that they do not know about.

A plugin binary may handle multiple recipient or identity types by being present in
the `PATH` under multiple names. This can be implemented with symlinks or aliases to
the canonical binary.

Multiple plugin binaries can support the same recipient and identity types; the first
binary found in the `PATH` will be used by age clients. Some Unix OSs support
"alternatives", which plugin binaries should leverage if they provide support for a
common recipient or identity type.

Note that the identity specified by a user doesn't need to point to a specific
decryption key, or indeed contain any key material at all. It only needs to contain
sufficient information for the plugin to locate the necessary key material.

### Standard age keys

A plugin MAY support decrypting files encrypted to native age recipients, by including
support for the `x25519` recipient stanza. Such plugins will pick their own name, and
users will use identity files containing identities that specify that plugin name.

## Example plugin binary

The following example uses `gumdrop` to parse CLI arguments, but any argument parsing
logic will work as long as it can detect the `--age-plugin=STATE_MACHINE` flag.

```rust
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, Callbacks, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine,
};
use gumdrop::Options;
use std::collections::HashMap;
use std::io;

struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<recipient::Error>> {
        todo!()
    }

    fn wrap_file_key(
        &mut self,
        file_key: &FileKey,
    ) -> Result<Vec<Stanza>, Vec<recipient::Error>> {
        todo!()
    }
}

struct IdentityPlugin;

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<identity::Error>> {
        todo!()
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        todo!()
    }
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run the given age plugin state machine", no_short)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if let Some(state_machine) = opts.age_plugin {
        // The plugin was started by an age client; run the state machine.
        run_state_machine(
            &state_machine,
            || RecipientPlugin,
            || IdentityPlugin,
        )?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.

    Ok(())
}
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
