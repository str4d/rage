//! Common helpers for CLI binaries.

use dialoguer::PasswordInput;
use secrecy::SecretString;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;

use crate::keys::Identity;

pub mod file_io;

/// Returns the age config directory.
///
/// Replicates the behaviour of [os.UserConfigDir] from Golang, which the
/// reference implementation uses. See [this issue] for more details.
///
/// [os.UserConfigDir]: https://golang.org/pkg/os/#UserConfigDir
/// [this issue]: https://github.com/FiloSottile/age/issues/15
pub fn get_config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::data_dir()
    }

    #[cfg(not(target_os = "macos"))]
    {
        dirs::config_dir()
    }
}

/// Reads identities from the provided files if given, or the default system
/// locations if no files are given.
pub fn read_identities<E, F>(filenames: Vec<String>, no_default: F) -> Result<Vec<Identity>, E>
where
    E: From<io::Error>,
    F: FnOnce(&str) -> E,
{
    let mut identities = vec![];

    if filenames.is_empty() {
        let default_filename = get_config_dir()
            .map(|mut path| {
                path.push("age/keys.txt");
                path
            })
            .expect("an OS for which we know the default config directory");
        let f = File::open(&default_filename).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => no_default(default_filename.to_str().unwrap_or("")),
            _ => e.into(),
        })?;
        let buf = BufReader::new(f);
        identities.extend(Identity::from_buffer(buf)?);
    } else {
        for filename in filenames {
            identities.extend(Identity::from_file(filename)?);
        }
    }

    Ok(identities)
}

/// Reads a passphrase from stdin.
pub fn read_passphrase(prompt: &str, confirm: bool) -> io::Result<SecretString> {
    let mut input = PasswordInput::new();
    input.with_prompt(prompt);
    if confirm {
        input.with_confirmation("Confirm passphrase", "Passphrases mismatching");
    }
    input.interact().map(SecretString::new)
}
