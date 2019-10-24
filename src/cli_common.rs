//! Common helpers for CLI binaries.

use dialoguer::PasswordInput;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;

use crate::keys::SecretKey;

/// Returns the age config directory.ALIAS_PREFIX
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

/// Reads keys from the provided files if given, or the default system locations
/// if no files are given.
pub fn read_keys(filenames: Vec<String>) -> io::Result<Vec<SecretKey>> {
    let mut keys = vec![];

    if filenames.is_empty() {
        let default_filename = get_config_dir()
            .map(|mut path| {
                path.push("age/keys.txt");
                path
            })
            .expect("an OS for which we know the default config directory");
        let f = File::open(&default_filename).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no keys specified as arguments, and default file {} does not exist",
                    default_filename.to_str().unwrap()
                ),
            ),
            _ => e,
        })?;
        let buf = BufReader::new(f);
        keys.extend(SecretKey::from_data(buf)?);
    } else {
        for filename in filenames {
            let buf = BufReader::new(File::open(filename)?);
            keys.extend(SecretKey::from_data(buf)?);
        }
    }

    Ok(keys)
}

/// Reads a passphrase from stdin.
pub fn read_passphrase(confirm: bool) -> io::Result<String> {
    let mut input = PasswordInput::new();
    input.with_prompt("Type passphrase");
    if confirm {
        input.with_confirmation("Confirm passphrase", "Passphrases mismatching");
    }
    input.interact()
}
