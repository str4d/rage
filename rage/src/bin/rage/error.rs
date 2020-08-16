use std::fmt;
use std::io;

pub(crate) enum EncryptError {
    BrokenPipe { is_stdout: bool, source: io::Error },
    IdentityFlag,
    InvalidRecipient(String),
    Io(io::Error),
    Minreq(minreq::Error),
    MissingPlugin(String),
    MissingRecipients,
    MixedRecipientAndPassphrase,
    PassphraseWithoutFileArgument,
    TimedOut(String),
    UnknownAlias(String),
}

impl From<age::EncryptError> for EncryptError {
    fn from(e: age::EncryptError) -> Self {
        match e {
            age::EncryptError::Io(e) => EncryptError::Io(e),
        }
    }
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl From<minreq::Error> for EncryptError {
    fn from(e: minreq::Error) -> Self {
        EncryptError::Minreq(e)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::BrokenPipe { is_stdout, source } => {
                if *is_stdout {
                    writeln!(f, "Could not write to stdout: {}", source)?;
                    write!(
                        f,
                        "Are you piping to a program that isn't reading from stdin?"
                    )
                } else {
                    write!(f, "Could not write to file: {}", source)
                }
            }
            EncryptError::IdentityFlag => {
                writeln!(f, "-i/--identity can't be used in encryption mode.")?;
                write!(f, "Did you forget to specify -d/--decrypt?")
            }
            EncryptError::InvalidRecipient(r) => write!(f, "Invalid recipient '{}'", r),
            EncryptError::Io(e) => write!(f, "{}", e),
            EncryptError::Minreq(e) => write!(f, "{}", e),
            EncryptError::MissingPlugin(name) => {
                writeln!(f, "Could not find '{}' on the PATH.", name)?;
                write!(f, "Have you installed the plugin?")
            }
            EncryptError::MissingRecipients => {
                writeln!(f, "Missing recipients.")?;
                write!(f, "Did you forget to specify -r/--recipient?")
            }
            EncryptError::MixedRecipientAndPassphrase => {
                write!(f, "-r/--recipient can't be used with -p/--passphrase")
            }
            EncryptError::PassphraseWithoutFileArgument => write!(
                f,
                "File to encrypt must be passed as an argument when using -p/--passphrase"
            ),
            EncryptError::TimedOut(source) => write!(f, "Timed out waiting for {}", source),
            EncryptError::UnknownAlias(alias) => write!(f, "Unknown {}", alias),
        }
    }
}

pub(crate) enum DecryptError {
    Age(age::DecryptError),
    ArmorFlag,
    IdentityNotFound(String),
    Io(io::Error),
    MissingIdentities(String),
    MissingPlugin(String),
    PassphraseFlag,
    #[cfg(not(unix))]
    PassphraseWithoutFileArgument,
    RecipientFlag,
    TimedOut(String),
    #[cfg(feature = "ssh")]
    UnsupportedKey(String, age::ssh::UnsupportedKey),
}

impl From<age::DecryptError> for DecryptError {
    fn from(e: age::DecryptError) -> Self {
        DecryptError::Age(e)
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::Age(e) => match e {
                age::DecryptError::ExcessiveWork { required, .. } => {
                    writeln!(f, "{}", e)?;
                    write!(f, "To decrypt, retry with --max-work-factor {}", required)
                }
                _ => write!(f, "{}", e),
            },
            DecryptError::ArmorFlag => {
                writeln!(f, "-a/--armor can't be used with -d/--decrypt.")?;
                write!(f, "Note that armored files are detected automatically.")
            }
            DecryptError::IdentityNotFound(filename) => {
                write!(f, "Identity file not found: {}", filename)
            }
            DecryptError::Io(e) => write!(f, "{}", e),
            DecryptError::MissingIdentities(default_filename) => {
                writeln!(f, "Missing identities.")?;
                writeln!(f, "Did you forget to specify -i/--identity?")?;
                writeln!(f, "You can also store default identities in this file:")?;
                write!(f, "    {}", default_filename)
            }
            DecryptError::MissingPlugin(name) => {
                writeln!(f, "Could not find '{}' on the PATH.", name)?;
                write!(f, "Have you installed the plugin?")
            }
            DecryptError::PassphraseFlag => {
                writeln!(f, "-p/--passphrase can't be used with -d/--decrypt.")?;
                write!(
                    f,
                    "Note that passphrase-encrypted files are detected automatically."
                )
            }
            #[cfg(not(unix))]
            DecryptError::PassphraseWithoutFileArgument => {
                writeln!(f, "This file requires a passphrase, and on Windows the")?;
                writeln!(f, "file to decrypt must be passed as a positional argument")?;
                write!(f, "when decrypting with a passphrase.")
            }
            DecryptError::RecipientFlag => {
                writeln!(f, "-r/--recipient can't be used with -d/--decrypt.")?;
                write!(
                    f,
                    "Did you mean to use -i/--identity to specify a private key?"
                )
            }
            DecryptError::TimedOut(source) => write!(f, "Timed out waiting for {}", source),
            #[cfg(feature = "ssh")]
            DecryptError::UnsupportedKey(filename, k) => k.display(f, Some(filename.as_str())),
        }
    }
}

pub(crate) enum Error {
    Decryption(DecryptError),
    Encryption(EncryptError),
}

impl From<DecryptError> for Error {
    fn from(e: DecryptError) -> Self {
        Error::Decryption(e)
    }
}

impl From<EncryptError> for Error {
    fn from(e: EncryptError) -> Self {
        Error::Encryption(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption(e) => writeln!(f, "{}", e)?,
            Error::Encryption(e) => writeln!(f, "{}", e)?,
        }
        writeln!(f)?;
        writeln!(
            f,
            "[ Did rage not do what you expected? Could an error be more useful? ]"
        )?;
        write!(
            f,
            "[ Tell us: https://str4d.xyz/rage/report                            ]"
        )
    }
}
