use std::fmt;
use std::io;

pub(crate) enum EncryptError {
    IdentityFlag,
    InvalidRecipient(String),
    Io(io::Error),
    MissingRecipients,
    MixedRecipientAndPassphrase,
    PassphraseWithoutFileArgument,
    UnknownAlias(String),
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::IdentityFlag => {
                writeln!(f, "-i/--identity can't be used in encryption mode.")?;
                write!(f, "Did you forget to specify -d/--decrypt?")
            }
            EncryptError::InvalidRecipient(r) => write!(f, "Invalid recipient '{}'", r),
            EncryptError::Io(e) => write!(f, "{}", e),
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
            EncryptError::UnknownAlias(alias) => write!(f, "Unknown {}", alias),
        }
    }
}

pub(crate) enum DecryptError {
    Age(age::Error),
    ArmorFlag,
    Io(io::Error),
    MissingIdentities,
    MixedIdentityAndPassphrase,
    PassphraseWithoutFileArgument,
    RecipientFlag,
    UnsupportedKey(String, age::keys::UnsupportedKey),
}

impl From<age::Error> for DecryptError {
    fn from(e: age::Error) -> Self {
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
            DecryptError::Age(e) => writeln!(f, "{}", e),
            DecryptError::ArmorFlag => {
                writeln!(f, "-a/--armor can't be used with -d/--decrypt.")?;
                write!(f, "Note that armored files are detected automatically.")
            }
            DecryptError::Io(e) => write!(f, "{}", e),
            DecryptError::MissingIdentities => {
                writeln!(f, "Missing identities.")?;
                write!(f, "Did you forget to specify -i/--identity?")
            }
            DecryptError::MixedIdentityAndPassphrase => {
                write!(f, "-i/--identity can't be used with -p/--passphrase")
            }
            DecryptError::PassphraseWithoutFileArgument => write!(
                f,
                "File to decrypt must be passed as an argument when using -p/--passphrase"
            ),
            DecryptError::RecipientFlag => {
                writeln!(f, "-r/--recipient can't be used with -d/--decrypt.")?;
                write!(
                    f,
                    "Did you mean to use -i/--identity to specify a private key?"
                )
            }
            DecryptError::UnsupportedKey(filename, k) => {
                writeln!(f, "Unsupported key: {}", filename)?;
                writeln!(f)?;
                write!(f, "{}", k)
            }
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
            "[ Tell us: https://github.com/str4d/rage/issues/new/choose          ]"
        )
    }
}
