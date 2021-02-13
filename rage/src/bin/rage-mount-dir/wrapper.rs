use std::{
    cell::RefCell,
    fmt,
    fs::File,
    io::{self, Seek, SeekFrom},
    path::PathBuf,
};

use age::{Decryptor, Identity};
use age_core::format::{FileKey, Stanza};
use secrecy::ExposeSecret;

/// A file key we cached. It is bound to the specific stanza it was unwrapped from.
pub(crate) struct CachedFileKey {
    stanza: Stanza,
    inner: FileKey,
}

impl fmt::Debug for CachedFileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.stanza.fmt(f)
    }
}

impl Identity for CachedFileKey {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        // This compares the entire stanza, including the file key ciphertexts, so we can
        // be confident that the wrapped file keys are identical, and thus return this
        // cached file key.
        if stanza == &self.stanza {
            Some(Ok(FileKey::from(*self.inner.expose_secret())))
        } else {
            None
        }
    }
}

/// A pseudo-identity that caches the first successfully-unwrapped file key.
struct FileKeyCacher<'a> {
    identities: &'a [Box<dyn Identity + Send + Sync>],
    cache: RefCell<Option<CachedFileKey>>,
}

impl<'a> FileKeyCacher<'a> {
    fn new(identities: &'a [Box<dyn Identity + Send + Sync>]) -> Self {
        FileKeyCacher {
            identities,
            cache: RefCell::new(None),
        }
    }
}

impl<'a> Identity for FileKeyCacher<'a> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        self.identities.iter().find_map(|identity| {
            if let Some(Ok(file_key)) = identity.unwrap_stanza(stanza) {
                *self.cache.borrow_mut() = Some(CachedFileKey {
                    stanza: stanza.clone(),
                    inner: FileKey::from(*file_key.expose_secret()),
                });
                Some(Ok(file_key))
            } else {
                None
            }
        })
    }
}

#[derive(Debug)]
pub(crate) struct AgeFile {
    pub(crate) file_key: CachedFileKey,
    pub(crate) size: u64,
}

/// Returns:
/// - Ok((path, Some(_))) if this is an age file we can decrypt.
/// - Ok((path, None)) if this is not an age file, or we can't decrypt it.
pub(crate) fn check_file(
    path: PathBuf,
    identities: &[Box<dyn Identity + Send + Sync>],
) -> io::Result<(PathBuf, Option<AgeFile>)> {
    let res = if let Ok(Decryptor::Recipients(d)) = Decryptor::new(File::open(&path)?) {
        let cacher = FileKeyCacher::new(identities);
        if let Ok(mut r) = d.decrypt(Some(&cacher).into_iter().map(|i| i as &dyn Identity)) {
            Some(AgeFile {
                file_key: cacher.cache.into_inner().unwrap(),
                size: r.seek(SeekFrom::End(0))?,
            })
        } else {
            None
        }
    } else {
        None
    };

    Ok((path, res))
}
