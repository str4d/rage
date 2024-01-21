use std::io::{self, BufReader};

use super::{file_io::InputReader, ReadError, StdinGuard, UiCallbacks};
use crate::{identity::IdentityFile, Identity};

#[cfg(feature = "armor")]
use crate::armor::ArmoredReader;

/// Reads identities from the provided files.
///
/// `filenames` may contain at most one entry of `"-"`, which will be interpreted as
/// reading from standard input. An error will be returned if `stdin_guard` is guarding an
/// existing usage of standard input.
pub fn read_identities(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
    stdin_guard: &mut StdinGuard,
) -> Result<Vec<Box<dyn Identity>>, ReadError> {
    let mut identities: Vec<Box<dyn Identity>> = Vec::with_capacity(filenames.len());

    parse_identity_files::<_, ReadError>(
        filenames,
        max_work_factor,
        stdin_guard,
        &mut identities,
        |identities, identity| {
            identities.push(Box::new(identity));
            Ok(())
        },
        |identities, _, identity| {
            identities.push(Box::new(identity.with_callbacks(UiCallbacks)));
            Ok(())
        },
        |identities, entry| {
            let entry = entry.into_identity(UiCallbacks);

            #[cfg(feature = "plugin")]
            let entry = entry.map_err(|e| match e {
                #[cfg(feature = "plugin")]
                crate::DecryptError::MissingPlugin { binary_name } => {
                    ReadError::MissingPlugin { binary_name }
                }
                // DecryptError::MissingPlugin is the only possible error kind returned by
                // IdentityFileEntry::into_identity.
                _ => unreachable!(),
            })?;

            // IdentityFileEntry::into_identity will never return a MissingPlugin error
            // when plugin feature is not enabled.
            #[cfg(not(feature = "plugin"))]
            let entry = entry.unwrap();

            identities.push(entry);

            Ok(())
        },
    )?;

    Ok(identities)
}

/// Parses the provided identity files.
pub(super) fn parse_identity_files<Ctx, E: From<ReadError> + From<io::Error>>(
    filenames: Vec<String>,
    max_work_factor: Option<u8>,
    stdin_guard: &mut StdinGuard,
    ctx: &mut Ctx,
    #[cfg(feature = "armor")] encrypted_identity: impl Fn(
        &mut Ctx,
        crate::encrypted::Identity<ArmoredReader<BufReader<InputReader>>, UiCallbacks>,
    ) -> Result<(), E>,
    #[cfg(feature = "ssh")] ssh_identity: impl Fn(&mut Ctx, &str, crate::ssh::Identity) -> Result<(), E>,
    identity_file_entry: impl Fn(&mut Ctx, crate::IdentityFileEntry) -> Result<(), E>,
) -> Result<(), E> {
    for filename in filenames {
        let mut reader = PeekableReader::new(BufReader::new(
            stdin_guard.open(filename.clone()).map_err(|e| match e {
                ReadError::Io(e) if matches!(e.kind(), io::ErrorKind::NotFound) => {
                    ReadError::IdentityNotFound(filename.clone())
                }
                _ => e,
            })?,
        ));

        #[cfg(feature = "armor")]
        // Try parsing as an encrypted age identity.
        if crate::encrypted::Identity::from_buffer(
            ArmoredReader::new_buffered(&mut reader),
            Some(filename.clone()),
            UiCallbacks,
            max_work_factor,
        )
        .is_ok()
        {
            // Re-parse while taking ownership of the reader. This will always succeed
            // because the age ciphertext header size is less than the underlying buffer
            // size, but the manual reset here ensures this fails gracefully if for
            // whatever reason the underlying buffer size changes unexpectedly.
            reader.reset()?;
            let identity = crate::encrypted::Identity::from_buffer(
                ArmoredReader::new_buffered(reader.inner),
                Some(filename.clone()),
                UiCallbacks,
                max_work_factor,
            )
            .expect("already parsed the age ciphertext header");

            encrypted_identity(
                ctx,
                identity.ok_or(ReadError::IdentityEncryptedWithoutPassphrase(filename))?,
            )?;
            continue;
        }

        #[cfg(feature = "armor")]
        reader.reset()?;

        // Try parsing as a single multi-line SSH identity.
        #[cfg(feature = "ssh")]
        match crate::ssh::Identity::from_buffer(&mut reader, Some(filename.clone())) {
            Ok(crate::ssh::Identity::Unsupported(k)) => {
                return Err(ReadError::UnsupportedKey(filename, k).into())
            }
            Ok(identity) => {
                ssh_identity(ctx, &filename, identity)?;
                continue;
            }
            Err(_) => (),
        }

        #[cfg(feature = "ssh")]
        reader.reset()?;

        // Try parsing as multiple single-line age identities.
        let identity_file = IdentityFile::from_buffer(reader)?;

        for entry in identity_file.into_identities() {
            identity_file_entry(ctx, entry)?;
        }
    }

    Ok(())
}

enum PeekState {
    Peeking { consumed: usize },
    Reading,
}

struct PeekableReader<R: io::BufRead> {
    inner: R,
    state: PeekState,
}

impl<R: io::BufRead> PeekableReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: PeekState::Peeking { consumed: 0 },
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        match &mut self.state {
            PeekState::Peeking { consumed } => {
                *consumed = 0;
                Ok(())
            }
            PeekState::Reading => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tried to reset after the underlying buffer was exceeded.",
            )),
        }
    }
}

impl<R: io::BufRead> io::Read for PeekableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.state {
            PeekState::Peeking { .. } => {
                // Perform a read that will never exceed the size of the inner buffer.
                use std::io::BufRead;
                let nread = {
                    let mut rem = self.fill_buf()?;
                    rem.read(buf)?
                };
                self.consume(nread);
                Ok(nread)
            }
            PeekState::Reading => self.inner.read(buf),
        }
    }
}

impl<R: io::BufRead> io::BufRead for PeekableReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self.state {
            PeekState::Peeking { consumed } => {
                let inner_len = self.inner.fill_buf()?.len();
                if inner_len == 0 {
                    // This state only occurs when the underlying data source is empty.
                    // Don't fall through to change the state to `Reading`, because we can
                    // always reset an empty stream.
                    assert_eq!(consumed, 0);
                    Ok(&[])
                } else if consumed < inner_len {
                    // Re-call so we aren't extending the lifetime of the mutable borrow
                    // on `self.inner` to outside the conditional, which would prevent us
                    // from performing other mutable operations on the other side.
                    Ok(&self.inner.fill_buf()?[consumed..])
                } else {
                    // We're done peeking.
                    self.inner.consume(consumed);
                    self.state = PeekState::Reading;
                    self.inner.fill_buf()
                }
            }
            PeekState::Reading => self.inner.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.state {
            PeekState::Peeking { consumed, .. } => *consumed += amt,
            PeekState::Reading => self.inner.consume(amt),
        }
    }
}
