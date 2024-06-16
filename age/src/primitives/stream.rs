//! I/O helper structs for age file encryption and decryption.

use age_core::secrecy::{ExposeSecret, SecretVec};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, KeySizeUser},
    ChaCha20Poly1305,
};
use pin_project::pin_project;
use std::cmp;
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

#[cfg(feature = "async")]
use futures::{
    io::{AsyncRead, AsyncSeek, AsyncWrite, Error},
    ready,
    task::{Context, Poll},
};
#[cfg(feature = "async")]
use std::pin::Pin;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

pub(crate) struct PayloadKey(
    pub(crate) GenericArray<u8, <ChaCha20Poly1305 as KeySizeUser>::KeySize>,
);

impl Drop for PayloadKey {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// The nonce used in age's STREAM encryption.
///
/// Structured as an 11 bytes of big endian counter, and 1 byte of last block flag
/// (`0x00 / 0x01`). We store this in the lower 12 bytes of a `u128`.
#[derive(Clone, Copy, Default)]
struct Nonce(u128);

impl Nonce {
    /// Unsets last-chunk flag.
    fn set_counter(&mut self, val: u64) {
        self.0 = u128::from(val) << 8;
    }

    fn increment_counter(&mut self) {
        // Increment the 11-byte counter
        self.0 += 1 << 8;
        if self.0 >> (8 * 12) != 0 {
            panic!("We overflowed the nonce!");
        }
    }

    fn is_last(&self) -> bool {
        self.0 & 1 != 0
    }

    fn set_last(&mut self, last: bool) -> Result<(), ()> {
        if !self.is_last() {
            self.0 |= u128::from(last);
            Ok(())
        } else {
            Err(())
        }
    }

    fn to_bytes(self) -> [u8; 12] {
        self.0.to_be_bytes()[4..]
            .try_into()
            .expect("slice is correct length")
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
struct EncryptedChunk {
    bytes: Vec<u8>,
    offset: usize,
}

/// `STREAM[key](plaintext)`
///
/// The [STREAM] construction for online authenticated encryption, instantiated with
/// ChaCha20-Poly1305 in 64KiB chunks, and a nonce structure of 11 bytes of big endian
/// counter, and 1 byte of last block flag (0x00 / 0x01).
///
/// [STREAM]: https://eprint.iacr.org/2015/189.pdf
pub(crate) struct Stream {
    aead: ChaCha20Poly1305,
    nonce: Nonce,
}

impl Stream {
    fn new(key: PayloadKey) -> Self {
        Stream {
            aead: ChaCha20Poly1305::new(&key.0),
            nonce: Nonce::default(),
        }
    }

    /// Wraps `STREAM` encryption under the given `key` around a writer.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    pub(crate) fn encrypt<W: Write>(key: PayloadKey, inner: W) -> StreamWriter<W> {
        StreamWriter {
            stream: Self::new(key),
            inner,
            chunk: Vec::with_capacity(CHUNK_SIZE),
            #[cfg(feature = "async")]
            encrypted_chunk: None,
        }
    }

    /// Wraps `STREAM` encryption under the given `key` around a writer.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub(crate) fn encrypt_async<W: AsyncWrite>(key: PayloadKey, inner: W) -> StreamWriter<W> {
        StreamWriter {
            stream: Self::new(key),
            inner,
            chunk: Vec::with_capacity(CHUNK_SIZE),
            encrypted_chunk: None,
        }
    }

    /// Wraps `STREAM` decryption under the given `key` around a reader.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    pub(crate) fn decrypt<R: Read>(key: PayloadKey, inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            plaintext_len: None,
            cur_plaintext_pos: 0,
            chunk: None,
            #[cfg(feature = "async")]
            seek_state: StreamSeekState::NoSeek,
        }
    }

    /// Wraps `STREAM` decryption under the given `key` around a reader.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub(crate) fn decrypt_async<R: AsyncRead>(key: PayloadKey, inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            plaintext_len: None,
            cur_plaintext_pos: 0,
            chunk: None,
            #[cfg(feature = "async")]
            seek_state: StreamSeekState::NoSeek,
        }
    }

    fn encrypt_chunk(&mut self, chunk: &[u8], last: bool) -> io::Result<Vec<u8>> {
        assert!(chunk.len() <= CHUNK_SIZE);

        self.nonce.set_last(last).map_err(|_| {
            io::Error::new(io::ErrorKind::WriteZero, "last chunk has been processed")
        })?;

        let encrypted = self
            .aead
            .encrypt(&self.nonce.to_bytes().into(), chunk)
            .expect("we will never hit chacha20::MAX_BLOCKS because of the chunk size");
        self.nonce.increment_counter();

        Ok(encrypted)
    }

    fn decrypt_chunk(&mut self, chunk: &[u8], last: bool) -> io::Result<SecretVec<u8>> {
        assert!(chunk.len() <= ENCRYPTED_CHUNK_SIZE);

        self.nonce.set_last(last).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "last chunk has been processed")
        })?;

        let decrypted = self
            .aead
            .decrypt(&self.nonce.to_bytes().into(), chunk)
            .map(SecretVec::new)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?;
        self.nonce.increment_counter();

        Ok(decrypted)
    }

    fn is_complete(&self) -> bool {
        self.nonce.is_last()
    }
}

/// Writes an encrypted age file.
#[pin_project(project = StreamWriterProj)]
pub struct StreamWriter<W> {
    stream: Stream,
    #[pin]
    inner: W,
    chunk: Vec<u8>,
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    encrypted_chunk: Option<EncryptedChunk>,
}

impl<W: Write> StreamWriter<W> {
    /// Writes the final chunk of the age file.
    ///
    /// You **MUST** call `finish` when you are done writing, in order to finish the
    /// encryption process. Failing to call `finish` will result in a truncated file that
    /// that will fail to decrypt.
    pub fn finish(mut self) -> io::Result<W> {
        let encrypted = self.stream.encrypt_chunk(&self.chunk, true)?;
        self.inner.write_all(&encrypted)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;

        while !buf.is_empty() {
            let to_write = cmp::min(CHUNK_SIZE - self.chunk.len(), buf.len());
            self.chunk.extend_from_slice(&buf[..to_write]);
            bytes_written += to_write;
            buf = &buf[to_write..];

            // At this point, either buf is empty, or we have a full chunk.
            assert!(buf.is_empty() || self.chunk.len() == CHUNK_SIZE);

            // Only encrypt the chunk if we have more data to write, as the last
            // chunk must be written in finish().
            if !buf.is_empty() {
                let encrypted = self.stream.encrypt_chunk(&self.chunk, false)?;
                self.inner.write_all(&encrypted)?;
                self.chunk.clear();
            }
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> StreamWriter<W> {
    fn poll_flush_chunk(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let StreamWriterProj {
            mut inner,
            encrypted_chunk,
            ..
        } = self.project();

        if let Some(chunk) = encrypted_chunk {
            loop {
                chunk.offset +=
                    ready!(inner.as_mut().poll_write(cx, &chunk.bytes[chunk.offset..]))?;
                if chunk.offset == chunk.bytes.len() {
                    break;
                }
            }
        }
        *encrypted_chunk = None;

        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> AsyncWrite for StreamWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If the buffer is empty, return immediately
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            ready!(self.as_mut().poll_flush_chunk(cx))?;

            // We can encounter one of three cases here:
            // 1. `0 < buf.len() <= CHUNK_SIZE - self.chunk.len()`: we append to the
            //    partial chunk and return. This may happen to complete the chunk.
            // 2. `0 < CHUNK_SIZE - self.chunk.len() < buf.len()`: we consume part of
            //    `buf` to complete the chunk, encrypt it, and return.
            // 3. `0 == CHUNK_SIZE - self.chunk.len() < buf.len()`: we hit case 1 in a
            //    previous invocation. We encrypt the chunk, and then loop around (where
            //    we are guaranteed to hit case 1).
            let to_write = cmp::min(CHUNK_SIZE - self.chunk.len(), buf.len());

            self.as_mut()
                .project()
                .chunk
                .extend_from_slice(&buf[..to_write]);
            buf = &buf[to_write..];

            // At this point, either buf is empty, or we have a full chunk.
            assert!(buf.is_empty() || self.chunk.len() == CHUNK_SIZE);

            // Only encrypt the chunk if we have more data to write, as the last
            // chunk must be written in poll_close().
            if !buf.is_empty() {
                let this = self.as_mut().project();
                *this.encrypted_chunk = Some(EncryptedChunk {
                    bytes: this.stream.encrypt_chunk(this.chunk, false)?,
                    offset: 0,
                });
                this.chunk.clear();
            }

            // If we wrote some data, return how much we wrote
            if to_write > 0 {
                return Poll::Ready(Ok(to_write));
            }

            // If we didn't write any data, loop and write some, to ensure
            // this function does not return 0. This enables compatibility with
            // futures::io::copy() and tokio::io::copy(), which will return a
            // WriteZero error in that case.
            // Since those functions copy 8K at a time, and CHUNK_SIZE is
            // a multiple of 8K, this ends up happening once for each chunk
            // after the first one
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush_chunk(cx))?;
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any remaining encrypted chunk bytes.
        ready!(self.as_mut().poll_flush_chunk(cx))?;

        if !self.stream.is_complete() {
            // Finish the stream.
            let this = self.as_mut().project();
            *this.encrypted_chunk = Some(EncryptedChunk {
                bytes: this.stream.encrypt_chunk(this.chunk, true)?,
                offset: 0,
            });
        }

        // Flush the final chunk (if we didn't in the first call).
        ready!(self.as_mut().poll_flush_chunk(cx))?;
        self.project().inner.poll_close(cx)
    }
}

/// The position in the underlying reader corresponding to the start of the stream.
///
/// To impl Seek for StreamReader, we need to know the point in the reader corresponding
/// to the first byte of the stream. But we can't query the reader for its current
/// position without having a specific constructor for `R: Read + Seek`, which makes the
/// higher-level API more complex. Instead, we count the number of bytes that have been
/// read from the reader until we first need to seek, and then inside `impl Seek` we can
/// query the reader's current position and figure out where the start was.
enum StartPos {
    /// An offset that we can subtract from the current position.
    Implicit(u64),
    /// The precise start position.
    Explicit(u64),
}

/// Provides access to a decrypted age file.
///
/// ### AsyncSeek implementation note
///
/// Starting a `seek()` future and then dropping the future before it is completed puts the [StreamReader] in a non-working state.
/// Make sure to complete all `seek()` calls to completion
#[pin_project]
pub struct StreamReader<R> {
    stream: Stream,
    #[pin]
    inner: R,
    encrypted_chunk: Vec<u8>,
    encrypted_pos: usize,
    start: StartPos,
    plaintext_len: Option<u64>,
    cur_plaintext_pos: u64,
    chunk: Option<SecretVec<u8>>,
    #[cfg(feature = "async")]
    seek_state: StreamSeekState,
}

impl<R> StreamReader<R> {
    fn count_bytes(&mut self, read: usize) {
        // We only need to count if we haven't yet worked out the start position.
        if let StartPos::Implicit(offset) = &mut self.start {
            *offset += read as u64;
        }
    }

    fn decrypt_chunk(&mut self) -> io::Result<()> {
        self.count_bytes(self.encrypted_pos);
        let chunk = &self.encrypted_chunk[..self.encrypted_pos];

        if chunk.is_empty() {
            if !self.stream.is_complete() {
                // Stream has ended before seeing the last chunk.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "age file is truncated",
                ));
            }
        } else {
            // This check works for all cases except when the age file is an integer
            // multiple of the chunk size. In that case, we try decrypting twice on a
            // decryption failure.
            let last = chunk.len() < ENCRYPTED_CHUNK_SIZE;

            self.chunk = match (self.stream.decrypt_chunk(chunk, last), last) {
                (Ok(chunk), _)
                    if chunk.expose_secret().is_empty() && self.cur_plaintext_pos > 0 =>
                {
                    assert!(last);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        crate::fl!("err-stream-last-chunk-empty"),
                    ));
                }
                (Ok(chunk), _) => Some(chunk),
                (Err(_), false) => Some(self.stream.decrypt_chunk(chunk, true)?),
                (Err(e), true) => return Err(e),
            };
        }

        // We've finished with this encrypted chunk.
        self.encrypted_pos = 0;

        Ok(())
    }

    fn read_from_chunk(&mut self, buf: &mut [u8]) -> usize {
        if self.chunk.is_none() {
            return 0;
        }

        let chunk = self.chunk.as_ref().unwrap();
        let cur_chunk_offset = self.cur_plaintext_pos as usize % CHUNK_SIZE;

        let to_read = cmp::min(chunk.expose_secret().len() - cur_chunk_offset, buf.len());

        buf[..to_read]
            .copy_from_slice(&chunk.expose_secret()[cur_chunk_offset..cur_chunk_offset + to_read]);
        self.cur_plaintext_pos += to_read as u64;
        if self.cur_plaintext_pos % CHUNK_SIZE as u64 == 0 {
            // We've finished with the current chunk.
            self.chunk = None;
        }

        to_read
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.chunk.is_none() {
            while self.encrypted_pos < ENCRYPTED_CHUNK_SIZE {
                match self
                    .inner
                    .read(&mut self.encrypted_chunk[self.encrypted_pos..])
                {
                    Ok(0) => break,
                    Ok(n) => self.encrypted_pos += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Err(e),
                    },
                }
            }
            self.decrypt_chunk()?;
        }

        Ok(self.read_from_chunk(buf))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + Unpin> AsyncRead for StreamReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        if self.chunk.is_none() {
            while self.encrypted_pos < ENCRYPTED_CHUNK_SIZE {
                let this = self.as_mut().project();
                match ready!(this
                    .inner
                    .poll_read(cx, &mut this.encrypted_chunk[*this.encrypted_pos..]))
                {
                    Ok(0) => break,
                    Ok(n) => self.encrypted_pos += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Poll::Ready(Err(e)),
                    },
                }
            }
            self.decrypt_chunk()?;
        }

        Poll::Ready(Ok(self.read_from_chunk(buf)))
    }
}

impl<R: Read + Seek> StreamReader<R> {
    fn start(&mut self) -> io::Result<u64> {
        match self.start {
            StartPos::Implicit(offset) => {
                let current = self.inner.seek(SeekFrom::Current(0))?;
                let start = current - offset;

                // Cache the start for future calls.
                self.start = StartPos::Explicit(start);

                Ok(start)
            }
            StartPos::Explicit(start) => Ok(start),
        }
    }

    /// Returns the length of the plaintext
    fn len(&mut self) -> io::Result<u64> {
        match self.plaintext_len {
            None => {
                // Cache the current position and nonce, and then grab the start and end
                // ciphertext positions.
                let cur_pos = self.inner.seek(SeekFrom::Current(0))?;
                let cur_nonce = self.stream.nonce.0;
                let ct_start = self.start()?;
                let ct_end = self.inner.seek(SeekFrom::End(0))?;
                let ct_len = ct_end - ct_start;

                // Use ceiling division to determine the number of chunks.
                let num_chunks =
                    (ct_len + (ENCRYPTED_CHUNK_SIZE as u64 - 1)) / ENCRYPTED_CHUNK_SIZE as u64;

                // Authenticate the ciphertext length by checking that we can successfully
                // decrypt the last chunk _as_ a last chunk.
                let last_chunk_start = ct_start + ((num_chunks - 1) * ENCRYPTED_CHUNK_SIZE as u64);
                let mut last_chunk = Vec::with_capacity((ct_end - last_chunk_start) as usize);
                self.inner.seek(SeekFrom::Start(last_chunk_start))?;
                self.inner.read_to_end(&mut last_chunk)?;
                self.stream.nonce.set_counter(num_chunks - 1);
                self.stream.decrypt_chunk(&last_chunk, true).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Last chunk is invalid, stream might be truncated",
                    )
                })?;

                // Now that we have authenticated the ciphertext length, we can use it to
                // calculate the plaintext length.
                let total_tag_size = num_chunks * TAG_SIZE as u64;
                let pt_len = ct_len - total_tag_size;

                // Return to the original position and restore the nonce.
                self.inner.seek(SeekFrom::Start(cur_pos))?;
                self.stream.nonce = Nonce(cur_nonce);

                // Cache the length for future calls.
                self.plaintext_len = Some(pt_len);

                Ok(pt_len)
            }
            Some(pt_len) => Ok(pt_len),
        }
    }
}

impl<R: Read + Seek> Seek for StreamReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Convert the offset into the target position within the plaintext
        let start = self.start()?;
        let target_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(offset) => {
                let res = (self.cur_plaintext_pos as i64) + offset;
                if res >= 0 {
                    res as u64
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }
            }
            SeekFrom::End(offset) => {
                let res = (self.len()? as i64) + offset;
                if res >= 0 {
                    res as u64
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }
            }
        };

        let cur_chunk_index = self.cur_plaintext_pos / CHUNK_SIZE as u64;

        let target_chunk_index = target_pos / CHUNK_SIZE as u64;
        let target_chunk_offset = target_pos % CHUNK_SIZE as u64;

        if target_chunk_index == cur_chunk_index {
            // We just need to reposition ourselves within the current chunk.
            self.cur_plaintext_pos = target_pos;
        } else {
            // Clear the current chunk
            self.chunk = None;

            // Seek to the beginning of the target chunk
            self.inner.seek(SeekFrom::Start(
                start + (target_chunk_index * ENCRYPTED_CHUNK_SIZE as u64),
            ))?;
            self.stream.nonce.set_counter(target_chunk_index);
            self.cur_plaintext_pos = target_chunk_index * CHUNK_SIZE as u64;

            // Read and drop bytes from the chunk to reach the target position.
            if target_chunk_offset > 0 {
                let mut to_drop = vec![0; target_chunk_offset as usize];
                self.read_exact(&mut to_drop)?;
            }
            // We need to handle the edge case where the last chunk is not short, and
            // `target_pos == self.len()` (so `target_chunk_index` points to the chunk
            // after the last chunk). The next read would return no bytes, but because
            // `target_chunk_offset == 0` we weren't forced to read past any in-chunk
            // bytes, and thus have not set the `last` flag on the nonce.
            //
            // To handle this edge case, when `target_pos` is a multiple of the chunk
            // size (i.e. this conditional branch), we compute the length of the
            // plaintext. This is cached, so the overhead should be minimal.
            else if target_pos == self.len()? {
                self.stream
                    .nonce
                    .set_last(true)
                    .expect("We unset the last chunk flag earlier");
            }
        }

        // All done!
        Ok(target_pos)
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + AsyncSeek + Unpin> StreamReader<R> {
    /// async poll alternative to the [StreamReader::start] function
    fn poll_start(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match self.start {
            StartPos::Implicit(offset) => {
                let this = self.project();
                let current = ready!(this.inner.poll_seek(cx, SeekFrom::Current(0)))?;
                let start = current - offset;

                // Cache the start for future calls.
                *this.start = StartPos::Explicit(start);

                Poll::Ready(Ok(start))
            }
            StartPos::Explicit(start) => Poll::Ready(Ok(start)),
        }
    }

    /// async poll-able implementation of the [StreamReader::len] function
    ///
    /// The current state of the len function is governed by the various input arguments,
    /// so for each poll the same arguments have to be reused for this function to work as intended
    fn poll_len(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        ct_start: u64,
        cur_pos_nonce: &mut Option<(u64, u128)>,
        ct_end: &mut Option<u64>,
        buf: &mut Option<Vec<u8>>,
        done_reading: &mut bool,
    ) -> Poll<io::Result<u64>> {
        if let Some(pt_len) = self.plaintext_len {
            return Poll::Ready(Ok(pt_len));
        }
        let mut this = self.project();

        // Cache the current position and nonce,
        let (cur_pos, cur_nonce) = match cur_pos_nonce {
            Some(s) => *s,
            m => {
                let current = ready!(this.inner.as_mut().poll_seek(cx, SeekFrom::Current(0)))?;
                *m = Some((current, this.stream.nonce.0));
                (current, this.stream.nonce.0)
            }
        };

        // and then grab the end ciphertext position.
        let ct_end = match ct_end {
            Some(s) => *s,
            m => {
                let new = ready!(this.inner.as_mut().poll_seek(cx, SeekFrom::End(0)))?;
                *m = Some(new);
                new
            }
        };

        let ct_len = ct_end - ct_start;
        // Use ceiling division to determine the number of chunks.
        let num_chunks = (ct_len + (ENCRYPTED_CHUNK_SIZE as u64 - 1)) / ENCRYPTED_CHUNK_SIZE as u64;

        // seek to the last chunk, and then allocate the buffer for it
        let buf = match buf {
            Some(s) => s,
            m => {
                let last_chunk_start = ct_start + ((num_chunks - 1) * ENCRYPTED_CHUNK_SIZE as u64);

                ready!(this
                    .inner
                    .as_mut()
                    .poll_seek(cx, SeekFrom::Start(last_chunk_start)))?;
                let buf = Vec::with_capacity((ct_end - last_chunk_start) as usize);
                m.insert(buf)
            }
        };

        if !*done_reading {
            // read the last chunk
            let mut int_buf = [0u8; ENCRYPTED_CHUNK_SIZE];
            loop {
                let read = ready!(this.inner.as_mut().poll_read(cx, &mut int_buf))?;
                if read == 0 {
                    break;
                } else {
                    buf.extend_from_slice(&int_buf[..read]);
                }
            }
            // Authenticate the ciphertext length by checking that we can successfully
            // decrypt the last chunk _as_ a last chunk.
            *done_reading = true;
            this.stream.nonce.set_counter(num_chunks - 1);
            this.stream
                .decrypt_chunk(buf.as_slice(), true)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Last chunk is invalid, stream might be truncated",
                    )
                })?;
        }

        // Now that we have authenticated the ciphertext length, we can use it to
        // calculate the plaintext length.
        let total_tag_size = num_chunks * TAG_SIZE as u64;
        let pt_len = ct_len - total_tag_size;

        // Return to the original position and restore the nonce.
        ready!(this.inner.poll_seek(cx, SeekFrom::Start(cur_pos)))?;
        this.stream.nonce = Nonce(cur_nonce);

        // Cache the length for future calls.
        *this.plaintext_len = Some(pt_len);
        return Poll::Ready(Ok(pt_len));
    }
}

#[derive(Debug)]
enum StreamSeekState {
    NoSeek,
    LenCalc {
        start: u64,
        cur_pos_nonce: Option<(u64, u128)>,
        ct_end: Option<u64>,
        buf: Option<Vec<u8>>,
        done_reading: bool,
    },
    Seeking {
        ct_start: u64,
        pt_len: u64,
        target_pos: u64,
    },
    ReadChunk {
        target_pos: u64,
        buffer: Vec<u8>,
        total_read: usize,
    },
    Done {
        target_pos: u64,
    },
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + AsyncSeek + Unpin> AsyncSeek for StreamReader<R> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        loop {
            let tmp_state = std::mem::replace(&mut self.seek_state, StreamSeekState::NoSeek);

            let (next_state, pending) = match tmp_state {
                // get the starting position
                StreamSeekState::NoSeek => match self.as_mut().poll_start(cx) {
                    Poll::Ready(r) => (
                        StreamSeekState::LenCalc {
                            start: r?,
                            cur_pos_nonce: None,
                            ct_end: None,
                            buf: None,
                            done_reading: false,
                        },
                        false,
                    ),
                    Poll::Pending => (StreamSeekState::NoSeek, true),
                },
                // calculate the length of the plaintext
                StreamSeekState::LenCalc {
                    start,
                    mut cur_pos_nonce,
                    mut ct_end,
                    mut buf,
                    mut done_reading,
                } => {
                    // calculate the length of the plaintext
                    match self.as_mut().poll_len(
                        cx,
                        start,
                        &mut cur_pos_nonce,
                        &mut ct_end,
                        &mut buf,
                        &mut done_reading,
                    ) {
                        Poll::Ready(pt_len) => {
                            let pt_len = pt_len?;

                            // Convert the offset into the target position within the plaintext
                            let target_pos = match pos {
                                SeekFrom::Start(offset) => offset,
                                SeekFrom::Current(offset) => {
                                    let res = (self.cur_plaintext_pos as i64) + offset;
                                    if res >= 0 {
                                        res as u64
                                    } else {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "cannot seek before the start",
                                        )));
                                    }
                                }
                                SeekFrom::End(offset) => {
                                    let res = (pt_len as i64) + offset;
                                    if res >= 0 {
                                        res as u64
                                    } else {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "cannot seek before the start",
                                        )));
                                    }
                                }
                            };

                            let cur_chunk_index = self.cur_plaintext_pos / CHUNK_SIZE as u64;
                            let target_chunk_index = target_pos / CHUNK_SIZE as u64;

                            if target_chunk_index == cur_chunk_index {
                                // We just need to reposition ourselves within the current chunk.
                                self.cur_plaintext_pos = target_pos;
                                (StreamSeekState::Done { target_pos }, false)
                            } else {
                                // clear the current chunk and start the seek op
                                self.chunk = None;
                                (
                                    StreamSeekState::Seeking {
                                        ct_start: start,
                                        pt_len,
                                        target_pos,
                                    },
                                    false,
                                )
                            }
                        }
                        Poll::Pending => (
                            StreamSeekState::LenCalc {
                                start,
                                cur_pos_nonce,
                                ct_end,
                                buf,
                                done_reading,
                            },
                            true,
                        ),
                    }
                }
                // do the seeking operation
                StreamSeekState::Seeking {
                    ct_start,
                    pt_len,
                    target_pos,
                } => {
                    let target_chunk_index = target_pos / CHUNK_SIZE as u64;
                    let target_chunk_offset = target_pos % CHUNK_SIZE as u64;

                    match Pin::new(&mut self.inner).poll_seek(
                        cx,
                        SeekFrom::Start(
                            ct_start + (target_chunk_index * ENCRYPTED_CHUNK_SIZE as u64),
                        ),
                    ) {
                        Poll::Ready(r) => {
                            r?;
                            self.stream.nonce.set_counter(target_chunk_index);
                            self.cur_plaintext_pos = target_chunk_index * CHUNK_SIZE as u64;

                            // Read and drop bytes from the chunk to reach the target position.
                            if target_chunk_offset > 0 {
                                (
                                    StreamSeekState::ReadChunk {
                                        target_pos,
                                        buffer: vec![0; target_chunk_offset as usize],
                                        total_read: 0,
                                    },
                                    false,
                                )
                            } else {
                                if target_pos == pt_len {
                                    self.stream
                                        .nonce
                                        .set_last(true)
                                        .expect("We unset the last chunk flag earlier");
                                }
                                (StreamSeekState::Done { target_pos }, false)
                            }
                        }
                        Poll::Pending => (
                            StreamSeekState::Seeking {
                                ct_start,
                                pt_len,
                                target_pos,
                            },
                            true,
                        ),
                    }
                }
                // read the offset into the target chunk
                StreamSeekState::ReadChunk {
                    target_pos,
                    mut buffer,
                    mut total_read,
                } => {
                    let target_pos = target_pos;
                    loop {
                        let data_to_be_read = &mut buffer.as_mut_slice()[total_read..];
                        let read_len = match self.as_mut().poll_read(cx, data_to_be_read) {
                            Poll::Ready(r) => r,
                            Poll::Pending => {
                                self.seek_state = StreamSeekState::ReadChunk {
                                    target_pos,
                                    buffer,
                                    total_read,
                                };
                                return Poll::Pending;
                            }
                        }?;
                        total_read += read_len;
                        if total_read == buffer.len() {
                            break;
                        } else if total_read > buffer.len() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "read to much data???",
                            )));
                        } else if read_len == 0 {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                        }
                    }
                    (StreamSeekState::Done { target_pos }, false)
                }
                // should not be reachable but for good measure
                StreamSeekState::Done { target_pos } => {
                    (StreamSeekState::Done { target_pos }, false)
                }
            };

            if let StreamSeekState::Done { target_pos } = &next_state {
                return Poll::Ready(Ok(*target_pos));
            } else {
                self.seek_state = next_state;
                if pending {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use age_core::secrecy::ExposeSecret;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    use super::{PayloadKey, Stream, CHUNK_SIZE};

    #[cfg(feature = "async")]
    use futures::{
        io::{AsyncRead, AsyncWrite},
        pin_mut,
        task::Poll,
    };
    #[cfg(feature = "async")]
    use futures_test::task::noop_context;

    #[test]
    fn chunk_round_trip() {
        let data = vec![42; CHUNK_SIZE];

        let encrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            s.encrypt_chunk(&data, false).unwrap()
        };

        let decrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            s.decrypt_chunk(&encrypted, false).unwrap()
        };

        assert_eq!(decrypted.expose_secret(), &data);
    }

    #[test]
    fn last_chunk_round_trip() {
        let data = vec![42; CHUNK_SIZE];

        let encrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            let res = s.encrypt_chunk(&data, true).unwrap();

            // Further calls return an error
            assert_eq!(
                s.encrypt_chunk(&data, false).unwrap_err().kind(),
                io::ErrorKind::WriteZero
            );
            assert_eq!(
                s.encrypt_chunk(&data, true).unwrap_err().kind(),
                io::ErrorKind::WriteZero
            );

            res
        };

        let decrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            let res = s.decrypt_chunk(&encrypted, true).unwrap();

            // Further calls return an error
            match s.decrypt_chunk(&encrypted, false) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
                _ => panic!("Expected error"),
            }
            match s.decrypt_chunk(&encrypted, true) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
                _ => panic!("Expected error"),
            }

            res
        };

        assert_eq!(decrypted.expose_secret(), &data);
    }

    fn stream_round_trip(data: &[u8]) {
        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(data).unwrap();
            w.finish().unwrap();
        };

        let decrypted = {
            let mut buf = vec![];
            let mut r = Stream::decrypt(PayloadKey([7; 32].into()), &encrypted[..]);
            r.read_to_end(&mut buf).unwrap();
            buf
        };

        assert_eq!(decrypted, data);
    }

    /// Check that we can encrypt an empty slice.
    ///
    /// This is the sole exception to the "last chunk must be non-empty" rule.
    #[test]
    fn stream_round_trip_empty() {
        stream_round_trip(&[]);
    }

    #[test]
    fn stream_round_trip_short() {
        stream_round_trip(&[42; 1024]);
    }

    #[test]
    fn stream_round_trip_chunk() {
        stream_round_trip(&[42; CHUNK_SIZE]);
    }

    #[test]
    fn stream_round_trip_long() {
        stream_round_trip(&[42; 100 * 1024]);
    }

    #[cfg(feature = "async")]
    fn stream_async_round_trip(data: &[u8]) {
        let mut encrypted = vec![];
        {
            let w = Stream::encrypt_async(PayloadKey([7; 32].into()), &mut encrypted);
            pin_mut!(w);

            let mut cx = noop_context();

            let mut tmp = data;
            loop {
                match w.as_mut().poll_write(&mut cx, tmp) {
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(written)) => tmp = &tmp[written..],
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
            loop {
                match w.as_mut().poll_close(&mut cx) {
                    Poll::Ready(Ok(())) => break,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        };

        let decrypted = {
            let mut buf = vec![];
            let r = Stream::decrypt_async(PayloadKey([7; 32].into()), &encrypted[..]);
            pin_mut!(r);

            let mut cx = noop_context();

            let mut tmp = [0; 4096];
            loop {
                match r.as_mut().poll_read(&mut cx, &mut tmp) {
                    Poll::Ready(Ok(0)) => break buf,
                    Poll::Ready(Ok(read)) => buf.extend_from_slice(&tmp[..read]),
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        };

        assert_eq!(decrypted, data);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_round_trip_short() {
        stream_async_round_trip(&[42; 1024]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_round_trip_chunk() {
        stream_async_round_trip(&[42; CHUNK_SIZE]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_round_trip_long() {
        stream_async_round_trip(&[42; 100 * 1024]);
    }

    #[cfg(feature = "async")]
    fn stream_async_io_copy(data: &[u8]) {
        use futures::AsyncWriteExt;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut encrypted = vec![];
        let result = runtime.block_on(async {
            let mut w = Stream::encrypt_async(PayloadKey([7; 32].into()), &mut encrypted);
            match futures::io::copy(data, &mut w).await {
                Ok(written) => {
                    w.close().await.unwrap();
                    Ok(written)
                }
                Err(e) => Err(e),
            }
        });

        match result {
            Ok(written) => assert_eq!(written, data.len() as u64),
            Err(e) => panic!("Unexpected error: {}", e),
        }

        let decrypted = {
            let mut buf = vec![];
            let result = runtime.block_on(async {
                let r = Stream::decrypt_async(PayloadKey([7; 32].into()), &encrypted[..]);
                futures::io::copy(r, &mut buf).await
            });

            match result {
                Ok(written) => assert_eq!(written, data.len() as u64),
                Err(e) => panic!("Unexpected error: {}", e),
            }

            buf
        };

        assert_eq!(decrypted, data);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_io_copy_short() {
        stream_async_io_copy(&[42; 1024]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_io_copy_chunk() {
        stream_async_io_copy(&[42; CHUNK_SIZE]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_io_copy_long() {
        stream_async_io_copy(&[42; 100 * 1024]);
    }

    #[test]
    fn stream_fails_to_decrypt_truncated_file() {
        let data = vec![42; 2 * CHUNK_SIZE];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&data).unwrap();
            // Forget to call w.finish()!
        };

        let mut buf = vec![];
        let mut r = Stream::decrypt(PayloadKey([7; 32].into()), &encrypted[..]);
        assert_eq!(
            r.read_to_end(&mut buf).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn stream_seeking() {
        let mut data = vec![0; 100 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let mut r = Stream::decrypt(PayloadKey([7; 32].into()), Cursor::new(encrypted));

        // Read through into the second chunk
        let mut buf = vec![0; 100];
        for i in 0..700 {
            r.read_exact(&mut buf).unwrap();
            assert_eq!(&buf[..], &data[100 * i..100 * (i + 1)]);
        }

        // Seek back into the first chunk
        r.seek(SeekFrom::Start(250)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[250..350]);

        // Seek forwards within this chunk
        r.seek(SeekFrom::Current(510)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[860..960]);

        // Seek backwards from the end
        r.seek(SeekFrom::End(-1337)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[data.len() - 1337..data.len() - 1237]);
    }

    #[test]
    fn seek_from_end_fails_on_truncation() {
        // The plaintext is the string "hello" followed by 65536 zeros, just enough to
        // give us some bytes to play with in the second chunk.
        let mut plaintext: Vec<u8> = b"hello".to_vec();
        plaintext.extend_from_slice(&[0; 65536]);

        // Encrypt the plaintext just like the example code in the docs.
        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&plaintext).unwrap();
            w.finish().unwrap();
        };

        // First check the correct behavior of seeks relative to EOF. Create a decrypting
        // reader, and move it one byte forward from the start, using SeekFrom::End.
        // Confirm that reading 4 bytes from that point gives us "ello", as it should.
        let mut reader = Stream::decrypt(PayloadKey([7; 32].into()), Cursor::new(&encrypted));
        let eof_relative_offset = 1_i64 - plaintext.len() as i64;
        reader.seek(SeekFrom::End(eof_relative_offset)).unwrap();
        let mut buf = [0; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ello", "This is correct.");

        // Do the same thing again, except this time truncate the ciphertext by one byte
        // first. This should cause some sort of error, instead of a successful read that
        // returns the wrong plaintext.
        let truncated_ciphertext = &encrypted[..encrypted.len() - 1];
        let mut truncated_reader = Stream::decrypt(
            PayloadKey([7; 32].into()),
            Cursor::new(truncated_ciphertext),
        );
        // Use the same seek target as above.
        match truncated_reader.seek(SeekFrom::End(eof_relative_offset)) {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    &e.to_string(),
                    "Last chunk is invalid, stream might be truncated",
                );
            }
            Ok(_) => panic!("This is a security issue."),
        }
    }

    #[test]
    fn seek_from_end_with_exact_chunk() {
        let plaintext: Vec<u8> = vec![42; 65536];

        // Encrypt the plaintext just like the example code in the docs.
        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&plaintext).unwrap();
            w.finish().unwrap();
        };

        // Seek to the end of the plaintext before decrypting.
        let mut reader = Stream::decrypt(PayloadKey([7; 32].into()), Cursor::new(&encrypted));
        reader.seek(SeekFrom::End(0)).unwrap();

        // Reading should return no bytes, because we're already at EOF.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn stream_async_seeking() {
        use futures::io::{AsyncReadExt, AsyncSeekExt};
        let mut data = vec![0; 100 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let mut r = Stream::decrypt_async(
            PayloadKey([7; 32].into()),
            futures::io::Cursor::new(encrypted),
        );

        // Read through into the second chunk
        let mut buf = vec![0; 100];
        for i in 0..700 {
            r.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf[..], &data[100 * i..100 * (i + 1)]);
        }

        // Seek back into the first chunk
        r.seek(SeekFrom::Start(250)).await.unwrap();
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], &data[250..350]);

        // Seek forwards within this chunk
        r.seek(SeekFrom::Current(510)).await.unwrap();
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], &data[860..960]);

        // Seek backwards from the end
        r.seek(SeekFrom::End(-1337)).await.unwrap();
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], &data[data.len() - 1337..data.len() - 1237]);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_seek_from_end_fails_on_truncation() {
        use futures::{AsyncReadExt, AsyncSeekExt};
        // The plaintext is the string "hello" followed by 65536 zeros, just enough to
        // give us some bytes to play with in the second chunk.
        let mut plaintext: Vec<u8> = b"hello".to_vec();
        plaintext.extend_from_slice(&[0; 65536]);

        // Encrypt the plaintext just like the example code in the docs.
        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&plaintext).unwrap();
            w.finish().unwrap();
        };

        // First check the correct behavior of seeks relative to EOF. Create a decrypting
        // reader, and move it one byte forward from the start, using SeekFrom::End.
        // Confirm that reading 4 bytes from that point gives us "ello", as it should.
        let mut reader = Stream::decrypt_async(
            PayloadKey([7; 32].into()),
            futures::io::Cursor::new(&encrypted),
        );
        let eof_relative_offset = 1_i64 - plaintext.len() as i64;
        reader
            .seek(SeekFrom::End(eof_relative_offset))
            .await
            .unwrap();
        let mut buf = [0; 4];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ello", "This is correct.");

        // Do the same thing again, except this time truncate the ciphertext by one byte
        // first. This should cause some sort of error, instead of a successful read that
        // returns the wrong plaintext.
        let truncated_ciphertext = &encrypted[..encrypted.len() - 1];
        let mut truncated_reader = Stream::decrypt_async(
            PayloadKey([7; 32].into()),
            futures::io::Cursor::new(truncated_ciphertext),
        );
        // Use the same seek target as above.
        match truncated_reader
            .seek(SeekFrom::End(eof_relative_offset))
            .await
        {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    &e.to_string(),
                    "Last chunk is invalid, stream might be truncated",
                );
            }
            Ok(_) => panic!("This is a security issue."),
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_seek_from_end_with_exact_chunk() {
        use futures::{AsyncReadExt, AsyncSeekExt};
        let plaintext: Vec<u8> = vec![42; 65536];

        // Encrypt the plaintext just like the example code in the docs.
        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(PayloadKey([7; 32].into()), &mut encrypted);
            w.write_all(&plaintext).unwrap();
            w.finish().unwrap();
        };

        // Seek to the end of the plaintext before decrypting.
        let mut reader = Stream::decrypt_async(
            PayloadKey([7; 32].into()),
            futures::io::Cursor::new(&encrypted),
        );
        reader.seek(SeekFrom::End(0)).await.unwrap();

        // Reading should return no bytes, because we're already at EOF.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf.len(), 0);
    }
}
