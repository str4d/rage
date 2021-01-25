//! I/O helper structs for age file encryption and decryption.

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaChaPoly1305,
};
use pin_project::pin_project;
use secrecy::{ExposeSecret, SecretVec};
use std::cmp;
use std::convert::TryInto;
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

#[cfg(feature = "async")]
use futures::{
    io::{AsyncRead, AsyncWrite, Error},
    ready,
    task::{Context, Poll},
};
#[cfg(feature = "async")]
use std::pin::Pin;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

pub(crate) struct PayloadKey(
    pub(crate) GenericArray<u8, <ChaChaPoly1305<c2_chacha::Ietf> as NewAead>::KeySize>,
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
            self.0 |= if last { 1 } else { 0 };
            Ok(())
        } else {
            Err(())
        }
    }

    fn to_bytes(&self) -> [u8; 12] {
        self.0.to_be_bytes()[4..]
            .try_into()
            .expect("slice is correct length")
    }
}

#[cfg(feature = "async")]
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
    aead: ChaChaPoly1305<c2_chacha::Ietf>,
    nonce: Nonce,
}

impl Stream {
    fn new(key: PayloadKey) -> Self {
        Stream {
            aead: ChaChaPoly1305::new(&key.0),
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
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "last chunk has been processed",
            )
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
impl<W: AsyncWrite> AsyncWrite for StreamWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_mut().poll_flush_chunk(cx))?;

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
                bytes: this.stream.encrypt_chunk(&this.chunk, false)?,
                offset: 0,
            });
            this.chunk.clear();
        }

        Poll::Ready(Ok(to_write))
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
                bytes: this.stream.encrypt_chunk(&this.chunk, true)?,
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

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
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
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
                _ => panic!("Expected error"),
            }
            match s.decrypt_chunk(&encrypted, true) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
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
            w.write_all(&data).unwrap();
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
                match w.as_mut().poll_write(&mut cx, &tmp) {
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
        let eof_relative_offset = 1 as i64 - plaintext.len() as i64;
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
}
