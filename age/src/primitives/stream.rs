//! I/O helper structs for age file encryption and decryption.

use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, NewAead},
    ChaChaPoly1305,
};
use lazy_static::lazy_static;
use pin_project::pin_project;
use rayon::prelude::*;
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

lazy_static! {
    static ref CHUNKS_SIZE: usize = num_cpus::get() * CHUNK_SIZE;
    static ref ENCRYPTED_CHUNKS_SIZE: usize = num_cpus::get() * ENCRYPTED_CHUNK_SIZE;
}

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

    fn increment_counter(&mut self, by: usize) {
        // Increment the 11-byte counter
        self.0 += (by as u128) << 8;
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
struct EncryptedChunks {
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
            chunks: Vec::with_capacity(*CHUNKS_SIZE),
            #[cfg(feature = "async")]
            encrypted_chunks: None,
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
            chunks: Vec::with_capacity(*CHUNKS_SIZE),
            encrypted_chunks: None,
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
            encrypted_chunks: vec![0; *ENCRYPTED_CHUNKS_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            cur_plaintext_pos: 0,
            chunks: None,
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
            encrypted_chunks: vec![0; *ENCRYPTED_CHUNKS_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            cur_plaintext_pos: 0,
            chunks: None,
        }
    }

    fn encrypt_chunks(&mut self, chunks: &[u8], last: bool) -> io::Result<Vec<u8>> {
        if self.nonce.is_last() {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "last chunk has been processed",
            ))?;
        };

        // Allocate an output buffer of the correct length.
        let chunks_len = chunks.len();
        let chunks = chunks.chunks(CHUNK_SIZE);
        let num_chunks = chunks.len();
        let mut encrypted = vec![0; chunks_len + TAG_SIZE * num_chunks];

        encrypted
            .chunks_mut(ENCRYPTED_CHUNK_SIZE)
            .zip(chunks)
            .enumerate()
            .par_bridge()
            .for_each_with(self.nonce, |nonce, (i, (encrypted, chunk))| {
                nonce.increment_counter(i);
                if i + 1 == num_chunks {
                    nonce.set_last(last).unwrap();
                }

                let (buffer, tag) = encrypted.split_at_mut(chunk.len());
                buffer.copy_from_slice(chunk);
                tag.copy_from_slice(
                    self.aead
                        .encrypt_in_place_detached(&nonce.to_bytes().into(), &[], buffer)
                        .expect("we will never hit chacha20::MAX_BLOCKS because of the chunk size")
                        .as_slice(),
                );
            });

        self.nonce.increment_counter(num_chunks);
        self.nonce.set_last(last).unwrap();

        Ok(encrypted)
    }

    fn decrypt_chunks(&mut self, chunks: &[u8], last: bool) -> io::Result<SecretVec<u8>> {
        if self.nonce.is_last() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "last chunk has been processed",
            ))?;
        };

        // Allocate an output buffer of the correct length.
        let chunks_len = chunks.len();
        let chunks = chunks.chunks(ENCRYPTED_CHUNK_SIZE);
        let num_chunks = chunks.len();
        let mut decrypted = vec![0; chunks_len - TAG_SIZE * num_chunks];

        for (i, (decrypted, chunk)) in decrypted.chunks_mut(CHUNK_SIZE).zip(chunks).enumerate() {
            if i + 1 == num_chunks {
                self.nonce.set_last(last).unwrap();
            }

            let (chunk, tag) = chunk.split_at(decrypted.len());
            decrypted.copy_from_slice(chunk);
            self.aead
                .decrypt_in_place_detached(
                    &self.nonce.to_bytes().into(),
                    &[],
                    decrypted,
                    tag.into(),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?;

            self.nonce.increment_counter(1);
        }

        Ok(SecretVec::new(decrypted))
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
    chunks: Vec<u8>,
    #[cfg(feature = "async")]
    encrypted_chunks: Option<EncryptedChunks>,
}

impl<W: Write> StreamWriter<W> {
    /// Writes the final chunk of the age file.
    ///
    /// You **MUST** call `finish` when you are done writing, in order to finish the
    /// encryption process. Failing to call `finish` will result in a truncated file that
    /// that will fail to decrypt.
    pub fn finish(mut self) -> io::Result<W> {
        let encrypted = self.stream.encrypt_chunks(&self.chunks, true)?;
        self.inner.write_all(&encrypted)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;

        while !buf.is_empty() {
            let to_write = cmp::min(*CHUNKS_SIZE - self.chunks.len(), buf.len());
            self.chunks.extend_from_slice(&buf[..to_write]);
            bytes_written += to_write;
            buf = &buf[to_write..];

            // At this point, either buf is empty, or we have a full set of chunks.
            assert!(buf.is_empty() || self.chunks.len() == *CHUNKS_SIZE);

            // Only encrypt the chunk if we have more data to write, as the last
            // chunk must be written in finish().
            if !buf.is_empty() {
                let encrypted = self.stream.encrypt_chunks(&self.chunks, false)?;
                self.inner.write_all(&encrypted)?;
                self.chunks.clear();
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
            encrypted_chunks,
            ..
        } = self.project();

        if let Some(chunk) = encrypted_chunks {
            loop {
                chunk.offset +=
                    ready!(inner.as_mut().poll_write(cx, &chunk.bytes[chunk.offset..]))?;
                if chunk.offset == chunk.bytes.len() {
                    break;
                }
            }
        }
        *encrypted_chunks = None;

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

        let to_write = cmp::min(*CHUNKS_SIZE - self.chunks.len(), buf.len());

        self.as_mut()
            .project()
            .chunks
            .extend_from_slice(&buf[..to_write]);
        buf = &buf[to_write..];

        // At this point, either buf is empty, or we have a full set of chunks.
        assert!(buf.is_empty() || self.chunks.len() == *CHUNKS_SIZE);

        // Only encrypt the chunk if we have more data to write, as the last
        // chunk must be written in poll_close().
        if !buf.is_empty() {
            let this = self.as_mut().project();
            *this.encrypted_chunks = Some(EncryptedChunks {
                bytes: this.stream.encrypt_chunks(&this.chunks, false)?,
                offset: 0,
            });
            this.chunks.clear();
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
            *this.encrypted_chunks = Some(EncryptedChunks {
                bytes: this.stream.encrypt_chunks(&this.chunks, true)?,
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
    encrypted_chunks: Vec<u8>,
    encrypted_pos: usize,
    start: StartPos,
    cur_plaintext_pos: u64,
    chunks: Option<SecretVec<u8>>,
}

impl<R> StreamReader<R> {
    fn count_bytes(&mut self, read: usize) {
        // We only need to count if we haven't yet worked out the start position.
        if let StartPos::Implicit(offset) = &mut self.start {
            *offset += read as u64;
        }
    }

    fn decrypt_chunks(&mut self) -> io::Result<()> {
        self.count_bytes(self.encrypted_pos);
        let chunks = &self.encrypted_chunks[..self.encrypted_pos];

        if chunks.is_empty() {
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
            // TODO: Generalise to multiple chunks.
            let last = chunks.len() < *ENCRYPTED_CHUNKS_SIZE;

            self.chunks = match (self.stream.decrypt_chunks(chunks, last), last) {
                (Ok(chunk), _) => Some(chunk),
                (Err(_), false) => Some(self.stream.decrypt_chunks(chunks, true)?),
                (Err(e), true) => return Err(e),
            };
        }

        // We've finished with these encrypted chunks.
        self.encrypted_pos = 0;

        Ok(())
    }

    fn read_from_chunks(&mut self, buf: &mut [u8]) -> usize {
        if self.chunks.is_none() {
            return 0;
        }

        let chunks = self.chunks.as_ref().unwrap();
        let cur_chunks_offset = self.cur_plaintext_pos as usize % *CHUNKS_SIZE;

        let to_read = cmp::min(chunks.expose_secret().len() - cur_chunks_offset, buf.len());

        buf[..to_read].copy_from_slice(
            &chunks.expose_secret()[cur_chunks_offset..cur_chunks_offset + to_read],
        );
        self.cur_plaintext_pos += to_read as u64;
        if self.cur_plaintext_pos % *CHUNKS_SIZE as u64 == 0 {
            // We've finished with the current chunks.
            self.chunks = None;
        }

        to_read
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.chunks.is_none() {
            while self.encrypted_pos < *ENCRYPTED_CHUNKS_SIZE {
                match self
                    .inner
                    .read(&mut self.encrypted_chunks[self.encrypted_pos..])
                {
                    Ok(0) => break,
                    Ok(n) => self.encrypted_pos += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Err(e),
                    },
                }
            }
            self.decrypt_chunks()?;
        }

        Ok(self.read_from_chunks(buf))
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> AsyncRead for StreamReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        if self.chunks.is_none() {
            while self.encrypted_pos < *ENCRYPTED_CHUNKS_SIZE {
                let this = self.as_mut().project();
                match ready!(this
                    .inner
                    .poll_read(cx, &mut this.encrypted_chunks[*this.encrypted_pos..]))
                {
                    Ok(0) => break,
                    Ok(n) => self.encrypted_pos += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Poll::Ready(Err(e)),
                    },
                }
            }
            self.decrypt_chunks()?;
        }

        Poll::Ready(Ok(self.read_from_chunks(buf)))
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
                let cur_pos = self.inner.seek(SeekFrom::Current(0))?;
                let ct_end = self.inner.seek(SeekFrom::End(0))?;
                self.inner.seek(SeekFrom::Start(cur_pos))?;

                let num_chunks = (ct_end / ENCRYPTED_CHUNK_SIZE as u64) + 1;
                let total_tag_size = num_chunks * TAG_SIZE as u64;
                let pt_end = ct_end - start - total_tag_size;

                let res = (pt_end as i64) + offset;
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

        let cur_chunk_index = self.cur_plaintext_pos / *CHUNKS_SIZE as u64;

        let target_chunk_index = target_pos / *CHUNKS_SIZE as u64;
        let target_chunk_offset = target_pos % *CHUNKS_SIZE as u64;

        if target_chunk_index == cur_chunk_index {
            // We just need to reposition ourselves within the current chunk.
            self.cur_plaintext_pos = target_pos;
        } else {
            // Clear the current chunk
            self.chunks = None;

            // Seek to the beginning of the target chunk
            self.inner.seek(SeekFrom::Start(
                start + (target_chunk_index * *ENCRYPTED_CHUNKS_SIZE as u64),
            ))?;
            self.stream.nonce.set_counter(target_chunk_index);
            self.cur_plaintext_pos = target_chunk_index * *CHUNKS_SIZE as u64;

            // Read and drop bytes from the chunk to reach the target position.
            if target_chunk_offset > 0 {
                let mut to_drop = vec![0; target_chunk_offset as usize];
                self.read_exact(&mut to_drop)?;
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
            s.encrypt_chunks(&data, false).unwrap()
        };

        let decrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            s.decrypt_chunks(&encrypted, false).unwrap()
        };

        assert_eq!(decrypted.expose_secret(), &data);
    }

    #[test]
    fn last_chunk_round_trip() {
        let data = vec![42; CHUNK_SIZE];

        let encrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            let res = s.encrypt_chunks(&data, true).unwrap();

            // Further calls return an error
            assert_eq!(
                s.encrypt_chunks(&data, false).unwrap_err().kind(),
                io::ErrorKind::WriteZero
            );
            assert_eq!(
                s.encrypt_chunks(&data, true).unwrap_err().kind(),
                io::ErrorKind::WriteZero
            );

            res
        };

        let decrypted = {
            let mut s = Stream::new(PayloadKey([7; 32].into()));
            let res = s.decrypt_chunks(&encrypted, true).unwrap();

            // Further calls return an error
            match s.decrypt_chunks(&encrypted, false) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
                _ => panic!("Expected error"),
            }
            match s.decrypt_chunks(&encrypted, true) {
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
        stream_round_trip(&vec![42; 1024]);
    }

    #[test]
    fn stream_round_trip_chunk() {
        stream_round_trip(&vec![42; CHUNK_SIZE]);
    }

    #[test]
    fn stream_round_trip_long() {
        stream_round_trip(&vec![42; 100 * 1024]);
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
                match w.as_mut().poll_write(&mut cx, &mut tmp) {
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
        stream_async_round_trip(&vec![42; 1024]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_round_trip_chunk() {
        stream_async_round_trip(&vec![42; CHUNK_SIZE]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn stream_async_round_trip_long() {
        stream_async_round_trip(&vec![42; 100 * 1024]);
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
}
