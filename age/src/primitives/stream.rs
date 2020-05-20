//! I/O helper structs for age file encryption and decryption.

use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaChaPoly1305,
};
use pin_project::pin_project;
use secrecy::{ExposeSecret, SecretVec};
use std::convert::TryInto;
use std::io::{self, Read, Seek, SeekFrom, Write};

#[cfg(feature = "async")]
use futures::{
    io::{AsyncRead, Error},
    ready,
    task::{Context, Poll},
};
#[cfg(feature = "async")]
use std::pin::Pin;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

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
    fn new(key: &[u8; 32]) -> Self {
        Stream {
            aead: ChaChaPoly1305::new((*key).into()),
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
    pub(crate) fn encrypt<W: Write>(key: &[u8; 32], inner: W) -> StreamWriter<W> {
        StreamWriter {
            stream: Self::new(key),
            inner,
            chunk: Vec::with_capacity(CHUNK_SIZE),
        }
    }

    /// Wraps `STREAM` decryption under the given `key` around a reader.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    pub(crate) fn decrypt<R: Read>(key: &[u8; 32], inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
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
    pub(crate) fn decrypt_async<R: AsyncRead>(key: &[u8; 32], inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
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
pub struct StreamWriter<W: Write> {
    stream: Stream,
    inner: W,
    chunk: Vec<u8>,
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
            let mut to_write = CHUNK_SIZE - self.chunk.len();
            if to_write > buf.len() {
                to_write = buf.len()
            }

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

        let mut to_read = chunk.expose_secret().len() - cur_chunk_offset;
        if to_read > buf.len() {
            to_read = buf.len()
        }

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
        }

        // All done!
        Ok(target_pos)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    use super::{Stream, CHUNK_SIZE};

    #[test]
    fn chunk_round_trip() {
        let key = [7; 32];
        let data = vec![42; CHUNK_SIZE];

        let encrypted = {
            let mut s = Stream::new(&key);
            s.encrypt_chunk(&data, false).unwrap()
        };

        let decrypted = {
            let mut s = Stream::new(&key);
            s.decrypt_chunk(&encrypted, false).unwrap()
        };

        assert_eq!(decrypted.expose_secret(), &data);
    }

    #[test]
    fn last_chunk_round_trip() {
        let key = [7; 32];
        let data = vec![42; CHUNK_SIZE];

        let encrypted = {
            let mut s = Stream::new(&key);
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
            let mut s = Stream::new(&key);
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

    #[test]
    fn stream_round_trip_short() {
        let key = [7; 32];
        let data = vec![42; 1024];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let decrypted = {
            let mut buf = vec![];
            let mut r = Stream::decrypt(&key, &encrypted[..]);
            r.read_to_end(&mut buf).unwrap();
            buf
        };

        assert_eq!(decrypted, data);
    }

    #[test]
    fn stream_round_trip_chunk() {
        let key = [7; 32];
        let data = vec![42; CHUNK_SIZE];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let decrypted = {
            let mut buf = vec![];
            let mut r = Stream::decrypt(&key, &encrypted[..]);
            r.read_to_end(&mut buf).unwrap();
            buf
        };

        assert_eq!(decrypted, data);
    }

    #[test]
    fn stream_round_trip_long() {
        let key = [7; 32];
        let data = vec![42; 100 * 1024];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let decrypted = {
            let mut buf = vec![];
            let mut r = Stream::decrypt(&key, &encrypted[..]);
            r.read_to_end(&mut buf).unwrap();
            buf
        };

        assert_eq!(decrypted, data);
    }

    #[test]
    fn stream_fails_to_decrypt_truncated_file() {
        let key = [7; 32];
        let data = vec![42; 2 * CHUNK_SIZE];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            // Forget to call w.finish()!
        };

        let mut buf = vec![];
        let mut r = Stream::decrypt(&key, &encrypted[..]);
        assert_eq!(
            r.read_to_end(&mut buf).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn stream_seeking() {
        let key = [7; 32];
        let mut data = vec![0; 100 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let mut r = Stream::decrypt(&key, Cursor::new(encrypted));

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
