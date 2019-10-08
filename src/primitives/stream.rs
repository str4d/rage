//! The [STREAM] construction for online authenticated encryption.
//!
//! [STREAM]: https://eprint.iacr.org/2015/189.pdf

use aead::{Aead, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use generic_array::{typenum::U12, GenericArray};
use std::io::{self, Read, Write};

const CHUNK_SIZE: usize = 64 * 1024;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + 16;

/// `STREAM[key](plaintext)`
///
/// Instantiated with ChaCha20-Poly1305 in 64KiB chunks, and a nonce structure of 11 bytes
/// of big endian counter, and 1 byte of last block flag (0x00 / 0x01).
pub struct Stream {
    aead: ChaCha20Poly1305,
    nonce: GenericArray<u8, U12>,
}

impl Stream {
    fn new(key: &[u8; 32]) -> Self {
        Stream {
            aead: ChaCha20Poly1305::new((*key).into()),
            nonce: [0; 12].into(),
        }
    }

    /// Wraps `STREAM` encryption under the given `key` around a writer.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: crate::primitives::hkdf
    pub fn encrypt<W: Write>(key: &[u8; 32], inner: W) -> impl Write {
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
    /// [`HKDF`]: crate::primitives::hkdf
    pub fn decrypt<R: Read>(key: &[u8; 32], inner: R) -> impl Read {
        StreamReader {
            stream: Self::new(key),
            inner,
            unread: vec![],
        }
    }

    fn increment_counter(&mut self) {
        // Increment the 11-byte big-endian counter
        for i in (0..11).rev() {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            } else if i == 0 {
                panic!("We overflowed the nonce!");
            }
        }
    }

    fn encrypt_chunk(&mut self, chunk: &[u8], last: bool) -> io::Result<Vec<u8>> {
        assert!(chunk.len() <= CHUNK_SIZE);

        if self.nonce[11] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "last chunk has been processed",
            ));
        }
        self.nonce[11] = if last { 1 } else { 0 };

        let encrypted = self
            .aead
            .encrypt(&self.nonce, chunk)
            .expect("we will never hit chacha20::MAX_BLOCKS because of the chunk size");
        self.increment_counter();

        Ok(encrypted)
    }

    fn decrypt_chunk(&mut self, chunk: &[u8], last: bool) -> io::Result<Vec<u8>> {
        assert!(chunk.len() <= ENCRYPTED_CHUNK_SIZE);

        if self.nonce[11] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "last chunk has been processed",
            ));
        }
        self.nonce[11] = if last { 1 } else { 0 };

        let decrypted = self
            .aead
            .decrypt(&self.nonce, chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?;
        self.increment_counter();

        Ok(decrypted)
    }
}

struct StreamWriter<W: Write> {
    stream: Stream,
    inner: W,
    chunk: Vec<u8>,
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
            // chunk must be written in flush().
            if !buf.is_empty() {
                let encrypted = self.stream.encrypt_chunk(&self.chunk, false)?;
                self.inner.write_all(&encrypted)?;
                self.chunk.clear();
            }
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let encrypted = self.stream.encrypt_chunk(&self.chunk, true)?;
        self.inner.write_all(&encrypted)?;
        self.inner.flush()
    }
}

struct StreamReader<R: Read> {
    stream: Stream,
    inner: R,
    unread: Vec<u8>,
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.unread.is_empty() {
            let mut chunk = vec![0; ENCRYPTED_CHUNK_SIZE];
            let mut end = 0;
            while end < ENCRYPTED_CHUNK_SIZE {
                match self.inner.read(&mut chunk[end..]) {
                    Ok(0) => break,
                    Ok(n) => end += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Err(e),
                    },
                }
            }

            if end == 0 {
                return Ok(0);
            }

            // This check works for all cases except when the message is an integer
            // multiple of the chunk size. In that case, we try decrypting twice on a
            // decryption failure.
            let last = end < ENCRYPTED_CHUNK_SIZE;

            self.unread = match (self.stream.decrypt_chunk(&chunk[..end], last), last) {
                (Ok(chunk), _) => chunk,
                (Err(_), false) => self.stream.decrypt_chunk(&chunk[..end], true)?,
                (Err(e), true) => return Err(e),
            };
        }

        let mut to_read = self.unread.len();
        if to_read > buf.len() {
            to_read = buf.len()
        }

        buf[..to_read].copy_from_slice(&self.unread[..to_read]);
        self.unread = self.unread.split_off(to_read);

        Ok(to_read)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

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

        assert_eq!(decrypted, data);
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
            assert_eq!(
                s.decrypt_chunk(&encrypted, false).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(
                s.decrypt_chunk(&encrypted, true).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );

            res
        };

        assert_eq!(decrypted, data);
    }

    #[test]
    fn stream_round_trip_short() {
        let key = [7; 32];
        let data = vec![42; 1024];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.flush().unwrap();
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
            w.flush().unwrap();
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
            w.flush().unwrap();
        };

        let decrypted = {
            let mut buf = vec![];
            let mut r = Stream::decrypt(&key, &encrypted[..]);
            r.read_to_end(&mut buf).unwrap();
            buf
        };

        assert_eq!(decrypted, data);
    }
}
