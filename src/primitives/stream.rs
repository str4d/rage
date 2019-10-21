//! The [STREAM] construction for online authenticated encryption.
//!
//! [STREAM]: https://eprint.iacr.org/2015/189.pdf

use aead::{Aead, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use generic_array::{typenum::U12, GenericArray};
use std::io::{self, Read, Seek, SeekFrom, Write};

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

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
            start: 0,
            cur_plaintext_pos: 0,
            unread: vec![],
        }
    }

    /// Wraps `STREAM` decryption under the given `key` around a seekable reader.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: crate::primitives::hkdf
    pub fn decrypt_seekable<R: Read + Seek>(
        key: &[u8; 32],
        mut inner: R,
    ) -> io::Result<StreamReader<R>> {
        let start = inner.seek(SeekFrom::Current(0))?;
        Ok(StreamReader {
            stream: Self::new(key),
            inner,
            start,
            cur_plaintext_pos: 0,
            unread: vec![],
        })
    }

    fn set_counter(&mut self, val: u64) {
        // Overwrite the counter with the new value
        self.nonce[0..3].copy_from_slice(&[0, 0, 0]);
        self.nonce[3..11].copy_from_slice(&val.to_be_bytes());

        // Unset last-chunk flag
        self.nonce[11] = 0;
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

/// Provides access to a decrypted age message.
pub struct StreamReader<R: Read> {
    stream: Stream,
    inner: R,
    start: u64,
    cur_plaintext_pos: u64,
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
                if self.stream.nonce[11] == 0 {
                    // Stream has ended before seeing the last chunk.
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "message is truncated",
                    ));
                } else {
                    return Ok(0);
                }
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
        self.cur_plaintext_pos += to_read as u64;

        Ok(to_read)
    }
}

impl<R: Read + Seek> Seek for StreamReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Convert the offset into the target position within the plaintext
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
                let pt_end = ct_end - self.start - total_tag_size;

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

        let offset = {
            let cur_chunk_index = self.cur_plaintext_pos / CHUNK_SIZE as u64;
            let cur_chunk_offset = self.cur_plaintext_pos as usize % CHUNK_SIZE;

            let target_chunk_index = target_pos / CHUNK_SIZE as u64;
            let target_chunk_offset = target_pos as usize % CHUNK_SIZE;

            if target_chunk_index == cur_chunk_index && target_chunk_offset >= cur_chunk_offset {
                // We just need to skip forward a few bytes
                target_chunk_offset - cur_chunk_offset
            } else {
                // Seek to the beginning of the target chunk
                self.inner.seek(SeekFrom::Start(
                    self.start + (target_chunk_index * ENCRYPTED_CHUNK_SIZE as u64),
                ))?;
                self.stream.set_counter(target_chunk_index);
                self.cur_plaintext_pos = target_chunk_index * CHUNK_SIZE as u64;
                self.unread.clear();

                target_chunk_offset
            }
        };

        // Read and drop bytes from the chunk to reach the target position.
        // A single call to self.read() is sufficient, because we know it will
        // read a full chunk from the inner reader, and offset is always smaller
        // than a chunk.
        if offset > 0 {
            let mut to_drop = Vec::with_capacity(offset);
            to_drop.resize(offset, 0);
            self.read(&mut to_drop)?;
        }

        // All done!
        Ok(target_pos)
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn stream_fails_to_decrypt_truncated_message() {
        let key = [7; 32];
        let data = vec![42; 2 * CHUNK_SIZE];

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            // Forget to call w.flush()!
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
        for i in 0..data.len() {
            data[i] = i as u8;
        }

        let mut encrypted = vec![];
        {
            let mut w = Stream::encrypt(&key, &mut encrypted);
            w.write_all(&data).unwrap();
            w.flush().unwrap();
        };

        let mut r = Stream::decrypt_seekable(&key, Cursor::new(encrypted)).unwrap();

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
