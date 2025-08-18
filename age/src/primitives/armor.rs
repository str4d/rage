//! I/O helper structs for the age ASCII armor format.

use base64::{prelude::BASE64_STANDARD, Engine};
use pin_project::pin_project;
use std::cmp;
use std::error;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

use crate::util::LINE_ENDING;

#[cfg(feature = "async")]
use futures::{
    io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader as AsyncBufReader, Error},
    ready,
    task::{Context, Poll},
};
#[cfg(feature = "async")]
use std::mem;
#[cfg(feature = "async")]
use std::ops::DerefMut;
#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use std::str;

const ARMORED_COLUMNS_PER_LINE: usize = 64;
const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;
const ARMORED_BEGIN_MARKER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMORED_END_MARKER: &str = "-----END AGE ENCRYPTED FILE-----";

const MIN_ARMOR_LEN: usize = 36; // ARMORED_BEGIN_MARKER.len() + 2

const BASE64_CHUNK_SIZE_COLUMNS: usize = 8 * 1024;
const BASE64_CHUNK_SIZE_BYTES: usize = BASE64_CHUNK_SIZE_COLUMNS / 4 * 3;

/// Specifies the format that [`ArmoredWriter`] should apply to its output.
pub enum Format {
    /// age binary format.
    Binary,
    /// ASCII armored format.
    AsciiArmor,
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
struct EncodedLine {
    bytes: Vec<u8>,
    offset: usize,
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
struct EncodedBytes {
    offset: usize,
    end: usize,
}

#[pin_project(project = LineEndingWriterProj)]
pub(crate) struct LineEndingWriter<W> {
    #[pin]
    inner: W,
    buf: Vec<u8>,
    total_written: usize,

    /// None if `AsyncWrite::poll_closed` has been called.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    line: Option<Vec<u8>>,
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    line_with_ending: Option<EncodedLine>,
}

impl<W: Write> LineEndingWriter<W> {
    fn new(mut inner: W) -> io::Result<Self> {
        // Write the begin marker
        inner.write_all(ARMORED_BEGIN_MARKER.as_bytes())?;
        inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(LineEndingWriter {
            inner,
            buf: Vec::with_capacity(8 * 1024),
            total_written: 0,
            #[cfg(feature = "async")]
            line: None,
            #[cfg(feature = "async")]
            line_with_ending: None,
        })
    }

    fn flush_buffered(&mut self) -> io::Result<()> {
        self.inner.write_all(&self.buf)?;
        self.total_written += self.buf.len();
        self.buf.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        // Ensure all bytes have been written.
        self.flush_buffered()?;

        // Write the end marker
        self.inner.write_all(LINE_ENDING.as_bytes())?;
        self.inner.write_all(ARMORED_END_MARKER.as_bytes())?;
        self.inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(self.inner)
    }
}

impl<W: Write> Write for LineEndingWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let written = buf.len();

        while !buf.is_empty() {
            let remaining =
                ARMORED_COLUMNS_PER_LINE - (self.total_written % ARMORED_COLUMNS_PER_LINE);

            // Write the next newline if we are at the end of the line.
            if remaining == ARMORED_COLUMNS_PER_LINE && self.total_written > 0 {
                self.buf.extend_from_slice(LINE_ENDING.as_bytes());
            }
            let to_write = cmp::min(remaining, buf.len());

            self.buf.extend_from_slice(&buf[..to_write]);
            buf = &buf[to_write..];
            self.total_written += to_write;
        }

        // Write the buffer to the inner writer, and drop the written bytes. We trigger
        // this when we are close to the buffer's capacity, to avoid reallocation.
        if self.buf.len() + 1024 > self.buf.capacity() {
            let inner_written = self.inner.write(&self.buf)?;
            let mut i = 0;
            self.buf.retain(|_| {
                let b = i >= inner_written;
                i += 1;
                b
            });
        }

        // We always return the number of bytes we consumed, not how many we actually
        // wrote to the inner writer. Any discrepancy is handled in self.flush().
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffered()?;
        self.inner.flush()
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> LineEndingWriter<W> {
    fn new_async(inner: W) -> Self {
        // Write the begin marker
        let bytes = [ARMORED_BEGIN_MARKER.as_bytes(), LINE_ENDING.as_bytes()].concat();

        LineEndingWriter {
            inner,
            buf: vec![],
            total_written: 0,
            line: Some(Vec::with_capacity(ARMORED_COLUMNS_PER_LINE)),
            line_with_ending: Some(EncodedLine { bytes, offset: 0 }),
        }
    }

    fn poll_flush_line(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let LineEndingWriterProj {
            mut inner,
            line_with_ending,
            ..
        } = self.project();

        if let Some(line) = line_with_ending {
            loop {
                line.offset += ready!(inner.as_mut().poll_write(cx, &line.bytes[line.offset..]))?;
                if line.offset == line.bytes.len() {
                    break;
                }
            }
        }
        *line_with_ending = None;

        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> AsyncWrite for LineEndingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_mut().poll_flush_line(cx))?;

        let this = self.as_mut().project();
        if let Some(line) = this.line {
            let mut to_write = ARMORED_COLUMNS_PER_LINE - line.len();
            if to_write > buf.len() {
                to_write = buf.len()
            }

            line.extend_from_slice(&buf[..to_write]);
            buf = &buf[to_write..];

            // At this point, either buf is empty, or we have a complete line.
            assert!(buf.is_empty() || line.len() == ARMORED_COLUMNS_PER_LINE);

            // Only add a line ending if we have more data to write, as the last
            // line must be written in poll_close().
            if !buf.is_empty() {
                *this.line_with_ending = Some(EncodedLine {
                    bytes: [line, LINE_ENDING.as_bytes()].concat(),
                    offset: 0,
                });
                line.clear();
            }

            Poll::Ready(Ok(to_write))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "AsyncWrite::poll_closed has been called",
            )))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush_line(cx))?;
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any remaining line bytes.
        ready!(self.as_mut().poll_flush_line(cx))?;

        let this = self.as_mut().project();
        if let Some(line) = this.line {
            // Finish the armored format with a partial line (if necessary) and the end
            // marker.
            *this.line_with_ending = Some(EncodedLine {
                bytes: [
                    line,
                    LINE_ENDING.as_bytes(),
                    ARMORED_END_MARKER.as_bytes(),
                    LINE_ENDING.as_bytes(),
                ]
                .concat(),
                offset: 0,
            });
        }
        *this.line = None;

        // Flush the final line (if we didn't in the first call).
        ready!(self.as_mut().poll_flush_line(cx))?;
        self.project().inner.poll_close(cx)
    }
}

#[pin_project(project = ArmorIsProj)]
enum ArmorIs<W> {
    Enabled {
        #[pin]
        inner: LineEndingWriter<W>,
        byte_buf: Option<Vec<u8>>,
        encoded_buf: Box<[u8; BASE64_CHUNK_SIZE_COLUMNS]>,
        #[cfg(feature = "async")]
        #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
        encoded_line: Option<EncodedBytes>,
    },

    Disabled {
        #[pin]
        inner: W,
    },
}

/// Writer that optionally applies the age ASCII armor format.
///
/// # Examples
///
/// ```
/// # use std::io::Read;
/// use std::io::Write;
/// use std::iter;
///
/// # fn run_main() -> Result<(), ()> {
/// # let identity = age::x25519::Identity::generate();
/// # let load_recipient = || Ok(identity.to_public());
/// let recipient = load_recipient()?;
/// let plaintext = b"Hello world!";
///
/// # fn encrypt(recipient: age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
/// let encrypted = {
///     let encryptor = age::Encryptor::with_recipients(iter::once(&recipient as _))
///         .expect("we provided a recipient");
///
///     let mut encrypted = vec![];
///     let mut writer = encryptor.wrap_output(
///         age::armor::ArmoredWriter::wrap_output(
///             &mut encrypted,
///             age::armor::Format::AsciiArmor,
///         )?
///     )?;
///     writer.write_all(plaintext)?;
///     writer.finish()
///         .and_then(|armor| armor.finish())?;
///
///     encrypted
/// };
/// # Ok(encrypted)
/// # }
/// # fn decrypt(identity: age::x25519::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
/// # let decrypted = {
/// #     let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(&encrypted[..]))?;
/// #     let mut decrypted = vec![];
/// #     let mut reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity))?;
/// #     reader.read_to_end(&mut decrypted);
/// #     decrypted
/// # };
/// # Ok(decrypted)
/// # }
/// # let decrypted = decrypt(
/// #     identity,
/// #     encrypt(recipient, &plaintext[..]).map_err(|_| ())?
/// # ).map_err(|_| ())?;
/// # assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// # run_main().unwrap();
/// ```
#[pin_project]
pub struct ArmoredWriter<W>(#[pin] ArmorIs<W>);

impl<W: Write> ArmoredWriter<W> {
    /// Wraps the given output in an `ArmoredWriter` that will apply the given [`Format`].
    pub fn wrap_output(output: W, format: Format) -> io::Result<Self> {
        match format {
            Format::AsciiArmor => LineEndingWriter::new(output).map(|w| {
                ArmoredWriter(ArmorIs::Enabled {
                    inner: w,
                    byte_buf: Some(Vec::with_capacity(BASE64_CHUNK_SIZE_BYTES)),
                    encoded_buf: Box::new([0; BASE64_CHUNK_SIZE_COLUMNS]),
                    #[cfg(feature = "async")]
                    encoded_line: None,
                })
            }),
            Format::Binary => Ok(ArmoredWriter(ArmorIs::Disabled { inner: output })),
        }
    }

    /// Writes the end marker of the age file, if armoring was enabled.
    ///
    /// You **MUST** call `finish` when you are done writing, in order to finish the
    /// armoring process. Failing to call `finish` will result in a truncated file that
    /// that will fail to decrypt.
    pub fn finish(self) -> io::Result<W> {
        match self.0 {
            ArmorIs::Enabled {
                mut inner,
                byte_buf,
                mut encoded_buf,
                ..
            } => {
                let byte_buf = byte_buf.unwrap();
                let encoded = BASE64_STANDARD
                    .encode_slice(&byte_buf, &mut encoded_buf[..])
                    .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES");
                inner.write_all(&encoded_buf[..encoded])?;
                inner.finish()
            }
            ArmorIs::Disabled { inner } => Ok(inner),
        }
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            ArmorIs::Enabled {
                inner,
                byte_buf,
                encoded_buf,
                ..
            } => {
                // Guaranteed to be Some (as long as async and sync writing isn't mixed),
                // because ArmoredWriter::finish consumes self.
                let byte_buf = byte_buf.as_mut().unwrap();

                let mut written = 0;
                loop {
                    let mut to_write = BASE64_CHUNK_SIZE_BYTES - byte_buf.len();
                    if to_write > buf.len() {
                        to_write = buf.len()
                    }

                    byte_buf.extend_from_slice(&buf[..to_write]);
                    buf = &buf[to_write..];
                    written += to_write;

                    // At this point, either buf is empty, or we have a full line.
                    assert!(buf.is_empty() || byte_buf.len() == BASE64_CHUNK_SIZE_BYTES);

                    // Only encode the line if we have more data to write, as the last
                    // (possibly-partial) line must be written in finish().
                    if buf.is_empty() {
                        break;
                    } else {
                        assert_eq!(
                            BASE64_STANDARD
                                .encode_slice(&byte_buf, &mut encoded_buf[..])
                                .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES"),
                            BASE64_CHUNK_SIZE_COLUMNS
                        );
                        inner.write_all(&encoded_buf[..])?;
                        byte_buf.clear();
                    };
                }

                Ok(written)
            }
            ArmorIs::Disabled { inner } => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            ArmorIs::Enabled { inner, .. } => inner.flush(),
            ArmorIs::Disabled { inner } => inner.flush(),
        }
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> ArmoredWriter<W> {
    /// Wraps the given output in an `ArmoredWriter` that will apply the given [`Format`].
    pub fn wrap_async_output(output: W, format: Format) -> Self {
        match format {
            Format::AsciiArmor => ArmoredWriter(ArmorIs::Enabled {
                inner: LineEndingWriter::new_async(output),
                byte_buf: Some(Vec::with_capacity(BASE64_CHUNK_SIZE_BYTES)),
                encoded_buf: Box::new([0; BASE64_CHUNK_SIZE_COLUMNS]),
                encoded_line: None,
            }),
            Format::Binary => ArmoredWriter(ArmorIs::Disabled { inner: output }),
        }
    }

    fn poll_flush_line(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if let ArmorIsProj::Enabled {
            mut inner,
            encoded_buf,
            encoded_line,
            ..
        } = self.project().0.project()
        {
            if let Some(line) = encoded_line {
                loop {
                    line.offset += ready!(inner
                        .as_mut()
                        .poll_write(cx, &encoded_buf[line.offset..line.end]))?;
                    if line.offset == line.end {
                        break;
                    }
                }
            }
            *encoded_line = None;
        }

        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<W: AsyncWrite> AsyncWrite for ArmoredWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_mut().poll_flush_line(cx))?;

        match self.project().0.project() {
            ArmorIsProj::Enabled {
                byte_buf,
                encoded_buf,
                encoded_line,
                ..
            } => {
                if let Some(byte_buf) = byte_buf {
                    let mut to_write = BASE64_CHUNK_SIZE_BYTES - byte_buf.len();
                    if to_write > buf.len() {
                        to_write = buf.len()
                    }

                    byte_buf.extend_from_slice(&buf[..to_write]);
                    buf = &buf[to_write..];

                    // At this point, either buf is empty, or we have a full line.
                    assert!(buf.is_empty() || byte_buf.len() == BASE64_CHUNK_SIZE_BYTES);

                    // Only encode the line if we have more data to write, as the last
                    // line must be written in poll_close().
                    if !buf.is_empty() {
                        assert_eq!(
                            BASE64_STANDARD
                                .encode_slice(&byte_buf, &mut encoded_buf[..],)
                                .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES"),
                            BASE64_CHUNK_SIZE_COLUMNS
                        );
                        *encoded_line = Some(EncodedBytes {
                            offset: 0,
                            end: BASE64_CHUNK_SIZE_COLUMNS,
                        });
                        byte_buf.clear();
                    }

                    Poll::Ready(Ok(to_write))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "AsyncWrite::poll_closed has been called",
                    )))
                }
            }
            ArmorIsProj::Disabled { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush_line(cx))?;
        match self.project().0.project() {
            ArmorIsProj::Enabled { inner, .. } => inner.poll_flush(cx),
            ArmorIsProj::Disabled { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any remaining encoded line bytes.
        ready!(self.as_mut().poll_flush_line(cx))?;

        if let ArmorIsProj::Enabled {
            byte_buf,
            encoded_buf,
            encoded_line,
            ..
        } = self.as_mut().project().0.project()
        {
            if let Some(byte_buf) = byte_buf {
                // Finish the armored format with a partial line (if necessary) and the end
                // marker.
                let encoded = BASE64_STANDARD
                    .encode_slice(&byte_buf, &mut encoded_buf[..])
                    .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES");
                *encoded_line = Some(EncodedBytes {
                    offset: 0,
                    end: encoded,
                });
            }
            *byte_buf = None;
        }

        // Flush the final chunk (if we didn't in the first call).
        ready!(self.as_mut().poll_flush_line(cx))?;

        match self.project().0.project() {
            ArmorIsProj::Enabled { inner, .. } => inner.poll_close(cx),
            ArmorIsProj::Disabled { inner } => inner.poll_close(cx),
        }
    }
}

/// The various errors that can be returned while parsing the armored format.
#[derive(Debug)]
pub enum ArmoredReadError {
    /// An error occurred while parsing Base64.
    Base64(base64::DecodeSliceError),
    /// The begin marker for the armor is invalid.
    InvalidBeginMarker,
    /// Invalid UTF-8 characters were encountered between the begin and end marker.
    InvalidUtf8,
    /// A line of the armor contains a `\r` character.
    LineContainsCr,
    /// The final Base64 line is non-canonical.
    MissingPadding,
    /// The armor is not wrapped at 64 characters.
    NotWrappedAt64Chars,
    /// There is a short line in the middle of the armor (only the final line may be short).
    ShortLineInMiddle,
    /// There are trailing non-whitespace characters after the end marker.
    TrailingGarbage,
}

impl fmt::Display for ArmoredReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArmoredReadError::Base64(e) => e.fmt(f),
            ArmoredReadError::InvalidBeginMarker => write!(f, "invalid armor begin marker"),
            ArmoredReadError::InvalidUtf8 => write!(f, "stream did not contain valid UTF-8"),
            ArmoredReadError::LineContainsCr => write!(f, "line contains CR"),
            ArmoredReadError::MissingPadding => {
                write!(f, "invalid armor (last line is missing padding)")
            }
            ArmoredReadError::NotWrappedAt64Chars => {
                write!(f, "invalid armor (not wrapped at 64 characters)")
            }
            ArmoredReadError::ShortLineInMiddle => {
                write!(f, "invalid armor (short line in middle of encoding)")
            }
            ArmoredReadError::TrailingGarbage => {
                write!(
                    f,
                    "invalid armor (non-whitespace characters after end marker)"
                )
            }
        }
    }
}

impl error::Error for ArmoredReadError {}

/// The position in the underlying reader corresponding to the start of the data inside
/// the armor.
///
/// To impl Seek for ArmoredReader, we need to know the point in the reader corresponding
/// to the first byte of the armored data. But we can't query the reader for its current
/// position without having a specific constructor for `R: Read + Seek`, which makes the
/// higher-level API more complex. Instead, we count the number of bytes that have been
/// read from the reader:
/// - If armor is enabled, we count starting from after the first line (which is the armor
///   begin marker).
/// - If armor is disabled, we count from the first byte we read.
///
/// Then when we first need to seek, inside `impl Seek` we can query the reader's current
/// position and figure out where the start was.
#[derive(Debug)]
enum StartPos {
    /// An offset that we can subtract from the current position.
    Implicit(u64),
    /// The precise start position.
    Explicit(u64),
}

/// Reader that will parse the age ASCII armor format if detected.
///
/// # Examples
///
/// ```
/// use std::io::Read;
/// # use std::io::Write;
/// use std::iter;
///
/// # fn run_main() -> Result<(), ()> {
/// # fn encrypt(recipient: age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
/// # let encrypted = {
/// #     let encryptor = age::Encryptor::with_recipients(iter::once(&recipient as _))
/// #         .expect("we provided a recipient");
/// #     let mut encrypted = vec![];
/// #     let mut writer = encryptor.wrap_output(
/// #         age::armor::ArmoredWriter::wrap_output(
/// #             &mut encrypted,
/// #             age::armor::Format::AsciiArmor,
/// #         )?
/// #     )?;
/// #     writer.write_all(plaintext)?;
/// #     writer.finish()
/// #         .and_then(|armor| armor.finish())?;
/// #     encrypted
/// # };
/// # Ok(encrypted)
/// # }
/// # let load_identity = || Ok(age::x25519::Identity::generate());
/// let identity = load_identity()?;
/// # let plaintext = b"Hello world!";
/// # let load_encrypted_file = || encrypt(identity.to_public(), &plaintext[..]).map_err(|_| ());
/// let encrypted = load_encrypted_file()?;
///
/// # fn decrypt(identity: age::x25519::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
/// let decrypted = {
///     let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(&encrypted[..]))?;
///
///     let mut decrypted = vec![];
///     let mut reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity))?;
///     reader.read_to_end(&mut decrypted);
///
///     decrypted
/// };
/// # Ok(decrypted)
/// # }
/// # let decrypted = decrypt(identity, encrypted).map_err(|_| ())?;
/// # assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// # run_main().unwrap();
/// ```
#[pin_project]
pub struct ArmoredReader<R> {
    #[pin]
    inner: R,
    start: StartPos,
    is_armored: Option<bool>,
    line_buf: Zeroizing<String>,
    byte_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    byte_start: usize,
    byte_end: usize,
    found_short_line: bool,
    found_end: bool,
    data_len: Option<u64>,
    data_read: usize,
}

impl<R: Read> ArmoredReader<BufReader<R>> {
    /// Wraps a reader that may contain an armored age file.
    pub fn new(reader: R) -> Self {
        ArmoredReader::with_buffered(BufReader::new(reader))
    }
}

#[cfg(feature = "cli-common")]
impl<R: BufRead> ArmoredReader<R> {
    /// Wraps a buffered reader that may contain an armored age file.
    pub(crate) fn new_buffered(reader: R) -> Self {
        ArmoredReader::with_buffered(reader)
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncRead + Unpin> ArmoredReader<AsyncBufReader<R>> {
    /// Wraps a reader that may contain an armored age file.
    pub fn from_async_reader(inner: R) -> Self {
        ArmoredReader::with_buffered(AsyncBufReader::new(inner))
    }
}

impl<R> ArmoredReader<R> {
    fn with_buffered(inner: R) -> Self {
        ArmoredReader {
            inner,
            start: StartPos::Implicit(0),
            is_armored: None,
            line_buf: Zeroizing::new(String::with_capacity(ARMORED_COLUMNS_PER_LINE + 2)),
            byte_buf: Zeroizing::new([0; ARMORED_BYTES_PER_LINE]),
            byte_start: ARMORED_BYTES_PER_LINE,
            byte_end: ARMORED_BYTES_PER_LINE,
            found_short_line: false,
            found_end: false,
            data_len: None,
            data_read: 0,
        }
    }

    fn count_reader_bytes(&mut self, read: usize) -> usize {
        // We only need to count if we haven't yet worked out the start position.
        if let StartPos::Implicit(offset) = &mut self.start {
            *offset += read as u64;
        }

        // Return the counted bytes for convenience.
        read
    }

    /// Detects whether this is an armored age file.
    ///
    /// We only use ArmoredReader to read age files, so we can rely on the following
    /// properties:
    ///
    /// - The first line of an armored age file is 35-36 bytes, depending on whether CRLF
    ///   or LF is used.
    /// - A non-armored age file with a v1 header will be a minimum of 70 bytes (22-byte
    ///   version line, 48-byte MAC line).
    /// - A non-armored age file with an unknown header version will be a minimum of 21
    ///   bytes (for a one-character version). However, assuming that age continues to
    ///   target at least the 128-bit security level, any future header version must
    ///   contain at least 16 more bytes, for a total minimum of 37 bytes.
    ///
    /// We therefore read exactly 36 bytes from the underlying reader, and parse it within
    /// the internal buffer to determine whether this is an armored age file.
    fn detect_armor(&mut self) -> io::Result<()> {
        if self.is_armored.is_some() {
            panic!("ArmoredReader::detect_armor() called twice");
        }

        const MARKER_LEN: usize = MIN_ARMOR_LEN - 2;

        // The first line of armor is the armor marker followed by either
        // CRLF or LF.
        let is_armored = &self.byte_buf[..MARKER_LEN] == ARMORED_BEGIN_MARKER.as_bytes();
        if is_armored {
            match (
                &self.byte_buf[MARKER_LEN..=MARKER_LEN],
                &self.byte_buf[MARKER_LEN..MIN_ARMOR_LEN],
            ) {
                (b"\n", _) => {
                    // We read one extra byte. If this is a valid armored file, that byte
                    // is valid UTF-8, so we can move it into the line buffer.
                    self.line_buf.push_str(
                        std::str::from_utf8(&self.byte_buf[MARKER_LEN + 1..MIN_ARMOR_LEN])
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    ArmoredReadError::InvalidUtf8,
                                )
                            })?,
                    );
                    self.count_reader_bytes(1);
                }
                (_, b"\r\n") => (),
                (_, _) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::InvalidBeginMarker,
                    ))
                }
            }
        } else {
            // Not armored, so the first line is part of the data.
            self.byte_start = 0;
            self.byte_end = MIN_ARMOR_LEN;
            self.count_reader_bytes(MIN_ARMOR_LEN);
        }

        self.is_armored = Some(is_armored);
        Ok(())
    }

    /// Validates `self.line_buf` and parses it into `self.byte_buf`.
    ///
    /// Returns `true` if this was the last line.
    fn parse_armor_line(&mut self) -> io::Result<bool> {
        // Handle line endings
        let line = if self.line_buf.ends_with("\r\n") {
            // trim_end_matches will trim the pattern repeatedly, but because
            // BufRead::read_line splits on line endings, this will never occur.
            self.line_buf.trim_end_matches("\r\n")
        } else if self.line_buf.ends_with('\n') {
            self.line_buf.trim_end_matches('\n')
        } else {
            // If the line does not end in a `\n`, then it must be the final line in the
            // file, because we parse the file into lines by splitting on `\n`. This will
            // either be an invalid line (and be caught as a different error), or the end
            // marker (which we allow to omit a trailing `\n`).
            &self.line_buf
        };
        if line.contains('\r') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ArmoredReadError::LineContainsCr,
            ));
        }

        // Enforce canonical armor format
        if line == ARMORED_END_MARKER {
            // This line is the EOF marker; we are done!
            self.found_end = true;
            return Ok(true);
        } else {
            match (self.found_short_line, line.len()) {
                (false, ARMORED_COLUMNS_PER_LINE) => (),
                (false, n) if n % 4 != 0 => {
                    // The `base64` crate does not (yet) support canonical decoding.
                    // Handle this ourselves until the upstream issue is closed:
                    // https://github.com/marshallpierce/rust-base64/issues/182
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::MissingPadding,
                    ));
                }
                (false, n) if n < ARMORED_COLUMNS_PER_LINE => {
                    // The format may contain a single short line at the end.
                    self.found_short_line = true;
                }
                (true, ARMORED_COLUMNS_PER_LINE) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::ShortLineInMiddle,
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::NotWrappedAt64Chars,
                    ));
                }
            }
        }

        // Decode the line
        self.byte_start = 0;
        self.byte_end = BASE64_STANDARD
            .decode_slice(line.as_bytes(), self.byte_buf.as_mut())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, ArmoredReadError::Base64(e)))?;

        // Finished with this buffered line!
        self.line_buf.clear();

        // We haven't found the end yet
        Ok(false)
    }
}

impl<R: BufRead> BufRead for ArmoredReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        loop {
            match self.is_armored {
                None => {
                    self.inner.read_exact(&mut self.byte_buf[..MIN_ARMOR_LEN])?;
                    self.detect_armor()?
                }
                Some(false) => {
                    break if self.byte_start >= self.byte_end {
                        self.inner.read(&mut self.byte_buf[..]).map(|read| {
                            self.byte_start = 0;
                            self.byte_end = read;
                            self.count_reader_bytes(read);
                            &self.byte_buf[..read]
                        })
                    } else {
                        Ok(&self.byte_buf[self.byte_start..self.byte_end])
                    }
                }
                Some(true) => {
                    break if self.found_end {
                        Ok(&[])
                    } else if self.byte_start >= self.byte_end {
                        if self.read_next_armor_line()? {
                            Ok(&[])
                        } else {
                            Ok(&self.byte_buf[self.byte_start..self.byte_end])
                        }
                    } else {
                        Ok(&self.byte_buf[self.byte_start..self.byte_end])
                    }
                }
            }
        }
    }

    fn consume(&mut self, amt: usize) {
        self.byte_start += amt;
        self.data_read += amt;
        assert!(self.byte_start <= self.byte_end);
    }
}

impl<R: BufRead> ArmoredReader<R> {
    /// Fills `self.byte_buf` with the next line of armored data.
    ///
    /// Returns `true` if this was the last line.
    fn read_next_armor_line(&mut self) -> io::Result<bool> {
        assert_eq!(self.is_armored, Some(true));

        // Read the next line
        self.inner
            .read_line(&mut self.line_buf)
            .map(|read| self.count_reader_bytes(read))?;

        // Parse the line into bytes
        if self.parse_armor_line()? {
            // This was the last line! Check for trailing garbage.
            loop {
                let amt = match self.inner.fill_buf()? {
                    &[] => break,
                    buf => {
                        if buf.iter().any(|b| !b.is_ascii_whitespace()) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                ArmoredReadError::TrailingGarbage,
                            ));
                        }
                        buf.len()
                    }
                };
                self.inner.consume(amt);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<R: BufRead> Read for ArmoredReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let buf_len = buf.len();

        while !buf.is_empty() {
            match self.fill_buf()? {
                [] => break,
                next => {
                    let read = cmp::min(next.len(), buf.len());

                    if next.len() < buf.len() {
                        buf[..read].copy_from_slice(next);
                    } else {
                        buf.copy_from_slice(&next[..read]);
                    }

                    self.consume(read);
                    buf = &mut buf[read..];
                }
            }
        }

        Ok(buf_len - buf.len())
    }
}

/// Copied from `futures_util::io::read_until::read_until_internal`.
#[cfg(feature = "async")]
fn read_until_internal<R: AsyncBufRead + ?Sized>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    byte: u8,
    buf: &mut Vec<u8>,
    read: &mut usize,
) -> Poll<io::Result<usize>> {
    loop {
        let (done, used) = {
            let available = ready!(reader.as_mut().poll_fill_buf(cx))?;
            if let Some(i) = memchr::memchr(byte, available) {
                buf.extend_from_slice(&available[..=i]);
                (true, i + 1)
            } else {
                buf.extend_from_slice(available);
                (false, available.len())
            }
        };
        reader.as_mut().consume(used);
        *read += used;
        if done || used == 0 {
            return Poll::Ready(Ok(mem::replace(read, 0)));
        }
    }
}

/// Adapted from `futures_util::io::read_line::read_line_internal`.
#[cfg(feature = "async")]
fn read_line_internal<R: AsyncBufRead + ?Sized>(
    reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    buf: &mut String,
    bytes: &mut Vec<u8>,
    read: &mut usize,
) -> Poll<io::Result<usize>> {
    let ret = ready!(read_until_internal(reader, cx, b'\n', bytes, read));
    match String::from_utf8(mem::take(bytes)) {
        Err(_) => Poll::Ready(ret.and_then(|_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ArmoredReadError::InvalidUtf8,
            ))
        })),
        Ok(mut line) => {
            debug_assert!(buf.is_empty());
            debug_assert_eq!(*read, 0);
            // Safety: `bytes` is a valid UTF-8 because `str::from_utf8` returned `Ok`.
            mem::swap(buf, &mut line);
            Poll::Ready(ret)
        }
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncBufRead + Unpin> AsyncBufRead for ArmoredReader<R> {
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        loop {
            match self.is_armored {
                None => {
                    let mut this = self.as_mut().project();
                    let available = loop {
                        let buf = ready!(this.inner.as_mut().poll_fill_buf(cx))?;
                        if buf.len() >= MIN_ARMOR_LEN {
                            break buf;
                        }
                    };
                    this.byte_buf[..MIN_ARMOR_LEN].copy_from_slice(&available[..MIN_ARMOR_LEN]);
                    this.inner.as_mut().consume(MIN_ARMOR_LEN);
                    self.detect_armor()?
                }
                Some(false) => {
                    let ret = if self.byte_start >= self.byte_end {
                        let this = self.as_mut().project();
                        let read = ready!(this.inner.poll_read(cx, &mut this.byte_buf[..]))?;
                        (*this.byte_start) = 0;
                        (*this.byte_end) = read;
                        self.count_reader_bytes(read);
                        &self.get_mut().byte_buf[..read]
                    } else {
                        let this = self.get_mut();
                        &this.byte_buf[this.byte_start..this.byte_end]
                    };
                    break Poll::Ready(Ok(ret));
                }
                Some(true) if self.found_end => return Poll::Ready(Ok(&[])),
                Some(true) => {
                    let ret = if self.byte_start >= self.byte_end {
                        let last =
                            ready!(Pin::new(self.deref_mut()).poll_read_next_armor_line(cx))?;
                        if last {
                            &[]
                        } else {
                            let this = self.get_mut();
                            &this.byte_buf[this.byte_start..this.byte_end]
                        }
                    } else {
                        let this = self.get_mut();
                        &this.byte_buf[this.byte_start..this.byte_end]
                    };
                    break Poll::Ready(Ok(ret));
                }
            }
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let this = self.as_mut().project();
        (*this.byte_start) += amt;
        (*this.data_read) += amt;
        assert!(this.byte_start <= this.byte_end);
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncBufRead + Unpin> ArmoredReader<R> {
    /// Fills `self.byte_buf` with the next line of armored data.
    ///
    /// Returns `true` if this was the last line.
    fn poll_read_next_armor_line(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        assert_eq!(self.is_armored, Some(true));

        // Read the next line
        {
            // Emulates `AsyncBufReadExt::read_line`.
            let mut this = self.as_mut().project();
            let buf: &mut String = this.line_buf;
            let mut bytes = mem::take(buf).into_bytes();
            let mut read = 0;
            ready!(read_line_internal(
                this.inner.as_mut(),
                cx,
                buf,
                &mut bytes,
                &mut read,
            ))
        }
        .map(|read| self.count_reader_bytes(read))?;

        // Parse the line into bytes.
        if self.parse_armor_line()? {
            // This was the last line! Check for trailing garbage.
            let mut this = self.as_mut().project();
            loop {
                let amt = match ready!(this.inner.as_mut().poll_fill_buf(cx))? {
                    &[] => break,
                    buf => {
                        if buf.iter().any(|b| !b.is_ascii_whitespace()) {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                ArmoredReadError::TrailingGarbage,
                            )));
                        }
                        buf.len()
                    }
                };
                this.inner.as_mut().consume(amt);
            }
            Poll::Ready(Ok(true))
        } else {
            Poll::Ready(Ok(false))
        }
    }
}

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl<R: AsyncBufRead + Unpin> AsyncRead for ArmoredReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        mut buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let buf_len = buf.len();

        while !buf.is_empty() {
            match Pin::new(self.deref_mut()).poll_fill_buf(cx) {
                Poll::Pending if buf_len > buf.len() => break,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok([])) => break,
                Poll::Ready(Ok(next)) => {
                    let read = cmp::min(next.len(), buf.len());

                    if next.len() < buf.len() {
                        buf[..read].copy_from_slice(next);
                    } else {
                        buf.copy_from_slice(&next[..read]);
                    }

                    Pin::new(self.deref_mut()).consume(read);
                    buf = &mut buf[read..];
                }
            }
        }

        Poll::Ready(Ok(buf_len - buf.len()))
    }
}

impl<R: Read + Seek> ArmoredReader<R> {
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

impl<R: BufRead + Seek> Seek for ArmoredReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        loop {
            match self.is_armored {
                None => {
                    self.inner.read_exact(&mut self.byte_buf[..MIN_ARMOR_LEN])?;
                    self.detect_armor()?
                }
                Some(armored) => {
                    // Convert the offset into the target position within the data inside
                    // the (maybe) armor.
                    let start = self.start()?;
                    let target_pos = match pos {
                        SeekFrom::Start(offset) => offset,
                        SeekFrom::Current(offset) => {
                            let res = (self.data_read as i64) + offset;
                            if res >= 0_i64 {
                                res as u64
                            } else {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "cannot seek before the start",
                                ));
                            }
                        }
                        SeekFrom::End(offset) => {
                            let data_len = match self.data_len {
                                Some(n) => n,
                                None => {
                                    // Read from the source until we find the end.
                                    let mut buf = [0; 4096];
                                    while self.read(&mut buf)? > 0 {}
                                    let data_len = self.data_read as u64;

                                    // Cache the data length for future calls.
                                    self.data_len = Some(data_len);

                                    data_len
                                }
                            };

                            let res = (data_len as i64) + offset;
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

                    if !armored {
                        // We can seek directly on the inner reader.
                        self.inner.seek(SeekFrom::Start(start + target_pos))?;
                        self.byte_start = 0;
                        self.byte_end = 0;
                        self.data_read = target_pos as usize;
                        break Ok(self.data_read as u64);
                    }

                    // Jump back to the start of the armor data, and then read and drop
                    // until we reach the target position. This is very inefficient, but
                    // as armored files can have arbitrary line endings within the file,
                    // we can't determine where the armor line containing the target
                    // position begins within the reader.
                    self.inner.seek(SeekFrom::Start(start))?;
                    self.line_buf.clear();
                    self.byte_start = ARMORED_BYTES_PER_LINE;
                    self.byte_end = ARMORED_BYTES_PER_LINE;
                    self.found_short_line = false;
                    self.found_end = false;
                    self.data_read = 0;

                    let mut buf = [0; 4096];
                    let mut to_read = target_pos as usize;
                    while to_read > buf.len() {
                        self.read_exact(&mut buf)?;
                        to_read -= buf.len();
                    }
                    if to_read > 0 {
                        self.read_exact(&mut buf[..to_read])?;
                    }

                    // All done!
                    break Ok(target_pos);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use super::{ArmoredReader, ArmoredWriter, Format, ARMORED_BYTES_PER_LINE};

    #[cfg(feature = "async")]
    use futures::{
        io::{AsyncRead, AsyncWrite},
        pin_mut,
        task::Poll,
    };
    #[cfg(feature = "async")]
    use futures_test::task::noop_context;

    #[test]
    fn armored_round_trip() {
        const MAX_LEN: usize = ARMORED_BYTES_PER_LINE * 50;

        let mut data = Vec::with_capacity(MAX_LEN);

        for i in 0..MAX_LEN {
            data.push(i as u8);

            let mut encoded = vec![];
            {
                let mut out = ArmoredWriter::wrap_output(&mut encoded, Format::AsciiArmor).unwrap();
                out.write_all(&data).unwrap();
                out.finish().unwrap();
            }

            let mut buf = vec![];
            {
                let mut input = ArmoredReader::new(&encoded[..]);
                input.read_to_end(&mut buf).unwrap();
            }

            assert_eq!(buf, data);
        }
    }

    #[cfg(feature = "async")]
    #[test]
    fn armored_async_round_trip() {
        const MAX_LEN: usize = ARMORED_BYTES_PER_LINE * 50;

        let mut data = Vec::with_capacity(MAX_LEN);

        for i in 0..MAX_LEN {
            data.push(i as u8);

            let mut encoded = vec![];
            {
                let w = ArmoredWriter::wrap_async_output(&mut encoded, Format::AsciiArmor);
                pin_mut!(w);

                let mut cx = noop_context();

                let mut tmp = &data[..];
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
            }

            let mut buf = vec![];
            {
                let input = ArmoredReader::from_async_reader(&encoded[..]);
                pin_mut!(input);

                let mut cx = noop_context();

                let mut tmp = [0; 4096];
                loop {
                    match input.as_mut().poll_read(&mut cx, &mut tmp) {
                        Poll::Ready(Ok(0)) => break,
                        Poll::Ready(Ok(read)) => buf.extend_from_slice(&tmp[..read]),
                        Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                        Poll::Pending => panic!("Unexpected Pending"),
                    }
                }
            }

            assert_eq!(buf, data);
        }
    }

    #[test]
    fn binary_seeking() {
        let mut data = vec![0; 100 * 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut written = vec![];
        {
            let mut w = ArmoredWriter::wrap_output(&mut written, Format::Binary).unwrap();
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };
        assert_eq!(written, data);

        let mut r = ArmoredReader::new(Cursor::new(written));

        // Read part-way into the first "line"
        let mut buf = vec![0; 100];
        r.read_exact(&mut buf[..5]).unwrap();
        assert_eq!(&buf[..5], &data[..5]);

        // Seek back to the beginning
        r.seek(SeekFrom::Start(0)).unwrap();

        // Read into the middle of the data
        for i in 0..70 {
            r.read_exact(&mut buf).unwrap();
            assert_eq!(&buf[..], &data[100 * i..100 * (i + 1)]);
        }

        // Seek back into the first line
        r.seek(SeekFrom::Start(5)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[5..105]);

        // Seek forwards from the current position
        r.seek(SeekFrom::Current(500)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[605..705]);

        // Seek backwards from the end
        r.seek(SeekFrom::End(-1337)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[data.len() - 1337..data.len() - 1237]);
    }

    #[test]
    fn armored_seeking() {
        let mut data = vec![0; 100 * 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut armored = vec![];
        {
            let mut w = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor).unwrap();
            w.write_all(&data).unwrap();
            w.finish().unwrap();
        };

        let mut r = ArmoredReader::new(Cursor::new(armored));

        // Read part-way into the first "line"
        let mut buf = vec![0; 100];
        r.read_exact(&mut buf[..5]).unwrap();
        assert_eq!(&buf[..5], &data[..5]);

        // Seek back to the beginning
        r.seek(SeekFrom::Start(0)).unwrap();

        // Read into the middle of the data
        for i in 0..70 {
            r.read_exact(&mut buf).unwrap();
            assert_eq!(&buf[..], &data[100 * i..100 * (i + 1)]);
        }

        // Seek back into the first line
        r.seek(SeekFrom::Start(5)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[5..105]);

        // Seek forwards from the current position
        r.seek(SeekFrom::Current(500)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[605..705]);

        // Seek backwards from the end
        r.seek(SeekFrom::End(-1337)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[data.len() - 1337..data.len() - 1237]);
    }
}
