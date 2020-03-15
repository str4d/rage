use radix64::{configs::Std, io::EncodeWriter, STD};
use std::cmp;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

use crate::{util::LINE_ENDING, Format};

const ARMORED_COLUMNS_PER_LINE: usize = 64;
const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;
const ARMORED_BEGIN_MARKER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMORED_END_MARKER: &str = "-----END AGE ENCRYPTED FILE-----";

pub(crate) struct LineEndingWriter<W: Write> {
    inner: W,
    total_written: usize,
}

impl<W: Write> LineEndingWriter<W> {
    fn new(mut inner: W) -> io::Result<Self> {
        // Write the begin marker
        inner.write_all(ARMORED_BEGIN_MARKER.as_bytes())?;
        inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(LineEndingWriter {
            inner,
            total_written: 0,
        })
    }

    fn finish(mut self) -> io::Result<W> {
        // Write the end marker
        self.inner.write_all(LINE_ENDING.as_bytes())?;
        self.inner.write_all(ARMORED_END_MARKER.as_bytes())?;
        self.inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(self.inner)
    }
}

impl<W: Write> Write for LineEndingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining = ARMORED_COLUMNS_PER_LINE - (self.total_written % ARMORED_COLUMNS_PER_LINE);

        // Write the next newline if we are at the end of the line.
        if remaining == ARMORED_COLUMNS_PER_LINE && self.total_written > 0 {
            // This may involve multiple write calls to the wrapped writer, but consumes
            // no bytes from the input buffer.
            self.inner.write_all(LINE_ENDING.as_bytes())?;
        }

        let to_write = cmp::min(remaining, buf.len());

        // Write at most one line's worth of input. This ensures that we maintain the
        // invariant that if the wrapped writer returns an error, no bytes of the input
        // buffer have been written.
        let written = self.inner.write(&buf[..to_write])?;

        self.total_written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) enum ArmoredWriter<W: Write> {
    Enabled {
        encoder: EncodeWriter<Std, LineEndingWriter<W>>,
    },

    Disabled {
        inner: W,
    },
}

impl<W: Write> ArmoredWriter<W> {
    pub(crate) fn wrap_output(inner: W, format: Format) -> io::Result<Self> {
        match format {
            Format::AsciiArmor => LineEndingWriter::new(inner).map(|w| ArmoredWriter::Enabled {
                encoder: EncodeWriter::new(STD, w),
            }),
            Format::Binary => Ok(ArmoredWriter::Disabled { inner }),
        }
    }

    pub(crate) fn finish(self) -> io::Result<W> {
        match self {
            ArmoredWriter::Enabled { encoder } => encoder
                .finish()
                .map_err(|e| io::Error::from(e.error().kind()))
                .and_then(|line_ending| line_ending.finish()),
            ArmoredWriter::Disabled { inner } => Ok(inner),
        }
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ArmoredWriter::Enabled { encoder } => encoder.write(buf),
            ArmoredWriter::Disabled { inner } => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ArmoredWriter::Enabled { encoder } => encoder.flush(),
            ArmoredWriter::Disabled { inner } => inner.flush(),
        }
    }
}

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

pub(crate) struct ArmoredReader<R: Read> {
    inner: BufReader<R>,
    start: StartPos,
    is_armored: Option<bool>,
    line_buf: Zeroizing<String>,
    line_read: usize,
    byte_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    byte_start: usize,
    byte_end: usize,
    found_short_line: bool,
    found_end: bool,
    data_len: Option<u64>,
    data_read: usize,
}

impl<R: Read> ArmoredReader<R> {
    pub(crate) fn from_reader(inner: R) -> Self {
        ArmoredReader {
            inner: BufReader::new(inner),
            start: StartPos::Implicit(0),
            is_armored: None,
            line_buf: Zeroizing::new(String::with_capacity(ARMORED_COLUMNS_PER_LINE + 2)),
            line_read: 0,
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

    fn detect_armor(&mut self) -> io::Result<()> {
        if self.is_armored.is_some() {
            panic!("ArmoredReader::detect_armor() called twice");
        }

        // Read the first line. This will throw an error if the data before the first 0x0A
        // byte is not valid UTF-8, but both the age header and the armor marker satisfy
        // this constraint.
        self.line_buf.clear();
        self.inner.read_line(&mut self.line_buf)?;

        // The first line of armor is the armor marker followed by either
        // CRLF or LF.
        let is_armored = self.line_buf.starts_with(ARMORED_BEGIN_MARKER);
        if is_armored {
            let remainder = &self.line_buf.as_bytes()[ARMORED_BEGIN_MARKER.len()..];
            if !(remainder == b"\r\n" || remainder == b"\n") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid armor begin marker",
                ));
            }
        } else {
            // Not armored, so the first line is part of the data.
            self.count_reader_bytes(self.line_buf.len());
        }

        self.is_armored = Some(is_armored);
        Ok(())
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

impl<R: Read> Read for ArmoredReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.is_armored {
                None => self.detect_armor()?,
                Some(false) => {
                    if self.line_buf.is_empty() {
                        return self.inner.read(buf).map(|read| {
                            self.data_read += read;
                            self.count_reader_bytes(read)
                        });
                    } else {
                        // Return any leftover data from armor detection
                        if self.line_read + buf.len() < self.line_buf.len() {
                            buf.copy_from_slice(
                                &self.line_buf.as_bytes()
                                    [self.line_read..self.line_read + buf.len()],
                            );
                            self.line_read += buf.len();
                            self.data_read += buf.len();
                            return Ok(buf.len());
                        } else {
                            let to_read = self.line_buf.len() - self.line_read;
                            buf[..to_read]
                                .copy_from_slice(&self.line_buf.as_bytes()[self.line_read..]);
                            self.line_buf.clear();
                            self.data_read += to_read;
                            return Ok(to_read);
                        }
                    }
                }
                Some(true) => break,
            }
        }
        if self.found_end {
            return Ok(0);
        }

        let buf_len = buf.len();

        // Output any remaining bytes from the previous line
        if self.byte_start + buf_len <= self.byte_end {
            buf.copy_from_slice(&self.byte_buf[self.byte_start..self.byte_start + buf_len]);
            self.byte_start += buf_len;
            return Ok(buf_len);
        } else {
            let to_read = self.byte_end - self.byte_start;
            buf[..to_read].copy_from_slice(&self.byte_buf[self.byte_start..self.byte_end]);
            buf = &mut buf[to_read..];
        }

        loop {
            // Read the next line
            self.line_buf.clear();
            self.inner
                .read_line(&mut self.line_buf)
                .map(|read| self.count_reader_bytes(read))?;

            // Handle line endings
            let line = if self.line_buf.ends_with("\r\n") {
                // trim_end_matches will trim the pattern repeatedly, but because
                // BufRead::read_line splits on line endings, this will never occur.
                self.line_buf.trim_end_matches("\r\n")
            } else if self.line_buf.ends_with('\n') {
                self.line_buf.trim_end_matches('\n')
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing line ending",
                ));
            };
            if line.contains('\r') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "line contains CR",
                ));
            }

            // Enforce canonical armor format
            if line == ARMORED_END_MARKER {
                // This line is the EOF marker; we are done!
                self.found_end = true;
                break;
            } else {
                match (self.found_short_line, line.len()) {
                    (false, ARMORED_COLUMNS_PER_LINE) => (),
                    (false, n) if n < ARMORED_COLUMNS_PER_LINE => {
                        // The format may contain a single short line at the end.
                        self.found_short_line = true;
                    }
                    (true, ARMORED_COLUMNS_PER_LINE) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid armor (short line in middle of encoding)",
                        ));
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid armor (not wrapped at 64 characters)",
                        ));
                    }
                }
            }

            // Decode the line
            self.byte_end = base64::decode_config_slice(
                line.as_bytes(),
                base64::STANDARD,
                self.byte_buf.as_mut(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Output as much as we can of this line
            if buf.len() <= self.byte_end {
                buf.copy_from_slice(&self.byte_buf[..buf.len()]);
                self.byte_start = buf.len();
                self.data_read += buf_len;
                return Ok(buf_len);
            } else {
                buf[..self.byte_end].copy_from_slice(&self.byte_buf[..self.byte_end]);
                buf = &mut buf[self.byte_end..];
            }
        }

        self.data_read += buf_len - buf.len();
        Ok(buf_len - buf.len())
    }
}

impl<R: Read + Seek> Seek for ArmoredReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        loop {
            match self.is_armored {
                None => self.detect_armor()?,
                Some(false) => {
                    break if self.line_buf.is_empty() {
                        // Map the data read onto the underlying stream.
                        let start = self.start()?;
                        let pos = match pos {
                            SeekFrom::Start(offset) => SeekFrom::Start(start + offset),
                            // Current and End positions don't need to be shifted.
                            x => x,
                        };
                        self.inner.seek(pos)
                    } else {
                        // We are still inside the first line.
                        match pos {
                            SeekFrom::Start(offset) => self.line_read = offset as usize,
                            SeekFrom::Current(offset) => {
                                let res = (self.line_read as i64) + offset;
                                if res >= 0 {
                                    self.line_read = res as usize;
                                } else {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "cannot seek before the start",
                                    ));
                                }
                            }
                            SeekFrom::End(offset) => {
                                let res = (self.line_buf.len() as i64) + offset;
                                if res >= 0 {
                                    self.line_read = res as usize;
                                } else {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "cannot seek before the start",
                                    ));
                                }
                            }
                        }
                        Ok(self.line_read as u64)
                    };
                }
                Some(true) => {
                    // Convert the offset into the target position within the data inside
                    // the armor.
                    let start = self.start()?;
                    let target_pos = match pos {
                        SeekFrom::Start(offset) => offset,
                        SeekFrom::Current(offset) => {
                            let res = (self.data_read as i64) + offset;
                            if res >= 0 as i64 {
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

                    // Jump back to the start of the armor data, and then read and drop
                    // until we reach the target position. This is very inefficient, but
                    // as armored files can have arbitrary line endings within the file,
                    // we can't determine where the armor line containing the target
                    // position begins within the reader.
                    self.inner.seek(SeekFrom::Start(start))?;
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

    use super::{ArmoredReader, ArmoredWriter, ARMORED_BYTES_PER_LINE};
    use crate::Format;

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
                let mut input = ArmoredReader::from_reader(&encoded[..]);
                input.read_to_end(&mut buf).unwrap();
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

        let mut r = ArmoredReader::from_reader(Cursor::new(written));

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

        let mut r = ArmoredReader::from_reader(Cursor::new(armored));

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
