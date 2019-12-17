use radix64::{configs::UrlSafeNoPad, io::EncodeWriter, URL_SAFE_NO_PAD};
use std::cmp;
use std::io::{self, Write};

use crate::util::LINE_ENDING;

const ARMORED_COLUMNS_PER_LINE: usize = 56;
const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;
const ARMORED_END_MARKER: &str = "--- end of file ---";

pub(crate) struct LineEndingWriter<W: Write> {
    inner: W,
    total_written: usize,
}

impl<W: Write> LineEndingWriter<W> {
    fn new(inner: W) -> Self {
        LineEndingWriter {
            inner,
            total_written: 0,
        }
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
        encoder: EncodeWriter<UrlSafeNoPad, LineEndingWriter<W>>,
    },

    Disabled {
        inner: W,
    },
}

impl<W: Write> ArmoredWriter<W> {
    pub(crate) fn wrap_output(inner: W, enabled: bool) -> Self {
        if enabled {
            ArmoredWriter::Enabled {
                encoder: EncodeWriter::new(URL_SAFE_NO_PAD, LineEndingWriter::new(inner)),
            }
        } else {
            ArmoredWriter::Disabled { inner }
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
