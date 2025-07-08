//! Common helpers for performing I/O.

use std::io::{self, Read, Stderr, Write};

use io_tee::{TeeReader, TeeWriter};

#[cfg(feature = "plugin")]
use io_tee::{ReadExt, WriteExt};

/// A wrapper around a reader that optionally tees its input to `stderr` for this process.
pub enum DebugReader<R: Read> {
    Off(R),
    On(TeeReader<R, Stderr>),
}

impl<R: Read> DebugReader<R> {
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    pub(crate) fn new(reader: R, debug_enabled: bool) -> Self {
        // Only enable debug tee in debug builds to prevent accidental plaintext leakage
        #[cfg(debug_assertions)]
        if debug_enabled {
            return DebugReader::On(reader.tee_dbg());
        }
        DebugReader::Off(reader)
    }
}

impl<R: Read> Read for DebugReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Off(reader) => reader.read(buf),
            Self::On(reader) => reader.read(buf),
        }
    }
}

/// A wrapper around a writer that optionally tees its output to `stderr` for this process.
pub enum DebugWriter<W: Write> {
    Off(W),
    On(TeeWriter<W, Stderr>),
}

impl<W: Write> DebugWriter<W> {
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    pub(crate) fn new(writer: W, debug_enabled: bool) -> Self {
        // Only enable debug tee in debug builds to prevent accidental plaintext leakage
        #[cfg(debug_assertions)]
        if debug_enabled {
            return DebugWriter::On(writer.tee_dbg());
        }
        DebugWriter::Off(writer)
    }
}

impl<W: Write> Write for DebugWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Off(writer) => writer.write(buf),
            Self::On(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Off(writer) => writer.flush(),
            Self::On(writer) => writer.flush(),
        }
    }
}
