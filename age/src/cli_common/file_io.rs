//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use is_terminal::IsTerminal;
use zeroize::Zeroize;

use crate::{fl, util::LINE_ENDING, wfl, wlnfl};

const SHORT_OUTPUT_LENGTH: usize = 20 * 80;

#[derive(Debug)]
struct DenyBinaryOutputError;

impl fmt::Display for DenyBinaryOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wlnfl!(f, "err-deny-binary-output")?;
        wfl!(f, "rec-deny-binary-output")
    }
}

impl std::error::Error for DenyBinaryOutputError {}

#[derive(Debug)]
struct DetectedBinaryOutputError;

impl fmt::Display for DetectedBinaryOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wlnfl!(f, "err-detected-binary")?;
        wfl!(f, "rec-detected-binary")
    }
}

impl std::error::Error for DetectedBinaryOutputError {}

#[derive(Debug)]
struct DenyOverwriteFileError(String);

impl fmt::Display for DenyOverwriteFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wfl!(f, "err-deny-overwrite-file", filename = self.0.as_str())
    }
}

impl std::error::Error for DenyOverwriteFileError {}

/// Wrapper around a [`File`].
pub struct FileReader {
    inner: File,
    filename: String,
}

/// Wrapper around either a file or standard input.
pub enum InputReader {
    /// Wrapper around a file.
    File(FileReader),
    /// Wrapper around standard input.
    Stdin(io::Stdin),
}

impl InputReader {
    /// Reads input from the given filename, or standard input if `None` or `Some("-")`.
    pub fn new(input: Option<String>) -> io::Result<Self> {
        if let Some(filename) = input {
            // Respect the Unix convention that "-" as an input filename
            // parameter is an explicit request to use standard input.
            if filename != "-" {
                return Ok(InputReader::File(FileReader {
                    inner: File::open(&filename)?,
                    filename,
                }));
            }
        }

        Ok(InputReader::Stdin(io::stdin()))
    }

    /// Returns true if this input is from a terminal, and a user is likely typing it.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Stdin(_)) && io::stdin().is_terminal()
    }

    pub(crate) fn filename(&self) -> Option<&str> {
        if let Self::File(f) = self {
            Some(&f.filename)
        } else {
            None
        }
    }
}

impl Read for InputReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            InputReader::File(f) => f.inner.read(buf),
            InputReader::Stdin(handle) => handle.read(buf),
        }
    }
}

/// A stdout write that optionally buffers the entire output before writing.
#[derive(Debug)]
enum StdoutBuffer {
    Direct(io::Stdout),
    Buffered(Vec<u8>),
}

impl StdoutBuffer {
    fn direct() -> Self {
        Self::Direct(io::stdout())
    }

    fn buffered() -> Self {
        Self::Buffered(Vec::with_capacity(8 * 1024 * 1024))
    }
}

impl Write for StdoutBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            StdoutBuffer::Direct(w) => w.write(data),
            StdoutBuffer::Buffered(buf) => {
                // If we need to re-allocate the buffer, do so manually so we can zeroize.
                if buf.len() + data.len() > buf.capacity() {
                    let mut new_buf = Vec::with_capacity(std::cmp::max(
                        buf.capacity() * 2,
                        buf.capacity() + data.len(),
                    ));
                    new_buf.extend_from_slice(buf);
                    buf.zeroize();
                    *buf = new_buf;
                }

                buf.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            StdoutBuffer::Direct(w) => w.flush(),
            StdoutBuffer::Buffered(buf) => {
                let mut w = io::stdout();
                w.write_all(buf)?;
                buf.zeroize();
                buf.clear();
                w.flush()
            }
        }
    }
}

impl Drop for StdoutBuffer {
    fn drop(&mut self) {
        // Destructors should not panic, so we ignore a failed flush.
        let _ = self.flush();
    }
}

/// The data format being written out.
#[derive(Debug)]
pub enum OutputFormat {
    /// Binary data that should not be sent to a TTY by default.
    Binary,
    /// Text data that is acceptable to send to a TTY.
    Text,
    /// Unknown data format; try to avoid sending binary data to a TTY.
    Unknown,
}

/// Writer that wraps standard output to handle TTYs nicely.
#[derive(Debug)]
pub struct StdoutWriter {
    inner: StdoutBuffer,
    count: usize,
    format: OutputFormat,
    is_tty: bool,
    truncated: bool,
}

impl StdoutWriter {
    fn new(format: OutputFormat, is_tty: bool, input_is_tty: bool) -> Self {
        StdoutWriter {
            // If the input comes from a TTY and the output will go to a TTY, buffer the
            // output so it doesn't get in the way of typing the input.
            inner: if input_is_tty && is_tty {
                StdoutBuffer::buffered()
            } else {
                StdoutBuffer::direct()
            },
            count: 0,
            format,
            is_tty,
            truncated: false,
        }
    }
}

impl Write for StdoutWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.is_tty {
            if let OutputFormat::Unknown = self.format {
                // Don't send unprintable output to TTY
                if std::str::from_utf8(data).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        DetectedBinaryOutputError,
                    ));
                }
            }

            let to_write = if let OutputFormat::Binary = self.format {
                // Only occurs if the user has explicitly forced stdout, so don't truncate.
                data.len()
            } else {
                // Drop output if we've truncated already, or need to.
                if self.truncated || self.count == SHORT_OUTPUT_LENGTH {
                    if !self.truncated {
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.inner.write_all(b"[")?;
                        self.inner.write_all(fl!("cli-truncated-tty").as_bytes())?;
                        self.inner.write_all(b"]")?;
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.truncated = true;
                    }

                    return io::sink().write(data);
                }

                let mut to_write = SHORT_OUTPUT_LENGTH - self.count;
                if to_write > data.len() {
                    to_write = data.len();
                }
                to_write
            };

            let mut ret = self.inner.write(&data[..to_write])?;
            self.count += to_write;

            if let OutputFormat::Binary = self.format {
                // Only occurs if the user has explicitly forced stdout, so don't truncate.
            } else {
                // If we have reached the output limit with data to spare,
                // truncate and drop the remainder.
                if self.count == SHORT_OUTPUT_LENGTH && data.len() > to_write {
                    if !self.truncated {
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.inner.write_all(b"[")?;
                        self.inner.write_all(fl!("cli-truncated-tty").as_bytes())?;
                        self.inner.write_all(b"]")?;
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.truncated = true;
                    }
                    ret += io::sink().write(&data[to_write..])?;
                }
            }

            Ok(ret)
        } else {
            self.inner.write(data)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A lazy [`File`] that is not opened until the first call to [`Write::write`] or
/// [`Write::flush`].
#[derive(Debug)]
pub struct LazyFile {
    filename: String,
    allow_overwrite: bool,
    #[cfg(unix)]
    mode: u32,
    file: Option<io::Result<File>>,
}

impl LazyFile {
    fn get_file(&mut self) -> io::Result<&mut File> {
        let filename = &self.filename;

        if self.file.is_none() {
            let mut options = OpenOptions::new();
            options.write(true);
            if self.allow_overwrite {
                options.create(true).truncate(true);
            } else {
                // In addition to the check in `OutputWriter::new`, we enforce this at
                // file opening time to avoid a race condition with the file being
                // separately created between `OutputWriter` construction and usage.
                options.create_new(true);
            }

            #[cfg(unix)]
            options.mode(self.mode);

            self.file = Some(options.open(filename));
        }

        self.file
            .as_mut()
            .unwrap()
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), format!("Failed to open file '{}'", filename)))
    }
}

impl io::Write for LazyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_file()?.flush()
    }
}

/// Wrapper around either a file or standard output.
#[derive(Debug)]
pub enum OutputWriter {
    /// Wrapper around a file.
    File(LazyFile),
    /// Wrapper around standard output.
    Stdout(StdoutWriter),
}

impl OutputWriter {
    /// Constructs a new `OutputWriter`.
    ///
    /// Writes to the file at path `output`, or standard output if `output` is `None` or
    /// `Some("-")`.
    ///
    /// If `allow_overwrite` is `true`, the file at path `output` will be overwritten if
    /// it exists. This option has no effect if `output` is `None` or `Some("-")`.
    pub fn new(
        output: Option<String>,
        allow_overwrite: bool,
        mut format: OutputFormat,
        _mode: u32,
        input_is_tty: bool,
    ) -> io::Result<Self> {
        let is_tty = console::user_attended();
        if let Some(filename) = output {
            // Respect the Unix convention that "-" as an output filename
            // parameter is an explicit request to use standard output.
            if filename != "-" {
                // We open the file lazily, but as we don't want the caller to assume
                // this, we eagerly confirm that the file does not exist if we can't
                // overwrite it.
                if !allow_overwrite && Path::new(&filename).exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        DenyOverwriteFileError(filename),
                    ));
                }

                return Ok(OutputWriter::File(LazyFile {
                    filename,
                    allow_overwrite,
                    #[cfg(unix)]
                    mode: _mode,
                    file: None,
                }));
            } else {
                // User explicitly requested stdout; force the format to binary so that we
                // don't try to parse it as UTF-8 in StdoutWriter and perhaps reject it.
                format = OutputFormat::Binary;
            }
        } else if is_tty {
            if let OutputFormat::Binary = format {
                // If output == Some("-") then this error is skipped.
                return Err(io::Error::new(io::ErrorKind::Other, DenyBinaryOutputError));
            }
        }

        Ok(OutputWriter::Stdout(StdoutWriter::new(
            format,
            is_tty,
            input_is_tty,
        )))
    }

    /// Returns true if this output is to a terminal, and a user will likely see it.
    pub fn is_terminal(&self) -> bool {
        match self {
            OutputWriter::File(..) => false,
            OutputWriter::Stdout(w) => w.is_tty,
        }
    }
}

impl Write for OutputWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            OutputWriter::File(f) => f.write(data),
            OutputWriter::Stdout(handle) => handle.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputWriter::File(f) => f.flush(),
            OutputWriter::Stdout(handle) => handle.flush(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(unix)]
    use super::{OutputFormat, OutputWriter};
    #[cfg(unix)]
    use std::io::Write;

    #[cfg(unix)]
    #[test]
    fn lazy_existing_file_allow_overwrite() {
        OutputWriter::new(
            Some("/dev/null".to_string()),
            true,
            OutputFormat::Text,
            0o600,
            false,
        )
        .unwrap()
        .flush()
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lazy_existing_file_forbid_overwrite() {
        use std::io;

        let e = OutputWriter::new(
            Some("/dev/null".to_string()),
            false,
            OutputFormat::Text,
            0o600,
            false,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    }
}
