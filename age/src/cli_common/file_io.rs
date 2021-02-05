//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

/// Wrapper around either a file or standard input.
pub enum InputReader {
    /// Wrapper around a file.
    File(File),
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
                return Ok(InputReader::File(File::open(filename)?));
            }
        }

        Ok(InputReader::Stdin(io::stdin()))
    }
}

impl Read for InputReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            InputReader::File(f) => f.read(buf),
            InputReader::Stdin(handle) => handle.read(buf),
        }
    }
}

/// The data format being written out.
pub enum OutputFormat {
    /// Binary data that should not be sent to a TTY by default.
    Binary,
    /// Text data that is acceptable to send to a TTY.
    Text,
    /// Unknown data format; try to avoid sending binary data to a TTY.
    Unknown,
}

/// Writer that wraps standard output to handle TTYs nicely.
pub struct StdoutWriter {
    inner: io::Stdout,
    count: usize,
    format: OutputFormat,
    is_tty: bool,
    truncated: bool,
}

impl StdoutWriter {
    fn new(format: OutputFormat, is_tty: bool) -> Self {
        StdoutWriter {
            inner: io::stdout(),
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
pub struct LazyFile {
    filename: String,
    #[cfg(unix)]
    mode: u32,
    file: Option<io::Result<File>>,
}

impl LazyFile {
    fn get_file(&mut self) -> io::Result<&mut File> {
        let filename = &self.filename;

        if self.file.is_none() {
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);

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
pub enum OutputWriter {
    /// Wrapper around a file.
    File(LazyFile),
    /// Wrapper around standard output.
    Stdout(StdoutWriter),
}

impl OutputWriter {
    /// Writes output to the given filename, or standard output if `None` or `Some("-")`.
    pub fn new(output: Option<String>, mut format: OutputFormat, _mode: u32) -> io::Result<Self> {
        let is_tty = console::user_attended();
        if let Some(filename) = output {
            // Respect the Unix convention that "-" as an output filename
            // parameter is an explicit request to use standard output.
            if filename != "-" {
                return Ok(OutputWriter::File(LazyFile {
                    filename,
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

        Ok(OutputWriter::Stdout(StdoutWriter::new(format, is_tty)))
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
    fn lazy_existing_file() {
        OutputWriter::new(Some("/dev/null".to_string()), OutputFormat::Text, 0o600)
            .unwrap()
            .flush()
            .unwrap();
    }
}
