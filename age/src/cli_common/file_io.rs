//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::util::LINE_ENDING;

const SHORT_OUTPUT_LENGTH: usize = 20 * 80;
const TRUNCATED_TTY_MSG: &[u8] =
    b"[truncated; use a pipe, a redirect, or -o/--output to see full message]";

#[derive(Debug)]
struct DenyBinaryOutputError;

impl fmt::Display for DenyBinaryOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "refusing to output binary to the terminal.")?;
        write!(f, "Did you mean to use -a/--armor? Force with '-o -'.")
    }
}

impl std::error::Error for DenyBinaryOutputError {}

#[derive(Debug)]
struct DetectedBinaryOutputError;

impl fmt::Display for DetectedBinaryOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "detected unprintable data; refusing to output to the terminal."
        )?;
        write!(f, "Force with '-o -'.")
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
                        self.inner.write_all(TRUNCATED_TTY_MSG)?;
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
                        self.inner.write_all(TRUNCATED_TTY_MSG)?;
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

/// Wrapper around either a file or standard output.
pub enum OutputWriter {
    /// Wrapper around a file.
    File(File),
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
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);

                #[cfg(unix)]
                options.mode(_mode);

                return Ok(OutputWriter::File(options.open(filename)?));
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
