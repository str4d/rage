use std::fs::File;
use std::io::{self, Read, Write};

/// Wrapper around either a file or standard input.
pub enum InputReader {
    File(File),
    Stdin(io::Stdin),
}

impl InputReader {
    /// Reads input from the given filename, or standard input if `None`.
    pub fn new(input: Option<String>) -> io::Result<Self> {
        Ok(if let Some(filename) = input {
            InputReader::File(File::open(filename)?)
        } else {
            InputReader::Stdin(io::stdin())
        })
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

/// Wrapper around either a file or standard output.
pub enum OutputWriter {
    File(File),
    Stdout(io::Stdout),
}

impl OutputWriter {
    /// Writes output to the given filename, or standard output if `None`.
    pub fn new(output: Option<String>) -> io::Result<Self> {
        Ok(if let Some(filename) = output {
            OutputWriter::File(File::create(filename)?)
        } else {
            // TODO: Return an error if bound to a TTY.
            OutputWriter::Stdout(io::stdout())
        })
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
