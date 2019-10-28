use nom::{
    combinator::map_res,
    error::{make_error, ErrorKind},
    multi::separated_nonempty_list,
    IResult,
};
use std::io::{self, Read, Write};

#[cfg(windows)]
pub(crate) const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
pub(crate) const LINE_ENDING: &str = "\n";

const ARMORED_END_MARKER: &[u8] = b"***";

/// Returns the slice of input up to (but not including) the first newline
/// character, if that slice is entirely Base64 characters
///
/// # Errors
///
/// - Returns Failure on an empty slice.
/// - Returns Incomplete(1) if a newline is not found.
pub(crate) fn take_b64_line(config: base64::Config) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input: &[u8]| {
        let mut end = 0;
        while end < input.len() {
            let c = input[end];

            if c == b'\n' {
                break;
            }

            // Substitute the character in twice after AA, so that padding
            // characters will also be detected as a valid if allowed.
            if base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_err() {
                end = 0;
                break;
            }

            end += 1;
        }

        if !input.is_empty() && end == 0 {
            Err(nom::Err::Error(make_error(input, ErrorKind::Eof)))
        } else if end < input.len() {
            Ok((&input[end..], &input[..end]))
        } else {
            Err(nom::Err::Incomplete(nom::Needed::Size(1)))
        }
    }
}

pub(crate) fn read_encoded_str(
    count: usize,
    config: base64::Config,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    use nom::bytes::streaming::take;

    // Unpadded encoded length
    let encoded_count = ((4 * count) + 2) / 3;

    move |input: &str| {
        // take() returns the total number of bytes it needs, not the
        // additional number of bytes like other APIs.
        let (i, data) = take(encoded_count)(input).map_err(|e| match e {
            nom::Err::Incomplete(nom::Needed::Size(n)) if n == encoded_count => {
                nom::Err::Incomplete(nom::Needed::Size(encoded_count - input.len()))
            }
            e => e,
        })?;

        match base64::decode_config(data, config) {
            Ok(decoded) => Ok((i, decoded)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
        }
    }
}

pub(crate) fn read_str_while_encoded(
    config: base64::Config,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    use nom::bytes::complete::take_while1;

    move |input: &str| {
        map_res(
            take_while1(|c| {
                let c = c as u8;
                // Substitute the character in twice after AA, so that padding
                // characters will also be detected as a valid if allowed.
                base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_ok()
            }),
            |data| base64::decode_config(data, config),
        )(input)
    }
}

pub(crate) fn read_wrapped_str_while_encoded(
    config: base64::Config,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    use nom::{bytes::streaming::take_while1, character::streaming::newline};

    move |input: &str| {
        map_res(
            separated_nonempty_list(
                newline,
                take_while1(|c| {
                    let c = c as u8;
                    // Substitute the character in twice after AA, so that padding
                    // characters will also be detected as a valid if allowed.
                    base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_ok()
                }),
            ),
            |chunks| {
                let data = chunks.join("");
                base64::decode_config(&data, config)
            },
        )(input)
    }
}

pub(crate) struct ArmoredWriter<W: Write> {
    inner: W,
    enabled: bool,
    chunk: (Option<u8>, Option<u8>, Option<u8>),
    line_length: usize,
}

impl<W: Write> ArmoredWriter<W> {
    pub(crate) fn wrap_output(inner: W, enabled: bool) -> Self {
        ArmoredWriter {
            inner,
            enabled,
            chunk: (None, None, None),
            line_length: 0,
        }
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if !self.enabled {
            return self.inner.write(buf);
        }

        let mut bytes_written = 0;

        while !buf.is_empty() {
            let byte = buf[0];
            buf = &buf[1..];
            bytes_written += 1;

            match self.chunk {
                (None, None, None) => self.chunk.0 = Some(byte),
                (Some(_), None, None) => self.chunk.1 = Some(byte),
                (Some(_), Some(_), None) => self.chunk.2 = Some(byte),
                (Some(a), Some(b), Some(c)) => {
                    // Wrap the line if needed
                    if self.line_length >= 56 {
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.line_length = 0;
                    }

                    // Process the bytes we already have
                    let mut encoded = [0; 4];
                    assert_eq!(
                        base64::encode_config_slice(
                            &[a, b, c],
                            base64::URL_SAFE_NO_PAD,
                            &mut encoded
                        ),
                        4
                    );
                    self.inner.write_all(&encoded)?;
                    self.line_length += 4;

                    // Store the new byte
                    self.chunk = (Some(byte), None, None);
                }
                _ => unreachable!(),
            }
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.enabled {
            // Wrap the line if needed
            if self.line_length >= 56 {
                self.inner.write_all(LINE_ENDING.as_bytes())?;
                self.line_length = 0;
            }

            // Process the remaining bytes
            let mut encoded = [0; 4];
            let encoded_size = match self.chunk {
                (None, None, None) => 0,
                (Some(a), None, None) => {
                    base64::encode_config_slice(&[a], base64::URL_SAFE_NO_PAD, &mut encoded)
                }
                (Some(a), Some(b), None) => {
                    base64::encode_config_slice(&[a, b], base64::URL_SAFE_NO_PAD, &mut encoded)
                }
                (Some(a), Some(b), Some(c)) => {
                    base64::encode_config_slice(&[a, b, c], base64::URL_SAFE_NO_PAD, &mut encoded)
                }
                _ => unreachable!(),
            };
            self.inner.write_all(&encoded[0..encoded_size])?;
            self.line_length += encoded_size;

            // Write a line ending if there is anything on the final line
            if self.line_length > 0 {
                self.inner.write_all(LINE_ENDING.as_bytes())?;
            }

            // Write the end marker
            self.inner.write_all(ARMORED_END_MARKER)?;
            self.inner.write_all(LINE_ENDING.as_bytes())?;
        }
        self.inner.flush()
    }
}

pub(crate) struct ArmoredReader<R: Read> {
    inner: R,
    enabled: bool,
    spare_bytes: (Option<u8>, Option<u8>),
    line_length: usize,
    found_end: bool,
}

impl<R: Read> ArmoredReader<R> {
    pub(crate) fn from_reader(inner: R, enabled: bool) -> Self {
        ArmoredReader {
            inner,
            enabled,
            spare_bytes: (None, None),
            line_length: 0,
            found_end: false,
        }
    }
}

impl<R: Read> Read for ArmoredReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.enabled {
            return self.inner.read(buf);
        }
        if self.found_end {
            return Ok(0);
        }

        let mut bytes_read = 0;

        if let Some(a) = self.spare_bytes.0.take() {
            buf[bytes_read] = a;
            bytes_read += 1;
        }
        if let Some(b) = self.spare_bytes.1.take() {
            buf[bytes_read] = b;
            bytes_read += 1;
        }

        while !self.found_end && bytes_read < buf.len() {
            // Clear any line endings
            if self.line_length >= 56 {
                let mut chunk = [0; 1];
                self.inner.read_exact(&mut chunk)?;
                if chunk[0] == b'\r' {
                    self.inner.read_exact(&mut chunk)?;
                    if chunk[0] != b'\n' {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid CRLF line ending",
                        ));
                    }
                } else if chunk[0] != b'\n' {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid line ending",
                    ));
                }
                self.line_length = 0;
            }

            let mut chunk = [0; 4];
            let mut end = 0;
            while end < 4 {
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

            // Check whether we have found a short line. Regular-length lines
            // are multiples of four bytes, and will never contain line-end
            // characters.
            if chunk[0] == b'*' {
                // Expected ending tag is "***\n" or "***\r\n"
                if &chunk == b"***\n" {
                    // All done!
                } else if &chunk == b"***\r" {
                    let mut final_byte = [0; 1];
                    self.inner.read_exact(&mut final_byte)?;
                    if &final_byte != b"\n" {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid ending tag",
                        ));
                    }
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid ending tag",
                    ));
                }

                self.found_end = true;
                break;
            } else {
                for (i, b) in chunk.iter().enumerate() {
                    if *b == b'\r' {
                        // Expected ending tag is "\r\n***\r\n"
                        let mut end_tag = [0; 7];
                        end_tag[..end - i].copy_from_slice(&chunk[i..]);
                        self.inner.read_exact(&mut end_tag[end - i..])?;
                        if &end_tag != b"\r\n***\r\n" {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid ending tag",
                            ));
                        }

                        end = i;
                        self.found_end = true;
                        break;
                    } else if *b == b'\n' {
                        // Expected ending tag is "\n***\n"
                        let mut end_tag = [0; 5];
                        end_tag[..end - i].copy_from_slice(&chunk[i..]);
                        self.inner.read_exact(&mut end_tag[end - i..])?;
                        if &end_tag != b"\n***\n" {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid ending tag",
                            ));
                        }

                        end = i;
                        self.found_end = true;
                        break;
                    }
                }
            }

            self.line_length += end;

            if end > 0 && bytes_read + 3 > buf.len() {
                // Read possibly-partial triplet, caching the extra bytes
                let mut decoded = [0; 3];
                let decoded_size = base64::decode_config_slice(
                    &chunk[..end],
                    base64::URL_SAFE_NO_PAD,
                    &mut decoded,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                // We can always read one byte here
                assert!(decoded_size > 0);
                buf[bytes_read] = decoded[0];
                bytes_read += 1;

                if decoded_size > 1 {
                    if bytes_read < buf.len() {
                        buf[bytes_read] = decoded[1];
                        bytes_read += 1;

                        if decoded_size > 2 {
                            if bytes_read < buf.len() {
                                buf[bytes_read] = decoded[2];
                                bytes_read += 1;
                            } else {
                                self.spare_bytes = (Some(decoded[2]), None);
                            }
                        }
                    } else {
                        self.spare_bytes.0 = Some(decoded[1]);
                        if decoded_size > 2 {
                            self.spare_bytes.1 = Some(decoded[2]);
                        }
                    }
                }
            } else {
                let decoded_size = base64::decode_config_slice(
                    &chunk[..end],
                    base64::URL_SAFE_NO_PAD,
                    &mut buf[bytes_read..],
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                bytes_read += decoded_size;
            }
        }

        Ok(bytes_read)
    }
}
