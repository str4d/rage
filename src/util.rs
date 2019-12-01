use std::io::{self, BufRead, BufReader, Read, Write};
use zeroize::Zeroizing;

#[cfg(windows)]
pub(crate) const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
pub(crate) const LINE_ENDING: &str = "\n";

const ARMORED_COLUMNS_PER_LINE: usize = 56;
const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;
const ARMORED_END_MARKER: &str = "--- end of file ---";

pub(crate) mod read {
    use nom::{
        combinator::{map_opt, map_res},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        IResult,
    };

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

    pub(crate) fn encoded_str(
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

    pub(crate) fn str_while_encoded(
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

    pub(crate) fn wrapped_str_while_encoded(
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

    pub(crate) fn encoded_data<T: Copy + AsMut<[u8]>>(
        count: usize,
        template: T,
    ) -> impl Fn(&[u8]) -> IResult<&[u8], T> {
        use nom::bytes::streaming::take;

        // Unpadded encoded length
        let encoded_count = ((4 * count) + 2) / 3;

        move |input: &[u8]| {
            // Cannot take the input directly, so we copy it here. We only call this with
            // short slices, so this continues to avoid allocations.
            let mut buf = template;

            // take() returns the total number of bytes it needs, not the
            // additional number of bytes like other APIs.
            let (i, data) = take(encoded_count)(input).map_err(|e| match e {
                nom::Err::Incomplete(nom::Needed::Size(n)) if n == encoded_count => {
                    nom::Err::Incomplete(nom::Needed::Size(encoded_count - input.len()))
                }
                e => e,
            })?;

            match base64::decode_config_slice(data, base64::URL_SAFE_NO_PAD, buf.as_mut()) {
                Ok(_) => Ok((i, buf)),
                Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
            }
        }
    }

    pub(crate) fn wrapped_encoded_data<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
        move |input: &[u8]| {
            map_opt(
                separated_nonempty_list(line_ending, take_b64_line(base64::URL_SAFE_NO_PAD)),
                |chunks| {
                    // Enforce that the only chunk allowed to be shorter than 56 characters
                    // is the last chunk.
                    if chunks.iter().rev().skip(1).any(|s| s.len() != 56)
                        || chunks.last().map(|s| s.len() > 56) == Some(true)
                    {
                        None
                    } else {
                        let data: Vec<u8> = chunks.into_iter().flatten().cloned().collect();
                        base64::decode_config(&data, base64::URL_SAFE_NO_PAD).ok()
                    }
                },
            )(input)
        }
    }
}

pub(crate) mod write {
    use cookie_factory::{combinator::string, SerializeFn, WriteContext};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);
        string(encoded)
    }

    pub(crate) fn wrapped_encoded_data<'a, W: 'a + Write>(
        data: &[u8],
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);

        move |mut w: WriteContext<W>| {
            let mut s = encoded.as_str();

            while s.len() > 56 {
                let (l, r) = s.split_at(56);
                w = string(l)(w)?;
                if !r.is_empty() {
                    w = string(line_ending)(w)?;
                }
                s = r;
            }

            string(s)(w)
        }
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
                    if self.line_length >= ARMORED_COLUMNS_PER_LINE {
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
            if self.line_length >= ARMORED_COLUMNS_PER_LINE {
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
            self.inner.write_all(ARMORED_END_MARKER.as_bytes())?;
            self.inner.write_all(LINE_ENDING.as_bytes())?;
        }
        self.inner.flush()
    }
}

pub(crate) struct ArmoredReader<R: Read> {
    inner: BufReader<R>,
    enabled: bool,
    line_buf: Zeroizing<String>,
    byte_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    byte_start: usize,
    byte_end: usize,
    found_end: bool,
}

impl<R: Read> ArmoredReader<R> {
    pub(crate) fn from_reader(inner: R, enabled: bool) -> Self {
        ArmoredReader {
            inner: BufReader::new(inner),
            enabled,
            line_buf: Zeroizing::new(String::with_capacity(ARMORED_COLUMNS_PER_LINE + 2)),
            byte_buf: Zeroizing::new([0; ARMORED_BYTES_PER_LINE]),
            byte_start: ARMORED_BYTES_PER_LINE,
            byte_end: ARMORED_BYTES_PER_LINE,
            found_end: false,
        }
    }
}

impl<R: Read> Read for ArmoredReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if !self.enabled {
            return self.inner.read(buf);
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
            self.inner.read_line(&mut self.line_buf)?;

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

            // If this line is the EOF marker, we are done!
            if line == ARMORED_END_MARKER {
                self.found_end = true;
                break;
            }

            // Decode the line
            self.byte_end = base64::decode_config_slice(
                line.as_bytes(),
                base64::URL_SAFE_NO_PAD,
                self.byte_buf.as_mut(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Output as much as we can of this line
            if buf.len() <= self.byte_end {
                buf.copy_from_slice(&self.byte_buf[..buf.len()]);
                self.byte_start = buf.len();
                return Ok(buf_len);
            } else {
                buf[..self.byte_end].copy_from_slice(&self.byte_buf[..self.byte_end]);
                buf = &mut buf[self.byte_end..];
            }
        }

        Ok(buf_len - buf.len())
    }
}
