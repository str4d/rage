#[cfg(windows)]
pub(crate) const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
pub(crate) const LINE_ENDING: &str = "\n";

pub(crate) mod read {
    use nom::{
        combinator::{map, map_opt, map_res},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        IResult,
    };

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

    /// From the age specification:
    /// ```text
    /// ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
    /// ```
    pub(crate) fn arbitrary_string(input: &[u8]) -> IResult<&[u8], &str> {
        use nom::bytes::streaming::take_while1;

        map(take_while1(|c| c >= 33 && c <= 126), |bytes| {
            std::str::from_utf8(bytes).expect("ASCII is valid UTF-8")
        })(input)
    }

    pub(crate) fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
        if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
            return None;
        }

        match base64::decode_config_slice(arg, base64::STANDARD_NO_PAD, buf.as_mut()) {
            Ok(_) => Some(buf),
            Err(_) => None,
        }
    }

    /// Returns the slice of input up to (but not including) the first LF
    /// character, if that slice is entirely Base64 characters
    ///
    /// # Errors
    ///
    /// - Returns Failure on an empty slice.
    /// - Returns Incomplete(1) if a LF is not found.
    fn take_b64_line(config: base64::Config) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
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

    pub(crate) fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        use nom::character::streaming::newline;

        map_opt(
            separated_nonempty_list(newline, take_b64_line(base64::STANDARD_NO_PAD)),
            |chunks| {
                // Enforce that the only chunk allowed to be shorter than 64 characters
                // is the last chunk.
                if chunks.iter().rev().skip(1).any(|s| s.len() != 64)
                    || chunks.last().map(|s| s.len() > 64) == Some(true)
                {
                    None
                } else {
                    let data: Vec<u8> = chunks.into_iter().flatten().cloned().collect();
                    base64::decode_config(&data, base64::STANDARD_NO_PAD).ok()
                }
            },
        )(input)
    }
}

pub(crate) mod write {
    use cookie_factory::{combinator::string, SerializeFn, WriteContext};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::STANDARD_NO_PAD);
        string(encoded)
    }

    pub(crate) fn wrapped_encoded_data<'a, W: 'a + Write>(data: &[u8]) -> impl SerializeFn<W> + 'a {
        let encoded = base64::encode_config(data, base64::STANDARD_NO_PAD);

        move |mut w: WriteContext<W>| {
            let mut s = encoded.as_str();

            while s.len() > 64 {
                let (l, r) = s.split_at(64);
                w = string(l)(w)?;
                if !r.is_empty() {
                    w = string("\n")(w)?;
                }
                s = r;
            }

            string(s)(w)
        }
    }
}
