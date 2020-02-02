/// From the age spec:
/// ```text
/// Each recipient stanza starts with a line beginning with -> and its type name, followed
/// by zero or more SP-separated arguments. The type name and the arguments are arbitrary
/// strings. Unknown recipient types are ignored. The rest of the recipient stanza is a
/// body of canonical base64 from RFC 4648 without padding wrapped at exactly 64 columns.
/// ```
#[derive(Debug)]
pub struct AgeStanza<'a> {
    pub tag: &'a str,
    pub args: Vec<&'a str>,
    pub body: Vec<u8>,
}

pub mod read {
    use nom::{
        bytes::streaming::tag,
        character::streaming::newline,
        combinator::{map, map_opt},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        sequence::separated_pair,
        IResult,
    };

    use super::AgeStanza;

    /// From the age specification:
    /// ```text
    /// ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
    /// ```
    pub fn arbitrary_string(input: &[u8]) -> IResult<&[u8], &str> {
        use nom::bytes::streaming::take_while1;

        map(take_while1(|c| c >= 33 && c <= 126), |bytes| {
            std::str::from_utf8(bytes).expect("ASCII is valid UTF-8")
        })(input)
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

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
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

    /// Reads an age stanza.
    pub fn age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            separated_pair(
                separated_nonempty_list(tag(" "), arbitrary_string),
                newline,
                wrapped_encoded_data,
            ),
            |(mut args, body)| {
                let tag = args.remove(0);
                AgeStanza { tag, args, body }
            },
        )(input)
    }
}

pub mod write {
    use cookie_factory::{
        combinator::string, multi::separated_list, sequence::tuple, SerializeFn, WriteContext,
    };
    use std::io::Write;
    use std::iter;

    fn wrapped_encoded_data<'a, W: 'a + Write>(data: &[u8]) -> impl SerializeFn<W> + 'a {
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

    /// Writes an age stanza.
    pub fn age_stanza<'a, W: 'a + Write>(
        tag: &'a str,
        args: &'a [&'a str],
        body: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            separated_list(
                string(" "),
                iter::once(tag).chain(args.iter().copied()).map(string),
            ),
            string("\n"),
            wrapped_encoded_data(body),
        ))
    }
}
