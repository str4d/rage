#[cfg(windows)]
pub(crate) const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
pub(crate) const LINE_ENDING: &str = "\n";

pub(crate) mod read {
    use nom::{
        combinator::map_res,
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
}

pub(crate) mod write {
    use cookie_factory::{combinator::string, SerializeFn};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);
        string(encoded)
    }
}
