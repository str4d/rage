use nom::{
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
        let (i, data) = take_while1(|c| {
            let c = c as u8;
            // Substitute the character in twice after AA, so that padding
            // characters will also be detected as a valid if allowed.
            base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_ok()
        })(input)?;

        match base64::decode_config(data, config) {
            Ok(decoded) => Ok((i, decoded)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
        }
    }
}

pub(crate) fn read_wrapped_str_while_encoded(
    config: base64::Config,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    use nom::{bytes::streaming::take_while1, character::streaming::newline};

    move |input: &str| {
        let (i, chunks) = separated_nonempty_list(
            newline,
            take_while1(|c| {
                let c = c as u8;
                // Substitute the character in twice after AA, so that padding
                // characters will also be detected as a valid if allowed.
                base64::decode_config_slice(&[65, 65, c, c], config, &mut [0, 0, 0]).is_ok()
            }),
        )(input)?;
        let data = chunks.join("");

        match base64::decode_config(&data, config) {
            Ok(decoded) => Ok((i, decoded)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
        }
    }
}
