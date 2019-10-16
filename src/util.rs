use nom::{
    bytes::streaming::{take, take_while1},
    character::streaming::newline,
    error::{make_error, ErrorKind},
    multi::separated_nonempty_list,
    IResult,
};

pub(crate) fn read_encoded_str(
    count: usize,
    config: base64::Config,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
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
