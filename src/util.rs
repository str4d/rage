use nom::{
    bytes::streaming::take,
    error::{make_error, ErrorKind},
    IResult,
};

pub(crate) fn read_encoded_str(count: usize) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
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

        match base64::decode_config(data, base64::URL_SAFE_NO_PAD) {
            Ok(decoded) => Ok((i, decoded)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
        }
    }
}
