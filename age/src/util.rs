use bech32::{FromBase32, Variant};

#[cfg(all(any(feature = "armor", feature = "cli-common"), windows))]
pub(crate) const LINE_ENDING: &str = "\r\n";
#[cfg(all(any(feature = "armor", feature = "cli-common"), not(windows)))]
pub(crate) const LINE_ENDING: &str = "\n";

pub(crate) fn parse_bech32(s: &str) -> Option<(String, Vec<u8>)> {
    bech32::decode(s).ok().and_then(|(hrp, data, variant)| {
        if let Variant::Bech32 = variant {
            Vec::from_base32(&data).ok().map(|d| (hrp, d))
        } else {
            None
        }
    })
}

pub(crate) mod read {
    use std::str::FromStr;

    use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
    use nom::{character::complete::digit1, combinator::verify, ParseTo};

    #[cfg(feature = "ssh")]
    use nom::{
        combinator::map_res,
        error::{make_error, ErrorKind},
        multi::separated_list1,
        IResult,
    };

    #[cfg(feature = "ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
    pub(crate) fn encoded_str(
        count: usize,
        engine: impl base64::Engine,
    ) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
        use nom::bytes::streaming::take;

        // Unpadded encoded length
        let encoded_count = ((4 * count) + 2) / 3;

        move |input: &str| {
            let (i, data) = take(encoded_count)(input)?;
            match engine.decode(data) {
                Ok(decoded) => Ok((i, decoded)),
                Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
            }
        }
    }

    #[cfg(feature = "ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
    pub(crate) fn str_while_encoded(
        engine: impl base64::Engine,
    ) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
        use nom::bytes::complete::take_while1;

        move |input: &str| {
            map_res(
                take_while1(|c| {
                    let c = c as u8;
                    // Substitute the character in twice after AA, so that padding
                    // characters will also be detected as a valid if allowed.
                    engine.decode_slice([65, 65, c, c], &mut [0, 0, 0]).is_ok()
                }),
                |data| engine.decode(data),
            )(input)
        }
    }

    #[cfg(feature = "ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
    pub(crate) fn wrapped_str_while_encoded(
        engine: impl Engine,
    ) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
        use nom::{bytes::streaming::take_while1, character::streaming::line_ending};

        move |input: &str| {
            map_res(
                separated_list1(
                    line_ending,
                    take_while1(|c| {
                        let c = c as u8;
                        // Substitute the character in twice after AA, so that padding
                        // characters will also be detected as a valid if allowed.
                        engine.decode_slice([65, 65, c, c], &mut [0, 0, 0]).is_ok()
                    }),
                ),
                |chunks| {
                    let data = chunks.join("");
                    engine.decode(&data)
                },
            )(input)
        }
    }

    pub(crate) fn base64_arg<A: AsRef<[u8]>, const N: usize, const B: usize>(
        arg: &A,
    ) -> Option<[u8; N]> {
        if N > B {
            return None;
        }

        let mut buf = [0; B];
        match BASE64_STANDARD_NO_PAD.decode_slice(arg, buf.as_mut()) {
            Ok(n) if n == N => Some(buf[..N].try_into().unwrap()),
            _ => None,
        }
    }

    /// Parses a decimal number composed only of digits with no leading zeros.
    pub(crate) fn decimal_digit_arg<T: FromStr>(arg: &str) -> Option<T> {
        verify::<_, _, _, (), _, _>(digit1, |n: &str| !n.starts_with('0'))(arg)
            .ok()
            .and_then(|(_, n)| n.parse_to())
    }
}

pub(crate) mod write {
    use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
    use cookie_factory::{combinator::string, SerializeFn};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = BASE64_STANDARD_NO_PAD.encode(data);
        string(encoded)
    }
}
