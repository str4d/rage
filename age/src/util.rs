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
    #[cfg(feature = "ssh")]
    use nom::{
        combinator::map_res,
        error::{make_error, ErrorKind},
        multi::separated_list1,
        IResult,
    };

    #[cfg(feature = "ssh")]
    pub(crate) fn encoded_str(
        count: usize,
        config: base64::Config,
    ) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
        use nom::bytes::streaming::take;

        // Unpadded encoded length
        let encoded_count = ((4 * count) + 2) / 3;

        move |input: &str| {
            let (i, data) = take(encoded_count)(input)?;
            match base64::decode_config(data, config) {
                Ok(decoded) => Ok((i, decoded)),
                Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
            }
        }
    }

    #[cfg(feature = "ssh")]
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

    #[cfg(feature = "ssh")]
    pub(crate) fn wrapped_str_while_encoded(
        config: base64::Config,
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

    pub(crate) fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
        if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
            return None;
        }

        match base64::decode_config_slice(arg, base64::STANDARD_NO_PAD, buf.as_mut()) {
            Ok(_) => Some(buf),
            Err(_) => None,
        }
    }
}

pub(crate) mod write {
    use cookie_factory::{combinator::string, SerializeFn};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::STANDARD_NO_PAD);
        string(encoded)
    }
}
