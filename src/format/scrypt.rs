const SCRYPT_RECIPIENT_TAG: &[u8] = b"scrypt ";

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) salt: [u8; 16],
    pub(crate) log_n: u8,
    pub(crate) encrypted_file_key: [u8; 32],
}

pub(super) mod read {
    use nom::{
        bytes::streaming::tag,
        character::streaming::digit1,
        combinator::{map, map_res},
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    fn salt(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
        encoded_data(16, [0; 16])(input)
    }

    fn log_n(input: &[u8]) -> IResult<&[u8], u8> {
        map_res(digit1, |log_n_str| {
            let log_n_str =
                std::str::from_utf8(log_n_str).expect("digit1 only returns valid ASCII bytes");
            u8::from_str_radix(log_n_str, 10)
        })(input)
    }

    pub(crate) fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(SCRYPT_RECIPIENT_TAG),
                map(
                    separated_pair(
                        separated_pair(salt, tag(" "), log_n),
                        line_ending,
                        encoded_data(32, [0; 32]),
                    ),
                    |((salt, log_n), encrypted_file_key)| RecipientLine {
                        salt,
                        log_n,
                        encrypted_file_key,
                    },
                ),
            )(input)
        }
    }
}

pub(super) mod write {
    use cookie_factory::{
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SCRYPT_RECIPIENT_TAG),
            encoded_data(&r.salt),
            string(format!(" {}{}", r.log_n, line_ending)),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
