use x25519_dalek::PublicKey;

const X25519_RECIPIENT_TAG: &[u8] = b"X25519 ";

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) epk: PublicKey,
    pub(crate) encrypted_file_key: [u8; 32],
}

pub(super) mod read {
    use nom::{
        bytes::streaming::tag,
        combinator::map,
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    pub(crate) fn epk(input: &[u8]) -> IResult<&[u8], PublicKey> {
        map(encoded_data(32, [0; 32]), PublicKey::from)(input)
    }

    pub(crate) fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(X25519_RECIPIENT_TAG),
                map(
                    separated_pair(epk, line_ending, encoded_data(32, [0; 32])),
                    |(epk, encrypted_file_key)| RecipientLine {
                        epk,
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
            slice(X25519_RECIPIENT_TAG),
            encoded_data(r.epk.as_bytes()),
            string(line_ending),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
