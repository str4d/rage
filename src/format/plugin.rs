/// From the age spec:
/// ```text
/// Each recipient stanza starts with a line beginning with -> and its type name, followed
/// by zero or more SP-separated arguments. The type name and the arguments are arbitrary
/// strings. Unknown recipient types are ignored. The rest of the recipient stanza is a
/// body of canonical base64 from RFC 4648 without padding wrapped at exactly 64 columns.
/// ```
#[derive(Debug)]
pub(crate) struct RecipientLine {
    tag: String,
    args: Vec<String>,
    body: Vec<u8>,
}

pub(super) mod read {
    use nom::{
        bytes::streaming::tag, character::streaming::newline, combinator::map,
        multi::separated_nonempty_list, sequence::separated_pair, IResult,
    };

    use super::*;
    use crate::util::read::{arbitrary_string, wrapped_encoded_data};

    pub(crate) fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        map(
            separated_pair(
                separated_nonempty_list(tag(" "), arbitrary_string),
                newline,
                wrapped_encoded_data,
            ),
            |(strings, body)| RecipientLine {
                tag: strings[0].to_string(),
                args: strings[1..].into_iter().map(|s| s.to_string()).collect(),
                body,
            },
        )(input)
    }
}

pub(super) mod write {
    use cookie_factory::{combinator::string, multi::separated_list, sequence::tuple, SerializeFn};
    use std::io::Write;
    use std::iter;

    use super::*;
    use crate::util::write::wrapped_encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &'a RecipientLine,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            separated_list(
                string(" "),
                iter::once(&r.tag)
                    .chain(r.args.iter())
                    .map(|arg| string(arg)),
            ),
            string("\n"),
            wrapped_encoded_data(&r.body),
        ))
    }
}
