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

/// A section of the age header that encapsulates the file key as encrypted to a specific
/// recipient.
#[derive(Debug)]
pub struct Stanza {
    /// A tag identifying this stanza type.
    pub tag: String,
    /// Zero or more arguments.
    pub args: Vec<String>,
    /// The body of the stanza, containing a wrapped [`FileKey`].
    ///
    /// [`FileKey`]: crate::keys::FileKey
    pub body: Vec<u8>,
}

impl From<AgeStanza<'_>> for Stanza {
    fn from(stanza: AgeStanza<'_>) -> Self {
        Stanza {
            tag: stanza.tag.to_string(),
            args: stanza.args.into_iter().map(|s| s.to_string()).collect(),
            body: stanza.body,
        }
    }
}

pub mod read {
    use nom::{
        bytes::streaming::{tag, take_while1},
        character::streaming::newline,
        combinator::{map, map_opt, opt, verify},
        multi::separated_nonempty_list,
        sequence::{pair, preceded},
        IResult,
    };

    use super::AgeStanza;

    /// From the age specification:
    /// ```text
    /// ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
    /// ```
    pub fn arbitrary_string(input: &[u8]) -> IResult<&[u8], &str> {
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
    fn take_b64_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
        verify(take_while1(|c| c != b'\n'), |bytes: &[u8]| {
            // STANDARD_NO_PAD only differs from STANDARD during serialization; the base64
            // crate always allows padding during parsing. We require canonical
            // serialization, so we explicitly reject padding characters here.
            base64::decode_config(bytes, base64::STANDARD_NO_PAD).is_ok() && !bytes.contains(&b'=')
        })(input)
    }

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        map_opt(separated_nonempty_list(newline, take_b64_line), |chunks| {
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
        })(input)
    }

    /// Reads an age stanza.
    pub fn age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            pair(
                separated_nonempty_list(tag(" "), arbitrary_string),
                opt(preceded(newline, wrapped_encoded_data)),
            ),
            |(mut args, body)| {
                let tag = args.remove(0);
                AgeStanza {
                    tag,
                    args,
                    body: body.unwrap_or_default(),
                }
            },
        )(input)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn base64_padding_rejected() {
            assert!(take_b64_line(b"Tm8gcGFkZGluZyE\n").is_ok());
            assert!(take_b64_line(b"Tm8gcGFkZGluZyE=\n").is_err());
        }
    }
}

pub mod write {
    use cookie_factory::{
        combinator::{cond, string},
        multi::separated_list,
        sequence::pair,
        SerializeFn, WriteContext,
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
        pair(
            separated_list(
                string(" "),
                iter::once(tag).chain(args.iter().copied()).map(string),
            ),
            cond(
                !body.is_empty(),
                pair(string("\n"), wrapped_encoded_data(body)),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{read, write};

    #[test]
    fn parse_age_stanza() {
        let test_tag = "X25519";
        let test_args = &["CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20"];
        let test_body = base64::decode_config(
            "C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig",
            base64::STANDARD_NO_PAD,
        )
        .unwrap();

        // We need two newlines here so that the streaming body parser can detect the
        // end of the stanza.
        let test_stanza = "X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig

";

        let (_, stanza) = read::age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body, test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, &test_body), &mut buf)
            .unwrap();
        // write::age_stanza does not append newlines.
        assert_eq!(buf, &test_stanza.as_bytes()[..test_stanza.len() - 2]);
    }

    #[test]
    fn age_stanza_with_empty_body() {
        let test_tag = "empty-body";
        let test_args = &["some", "arguments"];
        let test_body = &[];

        // We need two newlines here so that the streaming body parser can detect the
        // end of the stanza.
        let test_stanza = "empty-body some arguments

";

        let (_, stanza) = read::age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body, test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, test_body), &mut buf)
            .unwrap();
        // write::age_stanza does not append newlines.
        assert_eq!(buf, &test_stanza.as_bytes()[..test_stanza.len() - 2]);
    }
}
