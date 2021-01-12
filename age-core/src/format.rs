use rand::{
    distributions::{Distribution, Uniform},
    thread_rng, RngCore,
};
use secrecy::{ExposeSecret, Secret};

/// The prefix identifying an age stanza.
const STANZA_TAG: &str = "-> ";

/// The length of an age file key.
pub const FILE_KEY_BYTES: usize = 16;

/// A file key for encrypting or decrypting an age file.
pub struct FileKey(Secret<[u8; FILE_KEY_BYTES]>);

impl From<[u8; FILE_KEY_BYTES]> for FileKey {
    fn from(file_key: [u8; FILE_KEY_BYTES]) -> Self {
        FileKey(Secret::new(file_key))
    }
}

impl ExposeSecret<[u8; FILE_KEY_BYTES]> for FileKey {
    fn expose_secret(&self) -> &[u8; FILE_KEY_BYTES] {
        self.0.expose_secret()
    }
}

/// A section of the age header that encapsulates the file key as encrypted to a specific
/// recipient.
///
/// This is the reference type; see [`Stanza`] for the owned type.
#[derive(Debug)]
pub struct AgeStanza<'a> {
    /// A tag identifying this stanza type.
    pub tag: &'a str,
    /// Zero or more arguments.
    pub args: Vec<&'a str>,
    /// The body of the stanza, containing a wrapped [`FileKey`].
    pub body: Vec<u8>,
}

/// A section of the age header that encapsulates the file key as encrypted to a specific
/// recipient.
///
/// This is the owned type; see [`AgeStanza`] for the reference type.
#[derive(Debug, PartialEq)]
pub struct Stanza {
    /// A tag identifying this stanza type.
    pub tag: String,
    /// Zero or more arguments.
    pub args: Vec<String>,
    /// The body of the stanza, containing a wrapped [`FileKey`].
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

/// Creates a random recipient stanza that exercises the joint in the age v1 format.
///
/// This function is guaranteed to return a valid stanza, but makes no other guarantees
/// about the stanza's fields.
pub fn grease_the_joint() -> Stanza {
    // Generate arbitrary strings between 1 and 9 characters long.
    fn gen_arbitrary_string<R: RngCore>(rng: &mut R) -> String {
        let length = Uniform::from(1..9).sample(rng);
        Uniform::from(33..=126)
            .sample_iter(rng)
            .map(char::from)
            .take(length)
            .collect()
    }

    let mut rng = thread_rng();

    // Add a suffix to the random tag so users know what is going on.
    let tag = format!("{}-grease", gen_arbitrary_string(&mut rng));

    // Between this and the above generation bounds, the first line of the recipient
    // stanza will be between eight and 66 characters.
    let args = (0..Uniform::from(0..5).sample(&mut rng))
        .map(|_| gen_arbitrary_string(&mut rng))
        .collect();

    // A length between 0 and 100 bytes exercises the following stanza bodies:
    // - Empty
    // - Single short-line
    // - Single full-line
    // - Two lines, second short
    // - Two lines, both full
    // - Three lines, last short
    let mut body = vec![0; Uniform::from(0..100).sample(&mut rng)];
    rng.fill_bytes(&mut body);

    Stanza { tag, args, body }
}

pub mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_while, take_while1},
        character::streaming::newline,
        combinator::{map, map_opt, opt, verify},
        multi::{many0, separated_list1},
        sequence::{pair, preceded, terminated},
        IResult,
    };

    use super::{AgeStanza, STANZA_TAG};

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
    /// - Returns Incomplete(1) if a LF is not found.
    fn take_b64_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
        verify(take_while(|c| c != b'\n'), |bytes: &[u8]| {
            // STANDARD_NO_PAD only differs from STANDARD during serialization; the base64
            // crate always allows padding during parsing. We require canonical
            // serialization, so we explicitly reject padding characters here.
            base64::decode_config(bytes, base64::STANDARD_NO_PAD).is_ok() && !bytes.contains(&b'=')
        })(input)
    }

    /// Returns the slice of input up to (but not including) the first LF
    /// character, if that slice is entirely Base64 characters
    ///
    /// # Errors
    ///
    /// - Returns Failure on an empty slice.
    /// - Returns Incomplete(1) if a LF is not found.
    fn take_b64_line1(input: &[u8]) -> IResult<&[u8], &[u8]> {
        verify(take_while1(|c| c != b'\n'), |bytes: &[u8]| {
            // STANDARD_NO_PAD only differs from STANDARD during serialization; the base64
            // crate always allows padding during parsing. We require canonical
            // serialization, so we explicitly reject padding characters here.
            base64::decode_config(bytes, base64::STANDARD_NO_PAD).is_ok() && !bytes.contains(&b'=')
        })(input)
    }

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        map_opt(
            pair(
                // Any body lines before the last MUST be full-length.
                many0(map_opt(terminated(take_b64_line, newline), |chunk| {
                    if chunk.len() != 64 {
                        None
                    } else {
                        Some(chunk)
                    }
                })),
                // Last body line MUST be short (empty if necessary).
                map_opt(terminated(take_b64_line, newline), |chunk| {
                    if chunk.len() < 64 {
                        Some(chunk)
                    } else {
                        None
                    }
                }),
            ),
            |(full_chunks, partial_chunk)| {
                let data: Vec<u8> = full_chunks
                    .into_iter()
                    .chain(Some(partial_chunk))
                    .flatten()
                    .cloned()
                    .collect();
                base64::decode_config(&data, base64::STANDARD_NO_PAD).ok()
            },
        )(input)
    }

    fn legacy_wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        map_opt(separated_list1(newline, take_b64_line1), |chunks| {
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
    ///
    /// From the age spec:
    /// ```text
    /// Each recipient stanza starts with a line beginning with -> and its type name,
    /// followed by zero or more SP-separated arguments. The type name and the arguments
    /// are arbitrary strings. Unknown recipient types are ignored. The rest of the
    /// recipient stanza is a body of canonical base64 from RFC 4648 without padding
    /// wrapped at exactly 64 columns.
    /// ```
    pub fn age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            pair(
                preceded(
                    tag(STANZA_TAG),
                    terminated(separated_list1(tag(" "), arbitrary_string), newline),
                ),
                wrapped_encoded_data,
            ),
            |(mut args, body)| {
                let tag = args.remove(0);
                AgeStanza { tag, args, body }
            },
        )(input)
    }

    fn legacy_age_stanza_inner<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            pair(
                preceded(tag(STANZA_TAG), separated_list1(tag(" "), arbitrary_string)),
                terminated(opt(preceded(newline, legacy_wrapped_encoded_data)), newline),
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

    /// Reads a age stanza, allowing the legacy encoding of an body.
    ///
    /// From the age spec:
    /// ```text
    /// Each recipient stanza starts with a line beginning with -> and its type name,
    /// followed by zero or more SP-separated arguments. The type name and the arguments
    /// are arbitrary strings. Unknown recipient types are ignored. The rest of the
    /// recipient stanza is a body of canonical base64 from RFC 4648 without padding
    /// wrapped at exactly 64 columns.
    /// ```
    ///
    /// The spec was originally unclear about how to encode a stanza body. Both age and
    /// rage implemented the encoding in a way such that a stanza with a body of length of
    /// 0 mod 64 was indistinguishable from an incomplete stanza. The spec now requires a
    /// stanza body to always be terminated with a short line (empty if necessary). This
    /// API exists to handle files that include the legacy encoding. The only known
    /// generator of 0 mod 64 bodies is [`grease_the_joint`], so this should only affect
    /// age files encrypted with beta versions of the `age` or `rage` crates.
    ///
    /// [`grease_the_joint`]: super::grease_the_joint
    pub fn legacy_age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        alt((age_stanza, legacy_age_stanza_inner))(input)
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
        combinator::string,
        multi::separated_list,
        sequence::{pair, tuple},
        SerializeFn, WriteContext,
    };
    use std::io::Write;
    use std::iter;

    use super::STANZA_TAG;

    fn wrapped_encoded_data<'a, W: 'a + Write>(data: &[u8]) -> impl SerializeFn<W> + 'a {
        let encoded = base64::encode_config(data, base64::STANDARD_NO_PAD);

        move |mut w: WriteContext<W>| {
            let mut s = encoded.as_str();

            // Write full body lines.
            while s.len() >= 64 {
                let (l, r) = s.split_at(64);
                w = pair(string(l), string("\n"))(w)?;
                s = r;
            }

            // Last body line MUST be short (empty if necessary).
            pair(string(s), string("\n"))(w)
        }
    }

    /// Writes an age stanza.
    pub fn age_stanza<'a, W: 'a + Write, S: AsRef<str>>(
        tag: &'a str,
        args: &'a [S],
        body: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        pair(
            tuple((
                string(STANZA_TAG),
                separated_list(
                    string(" "),
                    iter::once(tag)
                        .chain(args.iter().map(|s| s.as_ref()))
                        .map(string),
                ),
                string("\n"),
            )),
            wrapped_encoded_data(body),
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

        // The only body line is short, so we don't need a trailing empty line.
        let test_stanza = "-> X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
";

        let (_, stanza) = read::age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body, test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, &test_body), &mut buf)
            .unwrap();
        assert_eq!(buf, test_stanza.as_bytes());
    }

    #[test]
    fn age_stanza_with_empty_body() {
        let test_tag = "empty-body";
        let test_args = &["some", "arguments"];
        let test_body = &[];

        // The body is empty, so it is represented with an empty line.
        let test_stanza = "-> empty-body some arguments

";

        let (_, stanza) = read::age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body, test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, test_body), &mut buf)
            .unwrap();
        assert_eq!(buf, test_stanza.as_bytes());
    }

    #[test]
    fn age_stanza_with_full_body() {
        let test_tag = "full-body";
        let test_args = &["some", "arguments"];
        let test_body = base64::decode_config(
            "xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA",
            base64::STANDARD_NO_PAD,
        )
        .unwrap();

        // The body fills a complete line, so it requires a trailing empty line.
        let test_stanza = "-> full-body some arguments
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA

";

        let (_, stanza) = read::age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body, test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, &test_body), &mut buf)
            .unwrap();
        assert_eq!(buf, test_stanza.as_bytes());
    }
}
