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
    ///
    /// Represented as the set of Base64-encoded lines for efficiency (so the caller can
    /// defer the cost of decoding until the structure containing this stanza has been
    /// fully-parsed).
    body: Vec<&'a [u8]>,
}

impl<'a> AgeStanza<'a> {
    /// Decodes and returns the body of this stanza.
    pub fn body(&self) -> Vec<u8> {
        // An AgeStanza will always contain at least one chunk.
        let (partial_chunk, full_chunks) = self.body.split_last().unwrap();

        // This is faster than collecting from a flattened iterator.
        let mut data = vec![0; full_chunks.len() * 64 + partial_chunk.len()];
        for (i, chunk) in full_chunks.iter().enumerate() {
            // These chunks are guaranteed to be full by construction.
            data[i * 64..(i + 1) * 64].copy_from_slice(chunk);
        }
        data[full_chunks.len() * 64..].copy_from_slice(partial_chunk);

        // The chunks are guaranteed to contain Base64 characters by construction.
        base64::decode_config(&data, base64::STANDARD_NO_PAD).unwrap()
    }
}

/// A section of the age header that encapsulates the file key as encrypted to a specific
/// recipient.
///
/// This is the owned type; see [`AgeStanza`] for the reference type.
#[derive(Debug, Clone, PartialEq)]
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
        let body = stanza.body();
        Stanza {
            tag: stanza.tag.to_string(),
            args: stanza.args.into_iter().map(|s| s.to_string()).collect(),
            body,
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
        bytes::streaming::{tag, take_while1, take_while_m_n},
        character::streaming::newline,
        combinator::{map, map_opt, opt},
        multi::{many_till, separated_list1},
        sequence::{pair, preceded, terminated},
        IResult,
    };

    use super::{AgeStanza, STANZA_TAG};

    fn is_base64_char(c: u8) -> bool {
        // Check against the ASCII values of the standard Base64 character set.
        match c {
            // A..=Z | a..=z | 0..=9 | + | /
            65..=90 | 97..=122 | 48..=57 | 43 | 47 => true,
            _ => false,
        }
    }

    /// From the age specification:
    /// ```text
    /// ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
    /// ```
    pub fn arbitrary_string(input: &[u8]) -> IResult<&[u8], &str> {
        map(take_while1(|c| (33..=126).contains(&c)), |bytes| {
            // Safety: ASCII bytes are valid UTF-8
            unsafe { std::str::from_utf8_unchecked(bytes) }
        })(input)
    }

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
        map(
            many_till(
                // Any body lines before the last MUST be full-length.
                terminated(take_while_m_n(64, 64, is_base64_char), newline),
                // Last body line MUST be short (empty if necessary).
                terminated(take_while_m_n(0, 63, is_base64_char), newline),
            ),
            |(full_chunks, partial_chunk): (Vec<&[u8]>, &[u8])| {
                let mut chunks = full_chunks;
                chunks.push(partial_chunk);
                chunks
            },
        )(input)
    }

    fn legacy_wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
        map_opt(
            separated_list1(newline, take_while1(is_base64_char)),
            |chunks: Vec<&[u8]>| {
                // Enforce that the only chunk allowed to be shorter than 64 characters
                // is the last chunk.
                let (partial_chunk, full_chunks) = chunks.split_last().unwrap();
                if full_chunks.iter().any(|s| s.len() != 64) || partial_chunk.len() > 64 {
                    None
                } else {
                    Some(chunks)
                }
            },
        )(input)
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
                    body: body.unwrap_or_else(|| vec![&[]]),
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
            assert!(wrapped_encoded_data(b"Tm8gcGFkZGluZyE\n").is_ok());
            assert!(wrapped_encoded_data(b"Tm8gcGFkZGluZyE=\n").is_err());
            // Internal padding is also rejected.
            assert!(wrapped_encoded_data(b"SW50ZXJuYWwUGFk\n").is_ok());
            assert!(wrapped_encoded_data(b"SW50ZXJuYWw=UGFk\n").is_err());
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
        assert_eq!(stanza.body(), test_body);

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
        assert_eq!(stanza.body(), test_body);

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
        assert_eq!(stanza.body(), test_body);

        let mut buf = vec![];
        cookie_factory::gen_simple(write::age_stanza(test_tag, test_args, &test_body), &mut buf)
            .unwrap();
        assert_eq!(buf, test_stanza.as_bytes());
    }

    #[test]
    fn age_stanza_with_legacy_full_body() {
        let test_tag = "full-body";
        let test_args = &["some", "arguments"];
        let test_body = base64::decode_config(
            "xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA",
            base64::STANDARD_NO_PAD,
        )
        .unwrap();

        // The body fills a complete line, but lacks a trailing empty line.
        let test_stanza = "-> full-body some arguments
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA
--- header end
";

        // The normal parser returns an error.
        assert!(read::age_stanza(test_stanza.as_bytes()).is_err());

        // We can parse with the legacy parser
        let (_, stanza) = read::legacy_age_stanza(test_stanza.as_bytes()).unwrap();
        assert_eq!(stanza.tag, test_tag);
        assert_eq!(stanza.args, test_args);
        assert_eq!(stanza.body(), test_body);
    }
}
