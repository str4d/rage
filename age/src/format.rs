//! The age file format.

use age_core::format::Stanza;
use std::io::{self, Read, Write};

use crate::{
    error::DecryptError,
    primitives::{HmacKey, HmacWriter},
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const AGE_MAGIC: &[u8] = b"age-encryption.org/";
const V1_MAGIC: &[u8] = b"v1";
const MAC_TAG: &[u8] = b"---";
const ENCODED_MAC_LENGTH: usize = 43;

#[derive(Debug, PartialEq)]
pub(crate) struct HeaderV1 {
    pub(crate) recipients: Vec<Stanza>,
    pub(crate) mac: [u8; 32],
    /// The serialized bytes of this header. Set if we parsed this header from a reader,
    /// to handle the possibility that the header is not round-trip canonical, such as it
    /// containing a legacy stanza with a body of length 0 mod 64.
    ///
    /// We do not write this back out in `Header::write`, because we never write headers
    /// that we have parsed, and headers we generate for writing will never have this set.
    encoded_bytes: Option<Vec<u8>>,
}

impl HeaderV1 {
    pub(crate) fn new(recipients: Vec<Stanza>, mac_key: HmacKey) -> Self {
        let mut header = HeaderV1 {
            recipients,
            mac: [0; 32],
            encoded_bytes: None,
        };

        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_v1_minus_mac(&header), &mut mac)
            .expect("can serialize Header into HmacWriter");
        header
            .mac
            .copy_from_slice(mac.finalize().into_bytes().as_slice());

        header
    }

    pub(crate) fn verify_mac(&self, mac_key: HmacKey) -> Result<(), hmac::crypto_mac::MacError> {
        let mut mac = HmacWriter::new(mac_key);
        if let Some(bytes) = &self.encoded_bytes {
            // The MAC covers all bytes up to the end of the --- prefix.
            mac.write_all(&bytes[..bytes.len() - ENCODED_MAC_LENGTH - 2])
                .expect("can serialize Header into HmacWriter");
        } else {
            cookie_factory::gen(write::header_v1_minus_mac(self), &mut mac)
                .expect("can serialize Header into HmacWriter");
        }
        mac.verify(&self.mac)
    }
}

impl Header {
    pub(crate) fn read<R: Read>(mut input: R) -> Result<Self, DecryptError> {
        let mut data = vec![];
        loop {
            match read::header(&data) {
                Ok((_, mut header)) => {
                    if let Header::V1(h) = &mut header {
                        h.encoded_bytes = Some(data);
                    }
                    break Ok(header);
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                    // Read the needed additional bytes. We need to be careful how the
                    // parser is constructed, because if we read more than we need, the
                    // remainder of the input will be truncated.
                    let m = data.len();
                    let new_len = m + n.get();
                    data.resize(new_len, 0);
                    input.read_exact(&mut data[m..new_len])?;
                }
                Err(_) => {
                    break Err(DecryptError::InvalidHeader);
                }
            }
        }
    }

    #[cfg(feature = "async")]
    pub(crate) async fn read_async<R: AsyncRead + Unpin>(
        mut input: R,
    ) -> Result<Self, DecryptError> {
        let mut data = vec![];
        loop {
            match read::header(&data) {
                Ok((_, mut header)) => {
                    if let Header::V1(h) = &mut header {
                        h.encoded_bytes = Some(data);
                    }
                    break Ok(header);
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                    // Read the needed additional bytes. We need to be careful how the
                    // parser is constructed, because if we read more than we need, the
                    // remainder of the input will be truncated.
                    let m = data.len();
                    let new_len = m + n.get();
                    data.resize(new_len, 0);
                    input.read_exact(&mut data[m..new_len]).await?;
                }
                Err(_) => {
                    break Err(DecryptError::InvalidHeader);
                }
            }
        }
    }

    pub(crate) fn write<W: Write>(&self, mut output: W) -> io::Result<()> {
        cookie_factory::gen(write::header(self), &mut output)
            .map(|_| ())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write header: {}", e),
                )
            })
    }

    #[cfg(feature = "async")]
    pub(crate) async fn write_async<W: AsyncWrite + Unpin>(&self, mut output: W) -> io::Result<()> {
        let mut buf = vec![];
        cookie_factory::gen(write::header(self), &mut buf)
            .map(|_| ())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write header: {}", e),
                )
            })?;

        output.write_all(&buf).await
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Header {
    V1(HeaderV1),
    Unknown(String),
}

mod read {
    use age_core::format::read::{arbitrary_string, legacy_age_stanza};
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::streaming::newline,
        combinator::{map, map_opt},
        multi::many1,
        sequence::{pair, preceded, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::base64_arg;

    fn recipient_stanza(input: &[u8]) -> IResult<&[u8], Stanza> {
        map(legacy_age_stanza, Stanza::from)(input)
    }

    fn header_v1(input: &[u8]) -> IResult<&[u8], HeaderV1> {
        preceded(
            pair(tag(V1_MAGIC), newline),
            map(
                pair(
                    many1(recipient_stanza),
                    preceded(
                        pair(tag(MAC_TAG), tag(b" ")),
                        terminated(
                            map_opt(take(ENCODED_MAC_LENGTH), |tag| base64_arg(&tag, [0; 32])),
                            newline,
                        ),
                    ),
                ),
                |(recipients, mac)| HeaderV1 {
                    recipients,
                    mac,
                    encoded_bytes: None,
                },
            ),
        )(input)
    }

    /// From the age specification:
    /// ```text
    /// The first line of the header is age-encryption.org/ followed by an arbitrary
    /// version string. ... We describe version v1, other versions can change anything
    /// after the first line.
    /// ```
    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        preceded(
            tag(AGE_MAGIC),
            alt((
                map(header_v1, Header::V1),
                map(terminated(arbitrary_string, newline), |s| {
                    Header::Unknown(s.to_string())
                }),
            )),
        )(input)
    }
}

mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{
        combinator::{slice, string},
        multi::all,
        sequence::tuple,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    fn recipient_stanza<'a, W: 'a + Write>(r: &'a Stanza) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let args: Vec<_> = r.args.iter().map(|s| s.as_str()).collect();
            let writer = age_stanza(&r.tag, &args, &r.body);
            writer(w)
        }
    }

    pub(super) fn header_v1_minus_mac<'a, W: 'a + Write>(
        h: &'a HeaderV1,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(AGE_MAGIC),
            slice(V1_MAGIC),
            string("\n"),
            all(h.recipients.iter().map(move |r| recipient_stanza(r))),
            slice(MAC_TAG),
        ))
    }

    fn header_v1<'a, W: 'a + Write>(h: &'a HeaderV1) -> impl SerializeFn<W> + 'a {
        tuple((
            header_v1_minus_mac(h),
            string(" "),
            encoded_data(&h.mac),
            string("\n"),
        ))
    }

    pub(super) fn header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| match h {
            Header::V1(v1) => header_v1(v1)(w),
            Header::Unknown(version) => tuple((slice(AGE_MAGIC), slice(version), string("\n")))(w),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Header;

    #[test]
    fn parse_header() {
        let test_header = "age-encryption.org/v1
-> X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
-> X25519 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
N3pgrXkbIn/RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
-> scrypt bBjlhJVYZeE4aqUdmtRHfw 15
ZV/AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
-> ssh-rsa mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA
mgmZq7tIm5ZyY89OmqZztOgG2tEB1TZvX3Q8oXESBuFjBBQkKaMLkaqh5GjcGRrZ
e5MmTXRdEyNPRl8qpystNZR1q2rEDUHSEJInVLW8OtvQRG8P303VpjnOUU53FSBw
yXxDtzxKxeloceFubn/HWGcR0mHU+1e9l39myQEUZjIoqFIELXvh9o6RUgYzaAI+
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
-> ssh-ed25519 BjH7FA RO+wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
51eEu5Oo2JYAG7OU4oamH03FDRP18/GnzeCrY7Z+sa8
-> some-empty-body-recipient BjH7FA 37 mhir0Q

-> some-full-body-recipient BjH7FA 37 mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA

-> some-other-recipient mhir0Q BjH7FA 37
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
--- fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
";
        let h = Header::read(test_header.as_bytes()).unwrap();
        let mut data = vec![];
        h.write(&mut data).unwrap();
        assert_eq!(std::str::from_utf8(&data), Ok(test_header));
    }

    #[test]
    fn parse_legacy_header() {
        let test_header = "age-encryption.org/v1
-> X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
-> some-empty-body-recipient BjH7FA 37 mhir0Q

-> some-full-body-recipient BjH7FA 37 mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA

-> some-other-recipient mhir0Q BjH7FA 37
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
--- fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
";
        let test_legacy_header = "age-encryption.org/v1
-> X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
-> some-empty-body-recipient BjH7FA 37 mhir0Q
-> some-full-body-recipient BjH7FA 37 mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA
-> some-other-recipient mhir0Q BjH7FA 37
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
--- fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
";
        let mut h = Header::read(test_header.as_bytes()).unwrap();
        let mut h_legacy = Header::read(test_legacy_header.as_bytes()).unwrap();
        // Remove the `encoded_bytes` field from both headers, which is intentionally
        // different (to ensure their MACs would validate, if these were real headers).
        match (&mut h, &mut h_legacy) {
            (Header::V1(h), Header::V1(h_legacy)) => {
                h.encoded_bytes = None;
                h_legacy.encoded_bytes = None;
            }
            _ => unreachable!(),
        }
        // The remainder of the headers should be identical.
        assert_eq!(h, h_legacy);
    }
}
