//! The age message format.

use std::io::{self, Read, Write};

use crate::primitives::HmacWriter;

pub(crate) mod plugin;
pub(crate) mod scrypt;
pub(crate) mod ssh_ed25519;
#[cfg(feature = "unstable")]
pub(crate) mod ssh_rsa;
pub(crate) mod x25519;

const AGE_MAGIC: &[u8] = b"age-encryption.org/";
const V1_MAGIC: &[u8] = b"v1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const MAC_TAG: &[u8] = b"---";

/// From the age spec:
/// ```text
/// Each recipient stanza starts with a line beginning with -> and its type name, followed
/// by zero or more SP-separated arguments. The type name and the arguments are arbitrary
/// strings. Unknown recipient types are ignored. The rest of the recipient stanza is a
/// body of canonical base64 from RFC 4648 without padding wrapped at exactly 64 columns.
/// ```
#[derive(Debug)]
pub(crate) struct AgeStanza<'a> {
    tag: &'a str,
    args: Vec<&'a str>,
    body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum RecipientLine {
    X25519(x25519::RecipientLine),
    Scrypt(scrypt::RecipientLine),
    #[cfg(feature = "unstable")]
    SshRsa(ssh_rsa::RecipientLine),
    SshEd25519(ssh_ed25519::RecipientLine),
    Plugin(plugin::RecipientLine),
}

impl From<x25519::RecipientLine> for RecipientLine {
    fn from(line: x25519::RecipientLine) -> Self {
        RecipientLine::X25519(line)
    }
}

impl From<scrypt::RecipientLine> for RecipientLine {
    fn from(line: scrypt::RecipientLine) -> Self {
        RecipientLine::Scrypt(line)
    }
}

#[cfg(feature = "unstable")]
impl From<ssh_rsa::RecipientLine> for RecipientLine {
    fn from(line: ssh_rsa::RecipientLine) -> Self {
        RecipientLine::SshRsa(line)
    }
}

impl From<ssh_ed25519::RecipientLine> for RecipientLine {
    fn from(line: ssh_ed25519::RecipientLine) -> Self {
        RecipientLine::SshEd25519(line)
    }
}

impl From<plugin::RecipientLine> for RecipientLine {
    fn from(line: plugin::RecipientLine) -> Self {
        RecipientLine::Plugin(line)
    }
}

pub struct HeaderV1 {
    pub(crate) recipients: Vec<RecipientLine>,
    pub(crate) mac: [u8; 32],
}

impl HeaderV1 {
    fn new(recipients: Vec<RecipientLine>, mac_key: [u8; 32]) -> Self {
        let mut header = HeaderV1 {
            recipients,
            mac: [0; 32],
        };

        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_v1_minus_mac(&header), &mut mac)
            .expect("can serialize Header into HmacWriter");
        header.mac.copy_from_slice(mac.result().code().as_slice());

        header
    }

    pub(crate) fn verify_mac(&self, mac_key: [u8; 32]) -> Result<(), hmac::crypto_mac::MacError> {
        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_v1_minus_mac(self), &mut mac)
            .expect("can serialize Header into HmacWriter");
        mac.verify(&self.mac)
    }
}

impl Header {
    pub(crate) fn new(recipients: Vec<RecipientLine>, mac_key: [u8; 32]) -> Self {
        Header::V1(HeaderV1::new(recipients, mac_key))
    }

    pub(crate) fn read<R: Read>(mut input: R) -> io::Result<Self> {
        let mut data = vec![];
        loop {
            match read::header(&data) {
                Ok((_, header)) => break Ok(header),
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                    // Read the needed additional bytes. We need to be careful how the
                    // parser is constructed, because if we read more than we need, the
                    // remainder of the input will be truncated.
                    let m = data.len();
                    data.resize(m + n, 0);
                    input.read_exact(&mut data[m..m + n])?;
                }
                Err(_) => {
                    break Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
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
}

pub(crate) enum Header {
    V1(HeaderV1),
    Unknown(String),
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::streaming::newline,
        combinator::{map, map_opt},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, separated_pair, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::{arbitrary_string, base64_arg, wrapped_encoded_data};

    fn age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            separated_pair(
                separated_nonempty_list(tag(" "), arbitrary_string),
                newline,
                wrapped_encoded_data,
            ),
            |(mut args, body)| {
                let tag = args.remove(0);
                AgeStanza { tag, args, body }
            },
        )(input)
    }

    fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(RECIPIENT_TAG),
            map_opt(age_stanza, |stanza| match stanza.tag {
                x25519::X25519_RECIPIENT_TAG => {
                    x25519::RecipientLine::from_stanza(stanza).map(RecipientLine::X25519)
                }
                scrypt::SCRYPT_RECIPIENT_TAG => {
                    scrypt::RecipientLine::from_stanza(stanza).map(RecipientLine::Scrypt)
                }
                #[cfg(feature = "unstable")]
                ssh_rsa::SSH_RSA_RECIPIENT_TAG => {
                    ssh_rsa::RecipientLine::from_stanza(stanza).map(RecipientLine::SshRsa)
                }
                ssh_ed25519::SSH_ED25519_RECIPIENT_TAG => {
                    ssh_ed25519::RecipientLine::from_stanza(stanza).map(RecipientLine::SshEd25519)
                }
                _ => Some(RecipientLine::Plugin(plugin::RecipientLine::from_stanza(
                    stanza,
                ))),
            }),
        )(input)
    }

    fn header_v1(input: &[u8]) -> IResult<&[u8], HeaderV1> {
        preceded(
            pair(tag(V1_MAGIC), newline),
            map(
                pair(
                    terminated(separated_nonempty_list(newline, recipient_line), newline),
                    preceded(
                        pair(tag(MAC_TAG), tag(b" ")),
                        terminated(
                            map_opt(take(43usize), |tag| base64_arg(&tag, [0; 32])),
                            newline,
                        ),
                    ),
                ),
                |(recipients, mac)| HeaderV1 { recipients, mac },
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
                map(arbitrary_string, |s| Header::Unknown(s.to_string())),
            )),
        )(input)
    }
}

mod write {
    use cookie_factory::{
        combinator::{slice, string},
        multi::separated_list,
        sequence::tuple,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    fn recipient_line<'a, W: 'a + Write>(r: &'a RecipientLine) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientLine::X25519(r) => x25519::write::recipient_line(r)(out),
                RecipientLine::Scrypt(r) => scrypt::write::recipient_line(r)(out),
                #[cfg(feature = "unstable")]
                RecipientLine::SshRsa(r) => ssh_rsa::write::recipient_line(r)(out),
                RecipientLine::SshEd25519(r) => ssh_ed25519::write::recipient_line(r)(out),
                RecipientLine::Plugin(r) => plugin::write::recipient_line(r)(out),
            }
        }
    }

    pub(super) fn header_v1_minus_mac<'a, W: 'a + Write>(
        h: &'a HeaderV1,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(AGE_MAGIC),
            slice(V1_MAGIC),
            string("\n"),
            separated_list(
                string("\n"),
                h.recipients.iter().map(move |r| recipient_line(r)),
            ),
            string("\n"),
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
            Header::Unknown(version) => panic!("Cannot write header for version {}", version),
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
}
