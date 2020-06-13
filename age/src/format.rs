//! The age file format.

use rand::{
    distributions::{Distribution, Uniform},
    thread_rng, RngCore,
};
use std::io::{self, Read, Write};

use crate::primitives::HmacWriter;

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) mod plugin;
pub(crate) mod scrypt;
pub(crate) mod ssh_ed25519;
pub(crate) mod ssh_rsa;
pub(crate) mod x25519;

const AGE_MAGIC: &[u8] = b"age-encryption.org/";
const V1_MAGIC: &[u8] = b"v1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const MAC_TAG: &[u8] = b"---";

#[derive(Debug)]
pub(crate) enum RecipientStanza {
    X25519(x25519::RecipientStanza),
    Scrypt(scrypt::RecipientStanza),
    SshRsa(ssh_rsa::RecipientStanza),
    SshEd25519(ssh_ed25519::RecipientStanza),
    Plugin(plugin::RecipientStanza),
}

impl From<x25519::RecipientStanza> for RecipientStanza {
    fn from(stanza: x25519::RecipientStanza) -> Self {
        RecipientStanza::X25519(stanza)
    }
}

impl From<scrypt::RecipientStanza> for RecipientStanza {
    fn from(stanza: scrypt::RecipientStanza) -> Self {
        RecipientStanza::Scrypt(stanza)
    }
}

impl From<ssh_rsa::RecipientStanza> for RecipientStanza {
    fn from(stanza: ssh_rsa::RecipientStanza) -> Self {
        RecipientStanza::SshRsa(stanza)
    }
}

impl From<ssh_ed25519::RecipientStanza> for RecipientStanza {
    fn from(stanza: ssh_ed25519::RecipientStanza) -> Self {
        RecipientStanza::SshEd25519(stanza)
    }
}

impl From<plugin::RecipientStanza> for RecipientStanza {
    fn from(stanza: plugin::RecipientStanza) -> Self {
        RecipientStanza::Plugin(stanza)
    }
}

/// Creates a random recipient stanza that exercises the joint in the age v1 format.
pub(crate) fn oil_the_joint() -> RecipientStanza {
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

    // Add a prefix to the random tag so users know what is going on.
    let tag = format!("joint-oil-{}", gen_arbitrary_string(&mut rng));

    // Between this and the above generation bounds, the first line of the recipient
    // stanza will be between five and 69 characters.
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

    plugin::RecipientStanza { tag, args, body }.into()
}

pub struct HeaderV1 {
    pub(crate) recipients: Vec<RecipientStanza>,
    pub(crate) mac: [u8; 32],
}

impl HeaderV1 {
    fn new(recipients: Vec<RecipientStanza>, mac_key: [u8; 32]) -> Self {
        let mut header = HeaderV1 {
            recipients,
            mac: [0; 32],
        };

        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_v1_minus_mac(&header), &mut mac)
            .expect("can serialize Header into HmacWriter");
        header
            .mac
            .copy_from_slice(mac.finalize().into_bytes().as_slice());

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
    pub(crate) fn new(recipients: Vec<RecipientStanza>, mac_key: [u8; 32]) -> Self {
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

    #[cfg(feature = "async")]
    pub(crate) async fn read_async<R: AsyncRead + Unpin>(mut input: R) -> io::Result<Self> {
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
                    input.read_exact(&mut data[m..m + n]).await?;
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

pub(crate) enum Header {
    V1(HeaderV1),
    Unknown(String),
}

mod read {
    use age_core::format::read::{age_stanza, arbitrary_string};
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::streaming::newline,
        combinator::{map, map_opt},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::base64_arg;

    fn recipient_stanza(input: &[u8]) -> IResult<&[u8], RecipientStanza> {
        preceded(
            tag(RECIPIENT_TAG),
            map_opt(age_stanza, |stanza| match stanza.tag {
                x25519::X25519_RECIPIENT_TAG => {
                    x25519::RecipientStanza::from_stanza(stanza).map(RecipientStanza::X25519)
                }
                scrypt::SCRYPT_RECIPIENT_TAG => {
                    scrypt::RecipientStanza::from_stanza(stanza).map(RecipientStanza::Scrypt)
                }
                ssh_rsa::SSH_RSA_RECIPIENT_TAG => {
                    ssh_rsa::RecipientStanza::from_stanza(stanza).map(RecipientStanza::SshRsa)
                }
                ssh_ed25519::SSH_ED25519_RECIPIENT_TAG => {
                    ssh_ed25519::RecipientStanza::from_stanza(stanza)
                        .map(RecipientStanza::SshEd25519)
                }
                _ => Some(RecipientStanza::Plugin(
                    plugin::RecipientStanza::from_stanza(stanza),
                )),
            }),
        )(input)
    }

    fn header_v1(input: &[u8]) -> IResult<&[u8], HeaderV1> {
        preceded(
            pair(tag(V1_MAGIC), newline),
            map(
                pair(
                    terminated(separated_nonempty_list(newline, recipient_stanza), newline),
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
                map(terminated(arbitrary_string, newline), |s| {
                    Header::Unknown(s.to_string())
                }),
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

    fn recipient_stanza<'a, W: 'a + Write>(r: &'a RecipientStanza) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientStanza::X25519(r) => x25519::write::recipient_stanza(r)(out),
                RecipientStanza::Scrypt(r) => scrypt::write::recipient_stanza(r)(out),
                RecipientStanza::SshRsa(r) => ssh_rsa::write::recipient_stanza(r)(out),
                RecipientStanza::SshEd25519(r) => ssh_ed25519::write::recipient_stanza(r)(out),
                RecipientStanza::Plugin(r) => plugin::write::recipient_stanza(r)(out),
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
                h.recipients.iter().map(move |r| recipient_stanza(r)),
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
