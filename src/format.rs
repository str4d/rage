//! The age message format.

use std::io::{self, Read, Write};
use x25519_dalek::PublicKey;

use crate::primitives::HmacWriter;

pub(crate) mod scrypt;
pub(crate) mod x25519;

const BINARY_MAGIC: &[u8] = b"This is a file";
const ARMORED_MAGIC: &[u8] = b"This is an armored file";
const V1_MAGIC: &[u8] = b"encrypted with age-tool.com, version 1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const SSH_RSA_RECIPIENT_TAG: &[u8] = b"ssh-rsa ";
const SSH_ED25519_RECIPIENT_TAG: &[u8] = b"ssh-ed25519 ";
const MAC_TAG: &[u8] = b"---";

#[derive(Debug)]
pub(crate) struct SshRsaRecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) encrypted_file_key: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct SshEd25519RecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) rest: x25519::RecipientLine,
}

#[derive(Debug)]
pub(crate) enum RecipientLine {
    X25519(x25519::RecipientLine),
    Scrypt(scrypt::RecipientLine),
    SshRsa(SshRsaRecipientLine),
    SshEd25519(SshEd25519RecipientLine),
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

impl RecipientLine {
    pub(crate) fn ssh_rsa(tag: [u8; 4], encrypted_file_key: Vec<u8>) -> Self {
        RecipientLine::SshRsa(SshRsaRecipientLine {
            tag,
            encrypted_file_key,
        })
    }

    pub(crate) fn ssh_ed25519(tag: [u8; 4], epk: PublicKey, encrypted_file_key: [u8; 32]) -> Self {
        RecipientLine::SshEd25519(SshEd25519RecipientLine {
            tag,
            rest: x25519::RecipientLine {
                epk,
                encrypted_file_key,
            },
        })
    }
}

pub struct Header {
    pub(crate) armored: bool,
    pub(crate) recipients: Vec<RecipientLine>,
    pub(crate) mac: [u8; 32],
}

impl Header {
    pub(crate) fn new(armored: bool, recipients: Vec<RecipientLine>, mac_key: [u8; 32]) -> Self {
        let mut header = Header {
            armored,
            recipients,
            mac: [0; 32],
        };

        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::canonical_header_minus_mac(&header), &mut mac)
            .expect("can serialize Header into HmacWriter");
        header.mac.copy_from_slice(mac.result().code().as_slice());

        header
    }

    pub(crate) fn verify_mac(&self, mac_key: [u8; 32]) -> Result<(), crypto_mac::MacError> {
        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::canonical_header_minus_mac(self), &mut mac)
            .expect("can serialize Header into HmacWriter");
        mac.verify(&self.mac)
    }

    pub(crate) fn read<R: Read>(mut input: R) -> io::Result<Self> {
        let mut data = vec![];
        loop {
            match read::any_header(&data) {
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
        if self.armored {
            cookie_factory::gen(write::armored_header(self), &mut output)
        } else {
            cookie_factory::gen(write::binary_header(self), &mut output)
        }
        .map(|_| ())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to write header: {}", e),
            )
        })
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::tag,
        combinator::map,
        multi::separated_nonempty_list,
        sequence::{pair, preceded, separated_pair, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::{encoded_data, wrapped_encoded_data};

    fn ssh_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        encoded_data(4, [0; 4])(input)
    }

    fn ssh_rsa_recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(SSH_RSA_RECIPIENT_TAG),
                map(
                    separated_pair(ssh_tag, line_ending, wrapped_encoded_data(line_ending)),
                    |(tag, encrypted_file_key)| {
                        RecipientLine::SshRsa(SshRsaRecipientLine {
                            tag,
                            encrypted_file_key,
                        })
                    },
                ),
            )(input)
        }
    }

    fn ssh_ed25519_recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(SSH_ED25519_RECIPIENT_TAG),
                map(
                    separated_pair(
                        separated_pair(ssh_tag, tag(" "), x25519::read::epk),
                        line_ending,
                        encoded_data(32, [0; 32]),
                    ),
                    |((tag, epk), encrypted_file_key)| {
                        RecipientLine::SshEd25519(SshEd25519RecipientLine {
                            tag,
                            rest: x25519::RecipientLine {
                                epk,
                                encrypted_file_key,
                            },
                        })
                    },
                ),
            )(input)
        }
    }

    fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(RECIPIENT_TAG),
                alt((
                    map(
                        x25519::read::recipient_line(line_ending),
                        RecipientLine::from,
                    ),
                    map(
                        scrypt::read::recipient_line(line_ending),
                        RecipientLine::from,
                    ),
                    ssh_rsa_recipient_line(line_ending),
                    ssh_ed25519_recipient_line(line_ending),
                )),
            )(input)
        }
    }

    fn header<'a, N>(
        armored: bool,
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Header> {
        move |input: &[u8]| {
            preceded(
                pair(tag(V1_MAGIC), line_ending),
                map(
                    pair(
                        terminated(
                            separated_nonempty_list(line_ending, recipient_line(line_ending)),
                            line_ending,
                        ),
                        preceded(
                            pair(tag(MAC_TAG), tag(b" ")),
                            terminated(encoded_data(32, [0; 32]), line_ending),
                        ),
                    ),
                    |(recipients, mac)| Header {
                        armored,
                        recipients,
                        mac,
                    },
                ),
            )(input)
        }
    }

    fn canonical_header(input: &[u8]) -> IResult<&[u8], Header> {
        preceded(
            pair(tag(BINARY_MAGIC), tag(b" ")),
            header(false, &nom::character::streaming::newline),
        )(input)
    }

    fn armored_header(input: &[u8]) -> IResult<&[u8], Header> {
        preceded(
            pair(tag(ARMORED_MAGIC), tag(b" ")),
            header(true, &|input: &[u8]| {
                // line_ending returns the total number of bytes it needs, not the
                // additional number of bytes like other APIs.
                nom::character::streaming::line_ending(input).map_err(|e| match e {
                    nom::Err::Incomplete(nom::Needed::Size(n)) => {
                        nom::Err::Incomplete(nom::Needed::Size(n - input.len()))
                    }
                    e => e,
                })
            }),
        )(input)
    }

    pub(super) fn any_header(input: &[u8]) -> IResult<&[u8], Header> {
        alt((canonical_header, armored_header))(input)
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
    use crate::util::{
        write::{encoded_data, wrapped_encoded_data},
        LINE_ENDING,
    };

    fn ssh_rsa_recipient_line<'a, W: 'a + Write>(
        r: &SshRsaRecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SSH_RSA_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(line_ending),
            wrapped_encoded_data(&r.encrypted_file_key, line_ending),
        ))
    }

    fn ssh_ed25519_recipient_line<'a, W: 'a + Write>(
        r: &SshEd25519RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(SSH_ED25519_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(" "),
            encoded_data(r.rest.epk.as_bytes()),
            string(line_ending),
            encoded_data(&r.rest.encrypted_file_key),
        ))
    }

    fn recipient_line<'a, W: 'a + Write>(
        r: &'a RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientLine::X25519(r) => x25519::write::recipient_line(r, line_ending)(out),
                RecipientLine::Scrypt(r) => scrypt::write::recipient_line(r, line_ending)(out),
                RecipientLine::SshRsa(r) => ssh_rsa_recipient_line(r, line_ending)(out),
                RecipientLine::SshEd25519(r) => ssh_ed25519_recipient_line(r, line_ending)(out),
            }
        }
    }

    fn header_minus_mac<'a, W: 'a + Write>(
        h: &'a Header,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(V1_MAGIC),
            string(line_ending),
            separated_list(
                string(line_ending),
                h.recipients
                    .iter()
                    .map(move |r| recipient_line(r, line_ending)),
            ),
            string(line_ending),
            slice(MAC_TAG),
        ))
    }

    fn header<'a, W: 'a + Write>(h: &'a Header, line_ending: &'a str) -> impl SerializeFn<W> + 'a {
        tuple((
            header_minus_mac(h, line_ending),
            string(" "),
            encoded_data(&h.mac),
            string(line_ending),
        ))
    }

    pub(super) fn canonical_header_minus_mac<'a, W: 'a + Write>(
        h: &'a Header,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(if h.armored {
                ARMORED_MAGIC
            } else {
                BINARY_MAGIC
            }),
            string(" "),
            header_minus_mac(h, "\n"),
        ))
    }

    pub(super) fn binary_header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((slice(BINARY_MAGIC), string(" "), header(h, "\n")))
    }

    pub(super) fn armored_header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((slice(ARMORED_MAGIC), string(" "), header(h, LINE_ENDING)))
    }
}

#[cfg(test)]
mod tests {
    use super::Header;

    #[test]
    fn parse_header() {
        let test_header = "This is a file encrypted with age-tool.com, version 1
-> X25519 CJM36AHmTbdHSuOQL-NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz-uPRyI0eQsWw7LWbbYig
-> X25519 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
N3pgrXkbIn_RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
-> scrypt bBjlhJVYZeE4aqUdmtRHfw 15
ZV_AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
-> ssh-rsa mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJ
CRB0ErXAmgmZq7tIm5ZyY89OmqZztOgG2tEB1TZvX3Q8oXESBuFjBBQk
KaMLkaqh5GjcGRrZe5MmTXRdEyNPRl8qpystNZR1q2rEDUHSEJInVLW8
OtvQRG8P303VpjnOUU53FSBwyXxDtzxKxeloceFubn_HWGcR0mHU-1e9
l39myQEUZjIoqFIELXvh9o6RUgYzaAI-m_uPLMQdlIkiOOdbsrE6tFes
RLZNHAYspeRKI9MJ--Xg9i7rutU34ZM-1BL6KgZfJ9FSm-GFHiVWpr1M
fYCo_w
-> ssh-ed25519 BjH7FA RO-wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
51eEu5Oo2JYAG7OU4oamH03FDRP18_GnzeCrY7Z-sa8
--- fgMiVLJHMlg9fW7CVG_hPS5EAU4Zeg19LyCP7SoH5nA
";
        let h = Header::read(test_header.as_bytes()).unwrap();
        assert!(!h.armored);
        let mut data = vec![];
        h.write(&mut data).unwrap();
        assert_eq!(std::str::from_utf8(&data), Ok(test_header));
    }
}
