//! The age message format.

use std::io::{self, Read, Write};

use crate::primitives::HmacWriter;

const V1_MAGIC: &[u8] = b"This is a file encrypted with age-tool.com, version 1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const X25519_RECIPIENT_TAG: &[u8] = b"X25519 ";
const SCRYPT_RECIPIENT_TAG: &[u8] = b"scrypt ";
const SSH_RSA_RECIPIENT_TAG: &[u8] = b"ssh-rsa ";
const SSH_ED25519_RECIPIENT_TAG: &[u8] = b"ssh-ed25519 ";
const MAC_TAG: &[u8] = b"---";

#[derive(Debug)]
pub(crate) struct X25519RecipientLine {
    pub(crate) epk: [u8; 32],
    pub(crate) encrypted_file_key: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ScryptRecipientLine {
    pub(crate) salt: [u8; 16],
    pub(crate) log_n: u8,
    pub(crate) encrypted_file_key: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct SshRsaRecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) encrypted_file_key: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct SshEd25519RecipientLine {
    pub(crate) tag: [u8; 4],
    pub(crate) rest: X25519RecipientLine,
}

#[derive(Debug)]
pub(crate) enum RecipientLine {
    X25519(X25519RecipientLine),
    Scrypt(ScryptRecipientLine),
    SshRsa(SshRsaRecipientLine),
    SshEd25519(SshEd25519RecipientLine),
}

impl RecipientLine {
    pub(crate) fn x25519(epk: [u8; 32], encrypted_file_key: Vec<u8>) -> Self {
        RecipientLine::X25519(X25519RecipientLine {
            epk,
            encrypted_file_key,
        })
    }
    pub(crate) fn scrypt(salt: [u8; 16], log_n: u8, encrypted_file_key: Vec<u8>) -> Self {
        RecipientLine::Scrypt(ScryptRecipientLine {
            salt,
            log_n,
            encrypted_file_key,
        })
    }
}

pub struct Header {
    pub(crate) recipients: Vec<RecipientLine>,
    pub(crate) mac: Vec<u8>,
}

impl Header {
    pub(crate) fn new(recipients: Vec<RecipientLine>, mac_key: [u8; 32]) -> Self {
        let mut header = Header {
            recipients,
            mac: vec![],
        };

        let mut mac = HmacWriter::new(&mac_key);
        cookie_factory::gen(write::header_minus_mac(&header), &mut mac).unwrap();
        header.mac.extend_from_slice(mac.result().code().as_slice());

        header
    }

    pub(crate) fn verify_mac(&self, mac_key: [u8; 32]) -> Option<()> {
        let mut mac = HmacWriter::new(&mac_key);
        cookie_factory::gen(write::header_minus_mac(self), &mut mac).unwrap();
        mac.verify(&self.mac).ok()
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

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take, take_while_m_n},
        character::streaming::{digit1, newline},
        error::{make_error, ErrorKind},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, separated_pair, terminated},
        IResult,
    };

    use super::*;

    fn encoded_data(count: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<u8>> {
        // Unpadded encoded length
        let encoded_count = ((4 * count) + 2) / 3;

        move |input: &[u8]| {
            // take() returns the total number of bytes it needs, not the
            // additional number of bytes like other APIs.
            let (i, data) = take(encoded_count)(input).map_err(|e| match e {
                nom::Err::Incomplete(nom::Needed::Size(n)) if n == encoded_count => {
                    nom::Err::Incomplete(nom::Needed::Size(encoded_count - input.len()))
                }
                e => e,
            })?;

            match base64::decode_config(data, base64::URL_SAFE_NO_PAD) {
                Ok(decoded) => Ok((i, decoded)),
                Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
            }
        }
    }

    fn x25519_epk(input: &[u8]) -> IResult<&[u8], [u8; 32]> {
        let (i, epk_vec) = encoded_data(32)(input)?;

        let mut epk = [0; 32];
        epk.copy_from_slice(&epk_vec);

        Ok((i, epk))
    }

    fn x25519_recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        let (i, (epk, encrypted_file_key)) = preceded(
            tag(X25519_RECIPIENT_TAG),
            separated_pair(x25519_epk, newline, encoded_data(32)),
        )(input)?;

        Ok((
            i,
            RecipientLine::X25519(X25519RecipientLine {
                epk,
                encrypted_file_key,
            }),
        ))
    }

    fn scrypt_salt(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
        let (i, salt_vec) = encoded_data(16)(input)?;

        let mut salt = [0; 16];
        salt.copy_from_slice(&salt_vec);

        Ok((i, salt))
    }

    fn scrypt_log_n(input: &[u8]) -> IResult<&[u8], u8> {
        let (i, log_n_str) = digit1(input)?;

        // digit1 will only return valid ASCII bytes
        let log_n_str = std::str::from_utf8(log_n_str).unwrap();

        match u8::from_str_radix(log_n_str, 10) {
            Ok(n) => Ok((i, n)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Digit))),
        }
    }

    fn scrypt_recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        let (i, ((salt, log_n), encrypted_file_key)) = preceded(
            tag(SCRYPT_RECIPIENT_TAG),
            separated_pair(
                separated_pair(scrypt_salt, tag(" "), scrypt_log_n),
                newline,
                encoded_data(32),
            ),
        )(input)?;

        Ok((
            i,
            RecipientLine::Scrypt(ScryptRecipientLine {
                salt,
                log_n,
                encrypted_file_key,
            }),
        ))
    }

    fn ssh_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        let (i, tag_vec) = encoded_data(4)(input)?;

        let mut tag = [0; 4];
        tag.copy_from_slice(&tag_vec);

        Ok((i, tag))
    }

    fn ssh_rsa_body(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        // We are reading 57-character lines, but if we set m = 57 then the
        // parser will speculatively read 57 character chunks, even if there are
        // fewer than 57 characters remaining in the header (which is the case
        // if an ssh-rsa recipient line is last in the header). Instead, set
        // m = 32 so we read enough to check we are definitely on a line, but
        // not enough to overflow the header.
        let (i, chunks) = separated_nonempty_list(
            newline,
            take_while_m_n(32usize, 57usize, |c| {
                base64::decode_config_slice(&[c, c, c, c], base64::URL_SAFE_NO_PAD, &mut [0, 0, 0])
                    .is_ok()
            }),
        )(input)?;
        let data: Vec<u8> = chunks.into_iter().flatten().cloned().collect();

        match base64::decode_config(&data, base64::URL_SAFE_NO_PAD) {
            Ok(decoded) => Ok((i, decoded)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Eof))),
        }
    }

    fn ssh_rsa_recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        let (i, (tag, encrypted_file_key)) = preceded(
            tag(SSH_RSA_RECIPIENT_TAG),
            separated_pair(ssh_tag, newline, ssh_rsa_body),
        )(input)?;

        Ok((
            i,
            RecipientLine::SshRsa(SshRsaRecipientLine {
                tag,
                encrypted_file_key,
            }),
        ))
    }

    fn ssh_ed25519_recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        let (i, ((tag, epk), encrypted_file_key)) = preceded(
            tag(SSH_ED25519_RECIPIENT_TAG),
            separated_pair(
                separated_pair(ssh_tag, tag(" "), x25519_epk),
                newline,
                encoded_data(32),
            ),
        )(input)?;

        Ok((
            i,
            RecipientLine::SshEd25519(SshEd25519RecipientLine {
                tag,
                rest: X25519RecipientLine {
                    epk,
                    encrypted_file_key,
                },
            }),
        ))
    }

    fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(RECIPIENT_TAG),
            alt((
                x25519_recipient_line,
                scrypt_recipient_line,
                ssh_rsa_recipient_line,
                ssh_ed25519_recipient_line,
            )),
        )(input)
    }

    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        let (i, _) = terminated(tag(V1_MAGIC), newline)(input)?;
        let (i, recipients) =
            terminated(separated_nonempty_list(newline, recipient_line), newline)(i)?;
        let (i, mac) = terminated(
            preceded(pair(tag(MAC_TAG), tag(b" ")), encoded_data(32)),
            newline,
        )(i)?;

        Ok((i, Header { recipients, mac }))
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

    fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);
        string(encoded)
    }

    fn x25519_recipient_line<W: Write>(r: &X25519RecipientLine) -> impl SerializeFn<W> {
        tuple((
            slice(X25519_RECIPIENT_TAG),
            encoded_data(&r.epk),
            string("\n"),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn scrypt_recipient_line<W: Write>(r: &ScryptRecipientLine) -> impl SerializeFn<W> {
        tuple((
            slice(SCRYPT_RECIPIENT_TAG),
            encoded_data(&r.salt),
            string(format!(" {}\n", r.log_n)),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn ssh_rsa_body<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);

        move |mut w: WriteContext<W>| {
            let mut s = encoded.as_str();

            while !s.is_empty() {
                let (l, r) = s.split_at(57);
                w = string(l)(w)?;
                if !r.is_empty() {
                    w = string("\n")(w)?;
                }
                s = r;
            }

            Ok(w)
        }
    }

    fn ssh_rsa_recipient_line<W: Write>(r: &SshRsaRecipientLine) -> impl SerializeFn<W> {
        tuple((
            slice(SSH_RSA_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string("\n"),
            ssh_rsa_body(&r.encrypted_file_key),
        ))
    }

    fn ssh_ed25519_recipient_line<W: Write>(r: &SshEd25519RecipientLine) -> impl SerializeFn<W> {
        tuple((
            slice(SSH_ED25519_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(" "),
            encoded_data(&r.rest.epk),
            string("\n"),
            encoded_data(&r.rest.encrypted_file_key),
        ))
    }

    fn recipient_line<'a, W: 'a + Write>(r: &'a RecipientLine) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientLine::X25519(r) => x25519_recipient_line(r)(out),
                RecipientLine::Scrypt(r) => scrypt_recipient_line(r)(out),
                RecipientLine::SshRsa(r) => ssh_rsa_recipient_line(r)(out),
                RecipientLine::SshEd25519(r) => ssh_ed25519_recipient_line(r)(out),
            }
        }
    }

    pub(super) fn header_minus_mac<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(V1_MAGIC),
            string("\n"),
            separated_list(string("\n"), h.recipients.iter().map(recipient_line)),
            string("\n"),
            slice(MAC_TAG),
        ))
    }

    pub(super) fn header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            header_minus_mac(h),
            string(" "),
            encoded_data(&h.mac),
            string("\n"),
        ))
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
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJC
RB0ErXAmgmZq7tIm5ZyY89OmqZztOgG2tEB1TZvX3Q8oXESBuFjBBQkKa
MLkaqh5GjcGRrZe5MmTXRdEyNPRl8qpystNZR1q2rEDUHSEJInVLW8Otv
QRG8P303VpjnOUU53FSBwyXxDtzxKxeloceFubn_HWGcR0mHU-1e9l39m
yQEUZjIoqFIELXvh9o6RUgYzaAI-m_uPLMQdlIkiOOdbsrE6tFesRLZNH
AYspeRKI9MJ--Xg9i7rutU34ZM-1BL6KgZfJ9FSm-GFHiVWpr1MfYCo_w
-> ssh-ed25519 BjH7FA RO-wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
51eEu5Oo2JYAG7OU4oamH03FDRP18_GnzeCrY7Z-sa8
--- fgMiVLJHMlg9fW7CVG_hPS5EAU4Zeg19LyCP7SoH5nA
";
        let h = Header::read(test_header.as_bytes()).unwrap();
        let mut data = vec![];
        h.write(&mut data).unwrap();
        assert_eq!(std::str::from_utf8(&data), Ok(test_header));
    }
}
