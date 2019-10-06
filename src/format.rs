//! The age message format.

const V1_MAGIC: &[u8] = b"This is a file encrypted with age-tool.com, version 1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const X25519_RECIPIENT_TAG: &[u8] = b"X25519 ";
const SCRYPT_RECIPIENT_TAG: &[u8] = b"scrypt ";
const MAC_TAG: &[u8] = b"---";

struct X25519Recipient {
    epk: [u8; 32],
    encrypted_file_key: Vec<u8>,
}

struct ScryptRecipient {
    salt: [u8; 16],
    n: usize,
    encrypted_file_key: Vec<u8>,
}

enum Recipient {
    X25519(X25519Recipient),
    Scrypt(ScryptRecipient),
}

pub struct Header {
    recipients: Vec<Recipient>,
    mac: Vec<u8>,
}

pub struct EncryptedMessage<'a> {
    header: Header,
    nonce: &'a [u8],
    payload: &'a [u8],
}

impl<'a> EncryptedMessage<'a> {
    pub fn read(data: &'a [u8]) -> Result<Self, ()> {
        let (i, header) = read::header(data).map_err(|_| ())?;

        if i.len() < 16 {
            return Err(());
        }

        let nonce = &i[..16];
        let payload = &i[16..];

        Ok(EncryptedMessage {
            header,
            nonce,
            payload,
        })
    }

    pub fn write(&self) -> Vec<u8> {
        let mut buf = vec![];
        cookie_factory::gen(write::header(&self.header), &mut buf).unwrap();
        buf.extend_from_slice(self.nonce);
        buf.extend_from_slice(self.payload);
        buf
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::complete::{tag, take},
        character::complete::{digit1, newline},
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
            // TODO handle newlines
            let (i, data) = take(encoded_count)(input)?;

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

    fn x25519_recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        let (i, (epk, encrypted_file_key)) = preceded(
            tag(X25519_RECIPIENT_TAG),
            separated_pair(x25519_epk, newline, encoded_data(32)),
        )(input)?;

        Ok((
            i,
            Recipient::X25519(X25519Recipient {
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

    fn scrypt_n(input: &[u8]) -> IResult<&[u8], usize> {
        let (i, n_str) = digit1(input)?;

        // digit1 will only return valid ASCII bytes
        let n_str = std::str::from_utf8(n_str).unwrap();

        match usize::from_str_radix(n_str, 10) {
            Ok(n) => Ok((i, n)),
            Err(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Digit))),
        }
    }

    fn scrypt_recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        let (i, ((salt, n), encrypted_file_key)) = preceded(
            tag(SCRYPT_RECIPIENT_TAG),
            separated_pair(
                separated_pair(scrypt_salt, tag(" "), scrypt_n),
                newline,
                encoded_data(32),
            ),
        )(input)?;

        Ok((
            i,
            Recipient::Scrypt(ScryptRecipient {
                salt,
                n,
                encrypted_file_key,
            }),
        ))
    }

    fn recipient(input: &[u8]) -> IResult<&[u8], Recipient> {
        preceded(
            tag(RECIPIENT_TAG),
            alt((x25519_recipient, scrypt_recipient)),
        )(input)
    }

    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        let (i, _) = terminated(tag(V1_MAGIC), newline)(input)?;
        let (i, recipients) = terminated(separated_nonempty_list(newline, recipient), newline)(i)?;
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

    fn x25519_recipient<W: Write>(r: &X25519Recipient) -> impl SerializeFn<W> {
        tuple((
            slice(X25519_RECIPIENT_TAG),
            encoded_data(&r.epk),
            string("\n"),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn scrypt_recipient<W: Write>(r: &ScryptRecipient) -> impl SerializeFn<W> {
        tuple((
            slice(SCRYPT_RECIPIENT_TAG),
            encoded_data(&r.salt),
            string(format!(" {}\n", r.n)),
            encoded_data(&r.encrypted_file_key),
        ))
    }

    fn recipient<'a, W: 'a + Write>(r: &'a Recipient) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                Recipient::X25519(r) => x25519_recipient(r)(out),
                Recipient::Scrypt(r) => scrypt_recipient(r)(out),
            }
        }
    }

    pub(super) fn header_minus_mac<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(V1_MAGIC),
            string("\n"),
            separated_list(string("\n"), h.recipients.iter().map(recipient)),
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
    use super::EncryptedMessage;

    #[test]
    fn message_parsing() {
        let test_msg = "This is a file encrypted with age-tool.com, version 1
-> X25519 CJM36AHmTbdHSuOQL-NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz-uPRyI0eQsWw7LWbbYig
-> X25519 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
N3pgrXkbIn_RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
-> scrypt bBjlhJVYZeE4aqUdmtRHfw 32768
ZV_AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
--- fgMiVLJHMlg9fW7CVG_hPS5EAU4Zeg19LyCP7SoH5nA
[BINARY ENCRYPTED PAYLOAD]
";
        let msg = EncryptedMessage::read(test_msg.as_bytes()).unwrap();
        assert_eq!(std::str::from_utf8(&msg.write()), Ok(test_msg));
    }
}
