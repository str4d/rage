//! The "tagpq" recipient type, native to age.

use std::collections::HashSet;
use std::fmt;

use age_core::{
    format::{FileKey, Stanza},
    primitives::hpke_seal,
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::{Bech32, Hrp};
use hpke::{Deserializable, Serializable};
use ml_kem::{KemCore, MlKem768};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;

use crate::{util::parse_bech32, EncryptError};

mod kem;

const RECIPIENT_PREFIX: &str = "age1tagpq";

const MLKEM768P256TAG_RECIPIENT_TAG: &str = "mlkem768p256tag";
const MLKEM768P256TAG_SALT: &str = "age-encryption.org/mlkem768p256tag";

type Kem = kem::MlKem768P256;

pub(crate) fn expand_pq_key(
    seed: &[u8; 64],
) -> (
    <MlKem768 as KemCore>::DecapsulationKey,
    <MlKem768 as KemCore>::EncapsulationKey,
) {
    let mut d = [0; 32];
    let mut z = [0; 32];
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);

    let (dk_pq, ek_pq) = MlKem768::generate_deterministic(&d.into(), &z.into());

    d.zeroize();
    z.zeroize();

    (dk_pq, ek_pq)
}

/// The hybrid post-quantum tagged age recipient type, designed for hardware keys where
/// decryption potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq)]
pub struct Recipient(<Kem as hpke::Kem>::PublicKey);

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a recipient key from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, bytes)| {
                if hrp == RECIPIENT_PREFIX {
                    <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes)
                        .map_err(|_| "invalid recipient")
                        .map(Self)
                } else {
                    Err("incorrect HRP")
                }
            })
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            bech32::encode::<Bech32>(Hrp::parse_unchecked(RECIPIENT_PREFIX), &self.0.to_bytes())
                .expect("HRP is valid")
        )
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (enc, ct) = hpke_seal::<Kem, _>(
            &self.0,
            MLKEM768P256TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut OsRng,
        );

        let ikm = enc
            .to_bytes()
            .into_iter()
            .chain(super::static_tag(
                self.0.ek_t.to_encoded_point(false).as_bytes(),
            ))
            .collect::<Vec<u8>>();
        let tag = super::stanza_tag(&ikm, MLKEM768P256TAG_SALT);

        let encoded_tag = BASE64_STANDARD_NO_PAD.encode(tag);
        let encoded_enc = BASE64_STANDARD_NO_PAD.encode(enc.to_bytes());

        Ok((
            vec![Stanza {
                tag: MLKEM768P256TAG_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_tag, encoded_enc],
                body: ct,
            }],
            super::label_pq_only(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Recipient;

    pub(crate) const TEST_RECIPIENT: &str =
        "age1tagpq1m3e4wvp6hzcrn9exhy0ae3xfx2sjymp594k3tg7j4dpmj922we65vtnmrt2pyallax8669zqkr2pmfchptr4n38kug2xmcmp3adk2lnjqu00x5kxz5pvhmrltvfh9wuq973pcx35cnq8syn9qd3tzpehgztl4xpzr3tpd67g8af9trnjpc05gh7wu536aq4qt2y8zhsm4tvrfpsfl36qs5fpzysnk3sp9w77qzeg49357xex40v4s2lvt620swyys7u8yxdcnu4rkkwxdmt55gsuc3h5c5swahnegjgqwc60hn085ec3sjztwm45l44y3j2at9t6v9zra4ek3kek6waecqm98yaxl37w0d2zra626nz63jdm5sg59w7lyptw83zm6fntd8d0x03a9z6h9prfgpygzar6zrxjcrt4cdctk2mhf95s4a6v4zklfd49xhpsaeujm57thx2x3e3hwzc86ftfhmq5mkxxz3d6r8ws24xj4qfn73eyezg2wy094e3why592pghz27ruq3vkyegrv80eftnw9wqzwgvnwyseaus0yt84fylzrpzp6x2fguxuqjmgudr8xd33qm30evdpxd3jvjg8qh4q60kyq80jgff369k7nrepdc38grd2dava520excqp0ey0x39khx8ry03yffcatgv84fsx5j49djpapedsy693zute5xv5g2ewzrlj5se7akvkc4g4vmzhputpq8eyj9wz5dz6qtn7g3cfpd95nahw4ytspan0feyye04dcylv24ege7zkaj004gjwcxqxfqu2quawa83sx452jqjn8t48czp0xspwgnmvjyhttzzy6nhq8xzkdwnvsfefkwva6asrqc93zjn4rly5gnlv93xy3uzmr39szvjnf63426qzyeyvguc4vdcquwgsxgq236afcpqz866ny4tn7ckc0umefj242rt5vtvwqzzrvfev2mpvqcufp9pqvefyv4ftyuhgausfzuaadsczeykmft5wv3frzgrcp9ztr93h478ke4t86spp2uhyjkj73mp9g92ddk2fpv7v3njzsqgwhq3789sqrgkskehn0zjscckhwftyq4vet7vrlx2hs5kd9cwnq6t0djffhh3zquh4j3p0yaj9z2rc9wykg0usqw7983rrgur9jg8rnnqypwcz2lyclnnc705fc5g3an93ps60q6mxqp85u0ewtxdjlqcks84yduft0a0g6e7naew3v9u2d08knarvajn8q3gq9pgxde3s7nx94lus48wwvw2xjm7k82tvylec2393jdsuvch2xpe77w8hpv9nvsxfsrs270njpmfvpmgyk2cffl9tjp3qqcc4dfkf5rme2dg0x7ew8g39www5smm705q5da4eqvnqwrkavtq6xje9ss38hnkglz4eddz8f5qruvqmq2ff9l22gwkv8h432rdkysy0grkul8e2fedvkyyapfxt760udcgu92m54wl9yavmj4ga3ph9r5n99cjrq6wj5v33x33fe5vkjvfwnnt40wuv2hyexc9f4ylyqv9ldqq9epd4yuv8vrsfx2qy2kqz08kqhnzspy6s0x8fa5c2xkg5y2q0rvz4vnk7rp0acg6eksc3t7cxnn8y7glkjsqja3p56uz6vvhcw55d3ysad0hvsqxpjnc7svenf2gc5xn5kyr0et2vvyruxlnpqcdpqh9pzplumy5yzjxftyzh9ujfw0jq7ee60zx2x23p0jzyh9dvmly8p9h9ysptlqu7kwnejd65dnr75a0np2fvke8xen38r57w6z3wz3mycjmmn267wwxndfh9jdps7uxtct2wwfgamkpa5ap8s96lhfjztpwcm6fguhphu38yunu2v4vz3syzrvgwtqpemkewzp766nyu6texxvjlaemnhyyqutkcy6a42vqfsz49rw5wr4gt70r4vdaasehqjg46fnyts4sthrxadfllha3avu49wsj2c4jx";

    #[test]
    fn recipient_encoding() {
        let recipient: Recipient = TEST_RECIPIENT.parse().unwrap();
        assert_eq!(recipient.to_string(), TEST_RECIPIENT);
    }
}
