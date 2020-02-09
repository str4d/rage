#![no_main]
use age_core::format::{read, write};
use cookie_factory::gen;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((leftover, stanza)) = read::age_stanza(data) {
        let mut buf = Vec::with_capacity(data.len());
        gen(
            write::age_stanza(stanza.tag, &stanza.args, &stanza.body),
            &mut buf,
        )
        .expect("can write to Vec");
        assert_eq!(buf, &data[0..data.len() - leftover.len()]);
    }
});
