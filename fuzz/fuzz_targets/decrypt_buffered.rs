#![no_main]
use libfuzzer_sys::fuzz_target;

use std::iter;

use age::Decryptor;

fuzz_target!(|data: &[u8]| {
    if let Ok(decryptor) = Decryptor::new_buffered(data) {
        let _ = decryptor.decrypt(iter::empty());
    }
});
