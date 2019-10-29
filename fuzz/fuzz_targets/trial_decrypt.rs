#![no_main]
use libfuzzer_sys::fuzz_target;

use age::Decryptor;

fuzz_target!(|data: &[u8]| {
    let decryptor = Decryptor::Keys(vec![]);
    let _ = decryptor.trial_decrypt(data);
});
