#![no_main]
use libfuzzer_sys::fuzz_target;

use std::iter;

use age::Decryptor;

fuzz_target!(|data: &[u8]| {
    if let Ok(decryptor) = Decryptor::new(data) {
        match decryptor {
            Decryptor::Recipients(d) => {
                let _ = d.decrypt(iter::empty());
            }
            // Don't pay the cost of scrypt while fuzzing.
            Decryptor::Passphrase(_) => (),
        }
    }
});
