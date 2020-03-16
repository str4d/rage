#![no_main]
use libfuzzer_sys::fuzz_target;

use age::Decryptor;

fuzz_target!(|data: &[u8]| {
    if let Ok(decryptor) = Decryptor::new(data) {
        match decryptor {
            Decryptor::Recipients(d) => {
                let _ = d.decrypt(&[]);
            }
            // Don't pay the cost of scrypt while fuzzing.
            Decryptor::Passphrase(_) => ()
        }
    }
});
