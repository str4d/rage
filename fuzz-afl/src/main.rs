#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        age::fuzz_header(data);
    });
}
