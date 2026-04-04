use catwalk::cml_sponge::{cipher_init, keystream};
/// PractRand feeder for the degenerate all-zero key / all-zero IV test case.
///
/// Usage:
///   cml_zero_key_dump | RNG_test stdin64 -tlmax 256GB
///
/// Tests the CML-Sponge cipher with key = 0x00…00 and IV = 0x00…00.
/// A cipher that degenerates on all-zero inputs is cryptographically weak;
/// this test verifies that CATWALK treats zero inputs as any other input.
use std::io::{self, BufWriter, Write};

fn main() {
    let key = [0x00u8; 32];
    let iv = [0x00u8; 16];
    let mut state = cipher_init(&key, &iv);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock());
    let mut buf = [0u8; 8192];
    loop {
        keystream(&mut state, &mut buf);
        if out.write_all(&buf).is_err() {
            break;
        }
    }
}
