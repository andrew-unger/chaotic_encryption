/// Dumps raw chaotic keystream bytes to stdout for statistical testing.
///
/// Usage:
///   keystream_dump [seed_index]       (seed_index: 0-255, default 0)
///   keystream_dump | RNG_test stdin64  (PractRand)
///   keystream_dump 5 | RNG_test stdin64 -tlmax 16GB  (multi-seed)
///
/// Outputs an infinite stream of bytes from ChaoticKeystream seeded with
/// a deterministic test key. Different seed indices produce independent streams.
use std::env;
use std::io::{self, Write, BufWriter};

use au79_crypto::chaos::ChaoticKeystream;

fn main() {
    let args: Vec<String> = env::args().collect();
    let seed_index: u8 = if args.len() > 1 {
        args[1].parse().unwrap_or(0)
    } else {
        0
    };

    let mut seed_material = b"chaotic keystream statistical evaluation seed v7".to_vec();
    seed_material.push(seed_index);

    let key = blake3::derive_key("au79-crypto.practrand.test.key.v7", &seed_material);
    let nonce = [0u8; 16];

    let mut ks = ChaoticKeystream::new(&key, &nonce);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock()); // 64 KB buffer

    let mut buf = [0u8; 8192];
    loop {
        ks.apply_keystream(&mut buf);
        if out.write_all(&buf).is_err() {
            break; // Pipe closed (PractRand finished)
        }
    }
}
