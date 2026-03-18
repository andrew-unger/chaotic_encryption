/// Dumps raw CML-Sponge keystream bytes to stdout for statistical testing.
///
/// Usage:
///   cml_keystream_dump [seed_index]       (seed_index: 0-255, default 0)
///   cml_keystream_dump | RNG_test stdin64
///   cml_keystream_dump 5 | RNG_test stdin64 -tlmax 16GB
///
/// Outputs an infinite stream of bytes from the CML-Sponge cipher seeded with
/// a deterministic test key derived via BLAKE3. Different seed indices produce
/// independent, non-overlapping streams.
use std::env;
use std::io::{self, Write, BufWriter};

use au79_crypto::cml_sponge::{cipher_init, keystream};

fn main() {
    let args: Vec<String> = env::args().collect();
    let seed_index: u8 = if args.len() > 1 {
        args[1].parse().unwrap_or(0)
    } else {
        0
    };

    // Derive a deterministic 32-byte key from the seed index using BLAKE3.
    let mut seed_material = b"cml-sponge statistical evaluation seed v1".to_vec();
    seed_material.push(seed_index);
    let key = blake3::derive_key("cml-sponge.practrand.test.key.v1", &seed_material);
    let iv = [0u8; 16];

    let mut state = cipher_init(&key, &iv);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock()); // 64 KB buffer

    let mut buf = [0u8; 8192];
    loop {
        keystream(&mut state, &mut buf);
        if out.write_all(&buf).is_err() {
            break; // Pipe closed (PractRand finished)
        }
    }
}
