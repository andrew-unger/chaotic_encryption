/// CML-Sponge reduced-round keystream dump for PractRand testing.
///
/// Usage: cml_rr_dump <rounds> [seed_index]
///   rounds:     1–8 (number of CML rounds per permutation)
///   seed_index: 0–255 (default 0)
///
/// Example: cml_rr_dump 1 | RNG_test stdin64
use std::env;
use std::io::{self, Write, BufWriter};

use au79_crypto::cml_sponge::{cipher_init_r, keystream_r};

fn main() {
    let args: Vec<String> = env::args().collect();
    let rounds: usize = if args.len() > 1 { args[1].parse().unwrap_or(8) } else { 8 };
    let seed_index: u8 = if args.len() > 2 { args[2].parse().unwrap_or(0) } else { 0 };

    let mut seed_material = b"cml-sponge.rr.eval.v1".to_vec();
    seed_material.push(seed_index);
    seed_material.push(rounds as u8);
    let key = blake3::derive_key("cml-sponge.rr.key.v1", &seed_material);
    let iv = [seed_index; 16];

    let mut state = cipher_init_r(&key, &iv, rounds);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock());

    let mut buf = [0u8; 8192];
    loop {
        keystream_r(&mut state, &mut buf, rounds);
        if out.write_all(&buf).is_err() {
            break;
        }
    }
}
