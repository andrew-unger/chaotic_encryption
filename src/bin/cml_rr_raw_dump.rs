//! CML-Sponge reduced-round RAW keystream dump (no Mix13) for PractRand.
//!
//! Like `cml_rr_dump`, but bypasses the Stafford Mix13 output finalizer.
//! This tests the raw permutation output at reduced round counts to find
//! the minimum round count at which the permutation alone passes PractRand.
//!
//! Usage: cml_rr_raw_dump <rounds> [seed_index]
//!   rounds:     1–8 (number of CML rounds per permutation)
//!   seed_index: 0–255 (default 0)
//!
//! Example: cml_rr_raw_dump 3 | RNG_test stdin64 -tlmax 4GB

use std::env;
use std::io::{self, Write, BufWriter};

use catwalk::cml_sponge::{cipher_init_r, cml_permute_r, raw_rate_bytes};

fn main() {
    let args: Vec<String> = env::args().collect();
    let rounds: usize = if args.len() > 1 { args[1].parse().unwrap_or(8) } else { 8 };
    let seed_index: u8 = if args.len() > 2 { args[2].parse().unwrap_or(0) } else { 0 };

    // Same key derivation as cml_rr_dump for comparability.
    let mut seed_material = b"cml-sponge.rr.eval.v1".to_vec();
    seed_material.push(seed_index);
    seed_material.push(rounds as u8);
    let key = blake3::derive_key("cml-sponge.rr.key.v1", &seed_material);
    let iv = [seed_index; 16];

    let mut state = cipher_init_r(&key, &iv, rounds);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock());

    let mut buf = [0u8; 64];
    loop {
        cml_permute_r(&mut state, rounds);
        raw_rate_bytes(&state, &mut buf);
        if out.write_all(&buf).is_err() {
            break;
        }
    }
}
