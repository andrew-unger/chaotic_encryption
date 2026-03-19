/// Dumps raw CML-Sponge keystream bytes to stdout for statistical testing.
///
/// Usage:
///   cml_keystream_dump [seed_index]
///   cml_keystream_dump | RNG_test stdin64
///   cml_keystream_dump 5 | RNG_test stdin64 -tlmax 256GB
///
/// Seed modes:
///   seed 0–253  : random-looking key AND IV both derived from the seed index.
///                 Each seed produces an independent stream — use these to test
///                 multiple (key, IV) pairs.
///   seed 254    : all-zero key (0x00…00), all-zero IV — tests degenerate inputs.
///   seed 255    : all-FF key (0xFF…FF), all-FF IV — tests the other extreme.
///
/// Key/IV derivation for seeds 0–253:
///   key = BLAKE3("cml-sponge.practrand.key.v2",  seed_material)
///   iv  = BLAKE3("cml-sponge.practrand.iv.v2",   seed_material)[0..16]
/// where seed_material = "cml-sponge statistical evaluation seed v2" ++ [seed_index].
use std::env;
use std::io::{self, Write, BufWriter};

use catwalk::cml_sponge::{cipher_init, keystream};

fn main() {
    let args: Vec<String> = env::args().collect();
    let seed_index: u8 = if args.len() > 1 {
        args[1].parse().unwrap_or(0)
    } else {
        0
    };

    let (key, iv): ([u8; 32], [u8; 16]) = match seed_index {
        254 => ([0x00u8; 32], [0x00u8; 16]),
        255 => ([0xFFu8; 32], [0xFFu8; 16]),
        idx => {
            let mut seed_material = b"cml-sponge statistical evaluation seed v2".to_vec();
            seed_material.push(idx);
            let key = blake3::derive_key("cml-sponge.practrand.key.v2", &seed_material);
            // Derive IV from the same seed with a distinct context string.
            let iv_full = blake3::derive_key("cml-sponge.practrand.iv.v2", &seed_material);
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_full[..16]);
            (key, iv)
        }
    };

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
