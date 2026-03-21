/// Dumps raw CML-Sponge keystream bytes to stdout for PractRand statistical testing.
///
/// Usage:
///   cml_keystream_dump [seed_index]
///   cml_keystream_dump 0   | RNG_test stdin64 -tlmax 1TB
///   cml_keystream_dump 254 | RNG_test stdin64 -tlmax 1TB
///
/// Seed modes (CATWALK v10 validation matrix):
///
///   Seeds 0–3:   BLAKE3-derived key AND IV.
///                seed_material = b"catwalk v10 practrand validation" ++ [seed_index as u8]
///                key = BLAKE3::derive_key("catwalk.v10.practrand.key", seed_material)
///                iv  = BLAKE3::derive_key("catwalk.v10.practrand.iv",  seed_material)[0..16]
///
///   Seed 64:     Alternating-bit degenerate case.
///                key = [0xAA, 0x55, 0xAA, 0x55, ...] × 16 (32 bytes)
///                iv  = [0xAA, 0x55, 0xAA, 0x55, ...] × 8  (16 bytes)
///
///   Seed 128:    High-bit degenerate case.
///                key = [0x80; 32], iv = [0x80; 16]
///
///   Seed 254:    All-zero degenerate case.
///                key = [0x00; 32], iv = [0x00; 16]
///
///   Seed 255:    All-ones degenerate case.
///                key = [0xFF; 32], iv = [0xFF; 16]
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
        128 => ([0x80u8; 32], [0x80u8; 16]),
        64  => {
            let mut key = [0u8; 32];
            let mut iv  = [0u8; 16];
            for (i, b) in key.iter_mut().enumerate() { *b = if i % 2 == 0 { 0xAA } else { 0x55 }; }
            for (i, b) in iv.iter_mut().enumerate()  { *b = if i % 2 == 0 { 0xAA } else { 0x55 }; }
            (key, iv)
        }
        idx => {
            // BLAKE3-derived key and IV for seeds 0–3 (and any other numeric seeds).
            // Context strings are version-locked to CATWALK v10 validation.
            let mut seed_material = b"catwalk v10 practrand validation".to_vec();
            seed_material.push(idx);
            let key = blake3::derive_key("catwalk.v10.practrand.key", &seed_material);
            let iv_full = blake3::derive_key("catwalk.v10.practrand.iv", &seed_material);
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
