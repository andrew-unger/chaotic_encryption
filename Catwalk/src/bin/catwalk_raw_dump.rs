//! Dumps raw CML-Sponge permutation output (pre-Mix13) to stdout for PractRand.
//!
//! This binary tests the intrinsic statistical quality of the CML-Sponge
//! permutation BEFORE the Stafford Mix13 output finalizer is applied.
//!
//! The standard squeeze path applies Mix13 to each rate word before output:
//!   output[i] = stafford_mix13(state.lattice[i])
//!
//! This binary bypasses Mix13 and outputs the raw rate words:
//!   output[i] = state.lattice[i]
//!
//! This answers whether Mix13 is defense-in-depth (permutation already strong)
//! or load-bearing (masking permutation weaknesses).
//!
//! Usage (seed mode — matches cml_keystream_dump key derivation):
//!   catwalk_raw_dump [seed_index]
//!   catwalk_raw_dump 0   | RNG_test stdin64 -tlmax 32GB
//!   catwalk_raw_dump 254 | RNG_test stdin64 -tlmax 32GB
//!
//! Usage (explicit key/IV mode):
//!   catwalk_raw_dump --key <64-hex-chars> --iv <32-hex-chars>
//!
//! Seed modes (same as cml_keystream_dump):
//!   Seeds 0–3: BLAKE3-derived key AND IV.
//!   Seed 254:  All-zero degenerate (key = [0x00; 32], iv = [0x00; 16]).
//!   Seed 255:  All-ones degenerate (key = [0xFF; 32], iv = [0xFF; 16]).

use std::env;
use std::io::{self, BufWriter, Write};
use std::process;

use catwalk::cml_sponge::{cipher_init, cml_permute_r, raw_rate_bytes};

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn usage() {
    eprintln!("Usage: catwalk_raw_dump [seed_index]");
    eprintln!("       catwalk_raw_dump --key <64-hex-chars> --iv <32-hex-chars>");
    eprintln!();
    eprintln!("Dumps raw CML-Sponge permutation output (pre-Mix13) for PractRand.");
    eprintln!();
    eprintln!("Seed mode examples:");
    eprintln!("  catwalk_raw_dump 0   | RNG_test stdin64 -tlmax 32GB");
    eprintln!("  catwalk_raw_dump 254 | RNG_test stdin64 -tlmax 32GB");
    eprintln!();
    eprintln!("Explicit key/IV example:");
    eprintln!("  catwalk_raw_dump \\");
    eprintln!("    --key 0000000000000000000000000000000000000000000000000000000000000000 \\");
    eprintln!("    --iv 00000000000000000000000000000000 | RNG_test stdin64 -tlmax 32GB");
}

fn derive_key_iv(seed_index: u8) -> ([u8; 32], [u8; 16]) {
    match seed_index {
        254 => ([0x00u8; 32], [0x00u8; 16]),
        255 => ([0xFFu8; 32], [0xFFu8; 16]),
        128 => ([0x80u8; 32], [0x80u8; 16]),
        64 => {
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            for (i, b) in key.iter_mut().enumerate() {
                *b = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            for (i, b) in iv.iter_mut().enumerate() {
                *b = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            (key, iv)
        }
        idx => {
            let mut seed_material = b"catwalk v10 practrand validation".to_vec();
            seed_material.push(idx);
            let key = blake3::derive_key("catwalk.v10.practrand.key", &seed_material);
            let iv_full = blake3::derive_key("catwalk.v10.practrand.iv", &seed_material);
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_full[..16]);
            (key, iv)
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Determine mode: seed index (positional) or --key/--iv (flags).
    let (key, iv) = if args.len() == 2 && !args[1].starts_with('-') {
        // Seed mode: catwalk_raw_dump <seed_index>
        let seed_index: u8 = match args[1].parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("Error: invalid seed index '{}'", args[1]);
                usage();
                process::exit(1);
            }
        };
        derive_key_iv(seed_index)
    } else if args.len() == 1 {
        // Default: seed 0
        derive_key_iv(0)
    } else {
        // Flag mode: --key <hex> --iv <hex>
        let mut key_hex: Option<&str> = None;
        let mut iv_hex: Option<&str> = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--key" => {
                    if i + 1 < args.len() {
                        key_hex = Some(&args[i + 1]);
                        i += 2;
                    } else {
                        eprintln!("Error: --key requires a value");
                        usage();
                        process::exit(1);
                    }
                }
                "--iv" => {
                    if i + 1 < args.len() {
                        iv_hex = Some(&args[i + 1]);
                        i += 2;
                    } else {
                        eprintln!("Error: --iv requires a value");
                        usage();
                        process::exit(1);
                    }
                }
                _ => {
                    eprintln!("Error: unknown argument '{}'", args[i]);
                    usage();
                    process::exit(1);
                }
            }
        }

        let key_hex = match key_hex {
            Some(k) => k,
            None => {
                eprintln!("Error: --key is required in flag mode");
                usage();
                process::exit(1);
            }
        };

        let iv_hex = match iv_hex {
            Some(v) => v,
            None => {
                eprintln!("Error: --iv is required in flag mode");
                usage();
                process::exit(1);
            }
        };

        let key_bytes = match parse_hex(key_hex) {
            Some(b) if b.len() == 32 => b,
            _ => {
                eprintln!("Error: --key must be exactly 64 hex characters (32 bytes)");
                process::exit(1);
            }
        };

        let iv_bytes = match parse_hex(iv_hex) {
            Some(b) if b.len() == 16 => b,
            _ => {
                eprintln!("Error: --iv must be exactly 32 hex characters (16 bytes)");
                process::exit(1);
            }
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_bytes);
        (key, iv)
    };

    // Initialize sponge state using the standard cipher_init path
    // (absorb key with DOMAIN_KEY, absorb IV with DOMAIN_IV).
    // This matches cml_keystream_dump's initialization exactly.
    let mut state = cipher_init(&key, &iv);

    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock()); // 64 KB buffer

    // Output loop: permute → dump raw rate words → repeat.
    //
    // The standard squeeze_block does:
    //   1. Read rate words through Mix13 → output
    //   2. Permute state
    //
    // We do:
    //   1. Permute state
    //   2. Read raw rate words (sites 0–7) → output (NO Mix13)
    //
    // The first permutation call here advances the state from its
    // post-init position, matching the squeeze_block cadence (which
    // also permutes once per 64-byte output block).
    let mut buf = [0u8; 64];
    loop {
        // Run full 8-round permutation.
        cml_permute_r(&mut state, 8);

        // Output raw rate bytes (sites 0–7) as little-endian u64 values.
        // NO Mix13 applied — this is the raw permutation output.
        raw_rate_bytes(&state, &mut buf);

        if out.write_all(&buf).is_err() {
            break; // Pipe closed (PractRand finished)
        }
    }
}
