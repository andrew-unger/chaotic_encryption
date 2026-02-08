/// Dumps raw chaotic keystream bytes to stdout for statistical testing.
///
/// Usage:
///   keystream_dump | RNG_test stdin        (PractRand)
///   keystream_dump | dieharder -a -g 200   (dieharder)
///
/// Outputs an infinite stream of bytes from ChaoticKeystream seeded with
/// a fixed test key. The stream is deterministic and reproducible.
use std::io::{self, Write, BufWriter};

use au79_crypto::chaos::ChaoticKeystream;

fn main() {
    // Deterministic test key derived from a fixed string via BLAKE3
    let key = blake3::derive_key("au79-crypto.practrand.test.key", b"chaotic keystream statistical evaluation seed");
    let nonce = [0u8; 16];

    let mut ks = ChaoticKeystream::new(&key, &nonce);
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock()); // 64 KB buffer

    let mut buf = [0u8; 8192];
    loop {
        for chunk in buf.chunks_exact_mut(8) {
            let val = ks.next_u64();
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        if out.write_all(&buf).is_err() {
            break; // Pipe closed (PractRand finished)
        }
    }
}
