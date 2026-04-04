/// CML-Sponge throughput benchmark.
///
/// Run with: cargo run --release --bin cml_perf_test
use std::time::Instant;

use catwalk::cml_sponge::{cipher_init, keystream};

fn bench_mb(mb: usize) -> f64 {
    let key = blake3::derive_key("cml-sponge.bench.key", b"perf-test-seed-v1");
    let iv = [0u8; 16];
    let mut state = cipher_init(&key, &iv);
    let mut buf = vec![0u8; mb * 1024 * 1024];

    let t0 = Instant::now();
    keystream(&mut state, &mut buf);
    let elapsed = t0.elapsed().as_secs_f64();
    mb as f64 / elapsed
}

fn main() {
    println!("CML-Sponge cipher throughput");
    println!("Build: release, target: native\n");

    // Warm up
    bench_mb(16);

    for &mb in &[64usize, 256, 1024] {
        let mbps = bench_mb(mb);
        println!(
            "  {:>4} MB: {:>6.0} MB/s  ({:.2} GB/s)",
            mb,
            mbps,
            mbps / 1024.0
        );
    }

    println!("\nReference points (typical x86-64 software implementations):");
    println!("  ChaCha20:        ~1500–3000 MB/s (without AVX-512)");
    println!("  AES-128-CTR:     ~3000–6000 MB/s (AES-NI)");
    println!("  CATWALK v10:     ~460  MB/s  (same hardware)");
}
