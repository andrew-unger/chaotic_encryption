use std::time::Instant;
use au79_crypto::chaos::ChaoticKeystream;

fn bench(label: &str, size_mb: usize) {
    let key = [0x42u8; 32];
    let nonce = [0x13u8; 16];
    let size = size_mb * 1024 * 1024;
    let mut data = vec![0u8; size];

    // Warm up
    let mut ks = ChaoticKeystream::new(&key, &nonce);
    ks.apply_keystream(&mut data[..4096]);

    // Measure
    let mut ks = ChaoticKeystream::new(&key, &nonce);
    let start = Instant::now();
    ks.apply_keystream(&mut data);
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    let throughput_mb = size_mb as f64 / secs;
    let throughput_gb = throughput_mb / 1024.0;
    println!("  {label}: {size_mb} MB in {secs:.3}s = {throughput_mb:.0} MB/s ({throughput_gb:.2} GB/s)");
}

fn main() {
    println!("AU79-Crypto v7 — ChaoticKeystream throughput");
    println!("Build: release, target: native");
    println!();

    bench("  64 MB", 64);
    bench( "256 MB", 256);
    bench("  1 GB", 1024);

    println!();
    println!("Reference points (typical x86-64 software implementations):");
    println!("  ChaCha20:        ~1500–3000 MB/s (without AVX-512)");
    println!("  AES-128-CTR:     ~3000–6000 MB/s (AES-NI)");
    println!("  AES-256-GCM:     ~1500–3000 MB/s (AES-NI + CLMUL)");
}
