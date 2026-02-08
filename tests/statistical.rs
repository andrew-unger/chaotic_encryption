/// Statistical tests for the chaotic keystream generator.
///
/// Implements key tests from NIST SP 800-22 and additional cipher-specific
/// tests. Run with: cargo test --release --test statistical -- --nocapture

use au79_crypto::chaos::ChaoticKeystream;

const SAMPLE_SIZE: usize = 10_000_000; // 10 MB

fn generate_keystream(seed_label: &str) -> Vec<u8> {
    let key = blake3::derive_key("au79-crypto.statistical.test", seed_label.as_bytes());
    let nonce = [0u8; 16];
    let mut ks = ChaoticKeystream::new(&key, &nonce);
    let mut data = vec![0u8; SAMPLE_SIZE];
    ks.apply_keystream(&mut data);
    data
}

// ── 1. Byte Frequency (Chi-Squared) ────────────────────────────────────────────
// Tests whether all 256 byte values appear with approximately equal frequency.
// For 10 MB of data, each byte should appear ~39062 times.
// Chi-squared with 255 degrees of freedom.

#[test]
fn byte_frequency_chi_squared() {
    let data = generate_keystream("byte_freq_test");
    let mut freq = [0u64; 256];
    for &b in &data {
        freq[b as usize] += 1;
    }
    let expected = SAMPLE_SIZE as f64 / 256.0;
    let chi_sq: f64 = freq.iter()
        .map(|&f| {
            let diff = f as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // 255 df: p=0.001 lower=198.0, p=0.999 upper=325.0
    println!("Byte frequency chi-squared: {:.2} (255 df, expect ~255, pass range [198, 325])", chi_sq);
    assert!(
        chi_sq > 198.0 && chi_sq < 325.0,
        "FAIL: chi-squared = {:.2} is outside [198, 325]", chi_sq
    );
}

// ── 2. Bit Frequency (Monobit) ─────────────────────────────────────────────────
// Tests whether the total number of 1-bits is close to 50%.

#[test]
fn bit_frequency_monobit() {
    let data = generate_keystream("monobit_test");
    let total_bits = (SAMPLE_SIZE * 8) as f64;
    let ones: u64 = data.iter().map(|&b| b.count_ones() as u64).sum();
    let proportion = ones as f64 / total_bits;

    // z-test: z = (ones - n/2) / sqrt(n/4)
    let z = (ones as f64 - total_bits / 2.0) / (total_bits / 4.0).sqrt();

    println!("Bit frequency: {:.6} (expect ~0.500000), z = {:.4}", proportion, z);
    assert!(
        z.abs() < 4.0,
        "FAIL: z-score = {:.4} (|z| > 4 indicates bias)", z
    );
}

// ── 3. Runs Test ────────────────────────────────────────────────────────────────
// Counts runs of consecutive identical bits. Too few or too many runs indicates
// non-randomness.

#[test]
fn runs_test() {
    let data = generate_keystream("runs_test");
    let n = (SAMPLE_SIZE * 8) as f64;

    // Count 1-bits and runs
    let ones: u64 = data.iter().map(|&b| b.count_ones() as u64).sum();
    let pi = ones as f64 / n;

    // Pre-test: if proportion is too far from 0.5, skip (monobit already catches this)
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        println!("Runs test: skipped (monobit pre-test failed, pi = {:.6})", pi);
        return;
    }

    // Count runs by iterating bits
    let mut runs: u64 = 1;
    let mut prev_bit = (data[0] >> 7) & 1;
    for &byte in &data {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            if bit_pos == 7 && std::ptr::eq(&byte, &data[0]) {
                continue; // skip first bit (already counted)
            }
            if bit != prev_bit {
                runs += 1;
            }
            prev_bit = bit;
        }
    }

    // Expected runs and variance
    let expected_runs = 1.0 + 2.0 * n * pi * (1.0 - pi);
    let variance = 2.0 * n * pi * (1.0 - pi) * (2.0 * pi * (1.0 - pi) - 1.0 / n);
    // Guard against negative variance from numerical issues
    if variance <= 0.0 {
        println!("Runs test: skipped (variance calculation issue)");
        return;
    }
    let z = (runs as f64 - expected_runs) / variance.sqrt();

    println!("Runs test: {} runs (expected {:.0}), z = {:.4}", runs, expected_runs, z);
    assert!(
        z.abs() < 4.0,
        "FAIL: z-score = {:.4} (|z| > 4 indicates non-random run structure)", z
    );
}

// ── 4. Serial Correlation ──────────────────────────────────────────────────────
// Measures Pearson correlation between consecutive bytes. Should be near zero.

#[test]
fn serial_correlation() {
    let data = generate_keystream("serial_corr_test");
    let n = data.len() - 1;

    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / data.len() as f64;

    let mut num = 0.0f64;
    let mut den = 0.0f64;
    for i in 0..data.len() {
        let xi = data[i] as f64 - mean;
        den += xi * xi;
        if i < n {
            let xi1 = data[i + 1] as f64 - mean;
            num += xi * xi1;
        }
    }

    let correlation = if den.abs() < 1e-10 { 0.0 } else { num / den };

    // For truly random data, |correlation| should be very small
    // With 10M samples, |r| > 0.001 would be suspicious
    println!("Serial correlation: {:.6} (expect ~0.000)", correlation);
    assert!(
        correlation.abs() < 0.002,
        "FAIL: serial correlation = {:.6} (|r| > 0.002 indicates dependence)", correlation
    );
}

// ── 5. Byte Pair (Digram) Frequency ────────────────────────────────────────────
// Tests frequency of consecutive byte pairs. 65536 possible pairs.

#[test]
fn byte_pair_frequency() {
    let data = generate_keystream("digram_test");
    let mut freq = vec![0u64; 65536];
    for pair in data.windows(2) {
        let idx = (pair[0] as usize) << 8 | pair[1] as usize;
        freq[idx] += 1;
    }

    let n_pairs = (SAMPLE_SIZE - 1) as f64;
    let expected = n_pairs / 65536.0;
    let chi_sq: f64 = freq.iter()
        .map(|&f| {
            let diff = f as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // 65535 df: mean = 65535, stddev = sqrt(2*65535) ≈ 362
    // Pass range: roughly mean ± 4*stddev = [64087, 66983]
    let z = (chi_sq - 65535.0) / (2.0 * 65535.0_f64).sqrt();
    println!("Byte pair chi-squared: {:.2} (65535 df, z = {:.4})", chi_sq, z);
    assert!(
        z.abs() < 4.0,
        "FAIL: byte pair z-score = {:.4}", z
    );
}

// ── 6. Compression Ratio ───────────────────────────────────────────────────────
// Truly random data should not be compressible. Ratio should be >= 1.0.

#[test]
fn compression_ratio() {
    use std::io::Write;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    // Use 1 MB for compression test (faster)
    let key = blake3::derive_key("au79-crypto.statistical.test", b"compression_test");
    let nonce = [0u8; 16];
    let mut ks = ChaoticKeystream::new(&key, &nonce);
    let size = 1_000_000;
    let mut data = vec![0u8; size];
    ks.apply_keystream(&mut data);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let ratio = data.len() as f64 / compressed.len() as f64;
    println!("Compression ratio: {:.4} (expect ~1.0, random data is incompressible)", ratio);
    assert!(
        ratio < 1.01,
        "FAIL: compression ratio = {:.4} (data is compressible, indicating patterns)", ratio
    );
}

// ── 7. Avalanche Test ──────────────────────────────────────────────────────────
// Flip a single bit in the key, compare keystream output. ~50% of bits should
// differ (Hamming distance ≈ 50%).

#[test]
fn avalanche_single_bit_key() {
    let key1 = blake3::derive_key("au79-crypto.statistical.test", b"avalanche_key_1");
    let mut key2 = key1;
    key2[0] ^= 1; // flip one bit

    let nonce = [0u8; 16];
    let size = 100_000; // 100 KB

    let mut ks1 = ChaoticKeystream::new(&key1, &nonce);
    let mut ks2 = ChaoticKeystream::new(&key2, &nonce);

    let mut data1 = vec![0u8; size];
    let mut data2 = vec![0u8; size];
    ks1.apply_keystream(&mut data1);
    ks2.apply_keystream(&mut data2);

    let total_bits = (size * 8) as f64;
    let differing_bits: u64 = data1.iter().zip(&data2)
        .map(|(&a, &b)| (a ^ b).count_ones() as u64)
        .sum();

    let proportion = differing_bits as f64 / total_bits;
    println!("Avalanche (key flip): {:.4}% bits differ (expect ~50%)", proportion * 100.0);
    assert!(
        (proportion - 0.5).abs() < 0.01,
        "FAIL: avalanche proportion = {:.4} (too far from 0.50)", proportion
    );
}

// ── 8. Avalanche Test (nonce) ──────────────────────────────────────────────────

#[test]
fn avalanche_single_bit_nonce() {
    let key = blake3::derive_key("au79-crypto.statistical.test", b"avalanche_nonce");
    let nonce1 = [0u8; 16];
    let mut nonce2 = nonce1;
    nonce2[0] ^= 1;

    let size = 100_000;

    let mut ks1 = ChaoticKeystream::new(&key, &nonce1);
    let mut ks2 = ChaoticKeystream::new(&key, &nonce2);

    let mut data1 = vec![0u8; size];
    let mut data2 = vec![0u8; size];
    ks1.apply_keystream(&mut data1);
    ks2.apply_keystream(&mut data2);

    let total_bits = (size * 8) as f64;
    let differing_bits: u64 = data1.iter().zip(&data2)
        .map(|(&a, &b)| (a ^ b).count_ones() as u64)
        .sum();

    let proportion = differing_bits as f64 / total_bits;
    println!("Avalanche (nonce flip): {:.4}% bits differ (expect ~50%)", proportion * 100.0);
    assert!(
        (proportion - 0.5).abs() < 0.01,
        "FAIL: avalanche proportion = {:.4} (too far from 0.50)", proportion
    );
}

// ── 9. Multiple Seeds Consistency ──────────────────────────────────────────────
// Run byte frequency on 10 different seeds to check the generator isn't just
// good for one particular seed.

#[test]
fn multi_seed_byte_frequency() {
    let mut all_pass = true;
    for i in 0..10 {
        let seed = format!("multi_seed_test_{}", i);
        let key = blake3::derive_key("au79-crypto.statistical.test", seed.as_bytes());
        let nonce = [0u8; 16];
        let mut ks = ChaoticKeystream::new(&key, &nonce);

        let size = 1_000_000; // 1 MB per seed
        let mut data = vec![0u8; size];
        ks.apply_keystream(&mut data);

        let mut freq = [0u64; 256];
        for &b in &data {
            freq[b as usize] += 1;
        }
        let expected = size as f64 / 256.0;
        let chi_sq: f64 = freq.iter()
            .map(|&f| {
                let diff = f as f64 - expected;
                diff * diff / expected
            })
            .sum();

        let pass = chi_sq > 198.0 && chi_sq < 325.0;
        println!("  Seed {}: chi-sq = {:.2} {}", i, chi_sq, if pass { "PASS" } else { "FAIL" });
        if !pass {
            all_pass = false;
        }
    }
    assert!(all_pass, "FAIL: one or more seeds failed byte frequency test");
}

// ── 10. Gap Test ───────────────────────────────────────────────────────────────
// Measures the gaps (distances) between occurrences of a specific byte value.
// The gaps should follow a geometric distribution.

#[test]
fn gap_test() {
    let data = generate_keystream("gap_test");
    let target: u8 = 42; // arbitrary byte value

    let mut gaps = Vec::new();
    let mut last_pos: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if b == target {
            if let Some(prev) = last_pos {
                gaps.push(i - prev);
            }
            last_pos = Some(i);
        }
    }

    // Expected mean gap for uniform bytes: 256
    let mean_gap: f64 = gaps.iter().map(|&g| g as f64).sum::<f64>() / gaps.len() as f64;

    println!("Gap test (byte {}): mean gap = {:.2} (expect ~256), {} gaps measured",
             target, mean_gap, gaps.len());
    assert!(
        (mean_gap - 256.0).abs() < 10.0,
        "FAIL: mean gap = {:.2} (too far from 256)", mean_gap
    );
}
