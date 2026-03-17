/// Multi-seed statistical validation.
///
/// Tests 50 different seeds with 1 MB each to catch weak key classes
/// without requiring PractRand. Run with: cargo test --release --test multi_seed_statistical -- --nocapture

use au79_crypto::chaos::ChaoticKeystream;

const SEED_COUNT: usize = 50;
const SAMPLE_SIZE: usize = 1_000_000; // 1 MB per seed

fn generate_keystream(seed_index: u8) -> Vec<u8> {
    let mut seed_material = b"au79-crypto.ci.multi-seed.v5".to_vec();
    seed_material.push(seed_index);

    let key = blake3::derive_key("au79-crypto.multi-seed.test.v5", &seed_material);
    let nonce = [0u8; 16];
    let mut ks = ChaoticKeystream::new(&key, &nonce);

    let mut data = vec![0u8; SAMPLE_SIZE];
    ks.apply_keystream(&mut data);
    data
}

// ── Byte Frequency (Chi-Squared) across 50 seeds ─────────────────────────────

#[test]
fn multi_seed_byte_frequency() {
    println!("Testing {} seeds (byte frequency chi-squared)", SEED_COUNT);
    let mut failures = Vec::new();

    for seed_idx in 0..SEED_COUNT {
        let data = generate_keystream(seed_idx as u8);

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

        // 255 df, ~4σ bounds (Bonferroni-safe for 50 simultaneous tests)
        let pass = chi_sq > 175.0 && chi_sq < 350.0;
        if !pass {
            failures.push((seed_idx, chi_sq));
        }
        println!("  Seed {:3}: chi-sq = {:7.2} {}", seed_idx, chi_sq, if pass { "PASS" } else { "FAIL" });
    }

    assert!(
        failures.is_empty(),
        "FAIL: {} seeds failed byte frequency: {:?}", failures.len(), failures
    );
}

// ── Monobit across 50 seeds ──────────────────────────────────────────────────

#[test]
fn multi_seed_monobit() {
    println!("Testing {} seeds (monobit)", SEED_COUNT);
    let mut failures = Vec::new();

    for seed_idx in 0..SEED_COUNT {
        let data = generate_keystream(seed_idx as u8);
        let total_bits = (SAMPLE_SIZE * 8) as f64;
        let ones: u64 = data.iter().map(|&b| b.count_ones() as u64).sum();
        let z = (ones as f64 - total_bits / 2.0) / (total_bits / 4.0).sqrt();

        let pass = z.abs() < 4.0;
        if !pass {
            failures.push((seed_idx, z));
        }
        println!("  Seed {:3}: z = {:7.4} {}", seed_idx, z, if pass { "PASS" } else { "FAIL" });
    }

    assert!(
        failures.is_empty(),
        "FAIL: {} seeds failed monobit: {:?}", failures.len(), failures
    );
}

// ── Serial Correlation across 50 seeds ───────────────────────────────────────

#[test]
fn multi_seed_serial_correlation() {
    println!("Testing {} seeds (serial correlation)", SEED_COUNT);
    let mut failures = Vec::new();

    for seed_idx in 0..SEED_COUNT {
        let data = generate_keystream(seed_idx as u8);
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
        // 4σ Bonferroni-corrected bound for 50 simultaneous tests.
        // σ = 1/sqrt(1_000_000) = 0.001; 4σ = 0.004.
        // Using 2σ = 0.002 produces ~2.5 expected failures across 50 seeds
        // purely from sampling variance — the same bound used by other tests here.
        let pass = correlation.abs() < 0.004;

        if !pass {
            failures.push((seed_idx, correlation));
        }
        println!("  Seed {:3}: r = {:8.6} {}", seed_idx, correlation, if pass { "PASS" } else { "FAIL" });
    }

    assert!(
        failures.is_empty(),
        "FAIL: {} seeds failed serial correlation: {:?}", failures.len(), failures
    );
}
