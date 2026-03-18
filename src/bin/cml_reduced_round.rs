/// CML-Sponge reduced-round distinguisher analysis.
///
/// For each round count R in 1..=8, tests whether an R-round CML-Sponge
/// keystream is statistically distinguishable from random using:
///   1. Chi-squared byte frequency (256 df, bounds 175–350 at 4σ)
///   2. Monobit test (|z| < 4.0)
///   3. Serial byte correlation (|r| < 0.004, Bonferroni-safe)
///   4. GF(2) rank of 8×8 matrices — expected full-rank fraction ~0.289;
///      checks that observed fraction is within 5σ of expected.
///
/// Run with: cargo run --release --bin cml_reduced_round

use au79_crypto::cml_sponge::{cipher_init_r, keystream_r};

const SAMPLE_BYTES: usize = 1_000_000; // 1 MB per test
const SEEDS: usize = 5;                // multiple seeds per round count

/// Expected fraction of full-rank 8×8 GF(2) matrices for uniform random data.
/// P = ∏_{k=0..7} (1 − 2^{k-8}) ≈ 0.2888
const EXPECTED_RANK8_FRAC: f64 = 0.288_788;

fn keystream_r_bytes(rounds: usize, seed: u8) -> Vec<u8> {
    let key = blake3::derive_key(
        "cml-sponge.reduced-round.analysis.v1",
        &[seed, rounds as u8],
    );
    let iv = [seed; 16];
    let mut state = cipher_init_r(&key, &iv, rounds);
    let mut out = vec![0u8; SAMPLE_BYTES];
    keystream_r(&mut state, &mut out, rounds);
    out
}

fn chi_squared(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let expected = data.len() as f64 / 256.0;
    freq.iter().map(|&f| {
        let d = f as f64 - expected;
        d * d / expected
    }).sum()
}

fn monobit_z(data: &[u8]) -> f64 {
    let total = (data.len() * 8) as f64;
    let ones: u64 = data.iter().map(|&b| b.count_ones() as u64).sum();
    (ones as f64 - total / 2.0) / (total / 4.0).sqrt()
}

fn serial_correlation(data: &[u8]) -> f64 {
    let n = data.len();
    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / n as f64;
    let mut num = 0.0f64;
    let mut den = 0.0f64;
    for i in 0..n {
        let xi = data[i] as f64 - mean;
        den += xi * xi;
        if i + 1 < n {
            num += xi * (data[i + 1] as f64 - mean);
        }
    }
    if den.abs() < 1e-10 { 0.0 } else { num / den }
}

/// GF(2) rank of an 8×8 matrix where each byte is one row.
fn gf2_rank_8x8(rows: &[u8; 8]) -> usize {
    let mut m = *rows;
    let mut rank = 0;
    for col in 0..8u8 {
        if let Some(p) = (rank..8).find(|&r| (m[r] >> col) & 1 == 1) {
            m.swap(rank, p);
            let prow = m[rank];
            for r in 0..8 {
                if r != rank && (m[r] >> col) & 1 == 1 {
                    m[r] ^= prow;
                }
            }
            rank += 1;
        }
    }
    rank
}

/// Returns (full_rank_fraction, z_score_vs_expected).
/// For uniform random data: expected fraction ≈ 0.2888.
/// σ = sqrt(p*(1-p)/n) where n = sample_bytes/8.
fn rank_test(data: &[u8]) -> (f64, f64) {
    let matrices: usize = data.len() / 8;
    let full_rank = data.chunks_exact(8)
        .filter(|c| gf2_rank_8x8(<&[u8; 8]>::try_from(*c).unwrap()) == 8)
        .count();
    let observed = full_rank as f64 / matrices as f64;
    let sigma = (EXPECTED_RANK8_FRAC * (1.0 - EXPECTED_RANK8_FRAC) / matrices as f64).sqrt();
    let z = (observed - EXPECTED_RANK8_FRAC) / sigma;
    (observed, z)
}

fn main() {
    println!("CML-Sponge Reduced-Round Distinguisher Analysis");
    println!("================================================");
    println!("Sample: {} bytes × {} seeds per round count", SAMPLE_BYTES, SEEDS);
    println!("Expected GF(2) 8×8 full-rank fraction (random): {:.4}\n", EXPECTED_RANK8_FRAC);

    println!("{:<8} {:<10} {:<10} {:<12} {:<10} {:<12} {:<8}",
        "Rounds", "ChiSq", "Monobit|z|", "SerialCorr", "Rank%", "RankZ", "Result");
    println!("{}", "-".repeat(74));

    let chi_range = 175.0..=350.0f64;
    let mono_thresh = 4.0f64;
    let serial_thresh = 0.004f64;
    let rank_z_thresh = 4.0f64;

    for rounds in 1..=8usize {
        let mut chi_vals = Vec::new();
        let mut mono_vals = Vec::new();
        let mut serial_vals = Vec::new();
        let mut rank_z_vals = Vec::new();
        let mut rank_pct_vals = Vec::new();

        for seed in 0..SEEDS {
            let data = keystream_r_bytes(rounds, seed as u8);
            chi_vals.push(chi_squared(&data));
            mono_vals.push(monobit_z(&data).abs());
            serial_vals.push(serial_correlation(&data).abs());
            let (pct, z) = rank_test(&data);
            rank_pct_vals.push(pct);
            rank_z_vals.push(z.abs());
        }

        let chi_mean = chi_vals.iter().sum::<f64>() / SEEDS as f64;
        let mono_max = mono_vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let serial_max = serial_vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let rank_pct_mean = rank_pct_vals.iter().sum::<f64>() / SEEDS as f64;
        let rank_z_max = rank_z_vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let chi_ok = chi_vals.iter().all(|&v| chi_range.contains(&v));
        let mono_ok = mono_max < mono_thresh;
        let serial_ok = serial_max < serial_thresh;
        let rank_ok = rank_z_max < rank_z_thresh;

        let pass = chi_ok && mono_ok && serial_ok && rank_ok;
        let marker = if rounds == 8 { " ← standard" } else { "" };

        println!("{:<8} {:<10.1} {:<10.4} {:<12.6} {:<10.4} {:<12.3} {:<8}{}",
            rounds,
            chi_mean,
            mono_max,
            serial_max,
            rank_pct_mean,
            rank_z_max,
            if pass { "PASS" } else { "FAIL" },
            marker,
        );
    }

    println!("\nThresholds: ChiSq 175–350 | Monobit |z|<4.0 | Serial |r|<0.004 | Rank |z|<4.0");
    println!("\nSecurity margin: number of rounds above the last failing round count.");
}
