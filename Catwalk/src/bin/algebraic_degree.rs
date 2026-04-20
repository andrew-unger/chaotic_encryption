//! Algebraic degree measurement for the CATWALK CML-Sponge permutation.
//!
//! Implements three complementary methods to estimate the algebraic degree
//! (over GF(2)) of each output bit as a function of the 1024-bit input,
//! for round counts 1 through 8.
//!
//! # Methods
//!
//! 1. **BLR-style linearity test** — measures Prob[f(x) ⊕ f(y) = f(x ⊕ y)]
//!    over random x, y.  A linear function scores 1.0; a random Boolean
//!    function scores 0.5.
//!
//! 2. **Stochastic divided difference** — computes the d-th order divided
//!    difference Δ^d f(x; v_1, …, v_d) for increasing d until it vanishes
//!    with high probability.  If deg(f) < d then Δ^d ≡ 0; if deg(f) ≥ d
//!    then Δ^d ≠ 0 with probability ≥ 1/2.
//!
//! 3. **Random subspace ANF** — project the 1024-bit input onto a random
//!    k-dimensional subspace, compute the exact ANF via Möbius transform
//!    (O(k · 2^k)), and report the degree of the projected function.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --bin algebraic_degree
//! ```

use catwalk::cml_sponge::permute_raw;

// ── SplitMix64 PRNG ───────────────────────────────────────────────────────

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Generate a random lattice (16 × u64).
    fn random_lattice(&mut self) -> [u64; 16] {
        let mut lat = [0u64; 16];
        for w in lat.iter_mut() {
            *w = self.next_u64();
        }
        lat
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Apply the permutation to a lattice copy and return the output lattice.
fn permute(input: &[u64; 16], rounds: usize) -> [u64; 16] {
    let mut lat = *input;
    let mut ctr = 0u64;
    permute_raw(&mut lat, &mut ctr, rounds);
    lat
}

/// Extract bit `bit_idx` (0..1024) from a 16×u64 lattice.
/// bit_idx = word * 64 + bit_within_word.
#[inline]
fn get_bit(lat: &[u64; 16], bit_idx: usize) -> u64 {
    let word = bit_idx / 64;
    let bit = bit_idx % 64;
    (lat[word] >> bit) & 1
}

/// XOR two lattices element-wise.
fn xor_lattice(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

// ── Method 1: BLR linearity test ─────────────────────────────────────────

/// For each output bit, estimate Prob[f(x) ⊕ f(y) = f(x ⊕ y)].
/// Returns the average linearity bias across all 1024 output bits.
fn blr_linearity_test(rounds: usize, n_samples: usize) -> (f64, f64, f64, f64, f64) {
    let mut rng = SplitMix64::new(rounds as u64 * 1000 + 42);
    let mut linear_count = [0u64; 1024];

    for _ in 0..n_samples {
        let x = rng.random_lattice();
        let y = rng.random_lattice();
        let xy = xor_lattice(&x, &y);

        let fx = permute(&x, rounds);
        let fy = permute(&y, rounds);
        let fxy = permute(&xy, rounds);

        for (bit, count) in linear_count.iter_mut().enumerate() {
            let lhs = get_bit(&fx, bit) ^ get_bit(&fy, bit);
            let rhs = get_bit(&fxy, bit);
            if lhs == rhs {
                *count += 1;
            }
        }
    }

    let biases: Vec<f64> = linear_count
        .iter()
        .map(|&c| c as f64 / n_samples as f64)
        .collect();

    let avg = biases.iter().sum::<f64>() / 1024.0;
    let min = biases.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = biases.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // Also compute average for low bits (bit 0 of each word) vs high bits (bit 63).
    let avg_bit0: f64 = (0..16).map(|w| biases[w * 64]).sum::<f64>() / 16.0;
    let avg_bit63: f64 = (0..16).map(|w| biases[w * 64 + 63]).sum::<f64>() / 16.0;

    (avg, min, max, avg_bit0, avg_bit63)
}

// ── Method 2: Stochastic divided difference ──────────────────────────────

/// Compute the d-th order divided difference for a single output bit:
///   Δ^d f(x; v_1, ..., v_d) = XOR_{S ⊆ {1..d}} f(x ⊕ XOR_{i ∈ S} v_i)
///
/// Returns 1 if non-zero, 0 if zero.
fn divided_difference(
    base: &[u64; 16],
    directions: &[[u64; 16]],
    rounds: usize,
    bit_idx: usize,
) -> u64 {
    let d = directions.len();
    assert!(d <= 20, "d too large (2^d evaluations)");
    let n_subsets = 1u32 << d;
    let mut acc = 0u64;

    for mask in 0..n_subsets {
        let mut point = *base;
        for (j, dir) in directions.iter().enumerate() {
            if (mask >> j) & 1 == 1 {
                for i in 0..16 {
                    point[i] ^= dir[i];
                }
            }
        }
        let out = permute(&point, rounds);
        acc ^= get_bit(&out, bit_idx);
    }
    acc
}

/// Estimate the algebraic degree for a given round count using the
/// stochastic divided difference method.
///
/// For each candidate degree d (from max down to 1), test N_TRIALS random
/// (base, directions) tuples.  If Δ^d is non-zero for at least one trial
/// on at least one output bit, we know deg ≥ d.
///
/// Returns the estimated lower bound on degree.
fn stochastic_degree_estimate(rounds: usize, max_d: usize, n_trials: usize) -> usize {
    let mut rng = SplitMix64::new(rounds as u64 * 7777 + 123);

    // Sample output bits across different positions within words to capture
    // carry propagation effects.  Bit 0 of a word never sees carries from
    // wrapping addition, so high-degree behavior only appears in upper bits.
    let sample_bits: Vec<usize> = (0..16)
        .flat_map(|w| [0, 15, 31, 47, 63].iter().map(move |&b| w * 64 + b))
        .collect(); // 80 bits: 5 positions per word × 16 words

    for d in (1..=max_d).rev() {
        let mut found_nonzero = false;
        for _ in 0..n_trials {
            let base = rng.random_lattice();
            let directions: Vec<[u64; 16]> = (0..d).map(|_| rng.random_lattice()).collect();

            for &bit in &sample_bits {
                if divided_difference(&base, &directions, rounds, bit) != 0 {
                    found_nonzero = true;
                    break;
                }
            }
            if found_nonzero {
                break;
            }
        }
        if found_nonzero {
            return d;
        }
    }
    0
}

// ── Method 3: Random subspace ANF ────────────────────────────────────────

/// Project the 1024-bit input onto a random k-dimensional subspace,
/// evaluate the function on all 2^k points, compute exact ANF via
/// Möbius transform, and return the degree.
fn subspace_anf_degree(rounds: usize, k: usize, bit_idx: usize, rng: &mut SplitMix64) -> usize {
    assert!(k <= 24, "k too large");

    // Generate k random direction vectors in {0,1}^1024.
    let directions: Vec<[u64; 16]> = (0..k).map(|_| rng.random_lattice()).collect();

    // Choose a random base point.
    let base = rng.random_lattice();

    // Evaluate f on all 2^k points in the affine subspace base ⊕ span(directions).
    let n = 1usize << k;
    let mut truth_table = vec![0u64; n];

    for (mask, entry) in truth_table.iter_mut().enumerate() {
        let mut point = base;
        for (j, dir) in directions.iter().enumerate() {
            if (mask >> j) & 1 == 1 {
                for i in 0..16 {
                    point[i] ^= dir[i];
                }
            }
        }
        let out = permute(&point, rounds);
        *entry = get_bit(&out, bit_idx);
    }

    // Möbius transform (ANF computation): in-place butterfly.
    // After transform, truth_table[mask] = a_mask (the ANF coefficient for monomial x^mask).
    let mut anf = truth_table;
    for i in 0..k {
        let step = 1 << i;
        for j in 0..n {
            if j & step != 0 {
                anf[j] ^= anf[j ^ step];
            }
        }
    }

    // Degree = max Hamming weight of any mask with non-zero ANF coefficient.
    let mut max_deg = 0;
    for (mask, &coeff) in anf.iter().enumerate() {
        if coeff != 0 {
            let hw = mask.count_ones() as usize;
            if hw > max_deg {
                max_deg = hw;
            }
        }
    }
    max_deg
}

/// Run subspace ANF over multiple output bits and random subspaces,
/// return (avg_degree, max_degree).
fn subspace_anf_sweep(
    rounds: usize,
    k: usize,
    n_bits: usize,
    n_projections: usize,
) -> (f64, usize) {
    let mut rng = SplitMix64::new(rounds as u64 * 9999 + k as u64);
    let mut max_deg = 0usize;
    let mut sum_deg = 0usize;
    let mut count = 0usize;

    // Sample output bits across different bit positions within words.
    // Include bit 0 (no carries), bit 31 (mid), and bit 63 (max carries)
    // to capture the full range of algebraic degree behavior.
    let bits: Vec<usize> = (0..4)
        .flat_map(|w| [0, 31, 63].iter().map(move |&b| w * 64 + b))
        .collect(); // 12 bits across 4 words
    let _ = n_bits; // use fixed sampling strategy instead

    for &bit in &bits {
        for _ in 0..n_projections {
            let deg = subspace_anf_degree(rounds, k, bit, &mut rng);
            if deg > max_deg {
                max_deg = deg;
            }
            sum_deg += deg;
            count += 1;
        }
    }

    (sum_deg as f64 / count as f64, max_deg)
}

// ── Main ──────────────────────────────────────────────────────────────────

fn main() {
    println!("==========================================================");
    println!("  CATWALK v9 — Algebraic Degree Analysis");
    println!("  CML-Sponge permutation (raw, no Mix13 finalizer)");
    println!("==========================================================");
    println!();

    // ── Phase 1: BLR linearity test ──────────────────────────────────
    println!("Phase 1: BLR Linearity Test");
    println!("  (Prob[f(x) XOR f(y) = f(x XOR y)]; linear = 1.0, random = 0.5)");
    println!();
    println!("  Rounds |   Avg   |   Min   |   Max   | Bit0 avg | Bit63 avg | Interpretation");
    println!("  -------|---------|---------|---------|----------|-----------|---------------");

    let blr_samples = 10_000;

    for rounds in 1..=8 {
        let (avg, min, max, avg_bit0, avg_bit63) = blr_linearity_test(rounds, blr_samples);
        let interp = if avg > 0.99 {
            "~linear (deg ≤ 1)"
        } else if avg > 0.75 {
            "low degree"
        } else if avg > 0.55 {
            "moderate degree"
        } else {
            "high degree (~random)"
        };
        println!(
            "       {} |  {:.4} |  {:.4} |  {:.4} |   {:.4}  |    {:.4}  | {}",
            rounds, avg, min, max, avg_bit0, avg_bit63, interp
        );
    }
    println!();

    // ── Phase 2: Stochastic divided difference ───────────────────────
    println!("Phase 2: Stochastic Divided Difference");
    println!("  (Lower bound on algebraic degree; d such that Δ^d ≠ 0)");
    println!();

    let dd_max_d = 18;
    let dd_trials = 20;

    println!("  Rounds | Degree ≥ | Note");
    println!("  -------|----------|-----");

    for rounds in 1..=8 {
        let deg = stochastic_degree_estimate(rounds, dd_max_d, dd_trials);
        let note = if deg >= dd_max_d {
            format!("(hit ceiling d={})", dd_max_d)
        } else if deg >= 10 {
            "high degree".to_string()
        } else {
            "low/moderate".to_string()
        };
        println!("       {} |       {:>2} | {}", rounds, deg, note);
    }
    println!();

    // ── Phase 3: Random subspace ANF ─────────────────────────────────
    println!("Phase 3: Random Subspace ANF (exact Möbius transform)");
    println!();

    for k in [20, 22] {
        println!("  Subspace dimension k = {}", k);
        println!("  Rounds |  Avg deg | Max deg");
        println!("  -------|----------|--------");

        let n_bits = 16;
        let n_proj = 4;

        for rounds in 1..=8 {
            let (avg, max_d) = subspace_anf_sweep(rounds, k, n_bits, n_proj);
            println!("       {} |    {:5.1} |     {:>2}", rounds, avg, max_d);
        }
        println!();
    }

    // ── Summary ──────────────────────────────────────────────────────
    println!("==========================================================");
    println!("  Analysis complete.");
    println!("  See docs/algebraic_degree_analysis.md for interpretation.");
    println!("==========================================================");
}
