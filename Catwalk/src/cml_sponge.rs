//! CML-Sponge: Coupled Map Lattice stream cipher with sponge construction.
//!
//! ## Design
//!
//! **State:** 16 × u64 (1024-bit) lattice + u64 Weyl counter.
//! - Rate:     sites 0–7  (512 bits) — XOR'd during absorb, read during squeeze.
//! - Capacity: sites 8–15 (512 bits) — never directly output; carries secret state.
//!
//! **Round function (4 steps, applied 8× per permutation):**
//! 1. Counter injection — Weyl counter (GOLDEN = φ×2^64) advanced and added into
//!    all 16 sites with distinct prime rotations {3,5,7,11,…,61}.  Runs before the
//!    map step to diversify site values and prevent the Cat Map's (0,0) fixed point
//!    from being reached in practice.
//! 2. Local map    — Arnold's Cat Map applied to 8 adjacent site pairs:
//!    (0,1),(2,3),…,(14,15).  Computed as a snapshot into m[].
//!    cat_map(x,y) = (x+y, x+2y) mod 2^64 — area-preserving, hyperbolic,
//!    Lyapunov exponent ln((3+√5)/2) ≈ 0.9624.
//! 3. CML coupling — `s[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16]`.
//!    Distances {1,3,7,11} (5-term) achieve full 16-site diffusion in exactly 2 rounds.
//!    p(x) = 1+x+x³+x⁷+x¹¹; p(1)=5 (odd) → C invertible over Z/2⁶⁴Z; det(C)=−33075.
//! 4. Multiplicative mixing — `s[2k+1] *= (s[2k] | 1)` for k=0..7.
//!
//! **Sponge construction (Bertoni et al.):**
//! - Absorb key  (32 bytes, domain 0x01): XOR into rate, permute.
//! - Absorb IV   (16 bytes, domain 0x02): XOR into rate, permute.
//! - Squeeze: output 64 bytes from rate, permute, repeat.
//!
//! **Cross-platform determinism:** all arithmetic is u64/u128 wrapping.
//! Canonical output is defined by the test vectors in `tests/cml_sponge_tests.rs`.

use zeroize::Zeroize;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Weyl sequence increment: fractional part of φ × 2^64.
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Number of lattice sites.
const N: usize = 16;

/// Rate portion: sites 0–7 → 64 bytes per squeeze.
const N_RATE: usize = 8;

/// Number of CML rounds per permutation.
/// Full 16-site diffusion occurs at round 2; 8 rounds gives 4× margin.
const N_ROUNDS: usize = 8;

// CML coupling distances for the 5-term polynomial p(x) = 1 + x + x³ + x⁷ + x¹¹
// are {1, 3, 7, 11}.  Together with self (distance 0) they achieve full 16-site
// diffusion in exactly 2 rounds.  They are baked as literal taps into the
// unrolled coupling in `cml_round` (Step 3); `coupling_unroll_matches_reference`
// in the tests locks that unrolling to the array formula.
//
// Selection rationale (all four distances odd and prime — nothing-up-my-sleeve):
//   1. Non-singular over ℂ: p(x) has no root among the 16th roots of unity;
//      min |λ_k| = 1.259 (+65% over the prior {1,5,11} design's 0.765).
//   2. Invertible over Z/2⁶⁴Z: p(1) = 5 (odd) → det(C) = −33075 = −3³×5²×7²
//      (odd) → gcd(33075, 2⁶⁴) = 1 → trivial kernel {0}, no capacity loss.
//      The prior 4-term {1,5,11} had det = −1088 (even): a 4-element kernel
//      and 2-bit effective capacity reduction.
//   3. Full 16-site diffusion by round 2 (symbolic simulation verified).
//   4. All distances odd → p(−1) = 1−1−1−1−1 = −3 ≠ 0.

/// Per-site counter rotation amounts: first 16 primes ≥ 3.
/// All odd, all coprime to 64, publicly verifiable as nothing-up-my-sleeve.
const ROT: [u32; 16] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 61];

/// Domain separation byte for key absorption.
const DOMAIN_KEY: u8 = 0x01;

/// Domain separation byte for IV absorption.
const DOMAIN_IV: u8 = 0x02;

/// Domain separation byte for associated data (authenticated, not encrypted).
const DOMAIN_AAD: u8 = 0x03;

/// Domain separation byte for ciphertext absorption during AEAD authentication.
const DOMAIN_CT: u8 = 0x04;

/// Domain separation byte for AEAD tag finalization.
const DOMAIN_TAG: u8 = 0x05;

/// Rate size in bytes.
const BLOCK_BYTES: usize = N_RATE * 8; // 64

// ── Local map ─────────────────────────────────────────────────────────────────

/// Arnold's Cat Map — the local nonlinear map applied to adjacent site pairs.
///
/// Implements the discrete linear toral automorphism in symplectic
/// integration order:
///
/// ```text
/// [x']   [1  1] [x]
/// [y'] = [1  2] [y]   (mod 2^64)
///
/// Computed as:
///   x' = x + y           (mod 2^64)
///   y' = x' + y          (mod 2^64)   ← uses updated x'; gives x + 2y
/// ```
///
/// ## Mathematical properties
///
/// - **Area-preserving:** det([[1,1],[1,2]]) = 2 − 1 = 1.
/// - **Hyperbolic (Anosov diffeomorphism):** eigenvalues (3 ± √5)/2 ≈ {2.618,
///   0.382} — both real, product 1, neither equal to ±1.  The map has a stable
///   and an unstable manifold filling R², giving maximum mixing.
/// - **Lyapunov exponent:** ln((3 + √5)/2) ≈ 0.9624 — the maximum achievable
///   for a 2×2 integer matrix with determinant 1 and trace 3.
/// - **No complement symmetry:** `cat_map(x, y) ≠ cat_map(MAX−x, MAX−y)` for
///   generic inputs by construction.  The Weyl counter injection still runs
///   first to diversify state.
/// - **Fixed point at (0, 0):** `cat_map(0, 0) = (0, 0)`.  This is benign in
///   practice: the Weyl counter injection (Step 1 of every CML round) runs
///   *before* the Cat Map, ensuring that any site pair reaching (0, 0) is
///   displaced by the counter before the map is applied.  The probability of a
///   site pair being exactly (0, 0) after counter injection is ≈ 2⁻¹²⁸ per
///   pair per round (two independent 64-bit coincidences required).
/// - **No parameters:** single canonical integer form — no fixed-point
///   approximation, no precision loss.
///
/// ## Pairing strategy
///
/// Applied to the 8 adjacent site pairs: (0,1), (2,3), (4,5), (6,7),
/// (8,9), (10,11), (12,13), (14,15).  This pairing matches Step 4's
/// multiplicative mixing pairs, creating a coherent two-layer nonlinear
/// transformation per pair per round before the coupling step propagates
/// results across the full 16-site lattice.
///
/// ## Constant-time guarantee
///
/// All operations are wrapping additions — no branches, no data-dependent
/// control flow, no divisions or modulo operators.  The implementation is
/// unconditionally constant-time.
#[inline(always)]
fn arnold_cat_map(x: u64, y: u64) -> (u64, u64) {
    let x_new = x.wrapping_add(y);
    let y_new = x_new.wrapping_add(y); // = x + 2y, symplectic order
    (x_new, y_new)
}

// ── CML round and permutation ──────────────────────────────────────────────

/// One CML round.  Mutates `s` and `counter` in place.
///
/// Written as fully-unrolled scalar SSA (16 named locals per stage) rather
/// than array loops with modular indexing.  This is byte-for-byte identical
/// to the array formulation — the coupling taps below are exactly
/// `m[(i+d) mod 16]` for d ∈ {0,1,3,7,11} — but it lets LLVM keep the whole
/// state in registers and schedule/CSE freely, instead of spilling the `m[]`
/// snapshot to the stack (the `m[(i+D)%N]` access pattern defeated register
/// promotion and cost ~117 stack moves per round).
#[inline(always)]
fn cml_round(s: &mut [u64; N], counter: &mut u64) {
    // Step 1 — Counter injection (all 16 sites, prime rotations).
    // Runs before the map to ensure no site pair is (0,0) when the Cat Map
    // is applied (see arnold_cat_map fixed-point note), and to diversify
    // state across sites before the nonlinear step.
    let c = counter.wrapping_add(GOLDEN);
    *counter = c;
    let a0 = s[0].wrapping_add(c.rotate_left(ROT[0]));
    let a1 = s[1].wrapping_add(c.rotate_left(ROT[1]));
    let a2 = s[2].wrapping_add(c.rotate_left(ROT[2]));
    let a3 = s[3].wrapping_add(c.rotate_left(ROT[3]));
    let a4 = s[4].wrapping_add(c.rotate_left(ROT[4]));
    let a5 = s[5].wrapping_add(c.rotate_left(ROT[5]));
    let a6 = s[6].wrapping_add(c.rotate_left(ROT[6]));
    let a7 = s[7].wrapping_add(c.rotate_left(ROT[7]));
    let a8 = s[8].wrapping_add(c.rotate_left(ROT[8]));
    let a9 = s[9].wrapping_add(c.rotate_left(ROT[9]));
    let a10 = s[10].wrapping_add(c.rotate_left(ROT[10]));
    let a11 = s[11].wrapping_add(c.rotate_left(ROT[11]));
    let a12 = s[12].wrapping_add(c.rotate_left(ROT[12]));
    let a13 = s[13].wrapping_add(c.rotate_left(ROT[13]));
    let a14 = s[14].wrapping_add(c.rotate_left(ROT[14]));
    let a15 = s[15].wrapping_add(c.rotate_left(ROT[15]));

    // Step 2 — Arnold's Cat Map on adjacent pairs (snapshot m[]).
    let (m0, m1) = arnold_cat_map(a0, a1);
    let (m2, m3) = arnold_cat_map(a2, a3);
    let (m4, m5) = arnold_cat_map(a4, a5);
    let (m6, m7) = arnold_cat_map(a6, a7);
    let (m8, m9) = arnold_cat_map(a8, a9);
    let (m10, m11) = arnold_cat_map(a10, a11);
    let (m12, m13) = arnold_cat_map(a12, a13);
    let (m14, m15) = arnold_cat_map(a14, a15);

    // Step 3 — CML additive coupling, 5-term p(x) = 1 + x + x³ + x⁷ + x¹¹.
    // o[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16].
    let o0 = m0
        .wrapping_add(m1)
        .wrapping_add(m3)
        .wrapping_add(m7)
        .wrapping_add(m11);
    let o1 = m1
        .wrapping_add(m2)
        .wrapping_add(m4)
        .wrapping_add(m8)
        .wrapping_add(m12);
    let o2 = m2
        .wrapping_add(m3)
        .wrapping_add(m5)
        .wrapping_add(m9)
        .wrapping_add(m13);
    let o3 = m3
        .wrapping_add(m4)
        .wrapping_add(m6)
        .wrapping_add(m10)
        .wrapping_add(m14);
    let o4 = m4
        .wrapping_add(m5)
        .wrapping_add(m7)
        .wrapping_add(m11)
        .wrapping_add(m15);
    let o5 = m5
        .wrapping_add(m6)
        .wrapping_add(m8)
        .wrapping_add(m12)
        .wrapping_add(m0);
    let o6 = m6
        .wrapping_add(m7)
        .wrapping_add(m9)
        .wrapping_add(m13)
        .wrapping_add(m1);
    let o7 = m7
        .wrapping_add(m8)
        .wrapping_add(m10)
        .wrapping_add(m14)
        .wrapping_add(m2);
    let o8 = m8
        .wrapping_add(m9)
        .wrapping_add(m11)
        .wrapping_add(m15)
        .wrapping_add(m3);
    let o9 = m9
        .wrapping_add(m10)
        .wrapping_add(m12)
        .wrapping_add(m0)
        .wrapping_add(m4);
    let o10 = m10
        .wrapping_add(m11)
        .wrapping_add(m13)
        .wrapping_add(m1)
        .wrapping_add(m5);
    let o11 = m11
        .wrapping_add(m12)
        .wrapping_add(m14)
        .wrapping_add(m2)
        .wrapping_add(m6);
    let o12 = m12
        .wrapping_add(m13)
        .wrapping_add(m15)
        .wrapping_add(m3)
        .wrapping_add(m7);
    let o13 = m13
        .wrapping_add(m14)
        .wrapping_add(m0)
        .wrapping_add(m4)
        .wrapping_add(m8);
    let o14 = m14
        .wrapping_add(m15)
        .wrapping_add(m1)
        .wrapping_add(m5)
        .wrapping_add(m9);
    let o15 = m15
        .wrapping_add(m0)
        .wrapping_add(m2)
        .wrapping_add(m6)
        .wrapping_add(m10);

    // Step 4 — Multiplicative mixing of adjacent pairs:
    // even site passes through; odd site *= (even | 1) (odd multiplier).
    s[0] = o0;
    s[1] = o1.wrapping_mul(o0 | 1);
    s[2] = o2;
    s[3] = o3.wrapping_mul(o2 | 1);
    s[4] = o4;
    s[5] = o5.wrapping_mul(o4 | 1);
    s[6] = o6;
    s[7] = o7.wrapping_mul(o6 | 1);
    s[8] = o8;
    s[9] = o9.wrapping_mul(o8 | 1);
    s[10] = o10;
    s[11] = o11.wrapping_mul(o10 | 1);
    s[12] = o12;
    s[13] = o13.wrapping_mul(o12 | 1);
    s[14] = o14;
    s[15] = o15.wrapping_mul(o14 | 1);
}

/// Apply N_ROUNDS of cml_round to the state.
#[inline]
fn cml_permute(state: &mut CmlSpongeState) {
    for _ in 0..N_ROUNDS {
        cml_round(&mut state.lattice, &mut state.counter);
    }
}

// ── State ────────────────────────────────────────────────────────────────────

/// CML-Sponge stream cipher state.
///
/// The lattice is split into rate (sites 0–7) and capacity (sites 8–15).
/// The capacity is never emitted; it carries hidden state between permutations,
/// providing the sponge security argument.
pub struct CmlSpongeState {
    /// 16 × u64 CML lattice.
    pub(crate) lattice: [u64; N],
    /// u64 Weyl sequence counter.
    pub(crate) counter: u64,
    /// Buffered keystream bytes not yet consumed.
    buf: [u8; BLOCK_BYTES],
    /// Read cursor into buf. Initialised to BLOCK_BYTES to signal "empty".
    buf_pos: usize,
}

impl CmlSpongeState {
    fn new() -> Self {
        Self {
            lattice: [0u64; N],
            counter: 0,
            buf: [0u8; BLOCK_BYTES],
            buf_pos: BLOCK_BYTES,
        }
    }
}

impl Drop for CmlSpongeState {
    fn drop(&mut self) {
        self.lattice.zeroize();
        self.counter.zeroize();
        self.buf.zeroize();
    }
}

// ── Absorb ────────────────────────────────────────────────────────────────────

/// XOR one 64-byte block into the rate portion (sites 0–7) then permute
/// with the supplied permutation.
fn absorb_block_with<F: FnOnce(&mut CmlSpongeState)>(
    state: &mut CmlSpongeState,
    block: &[u8; BLOCK_BYTES],
    permute: F,
) {
    for i in 0..N_RATE {
        // block is &[u8; BLOCK_BYTES] (64 bytes), i < N_RATE (8), so each
        // slice i*8..(i+1)*8 is exactly 8 bytes — try_into is infallible.
        let word = u64::from_le_bytes(
            block[i * 8..(i + 1) * 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        state.lattice[i] ^= word;
    }
    permute(state);
}

/// Absorb arbitrary-length data with Keccak-style multi-rate padding, using
/// the supplied permutation (`cml_permute` in production; a reduced-round
/// variant for cryptanalysis via [`cipher_init_r`]).
///
/// Padding: `data || domain_byte || 0x00…00 || 0x80`
/// where the total length is a multiple of BLOCK_BYTES (64).
///
/// Full input blocks are absorbed directly from `data` without copying; only
/// the final partial block — plus, when `data.len() % 64 == 63`, one extra
/// pad-only block — is staged on the stack.  This is byte-for-byte equivalent
/// to absorbing the padded message as one buffer, but performs no heap
/// allocation and leaves no unzeroized copy of secret input (the key passes
/// through here during `cipher_init`).
fn absorb_with<F: Fn(&mut CmlSpongeState)>(
    state: &mut CmlSpongeState,
    data: &[u8],
    domain: u8,
    permute: F,
) {
    let mut chunks = data.chunks_exact(BLOCK_BYTES);
    for chunk in &mut chunks {
        // chunks_exact(BLOCK_BYTES) guarantees each chunk is exactly BLOCK_BYTES bytes.
        absorb_block_with(
            state,
            chunk.try_into().unwrap_or_else(|_| unreachable!()),
            &permute,
        );
    }

    let rem = chunks.remainder();
    let mut tail = [0u8; BLOCK_BYTES];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = domain;
    if rem.len() == BLOCK_BYTES - 1 {
        // The domain byte landed in the block's last position, so the 0x80
        // terminator spills into an extra all-zero block — matching the
        // reference padding rule exactly.
        absorb_block_with(state, &tail, &permute);
        let mut terminator = [0u8; BLOCK_BYTES];
        terminator[BLOCK_BYTES - 1] = 0x80;
        absorb_block_with(state, &terminator, &permute);
    } else {
        tail[BLOCK_BYTES - 1] = 0x80;
        absorb_block_with(state, &tail, &permute);
    }
    // The tail block may hold a partial copy of secret input (e.g. key bytes).
    tail.zeroize();

    // Absorbing mutated the lattice, so any keystream still buffered from an
    // earlier squeeze predates this absorption.  Reusing it would let the start
    // of the next chunk's keystream depend on state from *before* the just-
    // absorbed ciphertext (violating the SpongeWrap chaining the AEAD relies on)
    // whenever a caller passes a chunk whose length is not a multiple of the
    // rate.  Invalidate the buffer so the next `keystream` call squeezes fresh
    // bytes from the updated state.
    state.buf_pos = BLOCK_BYTES;
}

/// Absorb with the standard full-round permutation.
fn absorb(state: &mut CmlSpongeState, data: &[u8], domain: u8) {
    absorb_with(state, data, domain, cml_permute);
}

// ── Output finalizer ──────────────────────────────────────────────────────────

/// Stafford Mix13 bijective finalizer.
///
/// Applied to each rate word before output to ensure full bit avalanche.
/// Mix13 is retained as a defense-in-depth output whitening layer.  It is
/// invertible (no entropy loss) and redistributes internal state bits
/// across all output bit positions.
/// Used by SplitMix64, Murmur3, and PCG for the same reason.
#[inline(always)]
fn stafford_mix13(x: u64) -> u64 {
    let x = x ^ (x >> 30);
    let x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    let x = x ^ (x >> 27);
    let x = x.wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

// ── Squeeze ───────────────────────────────────────────────────────────────────

/// Squeeze one 64-byte block from the rate portion using the given permutation, then advance state.
fn squeeze_block_with<F: FnOnce(&mut CmlSpongeState)>(
    state: &mut CmlSpongeState,
    permute: F,
) -> [u8; BLOCK_BYTES] {
    let mut block = [0u8; BLOCK_BYTES];
    for i in 0..N_RATE {
        let w = stafford_mix13(state.lattice[i]);
        block[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    permute(state);
    block
}

/// Core buffered-keystream loop shared by [`keystream`] and [`keystream_r`]:
/// refill the internal block buffer with the supplied permutation as needed
/// and hand each available span to `consume`.
fn keystream_spans_with<F, C>(state: &mut CmlSpongeState, total: usize, permute: F, mut consume: C)
where
    F: Fn(&mut CmlSpongeState),
    C: FnMut(usize, &[u8]),
{
    let mut pos = 0;
    while pos < total {
        if state.buf_pos >= BLOCK_BYTES {
            state.buf = squeeze_block_with(state, &permute);
            state.buf_pos = 0;
        }
        let take = (BLOCK_BYTES - state.buf_pos).min(total - pos);
        consume(pos, &state.buf[state.buf_pos..state.buf_pos + take]);
        state.buf_pos += take;
        pos += take;
    }
}

/// XOR keystream into `data` in place, advancing the state.
///
/// Equivalent to generating `data.len()` keystream bytes and XOR-ing them in,
/// but never materialises the keystream in a separate buffer — less copying,
/// and no transient keystream allocation to scrub afterwards.
fn xor_keystream(state: &mut CmlSpongeState, data: &mut [u8]) {
    let total = data.len();
    keystream_spans_with(state, total, cml_permute, |pos, ks| {
        for (d, k) in data[pos..pos + ks.len()].iter_mut().zip(ks) {
            *d ^= *k;
        }
    });
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise a `CmlSpongeState` from a 32-byte key and 16-byte IV.
///
/// Initialization sequence:
/// 1. All-zero 1024-bit state, counter = 0.
/// 2. Absorb key  (domain 0x01) → permute.
/// 3. Absorb IV   (domain 0x02) → permute.
///
/// # Nonce reuse
///
/// **Never reuse `(key, iv)` for two different messages.**  Reusing the same
/// key and IV produces the same keystream; XOR-ing two ciphertexts encrypted
/// under the same stream reveals the XOR of the plaintexts, and the authentication
/// tags no longer provide integrity.  Each encryption must use a fresh, randomly
/// generated IV (see the high-level [`crate::crypto::encrypt`] function, which
/// handles IV generation automatically).
pub fn cipher_init(key: &[u8; 32], iv: &[u8; 16]) -> CmlSpongeState {
    let mut state = CmlSpongeState::new();
    absorb(&mut state, key, DOMAIN_KEY);
    absorb(&mut state, iv, DOMAIN_IV);
    state
}

/// Fill `out` with keystream bytes, advancing the state.
///
/// Sequential calls are consistent with a single call of the total length.
pub fn keystream(state: &mut CmlSpongeState, out: &mut [u8]) {
    let total = out.len();
    keystream_spans_with(state, total, cml_permute, |pos, ks| {
        out[pos..pos + ks.len()].copy_from_slice(ks);
    });
}

/// Encrypt `plaintext` in place by XOR with keystream.
pub fn encrypt_in_place(state: &mut CmlSpongeState, data: &mut [u8]) {
    xor_keystream(state, data);
}

/// Decrypt is identical to encrypt for a stream cipher.
pub fn decrypt_in_place(state: &mut CmlSpongeState, data: &mut [u8]) {
    encrypt_in_place(state, data);
}

// ── AEAD construction (duplex, format v10) ───────────────────────────────────
//
// SpongeWrap-style duplex authenticated encryption: ONE permutation per
// 64-byte block (the retired v9 mode used two — a squeeze permutation for
// keystream plus an absorb permutation for authentication).
//
// Per 64-byte block:
//   1. keystream = Mix13(rate)        — read, no permute
//   2. ciphertext = plaintext ⊕ keystream
//   3. rate ⊕= ciphertext             — duplex injection
//   4. permute
//
// Step 3 makes the next block's keystream — and ultimately the tag — depend
// on the entire transcript so far: key, IV, AAD, and all prior ciphertext.
// Encrypt and decrypt inject the same ciphertext bytes, so both sides evolve
// identically and the final tags match iff the ciphertext was untampered.
//
// Finalisation always injects exactly one DOMAIN_CT-padded terminal block
// (carrying any pending partial-block ciphertext, or pure padding when the
// message length is a block multiple), then a DOMAIN_TAG block — so message
// boundaries are unambiguous and chunking cannot influence the tag.

/// Duplex AEAD session.
///
/// Usage:
/// 1. [`AeadSession::new`] with key and a **fresh, never-reused** nonce.
/// 2. [`AeadSession::absorb_aad`] with associated data (optional, once,
///    before any data).
/// 3. [`AeadSession::encrypt_chunk`] / [`AeadSession::decrypt_chunk`] for
///    consecutive data chunks — any sizes; chunk boundaries do not affect
///    the ciphertext or tag.
/// 4. [`AeadSession::finalize`] (consumes the session) for the 32-byte tag.
///
/// # Do not use plaintext before verifying
///
/// On decryption, data is revealed **before** authentication is checked.
/// Do not act on or forward decrypted bytes until `finalize`'s tag has been
/// compared against the stored tag with constant-time equality
/// (e.g. `subtle::ConstantTimeEq`).  The high-level `decrypt` in
/// [`crate::crypto`] enforces this contract structurally.
pub struct AeadSession {
    state: CmlSpongeState,
    /// Keystream for the current in-progress block — Mix13 of the rate,
    /// computed lazily when the block's first byte is processed.
    ks_block: [u8; BLOCK_BYTES],
    /// Ciphertext bytes of the current in-progress block, pending injection.
    ct_block: [u8; BLOCK_BYTES],
    /// Bytes of the current block processed so far (0..BLOCK_BYTES).
    fill: usize,
    /// Debug guard: AAD must be absorbed before any data is processed.
    #[cfg(debug_assertions)]
    data_started: bool,
}

impl AeadSession {
    /// Initialise a session from a 32-byte key and 16-byte nonce.
    ///
    /// See [`cipher_init`] for the absorption sequence and the nonce-reuse
    /// warning — reusing a `(key, nonce)` pair forfeits confidentiality
    /// and integrity.
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            state: cipher_init(key, iv),
            ks_block: [0u8; BLOCK_BYTES],
            ct_block: [0u8; BLOCK_BYTES],
            fill: 0,
            #[cfg(debug_assertions)]
            data_started: false,
        }
    }

    /// Absorb associated data (authenticated, not encrypted).
    ///
    /// Call at most once, after `new` and before any data chunks.  The
    /// caller typically passes the serialised file header so it is bound
    /// into the authentication tag without being encrypted.
    pub fn absorb_aad(&mut self, aad: &[u8]) {
        #[cfg(debug_assertions)]
        debug_assert!(
            !self.data_started,
            "absorb_aad must be called before encrypt_chunk/decrypt_chunk"
        );
        absorb(&mut self.state, aad, DOMAIN_AAD);
    }

    /// Compute the current block's keystream: Mix13 applied to the rate.
    fn refresh_keystream(&mut self) {
        for i in 0..N_RATE {
            let w = stafford_mix13(self.state.lattice[i]);
            self.ks_block[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
        }
    }

    /// Duplex injection: XOR the completed ciphertext block into the rate,
    /// then permute.  This is the single permutation per 64-byte block.
    fn inject_block(&mut self) {
        for i in 0..N_RATE {
            // ct_block is [u8; BLOCK_BYTES]; each 8-byte slice is infallible.
            let word = u64::from_le_bytes(
                self.ct_block[i * 8..(i + 1) * 8]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!()),
            );
            self.state.lattice[i] ^= word;
        }
        cml_permute(&mut self.state);
        self.fill = 0;
    }

    /// Encrypt `data` in place.  Callable repeatedly; chunk sizes are
    /// arbitrary and do not influence the ciphertext or tag.
    pub fn encrypt_chunk(&mut self, data: &mut [u8]) {
        #[cfg(debug_assertions)]
        if !data.is_empty() {
            self.data_started = true;
        }
        let mut pos = 0;
        while pos < data.len() {
            // Fast path: block-aligned with a full block available — process
            // word-wise straight between `data` and the rate, with no staging
            // through ks_block/ct_block.  Byte-identical to the general path.
            if self.fill == 0 && data.len() - pos >= BLOCK_BYTES {
                for i in 0..N_RATE {
                    let ks = stafford_mix13(self.state.lattice[i]);
                    let span = &mut data[pos + i * 8..pos + (i + 1) * 8];
                    // span is exactly 8 bytes — try_into is infallible.
                    let p =
                        u64::from_le_bytes((&*span).try_into().unwrap_or_else(|_| unreachable!()));
                    let c = p ^ ks;
                    span.copy_from_slice(&c.to_le_bytes());
                    self.state.lattice[i] ^= c; // duplex injection
                }
                cml_permute(&mut self.state);
                pos += BLOCK_BYTES;
                continue;
            }

            if self.fill == 0 {
                self.refresh_keystream();
            }
            let take = (BLOCK_BYTES - self.fill).min(data.len() - pos);
            for i in 0..take {
                let c = data[pos + i] ^ self.ks_block[self.fill + i];
                data[pos + i] = c;
                self.ct_block[self.fill + i] = c;
            }
            self.fill += take;
            pos += take;
            if self.fill == BLOCK_BYTES {
                self.inject_block();
            }
        }
    }

    /// Decrypt `data` in place.  Identical state evolution to
    /// [`AeadSession::encrypt_chunk`] — both inject the ciphertext bytes.
    ///
    /// See the type-level warning: do not use the plaintext before the
    /// finalize tag has been verified.
    pub fn decrypt_chunk(&mut self, data: &mut [u8]) {
        #[cfg(debug_assertions)]
        if !data.is_empty() {
            self.data_started = true;
        }
        let mut pos = 0;
        while pos < data.len() {
            // Fast path: see encrypt_chunk — word-wise, no staging buffers.
            if self.fill == 0 && data.len() - pos >= BLOCK_BYTES {
                for i in 0..N_RATE {
                    let ks = stafford_mix13(self.state.lattice[i]);
                    let span = &mut data[pos + i * 8..pos + (i + 1) * 8];
                    // span is exactly 8 bytes — try_into is infallible.
                    let c =
                        u64::from_le_bytes((&*span).try_into().unwrap_or_else(|_| unreachable!()));
                    span.copy_from_slice(&(c ^ ks).to_le_bytes());
                    self.state.lattice[i] ^= c; // inject the received ciphertext
                }
                cml_permute(&mut self.state);
                pos += BLOCK_BYTES;
                continue;
            }

            if self.fill == 0 {
                self.refresh_keystream();
            }
            let take = (BLOCK_BYTES - self.fill).min(data.len() - pos);
            for i in 0..take {
                let c = data[pos + i];
                self.ct_block[self.fill + i] = c;
                data[pos + i] = c ^ self.ks_block[self.fill + i];
            }
            self.fill += take;
            pos += take;
            if self.fill == BLOCK_BYTES {
                self.inject_block();
            }
        }
    }

    /// Finalise the session and return the 32-byte authentication tag.
    /// Consumes the session — no further data can be processed.
    ///
    /// After encryption: append the tag to the ciphertext.
    /// After decryption: compare against the stored tag in constant time
    /// (e.g. `subtle::ConstantTimeEq`) before trusting the plaintext.
    pub fn finalize(mut self) -> [u8; 32] {
        // Terminal ciphertext block: inject any pending partial-block
        // ciphertext with DOMAIN_CT padding.  Performed unconditionally
        // (pure padding when fill == 0) so every message ends with exactly
        // one padded CT block — block-aligned and empty messages are
        // unambiguous.
        let fill = self.fill;
        absorb(&mut self.state, &self.ct_block[..fill], DOMAIN_CT);
        // Tag-domain separation, then squeeze 32 bytes (4 rate words)
        // through the Mix13 output finaliser.
        absorb(&mut self.state, &[], DOMAIN_TAG);
        let mut tag = [0u8; 32];
        for i in 0..4 {
            let w = stafford_mix13(self.state.lattice[i]);
            tag[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
        }
        tag
        // `self` drops here: ks_block is zeroized (Drop), and the inner
        // CmlSpongeState zeroizes its lattice/counter/buffer.
    }
}

impl Drop for AeadSession {
    fn drop(&mut self) {
        // ks_block holds keystream (secret).  ct_block holds ciphertext
        // (public) but is scrubbed too — it costs nothing.
        self.ks_block.zeroize();
        self.ct_block.zeroize();
    }
}

// ── Reduced-round variant (for cryptanalysis) ─────────────────────────────────

/// Permutation with an explicit round count — used for reduced-round analysis.
/// `rounds` is clamped to a maximum of 32 (4× N_ROUNDS), allowing up to 4×
/// the standard round count for analysis purposes.
pub fn cml_permute_r(state: &mut CmlSpongeState, rounds: usize) {
    for _ in 0..rounds.min(32) {
        cml_round(&mut state.lattice, &mut state.counter);
    }
}

/// Copy the raw rate words (sites 0–7) into `out` as little-endian bytes,
/// WITHOUT applying the Stafford Mix13 output finalizer.
///
/// `out` must be exactly `BLOCK_BYTES` (64) bytes.
///
/// This is used exclusively by the `catwalk_raw_dump` PractRand binary to
/// test the intrinsic statistical quality of the CML-Sponge permutation
/// before Mix13 is applied.
pub fn raw_rate_bytes(state: &CmlSpongeState, out: &mut [u8; BLOCK_BYTES]) {
    for i in 0..N_RATE {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state.lattice[i].to_le_bytes());
    }
}

/// Initialise a state for reduced-round testing (same as cipher_init but
/// the number of rounds per permutation is overridden externally).
/// Useful for automated distinguisher tests.
pub fn cipher_init_r(key: &[u8; 32], iv: &[u8; 16], rounds: usize) -> CmlSpongeState {
    let mut state = CmlSpongeState::new();
    absorb_with(&mut state, key, DOMAIN_KEY, |st| cml_permute_r(st, rounds));
    absorb_with(&mut state, iv, DOMAIN_IV, |st| cml_permute_r(st, rounds));
    state
}

/// Generate keystream with a custom round count per permutation.
pub fn keystream_r(state: &mut CmlSpongeState, out: &mut [u8], rounds: usize) {
    let total = out.len();
    keystream_spans_with(
        state,
        total,
        |st| cml_permute_r(st, rounds),
        |pos, ks| {
            out[pos..pos + ks.len()].copy_from_slice(ks);
        },
    );
}

// ── Raw permutation for offline analysis ──────────────────────────────────

/// Apply `rounds` iterations of the CML round function directly to a raw
/// lattice array and Weyl counter, bypassing the [`CmlSpongeState`] wrapper.
///
/// This is intended **exclusively for offline algebraic analysis** (e.g.
/// measuring algebraic degree growth per round, computing ANFs, or building
/// differential trails).  It exposes the raw permutation without sponge
/// padding, domain separation, or the Stafford Mix13 output finalizer.
///
/// **Do not use for encryption or authentication.**
pub fn permute_raw(lattice: &mut [u64; 16], counter: &mut u64, rounds: usize) {
    for _ in 0..rounds.min(32) {
        cml_round(lattice, counter);
    }
}

#[cfg(test)]
mod round_tests {
    use super::*;

    /// Reference implementation of one round using array loops and modular
    /// indexing — the readable spec that the hand-unrolled `cml_round`
    /// replaced for speed.  Kept only in tests as the oracle.
    fn cml_round_reference(s: &mut [u64; N], counter: &mut u64) {
        const DIST: [usize; 4] = [1, 3, 7, 11];
        *counter = counter.wrapping_add(GOLDEN);
        for i in 0..N {
            s[i] = s[i].wrapping_add(counter.rotate_left(ROT[i]));
        }
        let mut m = [0u64; N];
        for k in 0..8 {
            let (mx, my) = arnold_cat_map(s[2 * k], s[2 * k + 1]);
            m[2 * k] = mx;
            m[2 * k + 1] = my;
        }
        for i in 0..N {
            s[i] = m[i]
                .wrapping_add(m[(i + DIST[0]) % N])
                .wrapping_add(m[(i + DIST[1]) % N])
                .wrapping_add(m[(i + DIST[2]) % N])
                .wrapping_add(m[(i + DIST[3]) % N]);
        }
        for k in 0..8 {
            let a = s[2 * k];
            s[2 * k + 1] = s[2 * k + 1].wrapping_mul(a | 1);
        }
    }

    /// The optimized unrolled `cml_round` must be byte-for-byte identical to
    /// the array-formula reference, across round counts and adversarial inputs.
    /// This locks the manual unrolling (and its literal coupling taps) to the
    /// spec on every platform, independent of the canonical keystream vectors.
    #[test]
    fn coupling_unroll_matches_reference() {
        // A spread of inputs: zeros, all-ones, alternating, counter-like, and
        // a deterministic LCG sweep — no RNG dependency, fully reproducible.
        let seeds: [u64; 5] = [0, u64::MAX, 0xAAAA_AAAA_AAAA_AAAA, 1, 0x9E37_79B9_7F4A_7C15];
        for &seed in &seeds {
            for start_counter in [0u64, 12345, u64::MAX] {
                let mut lat_opt = [0u64; N];
                let mut x = seed.wrapping_add(1);
                for w in lat_opt.iter_mut() {
                    // simple splitmix-style fill, distinct per lane
                    x = x.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(seed | 1);
                    *w = x ^ (x >> 29);
                }
                let mut lat_ref = lat_opt;
                let mut c_opt = start_counter;
                let mut c_ref = start_counter;
                // Apply several rounds; state must agree at every step.
                for _ in 0..5 {
                    cml_round(&mut lat_opt, &mut c_opt);
                    cml_round_reference(&mut lat_ref, &mut c_ref);
                    assert_eq!(lat_opt, lat_ref, "lattice diverged (seed {seed:#x})");
                    assert_eq!(c_opt, c_ref, "counter diverged (seed {seed:#x})");
                }
            }
        }
    }
}
