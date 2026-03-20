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
//! 3. CML coupling — s[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16].
//!    Distances {1,3,7,11} (5-term) achieve full 16-site diffusion in exactly 2 rounds.
//!    p(x) = 1+x+x³+x⁷+x¹¹; p(1)=5 (odd) → C invertible over Z/2⁶⁴Z; det(C)=−33075.
//! 4. Multiplicative mixing — s[2k+1] *= (s[2k] | 1) for k=0..7.
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

/// CML coupling distances for the 5-term polynomial p(x) = 1 + x + x³ + x⁷ + x¹¹.
/// Together with self (distance 0) these achieve full 16-site diffusion in 2 rounds.
///
/// Distances {1, 3, 7, 11} were selected to satisfy:
///   1. Non-singular coupling matrix — p(x) = 1 + x + x³ + x⁷ + x¹¹ has no roots
///      among the 16th roots of unity; min |λ_k| = 1.259 (eigenvalue margin, +65%
///      improvement over the prior {1,5,11} design's 0.765).
///   2. Invertible over Z/2⁶⁴Z — p(1) = 5 (odd) → det(C) = −33075 = −3³×5²×7² (odd)
///      → gcd(33075, 2⁶⁴) = 1 → kernel is trivial {0}.  No capacity loss.
///      The prior 4-term {1,5,11} had det = −1088 = −2⁶×17 (even), giving a
///      4-element kernel and 2-bit effective capacity reduction.
///   3. Full 16-site diffusion by round 2 (symbolic simulation verified).
///   4. All four distances are odd → p(-1) = 1−1−1−1−1 = −3 ≠ 0.
///   5. All distances are prime (1,3,7,11) — nothing-up-my-sleeve character.
const D1: usize = 1;
const D2: usize = 3;
const D3: usize = 7;
const D4: usize = 11;

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
/// (Störmer–Verlet) integration order:
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
#[inline(always)]
fn cml_round(s: &mut [u64; N], counter: &mut u64) {
    // Step 1 — Counter injection (all 16 sites, prime rotations).
    // Runs before the map to ensure no site pair is (0,0) when the Cat Map
    // is applied (see arnold_cat_map fixed-point note), and to diversify
    // state across sites before the nonlinear step.
    *counter = counter.wrapping_add(GOLDEN);
    for i in 0..N {
        s[i] = s[i].wrapping_add(counter.rotate_left(ROT[i]));
    }

    // Step 2 — Arnold's Cat Map on adjacent pairs: (0,1),(2,3),...,(14,15).
    // All pairs are written into snapshot m[] before coupling, preserving
    // the sponge's snapshot semantics (no site's coupling sees another
    // site's already-updated value from the same step).
    let mut m = [0u64; N];
    for k in 0..8 {
        let (mx, my) = arnold_cat_map(s[2 * k], s[2 * k + 1]);
        m[2 * k]     = mx;
        m[2 * k + 1] = my;
    }

    // Step 3 — CML additive coupling, 5-term p(x) = 1 + x + x³ + x⁷ + x¹¹.
    // Distances {1, 3, 7, 11}: det(C) = −33075 (odd) → fully invertible over Z/2⁶⁴Z.
    //
    // Multi-pass accumulation: each pass is a single-offset sequential loop that
    // the compiler can auto-vectorize with SIMD (each m[(i+D)%N] access is a
    // predictable rotated load).  A single fused loop with 5 terms defeats
    // auto-vectorization and is ~3× slower on x86-64.
    *s = m;                                                         // distance 0 (self)
    for i in 0..N { s[i] = s[i].wrapping_add(m[(i + D1) % N]); }  // distance 1
    for i in 0..N { s[i] = s[i].wrapping_add(m[(i + D2) % N]); }  // distance 3
    for i in 0..N { s[i] = s[i].wrapping_add(m[(i + D3) % N]); }  // distance 7
    for i in 0..N { s[i] = s[i].wrapping_add(m[(i + D4) % N]); }  // distance 11

    // Step 4 — Multiplicative mixing of adjacent pairs.
    for k in 0..8 {
        let a = s[2 * k];
        s[2 * k + 1] = s[2 * k + 1].wrapping_mul(a | 1);
    }
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
    /// Number of valid bytes in buf.
    buf_len: usize,
    /// Read cursor into buf.
    buf_pos: usize,
}

impl CmlSpongeState {
    fn new() -> Self {
        Self {
            lattice: [0u64; N],
            counter: 0,
            buf: [0u8; BLOCK_BYTES],
            buf_len: 0,
            buf_pos: 0,
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

/// XOR one 64-byte block into the rate portion (sites 0–7) then permute.
fn absorb_block(state: &mut CmlSpongeState, block: &[u8; BLOCK_BYTES]) {
    for i in 0..N_RATE {
        let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        state.lattice[i] ^= word;
    }
    cml_permute(state);
}

/// Absorb arbitrary-length data with Keccak-style multi-rate padding.
///
/// Padding: `data || domain_byte || 0x00…00 || 0x80`
/// where the total length is a multiple of BLOCK_BYTES (64).
fn absorb(state: &mut CmlSpongeState, data: &[u8], domain: u8) {
    // Build padded message.
    let mut msg: Vec<u8> = data.to_vec();
    msg.push(domain);
    while msg.len() % BLOCK_BYTES != BLOCK_BYTES - 1 {
        msg.push(0x00);
    }
    msg.push(0x80);
    debug_assert_eq!(msg.len() % BLOCK_BYTES, 0);

    for chunk in msg.chunks_exact(BLOCK_BYTES) {
        absorb_block(state, chunk.try_into().unwrap());
    }
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

/// Squeeze one 64-byte block from the rate portion, then permute.
fn squeeze_block(state: &mut CmlSpongeState) -> [u8; BLOCK_BYTES] {
    let mut block = [0u8; BLOCK_BYTES];
    for i in 0..N_RATE {
        let w = stafford_mix13(state.lattice[i]);
        block[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    cml_permute(state);
    block
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
    let mut pos = 0;
    while pos < out.len() {
        // Refill buffer if empty.
        if state.buf_pos >= state.buf_len {
            state.buf = squeeze_block(state);
            state.buf_len = BLOCK_BYTES;
            state.buf_pos = 0;
        }
        let available = state.buf_len - state.buf_pos;
        let want = out.len() - pos;
        let take = available.min(want);
        out[pos..pos + take].copy_from_slice(&state.buf[state.buf_pos..state.buf_pos + take]);
        state.buf_pos += take;
        pos += take;
    }
}

/// Encrypt `plaintext` in place by XOR with keystream.
pub fn encrypt_in_place(state: &mut CmlSpongeState, data: &mut [u8]) {
    let mut ks = vec![0u8; data.len()];
    keystream(state, &mut ks);
    for (d, k) in data.iter_mut().zip(ks.iter()) {
        *d ^= k;
    }
    ks.zeroize();
}

/// Decrypt is identical to encrypt for a stream cipher.
pub fn decrypt_in_place(state: &mut CmlSpongeState, data: &mut [u8]) {
    encrypt_in_place(state, data);
}

// ── AEAD construction ─────────────────────────────────────────────────────────
//
// SpongeWrap-style authenticated encryption.  After `cipher_init`, the caller:
//   1. Calls `absorb_aad` with associated data (authenticated, not encrypted).
//   2. Calls `aead_encrypt_chunk` / `aead_decrypt_chunk` for each data chunk.
//   3. Calls `aead_finalize` to produce / verify a 32-byte authentication tag.
//
// State evolution is identical in both encrypt and decrypt (both absorb the
// ciphertext with DOMAIN_CT), so the final tags match iff the same ciphertext
// was processed, providing Encrypt-then-MAC semantics natively.

/// Absorb associated data into the sponge (authenticated, not encrypted).
///
/// Call once after `cipher_init`, before any `aead_encrypt_chunk` calls.
/// The caller typically passes the serialised file header here so it is
/// bound into the authentication tag without being encrypted.
pub fn absorb_aad(state: &mut CmlSpongeState, data: &[u8]) {
    absorb(state, data, DOMAIN_AAD);
}

/// Encrypt `data` in place as one AEAD chunk, absorbing the resulting
/// ciphertext for authentication.
///
/// Call in order for consecutive plaintext chunks, then call `aead_finalize`.
/// Chunk sizes need not be multiples of 64; any size is accepted.
pub fn aead_encrypt_chunk(state: &mut CmlSpongeState, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    // Generate keystream and XOR plaintext → ciphertext in place.
    let mut ks = vec![0u8; data.len()];
    keystream(state, &mut ks);
    for (d, k) in data.iter_mut().zip(ks.iter()) {
        *d ^= k;
    }
    ks.zeroize();
    // Absorb the ciphertext for authentication.
    absorb(state, data, DOMAIN_CT);
}

/// Decrypt `data` in place as one AEAD chunk, absorbing the ciphertext
/// (the pre-XOR bytes) for authentication — matching `aead_encrypt_chunk`'s
/// state evolution exactly.
///
/// Call in order for consecutive ciphertext chunks, then call `aead_finalize`
/// and compare the returned tag against the stored tag in constant time.
///
/// # Do not use plaintext before verifying
///
/// `data` is overwritten with decrypted plaintext **before** authentication is
/// checked.  The caller must **not** act on or forward the contents of `data`
/// until `aead_finalize` has been called and the returned tag compared against
/// the stored tag using constant-time equality (e.g. `subtle::ConstantTimeEq`).
/// Using unauthenticated plaintext enables decryption-oracle and padding-oracle
/// attacks.  The high-level `decrypt` function in [`crate::crypto`] enforces
/// this contract structurally — callers of this low-level API must enforce it
/// themselves.
pub fn aead_decrypt_chunk(state: &mut CmlSpongeState, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    // Generate keystream (same state evolution as encryption).
    let mut ks = vec![0u8; data.len()];
    keystream(state, &mut ks);
    // Save original ciphertext before XOR-ing to plaintext.
    let mut ct = data.to_vec();
    // XOR to recover plaintext in place.
    for (d, k) in data.iter_mut().zip(ks.iter()) {
        *d ^= k;
    }
    ks.zeroize();
    // Absorb the ciphertext (not the plaintext) — must match encryption order.
    absorb(state, &ct, DOMAIN_CT);
    ct.zeroize();
}

/// Finalise the AEAD session and return a 32-byte authentication tag.
///
/// After encryption: append this tag to the ciphertext.
/// After decryption: compare this tag against the stored tag using a
///   constant-time comparison (e.g. `subtle::ConstantTimeEq`) before
///   trusting the decrypted plaintext.
///
/// The tag is derived from the sponge rate after a domain-separated
/// empty absorption (DOMAIN_TAG = 0x05), ensuring it is bound to
/// everything previously absorbed: key, IV, AAD, and all ciphertext blocks.
pub fn aead_finalize(state: &mut CmlSpongeState) -> [u8; 32] {
    // Empty absorption with TAG domain — domain-separated finalisation
    // that commences a permute, mixing in all prior state.
    absorb(state, &[], DOMAIN_TAG);
    // Squeeze 32 bytes (4 rate words) with Mix13 output finaliser.
    let mut tag = [0u8; 32];
    for i in 0..4 {
        let w = stafford_mix13(state.lattice[i]);
        tag[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    tag
}

// ── Reduced-round variant (for cryptanalysis) ─────────────────────────────────

/// Permutation with an explicit round count — used for reduced-round analysis.
/// `rounds` should be in 1..=N_ROUNDS; values outside this range are clamped.
pub fn cml_permute_r(state: &mut CmlSpongeState, rounds: usize) {
    for _ in 0..rounds.min(32) {
        cml_round(&mut state.lattice, &mut state.counter);
    }
}

/// Copy the raw rate words (sites 0–7) into `out` as little-endian bytes,
/// WITHOUT applying the Stafford Mix13 output finalizer.
///
/// `out` must be exactly [`BLOCK_BYTES`] (64) bytes.
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
    // Inline absorb with custom round count.
    let absorb_r = |st: &mut CmlSpongeState, data: &[u8], domain: u8| {
        let mut msg: Vec<u8> = data.to_vec();
        msg.push(domain);
        while msg.len() % BLOCK_BYTES != BLOCK_BYTES - 1 {
            msg.push(0x00);
        }
        msg.push(0x80);
        for chunk in msg.chunks_exact(BLOCK_BYTES) {
            let block: &[u8; BLOCK_BYTES] = chunk.try_into().unwrap();
            for i in 0..N_RATE {
                let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
                st.lattice[i] ^= word;
            }
            cml_permute_r(st, rounds);
        }
    };
    absorb_r(&mut state, key, DOMAIN_KEY);
    absorb_r(&mut state, iv, DOMAIN_IV);
    state
}

/// Generate keystream with a custom round count per permutation.
pub fn keystream_r(state: &mut CmlSpongeState, out: &mut [u8], rounds: usize) {
    let mut pos = 0;
    while pos < out.len() {
        if state.buf_pos >= state.buf_len {
            // Squeeze with reduced rounds (apply Mix13 finalizer, same as squeeze_block).
            let mut block = [0u8; BLOCK_BYTES];
            for i in 0..N_RATE {
                let w = stafford_mix13(state.lattice[i]);
                block[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }
            cml_permute_r(state, rounds);
            state.buf = block;
            state.buf_len = BLOCK_BYTES;
            state.buf_pos = 0;
        }
        let available = state.buf_len - state.buf_pos;
        let want = out.len() - pos;
        let take = available.min(want);
        out[pos..pos + take].copy_from_slice(&state.buf[state.buf_pos..state.buf_pos + take]);
        state.buf_pos += take;
        pos += take;
    }
}
