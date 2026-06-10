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
        m[2 * k] = mx;
        m[2 * k + 1] = my;
    }

    // Step 3 — CML additive coupling, 5-term p(x) = 1 + x + x³ + x⁷ + x¹¹.
    // Distances {1, 3, 7, 11}: det(C) = −33075 (odd) → fully invertible over Z/2⁶⁴Z.
    //
    // Multi-pass accumulation: each pass is a single-offset sequential loop that
    // the compiler can auto-vectorize with SIMD (each m[(i+D)%N] access is a
    // predictable rotated load).  A single fused loop with 5 terms defeats
    // auto-vectorization and is ~3× slower on x86-64.
    *s = m; // distance 0 (self)
    for i in 0..N {
        s[i] = s[i].wrapping_add(m[(i + D1) % N]);
    } // distance 1
    for i in 0..N {
        s[i] = s[i].wrapping_add(m[(i + D2) % N]);
    } // distance 3
    for i in 0..N {
        s[i] = s[i].wrapping_add(m[(i + D3) % N]);
    } // distance 7
    for i in 0..N {
        s[i] = s[i].wrapping_add(m[(i + D4) % N]);
    } // distance 11

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
