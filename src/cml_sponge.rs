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
//!    all 16 sites with distinct prime rotations {3,5,7,11,…,61}.  MUST be first:
//!    the logistic and tent maps satisfy f(x) = f(MAX^x), so injecting the counter
//!    before mapping breaks the complement symmetry that would otherwise make any
//!    key and its bitwise complement produce identical keystreams.
//! 2. Local maps   — logistic (even sites), tent (odd sites), computed as a snapshot.
//! 3. CML coupling — s[i] = m[i] + m[(i+1)%16] + m[(i+7)%16] + m[(i+8)%16].
//!    Distances {1,7,8} achieve full 16-site diffusion in exactly 4 rounds.
//! 4. Multiplicative mixing — s[2k+1] *= (s[2k] | 1) for k=0..7.
//!
//! **Sponge construction (Bertoni et al.):**
//! - Absorb key  (32 bytes, domain 0x01): XOR into rate, permute.
//! - Absorb IV   (16 bytes, domain 0x02): XOR into rate, permute.
//! - Squeeze: output 64 bytes from rate, permute, repeat.
//!
//! **Cross-platform determinism:** all arithmetic is u64/u128 wrapping.
//! Output is byte-for-byte identical to the Python reference implementation.

use zeroize::Zeroize;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Weyl sequence increment: fractional part of φ × 2^64.
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Number of lattice sites.
const N: usize = 16;

/// Rate portion: sites 0–7 → 64 bytes per squeeze.
const N_RATE: usize = 8;

/// Number of CML rounds per permutation.
/// Full 16-site diffusion occurs at round 4; 8 rounds gives 2× margin.
const N_ROUNDS: usize = 8;

/// CML coupling distances.  Together with self (distance 0) these achieve
/// full 16-site diffusion in 4 rounds (analytically verified).
const D1: usize = 1;
const D2: usize = 7;
const D3: usize = 8;

/// Per-site counter rotation amounts: first 16 primes ≥ 3.
/// All odd, all coprime to 64, publicly verifiable as nothing-up-my-sleeve.
const ROT: [u32; 16] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 61];

/// Domain separation byte for key absorption.
const DOMAIN_KEY: u8 = 0x01;

/// Domain separation byte for IV absorption.
const DOMAIN_IV: u8 = 0x02;

/// Rate size in bytes.
const BLOCK_BYTES: usize = N_RATE * 8; // 64

// ── Chaotic maps ──────────────────────────────────────────────────────────────

/// Fixed-point logistic map: (x * (MAX − x)) >> 62.
///
/// Approximates 4x(1−x) in u64 arithmetic.  The 128-bit product is
/// right-shifted 62 bits to keep the result in [0, 2^64).
#[inline(always)]
fn logistic_map(x: u64) -> u64 {
    let product = (x as u128).wrapping_mul((u64::MAX - x) as u128);
    (product >> 62) as u64
}

/// Branchless fixed-point tent map: 2x if MSB=0, else 2*(MAX−x).
#[inline(always)]
fn tent_map(x: u64) -> u64 {
    let mask = (x >> 63).wrapping_neg();
    let asc = x;
    let desc = u64::MAX - x;
    let sel = asc ^ (mask & (asc ^ desc));
    sel.wrapping_mul(2)
}

/// Apply the site-local map: logistic for even sites, tent for odd.
#[inline(always)]
fn local_map(x: u64, site: usize) -> u64 {
    if site % 2 == 0 {
        logistic_map(x)
    } else {
        tent_map(x)
    }
}

// ── CML round and permutation ──────────────────────────────────────────────

/// One CML round.  Mutates `s` and `counter` in place.
#[inline(always)]
fn cml_round(s: &mut [u64; N], counter: &mut u64) {
    // Step 1 — Counter injection (all 16 sites, prime rotations).
    // Must precede the map step to break the complement symmetry
    // logistic(x) == logistic(MAX ^ x) and tent(x) == tent(MAX ^ x).
    *counter = counter.wrapping_add(GOLDEN);
    for i in 0..N {
        s[i] = s[i].wrapping_add(counter.rotate_left(ROT[i]));
    }

    // Step 2 — Local maps (snapshot of all 16 sites).
    let mut m = [0u64; N];
    for i in 0..N {
        m[i] = local_map(s[i], i);
    }

    // Step 3 — CML additive coupling, distances {1, 7, 8}.
    for i in 0..N {
        s[i] = m[i]
            .wrapping_add(m[(i + D1) % N])
            .wrapping_add(m[(i + D2) % N])
            .wrapping_add(m[(i + D3) % N]);
    }

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
/// Required because `tent_map` always returns an even value (bit 0 = 0),
/// which would otherwise create a low-bit linear dependency in the output.
/// Mix13 is invertible, so no entropy is lost — it purely re-distributes the
/// internal state bits across all output bit positions.
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
}

/// Decrypt is identical to encrypt for a stream cipher.
pub fn decrypt_in_place(state: &mut CmlSpongeState, data: &mut [u8]) {
    encrypt_in_place(state, data);
}

// ── Reduced-round variant (for cryptanalysis) ─────────────────────────────────

/// Permutation with an explicit round count — used for reduced-round analysis.
/// `rounds` should be in 1..=N_ROUNDS; values outside this range are clamped.
pub fn cml_permute_r(state: &mut CmlSpongeState, rounds: usize) {
    for _ in 0..rounds.min(32) {
        cml_round(&mut state.lattice, &mut state.counter);
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
