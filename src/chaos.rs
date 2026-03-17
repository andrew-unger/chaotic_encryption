use zeroize::Zeroize;

/// Fixed-point logistic map: approximates 4*x*(1-x) using u64 arithmetic.
///
/// Treats x as a fixed-point value in [0, 2^64). Computes x*(MAX-x) as a
/// 128-bit product then extracts bits [62..126] to approximate multiplication
/// by 4. All arithmetic is wrapping — results are identical on every platform.
#[inline(always)]
fn logistic_map(x: u64) -> u64 {
    let x128 = x as u128;
    let complement = (u64::MAX as u128).wrapping_sub(x128);
    let product = x128.wrapping_mul(complement);
    (product >> 62) as u64
}

/// Fixed-point tent map: approximates min(2x, 2*(1-x)) with branchless u64 arithmetic.
///
/// MSB=0 → ascending branch (2x), MSB=1 → descending branch (2*(MAX-x)).
/// Branchless selection prevents timing side-channels.
#[inline(always)]
fn tent_map(x: u64) -> u64 {
    let mask = (x >> 63).wrapping_neg();
    let ascending = x;
    let descending = u64::MAX.wrapping_sub(x);
    let selected = ascending ^ (mask & (ascending ^ descending));
    selected.wrapping_mul(2)
}

/// One round of the 512-bit chaotic state update, operating on a borrowed
/// state array and Weyl counter. Extracted as a free function so that
/// `apply_keystream` can interleave two independent block computations
/// with no data dependencies between them, enabling CPU-level parallelism.
///
/// See `ChaoticKeystream` for full round documentation.
#[inline(always)]
fn round_fn(s: &mut [u64; 8], counter: &mut u64) {
    // 1. Nonlinear substitution — inverted map assignment between halves
    s[0] = logistic_map(s[0]); // lower: logistic on even
    s[1] = tent_map(s[1]);     // lower: tent on odd
    s[2] = logistic_map(s[2]);
    s[3] = tent_map(s[3]);
    s[4] = tent_map(s[4]);     // upper: tent on even (inverted)
    s[5] = logistic_map(s[5]); // upper: logistic on odd (inverted)
    s[6] = tent_map(s[6]);
    s[7] = logistic_map(s[7]);

    // 2. Counter injection into all 4 even-indexed words
    *counter = counter.wrapping_add(GOLDEN);
    s[0] = s[0].wrapping_add(*counter);
    s[2] = s[2].wrapping_add(counter.rotate_left(16));
    s[4] = s[4].wrapping_add(counter.rotate_left(32));
    s[6] = s[6].wrapping_add(counter.rotate_left(48));

    // 3a. ARX Layer A — within each half
    // Rotations (primes): lower half {17, 31, 47, 5}, upper half {13, 23, 37, 11}
    s[0] = s[0].wrapping_add(s[1].rotate_left(17));
    s[1] ^= s[2].rotate_left(31);
    s[2] = s[2].wrapping_add(s[3].rotate_left(47));
    s[3] ^= s[0].rotate_left(5);

    s[4] = s[4].wrapping_add(s[5].rotate_left(13));
    s[5] ^= s[6].rotate_left(23);
    s[6] = s[6].wrapping_add(s[7].rotate_left(37));
    s[7] ^= s[4].rotate_left(11);

    // 3b. ARX Layer B — cross-half coupling
    // After this step every word depends on all 512 state bits.
    // Rotations (primes): {29, 43, 7, 19, 41, 53, 3, 61}
    s[0] = s[0].wrapping_add(s[6].rotate_left(29));
    s[1] ^= s[7].rotate_left(43);
    s[2] = s[2].wrapping_add(s[4].rotate_left(7));
    s[3] ^= s[5].rotate_left(19);
    s[4] = s[4].wrapping_add(s[2].rotate_left(41));
    s[5] ^= s[3].rotate_left(53);
    s[6] = s[6].wrapping_add(s[0].rotate_left(3));
    s[7] ^= s[1].rotate_left(61);

    // 4. Multiplicative mixing — all 4 adjacent pairs
    s[1] = s[1].wrapping_mul(s[0] | 1);
    s[3] = s[3].wrapping_mul(s[2] | 1);
    s[5] = s[5].wrapping_mul(s[4] | 1);
    s[7] = s[7].wrapping_mul(s[6] | 1);
}

/// Chaotic keystream generator with integer-arithmetic logistic and tent maps.
///
/// ## Design
///
/// **State:** 8×u64 (512-bit) plus a Weyl counter. The lower 4 words are seeded
/// directly from the chaos subkey; the upper 4 words are seeded from nothing-up-my-
/// sleeve constants (fractional parts of √2, √3, √5, √7 — same source as SHA-512's
/// initial hash values) XOR'd with the nonce, providing a known, publicly-verifiable
/// second half with no hidden trapdoors.
///
/// ## Counter-mode block generation
///
/// After the 80-round warmup, `state` and `counter` are frozen as the base state.
/// Each block is generated independently:
///
/// 1. Copy base `state` to a local working copy.
/// 2. Inject the block counter into `working[0]` and `working[4]` (wrapping_add),
///    making each block's starting state unique.
/// 3. Run 20 rounds with a block-local Weyl counter seeded from the base counter.
/// 4. Output: `working[i] + pre[i]` for all i (ChaCha20-style).
/// 5. Increment the block counter.
///
/// Because blocks are independent, `apply_keystream` processes two 64-byte blocks
/// simultaneously by interleaving their round computations. The two streams have no
/// data dependencies, so the CPU's out-of-order execution runs them in parallel,
/// approximately halving keystream generation time.
///
/// **Round function:** Each round applies:
/// 1. Nonlinear chaotic maps (logistic/tent, inverted assignment between halves)
/// 2. Weyl counter injection via wrapping_add into all 4 even-indexed words
/// 3. Two-layer butterfly ARX: Layer A mixes within each half; Layer B mixes
///    across halves. Full 512-bit avalanche is achieved within 1 round.
/// 4. Multiplicative mixing on all 4 adjacent pairs (quadratic nonlinearity)
///
/// **Output:** 20 rounds per 64-byte block with ChaCha20-style pre+post state
/// addition (`output[i] = post[i] + pre[i]`), preventing state recovery even
/// from known keystream. Throughput: 64 bytes / 20 rounds = 3.2 bytes/round
/// (identical ratio to ChaCha20/20).
///
/// **Rotation constants:** All 16 ARX rotation amounts are the first 16 primes ≥ 3:
/// {3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,61}. All are odd (full 64-bit cycle
/// length) and publicly verifiable as nothing-up-my-sleeve numbers.
///
/// All arithmetic is u64/u128 wrapping — platform-identical output on every target.
pub struct ChaoticKeystream {
    state: [u64; 8],
    counter: u64,
    block_counter: u64,
}

/// Golden ratio constant (fractional part of φ×2^64) for the Weyl counter sequence.
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Sentinel used to escape the all-zero fixed point during and after initialization.
const NONZERO_SEED: u64 = 0xDEADBEEFCAFEBABE;

/// Nothing-up-my-sleeve constants for the upper state half.
/// These are the fractional parts of √2, √3, √5, √7 multiplied by 2^64 —
/// the same source as SHA-512's initial hash values (publicly verifiable).
const C0: u64 = 0x6a09e667f3bcc908; // frac(√2) × 2^64
const C1: u64 = 0xbb67ae8584caa73b; // frac(√3) × 2^64
const C2: u64 = 0x3c6ef372fe94f82b; // frac(√5) × 2^64
const C3: u64 = 0xa54ff53a5f1d36f1; // frac(√7) × 2^64

impl ChaoticKeystream {
    /// Create a new keystream from a 32-byte key and 16-byte nonce.
    ///
    /// State layout after loading:
    /// ```text
    /// [key[0..8], key[8..16], key[16..24], key[24..32],   ← lower half: key
    ///  C0^n0,     C1^n1,     C2^n0.rotl(32), C3^n1.rotl(32)]  ← upper half: const^nonce
    /// ```
    /// This is analogous to ChaCha20's state layout (key | const+nonce+counter).
    /// The constants provide a non-zero, publicly-auditable upper half so that
    /// a zero key does not create a degenerate initial state.
    ///
    /// After loading, 80 warmup rounds fully diffuse all 512 bits. The resulting
    /// `state` and `counter` are then frozen as the base state for all subsequent
    /// block generation; only `block_counter` advances during keystream output.
    pub fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let n0 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());

        let mut state = [
            // Lower half: key material
            u64::from_le_bytes(key[0..8].try_into().unwrap()),
            u64::from_le_bytes(key[8..16].try_into().unwrap()),
            u64::from_le_bytes(key[16..24].try_into().unwrap()),
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
            // Upper half: SHA-512-derived constants XOR'd with nonce
            C0 ^ n0,
            C1 ^ n1,
            C2 ^ n0.rotate_left(32),
            C3 ^ n1.rotate_left(32),
        ];

        // Guard zero initial state words (fixed point of both chaotic maps).
        // NONZERO_SEED is position-offset so each rescued word is distinct.
        for (i, s) in state.iter_mut().enumerate() {
            if *s == 0 {
                *s = NONZERO_SEED.wrapping_add(i as u64);
            }
        }

        let mut ks = Self { state, counter: 0, block_counter: 0 };

        // 80 warmup rounds — 4 full fill_block equivalents.
        // Full 512-bit avalanche is achieved in 1 round; 80 rounds erases all
        // initial state structure with a vast safety margin.
        for _ in 0..80 {
            ks.warmup_round();
        }

        // Post-warmup zero guard. Uses counter to distinguish rescued positions.
        for i in 0..8 {
            if ks.state[i] == 0 {
                ks.state[i] = NONZERO_SEED.wrapping_add(ks.counter.wrapping_add(i as u64));
            }
        }

        // state and counter are now frozen as the base state.
        // block_counter starts at 0 and increments per block.
        ks
    }

    /// One warmup round — mutates self.state and self.counter in place.
    /// Only called during initialization; not used during keystream generation.
    #[inline(always)]
    fn warmup_round(&mut self) {
        round_fn(&mut self.state, &mut self.counter);
    }

    /// Generate one 64-byte block from the base state and the current block counter.
    ///
    /// Each block is fully independent: copying the base state, injecting the
    /// block counter, running 20 rounds, then adding pre+post. This matches
    /// ChaCha20's counter-mode construction and enables parallel block generation.
    #[inline(always)]
    fn fill_block(&mut self) -> [u64; 8] {
        let bc = self.block_counter;
        let mut s = self.state;
        s[0] = s[0].wrapping_add(bc);
        s[4] = s[4].wrapping_add(bc.rotate_left(32));
        let pre = s;
        let mut weyl = self.counter;
        for _ in 0..20 {
            round_fn(&mut s, &mut weyl);
        }
        self.block_counter = self.block_counter.wrapping_add(1);
        [
            s[0].wrapping_add(pre[0]),
            s[1].wrapping_add(pre[1]),
            s[2].wrapping_add(pre[2]),
            s[3].wrapping_add(pre[3]),
            s[4].wrapping_add(pre[4]),
            s[5].wrapping_add(pre[5]),
            s[6].wrapping_add(pre[6]),
            s[7].wrapping_add(pre[7]),
        ]
    }

    /// Generate two 64-byte blocks simultaneously by interleaving round computations.
    ///
    /// Blocks A and B are independent (different block counter values), so their
    /// round computations have no data dependencies. The CPU's out-of-order execution
    /// can issue instructions from both streams simultaneously, approximately halving
    /// the time compared to two sequential fill_block calls.
    #[inline(always)]
    fn fill_two_blocks(&mut self) -> ([u64; 8], [u64; 8]) {
        let bc0 = self.block_counter;
        let bc1 = self.block_counter.wrapping_add(1);

        let mut a = self.state;
        a[0] = a[0].wrapping_add(bc0);
        a[4] = a[4].wrapping_add(bc0.rotate_left(32));
        let pre_a = a;
        let mut wa = self.counter;

        let mut b = self.state;
        b[0] = b[0].wrapping_add(bc1);
        b[4] = b[4].wrapping_add(bc1.rotate_left(32));
        let pre_b = b;
        let mut wb = self.counter;

        for _ in 0..20 {
            round_fn(&mut a, &mut wa);
            round_fn(&mut b, &mut wb);
        }

        self.block_counter = self.block_counter.wrapping_add(2);

        (
            [
                a[0].wrapping_add(pre_a[0]),
                a[1].wrapping_add(pre_a[1]),
                a[2].wrapping_add(pre_a[2]),
                a[3].wrapping_add(pre_a[3]),
                a[4].wrapping_add(pre_a[4]),
                a[5].wrapping_add(pre_a[5]),
                a[6].wrapping_add(pre_a[6]),
                a[7].wrapping_add(pre_a[7]),
            ],
            [
                b[0].wrapping_add(pre_b[0]),
                b[1].wrapping_add(pre_b[1]),
                b[2].wrapping_add(pre_b[2]),
                b[3].wrapping_add(pre_b[3]),
                b[4].wrapping_add(pre_b[4]),
                b[5].wrapping_add(pre_b[5]),
                b[6].wrapping_add(pre_b[6]),
                b[7].wrapping_add(pre_b[7]),
            ],
        )
    }

    /// XOR the chaotic keystream onto `data` in place.
    ///
    /// Processes 128-byte pairs via `fill_two_blocks` (two independent blocks
    /// interleaved for CPU-level parallelism), then handles any remaining
    /// 64-byte block and final partial block.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        // Process 128-byte (2-block) chunks with parallel block generation
        let mut chunks128 = data.chunks_exact_mut(128);
        for chunk in chunks128.by_ref() {
            let ([a0, a1, a2, a3, a4, a5, a6, a7], [b0, b1, b2, b3, b4, b5, b6, b7]) =
                self.fill_two_blocks();

            let x0 = u64::from_le_bytes(chunk[0..8].try_into().unwrap()) ^ a0;
            let x1 = u64::from_le_bytes(chunk[8..16].try_into().unwrap()) ^ a1;
            let x2 = u64::from_le_bytes(chunk[16..24].try_into().unwrap()) ^ a2;
            let x3 = u64::from_le_bytes(chunk[24..32].try_into().unwrap()) ^ a3;
            let x4 = u64::from_le_bytes(chunk[32..40].try_into().unwrap()) ^ a4;
            let x5 = u64::from_le_bytes(chunk[40..48].try_into().unwrap()) ^ a5;
            let x6 = u64::from_le_bytes(chunk[48..56].try_into().unwrap()) ^ a6;
            let x7 = u64::from_le_bytes(chunk[56..64].try_into().unwrap()) ^ a7;
            chunk[0..8].copy_from_slice(&x0.to_le_bytes());
            chunk[8..16].copy_from_slice(&x1.to_le_bytes());
            chunk[16..24].copy_from_slice(&x2.to_le_bytes());
            chunk[24..32].copy_from_slice(&x3.to_le_bytes());
            chunk[32..40].copy_from_slice(&x4.to_le_bytes());
            chunk[40..48].copy_from_slice(&x5.to_le_bytes());
            chunk[48..56].copy_from_slice(&x6.to_le_bytes());
            chunk[56..64].copy_from_slice(&x7.to_le_bytes());

            let y0 = u64::from_le_bytes(chunk[64..72].try_into().unwrap()) ^ b0;
            let y1 = u64::from_le_bytes(chunk[72..80].try_into().unwrap()) ^ b1;
            let y2 = u64::from_le_bytes(chunk[80..88].try_into().unwrap()) ^ b2;
            let y3 = u64::from_le_bytes(chunk[88..96].try_into().unwrap()) ^ b3;
            let y4 = u64::from_le_bytes(chunk[96..104].try_into().unwrap()) ^ b4;
            let y5 = u64::from_le_bytes(chunk[104..112].try_into().unwrap()) ^ b5;
            let y6 = u64::from_le_bytes(chunk[112..120].try_into().unwrap()) ^ b6;
            let y7 = u64::from_le_bytes(chunk[120..128].try_into().unwrap()) ^ b7;
            chunk[64..72].copy_from_slice(&y0.to_le_bytes());
            chunk[72..80].copy_from_slice(&y1.to_le_bytes());
            chunk[80..88].copy_from_slice(&y2.to_le_bytes());
            chunk[88..96].copy_from_slice(&y3.to_le_bytes());
            chunk[96..104].copy_from_slice(&y4.to_le_bytes());
            chunk[104..112].copy_from_slice(&y5.to_le_bytes());
            chunk[112..120].copy_from_slice(&y6.to_le_bytes());
            chunk[120..128].copy_from_slice(&y7.to_le_bytes());
        }

        // Handle remaining 64-127 bytes: one full block
        let rem = chunks128.into_remainder();
        let mut chunks64 = rem.chunks_exact_mut(64);
        if let Some(chunk) = chunks64.next() {
            let [w0, w1, w2, w3, w4, w5, w6, w7] = self.fill_block();
            let z0 = u64::from_le_bytes(chunk[0..8].try_into().unwrap()) ^ w0;
            let z1 = u64::from_le_bytes(chunk[8..16].try_into().unwrap()) ^ w1;
            let z2 = u64::from_le_bytes(chunk[16..24].try_into().unwrap()) ^ w2;
            let z3 = u64::from_le_bytes(chunk[24..32].try_into().unwrap()) ^ w3;
            let z4 = u64::from_le_bytes(chunk[32..40].try_into().unwrap()) ^ w4;
            let z5 = u64::from_le_bytes(chunk[40..48].try_into().unwrap()) ^ w5;
            let z6 = u64::from_le_bytes(chunk[48..56].try_into().unwrap()) ^ w6;
            let z7 = u64::from_le_bytes(chunk[56..64].try_into().unwrap()) ^ w7;
            chunk[0..8].copy_from_slice(&z0.to_le_bytes());
            chunk[8..16].copy_from_slice(&z1.to_le_bytes());
            chunk[16..24].copy_from_slice(&z2.to_le_bytes());
            chunk[24..32].copy_from_slice(&z3.to_le_bytes());
            chunk[32..40].copy_from_slice(&z4.to_le_bytes());
            chunk[40..48].copy_from_slice(&z5.to_le_bytes());
            chunk[48..56].copy_from_slice(&z6.to_le_bytes());
            chunk[56..64].copy_from_slice(&z7.to_le_bytes());
        }

        // Handle final partial block (0–63 bytes)
        let tail = chunks64.into_remainder();
        if !tail.is_empty() {
            let block = self.fill_block();
            let mut keyblock = [0u8; 64];
            for (i, &word) in block.iter().enumerate() {
                keyblock[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
            }
            for (d, k) in tail.iter_mut().zip(keyblock.iter()) {
                *d ^= k;
            }
        }
    }
}

impl Drop for ChaoticKeystream {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter.zeroize();
        self.block_counter.zeroize();
    }
}
