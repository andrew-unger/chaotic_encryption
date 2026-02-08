use zeroize::Zeroize;

/// Fixed-point logistic map: approximates 4*x*(1-x) using u64 arithmetic.
///
/// x is treated as a fixed-point value in [0, 2^64). The continuous logistic
/// map with r=4 maps [0,1] -> [0,1] with strong chaotic behavior. Here we
/// compute x*(MAX-x) as a 128-bit product, then take bits [62..126] to
/// approximate multiplication by 4 and truncation back to 64 bits.
#[inline]
fn logistic_map(x: u64) -> u64 {
    let x128 = x as u128;
    let complement = (u64::MAX as u128).wrapping_sub(x128);
    let product = x128.wrapping_mul(complement);
    (product >> 62) as u64
}

/// Fixed-point tent map: approximates mu*min(x, 1-x) with mu=2.
///
/// Branchless implementation to prevent timing side-channels. Uses the MSB
/// of x to select between ascending (2*x) and descending (2*(MAX-x)) branches
/// via bitwise masking rather than a conditional branch.
#[inline]
fn tent_map(x: u64) -> u64 {
    // MSB=0 → ascending branch (x * 2), MSB=1 → descending branch ((MAX-x) * 2)
    let mask = (x >> 63).wrapping_neg(); // 0x00..00 if MSB=0, 0xFF..FF if MSB=1
    let ascending = x;
    let descending = u64::MAX.wrapping_sub(x);
    let selected = ascending ^ (mask & (ascending ^ descending));
    selected.wrapping_mul(2)
}

/// Chaotic keystream generator using integer-arithmetic chaotic maps.
///
/// State consists of 4 x u64 words (256-bit total), updated each round by:
/// 1. Nonlinear substitution: logistic map on words 0,2; tent map on words 1,3
/// 2. Counter injection on multiple state words to prevent degenerate cycles
/// 3. ARX cross-coupling for linear diffusion
/// 4. Multiplicative mixing for quadratic nonlinearity
///
/// All arithmetic is u64/u128 wrapping — results are identical on every platform.
pub struct ChaoticKeystream {
    state: [u64; 4],
    counter: u64,
}

/// Golden ratio constant (fractional part of phi * 2^64) used for counter
/// injection. An irrational-derived odd constant ensures the counter never
/// repeats modular patterns that could interact with map fixed points.
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Sentinel value XOR'd into any zero state word during initialization to
/// avoid the all-zero fixed point of both logistic and tent maps.
const NONZERO_SEED: u64 = 0xDEADBEEFCAFEBABE;

impl ChaoticKeystream {
    /// Create a new chaotic keystream from a 32-byte key and 16-byte nonce.
    ///
    /// The key populates the 4 state words directly. The nonce is mixed in
    /// via XOR (both straight and rotated) to provide per-message variation.
    /// After initialization, 40 warmup rounds are run to thoroughly diffuse
    /// the key/nonce material through the state.
    pub fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let mut state = [
            u64::from_le_bytes(key[0..8].try_into().unwrap()),
            u64::from_le_bytes(key[8..16].try_into().unwrap()),
            u64::from_le_bytes(key[16..24].try_into().unwrap()),
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
        ];

        // Mix in nonce
        let n0 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
        state[0] ^= n0;
        state[1] ^= n1;
        state[2] ^= n0.rotate_left(32);
        state[3] ^= n1.rotate_left(32);

        // Ensure no state word is zero (avoid chaotic map fixed points)
        for s in &mut state {
            if *s == 0 {
                *s = NONZERO_SEED;
            }
        }

        let mut ks = Self { state, counter: 0 };

        // Warm up: 40 rounds to fully diffuse key+nonce into state
        for _ in 0..40 {
            ks.round();
        }

        ks
    }

    /// Execute one round of the chaotic state update.
    ///
    /// Structure (substitution-permutation-multiplication):
    /// 1. Nonlinear substitution: chaotic maps (logistic/tent)
    /// 2. Counter injection on multiple state words
    /// 3. ARX cross-coupling for linear diffusion
    /// 4. Multiplicative mixing for quadratic nonlinearity
    #[inline]
    fn round(&mut self) {
        // 1. Nonlinear layer: chaotic maps
        self.state[0] = logistic_map(self.state[0]);
        self.state[1] = tent_map(self.state[1]);
        self.state[2] = logistic_map(self.state[2]);
        self.state[3] = tent_map(self.state[3]);

        // 2. Counter injection on even-indexed words to prevent degenerate cycles
        //    in any state word (not just state[0])
        self.counter = self.counter.wrapping_add(GOLDEN);
        self.state[0] = self.state[0].wrapping_add(self.counter);
        self.state[2] ^= self.counter.rotate_left(32);

        // 3. ARX cross-coupling diffusion
        self.state[0] = self.state[0].wrapping_add(self.state[1].rotate_left(17));
        self.state[1] ^= self.state[2].rotate_left(31);
        self.state[2] = self.state[2].wrapping_add(self.state[3].rotate_left(47));
        self.state[3] ^= self.state[0].rotate_left(5);

        // 4. Multiplicative mixing: makes internal state evolution quadratic,
        //    resisting algebraic linearization. The | 1 ensures the multiplier
        //    is always odd (never zero), preventing information loss.
        self.state[1] = self.state[1].wrapping_mul(self.state[0] | 1);
        self.state[3] = self.state[3].wrapping_mul(self.state[2] | 1);
    }

    /// Generate the next 8 bytes of keystream as a u64.
    ///
    /// Output is a non-linear (quadratic) combination of state words:
    /// multiply adjacent pairs then XOR the products. This prevents an
    /// attacker from learning linear equations over the state from output
    /// observations, which a simple XOR-fold would leak.
    pub fn next_u64(&mut self) -> u64 {
        self.round();
        self.round();
        let lo = self.state[0].wrapping_mul(self.state[1] | 1);
        let hi = self.state[2].wrapping_mul(self.state[3] | 1);
        lo ^ hi
    }

    /// XOR the chaotic keystream onto `data` in place.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        // Process 8 bytes at a time for efficiency
        let chunks = data.len() / 8;
        let remainder = data.len() % 8;

        for i in 0..chunks {
            let ks = self.next_u64().to_le_bytes();
            let offset = i * 8;
            data[offset] ^= ks[0];
            data[offset + 1] ^= ks[1];
            data[offset + 2] ^= ks[2];
            data[offset + 3] ^= ks[3];
            data[offset + 4] ^= ks[4];
            data[offset + 5] ^= ks[5];
            data[offset + 6] ^= ks[6];
            data[offset + 7] ^= ks[7];
        }

        if remainder > 0 {
            let ks = self.next_u64().to_le_bytes();
            let offset = chunks * 8;
            for j in 0..remainder {
                data[offset + j] ^= ks[j];
            }
        }
    }

    /// Generate an unbiased random value in [0, bound) using rejection sampling.
    ///
    /// Uses Lemire's method: reject values below `(2^64 - bound) % bound` to
    /// eliminate modulo bias entirely. Expected iterations < 2 for any bound.
    fn bounded_random(&mut self, bound: u64) -> u64 {
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u64();
            if r >= threshold {
                return r % bound;
            }
        }
    }

    /// Generate a permutation of `len` elements using Fisher-Yates shuffle
    /// driven by chaotic keystream output with unbiased random selection.
    pub fn generate_permutation(&mut self, len: usize) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..len).collect();
        for i in (1..len).rev() {
            let j = self.bounded_random((i + 1) as u64) as usize;
            indices.swap(i, j);
        }
        indices
    }
}

impl Drop for ChaoticKeystream {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter.zeroize();
    }
}

/// Apply a permutation to data: output[i] = data[perm[i]].
pub fn apply_permutation(data: &[u8], perm: &[usize]) -> Vec<u8> {
    perm.iter().map(|&idx| data[idx]).collect()
}

/// Apply the inverse of a permutation: if perm maps position i → perm[i],
/// then inverse_permute restores data[perm[i]] = input[i].
pub fn apply_inverse_permutation(data: &[u8], perm: &[usize]) -> Vec<u8> {
    let mut result = vec![0u8; data.len()];
    for (i, &orig_idx) in perm.iter().enumerate() {
        result[orig_idx] = data[i];
    }
    result
}
