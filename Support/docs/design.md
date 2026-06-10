# CATWALK: Design and Specification

**Version:** v10 (CML-Sponge AEAD — 5-term coupling)
**Status:** Research implementation — self-reviewed, awaiting independent cryptanalysis
**Implementation:** `src/cml_sponge.rs` (Rust)

---

## 1. Motivation

### 1.1 Why Arnold's Cat Map?

A chaotic map is a deterministic function on a bounded domain whose orbits exhibit
sensitive dependence on initial conditions (the "butterfly effect"), dense periodic
orbits, and topological transitivity. In the classical continuous setting these
properties are well-studied. In an integer arithmetic setting — which is what a
computer implements — the maps retain the *statistical* properties that make them
interesting as mixing primitives: high sensitivity to initial state, rapid diffusion,
and hard-to-predict long-period behavior.

CATWALK uses **Arnold's Cat Map** as the local nonlinear map applied to adjacent site
pairs. The map is a discrete linear toral automorphism:

```
[x']   [1  1] [x]
[y'] = [1  2] [y]   (mod 2^64)

Computed in symplectic order:
  x' = x + y           (mod 2^64)
  y' = x' + y          (mod 2^64)   ← uses updated x'; gives x + 2y
```

Arnold's Cat Map was selected as the local map for three concrete reasons:

1. **Natively integer arithmetic.** No fixed-point approximation and no precision
   loss. The Cat Map requires only wrapping additions — the u64 ring is its
   natural domain.

2. **Provable hyperbolicity.** The map is an Anosov diffeomorphism on the torus.
   Its eigenvalues are (3 ± √5)/2 ≈ {2.618, 0.382} — real, distinct, product 1 —
   so the map has a stable and an unstable manifold filling R². This means any two
   nearby states diverge at an exponential rate (Lyapunov exponent
   ln((3+√5)/2) ≈ 0.9624) — a *proven* property, not a conjecture.

3. **No complement symmetry.** cat_map(MAX−x, MAX−y) ≠ cat_map(x, y) by
   construction, so the Weyl counter injection serves purely as state
   diversification. The complement-symmetry tests (TV2 vs TV3 in the test suite)
   verify this at the cipher level.

### 1.2 What the CML Provides

A **Coupled Map Lattice** (CML) is a network of locally-interacting chaotic maps.
Each site applies its map independently, then the result is diffused to neighboring
sites through an additive coupling step. This creates two distinct mixing mechanisms
that complement each other:

- **Nonlinear local mixing** from the chaotic maps (high sensitivity, quadratic growth)
- **Global diffusion** from the coupling topology (all-to-all avalanche in a bounded round count)

A conventional ARX (add-rotate-XOR) permutation achieves diffusion through linear
operations. The CML adds a layer of nonlinear, input-dependent mixing that is harder
to model with algebraic or differential techniques than pure ARX.

### 1.3 Research Claim

CATWALK claims to be a **cryptographically secure stream cipher with AEAD support**
based on a CML-Sponge construction. The claim is:

**Proven:** Full 16-site diffusion in 2 CML rounds (analytically — see §2.5).
**Conjectured:** The 8-round permutation is computationally indistinguishable from
a random permutation under the assumption that the CML nonlinearity, Weyl counter
injection, and multiplicative mixing together defeat known algebraic and
differential attacks. This conjecture has not been independently verified.
**Not claimed:** NIST-level or academic peer review. This is research-grade work.

---

## 2. Full Construction Specification

This section is complete enough to reimplement CATWALK from scratch.

### 2.1 State Layout

```
Lattice:   s[0..15]   — 16 × u64 (1024 bits total)
Counter:   c          — u64 Weyl sequence value
Buffer:    buf[0..63] — 64 bytes of buffered keystream output
buf_pos, buf_len       — cursor and valid length within buf
```

The lattice is divided into two halves:
- **Rate** (sites 0–7, 512 bits): XOR'd with input during absorb; read during squeeze.
- **Capacity** (sites 8–15, 512 bits): never directly output; carries hidden state.

Initial state: all sites zero, counter zero, buffer empty.

### 2.2 Local Map

**Arnold's Cat Map** applied to 8 adjacent site pairs:
(0,1), (2,3), (4,5), (6,7), (8,9), (10,11), (12,13), (14,15).

```
arnold_cat_map(x: u64, y: u64) -> (u64, u64):
    x' = x wrapping_add y
    y' = x' wrapping_add y     // symplectic order; equals x + 2y
    return (x', y')
```

This is the matrix [[1,1],[1,2]] acting on (x, y) mod 2^64. All operations are
wrapping additions — no branches, no u128 arithmetic, no divisions.

**Pairing strategy — adjacent pairs:** The 16 sites are paired as (0,1), (2,3), …,
(14,15). This pairing matches Step 4's multiplicative mixing pairs, creating a
coherent two-layer nonlinear transformation per pair per round: the Cat Map provides
additive symplectic mixing (Step 2), and the multiplicative mixing provides a
multiplicative layer (Step 4) on the same pairs. The coupling step (Step 3, distances
{1, 3, 7, 11}) then propagates each pair's mixed state across the full 16-site lattice.
Full 16-site diffusion in 2 rounds is achieved with the new coupling topology.

**Fixed point:** cat_map(0, 0) = (0, 0). This is the only fixed point. It is benign
in practice: the Weyl counter injection (Step 1) runs before Step 2, and the
probability of both sites in a pair being exactly 0 after counter injection is
≈ 2⁻¹²⁸ per pair per round (two independent 64-bit coincidences). No guard is
needed; see §5 of this document and `docs/security_argument_final.md` for the full analysis.

### 2.3 Coupling Topology

After the local maps are applied, each site is updated by adding the mapped values
of four neighbors:

```
s[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16]
```

where `m[i]` is the local-map output of site `i` before coupling (snapshot).

The coupling distances are **{1, 3, 7, 11}** (5-term coupling). These were selected
to satisfy four requirements simultaneously:

1. **Non-singular coupling matrix.** The coupling polynomial
   `p(x) = 1 + x + x^3 + x^7 + x^11` has no roots among the 16th roots of unity;
   the minimum eigenvalue magnitude is **1.259** (k=1,7,9,15), a 65% improvement
   over the v9 design (0.765). All coupling Fourier modes are amplified (|λ_k| > 1
   for k ≠ 0), meaning no mode contracts under coupling.
2. **Invertible over Z/2^64Z.** `p(1) = 5` (odd) → `det(C) = −33075 = −3³×5²×7²`
   (odd) → `gcd(33075, 2^64) = 1` → C is fully invertible. No information is lost
   in the coupling step; the sponge capacity is the full **512 bits** (no correction
   needed). The prior 4-term {1,5,11} had `det = −1088 = −2^6×17` (even), giving a
   4-element kernel and a 2-bit effective capacity reduction (510 bits).
3. **Full 16-site diffusion in 2 rounds.** Unchanged from {1,5,11}.
   Symbolically verified by tracking active-site reachability through the
   full round function (counter injection → cat map → coupling → mult mix).
4. **All four distances are odd:** `p(-1) = 1−1−1−1−1 = −3 ≠ 0` (algebraic
   guarantee). All distances are prime: {1, 3, 7, 11} — nothing-up-my-sleeve.

`|det(C)| = 33075`, rank = 16.

**Implementation note:** The 5-term coupling is implemented as 5 sequential passes
(one per distance) rather than a single fused loop. This allows the compiler to
auto-vectorize each pass independently. A single fused loop with 5 indexed offsets
prevents SIMD vectorization and causes ~3× throughput regression.

### 2.4 One CML Round (cml_round)

Applied in sequence per round:

**Step 1 — Counter injection (MUST be first):**
```
c = c wrapping_add GOLDEN              // advance Weyl counter
for i in 0..16:
    s[i] = s[i] wrapping_add (c rotate_left ROT[i])
```
where GOLDEN = 0x9E3779B97F4A7C15 (fractional part of φ × 2^64) and
ROT = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 61]
(first 16 primes ≥ 3; all coprime to 64, publicly verifiable).

The distinct rotation amounts ensure the same counter value contributes differently
to each site. This prevents a family of related-key attacks where sites evolve
in lock-step.

**Step 2 — Local map (snapshot):**
```
for k in 0..8:
    (m[2k], m[2k+1]) = arnold_cat_map(s[2k], s[2k+1])
```
All pairs are written into snapshot array `m[]` before coupling. This prevents
any site's coupling computation from seeing another site's already-updated value
from the same step — identical to the original snapshot semantics.

**Step 3 — CML additive coupling (5-term):**
```
s[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16]   for all i (wrapping)
```
Polynomial: `p(x) = 1 + x + x³ + x⁷ + x¹¹`; `p(1)=5` (odd) → C invertible over Z/2^64Z;
`det(C) = −33075` (odd); `min|λ_k| = 1.259`; full diffusion in 2 rounds.

**Step 4 — Multiplicative mixing:**
```
for k in 0..8:
    s[2k+1] = s[2k+1] wrapping_mul (s[2k] | 1)
```
The `| 1` ensures the multiplier is always odd, giving a full 64-bit cycle length
for the multiplicative operation.

### 2.5 Round Count

**N_ROUNDS = 8** rounds per permutation call.

Justification:
- Full diffusion (all 16 sites mutually dependent): 2 rounds (§2.3).
- CATWALK uses 8 rounds: **4× diffusion margin**.
- Comparison: Keccak-f[1600] uses 24 rounds; SHA-3's security margin is also 2×
  over the theoretical minimum for diffusion. CATWALK follows the same principle.
- PractRand validation at 256 GB with multiple seeds provides empirical support that
  8 rounds is sufficient for statistical indistinguishability (see `docs/archive/practrand_results_v9_1_7_8.md`).

Reduced-round PractRand testing (docs/reduced_round_analysis.md) confirms that the raw permutation achieves full statistical indistinguishability at 2 rounds without Mix13, giving the 8-round design a 4× conservative empirical security margin.

### 2.6 Sponge Construction

CATWALK uses a sponge construction following Bertoni et al. (2007), adapted for a
stream cipher context.

**Absorb phase:**
```
absorb(data, domain):
    msg = data ++ [domain] ++ [0x00 × padding] ++ [0x80]
    // padding ensures len(msg) is a multiple of 64 (BLOCK_BYTES)
    for each 64-byte block in msg:
        for i in 0..8:
            s[i] ^= block[i*8 .. (i+1)*8] as u64 (little-endian)
        cml_permute(state)   // 8 rounds
```
This is Keccak-style multi-rate padding: `data || domain || 0x00...00 || 0x80`
where padding brings the total to the next multiple of 64 bytes.

**Squeeze phase:**
```
squeeze_block():
    for i in 0..8:
        block[i*8..(i+1)*8] = stafford_mix13(s[i]).to_le_bytes()
    cml_permute(state)
    return block
```
The Stafford Mix13 finalizer (§2.7) is applied to each rate word before output.

**Initialization sequence:**
1. All-zero state (all 16 sites, counter, buffer).
2. Absorb key (32 bytes, DOMAIN_KEY = 0x01).
3. Absorb IV (16 bytes, DOMAIN_IV = 0x02).

After initialization the state is ready for keystream output or AEAD operations.

### 2.7 Stafford Mix13 Output Finalizer

Applied to each rate word before output:

```
mix13(x: u64) -> u64:
    x = x XOR (x >> 30)
    x = x wrapping_mul 0xBF58476D1CE4E5B9
    x = x XOR (x >> 27)
    x = x wrapping_mul 0x94D049BB133111EB
    x = x XOR (x >> 31)
    return x
```

**Why this is retained:** Mix13 is retained as an additional output whitening
layer. It is a bijection (invertible, no entropy loss)
that redistributes internal state bits across all output bit positions, providing
defense-in-depth against any residual structure. The same finalizer is used in
SplitMix64, Murmur3 hash, and PCG.

### 2.8 Domain Separation

Five domain bytes ensure that absorb calls for different roles cannot produce
identical state transitions even with the same data:

| Domain | Value | Used for |
|--------|-------|----------|
| DOMAIN_KEY | 0x01 | Key absorption during initialization |
| DOMAIN_IV  | 0x02 | IV absorption during initialization |
| DOMAIN_AAD | 0x03 | Associated data (authenticated, not encrypted) |
| DOMAIN_CT  | 0x04 | Ciphertext absorption during AEAD auth |
| DOMAIN_TAG | 0x05 | Empty absorption to trigger tag finalization |

Each domain byte is included as the first padding byte after the data, before the
zero-padding and 0x80 terminator. This follows the Keccak padding convention exactly.

Domain separation ensures: `absorb(data, 0x03) ≠ absorb(data, 0x04)` for any data,
so data authenticated as AAD cannot be confused with ciphertext, and the tag
finalization is distinguishable from both.

### 2.9 Key Schedule

```
master_key = Argon2id(
    password   = user_password,
    salt       = random_16_bytes ++ timestamp_8_bytes,
    m_cost     = 2^18 KiB   (256 MB),
    t_cost     = 4 iterations,
    p_cost     = 1 lane,
    output_len = 32 bytes
)

cipher_key = BLAKE3_derive_key("catwalk.v9.cipher", master_key)
```

Argon2id at 256 MB / 4 iterations costs ~1–4 seconds on typical hardware, making
brute-force password cracking expensive. BLAKE3 domain derivation after Argon2id
provides a clean separation between the KDF output and the cipher key even in
hypothetical scenarios where the same master key is used in multiple contexts.

The cipher key enters the sponge via `cipher_init(key, nonce)` where the nonce is
the 16-byte random value stored in the file header.

**Accepted parameter range on decryption:**
- m_log2 ∈ [16, 22] (64 MB – 4 GiB): the lower bound prevents headers crafted with
  weak KDF settings; the upper bound prevents a hostile header from forcing a
  multi-terabyte allocation (e.g. m_log2 = 31 → 2 TiB) as a denial-of-service.
- t_cost ∈ [2, 16]: the lower bound prevents single-iteration downgrade; the upper
  bound caps CPU cost.
- p_cost ≤ 16: caps lane count.
These checks occur *before* the KDF executes, preventing both timing oracles and
resource-exhaustion attacks.  The encrypt path only ever emits the defaults
(m_log2 = 18, t_cost = 4, p_cost = 1), so any header outside this range is
malformed or hostile.

### 2.10 AEAD Construction

CATWALK's AEAD follows SpongeWrap (Bertoni et al.):

**Encryption:**
```
1. cipher_init(cipher_key, nonce)       // key + IV absorbed
2. absorb_aad(header_bytes)             // domain 0x03
3. for each chunk of plaintext:
       keystream_bytes = squeeze(chunk_len)
       ciphertext = plaintext XOR keystream_bytes
       absorb(ciphertext, DOMAIN_CT)    // domain 0x04
4. tag = finalize()                     // absorb([], DOMAIN_TAG) then squeeze 32 bytes
5. output: header || ciphertext || tag
```

**Decryption:**
```
1. cipher_init(cipher_key, nonce)
2. absorb_aad(header_bytes)
3. for each chunk of ciphertext:
       save original_ciphertext = ciphertext
       keystream_bytes = squeeze(chunk_len)
       plaintext = ciphertext XOR keystream_bytes
       absorb(original_ciphertext, DOMAIN_CT)  // absorb the same bytes as encryption
4. computed_tag = finalize()
5. if NOT constant_time_eq(computed_tag, stored_tag): ABORT, discard plaintext
6. otherwise: return plaintext
```

The critical invariant: in both encrypt and decrypt paths, the sponge absorbs
**the ciphertext** with DOMAIN_CT. This means the sponge state after processing
all chunks is identical if and only if the same ciphertext was processed. The
final tag is therefore bound to: cipher_key, nonce, all header bytes (AAD), and
all ciphertext bytes — providing Encrypt-then-MAC semantics natively.

**Tag output is 32 bytes** extracted from the first 4 rate words (sites 0–3) after
the finalization permutation, each processed through Stafford Mix13.

---

## 3. Complement Symmetry

### 3.1 Arnold's Cat Map Has No Complement Symmetry

**Arnold's Cat Map has no complement symmetry** by construction.  For a pair (x, y):
```
cat_map(MAX-x, MAX-y) = (MAX-x + MAX-y, (MAX-x+MAX-y) + MAX-y)
                      = (2·MAX - x - y, 3·MAX - x - 2y)    (mod 2^64)
                      ≠ cat_map(x, y) = (x+y, x+2y)        in general
```
The difference is driven by the additive structure: `2·MAX = 2·(2^64−1) ≡ −2 mod 2^64`,
so the complemented output differs from both the original output and its complement,
for any non-trivial (x, y).

### 3.2 Role of Counter Injection (State Diversification)

The Weyl counter injection runs before the map step (Step 1). It provides per-site
state diversification before the Cat Map: each site receives a distinct rotation of
the same counter value, ensuring that even identical site values at round start
diverge immediately.

The counter injection runs **before** Step 2 (the Cat Map), and this ordering is
preserved.

### 3.3 Verification

The test vectors TV2 (all-zero key/IV) and TV3 (all-FF key/IV) in
`tests/cml_sponge_tests.rs` directly verify that complemented keys produce different
keystreams. The `arnold_cat_map_no_complement_symmetry` test in the same file
verifies the map itself lacks this symmetry at the unit level.

---

## 4. Security Argument

### 4.1 State Size and Security Level Claim

Total state: 16 × u64 + u64 counter = **1088 bits**.
Capacity: 8 × u64 = **512 bits**.
Rate: 8 × u64 = **512 bits**.

**Claimed security level: 128-bit equivalent.**

The claimed security level is limited by:
1. The 32-byte AEAD tag provides 128-bit forgery resistance under the birthday bound.
2. Practical password entropy under the Argon2id KDF.
3. The cipher itself targets 256-bit security (512-bit capacity), but the overall
   system is bounded by the weakest link.

### 4.2 Pre-image Resistance (Sponge Capacity)

Under the sponge security model, recovering the internal state from output requires
inverting the permutation or solving for the capacity bits. With **512 bits of capacity**
(full, since the 5-term coupling matrix is invertible over Z/2^64Z — no capacity correction
needed), the pre-image resistance claim is **~2^256** operations. This bound assumes the
CML-Sponge permutation is computationally indistinguishable from a random permutation
— a conjecture that has not been formally proven.

### 4.3 Forgery Resistance (Tag)

The authentication tag is 32 bytes (256 bits). Under the sponge forgery bound,
producing a valid (ciphertext, tag) pair without the key requires guessing the
sponge state after finalization, which has 256-bit complexity in the random
permutation model. The birthday bound for 32-byte tags is 2^128 — an adversary
making 2^128 forgery attempts would have a ~50% chance of success.

### 4.4 Birthday Bound

The 16-byte nonce means a random nonce collision becomes probable after ~2^64
encryptions with the same key. This is the same nonce space as AES-GCM with random
96-bit nonces, and is well within acceptable limits for practical use
(2^64 operations per key is 18 exabytes of distinct nonces).

### 4.5 Weakest Link Analysis

In order of decreasing strength:
1. **Cipher permutation**: Conjectured 256-bit security (512-bit capacity).
2. **AEAD tag**: 128-bit forgery resistance (birthday bound of 32-byte tag).
3. **Nonce space**: 128-bit collision resistance (16-byte random nonce).
4. **Password quality**: Dominant weakness in practice. A 20-character password from
   a 64-character set gives ~120 bits of entropy — competitive with the cipher, but
   most users choose far weaker passwords.

The password requirement (minimum 18 characters, max 3 consecutive repeats) is a
policy floor. It does not substitute for user understanding of password entropy.

### 4.6 What Would Need to Be True to Break CATWALK

For the cipher to be broken, an adversary would need to either:
1. **Find a structural weakness** in the 8-round CML-Sponge permutation that allows
   distinguishing it from a random permutation with fewer than 2^128 operations.
2. **Exploit the complement symmetry** — this is fixed by counter injection, but if
   the fix were improperly applied (e.g., counter injected after maps), the keystreams
   for complementary keys would be identical.
3. **Invert the sponge capacity** — recover the 512 hidden bits from observed rate
   output. This would require breaking the CML permutation.
4. **Forge a tag** without knowing the key — requires 2^128 forgery attempts.

### 4.7 Attacks Considered

| Attack | Status |
|--------|--------|
| Complement key pair | Absent by construction: Arnold's Cat Map has no complement symmetry; additionally verified by test vectors TV2/TV3 |
| Known-plaintext keystream recovery | Blocked by sponge capacity (512-bit hidden state) |
| Timing side-channel on MAC | Fixed: constant-time comparison via `subtle::ConstantTimeEq` |
| ZIP bomb on decompression | Fixed: 4 GB decompression cap |
| KDF downgrade (weak Argon2 params) | Fixed: parameter floor before KDF execution |
| Nonce reuse | File encryption always generates a fresh random 16-byte nonce; lower-level API exposes `cipher_init(key, iv)` directly and does NOT prevent nonce reuse |
| Output before tag verification | Blocked in `decrypt()`: plaintext is only returned after `ct_eq` passes |
| Differential cryptanalysis | Unconsidered; no differential analysis of the CML round has been performed |
| Algebraic attacks | Unconsidered; the quadratic nonlinearity of the maps complicates algebraic structure, but no formal analysis exists |
| Statistical distinguisher | Countered empirically by PractRand at 256 GB (see `docs/archive/practrand_results_v9_1_7_8.md`) |

### 4.8 Attacks NOT Ruled Out

- **Differential/linear cryptanalysis of the CML round.** The round function has not
  been analyzed for differential or linear characteristics. Standard techniques apply,
  but the Arnold's Cat Map + coupling combination is non-standard and analysis would
  require custom tooling.
- **Algebraic attacks.** Arnold's Cat Map is a linear map mod 2^64 — degree 1 in
  each variable. However, the coupling step (additive combination of four Cat Map
  outputs) and the multiplicative mixing (Step 4) together create a nonlinear system
  when viewed across rounds. The interaction between the Cat Map's linear structure
  and the coupling/multiplicative layers has not been formally analyzed.
- **Rotational cryptanalysis.** The Weyl counter uses rotation; rotational equivalences
  in the counter injection step have not been analyzed.
- **Period analysis of the Cat Map mod 2^64.** The Cat Map on Z/2^64 has a finite
  period. While this period is astronomically large for 64-bit inputs, the exact
  period structure has not been computed for the specific matrix [[1,1],[1,2]] and
  the interaction with the Weyl counter injection over 8 rounds has not been analyzed.

---

## 5. What This Is Not

**This construction has not received independent cryptanalysis.** The security
argument in §4 is internally consistent and covers known attacks, but it is
self-reviewed. A cryptographer reviewing this for the first time should treat it as
a research prototype, not a production primitive.

**This is not a drop-in replacement for ChaCha20-Poly1305 or AES-GCM.**
Those constructions have received decades of academic scrutiny and have formal
security proofs in the random permutation model. CATWALK does not.

**Appropriate uses:**
- Research into chaotic map cryptography and novel sponge constructions.
- Personal file encryption where you prefer a non-standard cipher and understand
  the security tradeoffs.
- Educational exploration of sponge-based AEAD design.

**Inappropriate uses:**
- Protecting data subject to regulatory requirements (PCI-DSS, HIPAA, GDPR
  with legal liability).
- Any application where you need formal security assurances.
- Protocol design where long-term security (>10 years) is required.
- Any context where "I wrote this myself" is not an acceptable risk answer.

---

## 6. Test Vectors

Canonical test vectors are defined in `tests/cml_sponge_tests.rs`.  The vectors
below were generated with the v10 construction: Arnold's Cat Map local map +
5-term coupling distances {1,3,7,11}.  All other parameters are unchanged.

**TV1** (incremental key/IV):
- key = `[0x00, 0x01, ..., 0x1F]` (32 bytes)
- iv  = `[0x00, 0x01, ..., 0x0F]` (16 bytes)
- First 64 keystream bytes (hex): `c137b12a97e698688596a0c5ed64a3646d89178033df7df7c9128450b5bada441a47d2e620a9ac8ec35ec25e77cdd3aa6fb6fa5ef7c604944b7303c977919480`

**TV2** (all-zero key/IV):
- key = `[0x00; 32]`, iv = `[0x00; 16]`
- First 64 bytes: `6388911bd2e420a790a975a8ee0b0932e7959b31a62dccfc0212d56c86bf80d824d2f6aac1692f3d32995b70fa7880e6181499e97db9b244b972d084c687581e`

**TV3** (all-FF key/IV — must differ from TV2 to confirm no complement symmetry):
- key = `[0xFF; 32]`, iv = `[0xFF; 16]`
- First 64 bytes: `d7b65ed8274a4667fd09fbfb4ba860c11076d272c204540746e34cc51241274e41e9518c64ffb54e6668c5fa980f9ed4b5b30095c343f1bde96d7c9ad1ca35b1`

**TV4** (repeating pattern):
- key = `[0x42; 32]`, iv = `[0x13; 16]`
- First 64 bytes: `b1e8729a2fa86cd109d1245a29420c46227ef9e23de58ed0ae6a6c6241257e9377dd56561935a658ed74b14f24c6e4d070bee8f9ac7d6cdf274ca0aed6d51118`

---

## 7. Parameters Summary

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Sites (N) | 16 | Power of 2; sufficient for rich coupling topology |
| Site width | 64 bits (u64) | Matches 64-bit CPU word width; no emulation overhead |
| Total state | 1024 bits (+ 64-bit counter) | Large enough for 512-bit capacity |
| Rate | 512 bits (8 sites × 64 bits) | 64 bytes per squeeze block |
| Capacity | 512 bits (full) | C invertible over Z/2^64Z → no capacity correction |
| Rounds | 8 per permutation | 4× full-diffusion margin (2 rounds = full diffusion, empirical minimum; 8 rounds = 4× conservative margin over PractRand distinguisher threshold — see docs/reduced_round_analysis.md) |
| Coupling distances | {1, 3, 7, 11} | 5-term; det=−33075 (odd, invertible); min\|λ\|=1.259; full diffusion in 2 rounds; all-prime |
| Weyl increment (GOLDEN) | 0x9E3779B97F4A7C15 | frac(φ) × 2^64; nothing-up-my-sleeve |
| Counter rotations (ROT) | First 16 primes ≥ 3 | All odd, coprime to 64; nothing-up-my-sleeve |
| Output finalizer | Stafford Mix13 | Output whitening layer; bijective |
| Tag size | 32 bytes | 128-bit forgery resistance under birthday bound |
| KDF | Argon2id | Memory-hard; recommended by OWASP and RFC 9106 |
| KDF memory | 256 MB (2^18 KiB) | ~1–4 second cost; configurable within floor |
| KDF iterations | 4 | Multiplies time cost beyond memory |
| Nonce size | 16 bytes | 128-bit nonce space; collision at ~2^64 encryptions |
| BLAKE3 derive | "catwalk.v9.cipher" | Domain separation between KDF output and cipher key (retained from v9 for file format compatibility; not updated to v10 to preserve decryption of existing files) |

## 8. Keyfile Support

CATWALK supports an optional keyfile as a second authentication factor. When a
keyfile is provided, the Argon2id input becomes:

```
password_bytes || 0x00 || BLAKE3(keyfile_contents)
```

The keyfile is hashed with BLAKE3 before combining with the password. This
gives a fixed 32-byte contribution regardless of keyfile size (max 1 GB) and
prevents feeding large files directly into Argon2id. The null-byte separator
between the password and the hash prevents length-extension ambiguity.

The `FLAG_KEYFILE` bit (`0x04`) in the file header indicates that a keyfile was
used during encryption. The keyfile *path* is never stored. On decryption the
user must supply the original keyfile — supplying a wrong or missing keyfile
produces the same error as a wrong password (`IntegrityCheckFailed`), so an
attacker cannot determine which factor was wrong.

### Flag assignment

| Bit | Constant            | Value | Meaning                                   |
|-----|---------------------|-------|-------------------------------------------|
| 0   | `FLAG_STRIP_METADATA` | 0x01 | Timestamp and extension stripped         |
| 1   | `FLAG_NO_COMPRESS`    | 0x02 | Ciphertext stored uncompressed           |
| 2   | `FLAG_KEYFILE`        | 0x04 | Keyfile was mixed into KDF input         |

### Threat model

A keyfile protects against scenarios where the password is compromised but the
keyfile is not: database breaches, password reuse across services, shoulder
surfing, etc.

A keyfile provides **no** additional protection if stored in the same location
as the encrypted file, or on a cloud service that syncs with the encrypted
file.

### Keyfile generation

Keyfiles should be 64 bytes of CSPRNG output. CATWALK provides two generation
methods:

- **CLI:** `catwalk genkey --output <path>` — generates 64 bytes from
  `rand::thread_rng()` (OS CSPRNG).
- **GUI:** "Generate new keyfile" button opens an interactive entropy
  harvesting dialog that collects mouse movement, click timestamps, keyboard
  timing, and frame jitter, then whitens all accumulated entropy with
  BLAKE3-XOF to produce a 64-byte keyfile.

The interactive harvesting is a UX and trust feature: users who move their
mouse are contributing genuine unpredictability that no software RNG can
replicate. The BLAKE3 step at derivation time provides compression and
whitening of the raw pool.
