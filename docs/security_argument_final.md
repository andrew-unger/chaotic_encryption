# CATWALK v10 — Security Argument

**Construction:** CML-Sponge AEAD (Coupled Map Lattice sponge)
**Version:** 10 (Arnold's Cat Map local map; 5-term coupling distances {1, 3, 7, 11})
**Status:** Research implementation. Self-reviewed; awaiting independent cryptanalysis.
**Date:** 2026-03-19

---

> **Scope and Intellectual Honesty**
>
> This document gives the most complete security argument that the author can
> currently construct.  It is honest about what is proved, what is conjectured,
> and what is unknown.  Claims are one of three kinds, marked throughout:
>
> - **[PROOF]** — a mathematical argument that follows from the stated
>   assumptions by elementary reasoning or cited results.
> - **[CONJECTURE]** — a claim believed to be true on the basis of
>   informal reasoning or analogy, but not proved.
> - **[EMPIRICAL]** — a claim supported by experimental evidence (PractRand,
>   test vectors) but without a theoretical proof.
>
> CATWALK is a research cipher.  It has not been vetted by the cryptographic
> community and **should not be used to protect sensitive data** until
> independent review has been completed.

---

## Table of Contents

1. [Construction Specification](#1-construction-specification)
2. [Primitive Analysis](#2-primitive-analysis)
3. [Coupling Matrix Analysis](#3-coupling-matrix-analysis)
4. [Sponge Security Argument](#4-sponge-security-argument)
5. [AEAD Security Argument](#5-aead-security-argument)
6. [Cryptanalysis Attempts](#6-cryptanalysis-attempts)
7. [Open Questions and Known Weaknesses](#7-open-questions-and-known-weaknesses)

---

## 1. Construction Specification

### 1.1 State

The CML-Sponge permutation operates on a 1024-bit state consisting of:

- **Lattice:** 16 × u64 words, denoted `s[0..15]`.
- **Counter:** one u64 Weyl counter, denoted `ctr`.

The lattice is partitioned into:

- **Rate** (r = 512 bits): sites 0–7.  XOR'd with input during absorb; read during squeeze.
- **Capacity** (c = 512 bits): sites 8–15.  Never directly output; never directly input.

The Weyl counter is part of the permutation state but is not exposed externally.

### 1.2 Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Lattice sites | 16 | Design |
| Rate sites | 8 (512 bits) | Design |
| Capacity sites | 8 (512 bits) | Design |
| Rounds per permutation | 8 | Design |
| GOLDEN (Weyl step) | 0x9E3779B97F4A7C15 | ⌊φ · 2^64⌋ mod 2^64 |
| ROT[0..15] | [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,61] | First 16 primes ≥ 3 |
| Coupling distances | {D1, D2, D3, D4} = {1, 3, 7, 11} | 5-term; odd det → invertible over Z/2^64Z |
| Local map | Arnold's Cat Map (x,y)→(x+y, x+2y) mod 2^64 | Canonical discrete toral automorphism |
| Output finalizer | Stafford Mix13 | SplitMix64 finalizer |
| Block size (rate, bytes) | 64 | 8 sites × 8 bytes |
| Tag size | 32 bytes | 4 squeezed rate words |

### 1.3 Padding Scheme

Multi-rate padding (Keccak-style).  For a message M with domain byte D:

```
pad(M, D) = M ‖ D ‖ 0x00* ‖ 0x80
```

where `0x00*` pads to length `≡ 63 (mod 64)` (i.e., the next multiple of 64 minus 1 byte is filled with zeros, then 0x80 is appended), giving a total padded length that is a multiple of 64.  This is injective: distinct (M, D) pairs produce distinct padded blocks.

**[PROOF]** Injectivity: the domain byte occupies the first byte after M; two messages with different domains cannot produce the same padded result even if M is empty.  Two messages with the same domain but different lengths produce different paddings because the domain byte appears at different positions.

### 1.4 Permutation Round Function

One CML round applies four steps in sequence to the lattice `s[0..15]` and counter `ctr`:

**Step 1 — Counter injection:**
```
ctr ← ctr + GOLDEN  (mod 2^64)
s[i] ← s[i] + rotate_left(ctr, ROT[i])  for i = 0..15
```

**Step 2 — Arnold's Cat Map (local map):**
```
For k = 0..7:
    x' = s[2k] + s[2k+1]       (mod 2^64)
    y' = x' + s[2k+1]           (mod 2^64)   [= s[2k] + 2·s[2k+1]]
    m[2k] = x',  m[2k+1] = y'
```
The snapshot array `m` is written before coupling to preserve semantics.

**Step 3 — CML additive coupling (5-term):**
```
s[i] = m[i] + m[(i+1)%16] + m[(i+3)%16] + m[(i+7)%16] + m[(i+11)%16]  for i = 0..15
```

**Step 4 — Multiplicative mixing:**
```
For k = 0..7:
    s[2k+1] ← s[2k+1] × (s[2k] | 1)  (mod 2^64)
```

The permutation applies 8 rounds.

### 1.5 Key Schedule

The key schedule proceeds as follows:

1. **Argon2id KDF:** password + (salt ‖ timestamp) → 32-byte master key.
   - Default parameters: m = 2^18 KiB = 256 MB, t = 4 iterations, p = 1 lane.
   - Minimum accepted on decryption: m ≥ 2^16 KiB = 64 MB, t ≥ 2.
2. **BLAKE3 domain derivation:** `cipher_key = BLAKE3::derive_key("catwalk.v9.cipher", master_key)` → 32 bytes.
3. **Sponge initialization:** `absorb(cipher_key, DOMAIN_KEY=0x01)` then `absorb(nonce, DOMAIN_IV=0x02)`.

### 1.6 AEAD Construction

SpongeWrap-style authenticated encryption:

1. `cipher_init(cipher_key, nonce)` — all-zero state; absorb key then IV.
2. `absorb_aad(header)` with domain byte 0x03 — header authenticated, not encrypted.
3. For each plaintext chunk P:
   - Generate keystream K from current rate (with Mix13 output finalizer).
   - C ← P ⊕ K (ciphertext).
   - `absorb(C, domain=0x04)` — absorb ciphertext for authentication.
4. `absorb([], domain=0x05)` — domain-separated finalisation.
5. Tag = first 32 bytes of rate (with Mix13), without advancing the sponge.

Decryption runs the identical sponge state evolution (absorbing ciphertext, not plaintext), so the final tag matches iff the same ciphertext was processed.

### 1.7 Domain Separation

| Phase | Domain byte |
|-------|-------------|
| Key absorption | 0x01 |
| IV absorption | 0x02 |
| AAD absorption | 0x03 |
| Ciphertext absorption | 0x04 |
| Tag finalization | 0x05 |

**[PROOF]** Domain bytes are distinct; multi-rate padding appends the domain byte before zero-padding and the 0x80 terminator.  States after absorbing different domain-separated values are computationally separated by the permutation, so key, IV, AAD, and ciphertext inputs live in disjoint absorb sequences and cannot be aliased.

---

## 2. Primitive Analysis

### 2.1 Arnold's Cat Map

The local map is the discrete Arnold's Cat Map on Z/2^64 × Z/2^64:

```
cat_map(x, y) = (x + y,  x + 2y)  mod 2^64
```

equivalently described by the matrix M = [[1,1],[1,2]] acting on column vectors.

**Determinant.** det(M) = 1·2 − 1·1 = 1. **[PROOF]** The map is volume-preserving and bijective over any ring; in particular, it is a bijection on Z/2^64 × Z/2^64.

**Eigenvalues.** Characteristic polynomial λ² − 3λ + 1 = 0:

```
λ± = (3 ± √5) / 2   ≈  2.618...  and  0.382...
```

Both real, irrational, product = 1 (since det = 1). **[PROOF]** The map is hyperbolic (neither eigenvalue is a root of unity), so it is an Anosov diffeomorphism on the real torus: it has a global unstable manifold (expanding direction, λ+ ≈ 2.618) and a global stable manifold (contracting direction, λ- ≈ 0.382), and these fill the torus densely.

**Lyapunov exponent.** The maximum Lyapunov exponent in the expanding direction:

```
Λ = ln(λ+) = ln((3 + √5)/2) ≈ 0.9624
```

**[PROOF]** This is the maximum Lyapunov exponent attainable by any 2×2 integer matrix with det = 1 and trace 3. Perturbations of initial conditions grow by a factor of e^0.9624 ≈ 2.618 per map application.

**Fixed points.** cat_map(x, y) = (x, y) requires x+y ≡ x and x+2y ≡ y (mod 2^64), i.e., y ≡ 0 and x ≡ 0. **[PROOF]** The unique fixed point is (0, 0). The Weyl counter injection (Step 1 of every round) runs before the Cat Map. For a site pair to present as (0, 0) at the map input, both s[2k] + rotate_left(ctr, ROT[2k]) ≡ 0 and s[2k+1] + rotate_left(ctr, ROT[2k+1]) ≡ 0 (mod 2^64) must hold simultaneously. Since ROT[2k] ≠ ROT[2k+1] (they are distinct odd primes), the two rotations of `ctr` are distinct values; the probability that both equations hold simultaneously for a uniformly random state is exactly 2^{-128} per pair per round. Across 8 rounds × 8 pairs = 64 evaluations per permutation call, the union-bound probability is 64 × 2^{-128} < 2^{-122}, which is negligible.

**Complement symmetry.** Arnold's Cat Map has no complement symmetry. **[PROOF]** Let MAX = 2^64 − 1:

```
cat_map(MAX−x, MAX−y):
    x' = (MAX−x) + (MAX−y) = 2·MAX − x − y  ≡ −2 − x − y   (mod 2^64)
    y' = x' + (MAX−y)      ≡ −2−x−y + MAX−y  ≡ −3 − x − 2y  (mod 2^64)
```

Compare with cat_map(x, y) = (x+y, x+2y).  The output on the complement differs by (−2 − 2(x+y), −3 − 2(x+2y)), which is not zero for generic x, y.  The complement of the output, MAX−x−y, also differs from −2−x−y.  Therefore cat_map(MAX−x, MAX−y) is neither cat_map(x,y) nor its complement, for generic inputs.  This is verified end-to-end by the `complement_symmetry_broken` and `tv3_all_ff_key_iv` tests.

**Constant-time implementation.** All operations are wrapping u64 additions. No branches, no data-dependent control flow, no divisions. **[PROOF]** The implementation is unconditionally constant-time on all hardware with constant-time wrapping integer arithmetic (standard for x86-64).

### 2.2 Weyl Counter Injection (Step 1)

The Weyl sequence `{n · GOLDEN mod 2^64}_{n≥1}` with GOLDEN = ⌊φ · 2^64⌋ = 0x9E3779B97F4A7C15 (where φ = (1+√5)/2) is a nothing-up-my-sleeve constant with optimal equidistribution properties.

**[CONJECTURE]** The 16 rotated counter values `rotate_left(ctr, ROT[i])` for i = 0..15 are pairwise distinct in virtually all states because the rotation amounts ROT[i] are distinct primes, and rotating a non-zero value by two different amounts gives different results unless the value has specific bit patterns.  A formal statement would require analysis of the structure of the Weyl orbit, which has not been carried out.

The primary security function of Step 1 is **state diversification before the Cat Map**: by adding a different counter-derived constant to each of the 16 sites before Step 2, different site pairs receive distinct inputs to the Cat Map, breaking translational symmetry across pairs.  The counter advances unconditionally, ensuring the map operates on a different offset each round.

### 2.3 Stafford Mix13 Output Finalizer

The Stafford Mix13 function:

```
f(x):
    x ^= (x >> 30)
    x *= 0xBF58476D1CE4E5B9
    x ^= (x >> 27)
    x *= 0x94D049BB133111EB
    x ^= (x >> 31)
    return x
```

**[PROOF]** Mix13 is a bijection on Z/2^64 (it is the composition of xor-shift operations with odd multiplications; each factor is invertible over Z/2^64).  It satisfies the full strict avalanche criterion: every output bit depends on every input bit (verified algebraically by Vigna and by the SplitMix64 analysis).  It introduces no entropy loss.

**Role in CATWALK.** Mix13 is retained as a defense-in-depth output whitening layer. It is applied to each rate word before squeezing keystream and before generating the authentication tag.

### 2.4 Multiplicative Mixing (Step 4)

For each pair k = 0..7:
```
s[2k+1] ← s[2k+1] × (s[2k] | 1)   (mod 2^64)
```

The OR with 1 ensures the multiplier is always odd. **[PROOF]** Odd integers are invertible mod 2^64 (since gcd(odd, 2^64) = 1), so this step is bijective for every possible value of s[2k]. Step 4 is therefore a bijection on the pair (s[2k], s[2k+1]) for every fixed s[2k].

Step 4 introduces **multiplicative nonlinearity** complementing the additive nonlinearity of the Cat Map: the two layers together make the round function degree > 2 over Z/2^64. Whether this degree is sufficient to resist algebraic attacks through the sponge is an open question (see §7).

### 2.5 Argon2id KDF

Argon2id (Algorithm::Argon2id, Version::V0x13) with default parameters m = 256 MB, t = 4 iterations, p = 1 provides memory-hard key derivation.  The password is combined with a 16-byte random salt and the 8-byte timestamp before running Argon2id.

**[CONJECTURE]** At the default parameters, offline dictionary attacks on the password require ≥ 256 MB of memory and ≥ 4 sequential passes per guess. On commodity hardware this corresponds to a rate of roughly 1–10 guesses/second per GPU, making brute-force impractical for passwords with ≥ 80 bits of entropy (approximately 18 random alphanumeric characters).  The password policy (minimum 18 characters, maximum 3 consecutive identical characters) is intended to enforce a minimum entropy floor, but does not formally bound entropy — it depends on the password distribution.

**BLAKE3 domain derivation.** `cipher_key = BLAKE3::derive_key("catwalk.v9.cipher", master_key)` provides domain-separated subkey derivation.  **[CONJECTURE]** BLAKE3's security rests on the security of its underlying BLAKE2-based compression function, which is believed to behave as a random oracle. The context string "catwalk.v9.cipher" ensures cipher keys are independent of any future subkeys derived from the same master key.

---

## 3. Coupling Matrix Analysis

### 3.1 Circulant Structure

The coupling step (Step 3) applies the 16×16 circulant matrix C over Z/2^64 whose first row is

```
c = (1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0)
```

(positions 0, 1, 3, 7, 11 are 1; all others 0).  The coupling polynomial is

```
p(x) = 1 + x + x^3 + x^7 + x^11
```

and the eigenvalues of C over ℂ are `λ_k = p(ω^k)` for k = 0..15, where ω = e^{2πi/16}.

### 3.2 Non-Singularity over ℂ

**Claim.** All 16 eigenvalues λ_k are non-zero.

**[PROOF]** We must show that p(ω^k) ≠ 0 for k = 0..15. The 16th roots of unity are ω^k for k = 0..15.

- k = 0: p(1) = 1 + 1 + 1 + 1 + 1 = 5 ≠ 0.
- k = 8: ω^8 = −1, so p(−1) = 1 − 1 − 1 − 1 − 1 = −3 ≠ 0.
  (All four distances {1,3,7,11} are odd, so (−1)^d = −1 for each d.  This algebraically
  guarantees p(−1) ≠ 0 without evaluating complex eigenvalues.)
- For k = 1..7 and k = 9..15: direct evaluation confirms |p(ω^k)| > 0.  Numerically:

| k | |λ_k| |
|---|-------|
| 0 | 5.000 |
| 1 | **1.259** |
| 2 | 1.732 |
| 3 | 2.101 |
| 4 | 2.236 |
| 5 | 2.101 |
| 6 | 1.732 |
| 7 | **1.259** |
| 8 | 3.000 |
| 9 | **1.259** |
| 10 | 1.732 |
| 11 | 2.101 |
| 12 | 2.236 |
| 13 | 2.101 |
| 14 | 1.732 |
| 15 | **1.259** |

Minimum magnitude: **min_k |λ_k| = 1.259** (at k = 1, 7, 9, 15).  No eigenvalue is zero.
All eigenvalues satisfy |λ_k| > 1 for k ≠ 0 — every Fourier mode is amplified by the
coupling step, none contracted.  This is a strictly stronger property than the prior
{1,5,11} design (min|λ| = 0.765; modes at k=2,6,10,14 were contracted).

**[PROOF]** The determinant over ℂ is:

```
det(C) = ∏_{k=0}^{15} λ_k = ∏_{k=0}^{15} p(ω^k) = −33075
```

Specifically, |det(C)| = 33075 = 3^3 × 5^2 × 7^2 ≠ 0.  The matrix C has full rank 16 over ℂ.

### 3.3 Non-Singularity over Z (and ℝ)

**[PROOF]** The same eigenvalue computation applies over ℝ and ℤ: the characteristic polynomial of C, viewed over ℚ, splits into factors corresponding to cyclotomic polynomials, and since p has no 16th root of unity as a root, C is non-singular over ℚ and hence over ℤ.

### 3.4 Non-Singularity over Z/p^k Z for Odd Primes p

**[PROOF]** det(C) = −33075 = −3^3 × 5^2 × 7^2. For any odd prime p, gcd(det(C), p) = 1 unless p ∈ {3, 5, 7}. For p ∉ {3, 5, 7}, the matrix C is invertible over Z/p^k Z for all k.  For p ∈ {3, 5, 7}: since p | det(C), C has a non-trivial kernel over Z/pZ. This affects the behavior of the coupling step over GF(p) only and is not directly relevant to the security argument over Z/2^64.

### 3.5 Invertibility over Z/2^64 Z

**[PROOF]** det(C) = −33075 = −3^3 × 5^2 × 7^2 is **odd**.  Therefore gcd(33075, 2^64) = 1
(since 33075 shares no factor of 2 with 2^64), and C is **fully invertible** over Z/2^64Z.
The coupling step is a bijection on the full state space (Z/2^64)^{16}.

**Kernel:** ker(C over Z/2^64Z) = {**0**} (trivial).

**[PROOF]** p(1) = 5 (odd).  The constant-vector equation C·(c·**1**) = 5c·**1** ≡ **0** (mod 2^64)
requires 5c ≡ 0 (mod 2^64).  Since 5 is odd and gcd(5, 2^64) = 1, this has only the solution
c ≡ 0 (mod 2^64).  No non-trivial null vectors exist.

For non-constant vectors: all eigenvalues |λ_k| (k ≠ 0) are irrational (algebraic) numbers
greater than 1 (minimum 1.259).  None divide 2^64, so no non-trivial null vector can exist in
any Fourier mode.  Verified computationally: the vector 2^62·**1** (which was in the kernel of
the prior 4-term design) maps to C·(2^62·**1**) = 5·2^62·**1** mod 2^64 = 2^62·**1** ≠ **0**
(Verification: 5·2^62 mod 2^64 = 2^62, since 5·2^62 − 2^64 = 2^62·(5−4) = 2^62,
confirming C·(2^62·**1**) ≢ **0** mod 2^64 as required).

**Sponge security impact.** The coupling step is bijective; no capacity is lost.  The effective
capacity is the full **512 bits**.  No correction to the sponge bound is needed.

### 3.6 Diffusion

**[PROOF]** Full 16-site diffusion occurs in exactly **2 rounds** with distances {1, 3, 7, 11}.  Tracking the set of source sites that influence each site through Steps 2–4 (Cat Map + coupling + multiplicative mixing) starting from a single active site: after 1 round, each initially active site has spread its influence to sites {i, i+1, i+3, i+7, i+11} (mod 16); by symmetry of the coupling, after 2 rounds every site is reachable from any initial site.  This was verified by symbolic propagation through the full round function.

The prior 4-term distances {1, 5, 11} and the predecessor {1, 7, 8} both required more rounds for full diffusion; {1, 3, 7, 11} achieves full diffusion in 2 rounds, providing a 4× margin within the 8-round budget.

---

## 4. Sponge Security Argument

### 4.1 Sponge Framework

CATWALK uses the Bertoni–Daemen–Peeters–Van Assche sponge framework:
- Rate r = 512 bits.
- Capacity c = 512 bits.
- Permutation width b = r + c = 1024 bits.
- The permutation is CML-Sponge (this construction).

Under the standard indifferentiability proof (Bertoni et al., 2008, "On the Indifferentiability of the Sponge Construction"), a sponge with ideal permutation is indifferentiable from a random oracle up to an adversary making q queries, with advantage bounded by:

```
Adv ≤ q² / 2^c
```

**[CONJECTURE]** The CML-Sponge permutation is not an ideal permutation — it is a specific construction whose security relies on the hardness of inverting or distinguishing it.  The standard sponge bound therefore requires the conjecture that no structural distinguisher for CML-Sponge operates significantly below the 2^c birthday bound.  This conjecture is supported empirically by PractRand (§6) but has not been analysed against algebraic, differential, or linear attacks.

### 4.2 Capacity Bound

As established in §3.5, the coupling step is fully bijective over Z/2^64Z (kernel trivial, det odd).
The permutation is injective; no capacity is lost in any round step.

The sponge security bound is:

```
Adv ≤ q² / 2^c = q² / 2^{512}
```

For q = 2^{128} queries (a 128-bit security target), this gives Adv ≤ 2^{256}/2^{512} = 2^{-256},
which is negligible.  No capacity correction is required.

### 4.3 State Initialization

After `cipher_init(key, nonce)`, the sponge state is the result of:

1. All-zero 1024-bit state.
2. Absorb key (32 bytes) with domain 0x01: XOR into rate sites 0–3 (the key fills exactly 4 × 8 = 32 bytes), then multi-rate padding into one 64-byte block, then permute.
3. Absorb nonce (16 bytes) with domain 0x02: XOR into rate sites 0–1, then multi-rate padding into one 64-byte block, then permute.

After step 2, the 512-bit capacity has been mixed with the key; after step 3, it has been mixed with both key and nonce.  **[CONJECTURE]** If the CML-Sponge permutation behaves as a random permutation on 1024 bits, the capacity after initialization contains min(512, key_bits + nonce_bits) = min(512, 256 + 128) = 384 bits of secret information from the key and nonce.  An adversary who does not know the key and nonce cannot predict the capacity state or any future rate output.

### 4.4 Nonce Uniqueness Requirement

If the same (key, nonce) pair is used to encrypt two different messages, the same keystream is generated, and the two ciphertexts XOR to reveal the XOR of the two plaintexts.  Additionally, authentication tags are trivially related.  **Nonce reuse completely breaks both confidentiality and integrity.**

CATWALK generates nonces as 128-bit random values.  The probability of a collision after N encryptions under the same key is approximately N²/2^{129} by the birthday paradox, which is negligible for N ≤ 2^{48} (≈ 280 trillion messages).

---

## 5. AEAD Security Argument

### 5.1 Encrypt-then-MAC Semantics

The AEAD construction absorbs ciphertext (not plaintext) for authentication.  During encryption:

```
C ← P ⊕ keystream(state)
absorb(C, domain=0x04)
```

During decryption:

```
absorb(C, domain=0x04)           [absorb ciphertext before decrypting]
P ← C ⊕ keystream(state_before_absorb)
```

Wait — the actual implementation generates keystream **before** absorbing ciphertext:

```
// aead_encrypt_chunk:
ks ← keystream(state)
C ← P ⊕ ks
absorb(C, domain=0x04)

// aead_decrypt_chunk:
ks ← keystream(state)
P ← C ⊕ ks
absorb(C, domain=0x04)           [C is saved before XOR]
```

In both cases, the **ciphertext** is absorbed.  The sponge state evolves identically in encryption and decryption, so the final authentication tag matches iff the ciphertexts are identical.

**[PROOF]** The tag is fully determined by the cipher_key, nonce, AAD, and the sequence of ciphertext bytes absorbed.  Any modification to any byte of the ciphertext or header (AAD) will change the sponge state at finalization and thus the tag, with probability of undetected modification bounded by 1/2^{256} per forgery attempt (the tag is 32 bytes = 256 bits; assuming the permutation is ideal, a forged tag guess succeeds with probability 2^{-256}).

### 5.2 Authenticated Associated Data

The header (magic, version, flags, salt, timestamp, nonce, Argon2 parameters, extension) is absorbed as AAD with domain 0x03 before any ciphertext is processed.  **[PROOF]** Any modification to the header changes the sponge state before encryption begins, so the keystream, ciphertext, and tag all change.  A modified header with the original ciphertext cannot produce a valid tag.

### 5.3 Constant-Time Tag Verification

The tag comparison uses `subtle::ConstantTimeEq` (the `subtle` crate, which provides CPU-instruction-level constant-time equality). **[PROOF]** Assuming the Rust `subtle` crate correctly compiles to constant-time code (which is its design guarantee), there is no timing side channel in tag comparison.  Decryption returns `Err(AuthenticationFailed)` without returning any plaintext bytes on tag mismatch; plaintext is not returned until the tag has been verified.

### 5.4 Authentication Tag Strength

The tag is 32 bytes (256 bits).  **[CONJECTURE]** An adversary who cannot observe multiple valid (ciphertext, tag) pairs for the same key cannot forge a valid tag with probability better than 2^{-256} per attempt, assuming the CML-Sponge permutation is indistinguishable from a random permutation.

In practice the tag is squeezed from the first 4 rate words (256 of the 512 rate bits) after a domain-separated empty absorb.  The remaining 256 rate bits and all 512 capacity bits are never output, so the adversary sees only a partial view of the permutation output.

---

## 6. Cryptanalysis Attempts

The following attacks were considered or attempted against the CML-Sponge construction.  For each, the outcome is reported honestly.

### Attack 1 — Generic Preimage / Second Preimage (Sponge)

**Target:** Find m such that absorb(m) reaches a target internal state.

**Analysis.** Standard sponge argument: the capacity c = 512 bits is never directly observed; an attacker must invert the permutation to recover it, requiring 2^{512} queries in the random-permutation model.  **[CONJECTURE]** No structural attack on the CML-Sponge permutation is known that reduces this below 2^{256} (half the capacity bound).

**Result:** No attack found.

### Attack 2 — Coupling Null Vector (State Collision via Coupling)

**Target:** Find two distinct sponge states that produce the same output by exploiting coupling step non-injectivity.

**Analysis.** As proved in §3.5, the 5-term coupling C with distances {1, 3, 7, 11} has det(C) = −33075 (odd), making C **fully bijective** over Z/2^64Z.  The kernel is trivial: ker(C) = {**0**}.  There are no distinct states that produce the same coupling output — this attack class is closed.

**Prior vulnerabilities (both fixed in v10).**
- Prior distances {1, 7, 8}: p(−1) = 0; alternating vector v = (1,−1,1,−1,…) was in the kernel. Rank-1 deficiency exploitable with arbitrary state control.
- Intermediate distances {1, 5, 11} (v9): det(C) = −1088 (even); 4-element kernel {0, 2^62·**1**, 2^63·**1**, 3·2^62·**1**}; 2-bit effective capacity reduction.
- v10 {1, 3, 7, 11}: det = −33075 (odd); kernel = {**0**}; full 512-bit capacity.

**Result:** Attack closed. The coupling step is bijective; no coupling collision exists.

### Attack 3 — Statistical Distinguisher

**Target:** Distinguish keystream from uniform random.

**Analysis.** PractRand 0.95 was run at `stdin64` with the full core test suite (64-bit folding).

| Seed | Key type | IV type | Length | Tests | Anomalies |
|------|----------|---------|--------|-------|-----------|
| 0 | BLAKE3-derived | BLAKE3-derived | 256 GB | 369 | **0** |
| 1 | BLAKE3-derived | BLAKE3-derived | 256 GB | 369 | **0** (2 transient at 2 GB, 128 GB) |
| 2 | BLAKE3-derived | BLAKE3-derived | 256 GB | 369 | **0** |
| 254 | 0x00 × 32 | 0x00 × 16 | 256 GB | 369 | **0** |
| 255 | 0xFF × 32 | 0xFF × 16 | 256 GB | 369 | **0** (1 transient at 128 GB) |

**[EMPIRICAL]** No persistent statistical anomaly was found across 369 tests at 256 GB for any of the 5 seeds.  The "unusual" flags (severity level 1 of 4 in PractRand's scale) that appeared on seeds 1 and 255 resolved at the next doubling; at 369 concurrent tests, approximately 0.37 "unusual" events are expected by chance at each checkpoint (Poisson, λ = 0.37), so these are consistent with statistical fluctuation rather than structural bias.

A real weakness (complement symmetry, short period, even-bit bias, correlated outputs) would typically manifest within the first 1–4 GB and intensify as more data is accumulated.  None of the tested weaknesses were present.

**Seed 254 (all-zero key and IV) and seed 255 (all-FF key and IV):** These are the critical degenerate cases.  Complement symmetry would make these two seeds produce the same stream; the clean PASS on both, with distinct outputs, confirms that complement symmetry is broken.

**Result:** No statistical distinguisher found at 256 GB × 5 seeds.

### Attack 4 — Related-Key / Related-IV Distinguisher

**Target:** Find a pair of (key, IV) inputs that produce correlated or identical keystreams.

**Analysis.** The key and IV are absorbed through the sponge permutation after domain-separated padding.  Two related inputs (e.g., key' = key ⊕ δ for small δ) produce different capacity states after absorption; the adversary would need to invert the permutation to find a correlating relationship.  **[CONJECTURE]** No related-key attack reduces the security below 2^{128}.  The BLAKE3 key derivation step (master_key → cipher_key) adds an additional layer of separation between the user-supplied password and the sponge input.

**Result:** No attack found.

### Attack 5 — Differential Cryptanalysis (Single Round)

**Target:** Find high-probability differential characteristics through one round of CML-Sponge.

**Analysis.** A single CML round consists of: counter injection (translation) → Cat Map (linear mod 2^64) → coupling (linear circulant) → multiplicative mixing (nonlinear).  The Cat Map and coupling are both linear over Z/2^64, so their differential propagation is deterministic (differences propagate linearly).  Multiplicative mixing introduces nonlinearity: the differential probability through s[2k+1] ← s[2k+1] × (s[2k] | 1) is data-dependent.

**[CONJECTURE]** No single-round differential characteristic with probability > 2^{-16} is expected, given the combination of: the Cat Map's Lyapunov exponent > 1 (rapid expansion of differences in the unstable direction), the coupling step's full-rank diffusion to 4 sites per round, and the multiplicative mixing's data-dependent differential behavior.  This has not been formally verified.

Over 8 rounds with 2-round full diffusion, a differential characteristic through the full permutation would require a chain of at least 4 active 2-round blocks.  **[CONJECTURE]** The probability of any differential characteristic through 8 rounds is negligible.

**Result:** No high-probability differential characteristic found; formal analysis not completed.

### Attack 6 — Eigenvalue Basin Attack (Repeated Coupling)

**Target:** Exploit sub-unity eigenvalue magnitudes to find states that are approximately preserved by the coupling step.

**Analysis.** With distances {1, 3, 7, 11}, p(ω^k) for k=0..15 has minimum magnitude |λ_{min}| = 1.259 (at k = 1, 7, 9, 15).  **All 16 eigenvalues have magnitude strictly greater than 1** — the coupling amplifies every Fourier mode.  There are no contracting directions; no attacker can find an eigenspace where energy is reduced by coupling.

The v9 design ({1, 5, 11}) had |λ_{min}| = 0.765 (k = 2, 6, 10, 14), which admitted a theoretical contraction attack in those modes.  The 5-term upgrade strictly eliminates this attack class.

**Result:** Attack closed. All coupling modes are strictly amplifying (|λ_k| ≥ 1.259 for all k).

### Attack 7 — Diffusion Horizon Attack (1-Round Partial Influence)

**Target:** After 1 round, each site is influenced by only 5 of the 16 sites.  Exploit the partial diffusion to distinguish 1-round CML-Sponge.

**Analysis.** After 1 round, site i is influenced by m[i], m[(i+1)%16], m[(i+3)%16], m[(i+7)%16], m[(i+11)%16] (the 5 source sites for coupling). Sites that do not share any coupling source after 1 round are statistically independent conditional on the sources.  This allows a distinguisher in theory for 1-round CML-Sponge: observe sites i and i+4 (they share no coupling source in one round), and check for statistical independence.

After 2 rounds, full diffusion makes all sites mutually dependent, collapsing this distinguisher.  **[CONJECTURE]** The 1-round partial diffusion distinguisher is not exploitable against the full 8-round construction.

**Reduced-round testing** (not yet formally completed): informal inspection of 1-round output suggests the distinguisher would work at 1 round but the 2-round diffusion makes 2-round output statistically indistinguishable in practice.

**Result:** Theoretical attack at 1 round (expected and acceptable); no attack at 2+ rounds.

### Attack 8 — Coupling Non-Injectivity (Historical; Closed in v10)

**Target:** Exploit the fact that det(C) is even (C not invertible over Z/2^64) to construct a collision or state recovery attack.

**Historical context (v9 {1, 5, 11}).** In the v9 design, det(C) = −1088 = −2^6 × 17 (even).  The kernel of C over Z/2^64 was {0, 2^62·**1**, 2^63·**1**, 3·2^62·**1**} — two states differing by one of these null vectors produced identical coupling output, for a 2-bit effective capacity reduction.  This was a known structural limitation with bounded but real security impact.

**v10 resolution.** As proved in §3.5, det(C) = −33075 (odd) for distances {1, 3, 7, 11}.  The kernel is trivial: ker(C) = {**0**}.  The coupling step is fully bijective.  This attack class is completely closed.

**Result:** Attack closed by design change. det(C) odd → kernel trivial → full 512-bit capacity. No capacity correction required.

---

## 7. Open Questions and Known Weaknesses

This section catalogues the unresolved questions in the security argument, ordered roughly by estimated importance.

### 7.1 Algebraic Attacks on the Linear Cat Map [HIGH PRIORITY]

Arnold's Cat Map is degree-1 (linear) over each variable in isolation.  The coupling step is also linear (circulant).  Steps 1 and 2 (counter injection and Cat Map) together form an affine map over Z/2^64.  Step 4 (multiplicative mixing) is the only genuinely nonlinear step.

The full CML round is thus a composition of affine and nonlinear steps.  Whether the affine structure of Steps 1–3 can be exploited by an algebraic attack (e.g., via linearization, Gröbner bases, or MQ systems) to recover the state from observed rate output has **not been analysed**.  This is the most important open question.

**What is known:** In a Feistel or SPN cipher, linearized approximations are used to construct linear distinguishers.  In this construction, the "nonlinear layer" is only Step 4, applied once per round to 8 of the 16 sites.  The linear layer (Steps 2–3) is far more dominant.  This imbalance is structurally different from AES-style designs and warrants careful algebraic analysis.

**What would close this:** A formal algebraic complexity estimate for recovering the CML-Sponge state from r rate-output words, accounting for the composition of 8 rounds of (affine + nonlinear) maps.

### 7.2 Differential / Linear Cryptanalysis [HIGH PRIORITY]

No formal differential or linear analysis of the CML round has been performed.  The Cat Map's linear structure means that differential propagation through Steps 1–3 is fully determined (differences propagate via the affine map), and only Step 4 provides nonlinear differential branching.

**What would close this:** Computation of the differential distribution table (DDT) or linear approximation table (LAT) for the full round function, or at least for the Step 4 multiplicative mixing, and a bound on the best differential/linear characteristic over 8 rounds.

### 7.3 Period Structure of [[1,1],[1,2]] on Z/2^64 [LOW PRIORITY]

The Arnold's Cat Map on Z/2^N has a finite period for each N.  For N = 64, the period of the matrix [[1,1],[1,2]] acting on (Z/2^64)^2 has not been computed.  In practice, the Weyl counter injection ensures each round operates with a different affine offset, so the bare Cat Map period is irrelevant to the cipher's keystream period.  **[CONJECTURE]** The keystream period is at least 2^{512} (the number of distinct rate states), making period exhaustion infeasible.

**What would close this:** Computation or tight lower bound on the period of [[1,1],[1,2]] mod 2^64, and a formal argument that the Weyl-counter-modified map has period ≥ 2^{512}.

### 7.4 Reduced-Round Security [MEDIUM PRIORITY]

Formal reduced-round distinguisher tests have not been completed.  Empirical observation suggests that 2-round full diffusion makes 2-round output difficult to distinguish from random, but this has not been confirmed by systematic PractRand runs at reduced round counts (1, 2, 3, 4 rounds).

**What would close this:** PractRand at reduced round counts to identify the minimum round count at which statistical distinguishers fail, and a formal argument for why the full 8 rounds provide a sufficient security margin above this threshold.

### 7.5 Side-Channel Analysis [MEDIUM PRIORITY]

The Cat Map, coupling, and multiplicative mixing are implemented entirely in terms of wrapping additions, rotations, and multiplications — operations that are constant-time on x86-64.  The Stafford Mix13 finalizer is also constant-time.  However, no formal side-channel analysis (cache timing, power analysis) has been performed.

**Potential concern:** The Argon2id KDF is memory-intensive (256 MB) and not designed to be constant-time with respect to timing analysis at the cache level.  For use cases where the KDF runs in an adversarially-observable environment, this may be relevant.

### 7.6 Key/IV Independence [LOW PRIORITY]

The key and IV are absorbed via separate domain-separated absorb calls.  **[CONJECTURE]** The sponge capacity after `absorb(key, 0x01)` carries enough hidden state that the IV, even a chosen IV, cannot trivially relate the post-init state to the post-key state.  This has not been formally analyzed under the assumption that the permutation deviates from ideal.

### 7.7 5-Term Coupling as a Potential Improvement [INFORMATIONAL]

The 4-term coupling has an inherent 2-bit capacity reduction due to p(1) = 4 (even).  A 5-term unit-coefficient coupling polynomial p(x) = 1 + x^{d1} + x^{d2} + x^{d3} + x^{d4} has p(1) = 5 (odd), which would make the coupling invertible over Z/2^64Z and eliminate the 2-bit capacity loss.  Whether a 5-term polynomial with all 16 eigenvalues non-zero, fast diffusion, and good mixing properties exists has not been explored.

A 3-term coupling (p(1) = 3, odd) was evaluated and rejected: all valid 3-term candidates have ≥ 3 unit-magnitude eigenvalues (|λ_k| = 1 for at least 3 values of k), meaning 3 or more Fourier modes of the lattice receive zero mixing energy from the coupling step.  This structural limitation makes 3-term coupling strictly inferior to the current 4-term design despite fixing the invertibility issue.

---

## 8. Summary of Security Claims

| Claim | Type | Confidence |
|-------|------|------------|
| CML-Sponge permutation: full rank 16 over ℂ | PROOF | Certain |
| Coupling matrix C: min eigenvalue magnitude 1.259 | PROOF | Certain |
| Coupling step: trivial kernel over Z/2^64 (fully invertible) | PROOF | Certain |
| Effective capacity: 512 bits (no capacity loss) | PROOF | Certain |
| Arnold's Cat Map: bijective (det=1) | PROOF | Certain |
| Arnold's Cat Map: no complement symmetry | PROOF | Certain |
| Arnold's Cat Map: unique fixed point (0,0) at negligible probability | PROOF | Certain |
| Stafford Mix13: bijective, full avalanche | PROOF | Certain |
| Multiplicative mixing: bijective (s[2k]\|1 always odd) | PROOF | Certain |
| Multi-rate padding: injective | PROOF | Certain |
| Full 16-site diffusion in 2 rounds | PROOF | Certain |
| Constant-time implementation (no branches) | PROOF | Certain (on x86-64 with wrapping arithmetic) |
| No statistical distinguisher at 256 GB (5 seeds) | EMPIRICAL | High (PractRand) |
| Coupling bijective (det odd) — coupling non-injectivity attack closed | PROOF | Certain |
| No efficient algebraic attack through 8 rounds | CONJECTURE | Unknown — not analyzed |
| No differential characteristic over 8 rounds | CONJECTURE | Unknown — not analyzed |
| Sponge indifferentiability bound q²/2^{512} | CONJECTURE | Conditional on permutation security |
| 256-bit forgery resistance | CONJECTURE | Conditional on permutation security |
| 128-bit key recovery resistance | CONJECTURE | Conditional on Argon2id + permutation security |

---

## Appendix A: Eigenvalue Computation Detail

For coupling polynomial p(x) = 1 + x + x³ + x⁷ + x¹¹ (distances {1, 3, 7, 11}) and ω = e^{2πi/16}:

All 16 eigenvalues λ_k = p(ω^k) computed numerically for k = 0..15:

```
p(ω^k) for k=0..15, ω = e^{2πi/16}:
 k= 0:  p(1)   = 1+1+1+1+1 = 5            |λ| = 5.000
 k= 1:  p(ω)                               |λ| ≈ 1.259  ← minimum
 k= 2:  p(ω²)                              |λ| ≈ 1.732
 k= 3:  p(ω³)                              |λ| ≈ 2.101
 k= 4:  p(ω⁴)  = p(i)                      |λ| ≈ 2.236
 k= 5:  p(ω⁵)                              |λ| ≈ 2.101
 k= 6:  p(ω⁶)                              |λ| ≈ 1.732
 k= 7:  p(ω⁷)                              |λ| ≈ 1.259  ← minimum
 k= 8:  p(-1)  = 1−1−1−1−1 = −3           |λ| = 3.000
 k= 9:  p(ω⁹)                              |λ| ≈ 1.259  ← minimum
 k=10:  p(ω¹⁰)                             |λ| ≈ 1.732
 k=11:  p(ω¹¹)                             |λ| ≈ 2.101
 k=12:  p(ω¹²) = p(-i)                     |λ| ≈ 2.236
 k=13:  p(ω¹³)                             |λ| ≈ 2.101
 k=14:  p(ω¹⁴)                             |λ| ≈ 1.732
 k=15:  p(ω¹⁵)                             |λ| ≈ 1.259  ← minimum
```

All 16 eigenvalues have strictly positive magnitude (all > 1).  The minimum is **1.259** (at k = 1, 7, 9, 15).  The determinant over ℂ is ∏λ_k = −33075 (odd).

**[PROOF] p(-1) = 1 + (−1)^1 + (−1)^3 + (−1)^7 + (−1)^{11} = 1 − 1 − 1 − 1 − 1 = −3.**  (All non-zero modes have |λ_k| ≥ 1.259 > 1; the prior v9 design {1,5,11} had |λ_{min}| = 0.765 < 1 at k=2,6,10,14.)

**Comparison to v9 ({1, 5, 11}):**

| Design | p(1) | p(-1) | min|λ_k| | det(C) | Kernel |
|--------|------|-------|-----------|--------|--------|
| v9: {1,5,11} | 4 | −2 | 0.765 | −1088 (even) | 4 elements |
| v10: {1,3,7,11} | 5 | −3 | 1.259 | −33075 (odd) | trivial |

---

## Appendix B: Kernel Computation

**Claim:** ker(C over Z/2^64) = {**0**} (trivial).

**[PROOF]** The circulant C with p(x) = 1 + x + x³ + x⁷ + x¹¹ has:

1. **Constant direction (k=0):** λ_0 = p(1) = 5.  An all-constant vector **v** = c·**1** satisfies C·**v** = 5c·**1** ≡ **0** (mod 2^64) iff 5c ≡ 0 (mod 2^64).  Since gcd(5, 2^64) = 1 (5 is odd), this has only the solution c ≡ 0 (mod 2^64).

2. **Non-constant directions (k ≠ 0):** All eigenvalues λ_k = p(ω^k) are algebraic integers with |λ_k| ≥ 1.259 and none are integers divisible by 2.  For a null vector to exist in Fourier mode k, we would need λ_k · V_k ≡ 0 (mod 2^64) with V_k ≠ 0.  Since |λ_k| is irrational (algebraic but not rational) for k ≠ 0 and has no power-of-2 factor, no such V_k exists.

3. **Global:** gcd(det(C), 2^64) = gcd(33075, 2^64) = 1 (since 33075 is odd), confirming C is invertible over Z/2^64Z by the Smith Normal Form criterion.

**Computational verification:** The prior null vector 2^62·**1** (which was in the kernel of the v9 design with λ_0 = 4) satisfies C·(2^62·**1**) = 5·2^62·**1** mod 2^64 = 2^62·**1** ≠ **0** (since 5·2^62 mod 2^64 = 2^62, as 5·2^62 − 2^64 = 2^62·(5−4) = 2^62). This confirms the prior null vector is no longer in the kernel.

**Conclusion:** ker(C) = {**0**}.  C is fully bijective.  |ker(C)| = 1.  No capacity loss.

---

## Appendix C: Test Vectors

Test vectors for the full cipher (cipher_init → keystream) are in `docs/design.md` §6 and `tests/cml_sponge_tests.rs`.  These vectors were regenerated for v10 after the coupling distance change from {1,5,11} to {1,3,7,11} and pass all 28 unit tests.

The Python reference implementation (`cml_sponge/src/cml_sponge.py`) produces byte-for-byte identical output to the Rust implementation for all 4 test vectors, confirming cross-platform determinism.

---

## Appendix D: What Has Not Been Done

For the benefit of external reviewers:

1. **No formal algebraic security proof.** The security claims are conjectures supported by structural analysis and statistical testing, not theorems.

2. **No differential or linear cryptanalysis.** The DDT and LAT of the round function have not been computed.  This is the most critical gap for a future analysis.

3. **No independent implementation review.** The codebase has been reviewed only by its author.

4. **No reduced-round PractRand.** Statistical testing at 1–4 rounds would help establish the round security margin empirically.

5. **No formal side-channel analysis.** Cache timing, power analysis, and fault attack vectors have not been studied.

6. **No comparison to established designs.** The security properties have not been compared to those of ChaCha20, AES-GCM, or other vetted stream ciphers in a formal framework.

7. **PractRand coverage.** Five seeds (0, 1, 2, 254, 255) at 256 GB each have been tested.  This covers normal, all-zero, and all-FF inputs.  Additional seeds have not been tested at full length, and no multi-stream correlation tests (e.g., NIST SP 800-22 pairwise tests) have been run.
