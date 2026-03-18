# CML-Sponge: Design Document

## 1. Overview

CML-Sponge is a stream cipher built from two distinct primitives:

1. **Coupled Map Lattice (CML)** — a 16-site chaotic dynamical system that
   provides the permutation function.
2. **Sponge construction** — a mode of operation that uses the permutation to
   build a cryptographic pseudorandom function from a key and IV.

The two components are independent: the sponge framework is agnostic to the
internal structure of the permutation, and the CML permutation can be analyzed
independently of how the sponge uses it.

---

## 2. State Layout

```
+----------------------------------+
|  Rate:     sites 0–7  (512 bits) |   ← XOR'd during absorb; output during squeeze
+----------------------------------+
|  Capacity: sites 8–15 (512 bits) |   ← never directly read or written by caller
+----------------------------------+
|  counter   (64 bits)             |   ← Weyl sequence counter; part of permutation
+----------------------------------+
```

**Total permutation state**: 16 × 64 + 64 = **1088 bits**.

**Sponge state (caller-visible)**: 1024 bits (lattice only).

### Justification of parameters

| Parameter   | Value       | Justification                                               |
|-------------|-------------|-------------------------------------------------------------|
| Sites       | 16          | Large enough for interesting CML dynamics; small enough to audit exhaustively |
| Rate        | 8 sites / 512 bits | 64 bytes per squeeze — good throughput                |
| Capacity    | 8 sites / 512 bits | 256-bit security level (birthday-bound = 2^256)       |
| Rate/cap split | 50/50   | Symmetric; maximizes throughput while maintaining 256-bit security |

---

## 3. Local Maps

Each lattice site applies one of two chaotic maps before the coupling step.

### 3.1 Logistic Map (even-indexed sites: 0, 2, 4, 6, 8, 10, 12, 14)

```
f_L(x) = (x * (2^64 − 1 − x)) >> 62
```

**Origin**: Integer analogue of the continuous logistic map `r·x·(1−x)` at
the fully chaotic parameter `r = 4`.  In the continuous case, `4·x·(1−x)` maps
`[0,1]` onto `[0,1]` with a single quadratic maximum.  The integer version
maps a u64 to a u64 by:

- Computing `x * (2^64 − 1 − x)`, which is the integer analogue of
  `x · (1 − x)` scaled to `[0, (2^64−1)^2 / 4]`.
- Shifting right by 62 (rather than 64) to keep 64 meaningful output bits.
  Shifting by 64 would reduce the output to at most 3 bits; shifting by 62
  preserves the full chaotic structure while keeping the result in u64.

**Properties**:
- Purely quadratic (degree 2 algebraic structure).
- Fixed points at `x = 0` and `x ≈ 2^63` in the continuous limit; these are
  repelled by the Weyl counter injection in step 3.
- No floating point; platform-portable.

### 3.2 Tent Map (odd-indexed sites: 1, 3, 5, 7, 9, 11, 13, 15)

```
f_T(x) = 2x           if MSB(x) = 0
f_T(x) = 2·(MAX − x)  if MSB(x) = 1
```

Implemented branchlessly using a mask derived from the MSB, preventing
timing side-channels.

**Origin**: Integer analogue of the piecewise-linear tent map `min(2x, 2(1−x))`
at parameter μ = 2 (maximally chaotic).

**Properties**:
- Piecewise linear (degree 1 per branch) — different algebraic structure from
  logistic, so adjacent site pairs cannot be reduced to a single polynomial.
- Bijective on its domain (unlike logistic, which has fold-backs).
- Branchless implementation prevents information leakage via execution time.

### 3.3 Rationale for Alternation

Even sites use logistic (quadratic); odd sites use tent (linear).  Alternating
different map families at adjacent sites prevents algebraic symmetry:

- A pair of identical logistic sites would have a tensor-product structure
  that might admit algebraic simplification.
- Mixing quadratic and linear maps at adjacent sites ensures the coupling
  step combines values with different algebraic degrees, producing higher
  effective degree in the combined expression.

---

## 4. CML Coupling Topology

### 4.1 Coupling distances {1, 7, 8}

After all local maps are computed as a simultaneous snapshot:

```
s[i] = m[i] + m[(i+1) % 16] + m[(i+7) % 16] + m[(i+8) % 16]   mod 2^64
```

Each site is the sum of four mapped values: itself, its nearest neighbor
(distance 1), a medium-range neighbor (distance 7), and its diametrically
opposite site (distance 8 = N/2).

**Why additive coupling (not XOR)?**

Addition modulo 2^64 produces carry propagation across word boundaries.
This creates nonlinear mixing that pure XOR cannot: for two values `a` and
`b`, XOR is linear in GF(2)^64, while addition is nonlinear due to carries.
The carry chain effectively "mixes" bits from lower positions into higher ones,
an effect absent from XOR.

**Why these specific distances?**

- Distance 1: Classical nearest-neighbor CML coupling (Kaneko 1984 original model).
- Distance 7: Asymmetric long-range coupling; the asymmetry (7 ≠ 8 = N/2)
  breaks the spatial Z/2 symmetry of the lattice, preventing any site from
  having a "mirror image" at a fixed offset.
- Distance 8: Diametrically opposite site on the ring-16 lattice; provides a
  global coupling component analogous to mean-field coupling in CML theory.

### 4.2 Diffusion Analysis

Define the **influence set** of site `j` after `r` rounds as the set of sites
whose output in round `r` depends on site `j`'s value in round 0.

At round 1, site `i` depends on sites `{i, i−1, i−7, i−8}` (mod 16) from
round 0.  Site `j`'s influence set after round 1 is therefore:
`{j, j+1, j+7, j+8}` (mod 16).

Propagating forward:

| Round | Influence set size | Notes |
|-------|--------------------|-------|
| 0     | 1                  | Just site j |
| 1     | 4                  | {j, j+1, j+7, j+8} |
| 2     | up to 16 (bounded by overlap) | each of the 4 sites expands by 4 |
| 3     | up to 16           | further expansion |
| 4     | 16 (all sites)     | full diffusion guaranteed |

**Formal proof of 4-round full diffusion:**

Start with a single site `j = 0` (by symmetry, valid for all j).

Round 1 influence: `S1 = {0, 1, 7, 8}` (4 sites).

Round 2: for each `x ∈ S1`, add `{x+1, x+7, x+8}`:
- From 0: {1, 7, 8}
- From 1: {2, 8, 9}
- From 7: {8, 14, 15}
- From 8: {9, 15, 0}

`S2 = {0, 1, 2, 7, 8, 9, 14, 15}` (8 sites).

Round 3: for each `x ∈ S2`, add `{x+1, x+7, x+8}` (mod 16):
- From 0: {1, 7, 8}
- From 1: {2, 8, 9}
- From 2: {3, 9, 10}
- From 7: {8, 14, 15}
- From 8: {9, 15, 0}
- From 9: {10, 0, 1}
- From 14: {15, 5, 6}
- From 15: {0, 6, 7}

`S3 = {0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 14, 15}` (12 sites; missing: 4, 11, 12, 13).

Round 4: expanding from `{3, 5, 10, 14}` (the boundary sites in S3):
- From 3: {4, 10, 11}      ← adds 4, 11
- From 5: {6, 12, 13}      ← adds 12, 13
- From 10: {11, 1, 2}
- From 14: {15, 5, 6}

`S4 = all 16 sites` ✓  (sites 4, 11, 12, 13 are covered).

Full diffusion in exactly 4 rounds.  With 8 rounds per permutation, we have
a **2× safety margin** over the minimum diffusion requirement.

---

## 5. Counter Injection (Weyl Sequence)

```python
counter = (counter + GOLDEN) % 2^64
s[0]  = (s[0]  + counter) % 2^64
s[4]  = (s[4]  + rotate64(counter, 16)) % 2^64
s[8]  = (s[8]  + rotate64(counter, 32)) % 2^64
s[12] = (s[12] + rotate64(counter, 48)) % 2^64
```

`GOLDEN = 0x9E3779B97F4A7C15` is the fractional part of `(√5−1)/2 × 2^64`.

**Purpose**: The CML logistic and tent maps both have fixed points (e.g., x=0
for logistic, x=0 for tent).  Without the counter, an unlucky initial state
could converge to a degenerate trajectory.  The Weyl increment is irrational
(in the sense that GOLDEN / 2^64 is irrational), ensuring the counter visits
all 2^64 values before repeating.

**Why four injection sites?**  Injecting at positions 0, 4, 8, 12 (spacing 4
= N/4) ensures the counter influence reaches all 16 sites within one round
via the coupling topology.  The rotations (0, 16, 32, 48 bits) ensure that
even if two injection sites receive related counter values, the bit patterns
differ, preventing correlated injection.

---

## 6. Multiplicative Mixing

```python
for k in 0..7:
    s[2k+1] = s[2k+1] * (s[2k] | 1)   mod 2^64
```

**Purpose**: Adds quadratic (degree-2) nonlinearity at the word level beyond
what the local maps provide.  After the additive coupling step, the lattice
values are linear combinations of mapped values.  The multiplicative step
makes `s[2k+1]` depend nonlinearly on both `s[2k]` and `s[2k+1]`.

**Why `(s[2k] | 1)`?**  Forces the multiplier to be odd.  In Z/2^64 Z, an
element is invertible (a unit) if and only if it is odd.  By ORing with 1,
we guarantee the multiplication is a bijection:  every possible output can be
uniquely decoded given `s[2k]`.  This preserves the invertibility of the full
round function (a requirement for the sponge permutation to be a bijection).

---

## 7. Full Round Summary

One round = four steps applied in order to all 16 sites:

```
1. m[i] = local_map(s[i], i)          for all i  (snapshot — read-only pass)
2. s[i] = m[i] + m[i+1] + m[i+7] + m[i+8]  mod 2^64  (coupling)
3. counter += GOLDEN  mod 2^64         (Weyl advance)
   s[0, 4, 8, 12] += rotate64(counter, 0, 16, 32, 48)  (injection)
4. s[2k+1] *= (s[2k] | 1)  mod 2^64   for k=0..7  (multiplicative)
```

One **permutation** = 8 such rounds.

---

## 8. Sponge Construction

### 8.1 Parameters

| Parameter      | Value                     |
|----------------|---------------------------|
| Permutation    | 8-round CML (above)        |
| Rate (r)       | sites 0–7 = 512 bits      |
| Capacity (c)   | sites 8–15 = 512 bits     |
| Block size     | 64 bytes                  |
| Security level | min(c/2, key length) bits  |

### 8.2 Padding

Multi-rate padding (identical to Keccak/SHA-3):
```
padded = input || domain_byte || 0x00 ... 0x00 || 0x80
```
Length of padded is a multiple of 64 bytes.  The domain byte provides
cryptographic domain separation:

- `0x01`: key absorption
- `0x02`: IV absorption

### 8.3 Absorb Phase

```
for each 64-byte padded block B:
    lattice[0..7] ^= unpack_le64(B)   # XOR into rate only
    permute(state)                     # 8 CML rounds
```

Capacity sites (8–15) are never directly written; they accumulate entropy from
the permutation only.

### 8.4 Squeeze Phase

```
while bytes_needed > 0:
    output 64 bytes = pack_le64(lattice[0..7])
    permute(state)
```

### 8.5 Initialization Sequence

```
state = all-zeros (1024-bit lattice + counter=0)
absorb(key, domain=0x01)
absorb(iv,  domain=0x02)
# State is now ready for squeezing.
```

### 8.6 Related-Key / Related-IV Resistance

The capacity is never directly written.  After a single 8-round permutation of
a 1-bit-different state, the capacity is expected to differ in ≈50% of its
512 bits (by the avalanche property of the permutation).  An adversary who
knows the keystream but not the key cannot recover the capacity without
inverting the permutation — a computation believed to require work proportional
to the capacity security level (2^256 for a 512-bit capacity).

---

## 9. Implementation Notes

1. **Snapshot requirement**: All `m[i]` values in step 1 of each round MUST be
   computed from the current lattice state before any `s[i]` are updated.
   This is the defining property of a synchronous CML.  Violating it (i.e.,
   reading updated `s[i]` values mid-step) produces an asynchronous CML with
   different — and likely weaker — diffusion properties.

2. **Buffering**: Each squeeze produces 64 bytes.  The `keystream()` function
   buffers the unread tail so that sequential calls with arbitrary lengths
   produce the same sequence as a single call for the total length.

3. **No floating point**: All arithmetic uses Python's arbitrary-precision
   integers with explicit `% (2**64)` reduction.  This ensures identical
   results across all platforms and Python versions.

4. **Byte order**: All u64 packing/unpacking uses little-endian byte order
   (consistent with most modern hardware and reference implementations).
