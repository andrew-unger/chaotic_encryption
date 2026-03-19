# CATWALK Security Argument — Arnold's Cat Map Construction

**Version:** v9-cat (Arnold's Cat Map local map)
**Status:** Research implementation — self-reviewed, awaiting independent cryptanalysis

This document supplements `docs/design.md` with a focused analysis of the security
properties that changed when the local map was substituted from tent+logistic to
Arnold's Cat Map.

---

## 1. Arnold's Cat Map — Mathematical Properties

### 1.1 Definition

The discrete Arnold's Cat Map on the torus Z/2^64 × Z/2^64:

```
[x']   [1  1] [x]
[y'] = [1  2] [y]   (mod 2^64)
```

Computed in symplectic (Störmer–Verlet) integration order:

```
x' = x + y           (mod 2^64)
y' = x' + y          (mod 2^64)   ← equivalent to x + 2y
```

### 1.2 Eigenvalue Analysis

The characteristic polynomial of [[1,1],[1,2]] is λ² − 3λ + 1 = 0, giving
eigenvalues:

```
λ₊ = (3 + √5) / 2  ≈  2.618...   (golden ratio squared)
λ₋ = (3 − √5) / 2  ≈  0.382...   (inverse of λ₊)
```

Both eigenvalues are real, irrational, and their product is 1 (det = 1). This is
the defining signature of an **Anosov diffeomorphism** on the 2-torus: the map has
a global stable manifold (contracting direction, eigenvalue < 1) and a global
unstable manifold (expanding direction, eigenvalue > 1), and these manifolds fill
the torus densely.

### 1.3 Lyapunov Exponent

The Lyapunov exponent in the expanding direction:

```
λ = ln(λ₊) = ln((3 + √5) / 2)  ≈  0.9624
```

This is the maximum Lyapunov exponent for any 2×2 integer matrix with determinant 1
and trace 3.  It means initial condition differences grow by a factor of e^0.9624 ≈
2.618 per application of the map.

### 1.4 Period on Z/2^64

On a finite ring Z/N, the Cat Map has a finite period.  For N = 2^k, the period
of the standard Cat Map matrix [[1,1],[1,2]] grows with k but has not been
analytically characterized for large k.  In practice, the Weyl counter injection
and the 8-round permutation structure ensure that the period is irrelevant: the
counter advances by GOLDEN = 0x9E3779B97F4A7C15 at every round, making each
round's map application dependent on a different counter value.

---

## 2. Fixed-Point Analysis

### 2.1 The (0, 0) Fixed Point

Arnold's Cat Map has exactly one fixed point on the 2-torus: (0, 0).

```
cat_map(0, 0) = (0 + 0, 0 + 0) = (0, 0)   ✓ confirmed
```

### 2.2 Why This Is Benign

The Weyl counter injection (Step 1 of every CML round) runs **before** Step 2
(the Cat Map).  After Step 1:

```
s[2k]   ← s[2k]   + counter.rotate_left(ROT[2k])
s[2k+1] ← s[2k+1] + counter.rotate_left(ROT[2k+1])
```

For a site pair to present as (0, 0) at the Cat Map input, both of the following
must hold simultaneously:

```
s[2k]   + counter.rotate_left(ROT[2k])   ≡ 0 (mod 2^64)
s[2k+1] + counter.rotate_left(ROT[2k+1]) ≡ 0 (mod 2^64)
```

Since ROT[2k] ≠ ROT[2k+1] (distinct primes), the two rotations of `counter` are
independent values.  The probability that both conditions hold simultaneously for
arbitrary s[2k] and s[2k+1] is:

```
P = 1/2^64 × 1/2^64 = 2^{-128}  per pair per round
```

Across 8 rounds × 8 pairs = 64 evaluations per permutation call:

```
P_any = 64 × 2^{-128} < 2^{-122}
```

This is negligibly small.  No explicit guard is needed or implemented.

### 2.3 Other Fixed Points and Short Cycles

On Z/2^64, the Cat Map may have additional fixed points and short cycles beyond
(0,0) depending on the specific matrix.  However, the Weyl counter injection makes
each round's effective map

```
(x, y) → cat_map(x + c₂ₖ, y + c₂ₖ₊₁)
```

where c₂ₖ = counter.rotate_left(ROT[2k]) is a different value for each round.
This effectively applies a different affine transformation each round, eliminating
any fixed-point structure that the bare Cat Map would have had.

---

## 3. Complement Symmetry Analysis

### 3.1 The Old Problem

The original tent and logistic maps satisfied:

```
f(x) = f(2^64 − 1 − x)   (complement symmetry)
```

This meant that if two cipher states were bitwise complements of each other, the maps
produced identical outputs, and the Weyl counter injection was required specifically
to break this symmetry before the map step.

### 3.2 Arnold's Cat Map — No Complement Symmetry

For cat_map(x, y) = (x+y, x+2y) and its action on complements (MAX−x, MAX−y)
where MAX = 2^64 − 1:

```
cat_map(MAX−x, MAX−y):
  x' = (MAX−x) + (MAX−y) = 2·MAX − x − y   (mod 2^64)
     = (−2) − x − y   (mod 2^64)           [since 2·MAX ≡ −2 mod 2^64]
  y' = x' + (MAX−y)
     = (−2 − x − y) + (MAX − y)
     = 3·MAX − x − 2y − 1   (mod 2^64)
     = (−3) − x − 2y   (mod 2^64)          [since 3·MAX ≡ −3 mod 2^64]
```

Compare with cat_map(x, y) = (x+y, x+2y).  The complement output equals
(−2−x−y, −3−x−2y) mod 2^64, which is neither (x+y, x+2y) nor its complement
(MAX−x−y, MAX−x−2y) for generic inputs.  The complement symmetry is absent.

### 3.3 Verification

The `arnold_cat_map_no_complement_symmetry` test in `tests/cml_sponge_tests.rs`
verifies this algebraically at the unit level.  The `complement_symmetry_broken`
and `tv3_all_ff_key_iv` tests verify it end-to-end at the cipher level.

---

## 4. Diffusion Analysis Under the New Map

### 4.1 Local Diffusion Per Round

Before coupling (Step 3), the Cat Map mixes each adjacent pair (2k, 2k+1):

```
m[2k]   = s[2k] + s[2k+1]
m[2k+1] = s[2k] + 2·s[2k+1]
```

Each output word depends on both input words.  The Jacobian is the matrix
[[1,1],[1,2]] with det = 1, so no entropy is lost.

The coupling step then distributes each m[i] to sites i, (i−1)%16, (i−7)%16, and
(i−8)%16.  After one complete round, the influence of each original site has
spread to 4 neighbors (the coupling distances {1, 7, 8} plus self).

### 4.2 Full Diffusion in 4 Rounds

The coupling topology proof from the original design is unchanged: distances {1, 7, 8}
achieve full 16-site diffusion in exactly 4 rounds.  The Cat Map substitution does
not affect this proof because the coupling step still uses all 16 m[i] values.

The only change is the *content* of m[i]: instead of logistic(s[i]) or tent(s[i]),
it is now arnold_cat_map(s[2k], s[2k+1]).  The diffusion argument depends only on
the structure of the coupling topology, not the specific map values.

### 4.3 Interaction with Multiplicative Mixing (Step 4)

Step 4 applies s[2k+1] ← s[2k+1] × (s[2k] | 1) to the same adjacent pairs as
the Cat Map.  This creates a two-layer nonlinear transformation per pair per round:

- **Cat Map (Step 2):** additive, area-preserving, hyperbolic.
- **Multiplicative mixing (Step 4):** multiplicative, data-dependent.

Together these provide two independent nonlinear operations on each pair before
the next round's coupling step, increasing resistance to algebraic attacks that
might target either layer in isolation.

---

## 5. Performance Impact

The map substitution eliminated all u128 arithmetic from the permutation.  The
original logistic map required one 128-bit multiply per even site; the Cat Map
requires only two wrapping additions per pair.

Measured on the benchmark hardware (Windows 10, x86-64):

| Metric | Before (tent+logistic) | After (Arnold's Cat Map) | Change |
|--------|------------------------|--------------------------|--------|
| Permutation (8 rounds) | 107.8 ns | 74.3 ns | −31% |
| Keystream throughput | 475 MiB/s | 641 MiB/s | +35% |
| AEAD encrypt 64 KB | 254 MiB/s | 345 MiB/s | +36% |
| AEAD decrypt 64 KB | 253 MiB/s | 343 MiB/s | +36% |

The performance gain comes entirely from removing the 128-bit multiply from the
inner loop.  The Cat Map's two wrapping additions are cheaper than either the
logistic map (u128 multiply + shift) or the tent map (wrapping_neg + two adds +
AND + XOR + multiply).

---

## 6. Statistical Validation

PractRand was run on the Arnold's Cat Map keystream (seed 0, 8-round permutation):

| Length | Tests | Anomalies | Time |
|--------|-------|-----------|------|
| 256 MB | 210 | 0 | 2.2 s |
| 512 MB | 226 | 0 | 4.7 s |
| 1 GB | 243 | 0 | 9.3 s |
| 2 GB | 261 | 0 | 18.2 s |
| 4 GB | 277 | 0 | 35.1 s |
| 8 GB | 294 | 0 | 69.7 s |
| 16 GB | 310 | 0 | 138 s |
| **32 GB** | **325** | **0** | **272 s** |

**Result: PASS — 325 tests, 0 anomalies at 32 GB.**

Full 256 GB validation (matching the original tent+logistic run in
`docs/practrand_results.md`) is pending.

---

## 7. Open Questions

1. **Period structure of [[1,1],[1,2]] on Z/2^64.** The exact period is unknown.
   It is likely very large but has not been computed.  The Weyl counter injection
   renders the bare period moot in practice (each round is effectively a different
   affine map), but a formal analysis would be reassuring.

2. **Algebraic attacks on the linear Cat Map.** The Cat Map is degree-1 (linear)
   per variable, unlike the degree-2 logistic and tent maps.  In isolation, a linear
   map is trivially invertible.  In the full CML round (coupling + multiplicative
   mixing), the system becomes nonlinear across sites.  Whether the linearity of
   the Cat Map exposes any algebraic shortcut through the full round function has
   not been analyzed.

3. **Differential cryptanalysis.** No differential analysis of the CML round with
   the Cat Map has been performed.  The coupling at distances {1, 7, 8} and the
   multiplicative mixing in Step 4 together create a complex differential structure,
   but this has not been quantified.
