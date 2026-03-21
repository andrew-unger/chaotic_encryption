# CATWALK v10 — Raw Permutation PractRand Validation

**Date:** 2026-03-20
**Binary:** `catwalk_raw_dump` (src/bin/catwalk_raw_dump.rs)
**PractRand version:** 0.95
**Test set:** core, folding = standard (64 bit)
**Target:** 32 GB per seed

---

## Purpose

This document records the PractRand results for the CML-Sponge permutation's
**raw output** — the rate words read directly from the lattice BEFORE the
Stafford Mix13 output finalizer is applied.

The standard squeeze path does:
```
output[i] = stafford_mix13(state.lattice[i])
```

The raw dump binary bypasses Mix13:
```
output[i] = state.lattice[i]
```

**Question answered:** Is Mix13 defense-in-depth (permutation already produces
statistically strong output) or load-bearing (masking weaknesses in the
permutation's raw output)?

---

## Construction Confirmation

Before running PractRand, the following were confirmed in the codebase:

| Property | Location | Value |
|----------|----------|-------|
| Coupling distances | `src/cml_sponge.rs` lines 62–65, 178–181 | {1, 3, 7, 11} |
| Cat Map order | `src/cml_sponge.rs` lines 139–142 | Symplectic (x' = x+y, y' = x+2y) |
| Mix13 in squeeze | `src/cml_sponge.rs` line 292 | `stafford_mix13(state.lattice[i])` |
| Rounds per permutation | `src/cml_sponge.rs` line 46 | 8 |
| Baseline commit | — | `93d8d296004f19b3c0f74106a316de057b59e234` |

---

## Mix13 Bypass Verification

Before running PractRand, the raw dump binary was verified to produce output
**different** from the standard keystream dump with the same key/IV (seed 254,
all-zero key and IV):

```
Raw dump (first 64 bytes):
  1f5f 0b5f d21f 30ab 09d2 f98f be73 7349
  e935 c0d1 6032 a25a 31c2 98e8 8bc9 f313
  4382 11d5 0f4d 7605 f67d 29ce 2f1d b3e3
  1d0b f12b 6aa3 c4c2 c7b5 4b22 5208 9564

Standard keystream (first 64 bytes):
  6388 911b d2e4 20a7 90a9 75a8 ee0b 0932
  e795 9b31 a62d ccfc 0212 d56c 86bf 80d8
  24d2 f6aa c169 2f3d 3299 5b70 fa78 80e6
  1814 99e9 7db9 b244 b972 d084 c687 581e
```

Outputs differ at every byte — Mix13 bypass confirmed.

---

## Seed Matrix

| Seed | Key derivation | Key | IV |
|------|---------------|-----|----|
| 0 | BLAKE3 `catwalk.v10.practrand.key` | (derived) | (derived, first 16 bytes) |
| 254 | Degenerate all-zero | `[0x00; 32]` | `[0x00; 16]` |
| 255 | Degenerate all-ones | `[0xFF; 32]` | `[0xFF; 16]` |

Key derivation for seed 0 uses the same material as `cml_keystream_dump`:
```
seed_material = b"catwalk v10 practrand validation" ++ [0u8]
key = BLAKE3::derive_key("catwalk.v10.practrand.key", seed_material)
iv  = BLAKE3::derive_key("catwalk.v10.practrand.iv",  seed_material)[0..16]
```

---

## Results

### Seed 0 (BLAKE3-derived) — PASS

```
length= 256 megabytes (2^28 bytes), time= 2.3 seconds
  no anomalies in 210 test result(s)

length= 512 megabytes (2^29 bytes), time= 4.8 seconds
  no anomalies in 226 test result(s)

length= 1 gigabyte (2^30 bytes), time= 9.7 seconds
  [Low4/64]Gap-16:B  R= +5.0  p = 3.2e-4  unusual
  ...and 242 test result(s) without anomalies

length= 2 gigabytes (2^31 bytes), time= 19.0 seconds
  no anomalies in 261 test result(s)

length= 4 gigabytes (2^32 bytes), time= 36.9 seconds
  no anomalies in 277 test result(s)

length= 8 gigabytes (2^33 bytes), time= 73.5 seconds
  no anomalies in 294 test result(s)

length= 16 gigabytes (2^34 bytes), time= 148 seconds
  no anomalies in 310 test result(s)

length= 32 gigabytes (2^35 bytes), time= 293 seconds
  no anomalies in 325 test result(s)
```

One transient "unusual" at 1 GB ([Low4/64]Gap-16:B, p=3.2e-4) — disappeared by 2 GB.
**Final: 325 tests, 0 anomalies at 32 GB.**

### Seed 254 (all-zero degenerate) — PASS

```
length= 256 megabytes (2^28 bytes), time= 2.4 seconds
  no anomalies in 210 test result(s)

length= 512 megabytes (2^29 bytes), time= 5.1 seconds
  no anomalies in 226 test result(s)

length= 1 gigabyte (2^30 bytes), time= 10.2 seconds
  no anomalies in 243 test result(s)

length= 2 gigabytes (2^31 bytes), time= 19.9 seconds
  no anomalies in 261 test result(s)

length= 4 gigabytes (2^32 bytes), time= 38.3 seconds
  no anomalies in 277 test result(s)

length= 8 gigabytes (2^33 bytes), time= 75.9 seconds
  DC6-9x1Bytes-1  R= +5.6  p = 3.2e-3  unusual
  ...and 293 test result(s) without anomalies

length= 16 gigabytes (2^34 bytes), time= 151 seconds
  DC6-9x1Bytes-1  R= +5.3  p = 4.0e-3  unusual
  ...and 309 test result(s) without anomalies

length= 32 gigabytes (2^35 bytes), time= 295 seconds
  no anomalies in 325 test result(s)
```

One transient "unusual" (DC6-9x1Bytes-1, p≈3–4e-3) at 8–16 GB — disappeared by 32 GB.
**Final: 325 tests, 0 anomalies at 32 GB.**

### Seed 255 (all-ones degenerate) — PASS

```
length= 256 megabytes (2^28 bytes), time= 2.4 seconds
  no anomalies in 210 test result(s)

length= 512 megabytes (2^29 bytes), time= 5.0 seconds
  no anomalies in 226 test result(s)

length= 1 gigabyte (2^30 bytes), time= 10.1 seconds
  no anomalies in 243 test result(s)

length= 2 gigabytes (2^31 bytes), time= 19.7 seconds
  [Low16/64]DC6-9x1Bytes-1  R= +5.8  p = 3.8e-3  unusual
  ...and 260 test result(s) without anomalies

length= 4 gigabytes (2^32 bytes), time= 38.2 seconds
  no anomalies in 277 test result(s)

length= 8 gigabytes (2^33 bytes), time= 75.9 seconds
  no anomalies in 294 test result(s)

length= 16 gigabytes (2^34 bytes), time= 151 seconds
  no anomalies in 310 test result(s)

length= 32 gigabytes (2^35 bytes), time= 295 seconds
  no anomalies in 325 test result(s)
```

One transient "unusual" ([Low16/64]DC6-9x1Bytes-1, p=3.8e-3) at 2 GB — disappeared by 4 GB.
**Final: 325 tests, 0 anomalies at 32 GB.**

---

## Summary

| Seed | Final length | Tests run | Failures | Anomalies at final length | Verdict |
|------|-------------|-----------|----------|--------------------------|---------|
| 0 | 32 GB (2^35) | 325 | 0 | 0 | **PASS** |
| 254 | 32 GB (2^35) | 325 | 0 | 0 | **PASS** |
| 255 | 32 GB (2^35) | 325 | 0 | 0 | **PASS** |
| **Total** | **96 GB** | **975** | **0** | **0** | **PASS** |

### Transient "unusual" ratings (all disappeared before 32 GB)

| Seed | Size | Test | R | p-value | Persisted to 32 GB? |
|------|------|------|---|---------|---------------------|
| 0 | 1 GB | [Low4/64]Gap-16:B | +5.0 | 3.2e-4 | No (gone by 2 GB) |
| 254 | 8 GB | DC6-9x1Bytes-1 | +5.6 | 3.2e-3 | No (weakened at 16 GB, gone by 32 GB) |
| 255 | 2 GB | [Low16/64]DC6-9x1Bytes-1 | +5.8 | 3.8e-3 | No (gone by 4 GB) |

All transient "unusual" ratings are well within normal statistical fluctuation
(PractRand's "unusual" threshold is approximately p < 0.01, and true RNGs
produce these routinely). None escalated to "suspicious" or "FAIL".

---

## Conclusion

**Mix13 is defense-in-depth, not load-bearing.**

The CML-Sponge permutation (8 rounds, 5-term coupling {1,3,7,11}, Arnold's
Cat Map, multiplicative mixing) produces statistically strong output at the
raw lattice level. The Stafford Mix13 finalizer provides an additional safety
margin but is not required to mask permutation weaknesses — the permutation
has no detectable weaknesses through 32 GB of PractRand testing.

This result is consistent with the design intent: the CML lattice dynamics
(counter injection → Cat Map → long-range coupling → multiplicative mixing)
produce sufficient diffusion and mixing that even the raw rate words pass
stringent statistical testing. Mix13 serves as a conservative additional
layer, ensuring that any subtle correlations that might emerge at longer
test lengths are eliminated before output.

---

## Comparison with Standard (Mix13-finalized) PractRand Results

| Configuration | Seeds tested | Max length per seed | Total volume | Failures |
|--------------|-------------|--------------------:|-------------:|----------|
| Standard (with Mix13) | 5 (0,1,2,254,255) | 256 GB | 1.28 TB+ | 0 |
| Raw (without Mix13) | 3 (0,254,255) | 32 GB | 96 GB | 0 |

The raw permutation matches the standard configuration's perfect record,
albeit at a shorter test length. The absence of any systematic difference
between the two configurations at 32 GB confirms that Mix13 is not compensating
for permutation-level bias.
