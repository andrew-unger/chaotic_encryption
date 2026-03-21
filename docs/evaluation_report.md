# CATWALK v10 — Independent Cryptographic Evaluation Report

**Evaluator:** Claude (Anthropic), acting as an independent cryptographer
**Date:** 2026-03-20
**Scope:** Complete read-only evaluation of the CATWALK v10 codebase
**Commit:** c002dfb6f92018197614a56b1b36764ab5fc0582 (plus uncommitted v10 changes)
**Files reviewed:** All `.rs` source files, all `docs/*.md`, all `tests/*.rs`, `benches/`, `Cargo.toml`

---

> **Disclaimer.** This evaluation was performed by a language model reading all source
> code and documentation in a single session.  It is NOT a substitute for a professional
> cryptographic audit by a credentialed third party.  The evaluator has no ability to run
> code, perform timing measurements, or conduct differential/algebraic cryptanalysis
> tooling.  Findings are based on structural analysis, mathematical reasoning, and
> comparison to established cryptographic designs.  Claims are categorized as:
>
> - **[SOUND]** — The claim is mathematically correct or follows from standard results.
> - **[REASONABLE]** — The claim is plausible and well-argued but not formally proven.
> - **[CONCERN]** — A potential weakness or gap that warrants further investigation.
> - **[ISSUE]** — A concrete problem identified in the code or design.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Construction Correctness](#2-construction-correctness)
3. [Primitive Analysis](#3-primitive-analysis)
4. [Security Assessment](#4-security-assessment)
5. [Implementation Security](#5-implementation-security)
6. [Code Quality](#6-code-quality)
7. [Novelty and Contribution](#7-novelty-and-contribution)
8. [Open Problems and Recommendations](#8-open-problems-and-recommendations)

---

## 1. Executive Summary

CATWALK is a research-grade authenticated encryption tool built on a novel **Coupled Map Lattice (CML) sponge construction**.  The core primitive is a 1024-bit state (16 × u64) permutation with a 512-bit rate / 512-bit capacity split, wrapped in a standard Bertoni–Daemen–Peeters–Van Assche sponge framework for AEAD.

**Strengths:**

- The sponge framework is correctly implemented with proper domain separation, multi-rate padding, and Encrypt-then-MAC semantics.
- The v10 coupling upgrade ({1,3,7,11}, 5-term) is a meaningful improvement: trivial kernel, odd determinant, all eigenvalue magnitudes > 1.
- Key material handling is careful: `LockedBuffer` with VirtualLock, zeroize-on-drop, constant-time tag comparison via `subtle`.
- The KDF (Argon2id at 256 MB / 4 iterations) is strong, and the decryption parameter floor prevents downgrade attacks.
- PractRand validation at 256 GB (5 seeds, zero anomalies) and ongoing 1 TB testing provide strong empirical evidence against statistical distinguishers.
- The documentation is unusually thorough and honest about what is proved vs. conjectured.

**Concerns:**

- The round function has **very low nonlinear density**: only Step 4 (multiplicative mixing) provides nonlinearity, and it acts on only 8 of 16 sites per round.  Steps 1–3 are entirely affine over Z/2^64.  This is the single most important open question.
- No differential or linear cryptanalysis has been performed.  The affine structure of Steps 1–3 makes the construction potentially vulnerable to algebraic or linearization attacks.
- The Cat Map is a **linear** map (degree 1 over Z/2^64), not a nonlinear one despite the "chaotic" framing.  The security argument relies heavily on the interaction between this linear map and the multiplicative mixing, but this interaction has not been formally analyzed.
- Throughput (~200 MB/s for AEAD) is 5–15× slower than ChaCha20-Poly1305, which may limit practical adoption.

**Overall assessment:** CATWALK is a well-engineered research prototype with a novel and interesting construction.  The sponge wrapper and key management are solid.  However, the core permutation's security rests on an unproven conjecture about the interaction of linear and nonlinear components, and the absence of formal cryptanalysis is the critical gap.  The author's own documentation is commendably honest about these limitations.

---

## 2. Construction Correctness

### 2.1 Sponge Framework

**[SOUND]** The sponge construction follows the standard Bertoni et al. framework correctly:

- **Rate/capacity split:** Sites 0–7 (rate, 512 bits) are XOR'd during absorb and read during squeeze.  Sites 8–15 (capacity, 512 bits) are never directly output.  This is implemented correctly in `absorb_block()` (line 241) and `squeeze_block()` (line 289).

- **Multi-rate padding:** `data || domain || 0x00...0x00 || 0x80` — this is the standard Keccak-style padding.  The implementation in `absorb()` (lines 253–266) correctly pads to a multiple of 64 bytes.  The padding is injective: different (data, domain) pairs produce different padded messages.

- **Domain separation:** Five distinct domain bytes (0x01–0x05) for key, IV, AAD, ciphertext, and tag finalization.  Correctly used throughout.

### 2.2 AEAD Construction

**[SOUND]** The AEAD follows SpongeWrap correctly:

- **Encrypt path** (`aead_encrypt_chunk`, line 383): squeeze keystream → XOR plaintext → absorb ciphertext.  Correct.
- **Decrypt path** (`aead_decrypt_chunk`, line 414): squeeze keystream → save ciphertext → XOR to plaintext → absorb saved ciphertext.  Correct — the saved ciphertext (not plaintext) is absorbed, matching the encrypt path's state evolution.
- **Tag finalization** (`aead_finalize`, line 441): empty absorb with DOMAIN_TAG, then read 32 bytes from rate.  Correct.

**[CONCERN]** The tag is only 32 bytes (256 bits) but is read from the first 4 of 8 rate words.  The remaining 4 rate words are discarded, as is the entire capacity.  While 256-bit tags are standard, the partial squeeze (4 of 8 words) means the tag reveals only 256 of the 512 rate bits.  This is fine — it's equivalent to truncating a longer squeeze output — but it means the effective forgery resistance is 2^{-256} per attempt, not 2^{-512}.  The documentation correctly states 128-bit forgery resistance under the birthday bound, which is appropriate for 256-bit tags.

### 2.3 Key Schedule

**[SOUND]** The key schedule is:

1. Argon2id(password, salt || timestamp) → 32-byte master key.
2. BLAKE3::derive_key("catwalk.v9.cipher", master_key) → 32-byte cipher key.
3. Sponge absorb(cipher_key, 0x01) then absorb(nonce, 0x02).

The BLAKE3 domain derivation provides clean key separation.  The context string "catwalk.v9.cipher" is retained from v9 for file format backward compatibility, which is correctly documented.

**[REASONABLE]** Using Argon2id at 256 MB / 4 iterations is a strong choice for password-based encryption.  The decryption-side parameter floor (m ≥ 64 MB, t ≥ 2) prevents crafted headers from bypassing the KDF cost.  The floor check at `crypto.rs:393` occurs before the KDF executes, preventing a timing oracle that would reveal whether the password is correct without paying the full KDF cost.

### 2.4 File Format

**[SOUND]** The header structure is clean and complete:

```
MAGIC(4) VERSION(1) FLAGS(1) SALT(16) TIMESTAMP(8) NONCE(16) ARGON2_M_LOG2(1) ARGON2_T_COST(1) ARGON2_P_COST(1) EXT_LEN(1) EXT(var) CIPHERTEXT(var) TAG(32)
```

The entire header (including Argon2 parameters) is absorbed as AAD, binding all metadata into the authentication tag.  This is correct and important — it prevents parameter manipulation without detection.

---

## 3. Primitive Analysis

### 3.1 Arnold's Cat Map

**[SOUND]** The Cat Map [[1,1],[1,2]] is:

- **Bijective:** det = 1, so it's a bijection on (Z/2^64)^2.  Verified.
- **Hyperbolic:** Eigenvalues (3±√5)/2 ≈ {2.618, 0.382}, both real, product 1.  Lyapunov exponent ≈ 0.9624.
- **No complement symmetry:** Correctly argued and verified by test vectors.
- **Unique fixed point at (0,0):** Correctly argued, with negligible probability analysis (2^{-128} per pair per round after counter injection).

**[CONCERN]** Despite the "chaotic" framing, the Cat Map is a **linear** map over Z/2^64.  It is literally the matrix multiplication [[1,1],[1,2]] · (x,y)^T mod 2^64.  The "chaotic" properties (sensitive dependence, dense periodic orbits) apply to the real torus T^2, but on Z/2^64 the map has finite period and is a linear function.  This linearity is the fundamental concern for the construction's security.

The Lyapunov exponent of ≈ 0.9624 means that *on the real torus*, nearby points diverge at rate e^{0.9624} ≈ 2.618 per iteration.  On Z/2^64, this translates to: if two inputs differ in the low bit, after one Cat Map application the difference occupies ~1.4 bits.  But this "diffusion" is entirely linear and predictable — an adversary who knows the map can compute the exact evolution of any difference.  **The Cat Map does not provide cryptographic nonlinearity.**

### 3.2 Coupling Step

**[SOUND]** The 5-term coupling with distances {1,3,7,11} is well-analyzed:

- p(x) = 1 + x + x^3 + x^7 + x^{11}
- p(1) = 5 (odd) → invertible over Z/2^64
- det(C) = −33075 (odd) → trivial kernel → full 512-bit capacity
- min|λ_k| = 1.259 (all modes amplifying)
- Full 16-site diffusion in 2 rounds

The comprehensive search over all C(15,4) = 1365 candidates, documented in `coupling_5term_evaluation.md`, is thorough.  The selection of {1,3,7,11} is well-justified.

**[SOUND]** However, the coupling step is also **linear** — it is a circulant matrix multiplication over Z/2^64.  Like the Cat Map, it provides diffusion but no nonlinearity.

### 3.3 Multiplicative Mixing (Step 4)

**[REASONABLE]** `s[2k+1] *= (s[2k] | 1)` is the sole source of nonlinearity in the round function.  The `| 1` ensures the multiplier is always odd (invertible mod 2^64).

This is structurally similar to the T-function in SNOW 2.0 or the multiplication in Salsa20/ChaCha20, but with a crucial difference: in ChaCha20, the nonlinear operation (addition mod 2^32) is interleaved with XOR and rotation in every quarter-round, providing dense nonlinear mixing.  In CATWALK, multiplication appears only once per round, acting on only 8 of 16 sites (the odd-indexed ones), and the remaining 3 steps are entirely affine.

**[CONCERN]** The nonlinear density is low.  Per round:
- Step 1 (counter injection): affine
- Step 2 (Cat Map): linear
- Step 3 (coupling): linear
- Step 4 (multiplicative mixing): **nonlinear on 8 sites only**

Over 8 rounds, this gives 8 applications of a multiplicative nonlinearity, each affecting half the state.  The question is whether this is sufficient to prevent algebraic or linearization attacks.  The author correctly identifies this as the highest-priority open question (§7.1 of the security argument).

### 3.4 Stafford Mix13 Output Finalizer

**[SOUND]** Mix13 is a well-known bijective finalizer (used in SplitMix64).  It provides full avalanche: every output bit depends on every input bit.  Applied to each rate word before output, it whitens any residual structure in the state.

**[REASONABLE]** Mix13 is defense-in-depth.  If the permutation is strong, Mix13 is redundant.  If the permutation has structural weaknesses, Mix13 may mask them in statistical tests (like PractRand) without actually fixing the underlying weakness.  This is a double-edged sword: it improves practical output quality but may give false confidence that the permutation is stronger than it actually is.

### 3.5 Weyl Counter Injection

**[SOUND]** The Weyl sequence with GOLDEN = ⌊φ · 2^64⌋ is a nothing-up-my-sleeve constant with known equidistribution properties.  The 16 distinct prime rotation amounts ensure different sites receive different counter contributions.

**[REASONABLE]** Counter injection is affine (state + constant), so it does not add nonlinearity.  Its primary roles are: (1) preventing the all-zero fixed point from being reached, (2) breaking translational symmetry between sites, and (3) ensuring the permutation is key-dependent even from round to round.

---

## 4. Security Assessment

### 4.1 Security Level

**[REASONABLE]** The claimed security level of 128 bits is reasonable given:
- 512-bit capacity (sponge bound: q^2/2^512 for q queries)
- 256-bit tag (birthday bound: 2^128 forgery resistance)
- 128-bit nonce space (birthday collision at ~2^64 encryptions)
- Password entropy as the practical weak link

### 4.2 The Core Conjecture

The entire security argument rests on one conjecture: **the CML-Sponge permutation is computationally indistinguishable from a random permutation**.

**[CONCERN]** This conjecture is untested against standard cryptanalytic techniques:

1. **Algebraic attacks.** Steps 1–3 of each round are affine over Z/2^64.  The multiplicative mixing in Step 4 introduces degree-2 terms (s[2k+1] × s[2k]).  Over 8 rounds, the algebraic degree grows, but the starting degree is very low compared to constructions like AES (which uses the GF(2^8) inverse, providing maximum algebraic degree 254 per S-box application) or Keccak (which uses χ, a degree-2 function over GF(2)^5 applied to all 1600 bits).

   In CATWALK, the degree-2 nonlinearity from Step 4 is applied to 8 of 16 state words per round.  The effective algebraic degree after r rounds grows roughly as 2^r for the affected words, reaching 2^8 = 256 after 8 rounds — but only for the words that are targets of multiplicative mixing.  The other 8 words (even-indexed) are only indirectly affected through the coupling step.  Whether this is sufficient to resist Gröbner basis attacks or linearization is unknown.

2. **Differential cryptanalysis.** The Cat Map and coupling are linear, so differences propagate deterministically through Steps 1–3.  Only Step 4 provides differential nonlinearity.  The differential distribution of `s[2k+1] × (s[2k] | 1)` over Z/2^64 has not been computed.  For comparison, AES's SubBytes has max differential probability 2^{-6}, providing a strong bound on multi-round differential characteristics.  Without a similar bound for CATWALK's Step 4, no differential security claim can be made.

3. **Linear cryptanalysis.** Similarly, the linear approximation table for Step 4 has not been computed.  The linearity of Steps 1–3 means that any linear approximation of Step 4 can be extended freely through those steps, potentially creating long linear trails.

### 4.3 PractRand Validation

**[SOUND]** PractRand at 256 GB × 5 seeds (all zero anomalies at final checkpoint) is strong empirical evidence against statistical distinguishers.  The ongoing 1 TB × 8 seed validation further strengthens this.

**[CONCERN]** PractRand tests output stream quality, not cryptographic security.  A generator that passes PractRand may still be broken by algebraic or structural attacks.  For example, truncated linear recurrences (like the Mersenne Twister) pass PractRand easily but are trivially broken cryptographically.  The Mix13 output finalizer may be masking algebraic structure in the underlying permutation that would be exploitable by a cryptanalyst but invisible to statistical tests.

### 4.4 Specific Attack Surfaces

**Nonce reuse:**
**[ISSUE]** The low-level API (`cipher_init`, `keystream`, etc.) does not prevent nonce reuse.  The documentation correctly warns about this, and the high-level `encrypt()` function generates random nonces.  However, the AEAD API (`absorb_aad`, `aead_encrypt_chunk`, etc.) is exposed publicly and could be misused.  This is standard for low-level crypto APIs (libsodium, ring, etc.), so it's more of a documentation concern than a bug.

**Decompression bomb:**
**[SOUND]** The 4 GB decompression cap in `utils.rs:9` correctly mitigates zip bomb attacks.

**Output before verification:**
**[SOUND]** `decrypt()` in `crypto.rs:471` compares tags with `ct_eq` before returning plaintext.  The low-level `aead_decrypt_chunk` correctly documents the "do not use before verification" contract.

**KDF downgrade:**
**[SOUND]** Parameter floor at `crypto.rs:393` prevents weak KDF parameters, checked before the KDF runs.

---

## 5. Implementation Security

### 5.1 Constant-Time Operations

**[SOUND]** The core permutation uses only:
- Wrapping addition (constant-time on all modern CPUs)
- Wrapping multiplication (constant-time on x86-64; may not be on all ARM implementations)
- Bitwise OR and shift (constant-time)
- No branches dependent on secret data

The tag comparison uses `subtle::ConstantTimeEq`, which is the standard approach.

**[CONCERN]** Wrapping multiplication (`wrapping_mul`) in Step 4 is constant-time on x86-64 but may have variable-time implementations on some microcontrollers or older ARM cores.  For the stated platform (Windows x86-64), this is not a concern.

### 5.2 Key Material Handling

**[SOUND]** `LockedBuffer` (`crypto.rs:50–77`) is well-designed:
- Heap-allocated (not stack, which can't be reliably locked)
- VirtualLock to prevent paging to disk
- Source array zeroized immediately after copy
- Unconditional zeroize on drop (even if VirtualLock failed)

**[SOUND]** `CmlSpongeState` implements Drop with zeroize for lattice, counter, and buffer.

**[CONCERN]** The `encrypt_in_place` function (`cml_sponge.rs:345`) allocates a keystream vector `vec![0u8; data.len()]` that is not zeroized after use.  Similarly, `aead_decrypt_chunk` (`cml_sponge.rs:419–422`) allocates keystream and ciphertext copies without zeroizing.  These transient buffers contain sensitive keystream bytes that may persist in memory after deallocation.  In practice, this is a minor concern (the allocator will reuse the memory), but for defense-in-depth, these should be zeroized.

### 5.3 Archive Extraction (GUI)

**[SOUND]** The archive extraction in `gui.rs:879–910` correctly sanitizes filenames by stripping path components and rejecting entries containing `..`.  This prevents path traversal attacks.

### 5.4 Password Validation

**[REASONABLE]** The password policy (min 18 chars, max 3 consecutive repeats) is a reasonable floor.  The maximum consecutive repeat check prevents trivially weak passwords like "aaaaaaaaaaaaaaaaaa".  However, the policy does not check against dictionaries or common patterns.  This is acknowledged in the documentation.

---

## 6. Code Quality

### 6.1 Architecture

The codebase is well-structured:

- `cml_sponge.rs` — core primitive (515 lines, self-contained)
- `crypto.rs` — high-level encrypt/decrypt with KDF (484 lines)
- `gui.rs` — egui GUI (982 lines, clean separation from crypto)
- `main.rs` — CLI entry point (139 lines)
- `error.rs` — error types (39 lines)
- `utils.rs` — compression, file info (150 lines)
- `lib.rs` — module exports (59 lines)

The separation between the sponge primitive and the high-level API is clean.  The GUI has no access to crypto internals beyond the public API.

### 6.2 Test Coverage

The test suite is comprehensive:

- **`cml_sponge_tests.rs`** (517 lines): 4 test vectors, complement symmetry, round-trip, key/IV sensitivity, stream consistency, AEAD domain separation, Cat Map algebraic properties.
- **`round_trip.rs`** (318 lines): Full encrypt/decrypt round-trips, error cases, edge cases (empty plaintext, max extension, flags), progress monotonicity.
- **`cml_reduced_round.rs`** (159 lines): Reduced-round statistical distinguisher.

**[SOUND]** The test vector approach (TV1–TV4 with known-answer tests) is the gold standard for cipher testing.  The complement symmetry tests (TV2 vs TV3) directly verify the critical property.

**[CONCERN]** There are no tests for multi-chunk AEAD (i.e., calling `aead_encrypt_chunk` multiple times with different chunk sizes and verifying the tag matches a single-chunk encryption of the same data).  The streaming encrypt in `crypto.rs` uses 64 KB chunks, so this code path is exercised indirectly by the round-trip tests, but explicit multi-chunk AEAD tests would strengthen confidence.

### 6.3 Benchmarking

**[SOUND]** The Criterion benchmark suite (`catwalk_bench.rs`, 165 lines) covers permutation, keystream, AEAD encrypt/decrypt at multiple sizes, and KDF.  The `benchmarks.md` documentation is thorough and includes interpretation of the results.

### 6.4 Documentation

**[SOUND]** The documentation is exceptional for a research project:

- `design.md` — complete construction specification (reimplementable from scratch)
- `security_argument_final.md` — formal security argument with proof/conjecture/empirical taxonomy
- `coupling_5term_evaluation.md` — exhaustive search over coupling candidates
- `practrand_results.md` — complete statistical validation results
- Inline doc comments on all public functions and critical internal functions

The honest delineation between PROOF, CONJECTURE, and EMPIRICAL claims in the security argument is commendable and unusual for a personal project.

---

## 7. Novelty and Contribution

### 7.1 What Is Novel

1. **CML-Sponge construction.** Using a Coupled Map Lattice as the permutation inside a standard sponge framework is, to the evaluator's knowledge, novel.  CMLs have been studied in chaos-based cryptography (Kocarev, Lian, Patidar, etc.), but typically as raw stream ciphers without the sponge wrapper.  The sponge framework provides a well-understood security model (indifferentiability from a random oracle) that the raw CML approach lacks.

2. **Arnold's Cat Map as a cryptographic primitive.** The Cat Map has been studied in image encryption (Fridrich, 1998; Chen et al., 2004), but its use in a rigorous sponge construction with formal capacity analysis is novel.

3. **Comprehensive coupling topology analysis.** The exhaustive search over all 1365 coupling distance combinations, with eigenvalue analysis, kernel computation, and diffusion verification, is thorough and provides a solid foundation for the design choice.

### 7.2 What Is Not Novel

1. **The sponge framework** — this is Bertoni et al. (2007/2008), applied as specified.
2. **Argon2id KDF** — standard, per RFC 9106.
3. **Stafford Mix13** — well-known finalizer from SplitMix64.
4. **Multiplicative mixing** (`s *= (s' | 1)`) — similar to techniques in SNOW, Salsa20, and other word-oriented ciphers.
5. **Weyl counter injection** — standard technique (used in SplitMix64, PCG, etc.).

### 7.3 Contribution Assessment

CATWALK's primary contribution is demonstrating that a CML-based permutation can be wrapped in a standard sponge framework to produce a complete AEAD cipher with:
- Formally analyzable capacity (512 bits)
- Clean domain separation
- Empirical statistical quality (PractRand at 256 GB+)
- Reasonable throughput (~200 MB/s)

The open question is whether the CML-Sponge permutation is actually secure against algebraic and differential attacks — this would be the central question for any academic review.

---

## 8. Open Problems and Recommendations

### 8.1 Critical (Must Address Before Any Security Claim)

1. **Algebraic analysis of the round function.**  The affine structure of Steps 1–3 combined with the single multiplicative nonlinearity in Step 4 makes this construction structurally different from all widely-studied designs.  Compute the algebraic degree of the permutation output as a function of the input after 1, 2, 4, and 8 rounds.  If the degree grows slowly (e.g., < 2^8 after 8 rounds for even-indexed sites), consider adding additional nonlinear steps.

2. **Differential analysis of Step 4.**  Compute or bound the maximum differential probability of the multiplicative mixing step `y' = y × (x | 1)` for arbitrary input differences (Δx, Δy) → output difference Δy'.  This is the critical primitive for bounding multi-round differential characteristics.

3. **Linear analysis.**  Compute or bound the maximum linear correlation of Step 4.  Since Steps 1–3 are linear, any linear approximation of Step 4 extends freely through those steps, so the linear security of the full round depends entirely on Step 4's resistance to linear approximation.

### 8.2 Important (Should Address for Credibility)

4. **Reduced-round PractRand.**  Run PractRand at 1, 2, 3, 4, and 5 rounds to determine the minimum round count at which statistical distinguishers fail.  This establishes the empirical security margin.  The existing `cml_reduced_round` binary and `cml_rr_dump` utility make this straightforward.

5. **Consider strengthening the nonlinear layer.**  Options include:
   - Apply multiplicative mixing to all 16 sites (not just odd-indexed ones)
   - Add a second nonlinear step (e.g., a bitwise AND/OR operation)
   - Use the Cat Map's output to modulate the multiplicative mixing (creating a degree-3 term)

   Any change would require regenerating test vectors and re-running PractRand.

6. **Keystream zeroization.**  Add `zeroize()` calls for transient keystream buffers in `encrypt_in_place`, `aead_encrypt_chunk`, and `aead_decrypt_chunk`.

### 8.3 Nice to Have

7. **NIST SP 800-22 tests.**  Run the NIST statistical test suite as a complement to PractRand, particularly the multi-stream correlation tests.

8. **Period analysis.**  Compute or bound the period of the Cat Map [[1,1],[1,2]] on Z/2^64, and analyze how the Weyl counter injection affects the overall permutation period.

9. **Benchmark on ARM.**  Verify constant-time behavior of `wrapping_mul` on ARM targets if cross-platform use is anticipated.

10. **Multi-chunk AEAD tests.**  Add explicit tests that verify a multi-chunk encryption produces the same (ciphertext, tag) as a single-chunk encryption of the same data.

11. **Zero-copy decrypt.**  The `aead_decrypt_chunk` function allocates both a keystream buffer and a ciphertext copy.  A zero-copy implementation that absorbs the ciphertext before XOR-ing would eliminate one allocation and close the encrypt/decrypt performance gap noted in the benchmarks.

---

## Appendix: File-by-File Review Notes

### `src/cml_sponge.rs` (515 lines)

- Lines 139–143: `arnold_cat_map` — correctly implements [[1,1],[1,2]] in symplectic order.  `#[inline(always)]` is appropriate for a hot inner loop.
- Lines 149–188: `cml_round` — four steps in correct order.  Snapshot semantics preserved via `m[]` array.
- Lines 170–181: Multi-pass coupling — 5 sequential loops for SIMD friendliness.  The comment about 3× regression from a fused loop is valuable implementation knowledge.
- Lines 253–266: `absorb` — padding logic is correct.  The `while` loop for zero-padding is clear but allocates a Vec for every absorb call; for very high-throughput scenarios, a stack-allocated buffer would be preferable.
- Lines 383–395: `aead_encrypt_chunk` — correct order: keystream → XOR → absorb ciphertext.
- Lines 414–429: `aead_decrypt_chunk` — correct: saves ciphertext, XOR to plaintext, absorbs saved ciphertext.  The `ct.to_vec()` allocation is the source of the decrypt performance gap.
- Lines 441–452: `aead_finalize` — correct: empty absorb with DOMAIN_TAG, then squeeze 4 words.  Note: does NOT call `cml_permute` after the squeeze, so the state after finalization contains the tag in the rate portion.  This is fine since the state is not reused.

### `src/crypto.rs` (484 lines)

- Lines 50–77: `LockedBuffer` — clean RAII pattern.  The `src.zeroize()` at line 59 correctly erases the stack copy.
- Lines 136–160: `derive_key` — Argon2id with combined salt.  The `checked_shl` at line 144 prevents overflow for extreme m_log2 values.
- Lines 212–325: `encrypt` — complete and correct.  Progress reporting is clean.  The chunk size (64 KB) is reasonable for streaming.
- Lines 353–426: `decrypt` — header parsing is correct.  The KDF parameter check at line 393 is properly placed before `derive_key`.
- Lines 431–483: `decrypt_v9` — tag verification at line 471 correctly uses `ct_eq`.  Plaintext is only returned after verification passes.

### `src/gui.rs` (982 lines)

- Line 616: `auto_detect_mode` — the variable name `is_eddy` is a leftover from the pre-rename era.  Minor cosmetic issue; no functional impact.
- Lines 879–910: `extract_archive` — path traversal prevention is correct (strips to filename only, rejects `..`).
- Lines 783–788: `Drop for CatwalkGui` — correctly zeroizes password fields.

### `tests/cml_sponge_tests.rs` (517 lines)

- Comprehensive coverage of the sponge primitive.
- TV1–TV4 test hardcoded known-answer values — any change to the permutation would be detected.
- Cat Map algebraic property tests (lines 447–517) are a nice touch for verifying mathematical assumptions.

### `tests/round_trip.rs` (318 lines)

- Good coverage of error cases (invalid magic, truncated file, wrong version, weak KDF, tampered ciphertext/header/tag).
- Progress monotonicity tests are unusual and valuable.

### `benches/catwalk_bench.rs` (165 lines)

- Line 11: Comment says `eddy_bench` — leftover from rename.  No functional impact.
- Good coverage of all performance-relevant operations.
- The KDF benchmark uses minimum parameters (64 MB / 2 iterations) to keep benchmark runtime reasonable.

---

*End of evaluation report.*
