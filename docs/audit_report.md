# CATWALK v10 — Self-Directed Codebase Audit Report

**Date:** 2026-03-20
**Auditor:** Claude (Anthropic), acting as code reviewer
**Baseline commit:** `896f884d9cdc1b618ec91b26ec2c7ff32a634f09`
**Scope:** All `.rs` source files, all `docs/*.md`, all `tests/*.rs`, `benches/`, `Cargo.toml`

---

## Executive Summary

A complete read of every file in the CATWALK codebase was performed, followed by a
systematic issue inventory organized by category.  **19 issues** were identified across
7 categories.  **14 issues** were fixed; **5** were classified as no-action (correct by
design or crossing the design line).

**No bugs were found.**  No security issues were found beyond what was already fixed in
the prior session (keystream buffer zeroization) and documented as open questions
(algebraic/differential analysis — see `docs/security_argument_final.md` §7).

All 49 tests pass.  Clippy reports zero warnings.  The release library builds cleanly.

---

## Methodology

1. **Phase 1 — Read Everything:** Every source file, test file, benchmark, doc, and
   config file was read in full.
2. **Phase 2 — Find Everything:** A complete issue inventory was produced, categorized
   as CAT-BUG, CAT-SEC, CAT-CONSISTENCY, CAT-STALE, CAT-TEST, CAT-QUALITY, CAT-DOC.
3. **Phase 3 — Fix Everything Safe:** Each issue was fixed one at a time with
   `cargo check` after each change.
4. **Phase 4 — Test Everything:** Full test suite (`cargo test --all-features`),
   clippy (`cargo clippy --all-features -- -D warnings`), doc-tests, release build.
5. **Phase 5 — This report.**

---

## Issue Inventory

### CAT-STALE — Stale References (11 found, 10 fixed, 1 no-action)

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| S1 | `benches/catwalk_bench.rs` | 132 | Stale `eddy_bench` reference in KDF comment | **Fixed** → `catwalk_bench` |
| S2 | `src/cml_sponge.rs` | 29 | References deleted Python reference implementation | **Fixed** → references test vectors |
| S3 | `docs/design.md` | 5 | Lists deleted Python file as implementation | **Fixed** → removed |
| S4 | `docs/design.md` | 69 | Says "4 CML rounds" for full diffusion; should be 2 | **Fixed** → `2` |
| S5 | `docs/security_argument_final.md` | 687 | References deleted Python impl; says "28 unit tests" | **Fixed** → removed Python ref, updated to 29 |
| S6 | `docs/security_argument_final.md` | 592 | §7.7 discusses 5-term coupling as "potential improvement" — already implemented | **Fixed** → marked as RESOLVED |
| S7 | `docs/benchmarks.md` | 94,97 | `--save-baseline v9` should be `v10` | **Fixed** → `v10` |
| S8 | `docs/practrand_results.md` | 183–184 | Duplicate bullet point | **Fixed** → removed duplicate |
| S9 | `README.md` | 18 | False v8 backward compatibility claim in feature list | **Fixed** → removed |
| S10 | `README.md` | 186 | Incorrect decrypt pseudocode order | **Fixed** → corrected to match actual implementation |
| S11 | `README.md` | 212 | False v8 backward compatibility section | **Fixed** → replaced with version note |
| S12 | `docs/practrand_results.md` | 27 | Old context strings for {1,7,8} results | **No action** — document describes old results correctly |

### CAT-CONSISTENCY — Naming / Version Inconsistencies (3 found, 1 fixed)

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| C1 | `src/cml_sponge.rs` | 9 | Python reference mention in test header | **Covered by S2** |
| C2 | `docs/design.md` | 564 | BLAKE3 context string `"catwalk.v9.cipher"` retained for compatibility | **No action** — intentional |
| C3 | `README.md` | 249 | Stale PractRand stats ("128 GB+, 355+ tests") | **Fixed** → updated to current results |

### CAT-DOC — Documentation Issues (2 found, both fixed)

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| D1 | `docs/security_argument_final.md` | 685 | Test count "28" should be "29" | **Fixed** (merged with S5) |
| D2 | `docs/design.md` | 69 | Diffusion round count error | **Fixed** (same as S4) |

### CAT-QUALITY — Code Quality (1 found, fixed)

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| Q1 | `src/crypto.rs` | 350,352 | Doc comment references `AuthenticationFailed` and `DecompressionFailed` — actual variants are `IntegrityCheckFailed` and `DecompressionTooLarge` | **Fixed** |

### CAT-TEST — Test Coverage (2 found, both addressed with comments)

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| T1 | `tests/round_trip.rs` | 16 | Short test passwords bypass 18-char minimum | **No action** — intentional; added explanatory comment |
| T2 | `tests/round_trip.rs` | various | Multiple short test passwords | **No action** — covered by T1 comment |

### CAT-BUG — Bugs (0 found)

No functional bugs were found in the codebase.

### CAT-SEC — Security Issues (0 new found)

No new security issues were found beyond:
- Keystream buffer zeroization (fixed in prior session)
- Open questions documented in `docs/security_argument_final.md` §7 (algebraic attacks,
  differential/linear analysis, period structure — these are research questions, not bugs)

---

## Test Results (Post-Fix)

```
cargo test --all-features
  cml_sponge_tests:  29 passed
  round_trip:        19 passed
  doc-tests:          1 passed
  TOTAL:             49 passed, 0 failed

cargo clippy --all-features -- -D warnings
  0 warnings

cargo build --release --lib
  OK (full release blocked only by locked cml_keystream_dump.exe from active PractRand run)
```

---

## Summary

| Category | Found | Fixed | No-Action |
|----------|-------|-------|-----------|
| CAT-STALE | 12 | 10 | 2 |
| CAT-CONSISTENCY | 3 | 1 | 2 |
| CAT-DOC | 2 | 2 | 0 |
| CAT-QUALITY | 1 | 1 | 0 |
| CAT-TEST | 2 | 0 | 2 |
| CAT-BUG | 0 | 0 | 0 |
| CAT-SEC | 0 | 0 | 0 |
| **Total** | **20** | **14** | **6** |

No cryptographic design decisions were changed.  No test vectors were modified.
No PractRand documents or running tests were affected.
