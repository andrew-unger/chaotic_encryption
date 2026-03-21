# CATWALK v10 — Final Pre-Submission Review

**Date:** 2026-03-21
**Reviewer:** Final automated review
**Baseline commit:** `4010a78` (pre-review)
**Purpose:** Pre-ePrint submission verification — ensure the repository, code, paper, and documentation are consistent, accurate, and ready for public scrutiny.

---

## Cross-Reference Results

### Paper vs Code (14 checks)

| # | Check | Paper value | Code location | Verdict |
|---|-------|-------------|---------------|---------|
| 1 | Coupling distances | {1, 3, 7, 11} | `cml_sponge.rs` L62–65 (D1=1, D2=3, D3=7, D4=11) | **MATCH** |
| 2 | Cat Map formula | x'=x+y, y'=x'+y (symplectic) | `cml_sponge.rs` L140–141 | **MATCH** |
| 3 | Weyl constant | 0x9E3779B97F4A7C15 | `cml_sponge.rs` L36 | **MATCH** |
| 4 | ROT values | [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,61] | `cml_sponge.rs` L69 | **MATCH** |
| 5 | Mix13 constants | 0xBF58476D1CE4E5B9, 0x94D049BB133111EB | `cml_sponge.rs` L280, L282 | **MATCH** |
| 6 | Domain bytes | KEY=0x01, IV=0x02, AAD=0x03, CT=0x04, TAG=0x05 | `cml_sponge.rs` L72–84 | **MATCH** |
| 7 | Round count | 8 | `cml_sponge.rs` L46 (N_ROUNDS=8) | **MATCH** |
| 8 | Rate/capacity split | 512/512, sites 0–7 / 8–15 | `cml_sponge.rs` L42 (N_RATE=8), absorb L242–244, squeeze L291 | **MATCH** |
| 9 | Tag size | 32 bytes | `cml_sponge.rs` L445, L450 (aead_finalize → [u8; 32]) | **MATCH** |
| 10 | Argon2id params | 256MB/4it default, 64MB/2it floor | `crypto.rs` L92–98 | **MATCH** |
| 11 | Nonce size | 16 bytes | `crypto.rs` L88 (NONCE_LEN=16) | **MATCH** |
| 12 | Encrypt-then-MAC | squeeze → XOR → absorb ciphertext | `cml_sponge.rs` L384–397 (aead_encrypt_chunk) | **MATCH** |
| 13 | Tag verified before return | ct_eq check before Ok() | `crypto.rs` L470–473 | **MATCH** |
| 14 | BLAKE3 context string | "catwalk.v9.cipher" (with footnote) | `crypto.rs` L164 | **MATCH** |

**Result: 14/14 MATCH. Zero discrepancies between paper and code.**

### Paper vs Documentation

| Value | Paper | Documentation | Verdict |
|-------|-------|---------------|---------|
| det(C) = −33075 | §4.6 | security_argument_final.md §1.2, coupling_5term_evaluation.md | **MATCH** |
| min\|λ_k\| = 1.259 | §4.6 | coupling_5term_evaluation.md §Executive Summary | **MATCH** |
| Effective capacity = 512 bits | §3.6, §5.1 | security_argument_final.md §1.2 | **MATCH** |
| Security margin = 4× | §6.4 | reduced_round_analysis.md | **MATCH** |
| PractRand 1 TB seeds 0,1 | §6.2 | practrand_1tb_v10.md (seeds 0,1 complete) | **MATCH** |
| Round count = 8 | §2.4, §3.6 | design.md §2.3 | **MATCH** |
| Coupling distances {1,3,7,11} | Throughout | design.md, security_argument_final.md | **MATCH** |

**Result: All values consistent.**

### README Accuracy

| Check | Status |
|-------|--------|
| Coupling distances {1,3,7,11} mentioned | ✅ Present (line 177) |
| Security disclaimer (research, not audited) | ✅ Present (lines 257–264) |
| Build/usage instructions current | ✅ Accurate |
| Paper referenced | ✅ Added in this review |
| No stale eddy/au79 references | ✅ Clean |
| v9/v10 relationship explained | ✅ Version Note section (line 212) |

### Test Coverage

| Property | Test file | Test name(s) | Covered? |
|----------|-----------|-------------|----------|
| Round-trip encrypt/decrypt | round_trip.rs, cml_sponge_tests.rs | round_trip_basic, round_trip_encrypt_decrypt, etc. | ✅ |
| Test vectors TV1–TV4 | cml_sponge_tests.rs | tv1–tv4 | ✅ |
| Complement symmetry (TV2 ≠ TV3) | cml_sponge_tests.rs | tv3_all_ff_key_iv, complement_symmetry_broken | ✅ |
| Key sensitivity (1-bit) | cml_sponge_tests.rs | key_sensitivity_one_bit | ✅ |
| IV sensitivity (1-bit) | cml_sponge_tests.rs | iv_sensitivity_one_bit | ✅ |
| AEAD tag binding (tampered CT) | cml_sponge_tests.rs, round_trip.rs | aead_tag_changes_with_ciphertext_tamper, tampered_ciphertext_fails | ✅ |
| AEAD tag binding (tampered header) | round_trip.rs | tampered_header_fails | ✅ |
| Domain separation (AAD ≠ CT) | cml_sponge_tests.rs | aead_absorb_aad_domain_separation | ✅ |
| Wrong password rejection | round_trip.rs | wrong_password_fails | ✅ |
| Truncated file rejection | round_trip.rs | truncated_file_rejected | ✅ |
| Progress monotonicity | round_trip.rs | progress_is_monotone_encrypt, progress_is_monotone_decrypt | ✅ |
| Multi-chunk AEAD consistency | cml_sponge_tests.rs | aead_multi_chunk_encrypt_decrypt_roundtrip | ✅ |

**Result: All 12 claimed properties have corresponding tests. No gaps.**

### Dependencies

| Crate | Version | Purpose | Security status |
|-------|---------|---------|-----------------|
| argon2 | 0.5.0 | KDF | RustCrypto; no known advisories |
| blake3 | 1.4.1 | Subkey derivation | Official; no known advisories |
| flate2 | 1.0.26 | Compression | Standard; no known advisories |
| rand | 0.8.5 | Random salt/nonce | Standard; no known advisories |
| rpassword | 7.2.0 | Terminal password input | Standard; no known advisories |
| subtle | 2.5.0 | Constant-time comparison | RustCrypto; used for ct_eq ✅ |
| zeroize | 1.6.0 | Secure memory wiping | RustCrypto; used for keys/state ✅ |
| criterion | 0.5 (dev) | Benchmarks | Not in production binary |
| eframe/egui | 0.31 (optional) | GUI | Feature-gated ✅ |
| rfd | 0.15 (optional) | File dialogs | Feature-gated ✅ |
| zip | 2.4 (optional) | Archive mode | Feature-gated ✅ |

**Result: All security-critical dependencies (subtle, zeroize, argon2, blake3) are present and from trusted sources. GUI dependencies are properly feature-gated.**

### File System

| Check | Status |
|-------|--------|
| README.md | ✅ Present, accurate |
| LICENSE | ⚠️ **Not present** — README states "not licensed for redistribution" |
| CHANGELOG | Not present (noted, not created) |
| .gitignore | ✅ Covers target/, *.log, *.exe, *.tmp, tmp/, .claude/ |
| Cargo.toml metadata | ✅ Fixed in this review (added authors, repository, readme) |
| paper/ directory | ✅ catwalk.tex + refs.bib |
| docs/ directory | ✅ 11 documentation files |
| Untracked files not in VCS | ✅ claude.exe, *.log files are untracked (gitignored) |

### API Surface

| Function | Doc comment | Accurate | Visibility |
|----------|-----------|----------|------------|
| cipher_init | ✅ Comprehensive (nonce reuse warning) | ✅ | pub |
| keystream | ✅ | ✅ | pub |
| encrypt_in_place | ✅ (minimal) | ✅ | pub |
| decrypt_in_place | ✅ (minimal) | ✅ | pub |
| absorb_aad | ✅ | ✅ | pub |
| aead_encrypt_chunk | ✅ | ✅ | pub |
| aead_decrypt_chunk | ✅ Comprehensive (security contract) | ✅ | pub |
| aead_finalize | ✅ Comprehensive | ✅ | pub |
| cml_permute_r | ✅ | ✅ | pub (needed by bins) |
| raw_rate_bytes | ✅ (notes testing purpose) | ✅ | pub (needed by bins) |
| cipher_init_r | ✅ | ✅ | pub (needed by bins) |
| keystream_r | ✅ (minimal) | ✅ | pub (needed by bins) |

**Note on `raw_rate_bytes` visibility:** It is `pub` and used by `src/bin/catwalk_raw_dump.rs` and `src/bin/cml_rr_raw_dump.rs`. Since binaries in the same crate access the library through the public API, `pub` is correct and required. The doc comment clearly marks it as testing-only.

**CmlSpongeState fields:** `lattice` and `counter` are `pub(crate)` (not externally visible). `buf`, `buf_len`, `buf_pos` are private. No internal state is inadvertently exposed to external callers.

---

## Issues Found and Fixed

### Issue 1 — Stale "Störmer–Verlet" reference in doc comment (Medium)

**What:** `cml_sponge.rs` line 94 doc comment described the Cat Map computation order as "Störmer–Verlet integration order." Störmer–Verlet is a numerical ODE integration method, not the correct term for the Cat Map's symplectic matrix decomposition.

**Which is correct:** The paper correctly describes this as "symplectic order" without the Störmer–Verlet attribution. This reference was supposed to have been removed in a prior review round but was missed.

**Fix:** Removed "(Störmer–Verlet)" from the doc comment. Changed to "symplectic integration order."

### Issue 2 — Missing Cargo.toml metadata (Low)

**What:** Cargo.toml was missing `authors`, `repository`, and `readme` fields. For a crate that will be publicly visible alongside the paper, this metadata should be present.

**Fix:** Added `authors = ["Andrew Unger"]`, `repository = "https://github.com/andrew-unger/chaotic_encryption"`, `readme = "README.md"`.

### Issue 3 — README did not mention the paper (Low)

**What:** The README documented the construction thoroughly but did not mention that a formal paper exists in `paper/`. A cryptographer cloning the repo would not know to look there.

**Fix:** Added a "Paper" section to README between the Overview and Installation sections, referencing `paper/catwalk.tex` and briefly describing its contents.

---

## Issues Requiring Human Decision

### 1. LICENSE file

The repository has no LICENSE file. The README states "This project is for personal use only and is not licensed for redistribution." Before ePrint submission:

- If the intention is for the code to be reviewable but not redistributable, the current state is fine (no license = all rights reserved).
- If the intention is for the code to be openly usable, add a license file (MIT, Apache-2.0, or similar).
- Consider adding a license field to Cargo.toml once decided.

### 2. Cargo.lock tracking

`Cargo.lock` is gitignored. For a binary crate, the Rust community recommends tracking `Cargo.lock` to ensure reproducible builds. This is a minor preference and not blocking.

### 3. CLI `--password` flag

The CLI uses `rpassword::prompt_password()` which reads from the terminal. There is no `--password` flag for scripted/non-interactive use. This means CLI round-trip testing cannot be automated. The integration tests in `round_trip.rs` cover the same code path, so this is not a gap in test coverage — but a reviewer attempting manual CLI testing will need to type the password interactively.

---

## Test Results

```
cargo test --all-features
  cml_sponge_tests:  29 passed
  round_trip:        19 passed
  doc-tests:          1 passed
  TOTAL:             49 passed, 0 failed

cargo clippy --all-features -- -D warnings
  0 warnings

cargo build --release --all-features
  OK

cargo build --release --no-default-features
  OK

cargo bench --bench catwalk_bench -- permutation_only
  permutation_only: 97.9 ns (smoke test: OK)

CLI round-trip (encrypt/decrypt/tamper/wrong-password):
  SKIPPED — rpassword reads from terminal; cannot pipe password.
  Equivalent coverage provided by round_trip.rs integration tests.
```

---

## Submission Readiness Assessment

### Code

The reference implementation is ready for public release alongside the paper.

A cryptographer auditing `src/cml_sponge.rs` would find:
- 533 lines of well-documented Rust with extensive doc comments on every public function
- The construction exactly matches the paper specification (14/14 checks passed)
- Clear separation of concerns: constants, local map, round function, permutation, sponge operations, AEAD, reduced-round variants
- Security-relevant contracts documented (nonce reuse warning on `cipher_init`, no-output-before-verification on `aead_decrypt_chunk`)
- Zeroize-on-drop for all state
- Constant-time tag comparison via `subtle::ConstantTimeEq`
- No unsafe code in the cipher core

### Documentation

The documentation is ready for public release. It is consistent with the code and paper:
- `docs/design.md` — complete construction specification
- `docs/security_argument_final.md` — formal security argument with honest claim labeling
- `docs/coupling_5term_evaluation.md` — exhaustive search methodology
- `docs/reduced_round_analysis.md` — reduced-round PractRand results
- `docs/practrand_1tb_v10.md` — 1 TB validation (in progress)
- `docs/practrand_raw_permutation.md` — raw permutation validation
- All numerical values cross-checked against code and paper

### Paper

No remaining issues were found in the paper during this review. All 14 construction values in the paper match the code exactly. The paper's claims about PractRand results, coupling properties, and security margins are consistent with the documentation.

### Overall Verdict

**READY WITH MINOR FIXES — all fixes applied in this review.**

Blocking issues: **0**
Issues fixed: **3** (Störmer-Verlet doc comment, Cargo.toml metadata, README paper reference)
Issues requiring human decision: **3** (LICENSE file, Cargo.lock tracking, CLI --password flag — none blocking)
