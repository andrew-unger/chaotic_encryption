# CATWALK v10 — Organization and Documentation Audit

**Date:** 2026-03-20
**Scope:** Full repository organization and documentation accuracy review
**Phase 1:** Repository structure cleanup
**Phase 2:** Documentation accuracy verification against source code

---

## Repository Changes

### Phase 1 — Structure Verification

The repository structure was verified against the target layout. **No files needed to be moved** — the existing structure matches the target:

```
src/          — 7 source files + 7 binaries in src/bin/
tests/        — 2 test files
benches/      — 1 benchmark file
docs/         — 10 documentation files
tools/        — 1 batch script (tracked), 1 batch script + log directory (untracked)
```

### Files Verified (31 tracked files)

| Location | Files | Status |
|----------|-------|--------|
| `src/*.rs` | lib.rs, cml_sponge.rs, crypto.rs, error.rs, utils.rs, main.rs, gui.rs | Correct |
| `src/bin/*.rs` | catwalk_raw_dump, cml_keystream_dump, cml_perf_test, cml_reduced_round, cml_rr_dump, cml_rr_raw_dump, cml_zero_key_dump | Correct |
| `tests/*.rs` | cml_sponge_tests.rs, round_trip.rs | Correct |
| `benches/` | catwalk_bench.rs | Correct |
| `docs/*.md` | 10 documentation files | Correct |
| `tools/` | practrand_multi_seed.bat | Correct |
| Root | Cargo.toml, README.md, .gitignore, .cargo/config.toml | Correct |

### No files deleted or moved.

---

## .gitignore Updates

Added three entries to `.gitignore`:

| Entry | Reason |
|-------|--------|
| `*.log` | PractRand log files generated in root directory during validation runs |
| `*.tmp` | Temporary files |
| `tmp/` | Temporary directory |

Pre-existing entries (unchanged): `target/`, `testing_grounds/`, `Cargo.lock`, `*.exe`, `.claude/`

### Build artifacts check
- `git ls-files | grep "^target/"` — zero matches (target/ not tracked) ✓
- `git ls-files | grep -E "\.(exe|dll|pdb|obj)"` — zero matches ✓
- `git ls-files | grep -E "(test_output|tmp|temp|scratch|\.DS_Store)"` — zero matches ✓

### Duplicate document check
- `practrand_results.md` AND `practrand_1tb_v10.md` — both kept; different constructions. Warning note on practrand_results.md updated to reference v10 results.
- Only `security_argument_final.md` exists (no duplicate `security_argument.md`).
- No other duplicates found.

---

## Documentation Findings

### docs/design.md — ACCURATE

All construction claims verified against `src/cml_sponge.rs` and `src/crypto.rs`:

| Claim | Source location | Status |
|-------|----------------|--------|
| State: 16×u64, rate 0–7, capacity 8–15 | cml_sponge.rs:39,42,207 | ✓ |
| Cat Map: x'=x+y, y'=x'+y | cml_sponge.rs:139–142 | ✓ |
| Coupling: 5-term {1,3,7,11} | cml_sponge.rs:62–65,177–181 | ✓ |
| GOLDEN = 0x9E3779B97F4A7C15 | cml_sponge.rs:36 | ✓ |
| ROT = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,61] | cml_sponge.rs:69 | ✓ |
| Mix13: 0xBF58476D1CE4E5B9, 0x94D049BB133111EB | cml_sponge.rs:280,282 | ✓ |
| DOMAIN: KEY=0x01, IV=0x02, AAD=0x03, CT=0x04, TAG=0x05 | cml_sponge.rs:72–84 | ✓ |
| N_ROUNDS = 8 | cml_sponge.rs:46 | ✓ |
| KDF: Argon2id 256MB/4it, floor 64MB/2it | crypto.rs:92–98 | ✓ |
| BLAKE3: "catwalk.v9.cipher" (retained for v9 file compat) | crypto.rs:164 | ✓ |
| Tag: 32 bytes | cml_sponge.rs:450 | ✓ |
| Nonce: 16 bytes | crypto.rs:88 | ✓ |
| Parameters table | design.md:549–566 | ✓ (round count rationale updated with 4× margin in previous session) |

### docs/security_argument_final.md — ISSUES FOUND (6 fixes applied)

| # | Location | Issue | Fix |
|---|----------|-------|-----|
| 1 | §6 Attack 3 (lines 480–496) | PractRand table showed 5 seeds at 256 GB from OLD {1,7,8} coupling, presented as v10 validation | Replaced with structured tables: v10 at 1 TB (seeds 0,1), v10 raw at 32 GB, original {1,7,8} at 256 GB (baseline) — each with source doc reference |
| 2 | §7.4 (lines 597–600) | Marked "[MEDIUM PRIORITY]" and said reduced-round tests "have not been completed" | Updated to "[RESOLVED]" with summary of completed results: 2-round minimum, 4× margin |
| 3 | Attack 7 (lines 553–554) | Said "not yet formally completed" | Updated with formal results from reduced_round_analysis.md |
| 4 | Appendix D item 4 (line 719) | Said "No reduced-round PractRand" | Updated to "COMPLETED" with summary |
| 5 | Appendix D item 6 (line 723) | Said "No comparison to established designs" | Updated to note empirical comparison exists in reduced_round_analysis.md |
| 6 | Appendix D item 7 (line 725) | Stale coverage description (5 seeds at 256 GB only) | Updated with comprehensive v10 coverage: 1 TB seeds 0-1, raw 32 GB, original 256 GB |

### docs/coupling_5term_evaluation.md — ACCURATE

- Correction note at top: accurate ({1,5,11} had 4-element kernel, not 64) ✓
- Top-tier candidates include {1,3,7,11} ✓
- Comparison table (3-term vs 4-term vs 5-term) matches security argument ✓
- det(C) = ±33075 consistent across documents ✓

### docs/reduced_round_analysis.md — ACCURATE

- Tent map reference already replaced in previous session (lines 222–229) ✓
- Security margin: 2 rounds raw → 4× margin ✓
- ChaCha20 (2.9×) / AES-128 (1.7×) comparison numbers present ✓
- Round 6 raw "unusual" characterization accurate ✓

### docs/practrand_1tb_v10.md — ACCURATE

- Git commit hash: c002dfb6f92018197614a56b1b36764ab5fc0582 ✓
- Coupling distances: {1,3,7,11} ✓
- Seeds 0 and 1 results accurately recorded ✓
- Interpretation section updated with interim findings in previous session ✓

### docs/practrand_raw_permutation.md — ACCURATE

- Finding clearly stated: Mix13 is defense-in-depth, not load-bearing ✓
- Three seeds (0, 254, 255) at 32 GB, 325 tests each, zero failures ✓
- Comparison table accurate ✓

### docs/practrand_results.md — ISSUE FOUND (1 fix applied)

| # | Issue | Fix |
|---|-------|-----|
| 1 | Warning note was out of date — mentioned "v10 smoke test at 8 GB" and "Full 256 GB re-validation pending" but v10 seeds 0-1 have since completed 1 TB | Updated warning to reference practrand_1tb_v10.md and practrand_raw_permutation.md |

### README.md — ACCURATE

- v10 construction description matches current code ✓
- No old names (eddy, au79) ✓
- Security disclaimer present ✓
- BLAKE3 context string "catwalk.v9.cipher" correctly shown ✓

### docs/evaluation_report.md — ACCURATE (historical document)

Contains "eddy" references in findings about the pre-rename era. These are historical and accurate for the commit the evaluation covers. No changes made.

### docs/audit_report.md — ACCURATE (historical document)

References evaluation_report.md's eddy findings. Historical, no changes.

### docs/benchmarks.md — ACCURATE

Performance numbers documented against correct construction.

### tools/practrand_multi_seed.bat — ISSUE FOUND (1 fix applied)

| # | Issue | Fix |
|---|-------|-----|
| 1 | Referenced old binary name `target\release\keystream_dump.exe` | Updated to `target\release\cml_keystream_dump.exe` |

---

## Cross-Document Consistency

All key values verified consistent across every document that mentions them:

| Value | Documents checked | Status |
|-------|-------------------|--------|
| Coupling {1,3,7,11} | cml_sponge.rs, design.md, security_argument_final.md, coupling_5term_evaluation.md, reduced_round_analysis.md, practrand_1tb_v10.md, practrand_raw_permutation.md, README.md | ✓ Consistent |
| det(C) = −33075 | security_argument_final.md, coupling_5term_evaluation.md, design.md, README.md | ✓ Consistent |
| min\|λ_k\| = 1.259 | security_argument_final.md, coupling_5term_evaluation.md, design.md | ✓ Consistent |
| Capacity = 512 bits (full) | design.md, security_argument_final.md, coupling_5term_evaluation.md, README.md | ✓ Consistent |
| Security margin = 4× | design.md, security_argument_final.md, reduced_round_analysis.md | ✓ Consistent |
| Round count = 8 | cml_sponge.rs, design.md, security_argument_final.md, README.md | ✓ Consistent |
| Rate/capacity = 512/512 | cml_sponge.rs, design.md, security_argument_final.md, README.md | ✓ Consistent |

**No inconsistencies found.**

---

## Stale Reference Check

```
rg -i "tent|logistic|au79|eddy" docs/ src/ README.md --type markdown --type rust
```

Results:
- **tent/logistic/au79**: zero matches in any file ✓
- **eddy**: matches only in historical documents:
  - `docs/practrand_results.md:9` — git commit description "Rename project from EDDY to CATWALK" (historical fact)
  - `docs/audit_report.md:54` — documents a no-action finding about evaluation_report.md's historical references
  - `docs/evaluation_report.md:382,399` — historical evaluation findings from pre-rename commit

All "eddy" references are in historical context describing the actual rename. No active code or current documentation references removed primitives.

---

## Test Results

```
cargo test --all-features: 49 passed, 0 failed
  - 29 cml_sponge_tests
  - 19 round_trip tests
  - 1 doc-test

cargo clippy --all-features -- -D warnings: 0 warnings
```
