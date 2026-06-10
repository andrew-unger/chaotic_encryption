# CATWALK (CML-Sponge AEAD) — Performance Benchmarks

**Date:** 2026-06-09
**Crate version:** 0.1.0
**Rust toolchain:** stable (1.96)
**Profile:** release (opt-level=3, LTO=fat, codegen-units=1)
**Platform:** Windows 11 Pro (x86-64)
**Benchmark harness:** criterion 0.5.1 (100 samples, default warmup/measurement time)

All AEAD timings include `cipher_init` + `absorb_aad` + encrypt/decrypt chunk + `aead_finalize`.
They do **not** include the Argon2id KDF; see the `kdf_only` entry for that cost.

> **Changelog vs. the 2026-03-18 baseline:** the AEAD data path was made
> allocation-free — `absorb` no longer copies its input into a padded heap
> buffer (full blocks are absorbed directly from the caller's slice), the
> keystream is XOR-ed into the data in place instead of being materialised in
> a scratch buffer, and `aead_decrypt_chunk`'s scratch shrank from 2× to 1×
> the chunk length.  Measured same-machine A/B (criterion `--baseline`):
> **encrypt 1 MB +51% throughput, decrypt 1 MB +57% throughput.**

---

## Results

### Primitive operations

| Benchmark | Mean time | Notes |
|-----------|-----------|-------|
| `permutation_only` | 107.4 ns | 8 × CML rounds; 1024-bit state |
| `keystream_64b` | 113.4 ns | 538 MiB/s; cipher_init state reused across iterations |

### AEAD encrypt throughput

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 4.26 µs | 229 MiB/s |
| 64 KB | 220.0 µs | 284 MiB/s |
| 1 MB | 3.87 ms | 259 MiB/s |

### AEAD decrypt throughput

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 4.23 µs | 231 MiB/s |
| 64 KB | 223.7 µs | 279 MiB/s |
| 1 MB | 4.22 ms | 237 MiB/s |

Encrypt and decrypt are now nearly symmetric: the former decrypt penalty came
from a keystream buffer plus a `2 × len` scratch resize per chunk, both of
which are gone.  The remaining ~8% gap at 1 MB is the unavoidable ciphertext
copy decrypt must keep so the pre-XOR bytes can be absorbed for authentication.

### Key derivation

| Benchmark | Mean time | Parameters |
|-----------|-----------|------------|
| `kdf_only` | 78.4 ms | Argon2id m=2^16 (64 MB), t=2, p=1 — minimum accepted by decrypt() |
| `kdf_only` (production) | ~1 s (estimated) | Argon2id m=2^18 (256 MB), t=4, p=1 — default encryption parameters |

> The production KDF estimate is extrapolated from the minimum-parameter
> measurement (m×4, t×2 ≈ 8× memory traffic).  Argon2id is not perfectly
> linear in memory due to cache effects; run `cargo bench -- kdf_only` with
> the parameters changed directly to measure the actual figure.

---

## Interpretation

**Permutation cost (107 ns per call):**
Each permutation applies 8 CML rounds over a 16×u64 (1024-bit) state.  At 107 ns
per call and 64 bytes of output per squeeze, the raw permutation throughput
ceiling is `64 / 107ns ≈ 570 MiB/s`.  The measured keystream rate of 538 MiB/s
is within 6% of that ceiling — the buffered-squeeze path adds almost no overhead.

**Streaming throughput plateau (~280 MiB/s):**
Throughput rises from ~230 MiB/s at 1 KB to a plateau of ~280 MiB/s at 64 KB
as the fixed `cipher_init` cost amortises away.  The plateau is dominated by
the absorb step in `aead_encrypt_chunk`/`aead_decrypt_chunk`: each 64-byte
ciphertext block costs one absorb permutation in addition to the squeeze
permutation for keystream, i.e. 2 permutations per 64 bytes
(`64 / (2 × 107ns) ≈ 285 MiB/s` theoretical ceiling — the measured plateau
sits essentially on it).  Any further large gain would require a duplex-style
mode that combines squeeze and absorb in a single permutation pass, which is
a file-format-breaking design change.

**KDF dominates at interactive scale:**
At ~78 ms for the minimum-parameter KDF (and ~1 s for production parameters),
the KDF completely dominates encryption time for any file smaller than a few
hundred megabytes.  This is intentional — the KDF cost is what makes offline
password-guessing attacks expensive.

---

## Baseline and regression tracking

These numbers serve as the v11 baseline.  To save them for future comparison:

```sh
cargo bench --bench catwalk_bench -- --save-baseline v11
```

To compare a future change against this baseline:

```sh
cargo bench --bench catwalk_bench -- --baseline v11
```

HTML reports are written to `target/criterion/` when `html_reports` feature is enabled.
