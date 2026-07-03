# CATWALK (CML-Sponge AEAD) — Performance Benchmarks

**Date:** 2026-06-10
**Crate version:** 0.1.0 (file format v10 — duplex AEAD)
**Rust toolchain:** stable (1.96)
**Profile:** release (opt-level=3, LTO=fat, codegen-units=1)
**Target CPU:** portable baseline (no `target-cpu` override — see note below)
**Platform:** Windows 11 Pro (x86-64, measured on a Ryzen 9 3900X)
**Benchmark harness:** criterion 0.5.1 (100 samples, default warmup/measurement time)

All AEAD timings include session init (`AeadSession::new`) + `absorb_aad` +
encrypt/decrypt + `finalize`.  They do **not** include the Argon2id KDF; see
the `kdf_only` entry for that cost.

> **Portable optimization pass (2026-06-10).** Two changes, both ISA-agnostic
> (they help every target, nothing machine-specific):
> 1. `cml_round` rewritten from array-with-modular-indexing to fully-unrolled
>    scalar SSA, cutting the per-round register spills (~117 → fewer stack
>    moves) — byte-for-byte identical output (all test vectors unchanged),
>    ~5% faster permutation.
> 2. Dropped the committed `-C target-cpu=native` build flag. For this scalar
>    64-bit-integer permutation it was a *pessimization* — LLVM's AVX2
>    autovectorization regressed the workload — as well as pinning binaries to
>    the build machine's ISA. Removing it is both portable and faster.
>
> Net same-machine effect vs. the pre-pass config: permutation 100.7 → 86.1 ns
> (**−15%**), AEAD 64 KB encrypt 488 → 629 MiB/s (**+29%**). (SIMD-accelerated
> dependencies blake3/zstd are unaffected — they do runtime CPU dispatch.)

---

## Results

### Primitive operations

| Benchmark | Mean time | Notes |
|-----------|-----------|-------|
| `permutation_only` | 86.1 ns | 8 × CML rounds; 1024-bit state |
| `keystream_64b` | 105.5 ns | 578 MiB/s; cipher_init state reused across iterations |

### AEAD encrypt throughput (duplex)

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 2.28 µs | 429 MiB/s |
| 64 KB | 99.4 µs | 629 MiB/s |
| 1 MB | 1.76 ms | 568 MiB/s |

### AEAD decrypt throughput (duplex)

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 2.46 µs | 396 MiB/s |
| 64 KB | 107.3 µs | 583 MiB/s |
| 1 MB | 1.90 ms | 526 MiB/s |

### Key derivation

| Benchmark | Mean time | Parameters |
|-----------|-----------|------------|
| `kdf_only` | 73.6 ms | Argon2id m=2^16 (64 MB), t=2, p=1 — minimum accepted by decrypt() |
| `kdf_only` (production) | ~1 s (estimated) | Argon2id m=2^18 (256 MB), t=4, p=1 — default encryption parameters |

> The production KDF estimate is extrapolated from the minimum-parameter
> measurement (m×4, t×2 ≈ 8× memory traffic).  Argon2id is not perfectly
> linear in memory due to cache effects; run `cargo bench -- kdf_only` with
> the parameters changed directly to measure the actual figure.

---

## Interpretation

**Permutation cost (86 ns per call):**
Each permutation applies 8 CML rounds over a 16×u64 (1024-bit) state.  The
duplex AEAD performs exactly one permutation per 64-byte block, so the raw
ceiling is `64 / 86ns ≈ 710 MiB/s`.  The measured streaming plateau of
~570–630 MiB/s sits at 80–89% of that ceiling; the gap is the per-block
Mix13 keystream read, the XOR/injection word loop, and session bookkeeping.

**Why no explicit SIMD / hand-vectorization:**
The permutation is scalar 64-bit integer work.  The only lever big enough to
matter would be vectorizing the round, but it does not pay off here and is not
portable: (a) the sole nonlinear step is a 64-bit multiply, which has no AVX2
equivalent (`vpmullq` is AVX-512DQ-only), forcing awkward 32×32 emulation;
(b) the 5-tap ring coupling needs heavy cross-lane shuffles that eat the
additive-layer savings; and (c) most decisively, the duplex chaining
serialises permutations (each block depends on the previous), so the
independent-lane batching that makes SIMD ciphers fast is structurally
impossible for a single message.  The fastest portable form is well-scheduled
scalar — which is why `target-cpu=native` (LLVM trying to vectorise anyway)
measured *slower* here.

**Duplex vs. the retired two-permutation mode:**
The v9-format AEAD cost 2 permutations per 64 bytes (squeeze for keystream,
padded absorb for authentication), capping it at ~285 MiB/s.  The duplex
halves the permutation count, and the block-aligned fast path processes data
word-wise directly between the caller's buffer and the rate with no staging
buffers.  Encrypt and decrypt are now within noise of each other.

**Chunking independence:**
Unlike the retired mode, the duplex session buffers partial blocks, so
ciphertext and tag are invariant under the caller's chunking; the streaming
and in-memory paths produce identical bytes by construction.

**KDF dominates at interactive scale:**
At ~74 ms for the minimum-parameter KDF (and ~1 s for production parameters),
the KDF completely dominates encryption time for any file smaller than a few
hundred megabytes.  This is intentional — the KDF cost is what makes offline
password-guessing attacks expensive.

---

## Baseline and regression tracking

These numbers serve as the `portable-v1` baseline.  To save them for future comparison:

```sh
cargo bench --bench catwalk_bench -- --save-baseline portable-v1
```

To compare a future change against this baseline:

```sh
cargo bench --bench catwalk_bench -- --baseline portable-v1
```

Measure like-for-like: keep the same `target-cpu` (the default, portable
baseline) on both sides, since the target CPU affects results as much as the
code does.

HTML reports are written to `target/criterion/` when `html_reports` feature is enabled.
