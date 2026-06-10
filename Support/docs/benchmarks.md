# CATWALK (CML-Sponge AEAD) — Performance Benchmarks

**Date:** 2026-06-09
**Crate version:** 0.1.0 (file format v10 — duplex AEAD)
**Rust toolchain:** stable (1.96)
**Profile:** release (opt-level=3, LTO=fat, codegen-units=1)
**Platform:** Windows 11 Pro (x86-64)
**Benchmark harness:** criterion 0.5.1 (100 samples, default warmup/measurement time)

All AEAD timings include session init (`AeadSession::new`) + `absorb_aad` +
encrypt/decrypt + `finalize`.  They do **not** include the Argon2id KDF; see
the `kdf_only` entry for that cost.

> **Changelog vs. the v11 (2026-06-09, pre-duplex) baseline:** the AEAD was
> rebuilt as a SpongeWrap duplex — one permutation per 64-byte block instead
> of two (squeeze + absorb), with a word-wise fast path for block-aligned
> data.  Measured same-machine A/B (criterion `--baseline v11`):
> **encrypt 64 KB +86%, decrypt 1 MB +119% throughput.**  Combined with the
> earlier allocation-elimination wave, total speedup since the 2026-03
> implementation is ≈ 2.8× (encrypt) to 3.4× (decrypt).

---

## Results

### Primitive operations

| Benchmark | Mean time | Notes |
|-----------|-----------|-------|
| `permutation_only` | 98.0 ns | 8 × CML rounds; 1024-bit state |
| `keystream_64b` | 105.4 ns | 579 MiB/s; cipher_init state reused across iterations |

### AEAD encrypt throughput (duplex)

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 2.80 µs | 349 MiB/s |
| 64 KB | 128.3 µs | 487 MiB/s |
| 1 MB | 2.38 ms | 419 MiB/s |

### AEAD decrypt throughput (duplex)

| Payload | Mean time | Throughput |
|---------|-----------|------------|
| 1 KB | 2.50 µs | 391 MiB/s |
| 64 KB | 118.6 µs | 527 MiB/s |
| 1 MB | 1.89 ms | 529 MiB/s |

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

**Permutation cost (98 ns per call):**
Each permutation applies 8 CML rounds over a 16×u64 (1024-bit) state.  The
duplex AEAD performs exactly one permutation per 64-byte block, so the raw
ceiling is `64 / 98ns ≈ 622 MiB/s`.  The measured streaming plateau of
~490–530 MiB/s sits at 80–85% of that ceiling; the gap is the per-block
Mix13 keystream read, the XOR/injection word loop, and session bookkeeping.

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

These numbers serve as the v10-duplex baseline.  To save them for future comparison:

```sh
cargo bench --bench catwalk_bench -- --save-baseline v10-duplex
```

To compare a future change against this baseline:

```sh
cargo bench --bench catwalk_bench -- --baseline v10-duplex
```

HTML reports are written to `target/criterion/` when `html_reports` feature is enabled.
