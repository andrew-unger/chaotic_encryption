# CLAUDE.md — Chaotic Encryption (CATWALK)

## Project Overview

**CATWALK** is a research-grade authenticated encryption tool built in Rust.
It implements a novel AEAD scheme on top of a CML-Sponge primitive (Coupled Map Lattice + sponge construction).

**This is research/experimental crypto — not production-hardened.**

## Repository Layout

```
chaotic_encryption/
├── Catwalk/          # Rust crate (library + CLI binary)
│   ├── src/
│   │   ├── lib.rs          — public API surface
│   │   ├── cml_sponge.rs   — core permutation primitive (CML lattice)
│   │   ├── crypto.rs       — AEAD layer (encrypt/decrypt, key schedule)
│   │   ├── utils.rs        — helpers (keyfile, zeroize wrappers, etc.)
│   │   ├── archive.rs      — optional zip archive support (feature = "archive")
│   │   ├── gui.rs          — optional egui GUI (feature = "gui")
│   │   ├── error.rs        — typed error enum
│   │   └── main.rs         — CLI entry point (clap)
│   └── Cargo.toml
└── Support/
    ├── README.md
    ├── tests/              — integration tests (cml_sponge_tests, round_trip, keyfile_tests)
    ├── benches/            — Criterion benchmarks
    ├── docs/
    └── paper/
```

## Cryptographic Design (summary)

- **Primitive:** 16×u64 (1024-bit) CML lattice — 512-bit rate / 512-bit capacity
- **Permutation:** Arnold's Cat Map + CML coupling (5-term polynomial) + Weyl counter injection, 8 rounds
- **Key schedule:** Argon2id (256 MB / 4 iters) → BLAKE3 domain derivation → 32-byte cipher key
- **AEAD mode:** SpongeWrap-style — absorb AAD (0x03), encrypt+absorb ciphertext (0x04), tag (0x05)
- **Security target:** 128-bit confidentiality/integrity; 256-bit pre-image on permutation state

## Build & Test

```bash
# Build CLI
cargo build --release

# Build with GUI
cargo build --release --features gui

# Run all tests
cargo test

# Run benchmarks
cargo bench

# Check + lint
cargo clippy -- -D warnings
cargo fmt --check
```

## Key Dependencies

| Crate     | Purpose                              |
|-----------|--------------------------------------|
| `argon2`  | Key derivation (Argon2id)            |
| `blake3`  | Domain-separated key derivation      |
| `zeroize` | Secure memory erasure of secrets     |
| `subtle`  | Constant-time comparisons            |
| `clap`    | CLI argument parsing                 |
| `flate2`  | DEFLATE compression                  |
| `zstd`    | Zstandard compression                |
| `eframe`/`egui` | GUI (optional feature)         |

## Security Notes

- `subtle` is used for all tag comparisons — never use `==` on authentication tags
- `zeroize` must be called on all key material after use — check drop impls
- `unsafe` blocks require `// SAFETY:` justification comments
- No secrets in error messages or log output
- `cargo audit` should be run before releases

## Coding Conventions

- Rust 2021 edition
- `thiserror` for library errors (`error.rs`)
- `Result<T, E>` + `?` propagation everywhere — no `unwrap()` outside tests
- `#[cfg(test)]` unit tests co-located with source; integration tests in `Support/tests/`
- Release profile: `opt-level=3`, `lto=true`, `panic=abort`, `strip=true`
