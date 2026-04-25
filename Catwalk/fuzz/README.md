# CATWALK fuzz harnesses

LibFuzzer-based fuzzing for the high-risk parsing and decryption surfaces.

## Setup

Requires Rust **nightly** plus the `cargo-fuzz` extension:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Function under test | Property |
|--------|--------------------|----------|
| `fuzz_decrypt` | [`crypto::decrypt`](../src/crypto.rs) | Never panic on attacker-controlled input |
| `fuzz_parse_file_info` | [`utils::parse_file_info`](../src/utils.rs) | Header parser is panic-free |
| `fuzz_archive_extract` | [`archive::extract_archive`](../src/archive.rs) (feature `archive`) | ZIP extractor is panic-free; structural zip-slip safety is covered by `Support/tests/archive_tests.rs` |

## Run

From `Catwalk/`:

```bash
# Smoke run (60 seconds — fast feedback)
cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=60

# Long run (24 hours, persistent corpus)
cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=86400

# All targets, brief
for target in fuzz_decrypt fuzz_parse_file_info fuzz_archive_extract; do
    cargo +nightly fuzz run "$target" -- -max_total_time=120
done
```

Crashes are saved under `fuzz/artifacts/<target>/` for replay:

```bash
cargo +nightly fuzz run fuzz_decrypt fuzz/artifacts/fuzz_decrypt/crash-<hash>
```

## Corpus

The `corpus/` and `artifacts/` directories are git-ignored. To bootstrap a
seed corpus from existing test vectors, copy known-good `.catwalk` blobs into
`fuzz/corpus/fuzz_decrypt/` before running.

## CI

Fuzzing requires nightly and is not part of the default CI matrix. Run smoke
fuzz manually before tagging a release; track findings in `SECURITY.md`.
