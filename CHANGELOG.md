# Changelog

All notable changes to Catwalk are documented here. Dates are UTC.

## 2026-06-10 — CLI hardening & verify-then-emit streaming

### Security
- **Verify-then-emit streaming decryption**: `decrypt_stream` now makes two
  passes — pass 1 decrypts and verifies the authentication tag without
  emitting anything; pass 2 re-decrypts and writes the authenticated
  plaintext, then re-checks the tag. No unverified plaintext (and no
  attacker-influenced input to the decompressor) ever reaches the output.
- **GUI secure-delete race fixed**: the original file is deleted only after
  the encryption worker completes successfully (previously the delete could
  fire on the next UI frame, before the worker had read the input).

### Added
- `--password-file PATH` on `encrypt` / `decrypt` / `archive` / `extract`
  for scripting (password is never accepted on the command line).
- Batch mode: when stdin is piped (and is not the data stream), the password
  is read from stdin; the interactive confirmation prompt is skipped.
- Clear error when stdin carries data and no password source is available
  (previously the process blocked forever on a console read).

### Changed
- CLI errors now print human-readable messages ("This file requires a
  keyfile for decryption") instead of Rust debug variant names.
- `publish = false` (proprietary research crate); cargo-deny passes clean
  (licenses, advisories, bans, sources).

## 2026-06-09 — Format v10: duplex AEAD (breaking format change)

### Changed
- **AEAD rebuilt as a SpongeWrap duplex** (`AeadSession`): one permutation
  per 64-byte block (keystream = Mix13(rate); ciphertext injected into the
  rate; permute) instead of v9's two permutations (squeeze + padded absorb).
  Measured: encrypt 64 KB 487 MiB/s, decrypt 1 MB 529 MiB/s — roughly
  2.8–3.4× the original implementation.
- **Chunking independence**: the session buffers partial blocks internally;
  ciphertext and tag no longer depend on how callers split the data (a v9
  footgun). Finalisation always injects exactly one DOMAIN_CT-padded
  terminal block, making message boundaries unambiguous.
- Format version byte 9 → **10**; BLAKE3 cipher-key context
  `catwalk.v9.cipher` → `catwalk.v10.cipher` (v9 and v10 files never share
  keys). v9 files are not readable; the format predates any release.
- Test vectors: TV1–TV4 (keystream) unchanged — the permutation is
  untouched and all PractRand evidence carries over. New pinned TV5
  (duplex ciphertext + tag).

### Removed
- Four superseded point-in-time review reports under `Support/docs/` and the
  redundant `cml_perf_test` binary (criterion bench covers it).

## 2026-06-09 — Hardening & performance wave

### Security
- Keystream buffer invalidation after every absorb (SpongeWrap chaining
  violation reachable through the public chunk API with unaligned chunks).
- Argon2 parameter **ceiling** on decryption (`m_log2 ≤ 22`, `t ≤ 16`,
  `p ≤ 16`): a crafted header can no longer demand a multi-terabyte KDF
  allocation as denial-of-service.
- Streaming decompression output capped at 4 GB (`CappedWriter`), closing a
  decompression-bomb gap (the in-memory path was already capped).
- Allocation-free absorb path no longer leaves an unzeroized heap copy of
  absorbed key material.

### Changed
- AEAD data path made allocation-free (in-place keystream XOR, direct
  absorption from caller buffers): +51 % encrypt / +57 % decrypt throughput
  at 1 MB versus the 2026-03 baseline.
