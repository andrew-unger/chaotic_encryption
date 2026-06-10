# CATWALK: Chaotic Encryption Tool

## Overview

CATWALK is a file encryption tool built on a novel chaotic stream cipher. The v10 cipher (CML-Sponge) uses a 16-site Coupled Map Lattice operating as a cryptographic sponge — providing authenticated encryption natively without a separate MAC primitive. Key derivation is handled by Argon2id and all key material is memory-locked and zeroized after use.

Available as both a command-line tool and a cross-platform graphical application.

## Features

- **CML-Sponge AEAD** — 16-site Coupled Map Lattice with 1024-bit state, 8-round permutation, SpongeWrap authenticated encryption; local map is Arnold's Cat Map (parameter-free, provably hyperbolic, natively integer); 5-term coupling with fully invertible circulant (det odd, trivial kernel, full 512-bit capacity)
- **Native Authentication** — AEAD tag produced by the sponge capacity; no separate MAC primitive required
- **Domain Separation** — Absorb phases (key, IV, AAD, ciphertext, tag) use distinct domain constants for strict phase isolation
- **Argon2id Key Derivation** — Memory-hard password hashing (256 MB / 4 iterations); parameters are authenticated in the AEAD header
- **Single Subkey** — BLAKE3 `derive_key` produces one 256-bit cipher key; the sponge handles both encryption and authentication
- **Streaming Encryption** — Data is processed in 64 KB chunks with no full-file keystream allocation
- **Memory-Locked Keys** — Heap-allocated key buffers, VirtualLock prevents swapping to disk; zeroized on drop
- **Privacy Options** — Optional metadata stripping and compression bypass to minimize information leakage
- **Argon2 Parameter Floor** — Decryption rejects artificially weak KDF parameters (prevents timing oracle attacks)
- **File Extension Preservation** — Original file extension is restored on decryption
- **Auto-Detection** — Automatically switches between Encrypt/Decrypt mode based on selected file
- **Cross-Platform GUI** — Native desktop application built with egui/eframe
- **Batch Archive Mode** — Bundle multiple files into a single encrypted `.catwalk` archive
- **Drag-and-Drop** — Drop files directly onto the GUI window
- **Password Policy Enforcement** — Minimum 18 characters, consecutive repeat detection, real-time strength feedback

## Paper

The design, analysis, and open problems are described in:

> **CATWALK: A Stream Cipher Based on Arnold's Cat Map in a Coupled Lattice Sponge Construction**
>
> `paper/catwalk.tex` — IACR ePrint submission (LaTeX source + bibliography)

The paper includes the complete construction specification, coupling matrix eigenvalue analysis, security argument with honest claim labeling, and statistical validation results.

## Installation

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.70+)
- **Linux only:** `libgtk-3-dev` (for native file dialogs)

### Build

```bash
git clone https://github.com/andrew-unger/chaotic_encryption.git
cd chaotic_encryption
cargo build --release
```

The binary will be at `target/release/catwalk` (or `catwalk.exe` on Windows).

To build without the GUI (CLI only):

```bash
cargo build --release --no-default-features
```

## Usage

### GUI Mode

Launch the application without arguments (or double-click the executable):

```bash
catwalk
```

The GUI provides:
- **Encrypt / Decrypt / File Info** mode selection
- File browser dialogs and drag-and-drop support
- Password entry with show/hide toggle and strength indicator
- Password confirmation for encryption
- Batch archive mode: bundle multiple files into a single encrypted `.catwalk` archive
- Automatic extraction when decrypting a batch archive
- Progress bar and elapsed time display
- Dark theme with CATWALK gold accent branding

### CLI Mode

#### Encrypt

```bash
catwalk encrypt <input_file> <output_file> [--no-metadata] [--no-compress]
```

You will be prompted for a password.

| Flag | Effect |
|------|--------|
| `--no-metadata` | Strips timestamp and file extension from the header |
| `--no-compress` | Skips compression (prevents compression oracle attacks) |

#### Decrypt

```bash
catwalk decrypt <input_file> <output_file> [--force]
```

The `--force` flag allows overwriting existing output files. The original file extension is automatically restored.

#### File Info

```bash
catwalk info <input_file>
```

Displays metadata about an encrypted `.catwalk` file without decrypting it (version, timestamp, Argon2 parameters, original extension).

## Examples

```bash
# Encrypt a document
catwalk encrypt report.pdf report.catwalk

# Encrypt with privacy options (no timestamp, no compression)
catwalk encrypt report.pdf report.catwalk --no-metadata --no-compress

# Decrypt it (original .pdf extension is restored automatically)
catwalk decrypt report.catwalk report

# View encrypted file metadata
catwalk info report.catwalk

# Launch the GUI
catwalk
```

## Technical Details

### Encryption Pipeline (v10)

```
password + random salt + timestamp
        |
        v
    Argon2id (256 MB, 4 iterations)
        |
        v
    master_key (32 bytes)
        |
        v (BLAKE3 derive_key "catwalk.v9.cipher")
    cipher_key (32 bytes)
        |
        v
    CML-Sponge AEAD init (cipher_key + nonce)
        |
        |--- absorb header (AAD) --------+
        |                                |
        v                                |
    stream encrypt plaintext             | authenticated
    (64 KB chunks, XOR + absorb CT)      | but not encrypted
        |                                |
        v                                |
    finalize → 32-byte AEAD tag ---------+
        |
        v
    header ‖ ciphertext ‖ tag
```

1. **Compress** plaintext with zlib (unless `--no-compress`)
2. **Derive** master key from password via Argon2id (parameters stored in header)
3. **Derive** single cipher key via BLAKE3 `derive_key` with version-locked context string
4. **Lock** key material in heap-allocated buffer via VirtualLock (prevents paging to disk)
5. **Build** header bytes (magic, version, flags, salt, timestamp, nonce, Argon2 params, extension)
6. **Init** CML-Sponge state from cipher key and nonce
7. **Absorb** header as authenticated associated data (DOMAIN_AAD)
8. **Encrypt** data in 64 KB streaming chunks: XOR keystream, then absorb ciphertext (DOMAIN_CT)
9. **Finalize** tag: absorb domain separator (DOMAIN_TAG), squeeze 32 bytes from capacity
10. **Zeroize** and unlock all key material on drop

### CML-Sponge Cipher

The `CmlSpongeState` is a 16-site Coupled Map Lattice (CML) operating as a cryptographic sponge.

**State:** 16 × u64 = 1024-bit total
- **Rate:** 512 bits (8 words) — absorb/squeeze interface
- **Capacity:** 512 bits (8 words) — never exposed externally

**Round function** (8 rounds per permutation):

| Stage | Operation | Purpose |
|-------|-----------|---------|
| 1. Counter injection | Weyl sequence (φ × 2⁶⁴) added to all 16 sites with prime rotations | State diversification; ensures no site pair is (0,0) before map |
| 2. Local map | Arnold's Cat Map on adjacent pairs (0,1),(2,3),…,(14,15) — `(x,y)→(x+y, x+2y)` | Provably hyperbolic nonlinear mixing; natively integer, no approximation |
| 3. CML coupling | Each site additively coupled with neighbors at distances {1, 3, 7, 11} — 5-term polynomial p(x)=1+x+x³+x⁷+x¹¹; det(C)=−33075 (odd, fully invertible) | Full 16-site diffusion in exactly 2 rounds |
| 4. Multiplicative mixing | `s[2k+1] *= (s[2k] | 1)` for k=0..7 | Second nonlinear layer on same adjacent pairs |

**Output finalizer:** Each squeezed word passes through Stafford Mix13 (the bijective finalizer used by SplitMix64 / PCG) for additional output whitening. Stafford Mix13 is fully invertible — no entropy is lost.

**Sponge construction (SpongeWrap AEAD):**
- Multi-rate padding with domain constants (KEY=0x01, IV=0x02, AAD=0x03, CT=0x04, TAG=0x05)
- State evolution is identical for encryption and decryption (both absorb ciphertext bytes), enabling tag verification from the sponge capacity without a separate MAC
- Encryption: `squeeze keystream → XOR plaintext → ciphertext; absorb(ciphertext)`
- Decryption: `squeeze keystream → save ciphertext; XOR ciphertext → plaintext; absorb(saved ciphertext)`

All arithmetic uses `u64`/`u128` wrapping operations, guaranteeing identical results on every platform.

### File Format (v9)

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `CATW` |
| Version | 1 byte | `9` |
| Flags | 1 byte | Bit 0: STRIP_METADATA, Bit 1: NO_COMPRESS |
| Salt | 16 bytes | Random, used as Argon2id salt prefix |
| Timestamp | 8 bytes | Unix epoch seconds (LE), or zero if metadata stripped |
| Nonce | 16 bytes | Random, mixed into sponge initial state |
| Argon2 m_cost | 1 byte | log₂ of memory in KiB (default: 18 = 256 MB) |
| Argon2 t_cost | 1 byte | Iteration count (default: 4) |
| Argon2 p_cost | 1 byte | Parallelism lanes (default: 1) |
| Extension length | 1 byte | Length of original file extension (0 if metadata stripped) |
| Extension | variable | Original file extension |
| Ciphertext | variable | Encrypted data |
| AEAD Tag | 32 bytes | CML-Sponge authentication tag (covers all header fields + ciphertext) |

All fields from Magic through Extension are authenticated as associated data (absorbed but not encrypted).

### Version Note

v9 and v10 share the same file format (version byte = 9); v10 refers to the cipher internals (5-term coupling), not the file format version.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `argon2` | Argon2id key derivation |
| `blake3` | Subkey derivation via `derive_key` |
| `flate2` | Zlib compression |
| `rand` | Random salt/nonce generation |
| `subtle` | Constant-time tag comparison |
| `zeroize` | Secure memory wiping for keys and state |
| `eframe` / `egui` | Cross-platform GUI (optional) |
| `rfd` | Native file dialogs (optional) |
| `zip` | Archive creation for batch mode (optional) |

## Password Policy

Passwords are validated on both the GUI and CLI before encryption is allowed:

- **Minimum 18 characters** — shorter passwords are rejected
- **Max 3 consecutive identical characters** — e.g. `aaa` is allowed, `aaaa` is not
- No requirements for uppercase, lowercase, numbers, or special characters

The strength meter provides real-time feedback:

| Length | Rating |
|--------|--------|
| < 18 | Weak (blocked) |
| 18 – 23 | Fair |
| 24 – 31 | Strong |
| 32+ | Very Strong |

## Statistical Validation

The CML-Sponge keystream (8 rounds, seed 0) has been validated with:

- **PractRand** — 1 TB × 2 seeds (v10), 256 GB × 5 seeds (original coupling); 397 tests, zero persistent anomalies
- **Reduced-round analysis** — 1-round, 4-round, and 8-round variants each pass PractRand to 1 GB, 16 GB, and 32 GB+ respectively before the first anomaly (none found yet)
- **Multi-seed CI tests** — 50 seeds × 1 MB each: chi-squared byte frequency (Bonferroni-corrected), monobit, and serial correlation
- **Single-seed suite** — 10 statistical tests including avalanche (single-bit key and IV sensitivity), gap, runs, compression ratio, and byte-pair frequency
- **Complement symmetry test** — All-zero and all-0xFF keys produce distinct, independent keystreams

## Security Considerations

- The CML-Sponge cipher is experimental and has not undergone formal cryptographic review
- Key derivation uses Argon2id (256 MB, 4 iterations) — each brute-force guess costs ~1 second and 256 MB of RAM
- Argon2 parameter floor: decryption rejects `m_log2 < 16` or `t_cost < 2` to prevent KDF downgrade timing attacks
- Argon2 parameter ceiling: decryption rejects `m_log2 > 22` (4 GiB), `t_cost > 16`, or `p_cost > 16` so a crafted header cannot trigger a multi-terabyte allocation or runaway CPU as a denial-of-service
- Authentication tag is produced natively by the sponge capacity — bound to cipher key, nonce, all header fields, and every ciphertext byte
- Constant-time tag comparison prevents timing side-channels during verification
- Key material is heap-allocated for reliable VirtualLock page-alignment (Windows), preventing swap to disk
- All key material and sponge state are zeroized on drop
- Compression oracle protection: `--no-compress` skips zlib (or set `skip_compression: true` in code); this is the safe default
- Optional `--no-metadata` strips timestamp and file extension from the header
- Decompression is capped at 4 GB to prevent zip-bomb attacks
- Archive extraction strips path components to prevent directory traversal attacks

## License

This project is for personal use only and is not licensed for redistribution.
