# AU79-Crypto: Chaotic Encryption Tool

## Overview

AU79-Crypto is a file encryption tool that uses chaotic dynamical systems as its primary cipher. Integer-arithmetic implementations of the logistic map and tent map generate a keystream for both data permutation and XOR encryption, with BLAKE3 for integrity verification and Argon2id for key derivation.

Available as both a command-line tool and a cross-platform graphical application.

## Features

- **Chaotic Keystream Cipher** — Logistic and tent maps in integer arithmetic generate the encryption keystream directly
- **Double-Round Diffusion** — Two chaotic rounds per output word for stronger mixing
- **Chaotic Permutation** — Fisher-Yates shuffle driven by the chaotic keystream reorders data before encryption
- **BLAKE3 Integrity** — Keyed MAC covering all header fields and ciphertext
- **Argon2id Key Derivation** — Memory-hard password hashing with explicit, tunable parameters (256 MB / 4 iterations)
- **Separate Subkeys** — BLAKE3 `derive_key` produces independent keys for cipher and MAC
- **Memory-Locked Keys** — VirtualLock prevents key material from being swapped to disk; zeroized on drop
- **Privacy Options** — Optional metadata stripping and compression bypass to minimize information leakage
- **Automatic Compression** — Zlib compression before encryption (can be disabled)
- **File Extension Preservation** — Original file extension is restored on decryption
- **Auto-Detection** — Automatically switches between Encrypt/Decrypt mode based on selected file
- **Cross-Platform GUI** — Native desktop application built with egui/eframe
- **Batch Archive Mode** — Bundle multiple files into a single encrypted `.au79` archive
- **Drag-and-Drop** — Drop files directly onto the GUI window
- **Password Policy Enforcement** — Minimum 18 characters, consecutive repeat detection, real-time strength feedback

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

The binary will be at `target/release/au79-crypto` (or `au79-crypto.exe` on Windows).

To build without the GUI (CLI only):

```bash
cargo build --release --no-default-features
```

## Usage

### GUI Mode

Launch the application without arguments (or double-click the executable):

```bash
au79-crypto
```

The GUI provides:
- **Encrypt / Decrypt / File Info** mode selection
- File browser dialogs and drag-and-drop support
- Password entry with show/hide toggle and strength indicator
- Password confirmation for encryption
- Batch archive mode: bundle multiple files into a single encrypted `.au79` archive
- Automatic extraction when decrypting a batch archive
- Progress bar and elapsed time display
- Dark theme with AU79 gold accent branding

### CLI Mode

#### Encrypt

```bash
au79-crypto encrypt <input_file> <output_file> [--no-metadata] [--no-compress]
```

You will be prompted for a password.

| Flag | Effect |
|------|--------|
| `--no-metadata` | Strips timestamp and file extension from the header |
| `--no-compress` | Skips compression (prevents pattern-based fingerprinting) |

#### Decrypt

```bash
au79-crypto decrypt <input_file> <output_file> [--force]
```

The `--force` flag allows overwriting existing output files. The original file extension is automatically restored.

#### File Info

```bash
au79-crypto info <input_file>
```

Displays metadata about an encrypted `.au79` file without decrypting it (version, timestamp, Argon2 parameters, original extension).

## Examples

```bash
# Encrypt a document
au79-crypto encrypt report.pdf report.au79

# Encrypt with privacy options (no timestamp, no compression)
au79-crypto encrypt report.pdf report.au79 --no-metadata --no-compress

# Decrypt it (original .pdf extension is restored automatically)
au79-crypto decrypt report.au79 report

# View encrypted file metadata
au79-crypto info report.au79

# Launch the GUI
au79-crypto
```

## Technical Details

### Encryption Pipeline

```
password + random salt + timestamp
        |
        v
    Argon2id (256 MB, 4 iterations)
        |
        v
    master_key (32 bytes)
       / \
      /   \
     v     v
chaos_key  mac_key          (BLAKE3 derive_key with distinct context strings)
     |         |
     v         |
ChaoticKeystream             (256-bit state: logistic + tent maps, double-round)
     |         |
     v         |
 permutation   |             (Fisher-Yates shuffle driven by keystream)
     |         |
     v         |
 XOR encrypt   |             (chaotic keystream applied to permuted data)
     |         |
     v         v
 ciphertext → BLAKE3 MAC     (keyed hash over full header + ciphertext)
```

1. **Compress** plaintext with zlib (unless `--no-compress`)
2. **Derive** master key from password via Argon2id (parameters stored in header)
3. **Split** master key into `chaos_key` and `mac_key` using BLAKE3 `derive_key`
4. **Lock** key material in memory via VirtualLock (prevents paging to disk)
5. **Initialize** the chaotic keystream generator from `chaos_key` + random nonce
6. **Permute** data via Fisher-Yates shuffle driven by the keystream
7. **Encrypt** permuted data by XOR with the continuing chaotic keystream
8. **MAC** all header fields and ciphertext with BLAKE3 keyed hash using `mac_key`
9. **Zeroize** and unlock all key material on drop

### Chaotic Keystream Generator

The `ChaoticKeystream` struct maintains a 256-bit state (4 x u64). Two rounds are executed per output word for stronger diffusion. Each round applies four stages:

| Stage | Operation | Purpose |
|-------|-----------|---------|
| 1. Substitution | Logistic map on words 0,2; tent map on words 1,3 | Nonlinear confusion via chaotic dynamics |
| 2. Counter injection | Golden-ratio counter added to words 0,2 | Prevents degenerate cycles and fixed points |
| 3. ARX diffusion | Wrapping add/XOR with rotated neighbors | Linear cross-coupling between state words |
| 4. Multiplicative mixing | `state[i] *= (state[j] \| 1)` | Quadratic nonlinearity resisting algebraic attacks |

**Output function:** `(s0 * (s1|1)) ^ (s2 * (s3|1))` — a non-linear, quadratic combination that prevents attackers from learning linear equations over the internal state.

All arithmetic uses `u64`/`u128` wrapping operations, guaranteeing identical results on every platform.

### File Format (v5)

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `AU79` |
| Version | 1 byte | `5` |
| Flags | 1 byte | Bit 0: STRIP_METADATA, Bit 1: NO_COMPRESS |
| Salt | 16 bytes | Random, used in Argon2id |
| Timestamp | 8 bytes | Unix epoch seconds (LE), or zero if metadata stripped |
| Nonce | 16 bytes | Random, mixed into chaotic state |
| Argon2 m_cost | 1 byte | log2 of memory in KiB (default: 18 = 256 MB) |
| Argon2 t_cost | 1 byte | Iteration count (default: 4) |
| Argon2 p_cost | 1 byte | Parallelism lanes (default: 1) |
| Extension length | 1 byte | Length of original file extension (0 if metadata stripped) |
| Extension | variable | Original file extension |
| Ciphertext | variable | Encrypted data |
| MAC | 32 bytes | BLAKE3 keyed hash |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `argon2` | Argon2id key derivation |
| `blake3` | Subkey derivation and keyed MAC |
| `flate2` | Zlib compression |
| `rand` | Random salt/nonce generation |
| `subtle` | Constant-time MAC comparison |
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

The chaotic keystream has been validated with:

- **PractRand** — 256 GB, 369 tests, zero anomalies
- **Multi-seed CI tests** — 50 seeds x 1 MB each: chi-squared byte frequency, monobit, and serial correlation
- **Single-seed suite** — 10 statistical tests including avalanche, gap, runs, compression ratio, and byte-pair frequency

A multi-seed PractRand batch script (`tools/practrand_multi_seed.bat`) is included for extended validation across 10 seeds at 16 GB each.

## Security Considerations

- The chaotic keystream cipher is experimental and has not undergone formal cryptographic review
- Key derivation uses Argon2id (256 MB, 4 iterations) — each brute-force guess costs ~1 second and 256 MB of RAM
- Double-round diffusion: two chaotic rounds per output word to strengthen mixing
- Separate subkeys prevent related-key interactions between cipher and MAC
- Key material is page-locked via VirtualLock (Windows) to prevent swapping to disk
- All key material, chaotic state, and GUI password fields are zeroized after use
- MAC is verified before any decryption (encrypt-then-MAC)
- Constant-time MAC comparison prevents timing side-channels
- Branchless tent map implementation prevents timing side-channel leakage of internal state
- Fisher-Yates permutation uses Lemire's rejection sampling for unbiased random selection
- Optional `--no-compress` flag prevents compression oracle attacks
- Optional `--no-metadata` flag strips timestamp and file extension from the header
- Decompression is capped at 4 GB to prevent zip-bomb attacks
- Archive extraction strips path components to prevent directory traversal attacks

## License

This project is for personal use only and is not licensed for redistribution.
