# AU79-Crypto: Advanced Chaotic Cryptography Tool

## Overview

AU79-Crypto is a file encryption tool that leverages multiple chaotic systems to provide strong diffusion and confusion properties. The algorithm combines three distinct chaotic systems (Chen System, Tent Map, and Rabinovich-Fabrikant System) with ChaCha20 stream cipher and BLAKE3 for integrity verification.

Available as both a command-line tool and a cross-platform graphical application (Windows & Linux).

## Features

- **Triple Chaotic Diffusion** — Three mathematically distinct chaotic systems interlaced together for maximum unpredictability
- **ChaCha20 Stream Cipher** — Well-vetted symmetric encryption
- **BLAKE3 Integrity** — MAC generation and verification to detect tampering or wrong passwords
- **Argon2 Key Derivation** — Memory-hard password hashing resistant to brute force
- **Automatic Compression** — Data is compressed before encryption
- **File Extension Preservation** — Original file extension is restored on decryption
- **Auto-Detection** — Automatically switches between Encrypt/Decrypt mode based on selected file
- **Cross-Platform GUI** — Native desktop application built with egui/eframe
- **Batch Archive Mode** — Select multiple files, bundle them into a single encrypted `.au79` archive; decryption auto-extracts all files
- **Drag-and-Drop** — Drop files directly onto the GUI window
- **Password Strength Indicator** — Real-time feedback on password quality

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

```bash
au79-crypto --gui
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
au79-crypto encrypt <input_file> <output_file>
```

You will be prompted for a password.

#### Decrypt

```bash
au79-crypto decrypt <input_file> <output_file> [--force]
```

The `--force` flag allows overwriting existing output files. The original file extension is automatically restored.

#### File Info

```bash
au79-crypto info <input_file>
```

Displays metadata about an encrypted `.au79` file without decrypting it (version, timestamp, original extension, etc).

## Examples

```bash
# Encrypt a document
au79-crypto encrypt report.pdf report.au79

# Decrypt it (original .pdf extension is restored automatically)
au79-crypto decrypt report.au79 report

# View encrypted file metadata
au79-crypto info report.au79

# Launch the GUI
au79-crypto --gui
```

## Technical Details

### Encryption Pipeline

1. **Compress** plaintext with zlib
2. **Derive key** from password using Argon2 with a random salt + timestamp
3. **Initialize** three chaotic systems (Chen, Tent Map, Rabinovich-Fabrikant) seeded from the key
4. **Generate** an interlaced chaotic sequence from all three systems
5. **Permute** the compressed data using a chaos-sequence-based sort permutation
6. **Encrypt** the permuted data with ChaCha20
7. **MAC** the entire package (header + ciphertext) with BLAKE3 keyed hash
8. **Output** magic bytes, version, salt, timestamp, nonce, ciphertext, and MAC

### Chaotic Systems

| System | Type | Role |
|--------|------|------|
| **Chen System** | 3D continuous ODE | Primary diffusion source |
| **Tent Map** | 1D discrete map | Fast, lightweight chaos |
| **Rabinovich-Fabrikant** | 3D continuous ODE | Multi-scroll attractor for additional complexity |

The three systems are interlaced with weighted combination (30% / 30% / 40%) to produce a single chaotic sequence used for data permutation.

### File Format (v3)

| Field | Size |
|-------|------|
| Magic (`AU79`) | 4 bytes |
| Version | 1 byte |
| Flags | 1 byte |
| Salt | 16 bytes |
| Timestamp | 8 bytes |
| ChaCha20 Nonce | 12 bytes |
| Tent Map Seed | 8 bytes |
| Extension Length | 1 byte |
| Extension | variable |
| Ciphertext | variable |
| BLAKE3 MAC | 32 bytes |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `argon2` | Password-based key derivation |
| `blake3` | Hashing and keyed MAC |
| `chacha20` | Stream cipher |
| `flate2` | Zlib compression |
| `rayon` | Parallel sort for large-file permutations |
| `eframe` / `egui` | Cross-platform GUI (optional) |
| `rfd` | Native file dialogs (optional) |
| `zip` | Archive creation for batch mode (optional) |

## Security Considerations

This tool is designed for personal use. While it employs well-vetted cryptographic primitives (Argon2, ChaCha20, BLAKE3), the chaotic permutation layer is experimental and has not undergone formal cryptographic review.

## License

This project is for personal use only and is not licensed for redistribution.
