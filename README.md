# AU79-Crypto: Advanced Chaotic Cryptography Tool

## Overview

AU79-Crypto is a robust file encryption tool that leverages multiple chaotic systems to provide strong diffusion and confusion properties. The algorithm combines three distinct chaotic systems (Chen System, Tent Map, and Rabinovich-Fabrikant System) with ChaCha20 stream cipher and BLAKE3 for integrity verification.

## Features

- **Triple Chaotic Diffusion**: Utilizes three mathematically distinct chaotic systems interlaced together for maximum unpredictability
- **Strong Symmetric Encryption**: Implements ChaCha20 for the stream cipher component
- **Integrity Protection**: Uses BLAKE3 for MAC generation and verification
- **Compression**: Automatically compresses data before encryption
- **File Extension Preservation**: Preserves original file extensions for easy decryption
- **Password-Based**: Simple password-based encryption, no key files to manage

## Security Features

- **Multi-layer Security**: Defense in depth with compression, chaotic permutation, stream cipher, and MAC
- **Chaotic Permutation**: Complete diffusion of data using chaos theory
- **Key Derivation**: Uses Argon2 for secure password-based key derivation
- **Cryptographic Primitives**: Relies on well-vetted cryptographic algorithms like ChaCha20 and BLAKE3

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/au79-crypto.git
cd au79-crypto
```

2. Build the project using Cargo:
```bash
cargo build --release
```

The compiled binary will be available at `target/release/au79-crypto`.

## Usage

### Encryption
```bash
au79-crypto encrypt <input_file> <output_file>
```

### Decryption
```bash
au79-crypto decrypt <input_file> <output_file> [--force]
```
The `--force` flag allows overwriting existing files during decryption.

### File Information
```bash
au79-crypto info <input_file>
```
Displays metadata about an encrypted file without decrypting it.

## Examples

Encrypt a document:
```bash
au79-crypto encrypt secret_document.pdf secret_document.encrypted
```

Decrypt a document:
```bash
au79-crypto decrypt secret_document.encrypted recovered_document
```
The original file extension will be automatically appended.

View file information:
```bash
au79-crypto info secret_document.encrypted
```

## Technical Details

AU79-Crypto employs a unique combination of chaotic systems for data diffusion:

1. **Chen System**: A three-dimensional continuous chaotic system with strong butterfly effect properties
2. **Tent Map**: A simple but effective discrete chaotic map with excellent performance characteristics
3. **Rabinovich-Fabrikant System**: A complex system featuring multi-scroll attractors

The encryption process follows these steps:
1. Compress plaintext data
2. Generate chaotic sequence by interlacing outputs from all three systems
3. Permute the compressed data using the chaotic sequence
4. Encrypt the permuted data with ChaCha20
5. Generate BLAKE3 MAC over the entire package for integrity
6. Combine all components with file metadata

## License

This project is for personal use only and is not licensed for redistribution.

## Security Considerations

This tool is primarily designed for personal use to secure files on your local system. It has not undergone formal cryptographic review or standardization processes required for production cryptographic software.

## Acknowledgments

The cryptographic primitives in this project rely on several Rust crates:
- `argon2` for key derivation
- `blake3` for hashing and MAC
- `chacha20` for stream cipher functionality
- `flate2` for compression
- `rayon` for parallel processing
