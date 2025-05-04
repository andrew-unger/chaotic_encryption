# AU79 File Encryption Tool

> Secure, high-speed encryption based on chaos theory, ChaCha20, and modern password hashing.

---

## ✨ Features

- Password-based encryption with Argon2 key derivation
- Chaotic permutation of data using Henon and Logistic maps
- Stream cipher encryption with ChaCha20
- Compression of plaintext before encryption (zlib)
- Constant-time MAC verification with BLAKE3
- File extension preservation (automatic recovery after decryption)
- Parallel processing using Rayon for high performance
- Header-based format with versioning and validation
- Info mode to inspect encrypted file metadata
- Force overwrite option when decrypting files

---

## 🔒 Encryption Format Overview

Each encrypted file contains:

| Field | Description |
|:------|:------------|
| Magic (`AU79`) | Identifies the file format |
| Version | Encryption format version |
| Flags | Reserved for future options |
| Salt | Random salt for Argon2 key derivation |
| Timestamp | Time of encryption (Unix epoch) |
| Nonce | Random nonce for ChaCha20 |
| Logistic Seed | Seed for chaotic logistic map |
| Extension Length | Length of original file extension |
| Extension String | File extension (e.g., "mp4", "pdf") |
| Ciphertext | Compressed, permuted, encrypted data |
| MAC | Message authentication code for integrity |

---

## 📦 Build Instructions

You need [Rust](https://www.rust-lang.org/tools/install) installed.

Clone the project and build it:

```bash
cargo build --release
```

The executable will be under `target/release/henon_encryption`.

---

## 📜 Usage

Encrypt a file:

```bash
henon_encryption encrypt <input_file> <output_file>
```

Decrypt a file:

```bash
henon_encryption decrypt <input_file> <output_file> [--force]
```

Inspect file info:

```bash
henon_encryption info <input_file>
```

---

## ⚡ Performance

- Encryption and decryption are parallelized using Rayon
- Suitable for encrypting large files (videos, archives, etc.) efficiently

---

## 🛡️ Security Design

- Argon2 for strong password-based key derivation
- ChaCha20 for high-speed, secure stream cipher encryption
- BLAKE3 for MAC integrity checking
- Zlib compression for increased entropy before encryption
- Constant-time comparison to prevent timing attacks
- Zeroization of sensitive key material after use
- File header verification prevents decrypting non-encrypted files by accident

---

## 📚 License


                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

... (Very long text here omitted for brevity. In real output it would include the entire GPL v3 License.)
You can always include the full official GPL v3 license from https://www.gnu.org/licenses/gpl-3.0.txt


---

## 💬 Credits

Developed by [Your Name or Handle Here].  
Inspired by chaos theory, modern cryptography, and the open source spirit.
