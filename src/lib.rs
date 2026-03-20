//! # catwalk — CATWALK file encryption library
//!
//! CATWALK is a research-grade authenticated encryption scheme built on the
//! CML-Sponge primitive (Coupled Map Lattice with sponge construction).
//!
//! ## Construction overview
//!
//! - **Primitive:** 16×u64 (1024-bit) CML lattice; 512-bit rate / 512-bit capacity split.
//! - **Key schedule:** Argon2id (256 MB / 4 iterations) → BLAKE3 domain derivation →
//!   32-byte cipher key.
//! - **AEAD mode:** SpongeWrap-style — absorb AAD (domain 0x03), encrypt+absorb
//!   ciphertext (domain 0x04), finalise tag (domain 0x05).
//! - **Security target:** 128-bit confidentiality and integrity under standard sponge
//!   assumptions; 256-bit pre-image resistance for the permutation state.
//!
//! ## Appropriate use
//!
//! This is a **research implementation** of a novel cryptographic construction.
//! It has **not** been externally audited.  Do not use it to protect data whose
//! compromise would be catastrophic.  For production use, prefer an audited
//! primitive (AES-GCM-SIV, ChaCha20-Poly1305, or XChaCha20-Poly1305).
//!
//! ## Quick start (high-level API)
//!
//! ```no_run
//! use catwalk::crypto::{encrypt, decrypt, EncryptOptions};
//!
//! let plaintext = std::fs::read("input.txt").unwrap();
//!
//! // Encrypt
//! let bundle = encrypt(
//!     &plaintext,
//!     "correct-horse-battery-staple-pw",
//!     "input.txt",
//!     &EncryptOptions { strip_metadata: false, skip_compression: true },
//!     None,  // progress callback
//! ).unwrap();
//! std::fs::write("output.catwalk", &bundle).unwrap();
//!
//! // Decrypt
//! let (recovered, extension) = decrypt(
//!     &bundle,
//!     "correct-horse-battery-staple-pw",
//!     None,  // progress callback
//! ).unwrap();
//! println!("recovered {} bytes, extension: {:?}", recovered.len(), extension);
//! ```
//!
//! ## Low-level AEAD API
//!
//! The [`cml_sponge`] module exposes the raw sponge primitives for testing and
//! research.  Callers are responsible for nonce management and tag verification.
//! See [`cml_sponge::aead_finalize`] for the no-output-before-verification contract.

pub mod crypto;
pub mod error;
pub mod utils;
pub mod cml_sponge;
