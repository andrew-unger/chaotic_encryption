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
//! - **AEAD mode (format v10):** SpongeWrap duplex — absorb AAD (domain 0x03), then
//!   one permutation per 64-byte block: keystream = Mix13(rate), ciphertext = plaintext
//!   ⊕ keystream, rate ⊕= ciphertext, permute.  Finalisation injects a DOMAIN_CT (0x04)
//!   padded terminal block and a DOMAIN_TAG (0x05) block, then squeezes a 32-byte tag.
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
//! // Encrypt (no keyfile)
//! let bundle = encrypt(
//!     &plaintext,
//!     "correct-horse-battery-staple-pw",
//!     "input.txt",
//!     &EncryptOptions { strip_metadata: false, skip_compression: true },
//!     None,  // keyfile path (None = password-only)
//!     None,  // progress callback
//! ).unwrap();
//! std::fs::write("output.catwalk", &bundle).unwrap();
//!
//! // Decrypt (no keyfile)
//! let (recovered, extension) = decrypt(
//!     &bundle,
//!     "correct-horse-battery-staple-pw",
//!     None,  // keyfile path
//!     None,  // progress callback
//! ).unwrap();
//! println!("recovered {} bytes, extension: {:?}", recovered.len(), extension);
//! ```
//!
//! ## Low-level AEAD API
//!
//! The [`cml_sponge`] module exposes the raw sponge primitives and the
//! [`cml_sponge::AeadSession`] duplex AEAD for testing and research.  Callers
//! are responsible for nonce management and tag verification.  See the
//! [`cml_sponge::AeadSession`] docs for the no-output-before-verification
//! contract.

pub mod cml_sponge;
pub mod crypto;
pub mod error;
pub mod utils;

#[cfg(feature = "archive")]
pub mod archive;
