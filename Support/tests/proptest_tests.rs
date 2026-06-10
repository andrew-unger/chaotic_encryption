//! Property-based tests for CATWALK crypto invariants.
//!
//! Uses proptest to verify that cryptographic contracts hold across arbitrary
//! inputs — not just the hand-crafted cases in the unit tests.
//!
//! Properties tested:
//!   1. Roundtrip  — any plaintext survives encrypt → decrypt unchanged.
//!   2. Ciphertext tamper — flipping any byte in the ciphertext body causes
//!      decryption to fail with IntegrityCheckFailed.
//!   3. Tag tamper — flipping any byte in the 32-byte authentication tag
//!      causes decryption to fail.
//!   4. Wrong password — decrypting with a different password always fails.
//!   5. Chunking invariance — duplex AEAD output is independent of how the
//!      caller splits the data into chunks.
//!   6. Keystream uniqueness — distinct IVs produce distinct keystreams.
//!
//! Note on case counts: properties 1–4 invoke the full Argon2id KDF (~1.5 s
//! per case at production parameters).  Case counts are intentionally small
//! (20 cases each) so the suite completes in ~2 minutes.  Property 5 uses
//! only the fast sponge primitive and runs 256 cases.

use catwalk::cml_sponge::{cipher_init, keystream, AeadSession};
use catwalk::crypto::{decrypt, encrypt, EncryptOptions};
use catwalk::error::CryptoError;
use proptest::prelude::*;

/// A valid password that satisfies the 18-char / max-3-consecutive policy.
const PW: &str = "correct-horse-battery-staple-1!";

/// Encryption options: no compression, no metadata strip.
fn opts() -> EncryptOptions {
    EncryptOptions {
        strip_metadata: false,
        skip_compression: true,
    }
}

// ── Property 1: Roundtrip ─────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Any plaintext (0–4096 bytes) encrypted then decrypted returns the
    /// original bytes unchanged.
    #[test]
    fn prop_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let ct = encrypt(&plaintext, PW, "test.bin", &opts(), None, None)
            .expect("encrypt failed");
        let (pt, _ext) = decrypt(&ct, PW, None, None)
            .expect("decrypt failed");
        prop_assert_eq!(pt, plaintext);
    }
}

// ── Property 2: Ciphertext tamper ────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Flipping any single byte in the ciphertext body (after the header,
    /// before the tag) causes IntegrityCheckFailed.
    #[test]
    fn prop_ciphertext_tamper_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..=1024),
        flip_seed in any::<usize>(),
    ) {
        let mut ct = encrypt(&plaintext, PW, "test.bin", &opts(), None, None)
            .expect("encrypt failed");

        // Tag = last 32 bytes. Header is at least 50 bytes.
        let tag_start = ct.len() - 32;
        let header_end = 50usize;
        if tag_start <= header_end {
            // Ciphertext body is empty — skip this case.
            return Ok(());
        }
        let body_len = tag_start - header_end;
        let flip_pos = header_end + (flip_seed % body_len);
        ct[flip_pos] ^= 0xFF;

        let result = decrypt(&ct, PW, None, None);
        prop_assert!(
            matches!(result, Err(CryptoError::IntegrityCheckFailed)),
            "expected IntegrityCheckFailed, got {:?}", result
        );
    }
}

// ── Property 3: Tag tamper ────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Flipping any single byte in the 32-byte AEAD tag causes
    /// IntegrityCheckFailed.
    #[test]
    fn prop_tag_tamper_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 0..=512),
        tag_byte_idx in 0usize..32,
    ) {
        let mut ct = encrypt(&plaintext, PW, "test.bin", &opts(), None, None)
            .expect("encrypt failed");

        let flip_pos = ct.len() - 32 + tag_byte_idx;
        ct[flip_pos] ^= 0x01;

        let result = decrypt(&ct, PW, None, None);
        prop_assert!(
            matches!(result, Err(CryptoError::IntegrityCheckFailed)),
            "expected IntegrityCheckFailed after tag tamper, got {:?}", result
        );
    }
}

// ── Property 4: Wrong password always fails ───────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Decrypting with a different password always returns an error.
    #[test]
    fn prop_wrong_password_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 0..=512),
    ) {
        const WRONG_PW: &str = "totally-different-password-42!!";
        let ct = encrypt(&plaintext, PW, "test.bin", &opts(), None, None)
            .expect("encrypt failed");
        let result = decrypt(&ct, WRONG_PW, None, None);
        prop_assert!(result.is_err(), "wrong password should fail, but got Ok");
    }
}

// ── Property 5: Duplex chunking invariance ───────────────────────────────────

proptest! {
    // Uses only the fast sponge primitive (no KDF) — default case count is fine.

    /// Encrypting the same plaintext as one chunk and as arbitrarily-split
    /// chunks must yield identical ciphertext and tag: the duplex session
    /// buffers partial blocks, so caller chunking is never observable.
    #[test]
    fn prop_chunking_never_affects_ciphertext_or_tag(
        plaintext in proptest::collection::vec(any::<u8>(), 0..=1024),
        splits in proptest::collection::vec(any::<usize>(), 0..=8),
    ) {
        let key = [0xC4u8; 32];
        let iv = [0x7Eu8; 16];
        let aad = b"chunking-invariance-property";

        // Reference: single-chunk encryption.
        let (ct_ref, tag_ref) = {
            let mut s = AeadSession::new(&key, &iv);
            s.absorb_aad(aad);
            let mut ct = plaintext.clone();
            s.encrypt_chunk(&mut ct);
            (ct, s.finalize())
        };

        // Split points derived from the fuzzer-chosen values, sorted and
        // clamped into range.
        let mut points: Vec<usize> = splits
            .iter()
            .map(|&x| if plaintext.is_empty() { 0 } else { x % (plaintext.len() + 1) })
            .collect();
        points.sort_unstable();

        let (ct_split, tag_split) = {
            let mut s = AeadSession::new(&key, &iv);
            s.absorb_aad(aad);
            let mut ct = plaintext.clone();
            let mut start = 0;
            for &p in &points {
                s.encrypt_chunk(&mut ct[start..p.max(start)]);
                start = p.max(start);
            }
            s.encrypt_chunk(&mut ct[start..]);
            (ct, s.finalize())
        };

        prop_assert_eq!(&ct_ref, &ct_split, "ciphertext depends on chunking");
        prop_assert_eq!(tag_ref, tag_split, "tag depends on chunking");

        // Decryption with yet another chunking recovers the plaintext and tag.
        let (pt_rec, tag_dec) = {
            let mut s = AeadSession::new(&key, &iv);
            s.absorb_aad(aad);
            let mut pt = ct_ref.clone();
            let mid = pt.len() / 3;
            let (a, b) = pt.split_at_mut(mid);
            s.decrypt_chunk(a);
            s.decrypt_chunk(b);
            (pt, s.finalize())
        };
        prop_assert_eq!(pt_rec, plaintext, "decrypt failed to recover plaintext");
        prop_assert_eq!(tag_dec, tag_ref, "decrypt tag mismatch");
    }
}

// ── Property 6: Keystream uniqueness ─────────────────────────────────────────

proptest! {
    // 256 cases — cipher_init is fast (no KDF), so default case count is fine.

    /// Two calls with the same key but distinct IVs must produce different
    /// 64-byte keystreams.  iv2 is derived by flipping bit 0 of iv1's first
    /// byte, guaranteeing iv1 ≠ iv2.
    #[test]
    fn prop_distinct_ivs_produce_distinct_keystreams(iv1 in any::<[u8; 16]>()) {
        let key = [0x5Au8; 32];
        let mut iv2 = iv1;
        iv2[0] ^= 0x01;

        let mut ks1 = [0u8; 64];
        let mut ks2 = [0u8; 64];
        keystream(&mut cipher_init(&key, &iv1), &mut ks1);
        keystream(&mut cipher_init(&key, &iv2), &mut ks2);

        prop_assert_ne!(ks1, ks2, "different IVs produced identical keystreams");
    }
}
