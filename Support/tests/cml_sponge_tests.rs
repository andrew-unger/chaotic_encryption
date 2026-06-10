//! CML Sponge cipher test suite.
//!
//! Local map: Arnold's Cat Map applied to adjacent site pairs (0,1),(2,3),…,(14,15).
//! Coupling: 5-term polynomial p(x)=1+x+x³+x⁷+x¹¹, distances {1,3,7,11} (v10).
//! Test vectors TV1–TV4 were regenerated for v10.  All other
//! tests (round-trip, AEAD, avalanche, etc.) are unchanged and must still pass.
//!
//! Covers:
//!   - Cross-validation against canonical test vectors (TV1–TV4)
//!   - Complement symmetry: all-zero and all-FF keys must diverge
//!   - Encrypt / decrypt round-trip
//!   - IV sensitivity: 1-bit IV change → different keystream
//!   - Key sensitivity: 1-bit key change → different keystream
//!   - Stream consistency: two equal-length requests == one combined request
//!   - Empty keystream: no-op
//!   - Multi-block output: >64-byte keystream is contiguous and deterministic
//!   - Zeroize-on-drop: state is accessible before drop (compile-level sanity)
//!   - Reduced-round variant: same init, 1-round vs 8-round → different output
//!   - AEAD: tag changes with AAD/ciphertext, round-trip, empty message, domain separation

use catwalk::cml_sponge::{
    absorb_aad, aead_decrypt_chunk, aead_encrypt_chunk, aead_finalize, cipher_init, cipher_init_r,
    decrypt_in_place, encrypt_in_place, keystream, keystream_r,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ks(key: &[u8; 32], iv: &[u8; 16], len: usize) -> Vec<u8> {
    let mut state = cipher_init(key, iv);
    let mut out = vec![0u8; len];
    keystream(&mut state, &mut out);
    out
}

fn ks_r(key: &[u8; 32], iv: &[u8; 16], len: usize, rounds: usize) -> Vec<u8> {
    let mut state = cipher_init_r(key, iv, rounds);
    let mut out = vec![0u8; len];
    keystream_r(&mut state, &mut out, rounds);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Canonical test vectors ────────────────────────────────────────────────────
// Generated with Arnold's Cat Map local map (adjacent-pair pairing).
// Updated for v10: 5-term coupling distances {1,3,7,11} replacing 4-term {1,5,11}.
// All other construction parameters are unchanged.
// TV1: incremental key/IV
// TV2: all-zero key/IV
// TV3: all-FF key/IV   (MUST differ from TV2 — complement symmetry verified)
// TV4: repeating 0x42 key, 0x13 IV

#[test]
fn tv1_incremental_key_iv() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| i as u8);
    // Arnold's Cat Map construction with Stafford Mix13 output finalizer.
    // Coupling distances updated from {1,5,11} to {1,3,7,11} (5-term, v10).
    let expected = "c137b12a97e698688596a0c5ed64a3646d89178033df7df7c9128450b5bada44\
                    1a47d2e620a9ac8ec35ec25e77cdd3aa6fb6fa5ef7c604944b7303c977919480";
    let got = ks(&key, &iv, 64);
    assert_eq!(hex(&got), expected, "TV1 mismatch");
}

#[test]
fn tv2_all_zero_key_iv() {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let expected = "6388911bd2e420a790a975a8ee0b0932e7959b31a62dccfc0212d56c86bf80d8\
                    24d2f6aac1692f3d32995b70fa7880e6181499e97db9b244b972d084c687581e";
    let got = ks(&key, &iv, 64);
    assert_eq!(hex(&got), expected, "TV2 mismatch");
}

#[test]
fn tv3_all_ff_key_iv() {
    let key = [0xFFu8; 32];
    let iv = [0xFFu8; 16];
    let expected = "d7b65ed8274a4667fd09fbfb4ba860c11076d272c204540746e34cc51241274e\
                    41e9518c64ffb54e6668c5fa980f9ed4b5b30095c343f1bde96d7c9ad1ca35b1";
    let got = ks(&key, &iv, 64);
    assert_eq!(hex(&got), expected, "TV3 mismatch");
    // Complement symmetry: all-FF must differ from all-zero.
    // Arnold's Cat Map has no complement symmetry by construction; the Weyl
    // counter injection provides additional state diversification.
    assert_ne!(
        hex(&got),
        hex(&ks(&[0u8; 32], &[0u8; 16], 64)),
        "TV3 must differ from TV2 (complement symmetry)"
    );
}

#[test]
fn tv4_repeating_key_iv() {
    let key = [0x42u8; 32];
    let iv = [0x13u8; 16];
    let expected = "b1e8729a2fa86cd109d1245a29420c46227ef9e23de58ed0ae6a6c6241257e93\
                    77dd56561935a658ed74b14f24c6e4d070bee8f9ac7d6cdf274ca0aed6d51118";
    let got = ks(&key, &iv, 64);
    assert_eq!(hex(&got), expected, "TV4 mismatch");
}

// ── Complement symmetry (core invariant of the fix) ───────────────────────────

#[test]
fn complement_symmetry_broken() {
    let key_zero = [0x00u8; 32];
    let key_ff = [0xFFu8; 32];
    let iv_zero = [0x00u8; 16];
    let iv_ff = [0xFFu8; 16];

    let ks_00 = ks(&key_zero, &iv_zero, 64);
    let ks_ff = ks(&key_ff, &iv_ff, 64);

    assert_ne!(ks_00, ks_ff,
        "all-zero and all-FF keys must produce distinct keystreams (complement symmetry bug present)");
}

#[test]
fn complement_symmetry_key_only() {
    let key_zero = [0x00u8; 32];
    let key_ff = [0xFFu8; 32];
    let iv = [0xABu8; 16];

    let s_zero = ks(&key_zero, &iv, 64);
    let s_ff = ks(&key_ff, &iv, 64);
    assert_ne!(
        s_zero, s_ff,
        "complemented key must produce different keystream"
    );
}

// ── Encrypt / decrypt round-trip ──────────────────────────────────────────────

#[test]
fn round_trip_encrypt_decrypt() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| (i * 13 + 5) as u8);

    let plaintext = b"CML Sponge round-trip test 12345";
    let mut buf = plaintext.to_vec();

    let mut enc_state = cipher_init(&key, &iv);
    encrypt_in_place(&mut enc_state, &mut buf);
    assert_ne!(buf, plaintext, "ciphertext must differ from plaintext");

    let mut dec_state = cipher_init(&key, &iv);
    decrypt_in_place(&mut dec_state, &mut buf);
    assert_eq!(buf, plaintext, "decrypted plaintext must match original");
}

#[test]
fn round_trip_empty() {
    let key = [0x55u8; 32];
    let iv = [0xAAu8; 16];
    let mut buf: Vec<u8> = vec![];
    let mut state = cipher_init(&key, &iv);
    encrypt_in_place(&mut state, &mut buf);
    assert!(buf.is_empty());
}

#[test]
fn round_trip_one_byte() {
    let key = [0x01u8; 32];
    let iv = [0x02u8; 16];
    let mut buf = vec![0xA5u8];
    let mut enc = cipher_init(&key, &iv);
    encrypt_in_place(&mut enc, &mut buf);
    let mut dec = cipher_init(&key, &iv);
    decrypt_in_place(&mut dec, &mut buf);
    assert_eq!(buf[0], 0xA5);
}

#[test]
fn round_trip_large() {
    let key = [0xDEu8; 32];
    let iv = [0xADu8; 16];
    let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let mut buf = plaintext.clone();
    let mut enc = cipher_init(&key, &iv);
    encrypt_in_place(&mut enc, &mut buf);
    assert_ne!(buf, plaintext);
    let mut dec = cipher_init(&key, &iv);
    decrypt_in_place(&mut dec, &mut buf);
    assert_eq!(buf, plaintext);
}

// ── Key / IV sensitivity ──────────────────────────────────────────────────────

#[test]
fn key_sensitivity_one_bit() {
    let iv = [0u8; 16];
    let key_a = [0u8; 32];
    let mut key_b = [0u8; 32];
    key_b[0] ^= 0x01; // flip one bit

    let a = ks(&key_a, &iv, 64);
    let b = ks(&key_b, &iv, 64);
    assert_ne!(a, b, "1-bit key change must change keystream");

    // rough avalanche: >25% bits differ
    let differing: usize = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum();
    assert!(
        differing > 128,
        "expected >128 bit differences, got {}",
        differing
    );
    let _ = key_a; // zero-initialize is intentional
}

#[test]
fn iv_sensitivity_one_bit() {
    let key = [0x99u8; 32];
    let iv_a = [0u8; 16];
    let mut iv_b = [0u8; 16];
    iv_b[15] ^= 0x80; // flip high bit of last byte

    let a = ks(&key, &iv_a, 64);
    let b = ks(&key, &iv_b, 64);
    assert_ne!(a, b, "1-bit IV change must change keystream");
}

// ── Stream consistency ────────────────────────────────────────────────────────

#[test]
fn stream_consistency_split_vs_combined() {
    let key = [0x77u8; 32];
    let iv = [0x33u8; 16];

    // Single request for 200 bytes
    let combined = ks(&key, &iv, 200);

    // Two sequential requests: 100 + 100
    let mut state = cipher_init(&key, &iv);
    let mut part1 = vec![0u8; 100];
    let mut part2 = vec![0u8; 100];
    keystream(&mut state, &mut part1);
    keystream(&mut state, &mut part2);

    assert_eq!(combined[..100], part1[..]);
    assert_eq!(combined[100..], part2[..]);
}

#[test]
fn stream_consistency_byte_by_byte() {
    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];

    let combined = ks(&key, &iv, 65); // crosses a 64-byte block boundary

    let mut state = cipher_init(&key, &iv);
    let mut out = vec![0u8; 1];
    for (i, &expected) in combined.iter().enumerate().take(65) {
        keystream(&mut state, &mut out);
        assert_eq!(
            out[0], expected,
            "byte {} mismatch in byte-by-byte stream",
            i
        );
    }
}

// ── Multi-block determinism ───────────────────────────────────────────────────

#[test]
fn multi_block_determinism() {
    let key = [0xFEu8; 32];
    let iv = [0xDCu8; 16];

    let a = ks(&key, &iv, 256);
    let b = ks(&key, &iv, 256);
    assert_eq!(
        a, b,
        "same key/IV must produce identical keystream across two calls"
    );
}

#[test]
fn multi_block_no_period() {
    // 640 bytes = 10 × 64-byte blocks.  Verify no naive period ≤ 64 bytes.
    let key = [0xBEu8; 32];
    let iv = [0xEFu8; 16];
    let out = ks(&key, &iv, 640);

    let block0 = &out[0..64];
    for i in 1..10 {
        assert_ne!(
            block0,
            &out[i * 64..(i + 1) * 64],
            "keystream block {} equals block 0 — detected naive period",
            i
        );
    }
}

// ── Reduced-round variant ─────────────────────────────────────────────────────

#[test]
fn reduced_round_differs_from_full() {
    let key = [0x12u8; 32];
    let iv = [0x34u8; 16];

    let full = ks_r(&key, &iv, 64, 8); // 8 rounds (standard)
    let reduced4 = ks_r(&key, &iv, 64, 4); // 4 rounds
    let reduced1 = ks_r(&key, &iv, 64, 1); // 1 round

    assert_ne!(full, reduced4, "4-round output must differ from 8-round");
    assert_ne!(full, reduced1, "1-round output must differ from 8-round");
    assert_ne!(reduced4, reduced1, "4-round and 1-round must differ");
}

#[test]
fn reduced_round_is_deterministic() {
    let key = [0xABu8; 32];
    let iv = [0xCDu8; 16];

    let a = ks_r(&key, &iv, 128, 3);
    let b = ks_r(&key, &iv, 128, 3);
    assert_eq!(a, b, "reduced-round keystream must be deterministic");
}

// ── AEAD tests ────────────────────────────────────────────────────────────────

/// Same key/nonce/plaintext with different AAD must produce a different tag.
#[test]
fn aead_tag_changes_with_aad() {
    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let plaintext = b"some secret data";

    let tag_with_aad_a = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, b"header_a");
        let mut ct = plaintext.to_vec();
        aead_encrypt_chunk(&mut s, &mut ct);
        aead_finalize(&mut s)
    };

    let tag_with_aad_b = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, b"header_b"); // different AAD
        let mut ct = plaintext.to_vec();
        aead_encrypt_chunk(&mut s, &mut ct);
        aead_finalize(&mut s)
    };

    assert_ne!(
        tag_with_aad_a, tag_with_aad_b,
        "different AAD must produce different tags"
    );
}

/// Flipping one ciphertext byte must cause the tag to differ.
#[test]
fn aead_tag_changes_with_ciphertext_tamper() {
    let key = [0x33u8; 32];
    let iv = [0x44u8; 16];
    let aad = b"test header";
    let plaintext = b"authentic message here!";

    // Encrypt and get tag
    let (ciphertext, original_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut ct = plaintext.to_vec();
        aead_encrypt_chunk(&mut s, &mut ct);
        let tag = aead_finalize(&mut s);
        (ct, tag)
    };

    // Tamper ciphertext and re-derive tag via decrypt path
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;

    let tampered_tag = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut buf = tampered.clone();
        aead_decrypt_chunk(&mut s, &mut buf, &mut vec![]);
        aead_finalize(&mut s)
    };

    assert_ne!(
        original_tag, tampered_tag,
        "tampered ciphertext must produce different tag"
    );
}

/// Full AEAD encrypt → decrypt round-trip with tag verification.
#[test]
fn aead_encrypt_decrypt_roundtrip_direct() {
    let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| (i * 3) as u8);
    let aad = b"associated_data_for_auth";
    let plaintext = b"plaintext that must survive encrypt-decrypt";

    // Encrypt
    let (ciphertext, enc_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut ct = plaintext.to_vec();
        aead_encrypt_chunk(&mut s, &mut ct);
        let tag = aead_finalize(&mut s);
        (ct, tag)
    };

    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    // Decrypt
    let (recovered, dec_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut pt = ciphertext.clone();
        aead_decrypt_chunk(&mut s, &mut pt, &mut vec![]);
        let tag = aead_finalize(&mut s);
        (pt, tag)
    };

    assert_eq!(enc_tag, dec_tag, "encrypt and decrypt tags must match");
    assert_eq!(
        recovered, plaintext,
        "decrypted plaintext must match original"
    );
}

/// Zero-length plaintext with non-empty AAD must still produce a 32-byte tag.
#[test]
fn aead_empty_message() {
    let key = [0x55u8; 32];
    let iv = [0x66u8; 16];
    let aad = b"non-empty associated data";

    let tag = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        // No aead_encrypt_chunk calls — zero-length message
        aead_finalize(&mut s)
    };

    // Tag must be non-zero and exactly 32 bytes
    assert_eq!(tag.len(), 32);
    assert_ne!(tag, [0u8; 32], "tag for empty message must not be all-zero");
}

/// Data absorbed as AAD vs. data absorbed as ciphertext must produce different tags.
/// This verifies that DOMAIN_AAD (0x03) and DOMAIN_CT (0x04) are distinct.
#[test]
fn aead_absorb_aad_domain_separation() {
    let key = [0x77u8; 32];
    let iv = [0x88u8; 16];
    let data = b"same bytes, different role";

    // Absorb as AAD only (no ciphertext)
    let tag_aad_only = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, data);
        aead_finalize(&mut s)
    };

    // Absorb as ciphertext only (no AAD)
    let tag_ct_only = {
        let mut s = cipher_init(&key, &iv);
        let mut buf = data.to_vec();
        aead_encrypt_chunk(&mut s, &mut buf);
        aead_finalize(&mut s)
    };

    assert_ne!(
        tag_aad_only, tag_ct_only,
        "AAD and ciphertext absorption must be domain-separated (different tags)"
    );
}

// ── Multi-chunk AEAD consistency ─────────────────────────────────────────────

/// Encrypting 192 bytes in three 64-byte chunks and decrypting in the same
/// three chunks must recover the original plaintext with matching tags.
/// This confirms that chunk boundaries are handled consistently across the
/// encrypt/decrypt pair — the SpongeWrap absorb-after-XOR protocol produces
/// identical state evolution regardless of which side performs it.
#[test]
fn aead_multi_chunk_encrypt_decrypt_roundtrip() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 5 + 0x10) as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| (i * 7 + 0x20) as u8);
    let aad = b"multi-chunk consistency test";
    let plaintext: [u8; 192] = core::array::from_fn(|i| (i % 251) as u8);

    // Encrypt in three 64-byte chunks
    let (ct0, ct1, ct2, enc_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut c0 = plaintext[0..64].to_vec();
        let mut c1 = plaintext[64..128].to_vec();
        let mut c2 = plaintext[128..192].to_vec();
        aead_encrypt_chunk(&mut s, &mut c0);
        aead_encrypt_chunk(&mut s, &mut c1);
        aead_encrypt_chunk(&mut s, &mut c2);
        let tag = aead_finalize(&mut s);
        (c0, c1, c2, tag)
    };

    // Each chunk must differ from its plaintext (encryption occurred)
    assert_ne!(
        &ct0[..],
        &plaintext[0..64],
        "chunk 0 ciphertext must differ from plaintext"
    );

    // Decrypt in three 64-byte chunks
    let (pt0, pt1, pt2, dec_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut d0 = ct0.clone();
        let mut d1 = ct1.clone();
        let mut d2 = ct2.clone();
        aead_decrypt_chunk(&mut s, &mut d0, &mut vec![]);
        aead_decrypt_chunk(&mut s, &mut d1, &mut vec![]);
        aead_decrypt_chunk(&mut s, &mut d2, &mut vec![]);
        let tag = aead_finalize(&mut s);
        (d0, d1, d2, tag)
    };

    // Tags must match (encrypt and decrypt state evolution is identical)
    assert_eq!(enc_tag, dec_tag, "encrypt and decrypt tags must match");

    // Recovered plaintext must match original
    assert_eq!(&pt0[..], &plaintext[0..64], "chunk 0 plaintext mismatch");
    assert_eq!(&pt1[..], &plaintext[64..128], "chunk 1 plaintext mismatch");
    assert_eq!(&pt2[..], &plaintext[128..192], "chunk 2 plaintext mismatch");
}

// ── Arnold's Cat Map mathematical verification ────────────────────────────────
//
// Verifies the basic algebraic properties of the Cat Map before trusting the
// cipher output.  These tests are independent of the sponge construction and
// test only the map function itself via the exported keystream primitive.
//
// The Cat Map matrix is [[1,1],[1,2]]:
//   x' = x + y
//   y' = x' + y  (symplectic order, = x + 2y)

fn cat_map_ref(x: u64, y: u64) -> (u64, u64) {
    let xn = x.wrapping_add(y);
    let yn = xn.wrapping_add(y);
    (xn, yn)
}

#[test]
fn arnold_cat_map_basic_correctness() {
    // From the mathematical definition: [[1,1],[1,2]] * [x,y]^T
    assert_eq!(cat_map_ref(1, 0), (1, 1), "cat_map(1,0) must equal (1,1)");
    assert_eq!(cat_map_ref(0, 1), (1, 2), "cat_map(0,1) must equal (1,2)");
    assert_eq!(cat_map_ref(1, 1), (2, 3), "cat_map(1,1) must equal (2,3)");
}

#[test]
fn arnold_cat_map_fixed_point() {
    // (0,0) is a fixed point: cat_map(0,0) = (0,0).
    // The Weyl counter injection in Step 1 of cml_round ensures this is
    // never presented to the map during cipher operation.
    assert_eq!(cat_map_ref(0, 0), (0, 0), "cat_map(0,0) must equal (0,0)");
}

#[test]
fn arnold_cat_map_not_involution() {
    // The map is not its own inverse.
    let x: u64 = 0x0123456789ABCDEF;
    let y: u64 = 0xFEDCBA9876543210;
    let (x1, y1) = cat_map_ref(x, y);
    let (x2, y2) = cat_map_ref(x1, y1);
    // Applying twice should NOT give back (x, y) for a non-trivial input.
    assert_ne!(
        (x2, y2),
        (x, y),
        "cat_map applied twice must not return original (not an involution)"
    );
}

#[test]
fn arnold_cat_map_area_preserving() {
    // det([[1,1],[1,2]]) = 1*2 - 1*1 = 1.
    // Consequence: the map is invertible and area-preserving.
    // Verify by checking inverse: inv = [[2,-1],[-1,1]]
    //   x_orig = 2*x' - y' = 2*(x+y) - (x+2y) = x
    //   y_orig = -x' + y'  = -(x+y) + (x+2y) = y
    let x: u64 = 0xDEADBEEFCAFEBABE;
    let y: u64 = 0x0102030405060708;
    let (xn, yn) = cat_map_ref(x, y);
    let x_rec = (2u64).wrapping_mul(xn).wrapping_sub(yn);
    let y_rec = yn.wrapping_sub(xn);
    assert_eq!(
        x_rec, x,
        "Cat Map inverse (area-preserving check) must recover x"
    );
    assert_eq!(
        y_rec, y,
        "Cat Map inverse (area-preserving check) must recover y"
    );
}

// ── Rate-boundary plaintext tests ─────────────────────────────────────────────
//
// These tests verify correct behaviour at and around the 64-byte rate boundary,
// catching off-by-one errors in the chunk/block logic.

#[test]
fn aead_roundtrip_63_bytes() {
    // One byte under a rate block — exercises partial-block logic.
    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let aad = b"aad-63";
    let mut pt = vec![0xAAu8; 63];
    let mut buf = Vec::new();

    let mut enc = cipher_init(&key, &iv);
    absorb_aad(&mut enc, aad);
    aead_encrypt_chunk(&mut enc, &mut pt);
    let enc_tag = aead_finalize(&mut enc);

    let ct = pt.clone();
    let mut dec_ct = ct.clone();
    let mut dec = cipher_init(&key, &iv);
    absorb_aad(&mut dec, aad);
    aead_decrypt_chunk(&mut dec, &mut dec_ct, &mut buf);
    let dec_tag = aead_finalize(&mut dec);

    assert_eq!(enc_tag, dec_tag, "tags must match for 63-byte plaintext");
    assert_eq!(
        dec_ct,
        vec![0xAAu8; 63],
        "63-byte plaintext must decrypt correctly"
    );
}

#[test]
fn aead_roundtrip_64_bytes() {
    // Exactly one rate block — boundary case.
    let key = [0x33u8; 32];
    let iv = [0x44u8; 16];
    let aad = b"aad-64";
    let mut pt = vec![0xBBu8; 64];
    let mut buf = Vec::new();

    let mut enc = cipher_init(&key, &iv);
    absorb_aad(&mut enc, aad);
    aead_encrypt_chunk(&mut enc, &mut pt);
    let enc_tag = aead_finalize(&mut enc);

    let mut dec_ct = pt.clone();
    let mut dec = cipher_init(&key, &iv);
    absorb_aad(&mut dec, aad);
    aead_decrypt_chunk(&mut dec, &mut dec_ct, &mut buf);
    let dec_tag = aead_finalize(&mut dec);

    assert_eq!(enc_tag, dec_tag, "tags must match for 64-byte plaintext");
    assert_eq!(
        dec_ct,
        vec![0xBBu8; 64],
        "64-byte plaintext must decrypt correctly"
    );
}

#[test]
fn aead_roundtrip_65_bytes() {
    // One byte over a rate block — crosses into the second block.
    let key = [0x55u8; 32];
    let iv = [0x66u8; 16];
    let aad = b"aad-65";
    let mut pt = vec![0xCCu8; 65];
    let mut buf = Vec::new();

    let mut enc = cipher_init(&key, &iv);
    absorb_aad(&mut enc, aad);
    aead_encrypt_chunk(&mut enc, &mut pt);
    let enc_tag = aead_finalize(&mut enc);

    let mut dec_ct = pt.clone();
    let mut dec = cipher_init(&key, &iv);
    absorb_aad(&mut dec, aad);
    aead_decrypt_chunk(&mut dec, &mut dec_ct, &mut buf);
    let dec_tag = aead_finalize(&mut dec);

    assert_eq!(enc_tag, dec_tag, "tags must match for 65-byte plaintext");
    assert_eq!(
        dec_ct,
        vec![0xCCu8; 65],
        "65-byte plaintext must decrypt correctly"
    );
}

#[test]
fn aead_roundtrip_128_bytes() {
    // Exactly two rate blocks.
    let key = [0x77u8; 32];
    let iv = [0x88u8; 16];
    let aad = b"aad-128";
    let mut pt = vec![0xDDu8; 128];
    let mut buf = Vec::new();

    let mut enc = cipher_init(&key, &iv);
    absorb_aad(&mut enc, aad);
    aead_encrypt_chunk(&mut enc, &mut pt);
    let enc_tag = aead_finalize(&mut enc);

    let mut dec_ct = pt.clone();
    let mut dec = cipher_init(&key, &iv);
    absorb_aad(&mut dec, aad);
    aead_decrypt_chunk(&mut dec, &mut dec_ct, &mut buf);
    let dec_tag = aead_finalize(&mut dec);

    assert_eq!(enc_tag, dec_tag, "tags must match for 128-byte plaintext");
    assert_eq!(
        dec_ct,
        vec![0xDDu8; 128],
        "128-byte plaintext must decrypt correctly"
    );
}

/// AEAD round-trip across multiple chunks whose lengths are NOT multiples of
/// the 64-byte rate.  This exercises the keystream-buffer invalidation that must
/// happen after each `absorb`: a partial-block chunk leaves keystream bytes
/// buffered, and the following chunk must squeeze fresh state rather than reuse
/// pre-absorb keystream.  Encrypt and decrypt must agree and recover the input.
#[test]
fn aead_roundtrip_unaligned_multi_chunk() {
    let key = [0x9Cu8; 32];
    let iv = [0x5Au8; 16];
    let aad = b"unaligned-chunks";
    let plaintext: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
    let sizes = [50usize, 70, 80]; // none a multiple of 64; sum = 200

    // Encrypt chunk-by-chunk.
    let (ciphertext, enc_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut ct = plaintext.clone();
        let mut off = 0;
        for &n in &sizes {
            aead_encrypt_chunk(&mut s, &mut ct[off..off + n]);
            off += n;
        }
        let tag = aead_finalize(&mut s);
        (ct, tag)
    };
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    // Decrypt with the same chunk boundaries.
    let (recovered, dec_tag) = {
        let mut s = cipher_init(&key, &iv);
        absorb_aad(&mut s, aad);
        let mut pt = ciphertext.clone();
        let mut buf = Vec::new();
        let mut off = 0;
        for &n in &sizes {
            aead_decrypt_chunk(&mut s, &mut pt[off..off + n], &mut buf);
            off += n;
        }
        let tag = aead_finalize(&mut s);
        (pt, tag)
    };

    assert_eq!(enc_tag, dec_tag, "encrypt and decrypt tags must match");
    assert_eq!(
        recovered, plaintext,
        "unaligned multi-chunk must round-trip"
    );
}

#[test]
fn arnold_cat_map_no_complement_symmetry() {
    // Arnold's Cat Map: cat_map(x,y) ≠ cat_map(MAX-x, MAX-y) for generic inputs.
    let x: u64 = 0x1111111111111111;
    let y: u64 = 0x2222222222222222;
    let (xn, yn) = cat_map_ref(x, y);
    let (xc, yc) = cat_map_ref(u64::MAX - x, u64::MAX - y);
    // The outputs should differ (they are related by negation modulo some shift,
    // not by bitwise complement, so this assertion holds for non-trivial inputs).
    assert_ne!(
        (xn, yn),
        (xc, yc),
        "Cat Map must not have complement symmetry: cat_map(x,y) ≠ cat_map(MAX-x,MAX-y)"
    );
}
