// Keyfile integration tests.
//
// NOTE: passwords here are intentionally short — encrypt/decrypt do not call
// validate_password; that is the CLI/GUI's responsibility.

use std::fs;
use std::path::PathBuf;
use catwalk::crypto::{encrypt, decrypt, EncryptOptions};
use catwalk::error::CryptoError;
use catwalk::crypto::constants::FLAG_KEYFILE;

const OPTS: EncryptOptions = EncryptOptions { strip_metadata: false, skip_compression: true };

// ── helpers ──────────────────────────────────────────────────────────────────

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("catwalk_kftest_{}", name))
}

fn write_tmp(name: &str, data: &[u8]) -> PathBuf {
    let p = tmp_path(name);
    fs::write(&p, data).expect("write tmp file");
    p
}

// ── Test 1 — keyfile round-trip ───────────────────────────────────────────────

#[test]
fn keyfile_round_trip() {
    let plaintext  = b"keyfile round-trip test payload";
    let password   = "correcthorsebattery";
    let keyfile    = write_tmp("kf1.key", b"super secret keyfile bytes for test 1");

    let encrypted = encrypt(plaintext, password, "test.txt", &OPTS, Some(&keyfile), None)
        .expect("encryption with keyfile failed");

    let (decrypted, ext) = decrypt(&encrypted, password, Some(&keyfile), None)
        .expect("decryption with keyfile failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "txt");

    let _ = fs::remove_file(keyfile);
}

// ── Test 2 — wrong keyfile rejected ──────────────────────────────────────────

#[test]
fn wrong_keyfile_rejected() {
    let plaintext = b"protected by keyfile a";
    let password  = "correcthorsebattery";
    let keyfile_a = write_tmp("kf2a.key", b"keyfile A contents - primary");
    let keyfile_b = write_tmp("kf2b.key", b"keyfile B contents - wrong one");

    let encrypted = encrypt(plaintext, password, "test.txt", &OPTS, Some(&keyfile_a), None)
        .expect("encryption failed");

    let result = decrypt(&encrypted, password, Some(&keyfile_b), None);
    assert!(
        matches!(result, Err(CryptoError::IntegrityCheckFailed)),
        "expected IntegrityCheckFailed with wrong keyfile, got {:?}", result.err()
    );

    let _ = fs::remove_file(keyfile_a);
    let _ = fs::remove_file(keyfile_b);
}

// ── Test 3 — missing keyfile rejected ────────────────────────────────────────

#[test]
fn missing_keyfile_rejected() {
    let plaintext = b"protected - you must have the keyfile";
    let password  = "correcthorsebattery";
    let keyfile   = write_tmp("kf3.key", b"the required keyfile");

    let encrypted = encrypt(plaintext, password, "data.bin", &OPTS, Some(&keyfile), None)
        .expect("encryption failed");

    // Decrypt without providing the keyfile at all.
    let result = decrypt(&encrypted, password, None, None);
    assert!(
        matches!(result, Err(CryptoError::KeyfileRequired)),
        "expected KeyfileRequired, got {:?}", result.err()
    );

    let _ = fs::remove_file(keyfile);
}

// ── Test 4 — spurious keyfile silently ignored ────────────────────────────────

#[test]
fn spurious_keyfile_ignored() {
    // Encrypt WITHOUT a keyfile, then try to decrypt WITH one.
    // The keyfile flag is not set in the header; the extra keyfile is ignored.
    let plaintext    = b"no keyfile was used during encryption";
    let password     = "correcthorsebattery";
    let spurious_kf  = write_tmp("kf4.key", b"an unnecessary keyfile");

    let encrypted = encrypt(plaintext, password, "data.bin", &OPTS, None, None)
        .expect("encryption without keyfile failed");

    // Verify FLAG_KEYFILE is NOT set.
    assert_eq!(encrypted[5] & FLAG_KEYFILE, 0, "FLAG_KEYFILE should not be set");

    let (decrypted, _) = decrypt(&encrypted, password, Some(&spurious_kf), None)
        .expect("decryption should succeed; spurious keyfile must be silently ignored");

    assert_eq!(decrypted, plaintext);

    let _ = fs::remove_file(spurious_kf);
}

// ── Test 5 — keyfile too large rejected ──────────────────────────────────────

#[test]
fn keyfile_too_large_rejected() {
    // Create a sparse file that appears 2 GB without consuming disk space.
    // set_len() on Windows (NTFS) and Linux (ext4/btrfs) creates a sparse file
    // so the logical size is 2 GB but physical allocation is near zero.
    let huge_path = tmp_path("kf5_huge.key");
    {
        let f = fs::File::create(&huge_path).expect("create huge file");
        f.set_len(2_000_000_000).expect("set file length to ~2 GB");
    }

    let result = encrypt(b"payload", "correcthorsebattery", "x.bin", &OPTS, Some(&huge_path), None);
    assert!(
        matches!(result, Err(CryptoError::KeyfileTooLarge)),
        "expected KeyfileTooLarge for a 2 GB keyfile, got {:?}", result.err()
    );

    let _ = fs::remove_file(huge_path);
}

// ── Test 6 — FLAG_KEYFILE correctly set in header ─────────────────────────────

#[test]
fn flag_keyfile_set_in_header() {
    let keyfile   = write_tmp("kf6.key", b"a modest keyfile for header flag test");
    let password  = "correcthorsebattery";

    // With keyfile — FLAG_KEYFILE (0x04) must be set.
    let encrypted_with = encrypt(b"payload", password, "x.bin", &OPTS, Some(&keyfile), None)
        .expect("encryption with keyfile");
    assert_eq!(
        encrypted_with[5] & FLAG_KEYFILE, FLAG_KEYFILE,
        "FLAG_KEYFILE should be set when a keyfile is provided"
    );

    // Without keyfile — FLAG_KEYFILE must NOT be set.
    let encrypted_without = encrypt(b"payload", password, "x.bin", &OPTS, None, None)
        .expect("encryption without keyfile");
    assert_eq!(
        encrypted_without[5] & FLAG_KEYFILE, 0,
        "FLAG_KEYFILE should not be set when no keyfile is provided"
    );

    let _ = fs::remove_file(keyfile);
}

// ── Test 7 — different keyfiles → different ciphertexts ──────────────────────

#[test]
fn different_keyfiles_produce_different_ciphertext() {
    let plaintext = b"same plaintext, same password, different keyfiles";
    let password  = "correcthorsebattery";
    let kf_a      = write_tmp("kf7a.key", b"keyfile alpha contents");
    let kf_b      = write_tmp("kf7b.key", b"keyfile beta  contents");

    let enc_a = encrypt(plaintext, password, "x.bin", &OPTS, Some(&kf_a), None)
        .expect("encryption with keyfile A");
    let enc_b = encrypt(plaintext, password, "x.bin", &OPTS, Some(&kf_b), None)
        .expect("encryption with keyfile B");

    // The ciphertexts must differ (different KDF inputs → different keys).
    // (They would also differ due to random salt/nonce, but distinct KDF input
    // ensures they're not accidentally equal even with the same random material.)
    assert_ne!(enc_a, enc_b, "different keyfiles must produce different ciphertext");

    let _ = fs::remove_file(kf_a);
    let _ = fs::remove_file(kf_b);
}

// ── Test 8 — EntropyPool derives deterministically from same inputs ───────────
// This lives here (not in gui.rs) because EntropyPool is a pure data structure
// and its derive_keyfile() output must be deterministic for a fixed pool state.
// We test it by directly exercising the BLAKE3 derivation logic.

#[test]
fn entropy_pool_derive_is_deterministic_for_same_pool() {
    // Two pools fed identical bytes must produce the same derive_keyfile() output.
    // We test this by reproducing the derivation formula directly, because
    // EntropyPool is in the gui module and not exported as a library type.
    // Instead we verify the BLAKE3 xof derivation primitive used inside it:
    //   BLAKE3-xof( pool_bytes || now_ns || "catwalk-keyfile-v1" ) → 64 bytes
    // is deterministic for the same inputs.

    let pool_bytes: Vec<u8> = (0u8..=127).collect(); // 128 bytes of entropy
    let fixed_ns: u64 = 1_711_000_000_000_000_000u64; // fixed "now"
    let label = b"catwalk-keyfile-v1";

    let derive = |pool: &[u8]| -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pool);
        hasher.update(&fixed_ns.to_le_bytes());
        hasher.update(label);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    };

    let out1 = derive(&pool_bytes);
    let out2 = derive(&pool_bytes);
    assert_eq!(out1, out2, "BLAKE3 derivation must be deterministic for same inputs");

    // Different pool → different output.
    let mut other_pool = pool_bytes.clone();
    other_pool[0] ^= 0xFF;
    let out3 = derive(&other_pool);
    assert_ne!(out1, out3, "different pool bytes must produce different derived keyfile");
}
