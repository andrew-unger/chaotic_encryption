// Note: Test passwords in this file are intentionally shorter than the 18-character
// minimum enforced by `validate_password`.  The `encrypt()` and `decrypt()` functions
// do NOT call `validate_password` — that is the caller's responsibility (enforced in
// the CLI and GUI).  These tests exercise the cipher and AEAD round-trip, not the
// password policy.

use std::sync::{Arc, Mutex};
use catwalk::crypto::{encrypt, decrypt, EncryptOptions, ProgressFn};
use catwalk::error::CryptoError;
use catwalk::crypto::constants::MIN_HEADER_LEN;

const DEFAULT_OPTS: EncryptOptions = EncryptOptions {
    strip_metadata: false,
    skip_compression: false,
};

// ── Existing round-trip tests ─────────────────────────────────────────────────

#[test]
fn round_trip_basic() {
    let plaintext = b"Hello, this is a test of CATWALK chaotic encryption!";
    let password = "testpassword123";
    let filename = "test.txt";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");

    // Verify magic bytes and version
    assert_eq!(&encrypted[..4], b"CATW");
    assert_eq!(encrypted[4], 9); // version 9

    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "txt");
}

#[test]
fn round_trip_empty() {
    let plaintext = b"";
    let password = "pass";
    let filename = "empty.bin";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "bin");
}

#[test]
fn round_trip_large() {
    // 1 MB of patterned data
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let password = "strong_password!@#$%";
    let filename = "data.dat";

    let encrypted = encrypt(&plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "dat");
}

#[test]
fn wrong_password_fails() {
    let plaintext = b"secret data";
    let password = "correct_password";
    let filename = "secret.txt";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");

    let result = decrypt(&encrypted, "wrong_password", None, None);
    assert!(result.is_err(), "decryption with wrong password should fail");
}

#[test]
fn tampered_ciphertext_fails() {
    let plaintext = b"integrity test data";
    let password = "integrity_pass";
    let filename = "test.txt";

    let mut encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");

    // Tamper with a byte in the ciphertext region (past the header, before tag)
    let tamper_pos = encrypted.len() - 33; // one byte before the 32-byte tag
    encrypted[tamper_pos] ^= 0xFF;

    let result = decrypt(&encrypted, password, None, None);
    assert!(result.is_err(), "tampered ciphertext should fail tag check");
}

#[test]
fn different_encryptions_differ() {
    let plaintext = b"same plaintext";
    let password = "same_password";
    let filename = "test.txt";

    let enc1 = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption 1 failed");
    let enc2 = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption 2 failed");

    // Different salt/nonce means different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    let (dec1, _) = decrypt(&enc1, password, None, None).expect("decryption 1 failed");
    let (dec2, _) = decrypt(&enc2, password, None, None).expect("decryption 2 failed");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, plaintext);
}

#[test]
fn round_trip_no_metadata() {
    let plaintext = b"metadata stripped test";
    let password = "strip_meta_pass";
    let filename = "document.pdf";

    let opts = EncryptOptions { strip_metadata: true, skip_compression: false };
    let encrypted = encrypt(plaintext, password, filename, &opts, None, None).expect("encryption failed");

    // Flags byte should have bit 0 set
    assert_eq!(encrypted[5] & 0x01, 0x01);
    // Timestamp should be zero
    assert_eq!(&encrypted[22..30], &[0u8; 8]);

    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, ""); // extension stripped
}

#[test]
fn round_trip_no_compress() {
    let plaintext = b"uncompressed test data here";
    let password = "no_compress_pass";
    let filename = "raw.bin";

    let opts = EncryptOptions { strip_metadata: false, skip_compression: true };
    let encrypted = encrypt(plaintext, password, filename, &opts, None, None).expect("encryption failed");

    // Flags byte should have bit 1 set
    assert_eq!(encrypted[5] & 0x02, 0x02);

    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "bin");
}

#[test]
fn round_trip_both_flags() {
    let plaintext = b"both flags enabled";
    let password = "both_flags_pass";
    let filename = "secret.docx";

    let opts = EncryptOptions { strip_metadata: true, skip_compression: true };
    let encrypted = encrypt(plaintext, password, filename, &opts, None, None).expect("encryption failed");

    // Both flag bits set
    assert_eq!(encrypted[5] & 0x03, 0x03);

    let (decrypted, ext) = decrypt(&encrypted, password, None, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "");
}

// ── Error case tests ──────────────────────────────────────────────────────────

#[test]
fn invalid_magic_bytes_rejected() {
    let mut data = vec![0u8; MIN_HEADER_LEN + 10];
    data[0..4].copy_from_slice(b"FAKE");
    data[4] = 9; // correct version
    let result = decrypt(&data, "password", None, None);
    assert!(matches!(result, Err(CryptoError::InvalidMagicBytes)),
        "expected InvalidMagicBytes, got {:?}", result.err());
}

#[test]
fn truncated_file_rejected() {
    // Too short to be a valid header
    let data = vec![b'C', b'A', b'T', b'W', 9u8, 0u8];
    let result = decrypt(&data, "password", None, None);
    assert!(matches!(result, Err(CryptoError::InvalidCiphertextLength)),
        "expected InvalidCiphertextLength, got {:?}", result.err());
}

#[test]
fn wrong_version_byte_rejected() {
    // Build a MIN_HEADER_LEN-sized blob with correct magic but version 8
    let mut data = vec![0u8; MIN_HEADER_LEN + 10];
    data[0..4].copy_from_slice(b"CATW");
    data[4] = 8; // old version — now invalid
    // Fill argon2 fields with safe values so we reach the version check
    let result = decrypt(&data, "password", None, None);
    assert!(matches!(result, Err(CryptoError::InvalidVersion)),
        "expected InvalidVersion, got {:?}", result.err());
}

#[test]
fn weak_kdf_params_rejected() {
    // Build a header with correct magic/version but m_log2 below minimum (16)
    let mut data = vec![0u8; MIN_HEADER_LEN + 10];
    data[0..4].copy_from_slice(b"CATW");
    data[4] = 9;   // correct version
    data[5] = 0;   // flags
    // salt: bytes 6..22 (16 bytes) — leave as zero
    // timestamp: bytes 22..30 (8 bytes) — leave as zero
    // nonce: bytes 30..46 (16 bytes) — leave as zero
    // argon params: bytes 46..49
    data[46] = 10; // m_log2 = 10 — below minimum of 16
    data[47] = 4;  // t_cost = 4
    data[48] = 1;  // p_cost = 1
    // ext_len: byte 49 = 0
    let result = decrypt(&data, "password", None, None);
    assert!(matches!(result, Err(CryptoError::WeakKdfParameters)),
        "expected WeakKdfParameters, got {:?}", result.err());
}

#[test]
fn tampered_tag_fails() {
    let plaintext = b"tag tamper test";
    let password = "tag_tamper_pass";
    let filename = "test.bin";

    let mut encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");

    // Flip a byte in the last 32 bytes (the tag)
    let last = encrypted.len();
    encrypted[last - 1] ^= 0xFF;

    let result = decrypt(&encrypted, password, None, None);
    assert!(matches!(result, Err(CryptoError::IntegrityCheckFailed)),
        "expected IntegrityCheckFailed, got {:?}", result.err());
}

#[test]
fn tampered_header_fails() {
    let plaintext = b"header tamper test";
    let password = "header_tamper_pass";
    let filename = "test.bin";

    let mut encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None, None).expect("encryption failed");

    // Flip a byte in the header (nonce region — bytes 30..46)
    encrypted[30] ^= 0x01;

    let result = decrypt(&encrypted, password, None, None);
    assert!(matches!(result, Err(CryptoError::IntegrityCheckFailed)),
        "expected IntegrityCheckFailed (AAD mismatch), got {:?}", result.err());
}

// ── Edge case tests ───────────────────────────────────────────────────────────

#[test]
fn zero_length_plaintext_with_compression() {
    let opts = EncryptOptions { strip_metadata: false, skip_compression: false };
    let encrypted = encrypt(b"", "edge_case_pass!", "empty.txt", &opts, None, None)
        .expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, "edge_case_pass!", None, None)
        .expect("decryption failed");
    assert!(decrypted.is_empty());
    assert_eq!(ext, "txt");
}

#[test]
fn max_extension_length() {
    // ext_len is stored as u8, so max is 255 characters
    let ext: String = "a".repeat(255);
    let filename = format!("file.{}", ext);
    let plaintext = b"max extension test";
    let password = "max_ext_pass_test!";
    let opts = EncryptOptions { strip_metadata: false, skip_compression: true };

    let encrypted = encrypt(plaintext, password, &filename, &opts, None, None)
        .expect("encryption failed");
    let (decrypted, recovered_ext) = decrypt(&encrypted, password, None, None)
        .expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(recovered_ext, ext);
}

// ── Progress monotonicity tests ───────────────────────────────────────────────

fn collect_progress(cb_values: Arc<Mutex<Vec<f32>>>) -> ProgressFn {
    Box::new(move |v: f32| {
        cb_values.lock().unwrap().push(v);
    })
}

#[test]
fn progress_is_monotone_encrypt() {
    let values = Arc::new(Mutex::new(Vec::<f32>::new()));
    let cb = collect_progress(values.clone());
    let plaintext: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    encrypt(&plaintext, "monotone_test_pass!", "test.bin", &DEFAULT_OPTS, None, Some(&cb))
        .expect("encryption failed");

    let v = values.lock().unwrap();
    assert!(!v.is_empty(), "no progress values reported");
    for w in v.windows(2) {
        assert!(w[1] >= w[0],
            "progress regressed: {} then {}", w[0], w[1]);
    }
    assert!(*v.last().unwrap() >= 0.9,
        "final progress value too low: {}", v.last().unwrap());
}

#[test]
fn progress_is_monotone_decrypt() {
    let plaintext: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    let encrypted = encrypt(&plaintext, "monotone_test_pass!", "test.bin", &DEFAULT_OPTS, None, None)
        .expect("encryption failed");

    let values = Arc::new(Mutex::new(Vec::<f32>::new()));
    let cb = collect_progress(values.clone());
    decrypt(&encrypted, "monotone_test_pass!", None, Some(&cb))
        .expect("decryption failed");

    let v = values.lock().unwrap();
    assert!(!v.is_empty(), "no progress values reported");
    for w in v.windows(2) {
        assert!(w[1] >= w[0],
            "progress regressed: {} then {}", w[0], w[1]);
    }
}
