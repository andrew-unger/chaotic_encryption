use au79_crypto::crypto::{encrypt, decrypt, EncryptOptions};

const DEFAULT_OPTS: EncryptOptions = EncryptOptions {
    strip_metadata: false,
    skip_compression: false,
};

#[test]
fn round_trip_basic() {
    let plaintext = b"Hello, this is a test of AU79 chaotic encryption!";
    let password = "testpassword123";
    let filename = "test.txt";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption failed");

    // Verify magic bytes and version
    assert_eq!(&encrypted[..4], b"AU79");
    assert_eq!(encrypted[4], 8); // version 8

    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "txt");
}

#[test]
fn round_trip_empty() {
    let plaintext = b"";
    let password = "pass";
    let filename = "empty.bin";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "bin");
}

#[test]
fn round_trip_large() {
    // 1 MB of patterned data
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let password = "strong_password!@#$%";
    let filename = "data.dat";

    let encrypted = encrypt(&plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "dat");
}

#[test]
fn wrong_password_fails() {
    let plaintext = b"secret data";
    let password = "correct_password";
    let filename = "secret.txt";

    let encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption failed");

    let result = decrypt(&encrypted, "wrong_password", None);
    assert!(result.is_err(), "decryption with wrong password should fail");
}

#[test]
fn tampered_ciphertext_fails() {
    let plaintext = b"integrity test data";
    let password = "integrity_pass";
    let filename = "test.txt";

    let mut encrypted = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption failed");

    // Tamper with a byte in the ciphertext region (past the header, before MAC)
    let tamper_pos = encrypted.len() - 33; // one byte before the 32-byte MAC
    encrypted[tamper_pos] ^= 0xFF;

    let result = decrypt(&encrypted, password, None);
    assert!(result.is_err(), "tampered ciphertext should fail MAC check");
}

#[test]
fn different_encryptions_differ() {
    let plaintext = b"same plaintext";
    let password = "same_password";
    let filename = "test.txt";

    let enc1 = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption 1 failed");
    let enc2 = encrypt(plaintext, password, filename, &DEFAULT_OPTS, None).expect("encryption 2 failed");

    // Different salt/nonce means different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    let (dec1, _) = decrypt(&enc1, password, None).expect("decryption 1 failed");
    let (dec2, _) = decrypt(&enc2, password, None).expect("decryption 2 failed");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, plaintext);
}

#[test]
fn round_trip_no_metadata() {
    let plaintext = b"metadata stripped test";
    let password = "strip_meta_pass";
    let filename = "document.pdf";

    let opts = EncryptOptions { strip_metadata: true, skip_compression: false };
    let encrypted = encrypt(plaintext, password, filename, &opts, None).expect("encryption failed");

    // Flags byte should have bit 0 set
    assert_eq!(encrypted[5] & 0x01, 0x01);
    // Timestamp should be zero
    assert_eq!(&encrypted[22..30], &[0u8; 8]);

    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, ""); // extension stripped
}

#[test]
fn round_trip_no_compress() {
    let plaintext = b"uncompressed test data here";
    let password = "no_compress_pass";
    let filename = "raw.bin";

    let opts = EncryptOptions { strip_metadata: false, skip_compression: true };
    let encrypted = encrypt(plaintext, password, filename, &opts, None).expect("encryption failed");

    // Flags byte should have bit 1 set
    assert_eq!(encrypted[5] & 0x02, 0x02);

    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "bin");
}

#[test]
fn round_trip_both_flags() {
    let plaintext = b"both flags enabled";
    let password = "both_flags_pass";
    let filename = "secret.docx";

    let opts = EncryptOptions { strip_metadata: true, skip_compression: true };
    let encrypted = encrypt(plaintext, password, filename, &opts, None).expect("encryption failed");

    // Both flag bits set
    assert_eq!(encrypted[5] & 0x03, 0x03);

    let (decrypted, ext) = decrypt(&encrypted, password, None).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "");
}
