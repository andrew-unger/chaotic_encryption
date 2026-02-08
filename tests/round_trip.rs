use au79_crypto::crypto::{encrypt, decrypt};

#[test]
fn round_trip_basic() {
    let plaintext = b"Hello, this is a test of AU79 chaotic encryption!";
    let password = "testpassword123";
    let filename = "test.txt";

    let encrypted = encrypt(plaintext, password, filename).expect("encryption failed");

    // Verify magic bytes and version
    assert_eq!(&encrypted[..4], b"AU79");
    assert_eq!(encrypted[4], 4); // version 4

    let (decrypted, ext) = decrypt(&encrypted, password).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "txt");
}

#[test]
fn round_trip_empty() {
    let plaintext = b"";
    let password = "pass";
    let filename = "empty.bin";

    let encrypted = encrypt(plaintext, password, filename).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "bin");
}

#[test]
fn round_trip_large() {
    // 1 MB of patterned data
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let password = "strong_password!@#$%";
    let filename = "data.dat";

    let encrypted = encrypt(&plaintext, password, filename).expect("encryption failed");
    let (decrypted, ext) = decrypt(&encrypted, password).expect("decryption failed");

    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, "dat");
}

#[test]
fn wrong_password_fails() {
    let plaintext = b"secret data";
    let password = "correct_password";
    let filename = "secret.txt";

    let encrypted = encrypt(plaintext, password, filename).expect("encryption failed");

    let result = decrypt(&encrypted, "wrong_password");
    assert!(result.is_err(), "decryption with wrong password should fail");
}

#[test]
fn tampered_ciphertext_fails() {
    let plaintext = b"integrity test data";
    let password = "integrity_pass";
    let filename = "test.txt";

    let mut encrypted = encrypt(plaintext, password, filename).expect("encryption failed");

    // Tamper with a byte in the ciphertext region (past the header, before MAC)
    let tamper_pos = encrypted.len() - 33; // one byte before the 32-byte MAC
    encrypted[tamper_pos] ^= 0xFF;

    let result = decrypt(&encrypted, password);
    assert!(result.is_err(), "tampered ciphertext should fail MAC check");
}

#[test]
fn different_encryptions_differ() {
    let plaintext = b"same plaintext";
    let password = "same_password";
    let filename = "test.txt";

    let enc1 = encrypt(plaintext, password, filename).expect("encryption 1 failed");
    let enc2 = encrypt(plaintext, password, filename).expect("encryption 2 failed");

    // Different salt/nonce means different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    let (dec1, _) = decrypt(&enc1, password).expect("decryption 1 failed");
    let (dec2, _) = decrypt(&enc2, password).expect("decryption 2 failed");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, plaintext);
}
