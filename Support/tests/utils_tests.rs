// Tests for utils.rs: parse_file_info, FileInfo display helpers,
// validate_password, format_byte_size, and the zlib backward-compat
// decompression path.

use catwalk::crypto::constants::{
    FLAG_KEYFILE, FLAG_NO_COMPRESS, FLAG_STRIP_METADATA, FLAG_ZSTD, MIN_HEADER_LEN, VERSION,
};
use catwalk::crypto::{decrypt, encrypt, validate_password, EncryptOptions};
use catwalk::error::CryptoError;
use catwalk::utils::{format_byte_size, parse_file_info};

// ── validate_password ────────────────────────────────────────────────────────

#[test]
fn password_below_min_length_rejected() {
    // 17 characters — one short of the 18-character minimum.
    let result = validate_password("shortpassword1234");
    assert!(result.is_err(), "password with 17 chars must be rejected");
    assert!(
        result.unwrap_err().contains("18"),
        "error message must mention the minimum length"
    );
}

#[test]
fn password_exactly_min_length_accepted() {
    // 18 characters, all distinct — must pass.
    let result = validate_password("abcdefghijklmnopqr");
    assert!(result.is_ok(), "exactly 18 distinct chars must be accepted");
}

#[test]
fn password_with_four_consecutive_identical_chars_rejected() {
    // "aaaa" is four identical chars in a row — exceeds max run of 3.
    let result = validate_password("correcthorsebattaaaa");
    assert!(
        result.is_err(),
        "four consecutive identical chars must be rejected"
    );
    assert!(
        result.unwrap_err().contains("consecutive"),
        "error message must mention consecutive characters"
    );
}

#[test]
fn password_with_exactly_three_consecutive_chars_accepted() {
    // Three identical chars in a row is the maximum allowed run.
    let result = validate_password("correcthorsebataaa!");
    assert!(
        result.is_ok(),
        "exactly three consecutive identical chars must be accepted: {:?}",
        result.err()
    );
}

#[test]
fn password_with_multiple_short_runs_accepted() {
    // Two separate runs of three — neither exceeds the limit.
    let result = validate_password("aaa_bbb_correcthorse");
    assert!(
        result.is_ok(),
        "multiple runs of three must be accepted: {:?}",
        result.err()
    );
}

#[test]
fn empty_password_rejected() {
    let result = validate_password("");
    assert!(result.is_err(), "empty password must be rejected");
}

// ── parse_file_info ───────────────────────────────────────────────────────────

#[test]
fn parse_file_info_invalid_magic() {
    let mut data = vec![0u8; MIN_HEADER_LEN + 10];
    data[0..4].copy_from_slice(b"JUNK");
    data[4] = VERSION;
    let result = parse_file_info(&data);
    assert!(
        matches!(result, Err(CryptoError::InvalidMagicBytes)),
        "expected InvalidMagicBytes, got {:?}",
        result.err()
    );
}

#[test]
fn parse_file_info_wrong_version() {
    let mut data = vec![0u8; MIN_HEADER_LEN + 10];
    data[0..4].copy_from_slice(b"CATW");
    data[4] = 7; // unsupported old version
    let result = parse_file_info(&data);
    assert!(
        matches!(result, Err(CryptoError::InvalidVersion)),
        "expected InvalidVersion, got {:?}",
        result.err()
    );
}

#[test]
fn parse_file_info_truncated_data() {
    // Correct magic and version but too short for a full header.
    let mut data = vec![0u8; MIN_HEADER_LEN - 1];
    data[0..4].copy_from_slice(b"CATW");
    data[4] = VERSION;
    let result = parse_file_info(&data);
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertextLength)),
        "expected InvalidCiphertextLength, got {:?}",
        result.err()
    );
}

#[test]
fn parse_file_info_succeeds_on_real_file() {
    // Encrypt a small payload and feed the output to parse_file_info.
    let opts = EncryptOptions {
        strip_metadata: false,
        skip_compression: true,
    };
    let encrypted =
        encrypt(b"hello", "pw", "doc.txt", &opts, None, None).expect("encryption failed");

    let info = parse_file_info(&encrypted).expect("parse_file_info failed on valid data");
    assert_eq!(info.version, VERSION);
    assert_eq!(info.extension, "txt");
    assert_eq!(info.flags & FLAG_NO_COMPRESS, FLAG_NO_COMPRESS);
    assert_eq!(info.flags & FLAG_STRIP_METADATA, 0);
    assert!(info.file_size > 0);
}

#[test]
fn parse_file_info_strip_metadata_flag() {
    let opts = EncryptOptions {
        strip_metadata: true,
        skip_compression: true,
    };
    let encrypted =
        encrypt(b"hello", "pw", "doc.txt", &opts, None, None).expect("encryption failed");

    let info = parse_file_info(&encrypted).expect("parse_file_info failed");
    assert_eq!(info.flags & FLAG_STRIP_METADATA, FLAG_STRIP_METADATA);
    assert_eq!(info.extension, ""); // stripped
    assert_eq!(info.timestamp, 0);
}

#[test]
fn parse_file_info_keyfile_flag() {
    use std::fs;
    let kf_path = std::env::temp_dir().join("utils_test_kf.key");
    fs::write(&kf_path, b"test keyfile").expect("write keyfile");

    let opts = EncryptOptions {
        strip_metadata: false,
        skip_compression: true,
    };
    let encrypted =
        encrypt(b"hello", "pw", "x.bin", &opts, Some(&kf_path), None).expect("encryption failed");

    let info = parse_file_info(&encrypted).expect("parse_file_info failed");
    assert_eq!(
        info.flags & FLAG_KEYFILE,
        FLAG_KEYFILE,
        "FLAG_KEYFILE must appear in parsed info"
    );

    let _ = fs::remove_file(kf_path);
}

#[test]
fn parse_file_info_zstd_flag_set_when_compressed() {
    let opts = EncryptOptions {
        strip_metadata: false,
        skip_compression: false, // compression ON → FLAG_ZSTD
    };
    let encrypted =
        encrypt(b"hello world!", "pw", "x.txt", &opts, None, None).expect("encryption failed");

    let info = parse_file_info(&encrypted).expect("parse_file_info failed");
    assert_eq!(
        info.flags & FLAG_ZSTD,
        FLAG_ZSTD,
        "FLAG_ZSTD must be set when skip_compression is false"
    );
}

// ── FileInfo helpers ──────────────────────────────────────────────────────────

#[test]
fn flags_display_no_flags() {
    let opts = EncryptOptions {
        strip_metadata: false,
        skip_compression: true,
    };
    let encrypted = encrypt(b"x", "pw", "x.bin", &opts, None, None).expect("enc");
    let info = parse_file_info(&encrypted).expect("parse");
    // Only FLAG_NO_COMPRESS is set for this combination.
    let display = info.flags_display();
    assert!(
        display.contains("NO_COMPRESS"),
        "expected NO_COMPRESS in flags_display, got: {}",
        display
    );
}

#[test]
fn flags_display_all_flags() {
    use std::fs;
    let kf_path = std::env::temp_dir().join("utils_test_allflags_kf.key");
    fs::write(&kf_path, b"kf bytes").expect("write keyfile");

    let opts = EncryptOptions {
        strip_metadata: true,
        skip_compression: false,
    };
    let encrypted = encrypt(b"x", "pw", "x.txt", &opts, Some(&kf_path), None).expect("enc");
    let info = parse_file_info(&encrypted).expect("parse");
    let display = info.flags_display();
    assert!(
        display.contains("STRIP_METADATA"),
        "missing STRIP_METADATA: {}",
        display
    );
    assert!(display.contains("KEYFILE"), "missing KEYFILE: {}", display);
    assert!(display.contains("ZSTD"), "missing ZSTD: {}", display);

    let _ = fs::remove_file(kf_path);
}

#[test]
fn argon2_memory_mb_is_sane() {
    let opts = EncryptOptions {
        strip_metadata: false,
        skip_compression: true,
    };
    let encrypted = encrypt(b"x", "pw", "x.bin", &opts, None, None).expect("enc");
    let info = parse_file_info(&encrypted).expect("parse");
    // Default m_log2 = 18 → 2^18 KiB / 1024 = 256 MB
    assert_eq!(
        info.argon2_memory_mb(),
        256,
        "default Argon2 memory must be 256 MB"
    );
}

// ── format_byte_size ──────────────────────────────────────────────────────────

#[test]
fn format_byte_size_bytes() {
    assert_eq!(format_byte_size(0), "0 B");
    assert_eq!(format_byte_size(1), "1 B");
    assert_eq!(format_byte_size(1023), "1023 B");
}

#[test]
fn format_byte_size_kilobytes() {
    assert_eq!(format_byte_size(1024), "1.0 KB");
    assert_eq!(format_byte_size(1536), "1.5 KB");
}

#[test]
fn format_byte_size_megabytes() {
    assert_eq!(format_byte_size(1024 * 1024), "1.00 MB");
}

#[test]
fn format_byte_size_gigabytes() {
    assert_eq!(format_byte_size(1024 * 1024 * 1024), "1.00 GB");
}

// ── zlib backward-compat decompression path ───────────────────────────────────
//
// The decrypt_v9 function takes the `decompress_data_zlib` branch when a file
// was encrypted with the legacy zlib compressor (FLAG_ZSTD is NOT set, but
// FLAG_NO_COMPRESS is also NOT set).  No existing test covers this path because
// the encrypt() API always sets FLAG_ZSTD when compression is enabled.
//
// We test the zlib path by calling decompress_data_zlib directly.

#[test]
fn decompress_data_zlib_round_trip() {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let original = b"hello from the legacy zlib path!";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(original).expect("zlib encode");
    let compressed = encoder.finish().expect("zlib finish");

    let result = catwalk::utils::decompress_data_zlib(&compressed)
        .expect("decompress_data_zlib failed on valid zlib data");
    assert_eq!(result, original);
}

#[test]
fn decompress_data_zlib_invalid_data_returns_error() {
    let garbage = b"this is not zlib compressed data at all!!!";
    let result = catwalk::utils::decompress_data_zlib(garbage);
    assert!(
        result.is_err(),
        "decompress_data_zlib must fail on corrupt input"
    );
}

// ── header ciphertext-length guard (cipher_start > tag_start) ─────────────────
//
// This guard fires in decrypt() when ext_len claims an extension so long that
// cipher_start would end up past or at tag_start.  The existing truncated_file
// test stops at the MIN_HEADER_LEN check; this test reaches the later guard.

#[test]
fn oversized_ext_len_rejected() {
    // Build a structurally valid header with correct magic/version/argon params,
    // then set ext_len so large that cipher_start > tag_start.
    let mut data = vec![0u8; MIN_HEADER_LEN + 40]; // just enough room
    data[0..4].copy_from_slice(b"CATW");
    data[4] = VERSION;
    data[5] = 0; // flags
                 // salt: bytes 6..22 — leave as zero
                 // timestamp: bytes 22..30 — leave as zero
                 // nonce: bytes 30..46 — leave as zero
                 // argon params at bytes 46..49:
    data[46] = 18; // m_log2 = 18 (meets minimum of 16)
    data[47] = 4; // t_cost = 4  (meets minimum of 2)
    data[48] = 1; // p_cost = 1
                  // ext_len at byte 49: set to 255 — far too large for this buffer
    data[49] = 255;

    let result = decrypt(&data, "password", None, None);
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertextLength)),
        "expected InvalidCiphertextLength for oversized ext_len, got {:?}",
        result.err()
    );
}

// ── Unicode password tests (covers chars().count() fix) ───────────────────────

#[test]
fn unicode_password_18_chars_but_over_18_bytes_accepted() {
    // 18 alternating emoji = 18 Unicode scalar values but 72 bytes.
    // Alternating ensures no consecutive-run violation.
    // The policy is chars().count() >= 18, so this must PASS.
    let pw = "🔑🗝🔑🗝🔑🗝🔑🗝🔑🗝🔑🗝🔑🗝🔑🗝🔑🗝"; // 9×(🔑🗝) = 18 chars
    assert_eq!(pw.chars().count(), 18);
    assert!(pw.len() > 18, "sanity: emoji is multi-byte");
    let result = validate_password(pw);
    assert!(
        result.is_ok(),
        "18 emoji chars must be accepted: {:?}",
        result
    );
}

#[test]
fn unicode_password_17_chars_rejected_even_if_over_18_bytes() {
    // 17 emoji = 17 chars but 68 bytes.
    // The policy requires >= 18 CHARS, so this must FAIL.
    let pw = "🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑"; // 17 🔑
    assert_eq!(pw.chars().count(), 17);
    assert!(pw.len() > 18, "sanity: still more than 18 bytes");
    let result = validate_password(pw);
    assert!(
        result.is_err(),
        "17 emoji chars must be rejected (below 18-char minimum)"
    );
}

// ── KDF parameter floor tests ─────────────────────────────────────────────────

#[test]
fn weak_t_cost_rejected_at_decrypt() {
    // Craft a header with t_cost = 1 (below minimum of 2).
    // decrypt() must return WeakKdfParameters before running the KDF.
    let mut data = vec![0u8; MIN_HEADER_LEN + 1]; // +1 for at least 1 ciphertext byte
    data[0..4].copy_from_slice(b"CATW");
    data[4] = VERSION;
    data[5] = 0; // flags
                 // salt: bytes 6..22 (leave as zero)
                 // timestamp: bytes 22..30 (leave as zero)
                 // nonce: bytes 30..46 (leave as zero)
                 // argon params at bytes 46..49:
    data[46] = 18; // m_log2 = 18 (meets floor)
    data[47] = 1; // t_cost = 1  (BELOW minimum of 2)
    data[48] = 1; // p_cost = 1
    data[49] = 0; // ext_len = 0

    let result = decrypt(&data, "somepassword-that-is-long-enough", None, None);
    assert!(
        matches!(result, Err(CryptoError::WeakKdfParameters)),
        "t_cost = 1 must be rejected as WeakKdfParameters, got {:?}",
        result.err()
    );
}

#[test]
fn weak_m_log2_rejected_at_decrypt() {
    // Craft a header with m_log2 = 15 (below minimum of 16).
    let mut data = vec![0u8; MIN_HEADER_LEN + 1];
    data[0..4].copy_from_slice(b"CATW");
    data[4] = VERSION;
    data[5] = 0; // flags
    data[46] = 15; // m_log2 = 15 (BELOW minimum of 16)
    data[47] = 2; // t_cost = 2 (meets floor)
    data[48] = 1; // p_cost = 1
    data[49] = 0; // ext_len = 0

    let result = decrypt(&data, "somepassword-that-is-long-enough", None, None);
    assert!(
        matches!(result, Err(CryptoError::WeakKdfParameters)),
        "m_log2 = 15 must be rejected as WeakKdfParameters, got {:?}",
        result.err()
    );
}
