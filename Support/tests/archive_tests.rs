// Integration tests for archive.rs.
//
// Requires: `cargo test --features archive`
//
// Tests cover:
//   - create_archive + extract_archive happy path
//   - Empty archive (zero files)
//   - Extraction of archive with `..` components in entry names (zip-slip defence)
//   - Extraction of archive with absolute path entry names
//   - create_archive with a non-existent source file
//   - extract_archive with corrupt ZIP data
//   - Count returned by extract_archive equals number of files

#[cfg(feature = "archive")]
mod archive {
    use catwalk::archive::{create_archive, extract_archive};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("catwalk_archtest_{}", name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmp dir");
        p
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, content).expect("write test file");
        p
    }

    // ── Happy path: create then extract ───────────────────────────────────────

    #[test]
    fn create_and_extract_round_trip() {
        let src_dir = tmp_dir("src_round_trip");
        let out_dir = tmp_dir("out_round_trip");

        let f1 = write_file(&src_dir, "alpha.txt", b"file alpha contents");
        let f2 = write_file(&src_dir, "beta.bin", b"\x00\x01\x02\x03");

        let zip_bytes = create_archive(&[f1, f2]).expect("create_archive failed");
        assert!(!zip_bytes.is_empty(), "archive must not be empty");

        let count = extract_archive(&zip_bytes, &out_dir).expect("extract_archive failed");
        assert_eq!(count, 2, "expected 2 files extracted");

        let got_alpha = fs::read(out_dir.join("alpha.txt")).expect("alpha.txt not extracted");
        assert_eq!(got_alpha, b"file alpha contents");

        let got_beta = fs::read(out_dir.join("beta.bin")).expect("beta.bin not extracted");
        assert_eq!(got_beta, b"\x00\x01\x02\x03");

        let _ = fs::remove_dir_all(&src_dir);
        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── Empty archive ─────────────────────────────────────────────────────────

    #[test]
    fn create_and_extract_empty_archive() {
        let out_dir = tmp_dir("out_empty");

        let zip_bytes = create_archive(&[]).expect("create_archive with empty list failed");
        let count =
            extract_archive(&zip_bytes, &out_dir).expect("extract_archive on empty zip failed");
        assert_eq!(count, 0, "expected 0 files for empty archive");

        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── Multiple files keep content independent ───────────────────────────────

    #[test]
    fn multiple_files_content_integrity() {
        let src_dir = tmp_dir("src_multi");
        let out_dir = tmp_dir("out_multi");

        // Create 5 files with distinct content.
        let files: Vec<PathBuf> = (0..5)
            .map(|i| {
                let content = format!("content of file {}", i);
                write_file(&src_dir, &format!("file{}.txt", i), content.as_bytes())
            })
            .collect();

        let zip_bytes = create_archive(&files).expect("create_archive failed");
        let count = extract_archive(&zip_bytes, &out_dir).expect("extract_archive failed");
        assert_eq!(count, 5);

        for i in 0..5 {
            let expected = format!("content of file {}", i);
            let got = fs::read_to_string(out_dir.join(format!("file{}.txt", i)))
                .expect("file not found after extraction");
            assert_eq!(got, expected, "file{}.txt content mismatch", i);
        }

        let _ = fs::remove_dir_all(&src_dir);
        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── Zip-slip: entry with ".." in name must be silently skipped ─────────────
    //
    // We craft a ZIP in memory with an entry named "../../evil.txt" and verify
    // that extract_archive does NOT create any file outside the output directory.

    #[test]
    fn dotdot_entry_is_skipped() {
        use std::io::{Cursor, Write};

        let out_dir = tmp_dir("out_zipslip");

        // Manually build a ZIP with a path-traversal entry name.
        let mut zip_buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("../../evil.txt", opts).expect("start_file");
            zip.write_all(b"I should not exist outside the output dir")
                .expect("write data");
            zip.finish().expect("finish zip");
        }
        let zip_bytes = zip_buf.into_inner();

        // extract_archive must either skip the entry or return an error.
        // Either outcome is acceptable — what must NOT happen is creating the
        // file two directories above out_dir.
        let _ = extract_archive(&zip_bytes, &out_dir);

        // The dangerous path must not have been created.
        let dangerous = out_dir.join("../../evil.txt");
        // Normalise to catch symlink tricks.
        assert!(
            !dangerous.exists(),
            "zip-slip file must not be created: {:?}",
            dangerous
        );

        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── Absolute path entry is sanitised ──────────────────────────────────────
    //
    // Entry named "/etc/passwd" should have directory components stripped so
    // only "passwd" is created inside the output dir.

    #[test]
    fn absolute_path_entry_is_sanitised() {
        use std::io::{Cursor, Write};

        let out_dir = tmp_dir("out_abspath");

        let mut zip_buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            // The entry is stored with an absolute-looking name.
            zip.start_file("/tmp/safe_output.txt", opts)
                .expect("start_file");
            zip.write_all(b"safe content").expect("write data");
            zip.finish().expect("finish zip");
        }
        let zip_bytes = zip_buf.into_inner();

        let count = extract_archive(&zip_bytes, &out_dir).expect("extract_archive failed");
        // The sanitised filename "safe_output.txt" must land inside out_dir.
        assert_eq!(count, 1);
        let extracted = out_dir.join("safe_output.txt");
        assert!(
            extracted.exists(),
            "expected safe_output.txt inside output dir"
        );
        assert_eq!(
            fs::read(&extracted).unwrap(),
            b"safe content",
            "content mismatch after path sanitisation"
        );

        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── create_archive with non-existent file returns IoError ─────────────────

    #[test]
    fn create_archive_missing_file_returns_error() {
        use catwalk::error::CryptoError;

        let missing = PathBuf::from("/this/path/definitely/does/not/exist/ghost.txt");
        let result = create_archive(&[missing]);
        assert!(
            result.is_err(),
            "create_archive with a missing file must fail"
        );
        assert!(
            matches!(result, Err(CryptoError::IoError(_))),
            "expected IoError, got {:?}",
            result.err()
        );
    }

    // ── extract_archive with corrupt ZIP data returns ArchiveError ─────────────

    #[test]
    fn extract_archive_corrupt_data_returns_error() {
        use catwalk::error::CryptoError;

        let out_dir = tmp_dir("out_corrupt");
        let garbage = b"this is definitely not a valid zip file at all";
        let result = extract_archive(garbage, &out_dir);
        assert!(
            result.is_err(),
            "extract_archive on corrupt data must return an error"
        );
        assert!(
            matches!(result, Err(CryptoError::ArchiveError(_))),
            "expected ArchiveError, got {:?}",
            result.err()
        );

        let _ = fs::remove_dir_all(&out_dir);
    }

    // ── Single file with no extension ─────────────────────────────────────────

    #[test]
    fn archive_file_without_extension() {
        let src_dir = tmp_dir("src_noext");
        let out_dir = tmp_dir("out_noext");

        let f = write_file(&src_dir, "README", b"no extension here");
        let zip_bytes = create_archive(&[f]).expect("create_archive failed");
        let count = extract_archive(&zip_bytes, &out_dir).expect("extract_archive failed");
        assert_eq!(count, 1);
        let got = fs::read(out_dir.join("README")).expect("README not found");
        assert_eq!(got, b"no extension here");

        let _ = fs::remove_dir_all(&src_dir);
        let _ = fs::remove_dir_all(&out_dir);
    }
}
