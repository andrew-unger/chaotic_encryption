#![no_main]

// Property: catwalk::archive::extract_archive must never panic on
// attacker-controlled bytes and must never write outside the supplied
// output_dir (zip-slip defense). This harness only checks the no-panic side;
// the structural zip-slip property is verified by archive_tests.rs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Use a fixed sandbox under the system temp dir; the archive extractor
    // creates a fresh subtree under it. We clear it each iteration so the
    // fuzzer doesn't accumulate state.
    let mut sandbox = std::env::temp_dir();
    sandbox.push("catwalk-fuzz-archive");

    let _ = std::fs::remove_dir_all(&sandbox);
    if std::fs::create_dir_all(&sandbox).is_err() {
        return;
    }

    let _ = catwalk::archive::extract_archive(data, sandbox.as_path());
});
