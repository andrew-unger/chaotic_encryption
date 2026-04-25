#![no_main]

// Property: catwalk::utils::parse_file_info must never panic when given
// attacker-controlled bytes. The function is intended to read header metadata
// from possibly-corrupt CATWALK files, so it is the canonical bug-magnet for
// header parsing issues.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = catwalk::utils::parse_file_info(data);
});
