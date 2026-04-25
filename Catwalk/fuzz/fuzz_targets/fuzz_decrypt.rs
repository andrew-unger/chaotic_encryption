#![no_main]

// Property: catwalk::crypto::decrypt must never panic on attacker-controlled
// input. It is allowed to return any CryptoError, but must not abort, deadlock,
// or unwrap a None / Err value.

use libfuzzer_sys::fuzz_target;

const FUZZ_PASSWORD: &str = "fuzz-only-fixed-password-not-secret";

fuzz_target!(|data: &[u8]| {
    let _ = catwalk::crypto::decrypt(data, FUZZ_PASSWORD, None, None);
});
