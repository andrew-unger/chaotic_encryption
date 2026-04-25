// Shared helpers for CATWALK integration tests.
//
// Each integration-test file is its own crate, so this module is included
// per-test via `mod common;`.  Items that go unused in a particular test
// trigger dead-code warnings, hence `#[allow(dead_code)]` on each helper.

use std::fs;
use std::path::{Path, PathBuf};

/// Build a temp-file path under the OS temp dir with a per-test prefix.
#[allow(dead_code)]
pub fn tmp_path(prefix: &str, name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("catwalk_{prefix}_{name}"))
}

/// Write `data` to a fresh temp file and return its path.
#[allow(dead_code)]
pub fn write_tmp(prefix: &str, name: &str, data: &[u8]) -> PathBuf {
    let p = tmp_path(prefix, name);
    fs::write(&p, data).expect("write tmp file");
    p
}

/// Create (or recreate) a temp directory and return its path.
#[allow(dead_code)]
pub fn tmp_dir(prefix: &str, name: &str) -> PathBuf {
    let p = tmp_path(prefix, name);
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create tmp dir");
    p
}

/// Write `content` to a file inside `dir` and return its path.
#[allow(dead_code)]
pub fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, content).expect("write test file");
    p
}
