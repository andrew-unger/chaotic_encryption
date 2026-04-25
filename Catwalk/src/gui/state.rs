use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use super::entropy::EntropyPool;

// ── Small UI helpers shared across the gui module ────────────────────────────

/// Lossy `Path` → owned `String`.  Centralizes the `to_string_lossy().to_string()`
/// idiom that appears throughout the GUI for filling in path-text fields.
pub(super) fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Build a `rfd::FileDialog` pre-titled — a tiny convenience over the bare
/// `rfd::FileDialog::new().set_title(...)` pair used by every dialog opener.
pub(super) fn fd(title: &str) -> rfd::FileDialog {
    rfd::FileDialog::new().set_title(title)
}

// ── Recent files config ──────────────────────────────────────────────────────

const MAX_RECENT: usize = 5;

fn config_path() -> PathBuf {
    let mut p = dirs_fallback();
    p.push(".catwalk_recent.txt");
    p
}

fn dirs_fallback() -> PathBuf {
    // Use the user's home directory; fallback to current dir.
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn load_recent_files() -> Vec<String> {
    let path = config_path();
    fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect()
}

fn save_recent_files(recent: &[String]) {
    let path = config_path();
    let content = recent.join("\n");
    if let Err(e) = fs::write(&path, content) {
        eprintln!(
            "Warning: could not save recent files list to '{}': {}",
            path.display(),
            e
        );
    }
}

pub(super) fn add_to_recent(recent: &mut Vec<String>, path: &str) {
    if path.is_empty() {
        return;
    }
    recent.retain(|p| p != path);
    recent.insert(0, path.to_string());
    recent.truncate(MAX_RECENT);
    save_recent_files(recent);
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Archive,
    Info,
}

#[derive(Debug, Clone)]
pub struct BatchFileEntry {
    pub(super) path: PathBuf,
    pub(super) size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    Empty,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

pub enum WorkerMessage {
    Progress(f32),
    Complete(Result<String, String>),
    AllDone,
}

// ── Application State ─────────────────────────────────────────────────────────

pub struct CatwalkGui {
    pub(super) mode: Mode,

    // Single-file
    pub(super) input_path: String,
    pub(super) output_path: String,

    // Password
    pub(super) password: String,
    pub(super) confirm_password: String,
    pub(super) show_password: bool,

    // Options
    pub(super) strip_metadata: bool,
    pub(super) skip_compression: bool,
    pub(super) secure_delete: bool,

    // Batch / archive
    pub(super) batch_files: Vec<BatchFileEntry>,
    pub(super) batch_output_path: String,

    // Status / progress
    pub(super) status_message: String,
    pub(super) status_is_error: bool,
    pub(super) progress: f32,
    pub(super) processing: bool,
    pub(super) operation_start: Option<Instant>,

    // File info
    pub(super) file_info_text: String,

    // Worker thread
    pub(super) worker_rx: Option<mpsc::Receiver<WorkerMessage>>,

    // Recent files
    pub(super) recent_files: Vec<String>,

    // Pending secure-delete path (set after successful encrypt)
    pub(super) pending_secure_delete: Option<PathBuf>,

    // ── Keyfile support ──────────────────────────────────────────────────────
    /// Keyfile to use when encrypting or archiving (None = no keyfile).
    pub(super) encrypt_keyfile: Option<PathBuf>,
    /// Keyfile to use when decrypting (None = no keyfile).
    pub(super) decrypt_keyfile: Option<PathBuf>,

    // ── Entropy harvesting dialog ────────────────────────────────────────────
    pub(super) show_entropy_dialog: bool,
    pub(super) entropy_pool: EntropyPool,
    /// Frame counter — increments every frame while the dialog is open.
    pub(super) entropy_counter: u64,
}

impl CatwalkGui {
    /// Update the status line and the error flag together.  Replaces the
    /// recurring `self.status_message = …; self.status_is_error = …;` pair.
    pub(super) fn set_status(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status_message = msg.into();
        self.status_is_error = is_error;
    }
}

impl Default for CatwalkGui {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            strip_metadata: false,
            skip_compression: false,
            secure_delete: false,
            batch_files: Vec::new(),
            batch_output_path: String::new(),
            status_message: "Ready".into(),
            status_is_error: false,
            progress: 0.0,
            processing: false,
            operation_start: None,
            file_info_text: String::new(),
            worker_rx: None,
            recent_files: load_recent_files(),
            pending_secure_delete: None,
            encrypt_keyfile: None,
            decrypt_keyfile: None,
            show_entropy_dialog: false,
            entropy_pool: EntropyPool::new(),
            entropy_counter: 0,
        }
    }
}
