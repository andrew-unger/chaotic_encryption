use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use eframe::egui;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use catwalk::archive::ARCHIVE_EXTENSION;
use catwalk::crypto::constants::{FLAGS_OFFSET, FLAG_KEYFILE};
use catwalk::crypto::{decrypt, encrypt, validate_password, EncryptOptions, ProgressFn};
use catwalk::error::CryptoError;
use catwalk::utils::parse_file_info;

use super::state::{
    add_to_recent, fd, path_to_string, BatchFileEntry, CatwalkGui, Mode, WorkerMessage,
};

impl CatwalkGui {
    // ── Keyfile helpers ──────────────────────────────────────────────────────

    /// Read the flags byte from the selected input file header and return true
    /// if FLAG_KEYFILE is set.  Returns false on any read or parse error.
    pub(super) fn detect_keyfile_flag(&self) -> bool {
        if self.input_path.is_empty() {
            return false;
        }
        let path = PathBuf::from(&self.input_path);
        let mut f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        // Read just enough to reach the flags byte.
        // Header layout: MAGIC(4) + VERSION(1) + FLAGS(1)  → need 6 bytes.
        let mut buf = [0u8; FLAGS_OFFSET + 1]; // = [0u8; 6]
        if f.read_exact(&mut buf).is_err() {
            return false;
        }
        if &buf[..4] != b"CATW" {
            return false;
        }
        (buf[FLAGS_OFFSET] & FLAG_KEYFILE) != 0
    }

    // ── File Browsing ───────────────────────────────────────────────────────────

    pub(super) fn browse_input(&mut self) {
        let dialog = fd("Select Input File")
            .add_filter("All Files", &["*"])
            .add_filter("CATWALK Encrypted", &["catwalk"]);
        if let Some(path) = dialog.pick_file() {
            self.auto_detect_mode(&path);
            self.input_path = path_to_string(&path);
            self.output_path = path_to_string(&self.compute_output_path(&path));
        }
    }

    pub(super) fn browse_output(&mut self) {
        if let Some(path) = fd("Select Output File").save_file() {
            self.output_path = path_to_string(&path);
        }
    }

    pub(super) fn browse_batch_files(&mut self) {
        let dialog = fd("Select Files").add_filter("All Files", &["*"]);
        if let Some(paths) = dialog.pick_files() {
            for path in paths {
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if self.batch_output_path.is_empty() {
                    if let Some(dir) = path.parent() {
                        self.batch_output_path =
                            path_to_string(&dir.join(format!("archive.{}", ARCHIVE_EXTENSION)));
                    }
                }
                self.batch_files.push(BatchFileEntry { path, size });
            }
        }
    }

    pub(super) fn browse_batch_folder(&mut self) {
        if let Some(dir) = fd("Select Folder to Archive").pick_folder() {
            self.add_folder_contents(&dir);
            if self.batch_output_path.is_empty() {
                self.batch_output_path =
                    path_to_string(&dir.join(format!("archive.{}", ARCHIVE_EXTENSION)));
            }
        }
    }

    pub(super) fn add_folder_contents(&mut self, dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    self.batch_files.push(BatchFileEntry { path, size });
                }
            }
        }
    }

    // ── Auto-Detect Mode ────────────────────────────────────────────────────────

    pub(super) fn auto_detect_mode(&mut self, path: &Path) {
        let is_catwalk = path.extension().map(|e| e == "catwalk").unwrap_or(false)
            || fs::read(path)
                .ok()
                .map(|d| d.len() >= 4 && &d[..4] == b"CATW")
                .unwrap_or(false);

        if is_catwalk {
            self.mode = Mode::Decrypt;
        } else {
            self.mode = Mode::Encrypt;
        }
    }

    // ── Path Helpers ────────────────────────────────────────────────────────────

    pub(super) fn compute_output_path(&self, input: &Path) -> PathBuf {
        let mut out = input.to_path_buf();
        match self.mode {
            Mode::Encrypt => {
                let mut name = input
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                name.push_str(".catwalk");
                out.set_file_name(name);
            }
            Mode::Decrypt => {
                if out.extension().map(|e| e == "catwalk").unwrap_or(false) {
                    out.set_extension("");
                }
            }
            Mode::Archive | Mode::Info => {}
        }
        out
    }

    // ── Validation ──────────────────────────────────────────────────────────────

    pub(super) fn can_process(&self) -> bool {
        if self.processing {
            return false;
        }

        match self.mode {
            Mode::Info => !self.input_path.is_empty(),
            Mode::Encrypt => {
                !self.input_path.is_empty()
                    && !self.output_path.is_empty()
                    && validate_password(&self.password).is_ok()
                    && bool::from(
                        self.password
                            .as_bytes()
                            .ct_eq(self.confirm_password.as_bytes()),
                    )
            }
            Mode::Archive => {
                !self.batch_files.is_empty()
                    && !self.batch_output_path.is_empty()
                    && validate_password(&self.password).is_ok()
                    && bool::from(
                        self.password
                            .as_bytes()
                            .ct_eq(self.confirm_password.as_bytes()),
                    )
            }
            Mode::Decrypt => {
                !self.input_path.is_empty()
                    && !self.output_path.is_empty()
                    && !self.password.is_empty()
            }
        }
    }

    // ── Background Operations ───────────────────────────────────────────────────

    pub(super) fn start_single_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.set_status("Processing...", false);
        self.file_info_text.clear();
        self.operation_start = Some(Instant::now());

        // Track input for recent files and secure delete
        let input_str = self.input_path.clone();
        let secure_delete = self.secure_delete && self.mode == Mode::Encrypt;
        let input_for_delete = if secure_delete {
            Some(PathBuf::from(&self.input_path))
        } else {
            None
        };

        let mode = self.mode;
        let input_path = PathBuf::from(&self.input_path);
        let output_path = PathBuf::from(&self.output_path);
        // Wrap the cloned password so it is zeroized when the worker thread's
        // closure is dropped (on normal completion, panic, or early return).
        let password = Zeroizing::new(self.password.clone());
        let options = EncryptOptions {
            strip_metadata: self.strip_metadata,
            skip_compression: self.skip_compression,
        };
        // Clone keyfile paths for the worker thread.
        let encrypt_keyfile = self.encrypt_keyfile.clone();
        let decrypt_keyfile = self.decrypt_keyfile.clone();

        // Add to recent files
        add_to_recent(&mut self.recent_files, &input_str);

        let progress_tx = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = match mode {
                Mode::Encrypt => encrypt_file(
                    &input_path,
                    &output_path,
                    password.as_str(),
                    &options,
                    encrypt_keyfile.as_deref(),
                    Some(&progress_cb),
                ),
                Mode::Decrypt => decrypt_file(
                    &input_path,
                    &output_path,
                    password.as_str(),
                    decrypt_keyfile.as_deref(),
                    Some(&progress_cb),
                ),
                Mode::Archive => unreachable!("Archive uses start_batch_operation"),
                Mode::Info => show_file_info(&input_path),
            };
            let _ = tx.send(WorkerMessage::Complete(result));
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
            // `password` (Zeroizing<String>) zeroes its heap allocation here
            // when the closure is dropped.
        });

        // Queue secure delete for after worker completes
        if let Some(path) = input_for_delete {
            // We'll handle this in poll_worker when AllDone arrives
            self.pending_secure_delete = Some(path);
        }
    }

    pub(super) fn start_batch_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.set_status("Creating archive...", false);
        self.operation_start = Some(Instant::now());

        let files: Vec<PathBuf> = self.batch_files.iter().map(|e| e.path.clone()).collect();
        let output_path = PathBuf::from(&self.batch_output_path);
        // Wrap the cloned password so it zeroizes when the worker thread's
        // closure is dropped.
        let password = Zeroizing::new(self.password.clone());
        let options = EncryptOptions {
            strip_metadata: self.strip_metadata,
            skip_compression: self.skip_compression,
        };
        let encrypt_keyfile = self.encrypt_keyfile.clone();

        let progress_tx = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = encrypt_archive(
                &files,
                &output_path,
                password.as_str(),
                &options,
                encrypt_keyfile.as_deref(),
                Some(&progress_cb),
            );
            let _ = tx.send(WorkerMessage::Complete(result));
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
            // `password` (Zeroizing<String>) zeroes its heap allocation here.
        });
    }

    pub(super) fn poll_worker(&mut self) {
        let Some(rx) = &self.worker_rx else { return };

        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMessage::Progress(v) => {
                    self.progress = v;
                }
                WorkerMessage::Complete(result) => match result {
                    // Direct field assigns rather than self.set_status() —
                    // the loop still holds an immutable borrow of
                    // self.worker_rx via `rx`, so taking &mut self here
                    // would conflict.
                    Ok(msg) => {
                        self.status_message = msg;
                        self.status_is_error = false;
                    }
                    Err(err) => {
                        self.status_message = err;
                        self.status_is_error = true;
                        // Cancel pending secure delete on failure
                        self.pending_secure_delete = None;
                    }
                },
                WorkerMessage::AllDone => {
                    self.processing = false;
                    if !self.status_is_error {
                        self.progress = 1.0;
                    } else {
                        // Don't secure-delete if the operation failed
                        self.pending_secure_delete = None;
                    }
                    self.worker_rx = None;
                    return;
                }
            }
        }
    }
}

// ── Crypto Helpers (framework-independent) ──────────────────────────────────

fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    options: &EncryptOptions,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let result = encrypt(
        &data,
        password,
        &input_path.to_string_lossy(),
        options,
        keyfile_path,
        progress,
    )
    .map_err(|e| format!("Encryption failed: {}", e))?;
    if let Some(cb) = &progress {
        cb(0.90);
    }
    fs::write(output_path, &result).map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress {
        cb(1.0);
    }
    Ok(format!(
        "Encrypted successfully: {}",
        output_path.to_string_lossy()
    ))
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let (result, extension) =
        decrypt(&data, password, keyfile_path, progress).map_err(|e| match e {
            CryptoError::IntegrityCheckFailed => {
                // Do NOT distinguish between wrong password and wrong keyfile.
                "Decryption failed: wrong password, wrong keyfile, or corrupted file.".to_string()
            }
            CryptoError::KeyfileRequired => {
                "This file was encrypted with a keyfile. Please select the keyfile and try again."
                    .to_string()
            }
            _ => format!("Decryption failed: {}", e),
        })?;

    if extension == ARCHIVE_EXTENSION {
        let extract_dir = output_path.with_extension("");
        let count = extract_archive(&result, &extract_dir)?;
        return Ok(format!(
            "Extracted {} file(s) to {}",
            count,
            extract_dir.to_string_lossy()
        ));
    }

    let mut final_output = output_path.to_path_buf();
    if !extension.is_empty() {
        final_output.set_extension(&extension);
    }

    if let Some(cb) = &progress {
        cb(0.90);
    }
    fs::write(&final_output, result).map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress {
        cb(1.0);
    }
    Ok(format!(
        "Decrypted successfully: {}",
        final_output.to_string_lossy()
    ))
}

fn encrypt_archive(
    files: &[PathBuf],
    output_path: &Path,
    password: &str,
    options: &EncryptOptions,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<String, String> {
    let archive = create_archive(files)?;
    let filename = format!("archive.{}", ARCHIVE_EXTENSION);
    let result = encrypt(
        &archive,
        password,
        &filename,
        options,
        keyfile_path,
        progress,
    )
    .map_err(|e| format!("Encryption failed: {}", e))?;
    if let Some(cb) = &progress {
        cb(0.90);
    }
    fs::write(output_path, &result).map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress {
        cb(1.0);
    }
    Ok(format!(
        "Encrypted {} file(s) into {}",
        files.len(),
        output_path.to_string_lossy()
    ))
}

fn create_archive(files: &[PathBuf]) -> Result<Vec<u8>, String> {
    catwalk::archive::create_archive(files).map_err(|e| e.to_string())
}

fn extract_archive(data: &[u8], output_dir: &Path) -> Result<usize, String> {
    catwalk::archive::extract_archive(data, output_dir).map_err(|e| e.to_string())
}

pub(super) fn show_file_info(input_path: &Path) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let info = parse_file_info(&data).map_err(|e| format!("{}", e))?;
    Ok(format!("{}", info))
}
