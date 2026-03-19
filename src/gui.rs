use std::io::{Cursor, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;
use std::fs;

use eframe::egui;
use zeroize::Zeroize;
use zip::write::SimpleFileOptions;

extern crate catwalk;
use catwalk::crypto::{encrypt, decrypt, validate_password, EncryptOptions, ProgressFn};
use catwalk::error::CryptoError;
use catwalk::utils::{parse_file_info, format_byte_size};

const ARCHIVE_EXTENSION: &str = "catwalkarchive";

// ── Constants ──────────────────────────────────────────────────────────────────

const GOLD: egui::Color32 = egui::Color32::from_rgb(255, 195, 0);
const GOLD_DIM: egui::Color32 = egui::Color32::from_rgb(180, 140, 20);
const SUCCESS_GREEN: egui::Color32 = egui::Color32::from_rgb(100, 220, 100);
const ERROR_RED: egui::Color32 = egui::Color32::from_rgb(240, 80, 80);

// ── Types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Info,
}

#[derive(Debug, Clone)]
pub struct BatchFileEntry {
    path: PathBuf,
    size: u64,
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

// ── Application State ──────────────────────────────────────────────────────────

pub struct CatwalkGui {
    mode: Mode,

    // Single-file
    input_path: String,
    output_path: String,

    // Password
    password: String,
    confirm_password: String,
    show_password: bool,

    // Batch mode
    batch_mode: bool,
    strip_metadata: bool,
    skip_compression: bool,
    batch_files: Vec<BatchFileEntry>,
    batch_output_path: String,

    // Status / progress
    status_message: String,
    status_is_error: bool,
    progress: f32,
    processing: bool,
    operation_start: Option<Instant>,

    // File info
    file_info_text: String,

    // Worker thread
    worker_rx: Option<mpsc::Receiver<WorkerMessage>>,
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
            batch_mode: false,
            strip_metadata: false,
            skip_compression: false,
            batch_files: Vec::new(),
            batch_output_path: String::new(),
            status_message: "Ready".into(),
            status_is_error: false,
            progress: 0.0,
            processing: false,
            operation_start: None,
            file_info_text: String::new(),
            worker_rx: None,
        }
    }
}

// ── eframe::App ────────────────────────────────────────────────────────────────

impl eframe::App for CatwalkGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.handle_dropped_files(ctx);

        self.render_top_panel(ctx);
        self.render_bottom_panel(ctx);
        self.render_central_panel(ctx);
    }
}

// ── Rendering ──────────────────────────────────────────────────────────────────

impl CatwalkGui {
    fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("CATWALK").size(22.0).strong().color(GOLD));
                ui.label(egui::RichText::new("Crypto").size(22.0).color(GOLD_DIM));
                ui.add_space(20.0);

                ui.separator();
                ui.add_space(10.0);

                let enabled = !self.processing;
                ui.add_enabled_ui(enabled, |ui| {
                    ui.radio_value(&mut self.mode, Mode::Encrypt, "Encrypt");
                    ui.radio_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                    ui.radio_value(&mut self.mode, Mode::Info, "File Info");

                    if self.mode == Mode::Encrypt {
                        ui.separator();
                        ui.checkbox(&mut self.batch_mode, "Batch Mode");
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn render_bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(6.0);

            // Status message (scrollable to handle long error messages)
            let color = if self.status_is_error {
                ERROR_RED
            } else if self.progress >= 1.0 {
                SUCCESS_GREEN
            } else {
                ui.visuals().text_color()
            };
            egui::ScrollArea::vertical()
                .id_salt("status_scroll")
                .max_height(40.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&self.status_message).color(color));
                });

            // Progress bar
            ui.add(
                egui::ProgressBar::new(self.progress)
                    .show_percentage()
                    .animate(self.processing),
            );

            // Elapsed time
            if let Some(start) = self.operation_start {
                let elapsed = start.elapsed();
                ui.label(
                    egui::RichText::new(format!("Elapsed: {:.1}s", elapsed.as_secs_f64()))
                        .small()
                        .color(egui::Color32::GRAY),
                );
            }

            ui.add_space(4.0);
        });
    }

    fn render_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Drag-and-drop overlay
            if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
                let painter = ui.painter();
                let rect = ui.max_rect();
                painter.rect_filled(rect, 8.0, egui::Color32::from_black_alpha(180));
                let text = if self.batch_mode {
                    "Drop files to add to batch"
                } else {
                    "Drop file to set as input"
                };
                painter.text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    text,
                    egui::FontId::proportional(24.0),
                    GOLD,
                );
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.mode {
                    Mode::Info => self.render_info_mode(ui),
                    Mode::Encrypt if self.batch_mode => self.render_batch_mode(ui),
                    _ => self.render_single_mode(ui),
                }
            });
        });
    }

    // ── Single File Mode ───────────────────────────────────────────────────────

    fn render_single_mode(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);

        // Input file
        ui.label(egui::RichText::new("Input File").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.input_path)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("Select a file..."),
            );
            if ui.button("Browse").clicked() {
                self.browse_input();
            }
        });
        if !self.input_path.is_empty() {
            if let Ok(meta) = fs::metadata(&self.input_path) {
                ui.label(
                    egui::RichText::new(format!("Size: {}", format_byte_size(meta.len())))
                        .small()
                        .color(egui::Color32::GRAY),
                );
            }
        }

        ui.add_space(10.0);

        // Output file
        ui.label(egui::RichText::new("Output File").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.output_path)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("Output location..."),
            );
            if ui.button("Browse").clicked() {
                self.browse_output();
            }
        });

        ui.add_space(10.0);

        // Password
        self.render_password_fields(ui);

        ui.add_space(16.0);

        // Action button
        let button_label = match self.mode {
            Mode::Encrypt => "Encrypt File",
            Mode::Decrypt => "Decrypt File",
            Mode::Info => "Show Info",
        };
        let can_go = self.can_process();
        ui.horizontal(|ui| {
            let btn = egui::Button::new(
                egui::RichText::new(button_label).strong().size(16.0),
            )
            .min_size(egui::vec2(160.0, 36.0));

            if ui.add_enabled(can_go, btn).clicked() {
                self.start_single_operation(ui.ctx().clone());
            }
        });
    }

    // ── Batch Mode ─────────────────────────────────────────────────────────────

    fn render_batch_mode(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);

        // Toolbar
        ui.horizontal(|ui| {
            if ui.button("Add Files").clicked() {
                self.browse_batch_files();
            }
            if ui.button("Clear All").clicked() && !self.processing {
                self.batch_files.clear();
                self.batch_output_path.clear();
            }

            let total_size: u64 = self.batch_files.iter().map(|e| e.size).sum();
            ui.label(
                egui::RichText::new(format!(
                    "{} file(s)  ({})",
                    self.batch_files.len(),
                    format_byte_size(total_size)
                ))
                .color(egui::Color32::GRAY),
            );
        });

        ui.add_space(6.0);

        // File list
        let available_height = (ui.available_height() - 240.0).max(80.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(available_height)
                .show(ui, |ui| {
                    if self.batch_files.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);
                            ui.label(
                                egui::RichText::new("Drag files here or click Add Files")
                                    .color(egui::Color32::GRAY)
                                    .size(16.0),
                            );
                            ui.add_space(30.0);
                        });
                    } else {
                        let mut remove_idx: Option<usize> = None;
                        egui::Grid::new("batch_grid")
                            .striped(true)
                            .num_columns(3)
                            .min_col_width(60.0)
                            .show(ui, |ui| {
                                ui.strong("File");
                                ui.strong("Size");
                                ui.strong("");
                                ui.end_row();

                                for (i, entry) in self.batch_files.iter().enumerate() {
                                    let name = entry
                                        .path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "???".into());
                                    ui.label(&name);
                                    ui.label(format_byte_size(entry.size));
                                    if !self.processing {
                                        if ui.small_button("Remove").clicked() {
                                            remove_idx = Some(i);
                                        }
                                    } else {
                                        ui.label("");
                                    }
                                    ui.end_row();
                                }
                            });
                        if let Some(idx) = remove_idx {
                            self.batch_files.remove(idx);
                        }
                    }
                });
        });

        ui.add_space(10.0);

        // Output archive path
        ui.label(egui::RichText::new("Output Archive").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.batch_output_path)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text(format!("Output .{} file...", ARCHIVE_EXTENSION)),
            );
            if ui.button("Browse").clicked() {
                let dialog = rfd::FileDialog::new()
                    .set_title("Save Encrypted Archive")
                    .add_filter("CATWALK Archive", &[ARCHIVE_EXTENSION]);
                if let Some(path) = dialog.save_file() {
                    self.batch_output_path = path.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(10.0);

        // Password
        self.render_password_fields(ui);

        ui.add_space(12.0);

        // Process button
        let label = format!("Encrypt {} File(s) as Archive", self.batch_files.len());
        let can_go = self.can_process();
        let btn = egui::Button::new(egui::RichText::new(&label).strong().size(16.0))
            .min_size(egui::vec2(240.0, 36.0));
        if ui.add_enabled(can_go, btn).clicked() {
            self.start_batch_operation(ui.ctx().clone());
        }
    }

    // ── Info Mode ──────────────────────────────────────────────────────────────

    fn render_info_mode(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Select a CATWALK encrypted file").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.input_path)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("Select .catwalk file..."),
            );
            if ui.button("Browse").clicked() {
                self.browse_input();
            }
        });

        ui.add_space(12.0);

        let can_go = !self.input_path.is_empty() && !self.processing;
        let btn = egui::Button::new(egui::RichText::new("Show File Info").strong())
            .min_size(egui::vec2(140.0, 32.0));
        if ui.add_enabled(can_go, btn).clicked() {
            match show_file_info(&PathBuf::from(&self.input_path)) {
                Ok(info) => {
                    self.file_info_text = info;
                    self.status_message = "File info retrieved.".into();
                    self.status_is_error = false;
                    self.progress = 1.0;
                }
                Err(e) => {
                    self.file_info_text.clear();
                    self.status_message = format!("Error: {}", e);
                    self.status_is_error = true;
                    self.progress = 0.0;
                }
            }
        }

        if !self.file_info_text.is_empty() {
            ui.add_space(16.0);
            egui::Frame::group(ui.style())
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("CATWALK File Information")
                            .strong()
                            .size(16.0)
                            .color(GOLD),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(&self.file_info_text)
                            .monospace(),
                    );
                });
        }
    }

    // ── Shared: Password Fields ────────────────────────────────────────────────

    fn render_password_fields(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Password").strong());
        ui.horizontal(|ui| {
            let mut edit = egui::TextEdit::singleline(&mut self.password)
                .desired_width(ui.available_width() - 80.0)
                .hint_text("Enter password...");
            if !self.show_password {
                edit = edit.password(true);
            }
            ui.add(edit);

            let toggle_label = if self.show_password { "Hide" } else { "Show" };
            if ui.button(toggle_label).clicked() {
                self.show_password = !self.show_password;
            }
        });

        // Password strength
        let strength = evaluate_password_strength(&self.password);
        if strength != PasswordStrength::Empty {
            render_password_strength(ui, strength);
            if let Err(reason) = validate_password(&self.password) {
                ui.colored_label(ERROR_RED, egui::RichText::new(reason).small());
            }
        }

        // Confirm password (encrypt only)
        if self.mode == Mode::Encrypt {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Confirm Password").strong());
            let mut edit = egui::TextEdit::singleline(&mut self.confirm_password)
                .desired_width(ui.available_width())
                .hint_text("Confirm password...");
            if !self.show_password {
                edit = edit.password(true);
            }
            ui.add(edit);

            if !self.password.is_empty() && !self.confirm_password.is_empty() {
                if self.password == self.confirm_password {
                    ui.colored_label(SUCCESS_GREEN, "Passwords match");
                } else {
                    ui.colored_label(ERROR_RED, "Passwords do not match");
                }
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Privacy Options").strong());
            ui.checkbox(&mut self.strip_metadata, "Strip Metadata (no timestamp/extension)");
            ui.checkbox(&mut self.skip_compression, "Skip Compression (no pattern fingerprinting)");
        }
    }

    // ── Drag and Drop ──────────────────────────────────────────────────────────

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        if self.batch_mode && self.mode == Mode::Encrypt {
            for file in &dropped {
                if let Some(path) = &file.path {
                    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    self.batch_files.push(BatchFileEntry {
                        path: path.clone(),
                        size,
                    });
                    if self.batch_output_path.is_empty() {
                        if let Some(dir) = path.parent() {
                            self.batch_output_path =
                                dir.join(format!("archive.{}", ARCHIVE_EXTENSION)).to_string_lossy().to_string();
                        }
                    }
                }
            }
        } else if let Some(first) = dropped.first() {
            if let Some(path) = &first.path {
                self.auto_detect_mode(path);
                self.input_path = path.to_string_lossy().to_string();
                self.output_path = self
                    .compute_output_path(path)
                    .to_string_lossy()
                    .to_string();
            }
        }
    }

    // ── File Browsing ──────────────────────────────────────────────────────────

    fn browse_input(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_title("Select Input File")
            .add_filter("All Files", &["*"])
            .add_filter("CATWALK Encrypted", &["catwalk"]);
        if let Some(path) = dialog.pick_file() {
            self.auto_detect_mode(&path);
            self.input_path = path.to_string_lossy().to_string();
            self.output_path = self
                .compute_output_path(&path)
                .to_string_lossy()
                .to_string();
        }
    }

    fn browse_output(&mut self) {
        let dialog = rfd::FileDialog::new().set_title("Select Output File");
        if let Some(path) = dialog.save_file() {
            self.output_path = path.to_string_lossy().to_string();
        }
    }

    fn browse_batch_files(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_title("Select Files")
            .add_filter("All Files", &["*"]);
        if let Some(paths) = dialog.pick_files() {
            for path in paths {
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if self.batch_output_path.is_empty() {
                    if let Some(dir) = path.parent() {
                        self.batch_output_path =
                            dir.join(format!("archive.{}", ARCHIVE_EXTENSION)).to_string_lossy().to_string();
                    }
                }
                self.batch_files.push(BatchFileEntry {
                    path,
                    size,
                });
            }
        }
    }

    // ── Auto-Detect Mode ─────────────────────────────────────────────────────

    fn auto_detect_mode(&mut self, path: &Path) {
        let is_eddy = path.extension().map(|e| e == "catwalk").unwrap_or(false)
            || fs::read(path)
                .ok()
                .map(|d| d.len() >= 4 && &d[..4] == b"CATW")
                .unwrap_or(false);

        if is_eddy {
            self.mode = Mode::Decrypt;
        } else {
            self.mode = Mode::Encrypt;
        }
    }

    // ── Path Helpers ───────────────────────────────────────────────────────────

    fn compute_output_path(&self, input: &Path) -> PathBuf {
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
            Mode::Info => {}
        }
        out
    }

    // ── Validation ─────────────────────────────────────────────────────────────

    fn can_process(&self) -> bool {
        if self.processing {
            return false;
        }

        match self.mode {
            Mode::Info => !self.input_path.is_empty(),
            Mode::Encrypt => {
                let has_files = if self.batch_mode {
                    !self.batch_files.is_empty() && !self.batch_output_path.is_empty()
                } else {
                    !self.input_path.is_empty() && !self.output_path.is_empty()
                };
                has_files
                    && validate_password(&self.password).is_ok()
                    && self.password == self.confirm_password
            }
            Mode::Decrypt => {
                !self.input_path.is_empty()
                    && !self.output_path.is_empty()
                    && !self.password.is_empty()
            }
        }
    }

    // ── Background Operations ──────────────────────────────────────────────────

    fn start_single_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.status_message = "Processing...".into();
        self.status_is_error = false;
        self.file_info_text.clear();
        self.operation_start = Some(Instant::now());

        let mode = self.mode;
        let input_path = PathBuf::from(&self.input_path);
        let output_path = PathBuf::from(&self.output_path);
        let password = self.password.clone();
        let options = EncryptOptions {
            strip_metadata: self.strip_metadata,
            skip_compression: self.skip_compression,
        };

        let progress_tx = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = match mode {
                Mode::Encrypt => encrypt_file(&input_path, &output_path, &password, &options, Some(&progress_cb)),
                Mode::Decrypt => decrypt_file(&input_path, &output_path, &password, Some(&progress_cb)),
                Mode::Info => show_file_info(&input_path),
            };
            let _ = tx.send(WorkerMessage::Complete(result));
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
        });
    }

    fn start_batch_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.status_message = "Creating archive...".into();
        self.status_is_error = false;
        self.operation_start = Some(Instant::now());

        let files: Vec<PathBuf> = self.batch_files.iter().map(|e| e.path.clone()).collect();
        let output_path = PathBuf::from(&self.batch_output_path);
        let password = self.password.clone();
        let options = EncryptOptions {
            strip_metadata: self.strip_metadata,
            skip_compression: self.skip_compression,
        };

        let progress_tx = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = encrypt_archive(&files, &output_path, &password, &options, Some(&progress_cb));
            let _ = tx.send(WorkerMessage::Complete(result));
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
        });
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.worker_rx else { return };

        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMessage::Progress(v) => {
                    self.progress = v;
                }
                WorkerMessage::Complete(result) => match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.status_is_error = false;
                    }
                    Err(err) => {
                        self.status_message = err;
                        self.status_is_error = true;
                    }
                },
                WorkerMessage::AllDone => {
                    self.processing = false;
                    if !self.status_is_error {
                        self.progress = 1.0;
                    }
                    self.worker_rx = None;
                    return;
                }
            }
        }
    }
}

impl Drop for CatwalkGui {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
    }
}

// ── Crypto Helpers (framework-independent) ─────────────────────────────────────

fn encrypt_file(input_path: &Path, output_path: &Path, password: &str, options: &EncryptOptions, progress: Option<&ProgressFn>) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let result = encrypt(&data, password, &input_path.to_string_lossy(), options, progress)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    if let Some(cb) = &progress { cb(0.90); }
    fs::write(output_path, &result).map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress { cb(1.0); }
    Ok(format!(
        "Encrypted successfully: {}",
        output_path.to_string_lossy()
    ))
}

fn decrypt_file(input_path: &Path, output_path: &Path, password: &str, progress: Option<&ProgressFn>) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let (result, extension) = decrypt(&data, password, progress).map_err(|e| match e {
        CryptoError::IntegrityCheckFailed => {
            "Wrong password or file is corrupted.".to_string()
        }
        _ => format!("Decryption failed: {}", e),
    })?;

    // Archive: extract zip contents to a directory
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

    if let Some(cb) = &progress { cb(0.90); }
    fs::write(&final_output, result)
        .map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress { cb(1.0); }
    Ok(format!(
        "Decrypted successfully: {}",
        final_output.to_string_lossy()
    ))
}

fn encrypt_archive(files: &[PathBuf], output_path: &Path, password: &str, options: &EncryptOptions, progress: Option<&ProgressFn>) -> Result<String, String> {
    let archive = create_archive(files)?;
    let filename = format!("archive.{}", ARCHIVE_EXTENSION);
    let result = encrypt(&archive, password, &filename, options, progress)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    if let Some(cb) = &progress { cb(0.90); }
    fs::write(output_path, &result)
        .map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress { cb(1.0); }
    Ok(format!(
        "Encrypted {} file(s) into {}",
        files.len(),
        output_path.to_string_lossy()
    ))
}

fn create_archive(files: &[PathBuf]) -> Result<Vec<u8>, String> {
    let buf = Vec::new();
    let mut zip = zip::ZipWriter::new(Cursor::new(buf));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        zip.start_file(&name, options)
            .map_err(|e| format!("Failed to add {}: {}", name, e))?;
        let data = fs::read(path)
            .map_err(|e| format!("Failed to read {}: {}", name, e))?;
        zip.write_all(&data)
            .map_err(|e| format!("Failed to write {}: {}", name, e))?;
    }

    let cursor = zip.finish().map_err(|e| format!("Failed to finalize archive: {}", e))?;
    Ok(cursor.into_inner())
}

fn extract_archive(data: &[u8], output_dir: &Path) -> Result<usize, String> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| format!("Failed to open archive: {}", e))?;

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create directory: {}", e))?;

    let count = archive.len();
    for i in 0..count {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Archive error: {}", e))?;
        let raw_name = file.name().to_string();
        // Sanitize: strip all path components, keep only the filename.
        // This prevents path traversal (../../etc/passwd) and absolute paths.
        let safe_name = Path::new(&raw_name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if safe_name.is_empty() || safe_name.contains("..") {
            continue;
        }
        let out_path = output_dir.join(&safe_name);
        let mut out_file = fs::File::create(&out_path)
            .map_err(|e| format!("Failed to create {}: {}", safe_name, e))?;
        std::io::copy(&mut file, &mut out_file)
            .map_err(|e| format!("Failed to extract {}: {}", safe_name, e))?;
    }

    Ok(count)
}

fn show_file_info(input_path: &Path) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let info = parse_file_info(&data).map_err(|e| format!("{}", e))?;
    Ok(format!("{}", info))
}

// ── Utility Functions ──────────────────────────────────────────────────────────

fn evaluate_password_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::Empty;
    }
    if validate_password(password).is_err() {
        return PasswordStrength::Weak;
    }
    let len = password.len();
    if len < 24 {
        PasswordStrength::Fair
    } else if len < 32 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::VeryStrong
    }
}

fn render_password_strength(ui: &mut egui::Ui, strength: PasswordStrength) {
    let (ratio, color, label) = match strength {
        PasswordStrength::Empty => return,
        PasswordStrength::Weak => (0.25, ERROR_RED, "Weak"),
        PasswordStrength::Fair => (0.5, egui::Color32::YELLOW, "Fair"),
        PasswordStrength::Strong => (0.75, egui::Color32::LIGHT_GREEN, "Strong"),
        PasswordStrength::VeryStrong => (1.0, SUCCESS_GREEN, "Very Strong"),
    };
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Strength:")
                .small()
                .color(egui::Color32::GRAY),
        );
        ui.add(
            egui::ProgressBar::new(ratio)
                .desired_width(100.0)
                .fill(color),
        );
        ui.colored_label(color, egui::RichText::new(label).small());
    });
}

// ── Entry Point ────────────────────────────────────────────────────────────────

pub fn run_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 550.0])
            .with_min_inner_size([500.0, 400.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "CATWALK",
        options,
        Box::new(|cc| {
            // Dark theme
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(CatwalkGui::default()))
        }),
    )
    .map_err(|e| format!("Error running GUI: {}", e))
}
