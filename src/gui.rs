use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;
use std::fs;

use eframe::egui;

extern crate au79_crypto;
use au79_crypto::crypto::{encrypt, decrypt};
use au79_crypto::error::CryptoError;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchFileStatus {
    Pending,
    Processing,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct BatchFileEntry {
    path: PathBuf,
    size: u64,
    status: BatchFileStatus,
    output_path: PathBuf,
    error: Option<String>,
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
    FileComplete { index: usize, result: Result<String, String> },
    BatchProgress { completed: usize, total: usize },
    AllDone,
}

// ── Application State ──────────────────────────────────────────────────────────

pub struct Au79Gui {
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
    batch_files: Vec<BatchFileEntry>,

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

impl Default for Au79Gui {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            batch_mode: false,
            batch_files: Vec::new(),
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

impl eframe::App for Au79Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.handle_dropped_files(ctx);

        self.render_top_panel(ctx);
        self.render_bottom_panel(ctx);
        self.render_central_panel(ctx);
    }
}

// ── Rendering ──────────────────────────────────────────────────────────────────

impl Au79Gui {
    fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("AU79").size(22.0).strong().color(GOLD));
                ui.label(egui::RichText::new("Crypto").size(22.0).color(GOLD_DIM));
                ui.add_space(20.0);

                ui.separator();
                ui.add_space(10.0);

                let enabled = !self.processing;
                ui.add_enabled_ui(enabled, |ui| {
                    ui.radio_value(&mut self.mode, Mode::Encrypt, "Encrypt");
                    ui.radio_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                    ui.radio_value(&mut self.mode, Mode::Info, "File Info");

                    if self.mode != Mode::Info {
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

            // Status message
            let color = if self.status_is_error {
                ERROR_RED
            } else if self.progress >= 1.0 {
                SUCCESS_GREEN
            } else {
                ui.visuals().text_color()
            };
            ui.label(egui::RichText::new(&self.status_message).color(color));

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
                    _ if self.batch_mode => self.render_batch_mode(ui),
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
                    egui::RichText::new(format!("Size: {}", format_file_size(meta.len())))
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
            }
            ui.label(
                egui::RichText::new(format!("{} file(s)", self.batch_files.len()))
                    .color(egui::Color32::GRAY),
            );
        });

        ui.add_space(6.0);

        // File table
        let available_height = (ui.available_height() - 200.0).max(100.0);
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
                            .num_columns(4)
                            .min_col_width(60.0)
                            .show(ui, |ui| {
                                // Header
                                ui.strong("File");
                                ui.strong("Size");
                                ui.strong("Status");
                                ui.strong("");
                                ui.end_row();

                                for (i, entry) in self.batch_files.iter().enumerate() {
                                    let name = entry
                                        .path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "???".into());
                                    ui.label(&name);
                                    ui.label(format_file_size(entry.size));

                                    let (text, color) = match &entry.status {
                                        BatchFileStatus::Pending => {
                                            ("Pending", egui::Color32::GRAY)
                                        }
                                        BatchFileStatus::Processing => {
                                            ("Processing...", egui::Color32::YELLOW)
                                        }
                                        BatchFileStatus::Complete => ("Done", SUCCESS_GREEN),
                                        BatchFileStatus::Failed => ("Failed", ERROR_RED),
                                    };
                                    ui.colored_label(color, text);

                                    if !self.processing {
                                        if ui.small_button("Remove").clicked() {
                                            remove_idx = Some(i);
                                        }
                                    } else {
                                        ui.label("");
                                    }
                                    ui.end_row();

                                    // Show error detail for failed files
                                    if let Some(err) = &entry.error {
                                        ui.label("");
                                        ui.label("");
                                        ui.colored_label(
                                            ERROR_RED,
                                            egui::RichText::new(err).small(),
                                        );
                                        ui.label("");
                                        ui.end_row();
                                    }
                                }
                            });
                        if let Some(idx) = remove_idx {
                            self.batch_files.remove(idx);
                        }
                    }
                });
        });

        ui.add_space(10.0);

        // Password
        self.render_password_fields(ui);

        ui.add_space(12.0);

        // Process button
        let label = match self.mode {
            Mode::Encrypt => format!("Encrypt {} File(s)", self.batch_files.len()),
            Mode::Decrypt => format!("Decrypt {} File(s)", self.batch_files.len()),
            Mode::Info => "Show Info".into(),
        };
        let can_go = self.can_process();
        let btn = egui::Button::new(egui::RichText::new(&label).strong().size(16.0))
            .min_size(egui::vec2(200.0, 36.0));
        if ui.add_enabled(can_go, btn).clicked() {
            self.start_batch_operation(ui.ctx().clone());
        }
    }

    // ── Info Mode ──────────────────────────────────────────────────────────────

    fn render_info_mode(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Select an AU79 encrypted file").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.input_path)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("Select .au79 file..."),
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
                        egui::RichText::new("AU79 File Information")
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
        }
    }

    // ── Drag and Drop ──────────────────────────────────────────────────────────

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        if self.batch_mode && self.mode != Mode::Info {
            for file in &dropped {
                if let Some(path) = &file.path {
                    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    let output_path = self.compute_output_path(path);
                    self.batch_files.push(BatchFileEntry {
                        path: path.clone(),
                        size,
                        status: BatchFileStatus::Pending,
                        output_path,
                        error: None,
                    });
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
            .add_filter("AU79 Encrypted", &["au79"]);
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
        let mut dialog = rfd::FileDialog::new().set_title("Select Files");
        if self.mode == Mode::Decrypt {
            dialog = dialog.add_filter("AU79 Encrypted", &["au79"]);
        }
        dialog = dialog.add_filter("All Files", &["*"]);
        if let Some(paths) = dialog.pick_files() {
            for path in paths {
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let output_path = self.compute_output_path(&path);
                self.batch_files.push(BatchFileEntry {
                    path,
                    size,
                    status: BatchFileStatus::Pending,
                    output_path,
                    error: None,
                });
            }
        }
    }

    // ── Auto-Detect Mode ─────────────────────────────────────────────────────

    fn auto_detect_mode(&mut self, path: &Path) {
        let is_au79 = path.extension().map(|e| e == "au79").unwrap_or(false)
            || fs::read(path)
                .ok()
                .map(|d| d.len() >= 4 && &d[..4] == b"AU79")
                .unwrap_or(false);

        if is_au79 {
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
                name.push_str(".au79");
                out.set_file_name(name);
            }
            Mode::Decrypt => {
                if out.extension().map(|e| e == "au79").unwrap_or(false) {
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
                    !self.batch_files.is_empty()
                } else {
                    !self.input_path.is_empty() && !self.output_path.is_empty()
                };
                has_files
                    && !self.password.is_empty()
                    && self.password == self.confirm_password
            }
            Mode::Decrypt => {
                let has_files = if self.batch_mode {
                    !self.batch_files.is_empty()
                } else {
                    !self.input_path.is_empty() && !self.output_path.is_empty()
                };
                has_files && !self.password.is_empty()
            }
        }
    }

    // ── Background Operations ──────────────────────────────────────────────────

    fn start_single_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.05;
        self.status_message = "Processing...".into();
        self.status_is_error = false;
        self.file_info_text.clear();
        self.operation_start = Some(Instant::now());

        let mode = self.mode;
        let input_path = PathBuf::from(&self.input_path);
        let output_path = PathBuf::from(&self.output_path);
        let password = self.password.clone();

        std::thread::spawn(move || {
            let result = match mode {
                Mode::Encrypt => encrypt_file(&input_path, &output_path, &password),
                Mode::Decrypt => decrypt_file(&input_path, &output_path, &password),
                Mode::Info => show_file_info(&input_path),
            };
            let _ = tx.send(WorkerMessage::FileComplete { index: 0, result });
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
        });
    }

    fn start_batch_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.status_message = "Processing batch...".into();
        self.status_is_error = false;
        self.operation_start = Some(Instant::now());

        for entry in &mut self.batch_files {
            if entry.status != BatchFileStatus::Complete {
                entry.status = BatchFileStatus::Processing;
                entry.error = None;
            }
        }

        let files: Vec<(usize, PathBuf, PathBuf)> = self
            .batch_files
            .iter()
            .enumerate()
            .filter(|(_, e)| e.status == BatchFileStatus::Processing)
            .map(|(i, e)| (i, e.path.clone(), e.output_path.clone()))
            .collect();
        let total = files.len();
        let mode = self.mode;
        let password = self.password.clone();

        std::thread::spawn(move || {
            for (completed, (index, input, output)) in files.into_iter().enumerate() {
                let result = match mode {
                    Mode::Encrypt => encrypt_file(&input, &output, &password),
                    Mode::Decrypt => decrypt_file(&input, &output, &password),
                    Mode::Info => show_file_info(&input),
                };
                let _ = tx.send(WorkerMessage::FileComplete { index, result });
                let _ = tx.send(WorkerMessage::BatchProgress {
                    completed: completed + 1,
                    total,
                });
                ctx.request_repaint();
            }
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
        });
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.worker_rx else { return };

        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMessage::FileComplete { index, result } => match result {
                    Ok(msg) => {
                        if self.batch_mode {
                            if let Some(entry) = self.batch_files.get_mut(index) {
                                entry.status = BatchFileStatus::Complete;
                            }
                        }
                        self.status_message = msg;
                        self.status_is_error = false;
                    }
                    Err(err) => {
                        if self.batch_mode {
                            if let Some(entry) = self.batch_files.get_mut(index) {
                                entry.status = BatchFileStatus::Failed;
                                entry.error = Some(err.clone());
                            }
                        }
                        self.status_message = err;
                        self.status_is_error = true;
                    }
                },
                WorkerMessage::BatchProgress { completed, total } => {
                    self.progress = completed as f32 / total as f32;
                }
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

// ── Crypto Helpers (framework-independent) ─────────────────────────────────────

fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let result = encrypt(&data, password, &input_path.to_string_lossy())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    fs::write(output_path, result).map_err(|e| format!("Failed to write output: {}", e))?;
    Ok(format!(
        "Encrypted successfully: {}",
        output_path.to_string_lossy()
    ))
}

fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let (result, extension) = decrypt(&data, password).map_err(|e| match e {
        CryptoError::IntegrityCheckFailed => {
            "Wrong password or file is corrupted.".to_string()
        }
        _ => format!("Decryption failed: {}", e),
    })?;

    let mut final_output = output_path.to_path_buf();
    if !extension.is_empty() {
        final_output.set_extension(&extension);
    }

    fs::write(&final_output, result)
        .map_err(|e| format!("Failed to write output: {}", e))?;
    Ok(format!(
        "Decrypted successfully: {}",
        final_output.to_string_lossy()
    ))
}

fn show_file_info(input_path: &Path) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read file: {}", e))?;

    if data.len() < 4 || &data[0..4] != b"AU79" {
        return Err("Not a valid AU79 encrypted file.".into());
    }

    let version = data[4];
    let flags = data[5];
    let ts_start = 6 + 16; // SALT_LEN
    if data.len() < ts_start + 8 + 12 + 8 + 1 {
        return Err("File too short to parse header.".into());
    }
    let timestamp =
        u64::from_le_bytes(data[ts_start..ts_start + 8].try_into().unwrap());
    let tent_seed = f64::from_le_bytes(
        data[ts_start + 8 + 12..ts_start + 8 + 12 + 8]
            .try_into()
            .unwrap(),
    );
    let ext_len = data[ts_start + 8 + 12 + 8] as usize;
    let ext_start = ts_start + 8 + 12 + 8 + 1;
    let extension = if data.len() >= ext_start + ext_len {
        String::from_utf8_lossy(&data[ext_start..ext_start + ext_len]).to_string()
    } else {
        "???".into()
    };

    let total_size = format_file_size(data.len() as u64);

    Ok(format!(
        "Magic:              AU79\n\
         Version:            {}\n\
         Flags:              {}\n\
         Timestamp:          {}\n\
         Tent Map Seed:      {:.6}\n\
         Original Extension: .{}\n\
         File Size:          {}",
        version, flags, timestamp, tent_seed, extension, total_size
    ))
}

// ── Utility Functions ──────────────────────────────────────────────────────────

fn format_file_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{} B", bytes)
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.2} MB", b / MB)
    } else {
        format!("{:.2} GB", b / GB)
    }
}

fn evaluate_password_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::Empty;
    }
    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let variety = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if len < 6 {
        PasswordStrength::Weak
    } else if len < 10 {
        if variety >= 3 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Fair
        }
    } else if variety >= 3 {
        PasswordStrength::VeryStrong
    } else {
        PasswordStrength::Strong
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
        "AU79-Crypto",
        options,
        Box::new(|cc| {
            // Dark theme
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(Au79Gui::default()))
        }),
    )
    .map_err(|e| format!("Error running GUI: {}", e))
}
