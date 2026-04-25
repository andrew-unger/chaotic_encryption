use std::collections::VecDeque;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use zeroize::Zeroize;

use super::state::CatwalkGui;

// ── Entropy Pool ──────────────────────────────────────────────────────────────
// Collects raw entropy from UI events (mouse movement, click timestamps,
// keyboard timing, frame jitter) and derives a 64-byte keyfile from the
// accumulated pool using BLAKE3-XOF for whitening.

pub struct EntropyPool {
    /// Raw entropy bytes accumulated from all sources.
    pool: Vec<u8>,
    /// Target: how many bytes we want before "done".
    target_bytes: usize,
    /// Track last mouse position for delta calculation.
    pub last_mouse: Option<egui::Pos2>,
    /// Visual history for the waveform display.
    history: VecDeque<f32>,
    history_max: usize,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    pub fn new() -> Self {
        Self {
            pool: Vec::new(),
            target_bytes: 64,
            last_mouse: None,
            history: VecDeque::with_capacity(256),
            history_max: 256,
        }
    }

    /// Absorb a single byte of entropy from any source.
    pub fn absorb(&mut self, byte: u8) {
        self.pool.push(byte);
        let val = byte as f32 / 255.0;
        if self.history.len() >= self.history_max {
            self.history.pop_front();
        }
        self.history.push_back(val);
    }

    /// Mix in an f32 value (mouse delta, position, etc.).
    pub fn absorb_f32(&mut self, val: f32) {
        let bits = val.to_bits();
        self.absorb(bits as u8);
        self.absorb((bits >> 8) as u8);
        self.absorb((bits >> 16) as u8);
        self.absorb((bits >> 24) as u8);
    }

    /// Mix in a u64 (timestamps, counters).
    pub fn absorb_u64(&mut self, val: u64) {
        for i in 0..8 {
            self.absorb((val >> (i * 8)) as u8);
        }
    }

    /// Fraction of required entropy collected (0.0 – 1.0).
    pub fn fullness(&self) -> f32 {
        (self.pool.len() as f32 / (self.target_bytes as f32 * 8.0)).min(1.0)
    }

    /// Returns true once enough raw bytes have been collected.
    pub fn is_ready(&self) -> bool {
        self.pool.len() >= self.target_bytes * 8
    }

    /// Derive the final 64-byte keyfile from the pool.
    /// Uses BLAKE3-XOF to compress and whiten all accumulated entropy.
    /// System time is mixed in so two pools with identical raw input (extremely
    /// unlikely) still produce different keyfiles.
    ///
    /// A 32-byte OS-randomness floor is also mixed in so that even in
    /// degenerate cases (scripted invocation with no user input, heartbeat
    /// counter dominating the pool) the derived keyfile retains full entropy
    /// from the kernel CSPRNG.
    pub fn derive_keyfile(&self) -> [u8; 64] {
        use rand::{rngs::OsRng, RngCore};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // OS-randomness floor: unconditional 32 bytes from the kernel CSPRNG.
        let mut os_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut os_entropy);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.pool);
        hasher.update(&now.to_le_bytes());
        hasher.update(&os_entropy);
        hasher.update(b"catwalk-keyfile-v1");
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);

        os_entropy.zeroize();
        output
    }

    pub fn history_iter(&self) -> impl Iterator<Item = f32> + '_ {
        self.history.iter().copied()
    }

    pub fn raw_byte_count(&self) -> usize {
        self.pool.len()
    }
}

// ── Entropy harvesting dialog ────────────────────────────────────────────────

impl CatwalkGui {
    pub(super) fn show_entropy_dialog_window(&mut self, ctx: &egui::Context) {
        // Clone flag so the borrow checker is happy while we pass &mut self inside.
        let mut open = self.show_entropy_dialog;
        egui::Window::new("Generate Keyfile")
            .collapsible(false)
            .resizable(true)
            .min_width(480.0)
            .open(&mut open)
            .show(ctx, |ui| {
                self.entropy_dialog_contents(ui, ctx);
            });
        self.show_entropy_dialog = open;
    }

    fn entropy_dialog_contents(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // ── Header ────────────────────────────────────────────────────────────
        ui.heading("Collect Randomness");
        ui.separator();
        if !self.entropy_pool.is_ready() {
            ui.label(
                "Move your mouse randomly in the area below. \
                 Click, type, and move erratically to generate a strong keyfile.",
            );
        } else {
            ui.colored_label(
                egui::Color32::from_rgb(100, 220, 100),
                "✓ Enough randomness collected. Save the keyfile to continue.",
            );
        }
        ui.add_space(8.0);

        // ── Progress bar ──────────────────────────────────────────────────────
        let progress = self.entropy_pool.fullness();
        let bar_color = if progress < 0.5 {
            egui::Color32::from_rgb(200, 100, 50)
        } else if progress < 1.0 {
            egui::Color32::from_rgb(200, 180, 50)
        } else {
            egui::Color32::from_rgb(80, 200, 80)
        };
        let progress_bar = egui::ProgressBar::new(progress)
            .text(format!(
                "{:.0}%  ({} raw bytes collected)",
                progress * 100.0,
                self.entropy_pool.raw_byte_count()
            ))
            .fill(bar_color);
        ui.add(progress_bar);
        ui.add_space(8.0);

        // ── Entropy canvas ────────────────────────────────────────────────────
        let desired_size = egui::vec2(ui.available_width(), 160.0);
        let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click_and_drag());

        // Canvas background
        ui.painter()
            .rect_filled(rect, 4.0, egui::Color32::from_rgb(20, 20, 30));

        // Canvas border — green when ready, dimmed otherwise
        let border_color = if self.entropy_pool.is_ready() {
            egui::Color32::from_rgb(80, 200, 80)
        } else {
            egui::Color32::from_rgb(80, 80, 120)
        };
        ui.painter().rect_stroke(
            rect,
            4.0,
            egui::Stroke::new(1.5, border_color),
            egui::StrokeKind::Outside,
        );

        // Entropy waveform
        let history: Vec<f32> = self.entropy_pool.history_iter().collect();
        if history.len() >= 2 {
            let n = history.len();
            let step = rect.width() / n as f32;
            let heat = self.entropy_pool.fullness();
            for i in 1..n {
                let x0 = rect.left() + (i - 1) as f32 * step;
                let x1 = rect.left() + i as f32 * step;
                let y0 = rect.bottom() - history[i - 1] * rect.height();
                let y1 = rect.bottom() - history[i] * rect.height();
                let color = egui::Color32::from_rgb(
                    (50.0 + heat * 150.0) as u8,
                    (150.0_f32 - heat * 50.0) as u8,
                    (200.0_f32 - heat * 150.0) as u8,
                );
                ui.painter().line_segment(
                    [egui::pos2(x0, y0), egui::pos2(x1, y1)],
                    egui::Stroke::new(1.5, color),
                );
            }
        }

        // Crosshair at mouse position
        if let Some(mp) = response.hover_pos() {
            let dim = egui::Color32::from_rgba_premultiplied(255, 255, 255, 60);
            ui.painter().line_segment(
                [
                    egui::pos2(mp.x, rect.top()),
                    egui::pos2(mp.x, rect.bottom()),
                ],
                egui::Stroke::new(1.0, dim),
            );
            ui.painter().line_segment(
                [
                    egui::pos2(rect.left(), mp.y),
                    egui::pos2(rect.right(), mp.y),
                ],
                egui::Stroke::new(1.0, dim),
            );
        }

        // "Move mouse here" hint when pool is not yet ready
        if !self.entropy_pool.is_ready() {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Move mouse here",
                egui::FontId::proportional(14.0),
                egui::Color32::from_rgba_premultiplied(180, 180, 180, 80),
            );
        }

        // ── Harvest entropy from this frame ───────────────────────────────────

        // Mouse movement inside the canvas
        if let Some(pos) = response.hover_pos() {
            if let Some(last) = self.entropy_pool.last_mouse {
                let dx = pos.x - last.x;
                let dy = pos.y - last.y;
                if dx.abs() > 0.1 || dy.abs() > 0.1 {
                    self.entropy_pool.absorb_f32(dx);
                    self.entropy_pool.absorb_f32(dy);
                    self.entropy_pool.absorb_f32(pos.x);
                    self.entropy_pool.absorb_f32(pos.y);
                }
            }
            self.entropy_pool.last_mouse = Some(pos);
        }

        // Mouse clicks
        if response.clicked() || response.secondary_clicked() {
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            self.entropy_pool.absorb_u64(ns);
        }

        // Keyboard timing anywhere in the dialog
        ctx.input(|input| {
            for event in &input.events {
                match event {
                    egui::Event::Key { .. } | egui::Event::Text(_) => {
                        let ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64;
                        self.entropy_pool.absorb_u64(ns);
                        self.entropy_pool.absorb_u64(self.entropy_counter);
                    }
                    _ => {}
                }
            }
        });

        // Heartbeat — frame timing jitter
        self.entropy_counter = self.entropy_counter.wrapping_add(1);
        self.entropy_pool.absorb_u64(self.entropy_counter);

        // Keep repainting while collecting so the waveform animates smoothly
        if !self.entropy_pool.is_ready() {
            ctx.request_repaint();
        }

        // ── Sources legend ────────────────────────────────────────────────────
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Collecting from:");
            let src_color = egui::Color32::from_rgb(100, 150, 220);
            ui.colored_label(src_color, "mouse");
            ui.label("•");
            ui.colored_label(src_color, "clicks");
            ui.label("•");
            ui.colored_label(src_color, "keyboard timing");
            ui.label("•");
            ui.colored_label(src_color, "frame jitter");
        });
        ui.add_space(8.0);
        ui.separator();

        // ── Save + Cancel buttons ─────────────────────────────────────────────
        ui.horizontal(|ui| {
            let save_enabled = self.entropy_pool.is_ready();
            if ui
                .add_enabled(save_enabled, egui::Button::new("Save Keyfile…"))
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Save Keyfile")
                    .set_file_name("catwalk.key")
                    .save_file()
                {
                    let keyfile_bytes = self.entropy_pool.derive_keyfile();
                    match fs::write(&path, keyfile_bytes) {
                        Ok(_) => {
                            self.encrypt_keyfile = Some(path.clone());
                            self.show_entropy_dialog = false;
                            self.status_message = format!(
                                "Keyfile saved: {}. It has been selected for encryption.",
                                path.display()
                            );
                            self.status_is_error = false;
                        }
                        Err(e) => {
                            self.status_message = format!("Failed to save keyfile: {}", e);
                            self.status_is_error = true;
                        }
                    }
                }
            }

            ui.add_space(8.0);
            if ui.button("Reset").clicked() {
                self.entropy_pool = EntropyPool::new();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Cancel").clicked() {
                    self.show_entropy_dialog = false;
                }
            });
        });

        ui.add_space(4.0);
        if self.entropy_pool.is_ready() {
            ui.colored_label(
                egui::Color32::from_rgb(220, 180, 50),
                "⚠ Store this keyfile separately from your encrypted files. \
                 Losing it means losing access to your data.",
            );
        }
    }
}
