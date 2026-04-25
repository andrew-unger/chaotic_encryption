use eframe::egui;
use zeroize::Zeroize;

extern crate catwalk;

mod entropy;
mod operations;
mod panels;
mod password;
mod state;

use state::{CatwalkGui, Mode};

// ── Color Palette ─────────────────────────────────────────────────────────────
// "Catwalk" — sleek runway aesthetic: cool neutrals with a soft violet accent.

const ACCENT: egui::Color32 = egui::Color32::from_rgb(160, 140, 200);
const ACCENT_DIM: egui::Color32 = egui::Color32::from_rgb(120, 110, 150);
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(180, 165, 220);
const SUCCESS: egui::Color32 = egui::Color32::from_rgb(100, 200, 140);
const ERROR: egui::Color32 = egui::Color32::from_rgb(220, 90, 90);
const MUTED: egui::Color32 = egui::Color32::from_rgb(140, 140, 150);
const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(35, 35, 42);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(28, 28, 34);
const FRAME_STROKE: egui::Color32 = egui::Color32::from_rgb(50, 50, 58);
const BTN_WIDTH: f32 = 82.0;
const H_MARGIN: f32 = 20.0;
const SECTION_MARGIN: f32 = 12.0;

// ── Theme Setup ───────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = SURFACE;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = egui::Color32::from_rgb(22, 22, 28);
    visuals.faint_bg_color = PANEL_BG;

    visuals.widgets.noninteractive.bg_fill = PANEL_BG;
    visuals.widgets.noninteractive.fg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(190, 190, 200));
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, FRAME_STROKE);

    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(50, 50, 58);
    visuals.widgets.inactive.fg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 180, 190));
    visuals.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(45, 45, 52);

    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(60, 58, 72);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, ACCENT_HOVER);
    visuals.widgets.hovered.weak_bg_fill = egui::Color32::from_rgb(55, 53, 65);

    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(70, 65, 85);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.active.weak_bg_fill = egui::Color32::from_rgb(65, 60, 78);

    visuals.selection.bg_fill = egui::Color32::from_rgb(80, 70, 110);
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    visuals.window_stroke = egui::Stroke::new(1.0, FRAME_STROKE);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 4.0);
    style.spacing.scroll = egui::style::ScrollStyle {
        bar_width: 6.0,
        ..style.spacing.scroll
    };
    ctx.set_style(style);
}

// ── Widget helpers ────────────────────────────────────────────────────────────

/// A grouped section with a title label and rounded frame.
///
/// NOTE: egui's `Frame::inner_margin` shifts the cursor for the left margin
/// but does not reduce `max_rect.right`, so `available_width()` inside the
/// frame is wider than it should be and content bleeds to the right border.
/// We work around this by explicitly constraining `max_width` after the frame
/// creates its child UI.
fn section_frame(ui: &mut egui::Ui, title: &str, add_body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(title)
            .size(13.0)
            .strong()
            .color(ACCENT_DIM),
    );
    ui.add_space(2.0);
    egui::Frame::NONE
        .fill(PANEL_BG)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(SECTION_MARGIN as i8))
        .stroke(egui::Stroke::new(1.0, FRAME_STROKE))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width() - SECTION_MARGIN);
            add_body(ui);
        });
}

/// Frame used for the top and bottom chrome panels.
fn chrome_panel_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(PANEL_BG)
        .inner_margin(egui::Margin::symmetric(H_MARGIN as i8, 8))
        .stroke(egui::Stroke::new(1.0, FRAME_STROKE))
}

/// A text field + right-aligned fixed-width button on one row.
fn file_row(ui: &mut egui::Ui, text: &mut String, hint: &str, btn_label: &str) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        let spacing = ui.spacing().item_spacing.x;
        let edit_width = (ui.available_width() - BTN_WIDTH - spacing).max(80.0);
        ui.add(
            egui::TextEdit::singleline(text)
                .desired_width(edit_width)
                .hint_text(hint),
        );
        let btn = egui::Button::new(btn_label).min_size(egui::vec2(BTN_WIDTH, 0.0));
        if ui.add(btn).clicked() {
            clicked = true;
        }
    });
    clicked
}

/// Render a styled mode-selector toggle button.
fn mode_toggle(ui: &mut egui::Ui, current: &mut Mode, value: Mode, label: &str) {
    let selected = *current == value;
    let text = egui::RichText::new(label).size(13.0).strong();
    let text = if selected {
        text.color(ACCENT)
    } else {
        text.color(MUTED)
    };

    let fill = if selected {
        egui::Color32::from_rgb(55, 50, 68)
    } else {
        egui::Color32::TRANSPARENT
    };

    let btn = egui::Button::new(text)
        .fill(fill)
        .corner_radius(4.0)
        .min_size(egui::vec2(72.0, 28.0));

    if ui.add(btn).clicked() {
        *current = value;
    }
}

/// Full-width action button with accent coloring.
fn action_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let width = ui.available_width();
    let text = egui::RichText::new(label)
        .strong()
        .size(15.0)
        .color(if enabled {
            egui::Color32::WHITE
        } else {
            egui::Color32::from_rgb(100, 100, 110)
        });
    let fill = if enabled {
        ACCENT_DIM
    } else {
        egui::Color32::from_rgb(45, 45, 52)
    };
    let btn = egui::Button::new(text)
        .fill(fill)
        .corner_radius(6.0)
        .min_size(egui::vec2(width, 38.0));
    ui.add_enabled(enabled, btn).clicked()
}

/// Securely overwrite a file with random data, then delete it.
fn secure_delete_file(path: &std::path::Path) -> Result<(), String> {
    catwalk::utils::secure_delete_file(path).map_err(|e| e.to_string())
}

// ── eframe::App ───────────────────────────────────────────────────────────────

impl eframe::App for CatwalkGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.handle_dropped_files(ctx);

        // Handle pending secure delete after successful encryption
        if let Some(path) = self.pending_secure_delete.take() {
            match secure_delete_file(&path) {
                Ok(()) => {
                    self.status_message =
                        format!("{} | Original securely deleted", self.status_message);
                }
                Err(e) => {
                    self.status_message = format!(
                        "{} | Warning: secure delete failed: {}",
                        self.status_message, e
                    );
                }
            }
        }

        self.render_top_panel(ctx);
        self.render_bottom_panel(ctx);
        self.render_central_panel(ctx);

        if self.show_entropy_dialog {
            self.show_entropy_dialog_window(ctx);
        }
    }
}

impl Drop for CatwalkGui {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
    }
}

// ── Entry Point ─────────────────────────────────────────────────────────────

pub fn run_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([540.0, 460.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "CATWALK",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(CatwalkGui::default()))
        }),
    )
    .map_err(|e| format!("Error running GUI: {}", e))
}
