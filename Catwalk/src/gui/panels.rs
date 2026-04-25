use std::fs;
use std::path::{Path, PathBuf};

use eframe::egui;

use catwalk::archive::ARCHIVE_EXTENSION;
use catwalk::utils::format_byte_size;

use super::state::{BatchFileEntry, CatwalkGui, Mode};
use super::{
    action_button, chrome_panel_frame, file_row, mode_toggle, section_frame, ACCENT, ACCENT_DIM,
    ERROR, H_MARGIN, MUTED, SUCCESS, SURFACE,
};

impl CatwalkGui {
    pub(super) fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(chrome_panel_frame())
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("CATWALK")
                            .size(22.0)
                            .strong()
                            .color(ACCENT),
                    );

                    ui.add_space(20.0);

                    let enabled = !self.processing;
                    ui.add_enabled_ui(enabled, |ui| {
                        egui::Frame::NONE
                            .fill(egui::Color32::from_rgb(30, 30, 36))
                            .corner_radius(6.0)
                            .inner_margin(egui::Margin::symmetric(4, 2))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 2.0;
                                    mode_toggle(ui, &mut self.mode, Mode::Encrypt, "Encrypt");
                                    mode_toggle(ui, &mut self.mode, Mode::Decrypt, "Decrypt");
                                    mode_toggle(ui, &mut self.mode, Mode::Archive, "Archive");
                                    mode_toggle(ui, &mut self.mode, Mode::Info, "Info");
                                });
                            });
                    });
                });
            });
    }

    pub(super) fn render_bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .frame(chrome_panel_frame())
            .show(ctx, |ui| {
                let color = if self.status_is_error {
                    ERROR
                } else if self.progress >= 1.0 {
                    SUCCESS
                } else {
                    MUTED
                };

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&self.status_message).color(color));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(start) = self.operation_start {
                            let elapsed = start.elapsed();
                            ui.label(
                                egui::RichText::new(format!("{:.1}s", elapsed.as_secs_f64()))
                                    .small()
                                    .color(MUTED),
                            );
                        }
                    });
                });

                ui.add_space(2.0);

                let bar = egui::ProgressBar::new(self.progress)
                    .show_percentage()
                    .animate(self.processing)
                    .fill(if self.progress >= 1.0 && !self.status_is_error {
                        SUCCESS
                    } else {
                        ACCENT_DIM
                    });
                ui.add(bar);
            });
    }

    pub(super) fn render_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(H_MARGIN as i8, 8)),
            )
            .show(ctx, |ui| {
                // Drag-and-drop overlay
                if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
                    let painter = ui.painter();
                    let rect = ui.max_rect();
                    painter.rect_filled(
                        rect,
                        10.0,
                        egui::Color32::from_rgba_premultiplied(30, 28, 40, 220),
                    );
                    painter.rect_stroke(
                        rect,
                        10.0,
                        egui::Stroke::new(2.0, ACCENT),
                        egui::StrokeKind::Outside,
                    );
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        if self.mode == Mode::Archive {
                            "Drop files to add to archive"
                        } else {
                            "Drop file to set as input"
                        },
                        egui::FontId::proportional(22.0),
                        ACCENT,
                    );
                    return;
                }

                // Enforce right margin that inner_margin fails to apply.
                ui.set_max_width(ui.available_width() - H_MARGIN);

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.mode {
                        Mode::Info => self.render_info_mode(ui),
                        Mode::Archive => self.render_batch_mode(ui),
                        _ => self.render_single_mode(ui),
                    });
            });
    }

    // ── Single File Mode ────────────────────────────────────────────────────────

    fn render_single_mode(&mut self, ui: &mut egui::Ui) {
        // Recent files
        if !self.recent_files.is_empty() && self.input_path.is_empty() {
            section_frame(ui, "RECENT FILES", |ui| {
                let mut selected_path: Option<String> = None;
                for path_str in &self.recent_files {
                    let display = Path::new(path_str)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path_str.clone());
                    if ui.small_button(&display).clicked() {
                        selected_path = Some(path_str.clone());
                    }
                }
                if let Some(p) = selected_path {
                    let path = PathBuf::from(&p);
                    self.auto_detect_mode(&path);
                    self.input_path = p;
                    self.output_path = self
                        .compute_output_path(&path)
                        .to_string_lossy()
                        .to_string();
                }
            });
            ui.add_space(2.0);
        }

        // File selection
        section_frame(ui, "FILES", |ui| {
            ui.label(egui::RichText::new("Input").small().color(MUTED));
            if file_row(
                ui,
                &mut self.input_path,
                "Select a file or drag and drop...",
                "Browse",
            ) {
                self.browse_input();
            }
            if !self.input_path.is_empty() {
                if let Ok(meta) = fs::metadata(&self.input_path) {
                    ui.label(
                        egui::RichText::new(format!("  {}", format_byte_size(meta.len())))
                            .small()
                            .color(MUTED),
                    );
                }
            }

            ui.add_space(6.0);

            ui.label(egui::RichText::new("Output").small().color(MUTED));
            if file_row(ui, &mut self.output_path, "Output location...", "Browse") {
                self.browse_output();
            }
        });

        ui.add_space(4.0);

        // Password
        section_frame(ui, "PASSWORD", |ui| {
            self.render_password_fields(ui);
        });

        ui.add_space(8.0);

        // Action
        let button_label = match self.mode {
            Mode::Encrypt => "Encrypt File",
            Mode::Decrypt => "Decrypt File",
            Mode::Archive => "Encrypt Archive",
            Mode::Info => "Show Info",
        };
        let can_go = self.can_process();
        if action_button(ui, button_label, can_go) {
            self.start_single_operation(ui.ctx().clone());
        }
    }

    // ── Archive Mode ────────────────────────────────────────────────────────────

    fn render_batch_mode(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("Bundle multiple files into a single encrypted archive")
                .small()
                .color(MUTED),
        );
        section_frame(ui, "FILES TO ARCHIVE", |ui| {
            // Toolbar
            ui.horizontal(|ui| {
                if ui.button("Add Files").clicked() {
                    self.browse_batch_files();
                }
                if ui.button("Add Folder").clicked() {
                    self.browse_batch_folder();
                }
                if ui.button("Clear All").clicked() && !self.processing {
                    self.batch_files.clear();
                    self.batch_output_path.clear();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let total_size: u64 = self.batch_files.iter().map(|e| e.size).sum();
                    ui.label(
                        egui::RichText::new(format!(
                            "{} file(s)  |  {}",
                            self.batch_files.len(),
                            format_byte_size(total_size)
                        ))
                        .small()
                        .color(MUTED),
                    );
                });
            });

            ui.add_space(4.0);

            // File list — use a fixed height since we're inside a ScrollArea
            // where available_height() returns infinity.
            let available_height = 200.0_f32;
            egui::Frame::NONE
                .fill(SURFACE)
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(available_height)
                        .show(ui, |ui| {
                            if self.batch_files.is_empty() {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(24.0);
                                    ui.label(
                                        egui::RichText::new(
                                            "Drag files here, click Add Files, or Add Folder",
                                        )
                                        .color(MUTED)
                                        .size(14.0),
                                    );
                                    ui.add_space(24.0);
                                });
                            } else {
                                let mut remove_idx: Option<usize> = None;
                                egui::Grid::new("batch_grid")
                                    .striped(true)
                                    .num_columns(3)
                                    .min_col_width(60.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("File")
                                                .small()
                                                .strong()
                                                .color(MUTED),
                                        );
                                        ui.label(
                                            egui::RichText::new("Size")
                                                .small()
                                                .strong()
                                                .color(MUTED),
                                        );
                                        ui.label("");
                                        ui.end_row();

                                        for (i, entry) in self.batch_files.iter().enumerate() {
                                            let name = entry
                                                .path
                                                .file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_else(|| "???".into());
                                            ui.label(&name);
                                            ui.label(
                                                egui::RichText::new(format_byte_size(entry.size))
                                                    .color(MUTED),
                                            );
                                            if !self.processing {
                                                if ui.small_button("x").clicked() {
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
        });

        ui.add_space(4.0);

        // Output archive
        section_frame(ui, "OUTPUT ARCHIVE", |ui| {
            let hint = format!("Output .{} file...", ARCHIVE_EXTENSION);
            if file_row(ui, &mut self.batch_output_path, &hint, "Browse") {
                let dialog = rfd::FileDialog::new()
                    .set_title("Save Encrypted Archive")
                    .add_filter("CATWALK Archive", &[ARCHIVE_EXTENSION]);
                if let Some(path) = dialog.save_file() {
                    self.batch_output_path = path.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(4.0);

        // Password
        section_frame(ui, "PASSWORD", |ui| {
            self.render_password_fields(ui);
        });

        ui.add_space(8.0);

        // Action
        let label = format!("Encrypt {} File(s) as Archive", self.batch_files.len());
        let can_go = self.can_process();
        if action_button(ui, &label, can_go) {
            self.start_batch_operation(ui.ctx().clone());
        }
    }

    // ── Info Mode ───────────────────────────────────────────────────────────────

    fn render_info_mode(&mut self, ui: &mut egui::Ui) {
        section_frame(ui, "FILE INSPECTOR", |ui| {
            ui.label(egui::RichText::new("Select a CATWALK encrypted file").color(MUTED));
            ui.add_space(4.0);
            if file_row(
                ui,
                &mut self.input_path,
                "Select .catwalk file...",
                "Browse",
            ) {
                self.browse_input();
            }
        });

        ui.add_space(8.0);

        let can_go = !self.input_path.is_empty() && !self.processing;
        if action_button(ui, "Show File Info", can_go) {
            match super::operations::show_file_info(&PathBuf::from(&self.input_path)) {
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
            ui.add_space(8.0);
            section_frame(ui, "FILE INFORMATION", |ui| {
                ui.label(egui::RichText::new(&self.file_info_text).monospace());
            });
        }
    }

    // ── Drag and Drop ───────────────────────────────────────────────────────────

    pub(super) fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| {
            if i.raw.dropped_files.is_empty() {
                vec![]
            } else {
                i.raw.dropped_files.clone()
            }
        });
        if dropped.is_empty() {
            return;
        }

        if self.mode == Mode::Archive {
            for file in &dropped {
                if let Some(path) = &file.path {
                    if path.is_dir() {
                        self.add_folder_contents(path);
                    } else {
                        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        self.batch_files.push(BatchFileEntry {
                            path: path.clone(),
                            size,
                        });
                    }
                    if self.batch_output_path.is_empty() {
                        let dir = if path.is_dir() {
                            path.as_path()
                        } else {
                            path.parent().unwrap_or(path)
                        };
                        self.batch_output_path = dir
                            .join(format!("archive.{}", ARCHIVE_EXTENSION))
                            .to_string_lossy()
                            .to_string();
                    }
                }
            }
        } else if let Some(first) = dropped.first() {
            if let Some(path) = &first.path {
                self.auto_detect_mode(path);
                self.input_path = path.to_string_lossy().to_string();
                self.output_path = self.compute_output_path(path).to_string_lossy().to_string();
            }
        }
    }
}
