use eframe::egui;
use subtle::ConstantTimeEq;

use catwalk::crypto::validate_password;

use super::entropy::EntropyPool;
use super::state::{CatwalkGui, Mode, PasswordStrength};
use super::{ACCENT_DIM, BTN_WIDTH, ERROR, MUTED, SUCCESS};

// ── Diceware word list (short, for passphrase generation) ─────────────────────

const WORDLIST: &[&str] = &[
    "acid", "acme", "aged", "also", "arch", "army", "atom", "aunt", "avid", "axis", "back", "ball",
    "band", "bank", "barn", "base", "bath", "bead", "beam", "bear", "bell", "belt", "bend", "bike",
    "bind", "bird", "bite", "blow", "blue", "blur", "boat", "body", "bolt", "bomb", "bond", "bone",
    "book", "born", "boss", "bowl", "bulk", "bump", "burn", "busy", "buzz", "cafe", "cage", "cake",
    "calm", "came", "camp", "cape", "card", "care", "cart", "case", "cash", "cast", "cave", "chat",
    "chip", "chop", "city", "clad", "clan", "clap", "clay", "clip", "club", "clue", "coal", "coat",
    "code", "coil", "coin", "cold", "cole", "come", "cone", "cook", "cool", "cope", "copy", "cord",
    "core", "corn", "cost", "cozy", "crew", "crop", "crow", "cube", "cult", "cups", "cure", "curl",
    "cute", "dale", "dame", "damp", "dare", "dark", "dart", "dash", "data", "date", "dawn", "deal",
    "dear", "debt", "deck", "deep", "deer", "demo", "dent", "deny", "desk", "dial", "dice", "diet",
    "dirt", "disc", "dish", "disk", "dive", "dock", "does", "dome", "done", "doom", "door", "dose",
    "dove", "down", "drag", "draw", "drip", "drop", "drum", "dual", "duel", "duke", "dull", "dune",
    "dusk", "dust", "duty", "dyed", "each", "earl", "earn", "ease", "east", "easy", "echo", "edge",
    "edit", "else", "emit", "ends", "envy", "epic", "even", "ever", "evil", "exam", "exec", "exit",
    "expo", "face", "fact", "fade", "fail", "fair", "fake", "fall", "fame", "fang", "fare", "farm",
    "fast", "fate", "fawn", "feed", "feel", "feet", "fell", "felt", "fern", "file", "fill", "film",
    "find", "fine", "fire", "firm", "fish", "fist", "five", "flag", "flame", "flap", "flat",
    "fled", "flew", "flex", "flip", "flog", "flow", "flux", "foam", "foil", "fold", "folk", "fond",
    "font", "fool", "fork", "form", "fort", "foul", "four", "fowl", "free", "frog", "from", "fuel",
    "full", "fund", "fury", "fuse", "fuzz", "gait", "gale", "game", "gang", "gate", "gave", "gaze",
    "gear", "gems", "gift", "gild", "gist", "give", "glad", "glen", "glow", "glue", "goat", "goes",
    "gold", "golf", "gone", "good", "grab", "gram", "gray", "grew", "grid", "grim", "grin", "grip",
    "grow", "gulf", "gust", "guts", "hack", "hail", "hair", "hale", "half", "hall", "halt", "hand",
    "hang", "hare", "harm", "harp", "haste", "hate", "haul", "have", "hawk", "haze", "head",
    "heal", "heap", "hear", "heat", "heel", "held", "helm", "help", "herb", "herd", "here", "hero",
    "hide", "high", "hike", "hill", "hilt", "hind", "hint", "hire", "hive", "hock", "hold", "hole",
    "holy", "home", "hood", "hook", "hope", "horn", "hose", "host", "hour", "howl", "huge", "hull",
    "hump", "hung", "hunt", "hurl", "hymn", "icon", "idea", "idle", "inch", "info", "into", "iris",
    "iron", "isle", "item", "jack", "jade", "jail", "jamb", "jars", "java", "jazz", "jest", "jets",
    "jobs", "join", "joke", "jolt", "jump", "june", "jury", "just", "keen", "keep", "kelp", "kept",
    "kick", "kids", "kill", "kind", "king", "kite", "knob", "knot", "know", "lace", "lack", "laid",
    "lake", "lamb", "lamp", "land", "lane", "lard", "lark", "lash", "last", "late", "lawn", "lazy",
    "lead", "leaf", "lean", "leap", "left", "lend", "lens", "less", "levy", "liar", "lick", "lied",
    "life", "lift", "like", "limb", "lime", "limp", "line", "link", "lion", "lips", "list", "live",
    "load", "loaf", "loan", "lock", "loft", "logo", "lone", "long", "look", "loop", "lord", "lore",
    "lose", "loss", "lost", "lots", "loud", "love", "luck", "lull", "lump", "lung", "lure", "lurk",
    "lush", "lust", "lynx", "mace", "made", "maid", "mail", "main", "make", "male", "mall", "malt",
    "mane", "many", "maps", "mare", "mark", "mars", "mash", "mask", "mass", "mast", "mate", "maze",
    "meal", "mean", "meat", "meet", "meld", "melt", "memo", "mend", "menu", "mere", "mesh", "mess",
    "mild", "mile", "milk", "mill", "mime", "mind", "mine", "mint", "miss", "mist", "moan", "moat",
    "mock", "mode", "mold", "monk", "mood", "moon", "moor", "more", "moss", "most", "moth", "move",
    "much", "mule", "muse", "mush", "must", "mute", "myth", "nail", "name", "navy", "near", "neat",
    "neck", "need", "nest", "nets", "news", "next", "nice", "nine", "node", "none", "norm", "nose",
    "note", "noun", "null", "numb",
];

/// Generate a random passphrase from the wordlist.
fn generate_passphrase(word_count: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| {
            let idx = rng.gen_range(0..WORDLIST.len());
            WORDLIST[idx]
        })
        .collect();
    words.join("-")
}

pub(super) fn evaluate_password_strength(password: &str) -> PasswordStrength {
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

pub(super) fn render_password_strength(ui: &mut egui::Ui, strength: PasswordStrength) {
    let (ratio, color, label) = match strength {
        PasswordStrength::Empty => return,
        PasswordStrength::Weak => (0.25, ERROR, "Weak"),
        PasswordStrength::Fair => (0.5, egui::Color32::from_rgb(200, 180, 80), "Fair"),
        PasswordStrength::Strong => (0.75, egui::Color32::from_rgb(130, 200, 140), "Strong"),
        PasswordStrength::VeryStrong => (1.0, SUCCESS, "Very Strong"),
    };
    ui.horizontal(|ui| {
        ui.add(
            egui::ProgressBar::new(ratio)
                .desired_width(100.0)
                .fill(color),
        );
        ui.label(egui::RichText::new(label).small().color(color));
    });
}

// ── Shared: Password Fields ─────────────────────────────────────────────────

impl CatwalkGui {
    pub(super) fn render_password_fields(&mut self, ui: &mut egui::Ui) {
        // Password input + Show/Hide button (aligned with Browse buttons)
        ui.horizontal(|ui| {
            let spacing = ui.spacing().item_spacing.x;
            let edit_width = (ui.available_width() - BTN_WIDTH - spacing).max(80.0);
            let mut edit = egui::TextEdit::singleline(&mut self.password)
                .desired_width(edit_width)
                .hint_text("Enter password...");
            if !self.show_password {
                edit = edit.password(true);
            }
            ui.add(edit);

            let toggle_label = if self.show_password { "Hide" } else { "Show" };
            let btn = egui::Button::new(toggle_label).min_size(egui::vec2(BTN_WIDTH, 0.0));
            if ui.add(btn).clicked() {
                self.show_password = !self.show_password;
            }
        });

        // Password strength
        let strength = evaluate_password_strength(&self.password);
        if strength != PasswordStrength::Empty {
            render_password_strength(ui, strength);
            if let Err(reason) = validate_password(&self.password) {
                ui.label(egui::RichText::new(reason).small().color(ERROR));
            }
        }

        // Confirm password + generate button (encrypt / archive only)
        if self.mode == Mode::Encrypt || self.mode == Mode::Archive {
            ui.add_space(4.0);

            ui.label(egui::RichText::new("Confirm").small().color(MUTED));
            ui.horizontal(|ui| {
                let spacing = ui.spacing().item_spacing.x;
                let edit_width = (ui.available_width() - BTN_WIDTH - spacing).max(80.0);
                let mut edit = egui::TextEdit::singleline(&mut self.confirm_password)
                    .desired_width(edit_width)
                    .hint_text("Confirm password...");
                if !self.show_password {
                    edit = edit.password(true);
                }
                ui.add(edit);

                let gen_btn = egui::Button::new(egui::RichText::new("Generate").color(ACCENT_DIM))
                    .min_size(egui::vec2(BTN_WIDTH, 0.0));
                if ui.add(gen_btn).clicked() {
                    let passphrase = generate_passphrase(6);
                    self.password = passphrase.clone();
                    self.confirm_password = passphrase;
                    self.show_password = true;
                    self.status_message = "Passphrase generated — copy it somewhere safe!".into();
                    self.status_is_error = false;
                }
            });

            if !self.password.is_empty() && !self.confirm_password.is_empty() {
                if bool::from(
                    self.password
                        .as_bytes()
                        .ct_eq(self.confirm_password.as_bytes()),
                ) {
                    ui.label(
                        egui::RichText::new("Passwords match")
                            .small()
                            .color(SUCCESS),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("Passwords do not match")
                            .small()
                            .color(ERROR),
                    );
                }
            }

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Options").small().strong().color(MUTED));
            ui.checkbox(
                &mut self.strip_metadata,
                "Strip metadata (no timestamp/extension)",
            );
            ui.checkbox(
                &mut self.skip_compression,
                "Skip compression (no pattern fingerprinting)",
            );
            ui.checkbox(
                &mut self.secure_delete,
                "Secure delete original after encryption",
            )
            .on_hover_text(
                "Best-effort overwrite + delete. Unreliable on SSDs (wear leveling), \
                 copy-on-write filesystems (BTRFS/ZFS/APFS/ReFS), and journaled filesystems. \
                 For true cryptographic erasure, use full-disk encryption and destroy the key.",
            );

            // ── Keyfile picker (encrypt / archive) ────────────────────────────
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Keyfile (optional)")
                    .small()
                    .strong()
                    .color(MUTED),
            );
            ui.horizontal(|ui| {
                match &self.encrypt_keyfile {
                    Some(path) => {
                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        ui.label(egui::RichText::new(&name).color(SUCCESS));
                        if ui.small_button("Clear").clicked() {
                            self.encrypt_keyfile = None;
                        }
                    }
                    None => {
                        ui.label(egui::RichText::new("No keyfile selected").color(MUTED));
                    }
                }
                if ui.small_button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select keyfile")
                        .pick_file()
                    {
                        self.encrypt_keyfile = Some(path);
                    }
                }
                if ui.small_button("Generate new…").clicked() {
                    self.show_entropy_dialog = true;
                    self.entropy_pool = EntropyPool::new();
                }
            });
            if self.encrypt_keyfile.is_some() {
                ui.colored_label(SUCCESS, "✓ Keyfile will be used for encryption");
                ui.label(
                    egui::RichText::new(
                        "⚠ You must use this exact keyfile to decrypt.\n\
                         Store it separately from the encrypted file.",
                    )
                    .small()
                    .color(egui::Color32::from_rgb(220, 180, 50)),
                );
            }
        }

        // ── Keyfile picker (decrypt only) ─────────────────────────────────────
        if self.mode == Mode::Decrypt {
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            let keyfile_required = self.detect_keyfile_flag();
            if keyfile_required {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 200, 50),
                    "⚠ This file was encrypted with a keyfile",
                );
            } else {
                ui.label(
                    egui::RichText::new("Keyfile (optional)")
                        .small()
                        .strong()
                        .color(MUTED),
                );
            }

            ui.horizontal(|ui| {
                match &self.decrypt_keyfile {
                    Some(path) => {
                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        ui.label(egui::RichText::new(&name).color(SUCCESS));
                        if ui.small_button("Clear").clicked() {
                            self.decrypt_keyfile = None;
                        }
                    }
                    None => {
                        if keyfile_required {
                            ui.colored_label(ERROR, "No keyfile selected — required");
                        } else {
                            ui.label(egui::RichText::new("No keyfile selected").color(MUTED));
                        }
                    }
                }
                if ui.small_button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select keyfile")
                        .pick_file()
                    {
                        self.decrypt_keyfile = Some(path);
                    }
                }
            });
        }
    }
}
