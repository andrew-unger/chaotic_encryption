use std::collections::VecDeque;
use std::io::{Cursor, Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::fs;

use eframe::egui;
use zeroize::Zeroize;
use zip::write::SimpleFileOptions;

extern crate catwalk;
use catwalk::crypto::{encrypt, decrypt, validate_password, EncryptOptions, ProgressFn};
use catwalk::crypto::constants::{FLAG_KEYFILE, FLAGS_OFFSET};
use catwalk::error::CryptoError;
use catwalk::utils::{parse_file_info, format_byte_size};

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
    pub fn derive_keyfile(&self) -> [u8; 64] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.pool);
        hasher.update(&now.to_le_bytes());
        hasher.update(b"catwalk-keyfile-v1");
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    pub fn history_iter(&self) -> impl Iterator<Item = f32> + '_ {
        self.history.iter().copied()
    }

    pub fn raw_byte_count(&self) -> usize {
        self.pool.len()
    }
}

const ARCHIVE_EXTENSION: &str = "catwalkarchive";

// ── Color Palette ─────────────────────────────────────────────────────────────
// "Catwalk" — sleek runway aesthetic: cool neutrals with a soft violet accent.

const ACCENT:      egui::Color32 = egui::Color32::from_rgb(160, 140, 200);
const ACCENT_DIM:  egui::Color32 = egui::Color32::from_rgb(120, 110, 150);
const ACCENT_HOVER:egui::Color32 = egui::Color32::from_rgb(180, 165, 220);
const SUCCESS:     egui::Color32 = egui::Color32::from_rgb(100, 200, 140);
const ERROR:       egui::Color32 = egui::Color32::from_rgb(220,  90,  90);
const MUTED:       egui::Color32 = egui::Color32::from_rgb(140, 140, 150);
const PANEL_BG:    egui::Color32 = egui::Color32::from_rgb( 35,  35,  42);
const SURFACE:     egui::Color32 = egui::Color32::from_rgb( 28,  28,  34);
const FRAME_STROKE:egui::Color32 = egui::Color32::from_rgb( 50,  50,  58);
const BTN_WIDTH:   f32 = 68.0;
const H_MARGIN:    i8 = 20;

// ── Diceware word list (short, for passphrase generation) ─────────────────────

const WORDLIST: &[&str] = &[
    "acid", "acme", "aged", "also", "arch", "army", "atom", "aunt",
    "avid", "axis", "back", "ball", "band", "bank", "barn", "base",
    "bath", "bead", "beam", "bear", "bell", "belt", "bend", "bike",
    "bind", "bird", "bite", "blow", "blue", "blur", "boat", "body",
    "bolt", "bomb", "bond", "bone", "book", "born", "boss", "bowl",
    "bulk", "bump", "burn", "busy", "buzz", "cafe", "cage", "cake",
    "calm", "came", "camp", "cape", "card", "care", "cart", "case",
    "cash", "cast", "cave", "chat", "chip", "chop", "city", "clad",
    "clan", "clap", "clay", "clip", "club", "clue", "coal", "coat",
    "code", "coil", "coin", "cold", "cole", "come", "cone", "cook",
    "cool", "cope", "copy", "cord", "core", "corn", "cost", "cozy",
    "crew", "crop", "crow", "cube", "cult", "cups", "cure", "curl",
    "cute", "dale", "dame", "damp", "dare", "dark", "dart", "dash",
    "data", "date", "dawn", "deal", "dear", "debt", "deck", "deep",
    "deer", "demo", "dent", "deny", "desk", "dial", "dice", "diet",
    "dirt", "disc", "dish", "disk", "dive", "dock", "does", "dome",
    "done", "doom", "door", "dose", "dove", "down", "drag", "draw",
    "drip", "drop", "drum", "dual", "duel", "duke", "dull", "dune",
    "dusk", "dust", "duty", "dyed", "each", "earl", "earn", "ease",
    "east", "easy", "echo", "edge", "edit", "else", "emit", "ends",
    "envy", "epic", "even", "ever", "evil", "exam", "exec", "exit",
    "expo", "face", "fact", "fade", "fail", "fair", "fake", "fall",
    "fame", "fang", "fare", "farm", "fast", "fate", "fawn", "feed",
    "feel", "feet", "fell", "felt", "fern", "file", "fill", "film",
    "find", "fine", "fire", "firm", "fish", "fist", "five", "flag",
    "flame","flap", "flat", "fled", "flew", "flex", "flip", "flog",
    "flow", "flux", "foam", "foil", "fold", "folk", "fond", "font",
    "fool", "fork", "form", "fort", "foul", "four", "fowl", "free",
    "frog", "from", "fuel", "full", "fund", "fury", "fuse", "fuzz",
    "gait", "gale", "game", "gang", "gate", "gave", "gaze", "gear",
    "gems", "gift", "gild", "gist", "give", "glad", "glen", "glow",
    "glue", "goat", "goes", "gold", "golf", "gone", "good", "grab",
    "gram", "gray", "grew", "grid", "grim", "grin", "grip", "grow",
    "gulf", "gust", "guts", "hack", "hail", "hair", "hale", "half",
    "hall", "halt", "hand", "hang", "hare", "harm", "harp", "haste",
    "hate", "haul", "have", "hawk", "haze", "head", "heal", "heap",
    "hear", "heat", "heel", "held", "helm", "help", "herb", "herd",
    "here", "hero", "hide", "high", "hike", "hill", "hilt", "hind",
    "hint", "hire", "hive", "hock", "hold", "hole", "holy", "home",
    "hood", "hook", "hope", "horn", "hose", "host", "hour", "howl",
    "huge", "hull", "hump", "hung", "hunt", "hurl", "hymn", "icon",
    "idea", "idle", "inch", "info", "into", "iris", "iron", "isle",
    "item", "jack", "jade", "jail", "jamb", "jars", "java", "jazz",
    "jest", "jets", "jobs", "join", "joke", "jolt", "jump", "june",
    "jury", "just", "keen", "keep", "kelp", "kept", "kick", "kids",
    "kill", "kind", "king", "kite", "knob", "knot", "know", "lace",
    "lack", "laid", "lake", "lamb", "lamp", "land", "lane", "lard",
    "lark", "lash", "last", "late", "lawn", "lazy", "lead", "leaf",
    "lean", "leap", "left", "lend", "lens", "less", "levy", "liar",
    "lick", "lied", "life", "lift", "like", "limb", "lime", "limp",
    "line", "link", "lion", "lips", "list", "live", "load", "loaf",
    "loan", "lock", "loft", "logo", "lone", "long", "look", "loop",
    "lord", "lore", "lose", "loss", "lost", "lots", "loud", "love",
    "luck", "lull", "lump", "lung", "lure", "lurk", "lush", "lust",
    "lynx", "mace", "made", "maid", "mail", "main", "make", "male",
    "mall", "malt", "mane", "many", "maps", "mare", "mark", "mars",
    "mash", "mask", "mass", "mast", "mate", "maze", "meal", "mean",
    "meat", "meet", "meld", "melt", "memo", "mend", "menu", "mere",
    "mesh", "mess", "mild", "mile", "milk", "mill", "mime", "mind",
    "mine", "mint", "miss", "mist", "moan", "moat", "mock", "mode",
    "mold", "monk", "mood", "moon", "moor", "more", "moss", "most",
    "moth", "move", "much", "mule", "muse", "mush", "must", "mute",
    "myth", "nail", "name", "navy", "near", "neat", "neck", "need",
    "nest", "nets", "news", "next", "nice", "nine", "node", "none",
    "norm", "nose", "note", "noun", "null", "numb",
];

// ── Config file for recent files ──────────────────────────────────────────────

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
    let _ = fs::write(&path, content);
}

fn add_to_recent(recent: &mut Vec<String>, path: &str) {
    if path.is_empty() { return; }
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

// ── Application State ─────────────────────────────────────────────────────────

pub struct CatwalkGui {
    mode: Mode,

    // Single-file
    input_path: String,
    output_path: String,

    // Password
    password: String,
    confirm_password: String,
    show_password: bool,

    // Options
    strip_metadata: bool,
    skip_compression: bool,
    secure_delete: bool,

    // Batch / archive
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

    // Recent files
    recent_files: Vec<String>,

    // Pending secure-delete path (set after successful encrypt)
    pending_secure_delete: Option<PathBuf>,

    // ── Keyfile support ──────────────────────────────────────────────────────
    /// Keyfile to use when encrypting or archiving (None = no keyfile).
    encrypt_keyfile: Option<PathBuf>,
    /// Keyfile to use when decrypting (None = no keyfile).
    decrypt_keyfile: Option<PathBuf>,

    // ── Entropy harvesting dialog ────────────────────────────────────────────
    show_entropy_dialog: bool,
    entropy_pool: EntropyPool,
    /// Frame counter — increments every frame while the dialog is open.
    entropy_counter: u64,
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

// ── Theme Setup ───────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = SURFACE;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = egui::Color32::from_rgb(22, 22, 28);
    visuals.faint_bg_color = PANEL_BG;

    visuals.widgets.noninteractive.bg_fill = PANEL_BG;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(190, 190, 200));
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, FRAME_STROKE);

    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(50, 50, 58);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 180, 190));
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A grouped section with a title label and rounded frame.
fn section_frame(ui: &mut egui::Ui, title: &str, add_body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(4.0);
    ui.label(egui::RichText::new(title).size(13.0).strong().color(ACCENT_DIM));
    ui.add_space(2.0);
    egui::Frame::NONE
        .fill(PANEL_BG)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(12))
        .stroke(egui::Stroke::new(1.0, FRAME_STROKE))
        .show(ui, add_body);
}

/// A text field + right-aligned fixed-width button on one row.
fn file_row(ui: &mut egui::Ui, text: &mut String, hint: &str, btn_label: &str) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        let spacing = ui.spacing().item_spacing.x;
        let edit_width = ui.available_width() - BTN_WIDTH - spacing;
        ui.add(
            egui::TextEdit::singleline(text)
                .desired_width(edit_width)
                .hint_text(hint),
        );
        let btn = egui::Button::new(btn_label)
            .min_size(egui::vec2(BTN_WIDTH, 0.0));
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
    let text = if selected { text.color(ACCENT) } else { text.color(MUTED) };

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
    let text = egui::RichText::new(label).strong().size(15.0).color(
        if enabled {
            egui::Color32::WHITE
        } else {
            egui::Color32::from_rgb(100, 100, 110)
        },
    );
    let fill = if enabled { ACCENT_DIM } else { egui::Color32::from_rgb(45, 45, 52) };
    let btn = egui::Button::new(text)
        .fill(fill)
        .corner_radius(6.0)
        .min_size(egui::vec2(width, 38.0));
    ui.add_enabled(enabled, btn).clicked()
}

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

/// Securely overwrite a file with random data, then delete it.
fn secure_delete_file(path: &Path) -> Result<(), String> {
    let meta = fs::metadata(path).map_err(|e| format!("Cannot read file: {}", e))?;
    let size = meta.len() as usize;

    // Three-pass overwrite: random, zeros, random
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    for pass in 0..3 {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("Cannot open for overwrite: {}", e))?;

        let mut buf = vec![0u8; 8192.min(size.max(1))];
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            if pass == 1 {
                // Middle pass: zeros (buf is already zeroed)
                for b in buf[..chunk].iter_mut() { *b = 0; }
            } else {
                rng.fill_bytes(&mut buf[..chunk]);
            }
            use std::io::Write;
            f.write_all(&buf[..chunk])
                .map_err(|e| format!("Overwrite failed: {}", e))?;
            remaining -= chunk;
        }
        f.sync_all().map_err(|e| format!("Sync failed: {}", e))?;
    }

    fs::remove_file(path).map_err(|e| format!("Delete failed: {}", e))?;
    Ok(())
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
                    self.status_message = format!(
                        "{} | Original securely deleted",
                        self.status_message
                    );
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

// ── Rendering ─────────────────────────────────────────────────────────────────

impl CatwalkGui {
    // ── Keyfile helpers ──────────────────────────────────────────────────────

    /// Read the flags byte from the selected input file header and return true
    /// if FLAG_KEYFILE is set.  Returns false on any read or parse error.
    fn detect_keyfile_flag(&self) -> bool {
        if self.input_path.is_empty() {
            return false;
        }
        let path = PathBuf::from(&self.input_path);
        let mut f = match fs::File::open(&path) {
            Ok(f)  => f,
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

    // ── Entropy harvesting dialog ────────────────────────────────────────────

    fn show_entropy_dialog_window(&mut self, ctx: &egui::Context) {
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
        ui.painter().rect_filled(rect, 4.0, egui::Color32::from_rgb(20, 20, 30));

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
            let n    = history.len();
            let step = rect.width() / n as f32;
            let heat = self.entropy_pool.fullness();
            for i in 1..n {
                let x0 = rect.left() + (i - 1) as f32 * step;
                let x1 = rect.left() + i as f32 * step;
                let y0 = rect.bottom() - history[i - 1] * rect.height();
                let y1 = rect.bottom() - history[i]     * rect.height();
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
                [egui::pos2(mp.x, rect.top()), egui::pos2(mp.x, rect.bottom())],
                egui::Stroke::new(1.0, dim),
            );
            ui.painter().line_segment(
                [egui::pos2(rect.left(), mp.y), egui::pos2(rect.right(), mp.y)],
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
            if ui.add_enabled(save_enabled, egui::Button::new("Save Keyfile…")).clicked() {
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

    fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::NONE
                .fill(PANEL_BG)
                .inner_margin(egui::Margin::symmetric(H_MARGIN, 8))
                .stroke(egui::Stroke::new(1.0, FRAME_STROKE)))
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

    fn render_bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::NONE
                .fill(PANEL_BG)
                .inner_margin(egui::Margin::symmetric(H_MARGIN, 8))
                .stroke(egui::Stroke::new(1.0, FRAME_STROKE)))
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

    fn render_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(SURFACE))
            .show(ctx, |ui| {
                // Drag-and-drop overlay
                if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
                    let painter = ui.painter();
                    let rect = ui.max_rect();
                    painter.rect_filled(rect, 10.0, egui::Color32::from_rgba_premultiplied(30, 28, 40, 220));
                    painter.rect_stroke(rect, 10.0, egui::Stroke::new(2.0, ACCENT), egui::StrokeKind::Outside);
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        if self.mode == Mode::Archive { "Drop files to add to archive" } else { "Drop file to set as input" },
                        egui::FontId::proportional(22.0),
                        ACCENT,
                    );
                    return;
                }

                // Apply only horizontal margins via an explicit content_rect.
                // We do NOT cap max.y here — the ScrollArea below handles the
                // vertical extent, allowing content to scroll rather than clip.
                // Using allocate_new_ui with an explicit Rect is the only reliable
                // way to constrain *both* left and right boundaries in egui, because
                // inner_margin.right does not reduce max_rect.right on panels.
                let h_margin = 20.0_f32;
                let full = ui.max_rect();
                let content_rect = egui::Rect::from_min_max(
                    egui::pos2(full.min.x + h_margin, full.min.y),
                    egui::pos2(full.max.x - h_margin, full.max.y),
                );

                ui.allocate_new_ui(egui::UiBuilder::new().max_rect(content_rect), |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add_space(8.0); // top padding
                            match self.mode {
                                Mode::Info    => self.render_info_mode(ui),
                                Mode::Archive => self.render_batch_mode(ui),
                                _             => self.render_single_mode(ui),
                            }
                            ui.add_space(8.0); // bottom padding
                        });
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
            if file_row(ui, &mut self.input_path, "Select a file or drag and drop...", "Browse") {
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

            // File list
            let available_height = (ui.available_height() - 280.0).max(60.0);
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
                                        egui::RichText::new("Drag files here, click Add Files, or Add Folder")
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
                                        ui.label(egui::RichText::new("File").small().strong().color(MUTED));
                                        ui.label(egui::RichText::new("Size").small().strong().color(MUTED));
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
            if file_row(ui, &mut self.input_path, "Select .catwalk file...", "Browse") {
                self.browse_input();
            }
        });

        ui.add_space(8.0);

        let can_go = !self.input_path.is_empty() && !self.processing;
        if action_button(ui, "Show File Info", can_go) {
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
            ui.add_space(8.0);
            section_frame(ui, "FILE INFORMATION", |ui| {
                ui.label(
                    egui::RichText::new(&self.file_info_text).monospace(),
                );
            });
        }
    }

    // ── Shared: Password Fields ─────────────────────────────────────────────────

    fn render_password_fields(&mut self, ui: &mut egui::Ui) {
        // Password input + Show/Hide button (aligned with Browse buttons)
        ui.horizontal(|ui| {
            let spacing = ui.spacing().item_spacing.x;
            let edit_width = ui.available_width() - BTN_WIDTH - spacing;
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
                let edit_width = ui.available_width() - BTN_WIDTH - spacing;
                let mut edit = egui::TextEdit::singleline(&mut self.confirm_password)
                    .desired_width(edit_width)
                    .hint_text("Confirm password...");
                if !self.show_password {
                    edit = edit.password(true);
                }
                ui.add(edit);

                let gen_btn = egui::Button::new(
                    egui::RichText::new("Generate").color(ACCENT_DIM),
                ).min_size(egui::vec2(BTN_WIDTH, 0.0));
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
                if self.password == self.confirm_password {
                    ui.label(egui::RichText::new("Passwords match").small().color(SUCCESS));
                } else {
                    ui.label(egui::RichText::new("Passwords do not match").small().color(ERROR));
                }
            }

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Options").small().strong().color(MUTED));
            ui.checkbox(&mut self.strip_metadata, "Strip metadata (no timestamp/extension)");
            ui.checkbox(&mut self.skip_compression, "Skip compression (no pattern fingerprinting)");
            ui.checkbox(&mut self.secure_delete, "Secure delete original after encryption");

            // ── Keyfile picker (encrypt / archive) ────────────────────────────
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Keyfile (optional)").small().strong().color(MUTED));
            ui.horizontal(|ui| {
                match &self.encrypt_keyfile {
                    Some(path) => {
                        let name = path.file_name()
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
                         Store it separately from the encrypted file."
                    ).small().color(egui::Color32::from_rgb(220, 180, 50))
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
                ui.label(egui::RichText::new("Keyfile (optional)").small().strong().color(MUTED));
            }

            ui.horizontal(|ui| {
                match &self.decrypt_keyfile {
                    Some(path) => {
                        let name = path.file_name()
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

    // ── Drag and Drop ───────────────────────────────────────────────────────────

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
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
                        let dir = if path.is_dir() { path.as_path() } else { path.parent().unwrap_or(path) };
                        self.batch_output_path =
                            dir.join(format!("archive.{}", ARCHIVE_EXTENSION)).to_string_lossy().to_string();
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

    // ── File Browsing ───────────────────────────────────────────────────────────

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

    fn browse_batch_folder(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_title("Select Folder to Archive");
        if let Some(dir) = dialog.pick_folder() {
            self.add_folder_contents(&dir);
            if self.batch_output_path.is_empty() {
                self.batch_output_path =
                    dir.join(format!("archive.{}", ARCHIVE_EXTENSION)).to_string_lossy().to_string();
            }
        }
    }

    fn add_folder_contents(&mut self, dir: &Path) {
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

    fn auto_detect_mode(&mut self, path: &Path) {
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
            Mode::Archive | Mode::Info => {}
        }
        out
    }

    // ── Validation ──────────────────────────────────────────────────────────────

    fn can_process(&self) -> bool {
        if self.processing {
            return false;
        }

        match self.mode {
            Mode::Info => !self.input_path.is_empty(),
            Mode::Encrypt => {
                !self.input_path.is_empty()
                    && !self.output_path.is_empty()
                    && validate_password(&self.password).is_ok()
                    && self.password == self.confirm_password
            }
            Mode::Archive => {
                !self.batch_files.is_empty()
                    && !self.batch_output_path.is_empty()
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

    // ── Background Operations ───────────────────────────────────────────────────

    fn start_single_operation(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.processing = true;
        self.progress = 0.0;
        self.status_message = "Processing...".into();
        self.status_is_error = false;
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
        let input_path  = PathBuf::from(&self.input_path);
        let output_path = PathBuf::from(&self.output_path);
        let password    = self.password.clone();
        let options = EncryptOptions {
            strip_metadata:   self.strip_metadata,
            skip_compression: self.skip_compression,
        };
        // Clone keyfile paths for the worker thread.
        let encrypt_keyfile = self.encrypt_keyfile.clone();
        let decrypt_keyfile = self.decrypt_keyfile.clone();

        // Add to recent files
        add_to_recent(&mut self.recent_files, &input_str);

        let progress_tx  = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = match mode {
                Mode::Encrypt => encrypt_file(
                    &input_path, &output_path, &password, &options,
                    encrypt_keyfile.as_deref(), Some(&progress_cb),
                ),
                Mode::Decrypt => decrypt_file(
                    &input_path, &output_path, &password,
                    decrypt_keyfile.as_deref(), Some(&progress_cb),
                ),
                Mode::Archive => unreachable!("Archive uses start_batch_operation"),
                Mode::Info    => show_file_info(&input_path),
            };
            let _ = tx.send(WorkerMessage::Complete(result));
            let _ = tx.send(WorkerMessage::AllDone);
            ctx.request_repaint();
        });

        // Queue secure delete for after worker completes
        if let Some(path) = input_for_delete {
            // We'll handle this in poll_worker when AllDone arrives
            self.pending_secure_delete = Some(path);
        }
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
        let output_path     = PathBuf::from(&self.batch_output_path);
        let password        = self.password.clone();
        let options = EncryptOptions {
            strip_metadata:   self.strip_metadata,
            skip_compression: self.skip_compression,
        };
        let encrypt_keyfile = self.encrypt_keyfile.clone();

        let progress_tx  = tx.clone();
        let progress_ctx = ctx.clone();
        let progress_cb: ProgressFn = Box::new(move |v: f32| {
            let _ = progress_tx.send(WorkerMessage::Progress(v));
            progress_ctx.request_repaint();
        });

        std::thread::spawn(move || {
            let result = encrypt_archive(
                &files, &output_path, &password, &options,
                encrypt_keyfile.as_deref(), Some(&progress_cb),
            );
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

impl Drop for CatwalkGui {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
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
    let result = encrypt(&data, password, &input_path.to_string_lossy(), options, keyfile_path, progress)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    if let Some(cb) = &progress { cb(0.90); }
    fs::write(output_path, &result).map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress { cb(1.0); }
    Ok(format!("Encrypted successfully: {}", output_path.to_string_lossy()))
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input: {}", e))?;
    let (result, extension) = decrypt(&data, password, keyfile_path, progress).map_err(|e| match e {
        CryptoError::IntegrityCheckFailed => {
            // Do NOT distinguish between wrong password and wrong keyfile.
            "Decryption failed: wrong password, wrong keyfile, or corrupted file.".to_string()
        }
        CryptoError::KeyfileRequired => {
            "This file was encrypted with a keyfile. Please select the keyfile and try again.".to_string()
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

    if let Some(cb) = &progress { cb(0.90); }
    fs::write(&final_output, result)
        .map_err(|e| format!("Failed to write output: {}", e))?;
    if let Some(cb) = &progress { cb(1.0); }
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
    let archive  = create_archive(files)?;
    let filename = format!("archive.{}", ARCHIVE_EXTENSION);
    let result = encrypt(&archive, password, &filename, options, keyfile_path, progress)
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

// ── Utility Functions ───────────────────────────────────────────────────────

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

// ── Entry Point ─────────────────────────────────────────────────────────────

pub fn run_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([750.0, 600.0])
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
