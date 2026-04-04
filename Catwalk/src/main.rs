// When built with the GUI feature, tell Windows not to open a console window
// on double-click. CLI usage (cargo run, terminal invocation) is unaffected.
#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rpassword::prompt_password;

use catwalk::crypto::{
    decrypt_stream, encrypt_stream, validate_password, EncryptOptions, ProgressFn,
};

// The in-memory API is used by the archive subcommand (feature-gated).
#[cfg(feature = "archive")]
use catwalk::crypto::{decrypt, encrypt};
use catwalk::error::CryptoError;
use catwalk::utils::display_file_info;

#[cfg(feature = "gui")]
mod gui;

// ── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "catwalk",
    about = "CATWALK: CML-Sponge AEAD file encryption tool",
    after_help = "Password requirements:\n  - Minimum 18 characters\n  - No more than 3 consecutive identical characters"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Launch the GUI (implied when no subcommand is given)
    #[arg(long)]
    gui: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file (use "-" for stdin/stdout)
    Encrypt {
        /// Input file path (or "-" for stdin)
        input: String,
        /// Output file path (or "-" for stdout)
        output: String,
        /// Strip timestamp and file extension from header
        #[arg(long)]
        no_metadata: bool,
        /// Disable compression (recommended for pre-compressed files)
        #[arg(long)]
        no_compress: bool,
        /// Optional keyfile for two-factor encryption
        #[arg(long, value_name = "PATH")]
        keyfile: Option<PathBuf>,
        /// Securely overwrite the input file after successful encryption
        #[arg(long)]
        secure_delete: bool,
    },

    /// Decrypt a file (use "-" for stdin/stdout)
    Decrypt {
        /// Input file path (or "-" for stdin)
        input: String,
        /// Output file path (or "-" for stdout)
        output: String,
        /// Overwrite output file if it already exists
        #[arg(long)]
        force: bool,
        /// Optional keyfile for two-factor decryption
        #[arg(long, value_name = "PATH")]
        keyfile: Option<PathBuf>,
    },

    /// Display header info for an encrypted file
    Info {
        /// Encrypted file path
        input: String,
    },

    /// Generate a random 64-byte keyfile
    Genkey {
        /// Output file path
        output: String,
        /// Overwrite output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Encrypt multiple files into a single encrypted archive
    #[cfg(feature = "archive")]
    Archive {
        /// Output encrypted archive path
        output: String,
        /// Input files to archive and encrypt
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Strip timestamp and file extension from header
        #[arg(long)]
        no_metadata: bool,
        /// Disable compression (recommended for pre-compressed files)
        #[arg(long)]
        no_compress: bool,
        /// Optional keyfile for two-factor encryption
        #[arg(long, value_name = "PATH")]
        keyfile: Option<PathBuf>,
        /// Securely overwrite the input files after successful encryption
        #[arg(long)]
        secure_delete: bool,
    },

    /// Decrypt an encrypted archive and extract its contents
    #[cfg(feature = "archive")]
    Extract {
        /// Encrypted archive file path
        input: String,
        /// Output directory for extracted files
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
        /// Overwrite existing files in output directory
        #[arg(long)]
        force: bool,
        /// Optional keyfile for two-factor decryption
        #[arg(long, value_name = "PATH")]
        keyfile: Option<PathBuf>,
    },
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_progress_cb() -> ProgressFn {
    use std::sync::Mutex;
    use std::time::Instant;

    struct State {
        start: Instant,
        last_phase: &'static str,
    }

    let state = Mutex::new(State {
        start: Instant::now(),
        last_phase: "",
    });

    Box::new(move |v: f32| {
        let mut st = state.lock().unwrap();
        let pct = v * 100.0;

        // Detect phase transitions and label them.
        let phase = if v < 0.06 {
            "Compressing"
        } else if v < 0.36 {
            "Deriving key"
        } else if v < 0.86 {
            "Processing"
        } else {
            "Finalizing"
        };

        // Reset timer on phase change for more accurate ETA within phases.
        if phase != st.last_phase {
            st.start = Instant::now();
            st.last_phase = phase;
        }

        let elapsed = st.start.elapsed().as_secs_f64();

        // Only show ETA during the long phases (KDF + cipher).
        if v > 0.06 && v < 0.86 {
            // Map progress into the current phase's local fraction.
            let (phase_start, phase_end) = if v < 0.36 {
                (0.05_f32, 0.35)
            } else {
                (0.35, 0.85)
            };
            let local_frac = ((v - phase_start) / (phase_end - phase_start)).clamp(0.001, 1.0);
            let eta = (elapsed / local_frac as f64) * (1.0 - local_frac as f64);

            if eta < 60.0 {
                eprint!("\r{}: {:3.0}%  ETA {:.0}s   ", phase, pct, eta);
            } else {
                eprint!(
                    "\r{}: {:3.0}%  ETA {:.0}m{:02.0}s   ",
                    phase,
                    pct,
                    eta / 60.0,
                    eta % 60.0
                );
            }
        } else {
            eprint!("\r{}: {:3.0}%   ", phase, pct);
        }

        let _ = io::stderr().flush();
    })
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<(), CryptoError> {
    let cli = Cli::parse();

    // Launch GUI when no subcommand is given (or --gui)
    #[cfg(feature = "gui")]
    if cli.command.is_none() || cli.gui {
        match gui::run_gui() {
            Ok(_) => return Ok(()),
            Err(e) => {
                eprintln!("Error starting GUI: {}", e);
                return Ok(());
            }
        }
    }

    // Without the gui feature, a missing subcommand is an error.
    #[cfg(not(feature = "gui"))]
    if cli.command.is_none() {
        eprintln!("No subcommand provided. Use --help for usage.");
        std::process::exit(1);
    }

    match cli.command.expect("guarded above: subcommand is present") {
        // ── encrypt ──────────────────────────────────────────────────────
        Command::Encrypt {
            input,
            output,
            no_metadata,
            no_compress,
            keyfile,
            secure_delete,
        } => {
            let from_stdin = input == "-";
            let to_stdout = output == "-";

            if secure_delete && from_stdin {
                eprintln!("Error: --secure-delete cannot be used with stdin.");
                std::process::exit(1);
            }

            let mut password =
                prompt_password("Enter password: ").expect("Failed to read password");

            if let Err(reason) = validate_password(&password) {
                eprintln!("Password rejected: {}", reason);
                password.clear();
                std::process::exit(1);
            }

            let confirm = prompt_password("Confirm password: ").expect("Failed to read password");
            if password != confirm {
                eprintln!("Error: Passwords do not match.");
                password.clear();
                std::process::exit(1);
            }

            let options = EncryptOptions {
                strip_metadata: no_metadata,
                skip_compression: no_compress,
            };

            let filename = if from_stdin { "stdin" } else { &input };
            let input_len = if from_stdin {
                None
            } else {
                Some(fs::metadata(&input)?.len())
            };
            let progress_cb = make_progress_cb();

            // Branch on concrete reader/writer types to satisfy generic bounds.
            macro_rules! do_encrypt {
                ($r:expr, $w:expr) => {
                    encrypt_stream(
                        $r,
                        $w,
                        &password,
                        filename,
                        &options,
                        keyfile.as_deref(),
                        Some(&progress_cb),
                        input_len,
                    )
                };
            }

            if from_stdin {
                let mut r = io::stdin().lock();
                if to_stdout {
                    do_encrypt!(&mut r, &mut io::stdout().lock())?;
                } else {
                    do_encrypt!(&mut r, &mut fs::File::create(&output)?)?;
                }
            } else {
                let mut r = fs::File::open(&input)?;
                if to_stdout {
                    do_encrypt!(&mut r, &mut io::stdout().lock())?;
                } else {
                    do_encrypt!(&mut r, &mut fs::File::create(&output)?)?;
                }
            }
            eprintln!();
            password.clear();

            eprintln!("Encryption completed successfully.");

            if secure_delete {
                catwalk::utils::secure_delete_file(Path::new(&input))?;
                eprintln!("Input file securely deleted.");
            }
        }

        // ── decrypt ──────────────────────────────────────────────────────
        Command::Decrypt {
            input,
            output,
            force,
            keyfile,
        } => {
            let from_stdin = input == "-";
            let to_stdout = output == "-";

            let password = prompt_password("Enter password: ").expect("Failed to read password");

            if !to_stdout && Path::new(&output).exists() && !force {
                eprintln!(
                    "Error: Output file {} already exists. Use --force to overwrite.",
                    output
                );
                std::process::exit(1);
            }

            let progress_cb = make_progress_cb();

            // Branch on concrete reader/writer types.
            // stdin must be buffered into a Cursor (not seekable).
            macro_rules! do_decrypt {
                ($r:expr, $w:expr) => {
                    decrypt_stream($r, $w, &password, keyfile.as_deref(), Some(&progress_cb))
                };
            }

            let extension = if from_stdin {
                let mut buf = Vec::new();
                io::stdin().lock().read_to_end(&mut buf)?;
                let mut r = Cursor::new(buf);
                if to_stdout {
                    let mut w = io::stdout().lock();
                    match do_decrypt!(&mut r, &mut w) {
                        Ok(ext) => ext,
                        Err(e) => {
                            eprintln!();
                            return Err(e);
                        }
                    }
                } else {
                    let mut w = fs::File::create(&output)?;
                    match do_decrypt!(&mut r, &mut w) {
                        Ok(ext) => ext,
                        Err(e) => {
                            eprintln!();
                            drop(w);
                            if let Err(rm_err) = fs::remove_file(&output) {
                                eprintln!(
                                    "Warning: could not remove partial output '{}': {}",
                                    output, rm_err
                                );
                            }
                            return Err(e);
                        }
                    }
                }
            } else {
                let mut r = fs::File::open(&input)?;
                if to_stdout {
                    let mut w = io::stdout().lock();
                    match do_decrypt!(&mut r, &mut w) {
                        Ok(ext) => ext,
                        Err(e) => {
                            eprintln!();
                            return Err(e);
                        }
                    }
                } else {
                    let mut w = fs::File::create(&output)?;
                    match do_decrypt!(&mut r, &mut w) {
                        Ok(ext) => ext,
                        Err(e) => {
                            eprintln!();
                            drop(w);
                            if let Err(rm_err) = fs::remove_file(&output) {
                                eprintln!(
                                    "Warning: could not remove partial output '{}': {}",
                                    output, rm_err
                                );
                            }
                            return Err(e);
                        }
                    }
                }
            };
            eprintln!();

            if !to_stdout {
                let mut final_output = PathBuf::from(&output);
                if !extension.is_empty() {
                    eprintln!("Original file extension detected: .{}", extension);
                    final_output.set_extension(&extension);
                    if final_output != Path::new(&output) {
                        fs::rename(&output, &final_output)?;
                    }
                } else {
                    eprintln!("No file extension detected in the encrypted file.");
                }
                eprintln!(
                    "Decryption completed successfully. Saved as: {}",
                    final_output.display()
                );
            } else {
                eprintln!("Decryption completed successfully.");
            }
        }

        // ── info ─────────────────────────────────────────────────────────
        Command::Info { input } => {
            if input == "-" {
                let mut buf = Vec::new();
                io::stdin().lock().read_to_end(&mut buf)?;
                display_file_info(&buf)?;
            } else {
                let data = fs::read(&input)?;
                display_file_info(&data)?;
            }
        }

        // ── archive ──────────────────────────────────────────────────────
        #[cfg(feature = "archive")]
        Command::Archive {
            output,
            files,
            no_metadata,
            no_compress,
            keyfile,
            secure_delete,
        } => {
            use catwalk::archive::{create_archive, ARCHIVE_EXTENSION};

            // Validate all input files exist before prompting for password
            for f in &files {
                if !f.exists() {
                    eprintln!("Error: File not found: {}", f.display());
                    std::process::exit(1);
                }
            }

            let mut password =
                prompt_password("Enter password: ").expect("Failed to read password");

            if let Err(reason) = validate_password(&password) {
                eprintln!("Password rejected: {}", reason);
                password.clear();
                std::process::exit(1);
            }

            let confirm = prompt_password("Confirm password: ").expect("Failed to read password");
            if password != confirm {
                eprintln!("Error: Passwords do not match.");
                password.clear();
                std::process::exit(1);
            }

            eprintln!("Creating archive from {} file(s)...", files.len());
            let archive_data = create_archive(&files)?;

            let options = EncryptOptions {
                strip_metadata: no_metadata,
                skip_compression: no_compress,
            };

            let progress_cb = make_progress_cb();
            let result = encrypt(
                &archive_data,
                &password,
                &format!("archive.{}", ARCHIVE_EXTENSION),
                &options,
                keyfile.as_deref(),
                Some(&progress_cb),
            )?;
            eprintln!();
            password.clear();

            let mut file = fs::File::create(&output)?;
            file.write_all(&result)?;
            eprintln!(
                "Archive encrypted successfully: {} ({} file(s))",
                output,
                files.len()
            );

            if secure_delete {
                for f in &files {
                    catwalk::utils::secure_delete_file(f)?;
                    eprintln!("Securely deleted: {}", f.display());
                }
            }
        }

        // ── extract ─────────────────────────────────────────────────────
        #[cfg(feature = "archive")]
        Command::Extract {
            input,
            output_dir,
            force,
            keyfile,
        } => {
            use catwalk::archive::{extract_archive, ARCHIVE_EXTENSION};

            let password = prompt_password("Enter password: ").expect("Failed to read password");

            let data = fs::read(&input)?;
            let progress_cb = make_progress_cb();
            let (result, extension) =
                decrypt(&data, &password, keyfile.as_deref(), Some(&progress_cb))?;
            eprintln!();

            if extension != ARCHIVE_EXTENSION {
                eprintln!(
                    "Error: This file is not an encrypted archive (extension: {}).",
                    if extension.is_empty() {
                        "none"
                    } else {
                        &extension
                    }
                );
                eprintln!("Use 'catwalk decrypt' for regular encrypted files.");
                std::process::exit(1);
            }

            if output_dir.exists() && !output_dir.is_dir() {
                eprintln!(
                    "Error: '{}' exists and is not a directory.",
                    output_dir.display()
                );
                std::process::exit(1);
            }

            if output_dir.is_dir()
                && !force
                && fs::read_dir(&output_dir)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            {
                eprintln!(
                    "Error: Output directory '{}' is not empty. Use --force to overwrite.",
                    output_dir.display()
                );
                std::process::exit(1);
            }

            let count = extract_archive(&result, &output_dir)?;
            eprintln!("Extracted {} file(s) to: {}", count, output_dir.display());
        }

        // ── genkey ───────────────────────────────────────────────────────
        Command::Genkey { output, force } => {
            if Path::new(&output).exists() && !force {
                eprintln!(
                    "Error: File '{}' already exists. Use --force to overwrite.",
                    output
                );
                std::process::exit(1);
            }

            use rand::RngCore;
            let mut buf = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut buf);

            let mut file = fs::File::create(&output)?;
            file.write_all(&buf)?;

            eprintln!("Keyfile written to: {}", output);
            eprintln!("Size: 64 bytes");
            eprintln!();
            eprintln!("Keep this file safe and separate from your encrypted files.");
            eprintln!("If you lose it, your encrypted data cannot be recovered.");
        }
    }

    Ok(())
}
