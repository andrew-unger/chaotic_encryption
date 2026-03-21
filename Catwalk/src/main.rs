// When built with the GUI feature, tell Windows not to open a console window
// on double-click. CLI usage (cargo run, terminal invocation) is unaffected.
#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use rpassword::prompt_password;

// Import the library crate explicitly
use catwalk::crypto::{encrypt, decrypt, validate_password, EncryptOptions, ProgressFn};
use catwalk::error::CryptoError;
use catwalk::utils::display_file_info;

// Include GUI module (conditionally)
#[cfg(feature = "gui")]
mod gui;

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {} encrypt <input_file> <output_file> [--no-metadata] [--no-compress] [--keyfile <PATH>]", prog);
    eprintln!("  {} decrypt <input_file> <output_file> [--force] [--keyfile <PATH>]", prog);
    eprintln!("  {} info    <input_file>", prog);
    eprintln!("  {} genkey  <output_file> [--force]", prog);
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  --no-metadata   Strip timestamp and file extension from header");
    eprintln!("  --no-compress   Disable compression (recommended for pre-compressed files)");
    eprintln!("  --force         Overwrite output file if it already exists");
    eprintln!("  --keyfile PATH  Optional keyfile for two-factor encryption/decryption.");
    eprintln!("                  The keyfile path is NOT stored in the encrypted file —");
    eprintln!("                  you must remember which keyfile was used.");
    eprintln!();
    eprintln!("Password requirements:");
    eprintln!("  - Minimum 18 characters");
    eprintln!("  - No more than 3 consecutive identical characters");
}

fn make_progress_cb() -> ProgressFn {
    Box::new(|v: f32| {
        eprint!("\rProgress: {:3.0}%", v * 100.0);
        let _ = io::stderr().flush();
    })
}

/// Parse `--keyfile <PATH>` out of a flags slice; returns the path if found.
fn parse_keyfile_flag(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--keyfile" {
            if let Some(path) = iter.next() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();

    // Launch GUI when no arguments are provided, or when --gui is passed
    #[cfg(feature = "gui")]
    if args.len() <= 1 || args[1] == "--gui" {
        match gui::run_gui() {
            Ok(_) => return Ok(()),
            Err(e) => {
                eprintln!("Error starting GUI: {}", e);
                return Ok(());
            }
        }
    }

    // CLI mode requires at least a command + input file
    if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        // ── encrypt ──────────────────────────────────────────────────────────
        "encrypt" => {
            if args.len() < 4 {
                eprintln!("Output file required for encryption.");
                std::process::exit(1);
            }
            let input_file  = &args[2];
            let output_file = &args[3];
            let flags       = &args[4..];

            let mut password = prompt_password("Enter password: ")
                .expect("Failed to read password");

            if let Err(reason) = validate_password(&password) {
                eprintln!("Password rejected: {}", reason);
                password.clear(); // zeroize before exit
                std::process::exit(1);
            }

            let mut options = EncryptOptions::default();
            let keyfile_path = parse_keyfile_flag(flags);

            for arg in flags.iter().filter(|a| *a != "--keyfile") {
                match arg.as_str() {
                    "--no-metadata" => options.strip_metadata  = true,
                    "--no-compress" => options.skip_compression = true,
                    s if s.starts_with("--") => {
                        // Skip values that follow --keyfile
                        eprintln!("Warning: unknown flag '{}'. Valid flags: --no-metadata, --no-compress, --keyfile", s);
                    }
                    _ => {} // path argument that follows --keyfile
                }
            }

            let data = fs::read(input_file)?;
            let progress_cb = make_progress_cb();
            let result = encrypt(&data, &password, input_file, &options, keyfile_path.as_deref(), Some(&progress_cb))?;
            eprintln!(); // newline after progress
            password.clear();
            let mut file = fs::File::create(output_file)?;
            file.write_all(&result)?;
            println!("Encryption completed successfully.");
        }

        // ── decrypt ──────────────────────────────────────────────────────────
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Output file required for decryption.");
                std::process::exit(1);
            }
            let input_file  = &args[2];
            let output_file = &args[3];
            let flags       = &args[4..];

            let password = prompt_password("Enter password: ")
                .expect("Failed to read password");

            let force        = flags.iter().any(|a| a == "--force");
            let keyfile_path = parse_keyfile_flag(flags);

            if Path::new(output_file).exists() && !force {
                eprintln!("Error: Output file {} already exists. Use --force to overwrite.", output_file);
                std::process::exit(1);
            }

            let data = fs::read(input_file)?;
            let progress_cb = make_progress_cb();
            let (result, extension) = decrypt(&data, &password, keyfile_path.as_deref(), Some(&progress_cb))?;
            eprintln!(); // newline after progress

            let mut final_output = PathBuf::from(output_file);
            if !extension.is_empty() {
                println!("Original file extension detected: .{}", extension);
                final_output.set_extension(&extension);
            } else {
                println!("No file extension detected in the encrypted file.");
            }

            let mut file = fs::File::create(&final_output)?;
            file.write_all(&result)?;
            println!("Decryption completed successfully. Saved as: {}", final_output.display());
        }

        // ── info ─────────────────────────────────────────────────────────────
        "info" => {
            let input_file = &args[2];
            let data = fs::read(input_file)?;
            display_file_info(&data)?;
        }

        // ── genkey ───────────────────────────────────────────────────────────
        "genkey" => {
            let output_file = &args[2];
            let force = args.iter().any(|a| a == "--force");

            if Path::new(output_file).exists() && !force {
                eprintln!("Error: File '{}' already exists. Use --force to overwrite.", output_file);
                std::process::exit(1);
            }

            // Generate 64 bytes from the OS CSPRNG.
            use rand::RngCore;
            let mut buf = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut buf);

            let mut file = fs::File::create(output_file)?;
            file.write_all(&buf)?;

            println!("Keyfile written to: {}", output_file);
            println!("Size: 64 bytes");
            println!();
            println!("Keep this file safe and separate from your encrypted files.");
            println!("If you lose it, your encrypted data cannot be recovered.");
        }

        _ => {
            eprintln!("Invalid mode. Use encrypt, decrypt, info, or genkey.");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}
