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
    eprintln!("  {} encrypt <input_file> <output_file> [--no-metadata] [--no-compress]", prog);
    eprintln!("  {} decrypt <input_file> <output_file> [--force]", prog);
    eprintln!("  {} info    <input_file>", prog);
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  --no-metadata   Strip timestamp and file extension from header");
    eprintln!("  --no-compress   Disable compression (recommended for pre-compressed files)");
    eprintln!("  --force         Overwrite output file if it already exists (decrypt only)");
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
    let input_file = &args[2];
    let password: Option<String> = if mode == "encrypt" || mode == "decrypt" {
        Some(prompt_password("Enter password: ").expect("Failed to read password"))
    } else {
        None
    };

    let data = fs::read(input_file)?;

    match mode.as_str() {
        "encrypt" => {
            if args.len() < 4 {
                eprintln!("Output file required for encryption.");
                std::process::exit(1);
            }
            if let Err(reason) = validate_password(password.as_ref().unwrap()) {
                eprintln!("Password rejected: {}", reason);
                std::process::exit(1);
            }
            let output_file = &args[3];

            let mut options = EncryptOptions::default();
            for arg in &args[4..] {
                match arg.as_str() {
                    "--no-metadata" => options.strip_metadata = true,
                    "--no-compress" => options.skip_compression = true,
                    _ => eprintln!("Warning: unknown flag '{}'. Valid flags: --no-metadata, --no-compress", arg),
                }
            }

            let progress_cb = make_progress_cb();
            let result = encrypt(&data, password.as_ref().unwrap(), input_file, &options, Some(&progress_cb))?;
            eprintln!(); // newline after progress
            let mut file = fs::File::create(output_file)?;
            file.write_all(&result)?;
            println!("Encryption completed successfully.");
        }
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Output file required for decryption.");
                std::process::exit(1);
            }
            let output_file = &args[3];
            let force = args.iter().any(|arg| arg == "--force");

            if Path::new(output_file).exists() && !force {
                eprintln!("Error: Output file {} already exists. Use --force to overwrite.", output_file);
                std::process::exit(1);
            }

            let progress_cb = make_progress_cb();
            let (result, extension) = decrypt(&data, password.as_ref().unwrap(), Some(&progress_cb))?;
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
        "info" => {
            display_file_info(&data)?;
        }
        _ => {
            eprintln!("Invalid mode. Use encrypt, decrypt, or info.");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}
