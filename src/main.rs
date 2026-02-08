use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use rpassword::prompt_password;

// Import the library crate explicitly
use au79_crypto::crypto::{encrypt, decrypt, validate_password};
use au79_crypto::error::CryptoError;
use au79_crypto::utils::display_file_info;

// Include GUI module (conditionally)
#[cfg(feature = "gui")]
mod gui;

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
        eprintln!("Usage:");
        eprintln!("  {} encrypt <input_file> <output_file>", args[0]);
        eprintln!("  {} decrypt <input_file> <output_file> [--force]", args[0]);
        eprintln!("  {} info <input_file>", args[0]);
        return Ok(());
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
                return Ok(());
            }
            if let Err(reason) = validate_password(password.as_ref().unwrap()) {
                eprintln!("Password rejected: {}", reason);
                return Ok(());
            }
            let output_file = &args[3];
            let result = encrypt(&data, password.as_ref().unwrap(), input_file)?;
            let mut file = fs::File::create(output_file)?;
            file.write_all(&result)?;
            println!("Encryption completed successfully.");
        }
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Output file required for decryption.");
                return Ok(());
            }
            let output_file = &args[3];
            let force = args.iter().any(|arg| arg == "--force");

            if Path::new(output_file).exists() && !force {
                eprintln!("Error: Output file {} already exists. Use --force to overwrite.", output_file);
                return Ok(());
            }

            let (result, extension) = decrypt(&data, password.as_ref().unwrap())?;
            let mut final_output = output_file.clone();
            if !extension.is_empty() {
                println!("Original file extension detected: .{}", extension);
                final_output.push('.');
                final_output.push_str(&extension);
            } else {
                println!("No file extension detected in the encrypted file.");
            }

            let mut file = fs::File::create(&final_output)?;
            file.write_all(&result)?;
            println!("Decryption completed successfully. Saved as: {}", final_output);
        }
        "info" => {
            display_file_info(&data)?;
        }
        _ => {
            eprintln!("Invalid mode. Use encrypt, decrypt, or info.");
        }
    }

    Ok(())
}