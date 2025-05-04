use argon2::Argon2;
use blake3;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use rayon;

// Constants
const VERSION: u8 = 3;
const MAGIC: &[u8; 4] = b"AU79";
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
const LOGISTIC_SEED_LEN: usize = 8;
const TIMESTAMP_LEN: usize = 8;
const WARMUP_ITERATIONS: usize = 100;
const CHACHA_NONCE_LEN: usize = 12;

#[derive(Debug)]
enum CryptoError {
    KeyDerivationFailed,
    IntegrityCheckFailed,
    InvalidCiphertextLength,
    IoError(io::Error),
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> CryptoError {
        CryptoError::IoError(err)
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed."),
            CryptoError::IntegrityCheckFailed => write!(f, "Integrity check failed."),
            CryptoError::InvalidCiphertextLength => write!(f, "Invalid ciphertext length."),
            CryptoError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

struct HenonMap {
    x: f64,
    y: f64,
    a: f64,
    b: f64,
}

impl HenonMap {
    fn new(x: f64, y: f64, a: f64, b: f64) -> Self {
        HenonMap { x, y, a, b }
    }

    fn iterate(&mut self) -> f64 {
        let next_x = 1.0 - self.a * self.x.powi(2) + self.y;
        let next_y = self.b * self.x;
        self.x = next_x;
        self.y = next_y;
        self.x
    }

    fn evolve(&mut self) {
        self.a = (self.a + self.iterate()).fract();
        self.b = (self.b + self.iterate()).fract();
    }
}

fn henon_warmup(h: &mut HenonMap, rounds: usize) {
    for _ in 0..rounds {
        h.iterate();
    }
}

fn logistic_map(mut x: f64, r: f64, len: usize) -> Vec<f64> {
    let mut result = vec![0.0f64; len];
    for i in 0..len {
        x = r * x * (1.0 - x);
        result[i] = x;
    }
    result
}

fn chaotic_permutation(input: &[u8], chaos_sequence: &[f64]) -> Vec<u8> {
    use rayon::prelude::*;
    let mut indices: Vec<(usize, f64)> = chaos_sequence.iter().cloned().enumerate().collect();
    indices.par_sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    indices.par_iter().map(|(orig_idx, _)| input[*orig_idx]).collect()
}

fn inverse_chaotic_permutation(input: &[u8], chaos_sequence: &[f64]) -> Vec<u8> {
    use rayon::prelude::*;
    let mut indices: Vec<(usize, f64)> = chaos_sequence.iter().cloned().enumerate().collect();
    indices.par_sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut inverse = vec![0usize; input.len()];
    for (i, (orig_idx, _)) in indices.iter().enumerate() {
        inverse[*orig_idx] = i;
    }
    (0..input.len()).into_par_iter().map(|i| input[inverse[i]]).collect()
}

fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    io::copy(&mut decoder, &mut decompressed)?;
    Ok(decompressed)
}

fn derive_key(password: &str, salt: &[u8], timestamp: &[u8]) -> Result<[u8; 32], CryptoError> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    let mut combined_salt = Vec::new();
    combined_salt.extend_from_slice(salt);
    combined_salt.extend_from_slice(timestamp);
    argon2
        .hash_password_into(password.as_bytes(), &combined_salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

fn generate_unique_nonce(key: &[u8], timestamp: &[u8]) -> [u8; CHACHA_NONCE_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(timestamp);
    hasher.update(&rand::thread_rng().gen::<[u8; 16]>());
    let hash = hasher.finalize();
    let mut nonce = [0u8; CHACHA_NONCE_LEN];
    nonce.copy_from_slice(&hash.as_bytes()[..CHACHA_NONCE_LEN]);
    nonce
}

fn encrypt(plaintext: &[u8], password: &str, input_filename: &str) -> Result<Vec<u8>, CryptoError> {
    let compressed = compress_data(plaintext)?;

    let mut salt_bytes = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt_bytes);

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::IoError(io::Error::new(io::ErrorKind::Other, "System time error")))?
        .as_secs()
        .to_le_bytes();

    let mut key = derive_key(password, &salt_bytes, &timestamp)?;
    let hash = blake3::hash(&key);

// Improve Chaotic Parameters - Fixed version
    let a = 1.2 + (f64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) / u64::MAX as f64) * 0.7;
    let b = 0.1 + (f64::from_le_bytes(hash.as_bytes()[8..16].try_into().unwrap()) / u64::MAX as f64) * 0.8;

    let mut rng = StdRng::from_seed(key);
    let x0 = rng.gen_range(0.0..1.0);
    let y0 = rng.gen_range(0.0..1.0);
    let logistic_seed = rng.gen_range(0.0..1.0);
    let mut henon = HenonMap::new(x0, y0, a, b);

    henon_warmup(&mut henon, WARMUP_ITERATIONS);
    henon.evolve();

    let logistic = logistic_map(logistic_seed, 3.99, compressed.len());
    let permuted_plaintext = chaotic_permutation(&compressed, &logistic);

    let mut nonce = generate_unique_nonce(&key, &timestamp);
    rand::thread_rng().fill(&mut nonce);

    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    let mut ciphertext = permuted_plaintext.clone();
    cipher.apply_keystream(&mut ciphertext);

    let extension = Path::new(input_filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let extension_len = extension.len() as u8;

    let mut mac = blake3::Hasher::new_keyed(&key);
    mac.update(MAGIC);
    mac.update(&[VERSION]);
    mac.update(&[0]); // Flags reserved
    mac.update(&salt_bytes);
    mac.update(&timestamp);
    mac.update(&nonce);
    mac.update(&ciphertext);
    mac.update(&[extension_len]);
    mac.update(&extension);
    let final_mac = mac.finalize();

    let logistic_bytes = logistic_seed.to_le_bytes();

    key[..].zeroize();

    let mut result = Vec::new();
    result.extend_from_slice(MAGIC);
    result.push(VERSION);
    result.push(0); // Flags
    result.extend_from_slice(&salt_bytes);
    result.extend_from_slice(&timestamp);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&logistic_bytes);
    result.push(extension_len);
    result.extend_from_slice(&extension);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(final_mac.as_bytes());
    Ok(result)
}

fn decrypt(ciphertext_bundle: &[u8], password: &str) -> Result<(Vec<u8>, String), CryptoError> {
    if ciphertext_bundle.len() < 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + CHACHA_NONCE_LEN + LOGISTIC_SEED_LEN + 1 + HASH_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let magic = &ciphertext_bundle[..4];
    if magic != MAGIC {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let version = ciphertext_bundle[4];
    if version != VERSION {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let salt_start = 6;
    let timestamp_start = salt_start + SALT_LEN;
    let nonce_start = timestamp_start + TIMESTAMP_LEN;
    let logistic_start = nonce_start + CHACHA_NONCE_LEN;
    let ext_len_start = logistic_start + LOGISTIC_SEED_LEN;

    let extension_len = ciphertext_bundle[ext_len_start] as usize;
    let ext_start = ext_len_start + 1;
    let cipher_start = ext_start + extension_len;
    let mac_start = ciphertext_bundle.len() - HASH_LEN;

    if cipher_start > mac_start {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let salt_bytes = &ciphertext_bundle[salt_start..timestamp_start];
    let timestamp = &ciphertext_bundle[timestamp_start..nonce_start];
    let nonce = &ciphertext_bundle[nonce_start..logistic_start];
    let logistic_bytes = &ciphertext_bundle[logistic_start..ext_len_start];
    let extension = &ciphertext_bundle[ext_start..cipher_start];
    let encrypted = &ciphertext_bundle[cipher_start..mac_start];
    let mac_bytes = &ciphertext_bundle[mac_start..];

    let mut key = derive_key(password, salt_bytes, timestamp)?;

    let mut mac = blake3::Hasher::new_keyed(&key);
    mac.update(magic);
    mac.update(&[version]);
    mac.update(&[0]); // Flags
    mac.update(salt_bytes);
    mac.update(timestamp);
    mac.update(nonce);
    mac.update(encrypted);
    mac.update(&[extension_len as u8]);
    mac.update(extension);
    let expected_mac = mac.finalize();

    if expected_mac.as_bytes().ct_eq(mac_bytes).unwrap_u8() != 1 {
        return Err(CryptoError::IntegrityCheckFailed);
    }

    let hash = blake3::hash(&key);

    let a = 1.35 + (hash.as_bytes()[0] as f64) / 100.0;
    let b = 0.25 + (hash.as_bytes()[1] as f64) / 100.0;

    let mut rng = StdRng::from_seed(key);
    let x0 = rng.gen_range(0.0..1.0);
    let y0 = rng.gen_range(0.0..1.0);
    let logistic_seed = f64::from_le_bytes(logistic_bytes.try_into().unwrap());

    let mut henon = HenonMap::new(x0, y0, a, b);
    henon_warmup(&mut henon, WARMUP_ITERATIONS);
    henon.evolve();

    let mut cipher = ChaCha20::new((&key).into(), (nonce).into());
    let mut decrypted = encrypted.to_vec();
    cipher.apply_keystream(&mut decrypted);

    let logistic = logistic_map(logistic_seed, 3.99, decrypted.len());
    let unpermuted = inverse_chaotic_permutation(&decrypted, &logistic);

    key[..].zeroize();
    let extension_str = String::from_utf8_lossy(extension).to_string();
    Ok((decompress_data(&unpermuted)?, extension_str))
}

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();

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
            if &data[..4] != MAGIC {
                eprintln!("This file is not a valid AU79 encrypted file.");
                return Ok(());
            }
            let version = data[4];
            let flags = data[5];
            let timestamp_start = 6 + SALT_LEN;
            let timestamp = u64::from_le_bytes(data[timestamp_start..timestamp_start+8].try_into().unwrap());
            let logistic_seed = f64::from_le_bytes(data[timestamp_start+8+12..timestamp_start+8+12+8].try_into().unwrap());
            let ext_len = data[timestamp_start+8+12+8];
            let ext_start = timestamp_start+8+12+8+1;
            let extension = &data[ext_start..ext_start+(ext_len as usize)];
            println!("----- File Info -----");
            println!("Version: {}", version);
            println!("Flags: {}", flags);
            println!("Timestamp (Unix Epoch): {}", timestamp);
            println!("Logistic Seed: {}", logistic_seed);
            println!("Original Extension: .{}", String::from_utf8_lossy(extension));
            println!("----------------------");
        }
        _ => {
            eprintln!("Invalid mode. Use encrypt, decrypt, or info.");
        }
    }

    Ok(())
}

