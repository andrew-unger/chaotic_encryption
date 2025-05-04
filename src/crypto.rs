use argon2::Argon2;
use blake3;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use subtle::ConstantTimeEq;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::chaos::{ChenSystem, TentMap, RabinovichFabrikantSystem, chen_warmup,
                   tent_warmup, rf_warmup, interlaced_chaos_sequence,
                   chaotic_permutation, inverse_chaotic_permutation};
use crate::error::CryptoError;
use crate::utils::{compress_data, decompress_data};

pub mod constants {
    pub const VERSION: u8 = 3;
    pub const MAGIC: &[u8; 4] = b"AU79";
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;
    pub const TENT_SEED_LEN: usize = 8;
    pub const TIMESTAMP_LEN: usize = 8;
    pub const WARMUP_ITERATIONS: usize = 100;
    pub const CHACHA_NONCE_LEN: usize = 12;
    
    // Chen system parameters
    pub const CHEN_DT: f64 = 0.01;
    
    // Rabinovich-Fabrikant parameters
    pub const RF_DT: f64 = 0.01;
}

use constants::*;

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

pub fn encrypt(plaintext: &[u8], password: &str, input_filename: &str) -> Result<Vec<u8>, CryptoError> {
    let compressed = compress_data(plaintext)?;

    let mut salt_bytes = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt_bytes);

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::SystemTimeError)?
        .as_secs()
        .to_le_bytes();

    let mut key = derive_key(password, &salt_bytes, &timestamp)?;
    let hash = blake3::hash(&key);

    // Extract parameters for Chen system
    let chen_a = 35.0 + (hash.as_bytes()[0] as f64) / 255.0;
    let chen_b = 3.0 + (hash.as_bytes()[1] as f64) / 255.0;
    let chen_c = 28.0 + (hash.as_bytes()[2] as f64) / 255.0;
    
    // Extract parameters for Tent Map
    let tent_mu = 1.5 + (hash.as_bytes()[3] as f64) / 255.0;
    
    // Extract parameters for Rabinovich-Fabrikant system
    let rf_alpha = 0.1 + (hash.as_bytes()[4] as f64) / 255.0;
    let rf_gamma = 0.1 + (hash.as_bytes()[5] as f64) / 255.0;

    let mut rng = StdRng::from_seed(key);
    
    // Initialize chaotic systems
    let chen_x0 = rng.gen_range(-10.0..10.0);
    let chen_y0 = rng.gen_range(-10.0..10.0);
    let chen_z0 = rng.gen_range(0.0..30.0);
    
    let tent_x0 = rng.gen_range(0.1..0.9); // Avoid fixed points at 0 and 1
    
    let rf_x0 = rng.gen_range(-1.0..1.0);
    let rf_y0 = rng.gen_range(-1.0..1.0);
    let rf_z0 = rng.gen_range(0.0..1.0);
    
    // Create chaotic systems
    let mut chen = ChenSystem::new(chen_x0, chen_y0, chen_z0, chen_a, chen_b, chen_c, CHEN_DT);
    let mut tent = TentMap::new(tent_x0, tent_mu);
    let mut rf = RabinovichFabrikantSystem::new(rf_x0, rf_y0, rf_z0, rf_alpha, rf_gamma, RF_DT);

    // Warm up the chaotic systems
    chen_warmup(&mut chen, WARMUP_ITERATIONS);
    tent_warmup(&mut tent, WARMUP_ITERATIONS);
    rf_warmup(&mut rf, WARMUP_ITERATIONS);
    
    // Evolve the systems to make them more unpredictable
    chen.evolve();
    tent.evolve();
    rf.evolve();

    // Generate interlaced chaos sequence
    let chaos_sequence = interlaced_chaos_sequence(&mut chen, &mut tent, &mut rf, compressed.len());
    
    // Perform permutation
    let permuted_plaintext = chaotic_permutation(&compressed, &chaos_sequence);

    // Continue with ChaCha20 encryption
    let nonce = generate_unique_nonce(&key, &timestamp);

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

    // Store the tent map's initial value for decryption
    let tent_bytes = tent_x0.to_le_bytes();

    key[..].zeroize();

    let mut result = Vec::new();
    result.extend_from_slice(MAGIC);
    result.push(VERSION);
    result.push(0); // Flags
    result.extend_from_slice(&salt_bytes);
    result.extend_from_slice(&timestamp);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&tent_bytes);
    result.push(extension_len);
    result.extend_from_slice(&extension);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(final_mac.as_bytes());
    Ok(result)
}

pub fn decrypt(ciphertext_bundle: &[u8], password: &str) -> Result<(Vec<u8>, String), CryptoError> {
    if ciphertext_bundle.len() < 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + CHACHA_NONCE_LEN + TENT_SEED_LEN + 1 + HASH_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let magic = &ciphertext_bundle[..4];
    if magic != MAGIC {
        return Err(CryptoError::InvalidMagicBytes);
    }

    let version = ciphertext_bundle[4];
    if version != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    let salt_start = 6;
    let timestamp_start = salt_start + SALT_LEN;
    let nonce_start = timestamp_start + TIMESTAMP_LEN;
    let tent_start = nonce_start + CHACHA_NONCE_LEN;
    let ext_len_start = tent_start + TENT_SEED_LEN;

    let extension_len = ciphertext_bundle[ext_len_start] as usize;
    let ext_start = ext_len_start + 1;
    let cipher_start = ext_start + extension_len;
    let mac_start = ciphertext_bundle.len() - HASH_LEN;

    if cipher_start > mac_start {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let salt_bytes = &ciphertext_bundle[salt_start..timestamp_start];
    let timestamp = &ciphertext_bundle[timestamp_start..nonce_start];
    let nonce = &ciphertext_bundle[nonce_start..tent_start];
    let tent_bytes = &ciphertext_bundle[tent_start..ext_len_start];
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

    // Extract parameters for Chen system - matching the encrypt function
    let chen_a = 35.0 + (hash.as_bytes()[0] as f64) / 255.0;
    let chen_b = 3.0 + (hash.as_bytes()[1] as f64) / 255.0;
    let chen_c = 28.0 + (hash.as_bytes()[2] as f64) / 255.0;
    
    // Extract parameters for Tent Map
    let tent_mu = 1.5 + (hash.as_bytes()[3] as f64) / 255.0;
    
    // Extract parameters for Rabinovich-Fabrikant system
    let rf_alpha = 0.1 + (hash.as_bytes()[4] as f64) / 255.0;
    let rf_gamma = 0.1 + (hash.as_bytes()[5] as f64) / 255.0;

    let mut rng = StdRng::from_seed(key);
    
    // Initialize chaotic systems with identical parameters
    let chen_x0 = rng.gen_range(-10.0..10.0);
    let chen_y0 = rng.gen_range(-10.0..10.0);
    let chen_z0 = rng.gen_range(0.0..30.0);
    
    let tent_x0 = f64::from_le_bytes(tent_bytes.try_into().unwrap());
    
    let rf_x0 = rng.gen_range(-1.0..1.0);
    let rf_y0 = rng.gen_range(-1.0..1.0);
    let rf_z0 = rng.gen_range(0.0..1.0);
    
    // Create chaotic systems
    let mut chen = ChenSystem::new(chen_x0, chen_y0, chen_z0, chen_a, chen_b, chen_c, CHEN_DT);
    let mut tent = TentMap::new(tent_x0, tent_mu);
    let mut rf = RabinovichFabrikantSystem::new(rf_x0, rf_y0, rf_z0, rf_alpha, rf_gamma, RF_DT);

    // Warm up the chaotic systems
    chen_warmup(&mut chen, WARMUP_ITERATIONS);
    tent_warmup(&mut tent, WARMUP_ITERATIONS);
    rf_warmup(&mut rf, WARMUP_ITERATIONS);
    
    // Evolve the systems
    chen.evolve();
    tent.evolve();
    rf.evolve();

    // First decrypt with ChaCha20
    let mut cipher = ChaCha20::new((&key).into(), (nonce).into());
    let mut decrypted = encrypted.to_vec();
    cipher.apply_keystream(&mut decrypted);

    // Generate the same interlaced chaos sequence
    let chaos_sequence = interlaced_chaos_sequence(&mut chen, &mut tent, &mut rf, decrypted.len());
    
    // Reverse the permutation
    let unpermuted = inverse_chaotic_permutation(&decrypted, &chaos_sequence);

    key[..].zeroize();
    let extension_str = String::from_utf8_lossy(extension).to_string();
    Ok((decompress_data(&unpermuted)?, extension_str))
}