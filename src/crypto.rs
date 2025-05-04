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

use crate::chaos::{HenonMap, henon_warmup, logistic_map, chaotic_permutation, inverse_chaotic_permutation};
use crate::error::CryptoError;
use crate::utils::{compress_data, decompress_data};

pub mod constants {
    pub const VERSION: u8 = 3;
    pub const MAGIC: &[u8; 4] = b"AU79";
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;
    pub const LOGISTIC_SEED_LEN: usize = 8;
    pub const TIMESTAMP_LEN: usize = 8;
    pub const WARMUP_ITERATIONS: usize = 100;
    pub const CHACHA_NONCE_LEN: usize = 12;
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

    // Improve Chaotic Parameters
    let a = 1.2 + (f64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) / u64::MAX as f64) * 0.7;
    let b = 0.1 + (f64::from_le_bytes(hash.as_bytes()[8..16].try_into().unwrap()) / u64::MAX as f64) * 0.8;

    let mut rng = StdRng::from_seed(key);
    let x0 = rng.gen_range(0.0..1.0);
    let y0 = rng.gen_range(0.0..1.0);
    let logistic_seed: f64 = rng.gen_range(0.0..1.0);
    let mut henon = HenonMap::new(x0, y0, a, b);

    henon_warmup(&mut henon, WARMUP_ITERATIONS);
    henon.evolve();

    let logistic = logistic_map(logistic_seed, 3.99, compressed.len());
    let permuted_plaintext = chaotic_permutation(&compressed, &logistic);

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

pub fn decrypt(ciphertext_bundle: &[u8], password: &str) -> Result<(Vec<u8>, String), CryptoError> {
    if ciphertext_bundle.len() < 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + CHACHA_NONCE_LEN + LOGISTIC_SEED_LEN + 1 + HASH_LEN {
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

    // Fixed the parameter mismatch:
    let a = 1.2 + (f64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) / u64::MAX as f64) * 0.7;
    let b = 0.1 + (f64::from_le_bytes(hash.as_bytes()[8..16].try_into().unwrap()) / u64::MAX as f64) * 0.8;

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