use argon2::{Algorithm, Argon2, Params, Version};
use blake3;
use rand::Rng;
use subtle::ConstantTimeEq;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::chaos::{ChaoticKeystream, apply_permutation, apply_inverse_permutation};
use crate::error::CryptoError;
use crate::utils::{compress_data, decompress_data};

pub mod constants {
    pub const VERSION: u8 = 4;
    pub const MAGIC: &[u8; 4] = b"AU79";
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;
    pub const NONCE_LEN: usize = 16;
    pub const TIMESTAMP_LEN: usize = 8;

    // Argon2id defaults
    pub const ARGON2_M_LOG2: u8 = 18; // 2^18 = 262144 KiB = 256 MB
    pub const ARGON2_T_COST: u8 = 4;  // 4 iterations
    pub const ARGON2_P_COST: u8 = 1;  // 1 lane

    // Password policy
    pub const MIN_PASSWORD_LEN: usize = 18;
    pub const MAX_CONSECUTIVE_REPEAT: usize = 3;

    // Minimum header size: magic(4) + ver(1) + flags(1) + salt(16) + ts(8) + nonce(16) + argon(3) + ext_len(1) + mac(32)
    pub const MIN_HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + NONCE_LEN + 3 + 1 + HASH_LEN;
}

use constants::*;

fn derive_key(
    password: &str,
    salt: &[u8],
    timestamp: &[u8],
    m_log2: u8,
    t_cost: u8,
    p_cost: u8,
) -> Result<[u8; 32], CryptoError> {
    let m_cost = 1u32
        .checked_shl(m_log2 as u32)
        .ok_or(CryptoError::KeyDerivationFailed)?;
    let params = Params::new(m_cost, t_cost as u32, p_cost as u32, Some(32))
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    let mut combined_salt = Vec::with_capacity(salt.len() + timestamp.len());
    combined_salt.extend_from_slice(salt);
    combined_salt.extend_from_slice(timestamp);

    argon2
        .hash_password_into(password.as_bytes(), &combined_salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

fn derive_subkeys(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let chaos_key = blake3::derive_key("au79-crypto.v4.chaos", master_key);
    let mac_key = blake3::derive_key("au79-crypto.v4.mac", master_key);
    (chaos_key, mac_key)
}

/// Validate that a password meets minimum complexity requirements.
///
/// Rules:
/// - Minimum 18 characters
/// - No more than 3 consecutive identical characters
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err("Password must be at least 18 characters");
    }
    let mut run: usize = 1;
    let mut prev: Option<char> = None;
    for ch in password.chars() {
        if Some(ch) == prev {
            run += 1;
            if run > MAX_CONSECUTIVE_REPEAT {
                return Err("Too many consecutive repeating characters (max 3)");
            }
        } else {
            run = 1;
        }
        prev = Some(ch);
    }
    Ok(())
}

pub fn encrypt(plaintext: &[u8], password: &str, input_filename: &str) -> Result<Vec<u8>, CryptoError> {
    let compressed = compress_data(plaintext)?;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt);

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::SystemTimeError)?
        .as_secs()
        .to_le_bytes();

    // Key derivation with explicit Argon2id parameters
    let m_log2 = ARGON2_M_LOG2;
    let t_cost = ARGON2_T_COST;
    let p_cost = ARGON2_P_COST;

    let mut master_key = derive_key(password, &salt, &timestamp, m_log2, t_cost, p_cost)?;
    let (mut chaos_key, mac_key) = derive_subkeys(&master_key);
    master_key.zeroize();

    // Initialize chaotic keystream
    let mut keystream = ChaoticKeystream::new(&chaos_key, &nonce);
    chaos_key.zeroize();

    // Chaotic permutation (Fisher-Yates driven by keystream)
    let perm = keystream.generate_permutation(compressed.len());
    let permuted = apply_permutation(&compressed, &perm);

    // Chaotic XOR encryption
    let mut ciphertext = permuted;
    keystream.apply_keystream(&mut ciphertext);

    // Original file extension
    let extension = Path::new(input_filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let ext_len = extension.len() as u8;

    // MAC over ALL header fields and ciphertext
    let mut mac = blake3::Hasher::new_keyed(&mac_key);
    mac.update(MAGIC);
    mac.update(&[VERSION]);
    mac.update(&[0]); // flags
    mac.update(&salt);
    mac.update(&timestamp);
    mac.update(&nonce);
    mac.update(&[m_log2]);
    mac.update(&[t_cost]);
    mac.update(&[p_cost]);
    mac.update(&[ext_len]);
    mac.update(&extension);
    mac.update(&ciphertext);
    let final_mac = mac.finalize();

    // Assemble output
    let mut result = Vec::with_capacity(
        MIN_HEADER_LEN + extension.len() + ciphertext.len(),
    );
    result.extend_from_slice(MAGIC);
    result.push(VERSION);
    result.push(0); // flags reserved
    result.extend_from_slice(&salt);
    result.extend_from_slice(&timestamp);
    result.extend_from_slice(&nonce);
    result.push(m_log2);
    result.push(t_cost);
    result.push(p_cost);
    result.push(ext_len);
    result.extend_from_slice(&extension);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(final_mac.as_bytes());

    Ok(result)
}

pub fn decrypt(ciphertext_bundle: &[u8], password: &str) -> Result<(Vec<u8>, String), CryptoError> {
    if ciphertext_bundle.len() < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    // Parse header
    let magic = &ciphertext_bundle[..4];
    if magic != MAGIC {
        return Err(CryptoError::InvalidMagicBytes);
    }

    let version = ciphertext_bundle[4];
    if version != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    // let _flags = ciphertext_bundle[5]; // reserved

    let salt_start = 6;
    let ts_start = salt_start + SALT_LEN;
    let nonce_start = ts_start + TIMESTAMP_LEN;
    let argon_start = nonce_start + NONCE_LEN;
    let ext_len_pos = argon_start + 3;

    let salt = &ciphertext_bundle[salt_start..ts_start];
    let timestamp = &ciphertext_bundle[ts_start..nonce_start];
    let nonce_bytes = &ciphertext_bundle[nonce_start..argon_start];
    let m_log2 = ciphertext_bundle[argon_start];
    let t_cost = ciphertext_bundle[argon_start + 1];
    let p_cost = ciphertext_bundle[argon_start + 2];

    let ext_len = ciphertext_bundle[ext_len_pos] as usize;
    let ext_start = ext_len_pos + 1;
    let cipher_start = ext_start + ext_len;
    let mac_start = ciphertext_bundle.len() - HASH_LEN;

    if cipher_start > mac_start {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let extension = &ciphertext_bundle[ext_start..cipher_start];
    let encrypted = &ciphertext_bundle[cipher_start..mac_start];
    let stored_mac = &ciphertext_bundle[mac_start..];

    // Key derivation using stored Argon2 parameters
    let mut master_key = derive_key(password, salt, timestamp, m_log2, t_cost, p_cost)?;
    let (mut chaos_key, mac_key) = derive_subkeys(&master_key);
    master_key.zeroize();

    // Verify MAC before any decryption
    let mut mac = blake3::Hasher::new_keyed(&mac_key);
    mac.update(magic);
    mac.update(&[version]);
    mac.update(&[0]); // flags
    mac.update(salt);
    mac.update(timestamp);
    mac.update(nonce_bytes);
    mac.update(&[m_log2]);
    mac.update(&[t_cost]);
    mac.update(&[p_cost]);
    mac.update(&[ext_len as u8]);
    mac.update(extension);
    mac.update(encrypted);
    let expected_mac = mac.finalize();

    if expected_mac.as_bytes().ct_eq(stored_mac).unwrap_u8() != 1 {
        chaos_key.zeroize();
        return Err(CryptoError::IntegrityCheckFailed);
    }

    // Initialize chaotic keystream with same key and nonce
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertextLength)?;
    let mut keystream = ChaoticKeystream::new(&chaos_key, &nonce);
    chaos_key.zeroize();

    // Generate same permutation (advances keystream identically to encrypt)
    let perm = keystream.generate_permutation(encrypted.len());

    // Chaotic XOR decryption
    let mut decrypted = encrypted.to_vec();
    keystream.apply_keystream(&mut decrypted);

    // Inverse permutation
    let unpermuted = apply_inverse_permutation(&decrypted, &perm);

    // Decompress
    let extension_str = String::from_utf8_lossy(extension).to_string();
    Ok((decompress_data(&unpermuted)?, extension_str))
}
