use argon2::{Algorithm, Argon2, Params, Version};
use blake3;
use rand::Rng;
use subtle::ConstantTimeEq;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::chaos::ChaoticKeystream;
use crate::error::CryptoError;
use crate::utils::{compress_data, decompress_data};

/// Progress callback type: receives a value in [0.0, 1.0].
pub type ProgressFn = Box<dyn Fn(f32) + Send>;

/// Call the progress callback if present.
#[inline]
fn report(progress: &Option<&ProgressFn>, value: f32) {
    if let Some(cb) = progress {
        cb(value);
    }
}

// ── Platform-specific memory locking (best-effort) ──────────────────────────

#[cfg(target_os = "windows")]
extern "system" {
    fn VirtualLock(lpAddress: *const u8, dwSize: usize) -> i32;
    fn VirtualUnlock(lpAddress: *const u8, dwSize: usize) -> i32;
}

#[cfg(target_os = "windows")]
fn lock_memory(ptr: *const u8, size: usize) -> bool {
    unsafe { VirtualLock(ptr, size) != 0 }
}

#[cfg(target_os = "windows")]
fn unlock_memory(ptr: *const u8, size: usize) {
    unsafe { let _ = VirtualUnlock(ptr, size); }
}

#[cfg(not(target_os = "windows"))]
fn lock_memory(_ptr: *const u8, _size: usize) -> bool { true }

#[cfg(not(target_os = "windows"))]
fn unlock_memory(_ptr: *const u8, _size: usize) {}

/// RAII wrapper that heap-allocates key material, attempts to page-lock it,
/// and unconditionally zeroizes on drop.
///
/// Heap allocation (Box) keeps key material off the stack and extends its
/// lifetime to exactly the scope of this wrapper. VirtualLock is attempted
/// on Windows but may silently fail if the heap address is not page-aligned
/// (32 bytes rarely spans a full 4 KB page). Zeroize always runs regardless.
struct LockedBuffer {
    data: Box<[u8; 32]>,
    locked: bool,
}

impl LockedBuffer {
    fn new(mut src: [u8; 32]) -> Self {
        // Copy to heap first, then zeroize the stack copy to minimize exposure
        let mut boxed = Box::new([0u8; 32]);
        boxed.copy_from_slice(&src);
        src.zeroize();
        let ptr = boxed.as_ptr();
        let locked = lock_memory(ptr, 32);
        Self { data: boxed, locked }
    }

    fn get(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            unlock_memory(self.data.as_ptr(), 32);
        }
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

pub mod constants {
    pub const VERSION: u8 = 7;
    pub const MAGIC: &[u8; 4] = b"AU79";
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;
    pub const NONCE_LEN: usize = 16;
    pub const TIMESTAMP_LEN: usize = 8;

    // Argon2id defaults
    pub const ARGON2_M_LOG2: u8 = 18; // 2^18 = 262144 KiB = 256 MB
    pub const ARGON2_T_COST: u8 = 4;  // 4 iterations
    pub const ARGON2_P_COST: u8 = 1;  // 1 lane

    // Minimum safe Argon2id parameters accepted on decryption.
    // Prevents a downgrade timing oracle where a modified header forces
    // cheap KDF evaluation before MAC rejection.
    pub const ARGON2_M_LOG2_MIN: u8 = 16; // 64 MB minimum
    pub const ARGON2_T_COST_MIN: u8 = 2;  // 2 iterations minimum

    // Password policy
    pub const MIN_PASSWORD_LEN: usize = 18;
    pub const MAX_CONSECUTIVE_REPEAT: usize = 3;

    // Flags byte bit definitions
    pub const FLAG_STRIP_METADATA: u8 = 0x01;
    pub const FLAG_NO_COMPRESS: u8 = 0x02;

    // Minimum header size: magic(4) + ver(1) + flags(1) + salt(16) + ts(8) + nonce(16) + argon(3) + ext_len(1) + mac(32)
    pub const MIN_HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + NONCE_LEN + 3 + 1 + HASH_LEN;
}

use constants::*;

// ── Encrypt Options ──────────────────────────────────────────────────────────

/// Options controlling encryption behavior.
#[derive(Debug, Clone, Copy)]
pub struct EncryptOptions {
    /// Strip timestamp and file extension from header (flags bit 0).
    pub strip_metadata: bool,
    /// Skip compression — encrypt raw plaintext (flags bit 1).
    ///
    /// Default is `true` (no compression). Enabling compression can improve
    /// output size for compressible data but risks a compression oracle if
    /// an adversary can influence plaintext content alongside a known secret.
    pub skip_compression: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            strip_metadata: false,
            // Safe default: compression off. Compression leaks plaintext length
            // information (CRIME-style oracle) and is opt-in rather than opt-out.
            skip_compression: true,
        }
    }
}

// ── Key Derivation ───────────────────────────────────────────────────────────

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
    // Version-locked context strings prevent cross-version key confusion
    let chaos_key = blake3::derive_key("au79-crypto.v7.chaos", master_key);
    let mac_key = blake3::derive_key("au79-crypto.v7.mac", master_key);
    (chaos_key, mac_key)
}

// ── Password Validation ──────────────────────────────────────────────────────

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

// ── Encrypt ──────────────────────────────────────────────────────────────────

pub fn encrypt(
    plaintext: &[u8],
    password: &str,
    input_filename: &str,
    options: &EncryptOptions,
    progress: Option<&ProgressFn>,
) -> Result<Vec<u8>, CryptoError> {
    let progress = &progress;

    // Phase 1: Compression (0.00 → 0.05)
    report(progress, 0.0);
    let data = if options.skip_compression {
        plaintext.to_vec()
    } else {
        compress_data(plaintext)?
    };
    report(progress, 0.05);

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt);

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);

    // Optionally strip timestamp
    let timestamp = if options.strip_metadata {
        [0u8; 8]
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::SystemTimeError)?
            .as_secs()
            .to_le_bytes()
    };

    // Phase 2: Argon2id KDF (0.05 → 0.35)
    let m_log2 = ARGON2_M_LOG2;
    let t_cost = ARGON2_T_COST;
    let p_cost = ARGON2_P_COST;

    let master_key = LockedBuffer::new(
        derive_key(password, &salt, &timestamp, m_log2, t_cost, p_cost)?
    );
    let (chaos_key_raw, mac_key_raw) = derive_subkeys(master_key.get());
    let chaos_key = LockedBuffer::new(chaos_key_raw);
    let mac_key = LockedBuffer::new(mac_key_raw);
    report(progress, 0.35);

    // Phase 3: XOR keystream (0.35 → 0.85)
    let mut keystream = ChaoticKeystream::new(chaos_key.get(), &nonce);
    let mut ciphertext = data;
    const CHUNK: usize = 65536;
    let total_len = ciphertext.len();
    if total_len > 0 {
        let mut offset = 0;
        while offset < total_len {
            let end = (offset + CHUNK).min(total_len);
            keystream.apply_keystream(&mut ciphertext[offset..end]);
            offset = end;
            if progress.is_some() {
                let frac = offset as f32 / total_len as f32;
                report(progress, 0.35 + frac * 0.50);
            }
        }
    }
    report(progress, 0.85);

    // Original file extension (optionally stripped)
    let extension = if options.strip_metadata {
        Vec::new()
    } else {
        Path::new(input_filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };
    let ext_len = extension.len() as u8;

    // Build flags byte
    let mut flags: u8 = 0;
    if options.strip_metadata {
        flags |= FLAG_STRIP_METADATA;
    }
    if options.skip_compression {
        flags |= FLAG_NO_COMPRESS;
    }

    // Phase 4: MAC + assembly (0.85 → 0.90)
    let mut mac = blake3::Hasher::new_keyed(mac_key.get());
    mac.update(MAGIC);
    mac.update(&[VERSION]);
    mac.update(&[flags]);
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
    result.push(flags);
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

    report(progress, 0.90);
    Ok(result)
}

// ── Decrypt ──────────────────────────────────────────────────────────────────

pub fn decrypt(
    ciphertext_bundle: &[u8],
    password: &str,
    progress: Option<&ProgressFn>,
) -> Result<(Vec<u8>, String), CryptoError> {
    let progress = &progress;

    report(progress, 0.0);

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

    let flags = ciphertext_bundle[5];

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

    // Reject downgraded Argon2 parameters before running KDF.
    // Prevents a timing oracle where a modified header forces cheap KDF
    // evaluation (full brute-force speed) before MAC rejects the message.
    if m_log2 < ARGON2_M_LOG2_MIN || t_cost < ARGON2_T_COST_MIN {
        return Err(CryptoError::WeakKdfParameters);
    }

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

    // Phase 2: Argon2id KDF (0.05 → 0.35)
    let master_key = LockedBuffer::new(
        derive_key(password, salt, timestamp, m_log2, t_cost, p_cost)?
    );
    let (chaos_key_raw, mac_key_raw) = derive_subkeys(master_key.get());
    let chaos_key = LockedBuffer::new(chaos_key_raw);
    let mac_key = LockedBuffer::new(mac_key_raw);
    report(progress, 0.35);

    // Verify MAC before any decryption (encrypt-then-MAC; constant-time comparison)
    let mut mac = blake3::Hasher::new_keyed(mac_key.get());
    mac.update(magic);
    mac.update(&[version]);
    mac.update(&[flags]);
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
        return Err(CryptoError::IntegrityCheckFailed);
    }
    report(progress, 0.40);

    // Initialize chaotic keystream with same key and nonce
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertextLength)?;
    let mut keystream = ChaoticKeystream::new(chaos_key.get(), &nonce);

    // Phase 3: XOR decryption (0.40 → 0.85)
    let mut decrypted = encrypted.to_vec();
    const CHUNK: usize = 65536;
    let total_len = decrypted.len();
    if total_len > 0 {
        let mut offset = 0;
        while offset < total_len {
            let end = (offset + CHUNK).min(total_len);
            keystream.apply_keystream(&mut decrypted[offset..end]);
            offset = end;
            if progress.is_some() {
                let frac = offset as f32 / total_len as f32;
                report(progress, 0.40 + frac * 0.45);
            }
        }
    }
    report(progress, 0.85);

    // Phase 4: Decompression (0.85 → 0.90)
    let no_compress = (flags & FLAG_NO_COMPRESS) != 0;
    let plaintext = if no_compress {
        decrypted
    } else {
        decompress_data(&decrypted)?
    };
    report(progress, 0.90);

    let extension_str = String::from_utf8_lossy(extension).to_string();
    Ok((plaintext, extension_str))
}
