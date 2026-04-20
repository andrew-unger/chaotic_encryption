use argon2::{Algorithm, Argon2, Params, Version};
use blake3;
use rand::Rng;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cml_sponge;
use crate::error::CryptoError;
use crate::utils::{compress_data, decompress_data, decompress_data_zlib};

/// Progress callback type: receives a value in [0.0, 1.0].
pub type ProgressFn = Box<dyn Fn(f32) + Send>;

const KEYFILE_MAX_BYTES: u64 = 1_073_741_824; // 1 GiB
const STREAM_CHUNK: usize = 65_536; // encrypt/decrypt chunk size

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
    // SAFETY: `ptr` points to the first byte of a live heap allocation of exactly
    // `size` bytes (a `Box<[u8; 32]>` allocated by `LockedBuffer::new`).  The
    // pointer is valid for the lifetime of that box, and `VirtualLock` only reads
    // the address range — it does not dereference Rust-managed memory itself.
    // No Rust aliasing or ownership invariants are violated by this call.
    unsafe { VirtualLock(ptr, size) != 0 }
}

#[cfg(target_os = "windows")]
fn unlock_memory(ptr: *const u8, size: usize) {
    // SAFETY: Same invariants as `lock_memory` above.  `VirtualUnlock` is called
    // on the same pointer and size that were passed to `VirtualLock` in
    // `LockedBuffer::new`, and is called from `LockedBuffer::drop` before the
    // box is freed, so the allocation is still live.
    //
    // Importantly, `VirtualUnlock` uses the address and size only for page-range
    // bookkeeping (updating the working-set lock count for the affected pages);
    // it does NOT dereference through `ptr` or read memory contents.  It is
    // therefore safe to call `VirtualUnlock` after the buffer has been zeroed by
    // `LockedBuffer::drop` — the zero contents are irrelevant to the OS call.
    unsafe {
        let _ = VirtualUnlock(ptr, size);
    }
}

#[cfg(not(target_os = "windows"))]
fn lock_memory(_ptr: *const u8, _size: usize) -> bool {
    true
}

#[cfg(not(target_os = "windows"))]
fn unlock_memory(_ptr: *const u8, _size: usize) {}

/// RAII wrapper that heap-allocates key material, attempts to page-lock it,
/// and unconditionally zeroizes on drop.
struct LockedBuffer {
    data: Box<[u8; 32]>,
    locked: bool,
}

impl LockedBuffer {
    fn new(mut src: [u8; 32]) -> Self {
        let mut boxed = Box::new([0u8; 32]);
        boxed.copy_from_slice(&src);
        src.zeroize();
        let ptr = boxed.as_ptr();
        let locked = lock_memory(ptr, 32);
        Self {
            data: boxed,
            locked,
        }
    }

    fn get(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Unlock before zeroize: on Windows `VirtualUnlock` only does page-range
        // bookkeeping so ordering is safe either way, but a future non-Windows
        // port using a backend that reads bytes during unlock would be broken
        // by zeroing first. This ordering matches libsodium / memsec.
        if self.locked {
            unlock_memory(self.data.as_ptr(), 32);
        }
        self.data.zeroize();
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

pub mod constants {
    /// File format version.  v9 uses CML-Sponge AEAD natively
    /// (single primitive for cipher + auth via sponge capacity).
    pub const VERSION: u8 = 9;
    pub const MAGIC: &[u8; 4] = b"CATW";
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;
    pub const NONCE_LEN: usize = 16;
    pub const TIMESTAMP_LEN: usize = 8;

    // Argon2id defaults
    pub const ARGON2_M_LOG2: u8 = 18; // 2^18 = 262144 KiB = 256 MB
    pub const ARGON2_T_COST: u8 = 4; // 4 iterations
    pub const ARGON2_P_COST: u8 = 1; // 1 lane

    // Minimum safe Argon2id parameters accepted on decryption.
    pub const ARGON2_M_LOG2_MIN: u8 = 16; // 64 MB minimum
    pub const ARGON2_T_COST_MIN: u8 = 2; // 2 iterations minimum
    pub const ARGON2_P_COST_MIN: u8 = 1; // at least 1 lane (argon2 crate rejects 0 internally)

    // Password policy
    pub const MIN_PASSWORD_LEN: usize = 18;
    pub const MAX_CONSECUTIVE_REPEAT: usize = 3;

    // Flags byte bit definitions (byte index 5 in the header).
    // Bit 0 — strip timestamp and file extension from header.
    pub const FLAG_STRIP_METADATA: u8 = 0x01;
    // Bit 1 — ciphertext is stored uncompressed.
    pub const FLAG_NO_COMPRESS: u8 = 0x02;
    // Bit 2 — a keyfile was mixed into the KDF input.
    pub const FLAG_KEYFILE: u8 = 0x04;
    // Bit 3 — compression uses zstd instead of zlib.
    // When unset and compression is enabled, zlib is assumed (backward compat).
    pub const FLAG_ZSTD: u8 = 0x08;

    /// Byte index of the flags field within the CATWALK header.
    pub const FLAGS_OFFSET: usize = 5;

    // Minimum header size: magic(4) + ver(1) + flags(1) + salt(16) + ts(8) + nonce(16) + argon(3) + ext_len(1) + tag(32)
    pub const MIN_HEADER_LEN: usize =
        4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + NONCE_LEN + 3 + 1 + HASH_LEN;
}

use constants::*;

// ── Encrypt Options ──────────────────────────────────────────────────────────

/// Options controlling encryption behavior.
#[derive(Debug, Clone, Copy)]
pub struct EncryptOptions {
    /// Strip timestamp and file extension from header (flags bit 0).
    pub strip_metadata: bool,
    /// Skip compression — encrypt raw plaintext (flags bit 1).
    pub skip_compression: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            strip_metadata: false,
            skip_compression: true,
        }
    }
}

// ── Key Derivation ───────────────────────────────────────────────────────────

/// Build the raw byte slice that Argon2id hashes as its "password" input.
///
/// Without a keyfile: `password_bytes`.
/// With a keyfile:    `password_bytes || 0x00 || BLAKE3(keyfile_contents)`.
///
/// The keyfile is hashed before combining so Argon2id always receives a
/// fixed-length input regardless of keyfile size (up to 1 GB).
/// The null-byte separator prevents length-extension ambiguity.
fn build_kdf_input(password: &str, keyfile_path: Option<&Path>) -> Result<Vec<u8>, CryptoError> {
    if let Some(path) = keyfile_path {
        // Check size via metadata first to avoid loading a huge file.
        let file_len = fs::metadata(path)?.len();
        if file_len > KEYFILE_MAX_BYTES {
            return Err(CryptoError::KeyfileTooLarge);
        }
        let mut contents = fs::read(path)?;
        let digest = blake3::hash(&contents);
        contents.zeroize();
        let mut material = password.as_bytes().to_vec();
        material.push(0x00); // separator — prevents length-extension ambiguity
        material.extend_from_slice(digest.as_bytes());
        Ok(material)
    } else {
        Ok(password.as_bytes().to_vec())
    }
}

/// Derive a 32-byte master key from raw KDF input bytes via Argon2id.
///
/// The salt passed to Argon2id is `salt || timestamp` so that the timestamp
/// contributes to the per-file KDF domain even when it is zeroed out by
/// `strip_metadata`.
fn derive_key(
    kdf_input: &[u8],
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

    let result = argon2.hash_password_into(kdf_input, &combined_salt, &mut key);
    // Salt is not secret, but zero it anyway for defense-in-depth consistency.
    combined_salt.zeroize();
    match result {
        Ok(()) => Ok(key),
        Err(_) => {
            // Clear any partial KDF output that may have been written to `key`
            // before the failure.
            key.zeroize();
            Err(CryptoError::KeyDerivationFailed)
        }
    }
}

/// Derive the v9 cipher key from the master key via BLAKE3 domain derivation.
fn derive_cipher_key_v9(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("catwalk.v9.cipher", master_key)
}

// ── Password Validation ──────────────────────────────────────────────────────

/// Validate that a password meets minimum complexity requirements.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < MIN_PASSWORD_LEN {
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

// ── Encrypt (v9 — CML-Sponge AEAD) ──────────────────────────────────────────

/// Encrypt `plaintext` and return the complete CATWALK v9 ciphertext bundle.
///
/// The returned bytes contain the header, ciphertext, and 32-byte AEAD tag —
/// all in one contiguous buffer ready to write to disk.
///
/// # Arguments
///
/// - `plaintext` — raw file bytes to encrypt.
/// - `password` — must satisfy the requirements checked by [`validate_password`].
/// - `input_filename` — used to extract the file extension stored in the header
///   (unless `options.strip_metadata` is set).
/// - `options` — controls compression and metadata stripping.
/// - `keyfile_path` — optional path to a keyfile. When `Some`, the keyfile's
///   BLAKE3 hash is mixed into the Argon2id input before the KDF runs, and
///   `FLAG_KEYFILE` is set in the header. The keyfile path itself is never stored.
/// - `progress` — optional callback called with values in `[0.0, 1.0]`.
pub fn encrypt(
    plaintext: &[u8],
    password: &str,
    input_filename: &str,
    options: &EncryptOptions,
    keyfile_path: Option<&Path>,
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

    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);

    let timestamp = if options.strip_metadata {
        [0u8; 8]
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::SystemTimeError)?
            .as_secs()
            .to_le_bytes()
    };

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
    if extension.len() > u8::MAX as usize {
        return Err(CryptoError::ExtensionTooLong);
    }
    let ext_len = extension.len() as u8;

    let mut flags: u8 = 0;
    if options.strip_metadata {
        flags |= FLAG_STRIP_METADATA;
    }
    if options.skip_compression {
        flags |= FLAG_NO_COMPRESS;
    }
    if keyfile_path.is_some() {
        flags |= FLAG_KEYFILE;
    }
    if !options.skip_compression {
        flags |= FLAG_ZSTD;
    } // new files use zstd

    let m_log2 = ARGON2_M_LOG2;
    let t_cost = ARGON2_T_COST;
    let p_cost = ARGON2_P_COST;

    // Phase 2: Build KDF input and run Argon2id (0.05 → 0.35)
    let mut kdf_input = build_kdf_input(password, keyfile_path)?;
    let master_key = LockedBuffer::new(derive_key(
        &kdf_input, &salt, &timestamp, m_log2, t_cost, p_cost,
    )?);
    kdf_input.zeroize();
    let cipher_key = LockedBuffer::new(derive_cipher_key_v9(master_key.get()));
    report(progress, 0.35);

    // Build header bytes — these become the AEAD associated data (authenticated
    // but not encrypted).  Must be serialised before starting the sponge so
    // we can absorb the exact bytes that will appear in the output.
    let mut header = Vec::with_capacity(50 + extension.len());
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(flags);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&timestamp);
    header.extend_from_slice(&nonce);
    header.push(m_log2);
    header.push(t_cost);
    header.push(p_cost);
    header.push(ext_len);
    header.extend_from_slice(&extension);

    // Initialise CML-Sponge AEAD and absorb header as associated data.
    let mut sponge = cml_sponge::cipher_init(cipher_key.get(), &nonce);
    cml_sponge::absorb_aad(&mut sponge, &header);

    // Phase 3: Stream encrypt + authenticate (0.35 → 0.85)
    let mut ciphertext = data;
    let mut scratch = Vec::with_capacity(STREAM_CHUNK);

    let total_len = ciphertext.len();
    if total_len > 0 {
        let mut offset = 0;
        while offset < total_len {
            let end = (offset + STREAM_CHUNK).min(total_len);
            cml_sponge::aead_encrypt_chunk(&mut sponge, &mut ciphertext[offset..end], &mut scratch);
            offset = end;
            if progress.is_some() {
                let frac = offset as f32 / total_len as f32;
                report(progress, 0.35 + frac * 0.50);
            }
        }
    }
    scratch.zeroize();
    report(progress, 0.85);

    // Phase 4: Finalise tag + assemble output (0.85 → 0.90)
    let tag = cml_sponge::aead_finalize(&mut sponge);

    let mut result = Vec::with_capacity(header.len() + ciphertext.len() + HASH_LEN);
    result.extend_from_slice(&header);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    report(progress, 0.90);
    Ok(result)
}

// ── Decrypt (v9 — CML-Sponge AEAD) ──────────────────────────────────────────

/// Decrypt a complete CATWALK v9 ciphertext bundle and return `(plaintext, extension)`.
///
/// `extension` is the original file extension stored in the header (empty string if
/// `strip_metadata` was set during encryption or no extension was present).
///
/// Verification is performed **before** the plaintext is returned.
///
/// # Arguments
///
/// - `ciphertext_bundle` — the complete output of [`encrypt`].
/// - `password` — the password used during encryption.
/// - `keyfile_path` — if `FLAG_KEYFILE` is set in the header, this **must**
///   be `Some(path)`. Providing `None` returns [`CryptoError::KeyfileRequired`].
///   Providing a keyfile for a file that was encrypted without one is silently
///   ignored (the flag is authoritative).
/// - `progress` — optional progress callback.
///
/// # Errors
///
/// All error variants from [`encrypt`] plus:
/// - [`CryptoError::KeyfileRequired`] — file needs a keyfile but none was supplied.
/// - [`CryptoError::KeyfileTooLarge`] — provided keyfile exceeds 1 GB.
pub fn decrypt(
    ciphertext_bundle: &[u8],
    password: &str,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<(Vec<u8>, String), CryptoError> {
    let progress = &progress;

    report(progress, 0.0);

    if ciphertext_bundle.len() < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    // Parse header fields.
    let magic = &ciphertext_bundle[..4];
    if magic != MAGIC {
        return Err(CryptoError::InvalidMagicBytes);
    }

    let version = ciphertext_bundle[4];
    if version != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    let flags = ciphertext_bundle[FLAGS_OFFSET];

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

    // Reject downgraded Argon2 parameters before running KDF (timing oracle defence).
    if m_log2 < ARGON2_M_LOG2_MIN || t_cost < ARGON2_T_COST_MIN || p_cost < ARGON2_P_COST_MIN {
        return Err(CryptoError::WeakKdfParameters);
    }

    // Enforce keyfile requirement before doing any expensive KDF work.
    // If the flag is set but no keyfile was supplied, fail immediately.
    // If no flag is set but a keyfile was supplied, silently ignore it —
    // the flag in the header is authoritative.
    let effective_keyfile = if (flags & FLAG_KEYFILE) != 0 {
        match keyfile_path {
            Some(p) => Some(p),
            None => return Err(CryptoError::KeyfileRequired),
        }
    } else {
        // File encrypted without a keyfile; ignore any keyfile supplied.
        None
    };

    let ext_len = ciphertext_bundle[ext_len_pos] as usize;
    let ext_start = ext_len_pos + 1;
    let cipher_start = ext_start + ext_len;
    let tag_start = ciphertext_bundle.len() - HASH_LEN;

    if cipher_start > tag_start {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let extension = &ciphertext_bundle[ext_start..cipher_start];
    let encrypted = &ciphertext_bundle[cipher_start..tag_start];
    let stored_tag = &ciphertext_bundle[tag_start..];

    // Phase 2: Build KDF input and run Argon2id (0.05 → 0.35)
    let mut kdf_input = build_kdf_input(password, effective_keyfile)?;
    let master_key = LockedBuffer::new(derive_key(
        &kdf_input, salt, timestamp, m_log2, t_cost, p_cost,
    )?);
    kdf_input.zeroize();
    report(progress, 0.35);

    decrypt_v9(
        master_key.get(),
        nonce_bytes,
        &ciphertext_bundle[..cipher_start],
        encrypted,
        stored_tag,
        flags,
        extension,
        progress,
    )
}

// ── Streaming I/O ───────────────────────────────────────────────────────────

/// Read from `reader` until `buf` is full or EOF.  Returns bytes read.
fn read_full<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Encrypt from a reader to a writer without loading the entire file into memory.
///
/// The output format is identical to [`encrypt`] — header, ciphertext, tag.
/// If compression is enabled (`!options.skip_compression`), the input is
/// stream-compressed through zlib before encryption.
///
/// `input_len` is used only for progress reporting and may be `None`.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
    input_filename: &str,
    options: &EncryptOptions,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
    input_len: Option<u64>,
) -> Result<(), CryptoError> {
    let progress = &progress;
    report(progress, 0.0);

    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);

    let timestamp = if options.strip_metadata {
        [0u8; 8]
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::SystemTimeError)?
            .as_secs()
            .to_le_bytes()
    };

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
    if extension.len() > u8::MAX as usize {
        return Err(CryptoError::ExtensionTooLong);
    }
    let ext_len = extension.len() as u8;

    let mut flags: u8 = 0;
    if options.strip_metadata {
        flags |= FLAG_STRIP_METADATA;
    }
    if options.skip_compression {
        flags |= FLAG_NO_COMPRESS;
    }
    if keyfile_path.is_some() {
        flags |= FLAG_KEYFILE;
    }
    if !options.skip_compression {
        flags |= FLAG_ZSTD;
    } // new files use zstd

    let m_log2 = ARGON2_M_LOG2;
    let t_cost = ARGON2_T_COST;
    let p_cost = ARGON2_P_COST;

    // KDF (0.05 → 0.35)
    report(progress, 0.05);
    let mut kdf_input = build_kdf_input(password, keyfile_path)?;
    let master_key = LockedBuffer::new(derive_key(
        &kdf_input, &salt, &timestamp, m_log2, t_cost, p_cost,
    )?);
    kdf_input.zeroize();
    let cipher_key = LockedBuffer::new(derive_cipher_key_v9(master_key.get()));
    report(progress, 0.35);

    // Build and write header.
    let mut header = Vec::with_capacity(50 + extension.len());
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(flags);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&timestamp);
    header.extend_from_slice(&nonce);
    header.push(m_log2);
    header.push(t_cost);
    header.push(p_cost);
    header.push(ext_len);
    header.extend_from_slice(&extension);
    writer.write_all(&header)?;

    // Init sponge and absorb header as AAD.
    let mut sponge = cml_sponge::cipher_init(cipher_key.get(), &nonce);
    cml_sponge::absorb_aad(&mut sponge, &header);

    // Stream encrypt (0.35 → 0.85).
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut scratch = Vec::with_capacity(STREAM_CHUNK);
    let mut bytes_out: u64 = 0;

    // Inner loop: read from source, encrypt chunk, write to output.
    let mut encrypt_loop = |source: &mut dyn Read| -> Result<(), CryptoError> {
        loop {
            let n = read_full(source, &mut buf)?;
            if n == 0 {
                break;
            }
            cml_sponge::aead_encrypt_chunk(&mut sponge, &mut buf[..n], &mut scratch);
            writer.write_all(&buf[..n])?;
            bytes_out += n as u64;
            if let Some(total) = input_len {
                if total > 0 {
                    let frac = (bytes_out as f32 / total as f32).min(1.0);
                    report(progress, 0.35 + frac * 0.50);
                }
            }
        }
        Ok(())
    };

    if options.skip_compression {
        encrypt_loop(reader)?;
    } else {
        let mut compressor =
            zstd::stream::read::Encoder::new(reader, 1).map_err(CryptoError::IoError)?;
        encrypt_loop(&mut compressor)?;
    }
    scratch.zeroize();
    report(progress, 0.85);

    // Finalize tag and write it.
    let tag = cml_sponge::aead_finalize(&mut sponge);
    writer.write_all(&tag)?;
    report(progress, 0.90);

    Ok(())
}

/// Decrypt from a seekable reader to a writer without loading the entire file
/// into memory.
///
/// Returns the original file extension (empty string if metadata was stripped).
///
/// # Security note
///
/// Unlike [`decrypt`], this function writes decrypted data to `writer`
/// **before** the authentication tag is verified.  If the tag check fails,
/// the caller is responsible for deleting or discarding the output.
/// This trade-off is inherent to streaming AEAD decryption and is standard
/// practice (cf. `age`, `gpg`).
///
/// Callers **must** treat the emitted bytes as unauthenticated until this
/// function returns `Ok(())`. In particular:
///
/// - When `writer` is a file, delete the file on `Err` (the CATWALK CLI does
///   this via [`std::fs::remove_file`]).
/// - When `writer` is stdout, a pipe, or any unseekable sink, downstream
///   consumers may have already read unauthenticated data before the tag is
///   checked. Document this to end users and advise them not to act on the
///   output until the process exits with code 0.
/// - When `writer` is an in-memory buffer, clear it on `Err` before reuse.
///
/// If any of these post-conditions cannot be guaranteed by the caller, use
/// the non-streaming [`decrypt`] function instead — it verifies the tag before
/// returning any plaintext.
pub fn decrypt_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
    keyfile_path: Option<&Path>,
    progress: Option<&ProgressFn>,
) -> Result<String, CryptoError> {
    let progress = &progress;
    report(progress, 0.0);

    // Determine file size via seek.
    let file_size = reader.seek(SeekFrom::End(0))? as usize;
    reader.seek(SeekFrom::Start(0))?;

    if file_size < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    // Read fixed-size header prefix:
    //   magic(4) + ver(1) + flags(1) + salt(16) + ts(8) + nonce(16) + argon(3) + ext_len(1) = 50
    let fixed_len = 4 + 1 + 1 + SALT_LEN + TIMESTAMP_LEN + NONCE_LEN + 3 + 1;
    let mut fixed = vec![0u8; fixed_len];
    reader.read_exact(&mut fixed)?;

    if &fixed[..4] != MAGIC {
        return Err(CryptoError::InvalidMagicBytes);
    }
    if fixed[4] != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    let flags = fixed[FLAGS_OFFSET];

    let salt_start = 6;
    let ts_start = salt_start + SALT_LEN;
    let nonce_start = ts_start + TIMESTAMP_LEN;
    let argon_start = nonce_start + NONCE_LEN;
    let ext_len_pos = argon_start + 3;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&fixed[salt_start..ts_start]);
    let mut ts = [0u8; TIMESTAMP_LEN];
    ts.copy_from_slice(&fixed[ts_start..nonce_start]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&fixed[nonce_start..argon_start]);

    let m_log2 = fixed[argon_start];
    let t_cost = fixed[argon_start + 1];
    let p_cost = fixed[argon_start + 2];

    if m_log2 < ARGON2_M_LOG2_MIN || t_cost < ARGON2_T_COST_MIN || p_cost < ARGON2_P_COST_MIN {
        return Err(CryptoError::WeakKdfParameters);
    }

    let effective_keyfile = if (flags & FLAG_KEYFILE) != 0 {
        match keyfile_path {
            Some(p) => Some(p),
            None => return Err(CryptoError::KeyfileRequired),
        }
    } else {
        None
    };

    let ext_len = fixed[ext_len_pos] as usize;
    let mut ext_bytes = vec![0u8; ext_len];
    if ext_len > 0 {
        reader.read_exact(&mut ext_bytes)?;
    }

    let header_len = fixed_len + ext_len;
    if header_len + HASH_LEN > file_size {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    let cipher_len = file_size - header_len - HASH_LEN;

    // Read the stored tag from the end of the file, then seek back.
    let cipher_pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start((file_size - HASH_LEN) as u64))?;
    let mut stored_tag = [0u8; HASH_LEN];
    reader.read_exact(&mut stored_tag)?;
    reader.seek(SeekFrom::Start(cipher_pos))?;

    // Reconstruct the full header for AAD.
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&fixed);
    header.extend_from_slice(&ext_bytes);

    // KDF (0.05 → 0.35)
    report(progress, 0.05);
    let mut kdf_input = build_kdf_input(password, effective_keyfile)?;
    let master_key = LockedBuffer::new(derive_key(&kdf_input, &salt, &ts, m_log2, t_cost, p_cost)?);
    kdf_input.zeroize();
    let cipher_key = LockedBuffer::new(derive_cipher_key_v9(master_key.get()));
    report(progress, 0.35);

    // Init sponge and absorb header as AAD.
    let mut sponge = cml_sponge::cipher_init(cipher_key.get(), &nonce);
    cml_sponge::absorb_aad(&mut sponge, &header);

    // Stream decrypt (0.40 → 0.85).
    let no_compress = (flags & FLAG_NO_COMPRESS) != 0;
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut scratch = Vec::with_capacity(STREAM_CHUNK * 2);
    let mut remaining = cipher_len;

    // Inner loop: read ciphertext chunk, decrypt, write to sink.
    let mut decrypt_loop = |sink: &mut dyn Write| -> Result<(), CryptoError> {
        while remaining > 0 {
            let to_read = remaining.min(STREAM_CHUNK);
            reader.read_exact(&mut buf[..to_read])?;
            cml_sponge::aead_decrypt_chunk(&mut sponge, &mut buf[..to_read], &mut scratch);
            sink.write_all(&buf[..to_read])?;
            remaining -= to_read;
            // cipher_len.max(1) avoids division by zero when cipher_len == 0
            // (empty ciphertext body); in that case remaining == 0 and the loop
            // never executes, so this line is unreachable, but the guard is kept
            // for clarity.
            let frac = (cipher_len - remaining) as f32 / cipher_len.max(1) as f32;
            report(progress, 0.40 + frac * 0.45);
        }
        Ok(())
    };

    let use_zstd = (flags & FLAG_ZSTD) != 0;
    if no_compress {
        decrypt_loop(writer)?;
    } else if use_zstd {
        let mut decoder =
            zstd::stream::write::Decoder::new(writer).map_err(CryptoError::IoError)?;
        decrypt_loop(&mut decoder)?;
        decoder.flush().map_err(CryptoError::IoError)?;
    } else {
        let mut decoder = flate2::write::ZlibDecoder::new(writer);
        decrypt_loop(&mut decoder)?;
        decoder.finish().map_err(CryptoError::IoError)?;
    }
    scratch.zeroize();
    report(progress, 0.85);

    // Verify authentication tag (constant-time).
    let computed_tag = cml_sponge::aead_finalize(&mut sponge);
    if computed_tag.ct_eq(&stored_tag).unwrap_u8() != 1 {
        return Err(CryptoError::IntegrityCheckFailed);
    }
    report(progress, 0.90);

    Ok(String::from_utf8(ext_bytes).unwrap_or_else(|_| "???".to_string()))
}

// ── v9 decryption (CML-Sponge AEAD) ─────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn decrypt_v9(
    master_key: &[u8; 32],
    nonce_bytes: &[u8],
    header: &[u8],
    encrypted: &[u8],
    stored_tag: &[u8],
    flags: u8,
    extension: &[u8],
    progress: &Option<&ProgressFn>,
) -> Result<(Vec<u8>, String), CryptoError> {
    let cipher_key = LockedBuffer::new(derive_cipher_key_v9(master_key));

    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertextLength)?;

    // Init sponge and absorb header as AAD — must match encryption exactly.
    let mut sponge = cml_sponge::cipher_init(cipher_key.get(), &nonce);
    cml_sponge::absorb_aad(&mut sponge, header);

    // Phase 3: Stream decrypt (0.40 → 0.85)
    let mut decrypted = encrypted.to_vec();
    let mut scratch = Vec::with_capacity(STREAM_CHUNK * 2);

    let total_len = decrypted.len();
    if total_len > 0 {
        let mut offset = 0;
        while offset < total_len {
            let end = (offset + STREAM_CHUNK).min(total_len);
            cml_sponge::aead_decrypt_chunk(&mut sponge, &mut decrypted[offset..end], &mut scratch);
            offset = end;
            if progress.is_some() {
                let frac = offset as f32 / total_len as f32;
                report(progress, 0.40 + frac * 0.45);
            }
        }
    }
    scratch.zeroize();
    report(progress, 0.85);

    // Verify authentication tag (constant-time).
    let computed_tag = cml_sponge::aead_finalize(&mut sponge);
    if computed_tag.ct_eq(stored_tag).unwrap_u8() != 1 {
        return Err(CryptoError::IntegrityCheckFailed);
    }
    report(progress, 0.88);

    // Phase 4: Decompression (0.88 → 0.90)
    let no_compress = (flags & FLAG_NO_COMPRESS) != 0;
    let use_zstd = (flags & FLAG_ZSTD) != 0;
    let plaintext = if no_compress {
        decrypted
    } else if use_zstd {
        decompress_data(&decrypted)?
    } else {
        decompress_data_zlib(&decrypted)?
    };
    report(progress, 0.90);

    let extension_str = String::from_utf8(extension.to_vec()).unwrap_or_else(|_| "???".to_string());
    Ok((plaintext, extension_str))
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // `validate_password` enforces BOTH a minimum length (18 chars) and a cap on
    // consecutive identical characters (max 3).  The length check fires first,
    // so we pad test inputs to exceed the length minimum when exercising the
    // repeat cap.

    #[test]
    fn validate_password_accepts_three_consecutive_repeats() {
        // "aaa" + 15 varied chars = 18 chars total, max run = 3 → OK
        let pw = "aaaBcDeFgHiJkLmNoP";
        assert_eq!(pw.len(), 18);
        assert!(validate_password(pw).is_ok());
    }

    #[test]
    fn validate_password_rejects_four_consecutive_repeats() {
        // "aaaa" + 14 varied chars = 18 chars total, max run = 4 → FAIL
        let pw = "aaaaBcDeFgHiJkLmNo";
        assert_eq!(pw.len(), 18);
        let res = validate_password(pw);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("consecutive"));
    }

    #[test]
    fn validate_password_rejects_short_password() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("seventeencharsxx").is_err()); // 16 chars
    }

    #[test]
    fn derive_key_rejects_p_cost_zero_via_explicit_floor_check() {
        // `derive_key` itself does not enforce the floor — the floor is applied
        // in `decrypt`/`decrypt_stream` via ARGON2_P_COST_MIN.  With `p_cost = 0`
        // the underlying argon2 crate also rejects the Params, producing a
        // KeyDerivationFailed.  This test exercises that internal path.
        let salt = [0u8; 16];
        let ts = [0u8; 8];
        let result = derive_key(b"some-kdf-input", &salt, &ts, 16, 2, 0);
        assert!(matches!(result, Err(CryptoError::KeyDerivationFailed)));
    }

    #[test]
    fn argon2_parameter_floor_constants() {
        // Sanity check — the floor values are what the plan + docs assert.
        assert_eq!(constants::ARGON2_T_COST_MIN, 2);
        assert_eq!(constants::ARGON2_M_LOG2_MIN, 16);
        assert_eq!(constants::ARGON2_P_COST_MIN, 1);
    }
}
