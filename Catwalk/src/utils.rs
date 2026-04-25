use crate::crypto::constants::*;
use crate::error::CryptoError;
use flate2::read::ZlibDecoder;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

const MAX_DECOMPRESSED_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
const DECOMPRESS_BUF: usize = 64 * 1024;

/// Compress data using zstd (level 1 — fast, good ratio).
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    zstd::encode_all(data, 1).map_err(CryptoError::IoError)
}

fn read_all_capped<R: Read>(mut decoder: R) -> Result<Vec<u8>, CryptoError> {
    let mut decompressed = Vec::new();
    let mut buf = [0u8; DECOMPRESS_BUF];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if decompressed.len() as u64 + n as u64 > MAX_DECOMPRESSED_SIZE {
            return Err(CryptoError::DecompressionTooLarge);
        }
        decompressed.extend_from_slice(&buf[..n]);
    }
    Ok(decompressed)
}

/// Decompress zstd-compressed data with a 4 GB size limit.
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoder = zstd::Decoder::new(data).map_err(CryptoError::IoError)?;
    read_all_capped(decoder)
}

/// Decompress zlib-compressed data (backward compat for pre-zstd files).
pub fn decompress_data_zlib(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    read_all_capped(ZlibDecoder::new(data))
}

// ── File Info ────────────────────────────────────────────────────────────────

pub struct FileInfo {
    pub version: u8,
    pub flags: u8,
    pub timestamp: u64,
    pub argon2_m_log2: u8,
    pub argon2_t_cost: u8,
    pub argon2_p_cost: u8,
    pub extension: String,
    pub file_size: u64,
}

impl FileInfo {
    pub fn flags_display(&self) -> String {
        let mut parts = Vec::new();
        if self.flags & FLAG_STRIP_METADATA != 0 {
            parts.push("STRIP_METADATA");
        }
        if self.flags & FLAG_NO_COMPRESS != 0 {
            parts.push("NO_COMPRESS");
        }
        if self.flags & FLAG_KEYFILE != 0 {
            parts.push("KEYFILE");
        }
        if self.flags & FLAG_ZSTD != 0 {
            parts.push("ZSTD");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(", ")
        }
    }

    pub fn argon2_memory_mb(&self) -> u64 {
        (1u64 << self.argon2_m_log2) / 1024
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Magic:              CATW\n\
             Version:            {}\n\
             Flags:              {} ({})\n\
             Timestamp:          {}\n\
             Argon2 Memory:      {} MB (2^{} KiB)\n\
             Argon2 Iterations:  {}\n\
             Argon2 Parallelism: {}\n\
             Original Extension: .{}\n\
             File Size:          {}",
            self.version,
            self.flags,
            self.flags_display(),
            self.timestamp,
            self.argon2_memory_mb(),
            self.argon2_m_log2,
            self.argon2_t_cost,
            self.argon2_p_cost,
            self.extension,
            format_byte_size(self.file_size),
        )
    }
}

pub fn parse_file_info(data: &[u8]) -> Result<FileInfo, CryptoError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        return Err(CryptoError::InvalidMagicBytes);
    }

    let version = data[4];
    if version != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    if data.len() < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let flags = data[5];
    let ts_start = 6 + SALT_LEN;
    // data.len() >= MIN_HEADER_LEN was verified above; this 8-byte slice is within bounds.
    let timestamp = u64::from_le_bytes(
        data[ts_start..ts_start + 8]
            .try_into()
            .unwrap_or_else(|_| unreachable!()),
    );
    let argon_start = ts_start + TIMESTAMP_LEN + NONCE_LEN;
    let m_log2 = data[argon_start];
    let t_cost = data[argon_start + 1];
    let p_cost = data[argon_start + 2];
    let ext_len = data[argon_start + 3] as usize;
    let ext_start = argon_start + 4;

    let extension = if data.len() >= ext_start + ext_len {
        String::from_utf8(data[ext_start..ext_start + ext_len].to_vec())
            .unwrap_or_else(|_| "???".to_string())
    } else {
        "???".into()
    };

    Ok(FileInfo {
        version,
        flags,
        timestamp,
        argon2_m_log2: m_log2,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        extension,
        file_size: data.len() as u64,
    })
}

pub fn display_file_info(data: &[u8]) -> Result<(), CryptoError> {
    let info = parse_file_info(data)?;
    println!("----- File Info -----");
    println!("{}", info);
    println!("----------------------");
    Ok(())
}

// ── Secure Delete ──────────────────────────────────────────────────────────

/// Securely overwrite a file with three passes (random, zeros, random),
/// then delete it.
///
/// # Limitations
///
/// This is a **best-effort** overwrite and is **not cryptographically reliable**
/// on modern storage. In particular:
///
/// - **SSDs / flash storage**: wear-leveling remaps logical blocks to different
///   physical cells, so the overwritten bytes may persist in retired cells.
/// - **Copy-on-write filesystems** (BTRFS, ZFS, APFS, ReFS): a write goes to
///   a new block; the original block remains until garbage collection.
/// - **Journaled filesystems** (NTFS, ext4, HFS+): a copy of data may exist in
///   the journal.
/// - **Virtual machines / hypervisor storage**: snapshots or thin-provisioned
///   images may retain prior contents.
///
/// For genuine data destruction on SSD-era hardware, use full-disk encryption
/// (BitLocker, FileVault, LUKS) and destroy the key, or use the vendor's
/// secure-erase utility.
pub fn secure_delete_file(path: &Path) -> Result<(), CryptoError> {
    use rand::RngCore;

    let size = fs::metadata(path)?.len() as usize;
    let mut rng = rand::thread_rng();

    for pass in 0..3 {
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; 8192.min(size.max(1))];
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            if pass == 1 {
                buf[..chunk].fill(0);
            } else {
                rng.fill_bytes(&mut buf[..chunk]);
            }
            f.write_all(&buf[..chunk])?;
            remaining -= chunk;
        }
        f.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}

// ── Formatting ─────────────────────────────────────────────────────────────

pub fn format_byte_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{} B", bytes)
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.2} MB", b / MB)
    } else {
        format!("{:.2} GB", b / GB)
    }
}
