use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fmt;
use std::io::{Read, Write};
use crate::error::CryptoError;
use crate::crypto::constants::*;

const MAX_DECOMPRESSED_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 { break; }
        if decompressed.len() as u64 + n as u64 > MAX_DECOMPRESSED_SIZE {
            return Err(CryptoError::DecompressionTooLarge);
        }
        decompressed.extend_from_slice(&buf[..n]);
    }
    Ok(decompressed)
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
        if self.flags & FLAG_STRIP_METADATA != 0 { parts.push("STRIP_METADATA"); }
        if self.flags & FLAG_NO_COMPRESS != 0 { parts.push("NO_COMPRESS"); }
        if parts.is_empty() { "none".to_string() } else { parts.join(", ") }
    }

    pub fn argon2_memory_mb(&self) -> u64 {
        (1u64 << self.argon2_m_log2) / 1024
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Magic:              AU79\n\
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
    if version != 8 && version != VERSION {
        return Err(CryptoError::InvalidVersion);
    }

    if data.len() < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let flags = data[5];
    let ts_start = 6 + SALT_LEN;
    let timestamp = u64::from_le_bytes(data[ts_start..ts_start + 8].try_into().unwrap());
    let argon_start = ts_start + TIMESTAMP_LEN + NONCE_LEN;
    let m_log2 = data[argon_start];
    let t_cost = data[argon_start + 1];
    let p_cost = data[argon_start + 2];
    let ext_len = data[argon_start + 3] as usize;
    let ext_start = argon_start + 4;

    let extension = if data.len() >= ext_start + ext_len {
        String::from_utf8_lossy(&data[ext_start..ext_start + ext_len]).to_string()
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
