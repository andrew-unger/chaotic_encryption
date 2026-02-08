use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
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
    let decoder = ZlibDecoder::new(data);
    let mut limited = decoder.take(MAX_DECOMPRESSED_SIZE + 1);
    let mut decompressed = Vec::new();
    limited.read_to_end(&mut decompressed)?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(CryptoError::DecompressionTooLarge);
    }
    Ok(decompressed)
}

pub fn display_file_info(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        eprintln!("This file is not a valid AU79 encrypted file.");
        return Err(CryptoError::InvalidMagicBytes);
    }

    let version = data[4];
    if version != VERSION {
        eprintln!("Unsupported file version: {}", version);
        return Err(CryptoError::InvalidVersion);
    }

    let flags = data[5];
    let ts_start = 6 + SALT_LEN;

    if data.len() < MIN_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertextLength);
    }

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

    let m_cost_mb = (1u64 << m_log2) / 1024;

    println!("----- File Info -----");
    println!("Magic: AU79");
    println!("Version: {}", version);
    println!("Flags: {}", flags);
    println!("Timestamp (Unix Epoch): {}", timestamp);
    println!("Argon2 Memory: {} MB (2^{} KiB)", m_cost_mb, m_log2);
    println!("Argon2 Iterations: {}", t_cost);
    println!("Argon2 Parallelism: {}", p_cost);
    println!("Original Extension: .{}", extension);
    println!("----------------------");

    Ok(())
}
