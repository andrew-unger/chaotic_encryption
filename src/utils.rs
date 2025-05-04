use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{self, Write};
use crate::error::CryptoError;
use crate::crypto::constants::*;

pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    io::copy(&mut decoder, &mut decompressed)?;
    Ok(decompressed)
}

pub fn display_file_info(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        eprintln!("This file is not a valid AU79 encrypted file.");
        return Err(CryptoError::InvalidMagicBytes);
    }
    
    let version = data[4];
    let flags = data[5];
    let timestamp_start = 6 + SALT_LEN;
    
    if data.len() < timestamp_start + TIMESTAMP_LEN + CHACHA_NONCE_LEN + TENT_SEED_LEN + 1 {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    
    let timestamp = u64::from_le_bytes(data[timestamp_start..timestamp_start+8].try_into().unwrap());
    let tent_seed = f64::from_le_bytes(data[timestamp_start+8+12..timestamp_start+8+12+8].try_into().unwrap());
    let ext_len = data[timestamp_start+8+12+8];
    let ext_start = timestamp_start+8+12+8+1;
    
    if data.len() < ext_start + (ext_len as usize) {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    
    let extension = &data[ext_start..ext_start+(ext_len as usize)];
    
    println!("----- File Info -----");
    println!("Magic: {}", String::from_utf8_lossy(MAGIC));
    println!("Version: {}", version);
    println!("Flags: {}", flags);
    println!("Timestamp (Unix Epoch): {}", timestamp);
    println!("Tent Map Seed: {}", tent_seed);
    println!("Original Extension: .{}", String::from_utf8_lossy(extension));
    println!("----------------------");
    
    Ok(())
}