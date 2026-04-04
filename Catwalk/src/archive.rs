//! ZIP archive creation and extraction for batch file encryption.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use crate::error::CryptoError;

/// Archive extension used to identify encrypted archives on decryption.
pub const ARCHIVE_EXTENSION: &str = "catwalkarchive";

/// Create an in-memory ZIP archive from the given files.
///
/// Each file is stored with its filename only (no directory structure).
pub fn create_archive(files: &[PathBuf]) -> Result<Vec<u8>, CryptoError> {
    let buf = Vec::new();
    let mut zip = zip::ZipWriter::new(Cursor::new(buf));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        zip.start_file(&name, options)
            .map_err(|e| CryptoError::ArchiveError(format!("Failed to add {}: {}", name, e)))?;
        let data = fs::read(path)?;
        zip.write_all(&data)?;
    }

    let cursor = zip
        .finish()
        .map_err(|e| CryptoError::ArchiveError(format!("Failed to finalize archive: {}", e)))?;
    Ok(cursor.into_inner())
}

/// Extract a ZIP archive into `output_dir`, returning the number of files extracted.
///
/// Only filenames are used (directory components and `..` are stripped for safety).
pub fn extract_archive(data: &[u8], output_dir: &Path) -> Result<usize, CryptoError> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| CryptoError::ArchiveError(format!("Failed to open archive: {}", e)))?;

    fs::create_dir_all(output_dir)?;

    // Canonicalize the output directory root once so we can verify each
    // extracted path stays within it (defence against zip slip).
    let canonical_root = output_dir
        .canonicalize()
        .map_err(|e| CryptoError::ArchiveError(format!("Cannot canonicalize output dir: {}", e)))?;

    let count = archive.len();
    for i in 0..count {
        let mut file = archive
            .by_index(i)
            .map_err(|e| CryptoError::ArchiveError(format!("Archive error: {}", e)))?;
        let raw_name = file.name().to_string();
        let safe_name = Path::new(&raw_name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if safe_name.is_empty() || safe_name.contains("..") {
            continue;
        }
        let out_path = output_dir.join(&safe_name);
        // Create the file first so canonicalize has a real path to resolve.
        let mut out_file = fs::File::create(&out_path)?;
        // Verify the resolved path is still inside the output directory.
        let canonical_out = out_path.canonicalize().map_err(|e| {
            CryptoError::ArchiveError(format!("Cannot canonicalize output path: {}", e))
        })?;
        if !canonical_out.starts_with(&canonical_root) {
            drop(out_file);
            let _ = fs::remove_file(&out_path);
            return Err(CryptoError::ArchiveError(format!(
                "Rejected unsafe path in archive: {}",
                raw_name
            )));
        }
        std::io::copy(&mut file, &mut out_file)?;
    }

    Ok(count)
}
