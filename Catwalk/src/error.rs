use std::io;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key derivation failed.")]
    KeyDerivationFailed,
    #[error("Integrity check failed.")]
    IntegrityCheckFailed,
    #[error("Invalid ciphertext length.")]
    InvalidCiphertextLength,
    #[error("Invalid magic bytes. Not a CATWALK file.")]
    InvalidMagicBytes,
    #[error("Unsupported file version.")]
    InvalidVersion,
    #[error("System time error.")]
    SystemTimeError,
    #[error("Decompressed data exceeds maximum allowed size.")]
    DecompressionTooLarge,
    #[error("File header contains KDF parameters below the minimum security threshold.")]
    WeakKdfParameters,
    /// Keyfile exceeds the 1 GB maximum size.
    #[error("Keyfile exceeds maximum size of 1 GB")]
    KeyfileTooLarge,
    /// File was encrypted with a keyfile but none was provided for decryption.
    #[error("This file requires a keyfile for decryption")]
    KeyfileRequired,
    /// Archive creation or extraction failed.
    #[error("Archive error: {0}")]
    ArchiveError(String),
    /// File extension exceeds 255 bytes (maximum storable in u8 ext_len header field).
    #[error("File extension exceeds maximum length of 255 bytes")]
    ExtensionTooLong,
    #[error("IO Error: {0}")]
    IoError(#[from] io::Error),
}
