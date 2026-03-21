use std::io;

#[derive(Debug)]
pub enum CryptoError {
    KeyDerivationFailed,
    IntegrityCheckFailed,
    InvalidCiphertextLength,
    InvalidMagicBytes,
    InvalidVersion,
    SystemTimeError,
    DecompressionTooLarge,
    WeakKdfParameters,
    /// Keyfile exceeds the 1 GB maximum size.
    KeyfileTooLarge,
    /// File was encrypted with a keyfile but none was provided for decryption.
    KeyfileRequired,
    IoError(io::Error),
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> CryptoError {
        CryptoError::IoError(err)
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyDerivationFailed        => write!(f, "Key derivation failed."),
            CryptoError::IntegrityCheckFailed       => write!(f, "Integrity check failed."),
            CryptoError::InvalidCiphertextLength    => write!(f, "Invalid ciphertext length."),
            CryptoError::InvalidMagicBytes          => write!(f, "Invalid magic bytes. Not a CATWALK file."),
            CryptoError::InvalidVersion             => write!(f, "Unsupported file version."),
            CryptoError::SystemTimeError            => write!(f, "System time error."),
            CryptoError::DecompressionTooLarge      => write!(f, "Decompressed data exceeds maximum allowed size."),
            CryptoError::WeakKdfParameters          => write!(f, "File header contains KDF parameters below the minimum security threshold."),
            CryptoError::KeyfileTooLarge            => write!(f, "Keyfile exceeds maximum size of 1 GB"),
            CryptoError::KeyfileRequired            => write!(f, "This file requires a keyfile for decryption"),
            CryptoError::IoError(e)                 => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}
