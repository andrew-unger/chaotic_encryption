use std::io;

#[derive(Debug)]
pub enum CryptoError {
    KeyDerivationFailed,
    IntegrityCheckFailed,
    InvalidCiphertextLength,
    InvalidMagicBytes,
    InvalidVersion,
    SystemTimeError,
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
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed."),
            CryptoError::IntegrityCheckFailed => write!(f, "Integrity check failed."),
            CryptoError::InvalidCiphertextLength => write!(f, "Invalid ciphertext length."),
            CryptoError::InvalidMagicBytes => write!(f, "Invalid magic bytes. Not an AU79 file."),
            CryptoError::InvalidVersion => write!(f, "Unsupported file version."),
            CryptoError::SystemTimeError => write!(f, "System time error."),
            CryptoError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}