use thiserror::Error;

/// Errors from BitLocker detection, metadata parsing, and unlock.
#[derive(Debug, Error)]
pub enum BitlockerError {
    #[error("not a BitLocker volume")]
    NotBitlocker,
    #[error("malformed FVE metadata: {0}")]
    Malformed(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("no volume master key could be unlocked with the supplied credential")]
    BadCredential,
    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
