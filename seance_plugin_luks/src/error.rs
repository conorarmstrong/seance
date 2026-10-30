//! Error types for LUKS parsing and decryption.

use thiserror::Error;

/// Errors that can occur while parsing a LUKS header or unlocking a volume.
#[derive(Debug, Error)]
pub enum LuksError {
    /// The volume does not begin with the LUKS magic bytes.
    #[error("not a LUKS volume (bad magic)")]
    NotLuks,

    /// The LUKS version is present but not supported by this implementation.
    #[error("unsupported LUKS version: {0}")]
    UnsupportedVersion(u16),

    /// A cipher, mode, hash or KDF named in the header is not implemented here.
    #[error("unsupported parameter: {0}")]
    Unsupported(String),

    /// The on-disk header is truncated or structurally invalid.
    #[error("malformed LUKS header: {0}")]
    Malformed(String),

    /// The LUKS2 JSON metadata area could not be parsed.
    #[error("invalid LUKS2 metadata: {0}")]
    Metadata(String),

    /// The supplied passphrase did not unlock any active keyslot.
    #[error("no keyslot could be unlocked with the supplied passphrase")]
    BadPassphrase,

    /// An I/O error occurred reading the underlying volume.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
