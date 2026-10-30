#![forbid(unsafe_code)]
mod checks;
pub mod custom;
pub mod engine;
pub mod ext2_indirect;
pub mod formats;
pub mod registry;
pub mod signature;

pub use custom::{register_custom_signatures, CustomSignatureSpec};
pub use engine::{CarvedFile, CarvingEngine};
pub use registry::SignatureRegistry;
pub use signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};

#[cfg(test)]
mod scan_tests;
#[cfg(test)]
mod tests;
