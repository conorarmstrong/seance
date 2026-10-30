use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Fallout 4 Savegame carving signature. Header: ASCII "FO4_SAVEGAM" at offset 0 (the C source
/// registers the
/// literal "FO4_SAVEGAME" but with a compare length of 11, so only the
/// first 11 bytes form the magic). Header-only, no footer or fixed size.
struct FosSignature;

const FOS_MAGIC: &[u8] = b"FO4_SAVEGAM";

impl FileSignature for FosSignature {
    fn name(&self) -> &str {
        "Fallout 4 Savegame"
    }
    fn extensions(&self) -> &[&str] {
        &["fos"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= FOS_MAGIC.len() && &buf[0..FOS_MAGIC.len()] == FOS_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0x10,
                extension: "fos".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FOS_MAGIC, Arc::new(FosSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fos_header_match() {
        let sig = FosSignature;
        assert!(sig
            .header_check(b"FO4_SAVEGAME\x00\x00\x00\x00", 0)
            .is_some());
    }

    #[test]
    fn test_fos_no_match() {
        let sig = FosSignature;
        assert!(sig.header_check(b"FO4_SAVXXXXX", 0).is_none());
        assert!(sig.header_check(b"FO4", 0).is_none());
    }
}
