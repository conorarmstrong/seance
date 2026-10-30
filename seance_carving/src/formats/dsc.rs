use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Nikon DSC carving signature. Header: ASCII "MLT" at offset 588. PhotoRec requires at least 1024
/// bytes of
/// data present (a header window past the engine's 512-byte block, `header_window`)
/// and sets a minimum file size of 588+3. No footer.
struct DscSignature;

const DSC_OFFSET: usize = 588;

impl FileSignature for DscSignature {
    fn name(&self) -> &str {
        "DSC"
    }
    fn extensions(&self) -> &[&str] {
        &["dsc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 1024 && &buf[DSC_OFFSET..DSC_OFFSET + 3] == b"MLT" {
            Some(RecoveryInit {
                min_filesize: (DSC_OFFSET + 3) as u64,
                extension: "dsc".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn header_window(&self) -> usize {
        1024
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(588, b"MLT", Arc::new(DscSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsc_header_match() {
        let mut buf = vec![0u8; 1024];
        buf[DSC_OFFSET..DSC_OFFSET + 3].copy_from_slice(b"MLT");
        assert!(DscSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dsc_no_match() {
        let buf = vec![0u8; 1024];
        assert!(DscSignature.header_check(&buf, 0).is_none());
        // Magic present but buffer too short (< 1024 bytes).
        let mut short = vec![0u8; DSC_OFFSET + 3];
        short[DSC_OFFSET..DSC_OFFSET + 3].copy_from_slice(b"MLT");
        assert!(DscSignature.header_check(&short, 0).is_none());
    }
}
