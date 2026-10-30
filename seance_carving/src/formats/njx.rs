use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// NJStar Document (NJX) carving signature. Header: {0x04,'N','j',0x0f} at offset 0, with "NJStar"
/// at offset 6.
/// Footer: {'N','J','*',0x04}.
struct NjxSignature;

const NJX_MAGIC: &[u8] = &[0x04, b'N', b'j', 0x0f];
const NJX_FOOTER: &[u8] = &[b'N', b'J', b'*', 0x04];

impl FileSignature for NjxSignature {
    fn name(&self) -> &str {
        "NJX"
    }

    fn extensions(&self) -> &[&str] {
        &["njx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..4] == NJX_MAGIC && &buf[6..12] == b"NJStar" {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "njx".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, NJX_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, NJX_MAGIC, Arc::new(NjxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_njx_header_match() {
        let sig = NjxSignature;
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(NJX_MAGIC);
        buf[6..12].copy_from_slice(b"NJStar");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_njx_no_match() {
        let sig = NjxSignature;
        // Correct magic but missing NJStar tag.
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(NJX_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let bad = vec![0u8; 12];
        assert!(sig.header_check(&bad, 0).is_none());
    }

    #[test]
    fn test_njx_footer_detection() {
        let sig = NjxSignature;
        let mut recovery = FileRecovery {
            extension: "njx".to_string(),
            file_size: 40,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 12,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 5];
        buf.extend_from_slice(NJX_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(40 + 5 + NJX_FOOTER.len() as u64)
        );
    }
}
