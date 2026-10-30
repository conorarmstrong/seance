use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER Manufacturing carving signature. Header: "#UGC:2 MFG_ASSEM" (16 bytes) at offset 0.
/// Footer: "#END_OF_UGC" plus 1 trailing byte (file_search_footer extra_length=1).
struct MfgSignature;

const MFG_MAGIC: [u8; 16] = *b"#UGC:2 MFG_ASSEM";
const MFG_FOOTER: [u8; 11] = *b"#END_OF_UGC";
const MFG_FOOTER_EXTRA: u64 = 1;

impl FileSignature for MfgSignature {
    fn name(&self) -> &str {
        "Pro/ENGINEER Manufacturing"
    }
    fn extensions(&self) -> &[&str] {
        &["mfg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= MFG_MAGIC.len() && buf[0..MFG_MAGIC.len()] == MFG_MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "mfg".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the "#END_OF_UGC" footer; the file ends 1 byte past it.
        match footer_end_spanning(buf, recovery, &MFG_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + MFG_FOOTER_EXTRA),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &MFG_MAGIC, Arc::new(MfgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfg_header_match() {
        let sig = MfgSignature;
        let mut buf = MFG_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mfg_no_match() {
        let sig = MfgSignature;
        assert!(sig.header_check(b"#UGC:2 NOT_ASSEM", 0).is_none());
        assert!(sig.header_check(b"#UGC", 0).is_none());
    }

    #[test]
    fn test_mfg_footer_stop() {
        let sig = MfgSignature;
        let mut recovery = FileRecovery {
            extension: "mfg".to_string(),
            file_size: 200,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 16,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 3];
        buf.extend_from_slice(&MFG_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(200 + 3 + MFG_FOOTER.len() as u64 + MFG_FOOTER_EXTRA)
        );
    }
}
