use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER Model (PRT) carving signature. Header: "#UGC:2 PART " at offset 0. Footer:
/// "#END_OF_UGC" plus one trailing byte.
struct PrtSignature;

const PRT_MAGIC: &[u8] = b"#UGC:2 PART ";
const PRT_FOOTER: &[u8] = b"#END_OF_UGC";

impl FileSignature for PrtSignature {
    fn name(&self) -> &str {
        "PRT"
    }

    fn extensions(&self) -> &[&str] {
        &["prt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= PRT_MAGIC.len() && &buf[..PRT_MAGIC.len()] == PRT_MAGIC {
            Some(RecoveryInit {
                min_filesize: PRT_MAGIC.len() as u64,
                extension: "prt".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // file_search_footer with extra_length 1: keep one byte past the footer.
        match footer_end_spanning(buf, recovery, PRT_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + 1),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PRT_MAGIC, Arc::new(PrtSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prt_header_match() {
        let sig = PrtSignature;
        assert!(sig.header_check(b"#UGC:2 PART body", 0).is_some());
    }

    #[test]
    fn test_prt_no_match() {
        let sig = PrtSignature;
        assert!(sig.header_check(b"#UGC:2 CURVE", 0).is_none());
        assert!(sig.header_check(b"#UGC", 0).is_none());
    }

    #[test]
    fn test_prt_footer_detection() {
        let sig = PrtSignature;
        let mut recovery = FileRecovery {
            extension: "prt".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 12,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(b"xx#END_OF_UGC\n");
        let result = sig.data_check(&buf, &mut recovery);
        // 100 + pos(2) + footer(11) + extra(1) = 114
        assert_eq!(result, DataCheckResult::Stop(114));
    }
}
