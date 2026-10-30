use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GraphPrism 4 (PZF) carving signature. Header: "PCFFGRA4" at offset 0. Footer: 15 x 0xff then
/// 0x01 0x40.
struct PzfSignature;

const PZF_MAGIC: &[u8] = b"PCFFGRA4";
const PZF_FOOTER: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x40,
];

impl FileSignature for PzfSignature {
    fn name(&self) -> &str {
        "PZF"
    }

    fn extensions(&self) -> &[&str] {
        &["pzf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= PZF_MAGIC.len() && &buf[..PZF_MAGIC.len()] == PZF_MAGIC {
            Some(RecoveryInit {
                min_filesize: PZF_MAGIC.len() as u64,
                extension: "pzf".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // file_search_footer with extra_length 0.
        if let Some(pos) = buf.windows(PZF_FOOTER.len()).position(|w| w == PZF_FOOTER) {
            return DataCheckResult::Stop(
                recovery.file_size + pos as u64 + PZF_FOOTER.len() as u64,
            );
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PZF_MAGIC, Arc::new(PzfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pzf_header_match() {
        let sig = PzfSignature;
        assert!(sig.header_check(b"PCFFGRA4rest", 0).is_some());
    }

    #[test]
    fn test_pzf_no_match() {
        let sig = PzfSignature;
        assert!(sig.header_check(b"PCFFGRA5", 0).is_none());
        assert!(sig.header_check(b"PCFF", 0).is_none());
    }

    #[test]
    fn test_pzf_footer_detection() {
        let sig = PzfSignature;
        let mut recovery = FileRecovery {
            extension: "pzf".to_string(),
            file_size: 300,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 8,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0xaa, 0xbb];
        buf.extend_from_slice(PZF_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        // 300 + pos(2) + footer(17) = 319
        assert_eq!(result, DataCheckResult::Stop(319));
    }
}
