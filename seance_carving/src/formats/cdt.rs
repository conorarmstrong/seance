use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ConceptDraw PRO (CDT/CDL/CDD) carving signature. Header: "CONCEPT" (7 bytes) at offset 12. The
/// extension is refined from the
/// first byte: 0xEE -> cdl (library), 0xEF -> cdd (document), 0xF0 -> cdt (template).
/// No footer or embedded size.
const CDT_MAGIC: &[u8] = b"CONCEPT";
const CDT_MAGIC_OFFSET: usize = 12;

struct CdtSignature;

impl FileSignature for CdtSignature {
    fn name(&self) -> &str {
        "CDT"
    }

    fn extensions(&self) -> &[&str] {
        &["cdt", "cdl", "cdd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = CDT_MAGIC_OFFSET + CDT_MAGIC.len();
        if buf.len() >= end && &buf[CDT_MAGIC_OFFSET..end] == CDT_MAGIC {
            let extension = match buf[0] {
                0xee => "cdl",
                0xef => "cdd",
                0xf0 => "cdt",
                _ => "cdt",
            };
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: extension.to_string(),
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
    registry.register(CDT_MAGIC_OFFSET as u16, CDT_MAGIC, Arc::new(CdtSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cdt(first: u8) -> Vec<u8> {
        let mut buf = vec![0u8; CDT_MAGIC_OFFSET];
        buf[0] = first;
        buf.extend_from_slice(CDT_MAGIC);
        buf
    }

    #[test]
    fn test_cdt_header_match() {
        let sig = CdtSignature;
        assert_eq!(
            sig.header_check(&make_cdt(0xee), 0).unwrap().extension,
            "cdl"
        );
        assert_eq!(
            sig.header_check(&make_cdt(0xef), 0).unwrap().extension,
            "cdd"
        );
        assert_eq!(
            sig.header_check(&make_cdt(0xf0), 0).unwrap().extension,
            "cdt"
        );
        assert_eq!(
            sig.header_check(&make_cdt(0x00), 0).unwrap().extension,
            "cdt"
        );
    }

    #[test]
    fn test_cdt_no_match() {
        let sig = CdtSignature;
        // Magic in wrong place.
        assert!(sig.header_check(b"CONCEPTxxxxxxxxxxxx", 0).is_none());
        // Too short.
        assert!(sig.header_check(b"CONCEPT", 0).is_none());
    }
}
