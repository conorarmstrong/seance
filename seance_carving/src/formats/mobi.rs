use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mobi e-book carving signature. Header: "BOOKMOBI" at offset 0x3c.
/// Footer: 58-byte FLIS/FCIS trailer, with 26 extra trailing bytes.
struct MobiSignature;

const MOBI_FOOTER: &[u8] = &[
    b'F', b'L', b'I', b'S', 0x00, 0x00, 0x00, 0x08, 0x00, b'A', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
    0xff, 0xff, 0xff, 0xff, b'F', b'C', b'I', b'S', 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const MOBI_FOOTER_EXTRA: u64 = 26;

impl FileSignature for MobiSignature {
    fn name(&self) -> &str {
        "MOBI"
    }

    fn extensions(&self) -> &[&str] {
        &["mobi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x44 && &buf[0x3c..0x44] == b"BOOKMOBI" {
            Some(RecoveryInit {
                min_filesize: 0x44,
                extension: "mobi".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, MOBI_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + MOBI_FOOTER_EXTRA),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0x3c, b"BOOKMOBI", Arc::new(MobiSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobi_header_match() {
        let sig = MobiSignature;
        let mut buf = vec![0u8; 0x44];
        buf[0x3c..0x44].copy_from_slice(b"BOOKMOBI");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mobi_no_match() {
        let sig = MobiSignature;
        let buf = vec![0u8; 0x44];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_mobi_footer_detection() {
        let sig = MobiSignature;
        let mut recovery = FileRecovery {
            extension: "mobi".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 0x44,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 4];
        buf.extend_from_slice(MOBI_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(100 + 4 + MOBI_FOOTER.len() as u64 + MOBI_FOOTER_EXTRA)
        );
    }
}
