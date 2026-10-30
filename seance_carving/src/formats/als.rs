use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Ableton Live Sets carving signature. Header: {0xab,0x1e,'V','x',0x03} at offset 0, plus
/// {0x0c,"LiveDocument"} at
/// offset 11. Footer: 22-byte trailer scanned with extra_length 7.
struct AlsSignature;

const ALS_MAGIC: &[u8] = &[0xab, 0x1e, b'V', b'x', 0x03];
const ALS_HEADER2: &[u8] = &[
    0x0c, b'L', b'i', b'v', b'e', b'D', b'o', b'c', b'u', b'm', b'e', b'n', b't',
];
const ALS_FOOTER: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x80, 0x01,
];

impl FileSignature for AlsSignature {
    fn name(&self) -> &str {
        "ALS"
    }

    fn extensions(&self) -> &[&str] {
        &["als"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 24 && &buf[0..5] == ALS_MAGIC && &buf[11..24] == ALS_HEADER2 {
            Some(RecoveryInit {
                min_filesize: 24,
                extension: "als".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Footer scan: 22-byte trailer plus 7 extra bytes (PhotoRec extra_length).
        match footer_end_spanning(buf, recovery, ALS_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + 7),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ALS_MAGIC, Arc::new(AlsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_als_header_match() {
        let mut buf = Vec::new();
        buf.extend_from_slice(ALS_MAGIC); // 0..5
        buf.extend_from_slice(&[0x00; 6]); // 5..11
        buf.extend_from_slice(ALS_HEADER2); // 11..24
        assert!(AlsSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_als_no_match() {
        let mut buf = Vec::new();
        buf.extend_from_slice(ALS_MAGIC);
        buf.extend_from_slice(&[0x00; 19]);
        // Offset-11 marker absent.
        assert!(AlsSignature.header_check(&buf, 0).is_none());
        assert!(AlsSignature.header_check(b"notals", 0).is_none());
    }

    #[test]
    fn test_als_footer() {
        let mut recovery = FileRecovery {
            extension: "als".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 24,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0x11, 0x22];
        buf.extend_from_slice(ALS_FOOTER);
        let result = AlsSignature.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(100 + 2 + ALS_FOOTER.len() as u64 + 7)
        );
    }
}
