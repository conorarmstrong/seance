use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Java Class carving signature. Header: CA FE BA BE at offset 0, with major_version (be16 @6) in
/// 45..=100
/// and constant_pool_count (be16 @8) > 0. No footer, no encoded size.
struct ClassSignature;

impl FileSignature for ClassSignature {
    fn name(&self) -> &str {
        "Java Class"
    }
    fn extensions(&self) -> &[&str] {
        &["class"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 10 && buf[0] == 0xCA && buf[1] == 0xFE && buf[2] == 0xBA && buf[3] == 0xBE {
            let major_version = u16::from_be_bytes([buf[6], buf[7]]);
            let constant_pool_count = u16::from_be_bytes([buf[8], buf[9]]);
            if (45..=100).contains(&major_version) && constant_pool_count > 0 {
                return Some(RecoveryInit {
                    min_filesize: 10,
                    extension: "class".to_string(),
                    calculated_file_size: None,
                });
            }
        }
        None
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
    registry.register(0, &[0xCA, 0xFE, 0xBA, 0xBE], Arc::new(ClassSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_header_match() {
        let sig = ClassSignature;
        // major_version 52 (Java 8), constant_pool_count 10.
        let buf = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x0A];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_class_no_match() {
        let sig = ClassSignature;
        // Wrong magic.
        assert!(sig
            .header_check(&[0x00, 0x01, 0x02, 0x03, 0, 0, 0, 0x34, 0, 0x0A], 0)
            .is_none());
        // major_version out of range (255).
        assert!(sig
            .header_check(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0x00, 0xFF, 0, 0x0A], 0)
            .is_none());
    }
}
