use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RPM package carving signature. Header: 0xed 0xab 0xee 0xdb 0x03 (RPM v3 lead) at offset 0. The
/// 96-byte lead
/// is validated: type (be16 @6) <= 1, signature_type (be16 @78) in {0,1,5}, and
/// a non-empty package name (@10). No footer; PhotoRec enforces a minimum size.
struct RpmSignature;

impl FileSignature for RpmSignature {
    fn name(&self) -> &str {
        "RPM"
    }
    fn extensions(&self) -> &[&str] {
        &["rpm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need the full 96-byte rpmlead to validate signature_type @78..80.
        if buf.len() < 96 {
            return None;
        }
        let hdr_type = u16::from_be_bytes([buf[6], buf[7]]);
        if hdr_type > 1 {
            return None; // 0=bin 1=src
        }
        let signature_type = u16::from_be_bytes([buf[78], buf[79]]);
        match signature_type {
            0 | 1 | 5 => {} // RPMSIG_NONE / RPMSIG_PGP262_1024 / RPMSIG_HEADERSIG
            _ => return None,
        }
        if buf[10] == 0 {
            return None; // name[0] must be non-empty
        }
        Some(RecoveryInit {
            min_filesize: 96 + 16 + 16, // file header + checksum + content header
            extension: "rpm".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0xed, 0xab, 0xee, 0xdb, 0x03], Arc::new(RpmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_lead() -> Vec<u8> {
        let mut buf = vec![0u8; 96];
        buf[0..5].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 0x03]);
        buf[10] = b'p'; // name[0]
        buf
    }

    #[test]
    fn test_rpm_header_match() {
        let sig = RpmSignature;
        let buf = base_lead(); // type=0, signature_type=0, name set
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rpm_no_match() {
        let sig = RpmSignature;
        // type > 1
        let mut buf = base_lead();
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // bad signature_type
        let mut buf = base_lead();
        buf[78..80].copy_from_slice(&7u16.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // empty name
        let mut buf = base_lead();
        buf[10] = 0;
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
