use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Reson Sonar Data carving signature. Header: 25-byte fixed magic ending in
/// "[HEADER]" at offset 0. No footer.
struct PdsSignature;

const PDS_MAGIC: &[u8] = &[
    0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x04, 0x5b, b'H', b'E', b'A', b'D', b'E', b'R', 0x5d,
];

impl FileSignature for PdsSignature {
    fn name(&self) -> &str {
        "Reson Sonar Data"
    }
    fn extensions(&self) -> &[&str] {
        &["pds"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= PDS_MAGIC.len() && &buf[0..PDS_MAGIC.len()] == PDS_MAGIC {
            Some(RecoveryInit {
                min_filesize: PDS_MAGIC.len() as u64,
                extension: "pds".to_string(),
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
    registry.register(0, PDS_MAGIC, Arc::new(PdsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pds_header_match() {
        let sig = PdsSignature;
        let mut buf = Vec::from(PDS_MAGIC);
        buf.push(0x00);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_pds_no_match() {
        let sig = PdsSignature;
        let mut buf = Vec::from(PDS_MAGIC);
        buf[0] = 0xff;
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"\x0c\x00\x08", 0).is_none());
    }
}
