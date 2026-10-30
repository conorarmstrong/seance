use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Macromedia Flash Video (FLV) carving signature. Header: "FLV" 46 4c 56 01 at offset 0;
/// type_flags byte at
/// offset 4 must have no reserved bits set and a big-endian data_offset at
/// offset 5 must be >= 9.
///
/// Note: PhotoRec's data_check_flv walks the tag chain to compute the exact
/// size. That elaborate stateful validation is omitted here; recovery carves
/// to the next header or the max size instead. Header magic and the
/// type_flags/data_offset sanity checks are preserved.
struct FlvSignature;

const FLV_MAGIC: &[u8] = &[b'F', b'L', b'V', 0x01];

impl FileSignature for FlvSignature {
    fn name(&self) -> &str {
        "FLV"
    }
    fn extensions(&self) -> &[&str] {
        &["flv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 9 || &buf[0..4] != FLV_MAGIC {
            return None;
        }
        let type_flags = buf[4];
        let data_offset = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if (type_flags & 0xfa) != 0 || data_offset < 9 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 9,
            extension: "flv".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FLV_MAGIC, Arc::new(FlvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flv_header_match() {
        let sig = FlvSignature;
        // type_flags=0x05 (audio+video bits), data_offset=9 (big endian).
        let buf = [b'F', b'L', b'V', 0x01, 0x05, 0x00, 0x00, 0x00, 0x09];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_flv_no_match() {
        let sig = FlvSignature;
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 9], 0).is_none());
        // Correct magic but reserved type_flags bits set.
        let buf = [b'F', b'L', b'V', 0x01, 0xff, 0x00, 0x00, 0x00, 0x09];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
