use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Silhouette Studio carving signature. Header at offset 0: "silhouette04;". The size field is a
/// little-endian
/// uint32 at offset 14 (magic[12] + unk[2]); calculated file size = size + 77.
/// No footer; size is enforced from the header.
const STUDIO_MAGIC: &[u8] = b"silhouette04;";

struct StudioSignature;

impl FileSignature for StudioSignature {
    fn name(&self) -> &str {
        "Silhouette Studio"
    }
    fn extensions(&self) -> &[&str] {
        &["studio"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < STUDIO_MAGIC.len() || &buf[..STUDIO_MAGIC.len()] != STUDIO_MAGIC {
            return None;
        }
        // Size is a LE uint32 at offset 14 (magic[12] + unk[2]); total = size + 77.
        let calculated_file_size = if buf.len() >= 18 {
            let size = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]) as u64;
            Some(size + 77)
        } else {
            None
        };
        Some(RecoveryInit {
            min_filesize: 77,
            extension: "studio".to_string(),
            calculated_file_size,
        })
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
    registry.register(0, STUDIO_MAGIC, Arc::new(StudioSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_studio_header_match() {
        let sig = StudioSignature;
        // magic(13) + unk(1 to reach offset 14) + size(4).
        let mut buf = STUDIO_MAGIC.to_vec();
        buf.push(0x00); // offset 13 (unk[1])
        buf.extend_from_slice(&100u32.to_le_bytes()); // size at offset 14..18
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(100 + 77));
    }

    #[test]
    fn test_studio_no_match() {
        let sig = StudioSignature;
        assert!(sig.header_check(b"silhouette05;", 0).is_none());
        assert!(sig.header_check(b"NOTSTUDIO", 0).is_none());
    }
}
