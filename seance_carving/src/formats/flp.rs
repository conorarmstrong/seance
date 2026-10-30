use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Fruity Loops project (FLP) carving signature. Header: "FLhd" chunk 46 4c 68 64 06 00 00 00 at
/// offset 0,
/// followed by an "FLdt" data chunk at offset 14 whose little-endian length
/// (offset 18) plus the 0x16-byte header gives the file size. No footer.
struct FlpSignature;

const FLP_MAGIC: &[u8] = &[b'F', b'L', b'h', b'd', 0x06, 0x00, 0x00, 0x00];

impl FileSignature for FlpSignature {
    fn name(&self) -> &str {
        "FLP"
    }
    fn extensions(&self) -> &[&str] {
        &["flp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 22 || &buf[0..8] != FLP_MAGIC {
            return None;
        }
        // Second chunk magic "FLdt" at offset 14.
        if &buf[14..18] != b"FLdt" {
            return None;
        }
        let len2 = u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]) as u64;
        if len2 == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 22,
            extension: "flp".to_string(),
            calculated_file_size: Some(len2 + 0x16),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FLP_MAGIC, Arc::new(FlpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flp_header_match() {
        let sig = FlpSignature;
        let mut buf = FLP_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // format/tracks/time
        buf.extend_from_slice(b"FLdt"); // offset 14
        buf.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // len2 = 16, offset 18
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(16 + 0x16));
    }

    #[test]
    fn test_flp_no_match() {
        let sig = FlpSignature;
        // Correct FLhd magic but missing FLdt chunk.
        let mut buf = FLP_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 14]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        assert!(sig.header_check(&[0u8; 22], 0).is_none());
    }
}
