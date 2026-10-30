use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// X3F (Sigma/Foveon X3 raw picture) carving signature. Header: "FOVb" (0x46 0x4F 0x56 0x62) at
/// offset 0.
/// Validates non-zero rows/columns and a valid rotation; min_filesize 1024, no footer.
/// Note: PhotoRec's disambiguation against the x3i format is not implemented.
struct X3fSignature;

impl FileSignature for X3fSignature {
    fn name(&self) -> &str {
        "X3F"
    }

    fn extensions(&self) -> &[&str] {
        &["x3f"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(struct x3f_header) == 40
        if buf.len() < 40 || &buf[0..4] != b"FOVb" {
            return None;
        }
        let columns = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let rows = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let rotation = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        if rows == 0 || columns == 0 {
            return None;
        }
        if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 1024,
            extension: "x3f".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"FOVb", Arc::new(X3fSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3f_header_match() {
        let mut buf = [0u8; 40];
        buf[0..4].copy_from_slice(b"FOVb");
        buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // columns
        buf[32..36].copy_from_slice(&1u32.to_le_bytes()); // rows
        buf[36..40].copy_from_slice(&0u32.to_le_bytes()); // rotation
        let sig = X3fSignature;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_x3f_no_match() {
        let sig = X3fSignature;
        let mut buf = [0u8; 40];
        buf[0..4].copy_from_slice(b"FOVc");
        assert!(sig.header_check(&buf, 0).is_none());
        // Correct magic but zero rows/columns -> reject.
        buf[0..4].copy_from_slice(b"FOVb");
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
