use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// STL binary (Stereolithography CAD) carving signature. Ported from file_stl.c.
/// Header: "solid " at offset 0. The 80-byte text header must contain a NUL within the
/// first 65 bytes, followed only by spaces up to byte 80. Size is encoded: 80 + 4 +
/// triangle_count * 50, where triangle_count is a 32-bit LE value at offset 80.
struct StlSignature;

impl FileSignature for StlSignature {
    fn name(&self) -> &str {
        "STL"
    }

    fn extensions(&self) -> &[&str] {
        &["stl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 84 || &buf[0..6] != b"solid " {
            return None;
        }
        // First NUL must appear within the first 65 bytes (i <= 64).
        let mut i = 0usize;
        while i < 80 && buf[i] != 0 {
            i += 1;
        }
        if i > 64 {
            return None;
        }
        // Everything after the NUL up to byte 80 must be spaces.
        i += 1;
        while i < 80 && buf[i] == b' ' {
            i += 1;
        }
        if i != 80 {
            return None;
        }
        let count = u32::from_le_bytes([buf[80], buf[81], buf[82], buf[83]]) as u64;
        let filesize = 80 + 4 + count * 50;
        Some(RecoveryInit {
            min_filesize: 84,
            extension: "stl".to_string(),
            calculated_file_size: Some(filesize),
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
    registry.register(0, b"solid ", Arc::new(StlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stl_header_match() {
        let sig = StlSignature;
        let mut buf = vec![0u8; 84];
        buf[0..6].copy_from_slice(b"solid ");
        buf[6] = 0; // NUL at position 6
        for b in buf.iter_mut().take(80).skip(7) {
            *b = b' ';
        }
        buf[80] = 1; // triangle_count = 1
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(80 + 4 + 50));
    }

    #[test]
    fn test_stl_no_match() {
        let sig = StlSignature;
        // No "solid " prefix.
        assert!(sig.header_check(&[0x41u8; 84], 0).is_none());
        // Prefix ok but no NUL in first 80 bytes -> i reaches 80 (> 64).
        let mut buf = vec![b' '; 84];
        buf[0..6].copy_from_slice(b"solid ");
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
