use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mozilla XPCOM Type Library carving signature. Header: 16-byte magic "XPCOM\nTypeLib\r\n\x1a" at
/// offset 0. The big-endian
/// file_length field (offset 20) encodes the exact file size.
struct XptSignature;

const XPT_MAGIC: &[u8] = b"XPCOM\nTypeLib\r\n\x1a";

impl FileSignature for XptSignature {
    fn name(&self) -> &str {
        "XPT"
    }

    fn extensions(&self) -> &[&str] {
        &["xpt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct TypeLibHeader: magic[16], major(1), minor(1),
        // num_interfaces be16(@18), file_length be32(@20)
        if buf.len() < 24 || &buf[0..16] != XPT_MAGIC {
            return None;
        }
        let file_length = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]) as u64;
        if file_length < 65 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 65,
            extension: "xpt".to_string(),
            calculated_file_size: Some(file_length),
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
    registry.register(0, XPT_MAGIC, Arc::new(XptSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with_len(len: u32) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0..16].copy_from_slice(XPT_MAGIC);
        b[20..24].copy_from_slice(&len.to_be_bytes());
        b
    }

    #[test]
    fn test_xpt_header_match() {
        let sig = XptSignature;
        let init = sig.header_check(&header_with_len(128), 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(128));
    }

    #[test]
    fn test_xpt_no_match() {
        let sig = XptSignature;
        // file_length below the 65-byte minimum.
        assert!(sig.header_check(&header_with_len(10), 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 24], 0).is_none());
    }
}
