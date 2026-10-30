use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Macromedia Freehand 5 carving signature. Header: magic 41 47 44 31 be b8 bb ce at offset 0, then
/// a big-endian
/// datalen at offset 8 giving the payload size. No footer.
struct Fh5Signature;

const FH5_MAGIC: &[u8] = &[0x41, 0x47, 0x44, 0x31, 0xbe, 0xb8, 0xbb, 0xce];

impl FileSignature for Fh5Signature {
    fn name(&self) -> &str {
        "FH5"
    }
    fn extensions(&self) -> &[&str] {
        &["fh5"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..8] != FH5_MAGIC {
            return None;
        }
        // datalen: big-endian size without headers.
        let datalen = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
        // sizeof(struct fh5_header_s) == 12.
        if datalen < 12 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 4096,
            extension: "fh5".to_string(),
            calculated_file_size: Some(datalen),
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
    registry.register(0, FH5_MAGIC, Arc::new(Fh5Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fh5_header_match() {
        let sig = Fh5Signature;
        let mut buf = FH5_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // datalen = 65536
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(65536));
    }

    #[test]
    fn test_fh5_no_match() {
        let sig = Fh5Signature;
        assert!(sig.header_check(b"NOTFH5AAAAAA", 0).is_none());
        // Correct magic but datalen too small.
        let mut buf = FH5_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x05]);
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
