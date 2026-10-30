use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VectorWorks MCD carving signature. Header: "VectorWorks" at offset 0x0e, with the first two file
/// bytes both 0x00. No footer.
struct McdSignature;

const MCD_MAGIC: &[u8] = b"VectorWorks";
const MCD_OFFSET: usize = 0x0e;

impl FileSignature for McdSignature {
    fn name(&self) -> &str {
        "MCD"
    }
    fn extensions(&self) -> &[&str] {
        &["mcd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = MCD_OFFSET + MCD_MAGIC.len();
        if buf.len() >= end
            && buf[0] == 0x00
            && buf[1] == 0x00
            && &buf[MCD_OFFSET..end] == MCD_MAGIC
        {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "mcd".to_string(),
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
    registry.register(MCD_OFFSET as u16, MCD_MAGIC, Arc::new(McdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; MCD_OFFSET + MCD_MAGIC.len()];
        buf[MCD_OFFSET..].copy_from_slice(MCD_MAGIC);
        buf
    }

    #[test]
    fn test_mcd_header_match() {
        let sig = McdSignature;
        assert!(sig.header_check(&make_buf(), 0).is_some());
    }

    #[test]
    fn test_mcd_no_match() {
        let sig = McdSignature;
        // Correct magic but first bytes not zero.
        let mut buf = make_buf();
        buf[0] = 0x01;
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let mut buf2 = make_buf();
        buf2[MCD_OFFSET] = b'X';
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
