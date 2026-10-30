use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Duotone Options carving signature. Header: bytes 0x05 "Black" 0x00 0x00 at offset 0x2c,
/// plus buffer[0]==0 and
/// buffer[1]==1 at file start. No footer; max-size cutoff.
struct AdoSignature;

const ADO_MAGIC: &[u8] = &[0x05, b'B', b'l', b'a', b'c', b'k', 0x00, 0x00];
const ADO_OFFSET: usize = 0x2c;

impl FileSignature for AdoSignature {
    fn name(&self) -> &str {
        "ADO"
    }
    fn extensions(&self) -> &[&str] {
        &["ado"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ADO_OFFSET + ADO_MAGIC.len()
            && buf[0] == 0
            && buf[1] == 1
            && &buf[ADO_OFFSET..ADO_OFFSET + ADO_MAGIC.len()] == ADO_MAGIC
        {
            Some(RecoveryInit {
                min_filesize: (ADO_OFFSET + ADO_MAGIC.len()) as u64,
                extension: "ado".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(ADO_OFFSET as u16, ADO_MAGIC, Arc::new(AdoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; ADO_OFFSET + ADO_MAGIC.len()];
        buf[0] = 0;
        buf[1] = 1;
        buf[ADO_OFFSET..ADO_OFFSET + ADO_MAGIC.len()].copy_from_slice(ADO_MAGIC);
        buf
    }

    #[test]
    fn test_ado_header_match() {
        let sig = AdoSignature;
        let buf = make_buf();
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ado_no_match() {
        let sig = AdoSignature;
        // Missing the leading buffer[1]==1 constraint.
        let mut buf = make_buf();
        buf[1] = 0;
        assert!(sig.header_check(&buf, 0).is_none());
        // Corrupt magic at offset 0x2c.
        let mut buf2 = make_buf();
        buf2[ADO_OFFSET] = 0xFF;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
