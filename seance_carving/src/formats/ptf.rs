use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro Tools session carving signature. Header: 18-byte magic {0x03,"0010111","10010101",1,0x00} at
/// offset 0.
/// The byte at offset 0x12 selects the extension: 1 -> ptf, 5 -> ptx.
/// No footer; size not encoded.
struct PtfSignature;

const PTF_MAGIC: [u8; 18] = [
    0x03, b'0', b'0', b'1', b'0', b'1', b'1', b'1', b'1', b'0', b'0', b'1', b'0', b'1', b'0', b'1',
    b'1', 0x00,
];

impl FileSignature for PtfSignature {
    fn name(&self) -> &str {
        "PTF"
    }
    fn extensions(&self) -> &[&str] {
        &["ptf", "ptx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 19 && buf[0..18] == PTF_MAGIC {
            let extension = match buf[0x12] {
                1 => "ptf",
                5 => "ptx",
                _ => return None,
            };
            Some(RecoveryInit {
                min_filesize: 19,
                extension: extension.to_string(),
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
    registry.register(0, &PTF_MAGIC, Arc::new(PtfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptf_header_match() {
        let mut buf = PTF_MAGIC.to_vec();
        buf.push(0x00); // byte 0x12
        buf[0x12] = 1;
        let init = PtfSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "ptf");
        buf[0x12] = 5;
        let init = PtfSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "ptx");
    }

    #[test]
    fn test_ptf_no_match() {
        let mut buf = PTF_MAGIC.to_vec();
        buf.push(0x02); // byte 0x12 out of range
        assert!(PtfSignature.header_check(&buf, 0).is_none());
        assert!(PtfSignature.header_check(b"short", 0).is_none());
    }
}
