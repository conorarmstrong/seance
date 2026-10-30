use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TeX DVI carving signature. Header at offset 0: pre byte 0xf7, version 0x02, then num=0x018392c0
/// and
/// den=0x1c3b0000 big-endian, with the two mag high bytes forced to 0x00.
/// min_filesize = 0x15 + comment-size byte at offset 0x14. No footer.
struct DviSignature;

const DVI_MAGIC: &[u8] = &[
    0xf7, 0x02, 0x01, 0x83, 0x92, 0xc0, 0x1c, 0x3b, 0x00, 0x00, 0x00, 0x00,
];

impl FileSignature for DviSignature {
    fn name(&self) -> &str {
        "DVI"
    }
    fn extensions(&self) -> &[&str] {
        &["dvi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x15 && &buf[0..12] == DVI_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0x15 + buf[0x14] as u64,
                extension: "dvi".to_string(),
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
    registry.register(0, DVI_MAGIC, Arc::new(DviSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dvi_header_match() {
        let sig = DviSignature;
        let mut buf = DVI_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00; 16]); // pad past offset 0x14
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 0x15);
    }

    #[test]
    fn test_dvi_no_match() {
        let sig = DviSignature;
        // Wrong pre byte
        let mut buf = DVI_MAGIC.to_vec();
        buf[0] = 0x00;
        buf.extend_from_slice(&[0x00; 16]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short
        assert!(sig.header_check(DVI_MAGIC, 0).is_none());
    }
}
