use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GIMP XCF image carving signature. Header: "gimp xcf " prefix at offset 0 (magics "gimp xcf
/// file",
/// "gimp xcf v00", "gimp xcf v01"). Validates zero byte, non-zero
/// width/height and base_type <= 2. No footer; size not encoded.
struct XcfSignature;

impl FileSignature for XcfSignature {
    fn name(&self) -> &str {
        "XCF"
    }

    fn extensions(&self) -> &[&str] {
        &["xcf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct xcf_header: magic[9], version[4], zero(@13),
        // width be32(@14), height be32(@18), base_type be32(@22)
        if buf.len() < 26 || &buf[0..9] != b"gimp xcf " {
            return None;
        }
        if buf[13] != 0 {
            return None;
        }
        let width = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let height = u32::from_be_bytes([buf[18], buf[19], buf[20], buf[21]]);
        let base_type = u32::from_be_bytes([buf[22], buf[23], buf[24], buf[25]]);
        if width == 0 || height == 0 || base_type > 2 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 26,
            extension: "xcf".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024 * 1024 // 1 GB (PhotoRec value)
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"gimp xcf file", Arc::new(XcfSignature));
    registry.register(0, b"gimp xcf v00", Arc::new(XcfSignature));
    registry.register(0, b"gimp xcf v01", Arc::new(XcfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut v = b"gimp xcf file".to_vec(); // 13 bytes, zero byte follows
        v.push(0x00); // zero @13
        v.extend_from_slice(&[0, 0, 0, 1]); // width = 1
        v.extend_from_slice(&[0, 0, 0, 1]); // height = 1
        v.extend_from_slice(&[0, 0, 0, 0]); // base_type = 0
        v
    }

    #[test]
    fn test_xcf_header_match() {
        let sig = XcfSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_xcf_no_match() {
        let sig = XcfSignature;
        // Wrong prefix
        assert!(sig
            .header_check(b"NOTAXCFHEADER0123456789ABCD", 0)
            .is_none());
        // Valid prefix but base_type > 2
        let mut bad = valid_header();
        bad[25] = 3;
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
