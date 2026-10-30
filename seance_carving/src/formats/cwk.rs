use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AppleWorks / ClarisWorks (CWK) carving signature. Header: "BOBO" creator type at offset 4, with
/// reserved0 (be64 @12) == 0 and
/// reserved1 (be16 @20) == 1. Footer: trailing marker 0xF0 0xF1 0xF2 0xF3.
struct CwkSignature;

const CWK_FOOTER: [u8; 4] = [0xf0, 0xf1, 0xf2, 0xf3];

impl FileSignature for CwkSignature {
    fn name(&self) -> &str {
        "CWK"
    }
    fn extensions(&self) -> &[&str] {
        &["cwk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 22
            && &buf[4..8] == b"BOBO"
            && buf[12..20].iter().all(|&b| b == 0)
            && buf[20] == 0x00
            && buf[21] == 0x01
        {
            Some(RecoveryInit {
                min_filesize: 22,
                extension: "cwk".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, &CWK_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        200 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(4, b"BOBO", Arc::new(CwkSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[4..8].copy_from_slice(b"BOBO");
        // reserved0 (12..20) stays zero; reserved1 (be16 @20) == 1
        buf[20] = 0x00;
        buf[21] = 0x01;
        buf
    }

    #[test]
    fn test_cwk_header_match() {
        assert!(CwkSignature.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_cwk_no_match() {
        // Wrong creator type.
        let mut buf = valid_header();
        buf[4..8].copy_from_slice(b"NONO");
        assert!(CwkSignature.header_check(&buf, 0).is_none());
        // reserved1 != 1.
        let mut buf2 = valid_header();
        buf2[21] = 0x02;
        assert!(CwkSignature.header_check(&buf2, 0).is_none());
    }

    #[test]
    fn test_cwk_footer_detection() {
        let mut recovery = FileRecovery {
            extension: "cwk".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 22,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let buf = [0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0x00];
        assert_eq!(
            CwkSignature.data_check(&buf, &mut recovery),
            DataCheckResult::Stop(105)
        );
    }
}
