use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FileMaker Pro database (FP7/FMP12) carving signature. Header: a 20-byte magic at offset 0 ending
/// in "HBAM7", and an
/// "HBAM" marker at offset 0x20d. The "Pro 12" string at offset 0x21e selects
/// the fmp12 extension. No footer.
///
/// The markers lie past the engine's 512-byte block, so the signature asks for
/// a header window (`header_window`) and the engine reads ahead for it.
///
/// Note: PhotoRec's file_check_fp7 truncates the recovered size down to a
/// 4096-byte multiple; that final alignment is omitted here.
struct Fp7Signature;

const FP7_MAGIC: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x02, 0xc0, b'H',
    b'B', b'A', b'M', b'7',
];

impl FileSignature for Fp7Signature {
    fn name(&self) -> &str {
        "FP7"
    }
    fn extensions(&self) -> &[&str] {
        &["fp7", "fmp12"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x230 || &buf[0x20d..0x211] != b"HBAM" {
            return None;
        }
        let extension = if &buf[0x21e..0x224] == b"Pro 12" {
            "fmp12"
        } else {
            "fp7"
        };
        Some(RecoveryInit {
            min_filesize: 4096,
            extension: extension.to_string(),
            calculated_file_size: None,
        })
    }

    fn header_window(&self) -> usize {
        0x230
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FP7_MAGIC, Arc::new(Fp7Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp7_header_match() {
        let sig = Fp7Signature;
        let mut buf = vec![0u8; 0x230];
        buf[0..FP7_MAGIC.len()].copy_from_slice(FP7_MAGIC);
        buf[0x20d..0x211].copy_from_slice(b"HBAM");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "fp7");
    }

    #[test]
    fn test_fp7_fmp12_extension() {
        let sig = Fp7Signature;
        let mut buf = vec![0u8; 0x230];
        buf[0..FP7_MAGIC.len()].copy_from_slice(FP7_MAGIC);
        buf[0x20d..0x211].copy_from_slice(b"HBAM");
        buf[0x21e..0x224].copy_from_slice(b"Pro 12");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "fmp12");
    }

    #[test]
    fn test_fp7_no_match() {
        let sig = Fp7Signature;
        // Too short.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        // Long enough but missing HBAM marker at 0x20d.
        assert!(sig.header_check(&vec![0u8; 0x230], 0).is_none());
    }
}
