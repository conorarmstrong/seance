use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MYO (Mind Your Own Business / MYOB accounting) carving signature.
/// Header: ASCII "FC!DEF" at offset 0x9ce. The 32-bit little-endian value at
/// the file start (offset 0) plus 1 gives the file size, which must be at
/// least 0x9ce + 6. Size-driven recovery; no footer.
struct MyoSignature;

const MYO_MAGIC_OFFSET: usize = 0x9ce;

impl FileSignature for MyoSignature {
    fn name(&self) -> &str {
        "MYO"
    }
    fn extensions(&self) -> &[&str] {
        &["myo"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < MYO_MAGIC_OFFSET + 6 {
            return None;
        }
        if &buf[MYO_MAGIC_OFFSET..MYO_MAGIC_OFFSET + 6] != b"FC!DEF" {
            return None;
        }
        let size = (buf[0] as u64)
            + ((buf[1] as u64) << 8)
            + ((buf[2] as u64) << 16)
            + ((buf[3] as u64) << 24)
            + 1;
        if size < (MYO_MAGIC_OFFSET as u64) + 6 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0,
            extension: "myo".to_string(),
            calculated_file_size: Some(size),
        })
    }

    /// The magic lies past the engine's 512-byte block: ask to be shown that far.
    fn header_window(&self) -> usize {
        MYO_MAGIC_OFFSET + 6
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
    // Magic sits at 0x9ce (2510), which fits in u16.
    registry.register(MYO_MAGIC_OFFSET as u16, b"FC!DEF", Arc::new(MyoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_myo_header_match() {
        let sig = MyoSignature;
        let mut buf = vec![0u8; MYO_MAGIC_OFFSET + 6];
        buf[MYO_MAGIC_OFFSET..MYO_MAGIC_OFFSET + 6].copy_from_slice(b"FC!DEF");
        // size field: 0xffff + 1 = 65536, well above the 0x9ce+6 minimum.
        buf[0] = 0xff;
        buf[1] = 0xff;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(0x10000));
    }

    #[test]
    fn test_myo_no_match() {
        let sig = MyoSignature;
        // Wrong magic.
        let buf = vec![0u8; MYO_MAGIC_OFFSET + 6];
        assert!(sig.header_check(&buf, 0).is_none());
        // Correct magic but size too small.
        let mut buf2 = vec![0u8; MYO_MAGIC_OFFSET + 6];
        buf2[MYO_MAGIC_OFFSET..MYO_MAGIC_OFFSET + 6].copy_from_slice(b"FC!DEF");
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
