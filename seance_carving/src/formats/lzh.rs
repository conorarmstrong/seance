use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// lzh/LArc archive carving signature. Header: method id "-lhX-"/"-lzs-"/"-lz4-" at offset 2, level
/// byte at offset 20.
/// No footer. file_rename_level0 (embedded filename) is not implemented; carving is unaffected.
struct LzhSignature;

const LZH_MAGICS: [&[u8]; 11] = [
    b"-lh0-", b"-lh1-", b"-lh2-", b"-lh3-", b"-lh4-", b"-lh5-", b"-lh6-", b"-lh7-", b"-lhd-",
    b"-lzs-", b"-lz4-",
];

impl FileSignature for LzhSignature {
    fn name(&self) -> &str {
        "LZH"
    }
    fn extensions(&self) -> &[&str] {
        &["lzh"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic sits at offset 2 (registered offset). Level byte at offset 20.
        if buf.len() < 22 {
            return None;
        }
        // Guard the method-id shape ("-l?-") at offset 2.
        if buf[2] != b'-' || buf[3] != b'l' || buf[6] != b'-' {
            return None;
        }
        let ok = match buf[20] {
            // Level 0: header_size (buf[0]) must equal 22 + filename_len (buf[21]).
            0 => buf[0] as usize == 22 + buf[21] as usize,
            // Level 1: reserved byte (buf[19]) must be 0x20.
            1 => buf[19] == 0x20,
            // Level 2: accepted.
            2 => true,
            _ => false,
        };
        if !ok {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 22,
            extension: "lzh".to_string(),
            calculated_file_size: None,
        })
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
    for magic in LZH_MAGICS {
        registry.register(2, magic, Arc::new(LzhSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_level(magic: &[u8], level: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 22];
        buf[2..7].copy_from_slice(magic);
        buf[20] = level;
        buf
    }

    #[test]
    fn test_lzh_header_match() {
        let sig = LzhSignature;
        // Level 1 with reserved byte 0x20.
        let mut buf = make_level(b"-lh5-", 1);
        buf[19] = 0x20;
        assert!(sig.header_check(&buf, 0).is_some());
        // Level 2 accepted unconditionally.
        let buf2 = make_level(b"-lh0-", 2);
        assert!(sig.header_check(&buf2, 0).is_some());
    }

    #[test]
    fn test_lzh_no_match() {
        let sig = LzhSignature;
        // Level 1 without the required reserved 0x20.
        let mut buf = make_level(b"-lh5-", 1);
        buf[19] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong shape.
        assert!(sig.header_check(&[0u8; 22], 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
