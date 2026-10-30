use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Macromedia/Adobe Flash (SWF) carving signature. Three magic variants at offset 0:
///   - `CWS` zlib-compressed  -> ext "swc", size = LE uint32 at offset 4
///   - `FWS` uncompressed      -> ext "swf", size = LE uint32 at offset 4
///   - `ZWS` LZMA-compressed   -> ext "swf", size = 17 + compressedLen (LE u32 @8)
///
/// No footer. PhotoRec's extra validation (FWS rectangle bit-field via read_SB
/// and CWS zlib inflate probe) is not implemented (see note); version and size-field
/// checks are retained.
struct SwfSignature;

impl FileSignature for SwfSignature {
    fn name(&self) -> &str {
        "SWF"
    }
    fn extensions(&self) -> &[&str] {
        &["swf", "swc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 {
            return None;
        }
        let magic = &buf[0..3];
        if magic == b"CWS" {
            // Compressed flash with Z_DEFLATED.
            if !(buf[3] >= 6 && buf[3] <= 20 && (buf[8] & 0x0f) == 8) {
                return None;
            }
            let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
            if size < 9 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "swc".to_string(),
                calculated_file_size: Some(size),
            })
        } else if magic == b"FWS" {
            if !(buf[3] >= 3 && buf[3] <= 20) {
                return None;
            }
            let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
            if size < 9 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "swf".to_string(),
                calculated_file_size: Some(size),
            })
        } else if magic == b"ZWS" {
            // ZWS (LZMA) compression is permitted in SWF 13 or later only.
            let version = buf[3];
            if !(13..=50).contains(&version) {
                return None;
            }
            let script_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let compressed_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
            if script_len < 8 || compressed_len < 6 {
                return None;
            }
            // 4 (header) + 4 (scriptLen) + 4 (compressedLen) + 5 (LZMA props) + data
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "swf".to_string(),
                calculated_file_size: Some(17 + compressed_len),
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
    registry.register(0, b"CWS", Arc::new(SwfSignature));
    registry.register(0, b"FWS", Arc::new(SwfSignature));
    registry.register(0, b"ZWS", Arc::new(SwfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swf_header_match() {
        let sig = SwfSignature;
        // FWS uncompressed, version 6, size 100
        let mut buf = [0u8; 12];
        buf[0..3].copy_from_slice(b"FWS");
        buf[3] = 6;
        buf[4..8].copy_from_slice(&100u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match FWS");
        assert_eq!(init.extension, "swf");
        assert_eq!(init.calculated_file_size, Some(100));

        // CWS compressed -> swc extension
        let mut cbuf = [0u8; 12];
        cbuf[0..3].copy_from_slice(b"CWS");
        cbuf[3] = 8;
        cbuf[4..8].copy_from_slice(&200u32.to_le_bytes());
        cbuf[8] = 0x08; // zlib CM nibble
        let cinit = sig.header_check(&cbuf, 0).expect("should match CWS");
        assert_eq!(cinit.extension, "swc");
    }

    #[test]
    fn test_swf_no_match() {
        let sig = SwfSignature;
        // Unknown magic
        let mut buf = [0u8; 12];
        buf[0..3].copy_from_slice(b"ABC");
        assert!(sig.header_check(&buf, 0).is_none());
        // FWS but size below minimum
        let mut buf2 = [0u8; 12];
        buf2[0..3].copy_from_slice(b"FWS");
        buf2[3] = 6;
        buf2[4..8].copy_from_slice(&3u32.to_le_bytes());
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
