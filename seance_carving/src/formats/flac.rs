use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FLAC audio file signature detector.
/// Header: 66 4C 61 43 ("fLaC") at offset 0, followed by a STREAMINFO metadata block.
/// The first metadata block must be STREAMINFO (block type 0). The block header byte
/// at offset 4 has bit 7 as "last block" flag and bits 0-6 as block type.
/// STREAMINFO is always 34 bytes, encoded as a 24-bit big-endian length at bytes 5-7.
/// No reliable total file size from headers; uses max-size recovery.
/// Ref: https://xiph.org/flac/format.html
struct FlacSignature;

impl FileSignature for FlacSignature {
    fn name(&self) -> &str {
        "FLAC"
    }

    fn extensions(&self) -> &[&str] {
        &["flac"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need at least: 4 (magic) + 1 (block header) + 3 (block length) = 8 bytes
        if buf.len() < 8 {
            return None;
        }

        // Verify magic bytes: "fLaC"
        if buf[0] != 0x66 || buf[1] != 0x4C || buf[2] != 0x61 || buf[3] != 0x43 {
            return None;
        }

        // Byte 4 is the metadata block header:
        //   bit 7: last-metadata-block flag
        //   bits 0-6: block type (must be 0 = STREAMINFO for the first block)
        let block_type = buf[4] & 0x7F;
        if block_type != 0 {
            return None;
        }

        // Bytes 5-7: 24-bit big-endian block data length (STREAMINFO is always 34 bytes)
        let block_length = ((buf[5] as u32) << 16) | ((buf[6] as u32) << 8) | (buf[7] as u32);
        if block_length != 34 {
            return None;
        }

        Some(RecoveryInit {
            // Minimum: 4 (magic) + 4 (block header+length) + 34 (STREAMINFO data) = 42 bytes
            min_filesize: 42,
            extension: "flac".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // FLAC audio frames have no simple end marker we can scan for without
        // full frame parsing. Rely on max_file_size or next-header interruption.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024 * 1024 // 1 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x66, 0x4C, 0x61, 0x43], Arc::new(FlacSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid FLAC header:
    /// 4 bytes magic + 1 byte block header + 3 bytes length (34) + 34 bytes STREAMINFO data = 42 bytes
    fn valid_flac_header() -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic: "fLaC"
        buf.extend_from_slice(&[0x66, 0x4C, 0x61, 0x43]);
        // Block header: last-block flag set (0x80) | block type 0 (STREAMINFO) = 0x80
        buf.push(0x80);
        // Block length: 34 as 24-bit big-endian
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x22); // 34 = 0x22
                        // 34 bytes of STREAMINFO data (contents don't matter for header_check)
        buf.extend_from_slice(&[0u8; 34]);
        buf
    }

    #[test]
    fn test_flac_valid_header() {
        let sig = FlacSignature;
        let buf = valid_flac_header();
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "flac");
        assert_eq!(init.min_filesize, 42);
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_flac_valid_header_not_last_block() {
        let sig = FlacSignature;
        let mut buf = valid_flac_header();
        // Clear last-block flag: block header = 0x00 (block type 0, not last)
        buf[4] = 0x00;
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "flac");
    }

    #[test]
    fn test_flac_invalid_block_type() {
        let sig = FlacSignature;
        let mut buf = valid_flac_header();
        // Set block type to 4 (VORBIS_COMMENT) instead of 0 (STREAMINFO)
        buf[4] = 0x04;
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_invalid_block_type_with_last_flag() {
        let sig = FlacSignature;
        let mut buf = valid_flac_header();
        // Set block type to 3 (SEEKTABLE) with last-block flag
        buf[4] = 0x83;
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_wrong_streaminfo_length() {
        let sig = FlacSignature;
        let mut buf = valid_flac_header();
        // Set block length to 35 instead of 34
        buf[7] = 0x23;
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_no_match() {
        let sig = FlacSignature;
        let buf = vec![0u8; 42];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_short_buffer() {
        let sig = FlacSignature;
        // Only 7 bytes — need at least 8
        let buf = [0x66, 0x4C, 0x61, 0x43, 0x80, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_short_buffer_magic_only() {
        let sig = FlacSignature;
        // Only the 4-byte magic
        let buf = [0x66, 0x4C, 0x61, 0x43];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_flac_max_file_size() {
        let sig = FlacSignature;
        assert_eq!(sig.max_file_size(), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_flac_data_check_continues() {
        let sig = FlacSignature;
        let mut recovery = FileRecovery {
            extension: "flac".to_string(),
            file_size: 1000,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 42,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        assert_eq!(
            sig.data_check(&[], &mut recovery),
            DataCheckResult::Continue
        );
    }
}
