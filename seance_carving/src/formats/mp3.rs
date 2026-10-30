use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MP3 audio file signature detector (ID3v2 tag detection path).
/// Header: 49 44 33 ("ID3") at offset 0, followed by version and syncsafe tag size.
/// ID3v2 versions 2, 3, and 4 are recognized.
/// MP3 total file size cannot be determined from the ID3 tag alone, so we rely on
/// max-size recovery.
/// Ref: ID3v2 spec (id3.org), reference/testdisk/src/file_mp3.c
struct Mp3Signature;

impl FileSignature for Mp3Signature {
    fn name(&self) -> &str {
        "MP3"
    }

    fn extensions(&self) -> &[&str] {
        &["mp3"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // ID3v2 header is 10 bytes minimum
        if buf.len() < 10 {
            return None;
        }
        // Magic: "ID3"
        if buf[0] != 0x49 || buf[1] != 0x44 || buf[2] != 0x33 {
            return None;
        }
        // Version byte at offset 3 must be 2, 3, or 4
        let version = buf[3];
        if version != 2 && version != 3 && version != 4 {
            return None;
        }

        // Bytes 6-9: syncsafe integer encoding the tag size (excludes the 10-byte header).
        // Each byte uses only the lower 7 bits; bit 7 must be 0.
        for &b in &buf[6..10] {
            if b & 0x80 != 0 {
                return None;
            }
        }
        let _tag_size = ((buf[6] as u32) << 21)
            | ((buf[7] as u32) << 14)
            | ((buf[8] as u32) << 7)
            | (buf[9] as u32);

        // Tag size alone is not the full MP3 file size (audio frames follow),
        // so we do not set calculated_file_size.
        Some(RecoveryInit {
            min_filesize: 10, // At minimum the ID3 header itself
            extension: "mp3".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // MP3 audio frames are complex to validate without a full decoder.
        // Rely on max_file_size or next-header interruption.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024 // 256 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x49, 0x44, 0x33], Arc::new(Mp3Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid ID3v2 header with the given version byte
    /// and syncsafe tag size bytes.
    fn make_id3v2_header(version: u8, revision: u8, flags: u8, size: [u8; 4]) -> Vec<u8> {
        vec![
            0x49, 0x44, 0x33, // "ID3"
            version, revision, flags, size[0], size[1], size[2], size[3],
        ]
    }

    #[test]
    fn test_mp3_id3v2_3_header_match() {
        let sig = Mp3Signature;
        // ID3v2.3.0, no flags, tag size = 0
        let buf = make_id3v2_header(3, 0, 0x00, [0x00, 0x00, 0x00, 0x00]);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "mp3");
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_mp3_id3v2_4_header_match() {
        let sig = Mp3Signature;
        // ID3v2.4.0, no flags, tag size = 1024 syncsafe (0x00, 0x00, 0x08, 0x00)
        let buf = make_id3v2_header(4, 0, 0x00, [0x00, 0x00, 0x08, 0x00]);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "mp3");
    }

    #[test]
    fn test_mp3_invalid_version_rejected() {
        let sig = Mp3Signature;
        // ID3v2.5 does not exist — should be rejected
        let buf = make_id3v2_header(5, 0, 0x00, [0x00, 0x00, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Version 0 should also be rejected
        let buf = make_id3v2_header(0, 0, 0x00, [0x00, 0x00, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_mp3_no_match() {
        let sig = Mp3Signature;
        // Buffer with no ID3 magic
        let buf = vec![0u8; 10];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_mp3_short_buffer() {
        let sig = Mp3Signature;
        // Buffer too short for the 10-byte ID3v2 header
        let buf = [0x49, 0x44, 0x33, 0x03, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
