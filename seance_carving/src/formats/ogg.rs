use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OGG container file signature detector.
/// Header: 4F 67 67 53 ("OggS") at offset 0.
/// OGG files consist of concatenated pages; there is no total-size field in the header.
/// We use max-size recovery as a cutoff.
/// Ref: RFC 3533 (OGG encapsulation), RFC 7845 (Opus), RFC 7845 (Vorbis)
struct OggSignature;

impl FileSignature for OggSignature {
    fn name(&self) -> &str {
        "OGG"
    }

    fn extensions(&self) -> &[&str] {
        &["ogg", "oga", "ogv", "opus"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need at least 27 bytes for a minimal OGG page header
        if buf.len() < 27 {
            return None;
        }
        // Magic: "OggS"
        if buf[0] != 0x4F || buf[1] != 0x67 || buf[2] != 0x67 || buf[3] != 0x53 {
            return None;
        }
        // Byte 4: stream structure version (must be 0)
        if buf[4] != 0x00 {
            return None;
        }
        // Byte 5: header type flag — bit 0x02 (beginning of stream) should be set
        // for the first page of a logical bitstream
        if buf[5] & 0x02 == 0 {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 27, // Minimum: one OGG page header
            extension: "ogg".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // OGG pages are concatenated with no reliable end-of-stream marker
        // that we can detect without parsing every page. Rely on max_file_size.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024 * 1024 // 1 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x4F, 0x67, 0x67, 0x53], Arc::new(OggSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ogg_header_match() {
        let sig = OggSignature;
        // Valid OGG page header: magic(4) + version(1) + header_type(1) + granule(8)
        // + serial(4) + page_seq(4) + checksum(4) + num_segments(1) = 27 bytes
        let mut buf = [0u8; 27];
        buf[0] = 0x4F; // 'O'
        buf[1] = 0x67; // 'g'
        buf[2] = 0x67; // 'g'
        buf[3] = 0x53; // 'S'
        buf[4] = 0x00; // version 0
        buf[5] = 0x02; // BOS flag set
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "ogg");
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_ogg_invalid_version() {
        let sig = OggSignature;
        let mut buf = [0u8; 27];
        buf[0] = 0x4F;
        buf[1] = 0x67;
        buf[2] = 0x67;
        buf[3] = 0x53;
        buf[4] = 0x01; // invalid version
        buf[5] = 0x02; // BOS flag set
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_ogg_no_match() {
        let sig = OggSignature;
        let buf = vec![0u8; 27];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_ogg_short_buffer() {
        let sig = OggSignature;
        // Only 4 bytes — too short for a valid OGG page header
        let buf = [0x4F, 0x67, 0x67, 0x53];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_ogg_no_bos_flag() {
        let sig = OggSignature;
        let mut buf = [0u8; 27];
        buf[0] = 0x4F;
        buf[1] = 0x67;
        buf[2] = 0x67;
        buf[3] = 0x53;
        buf[4] = 0x00; // valid version
        buf[5] = 0x00; // BOS flag NOT set — should reject
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
