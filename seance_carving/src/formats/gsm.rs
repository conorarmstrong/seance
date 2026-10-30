use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GSM 06.10 audio (.gsm) carving signature. A raw GSM stream is a sequence of 33-byte frames, each
/// starting with a marker byte
/// in the range 0xd0..=0xdf. The header check requires at least 3 consecutive valid
/// frames to reduce false positives (the header magic is a single byte).
struct GsmSignature;

const GSM_FRAME: usize = 33;

impl FileSignature for GsmSignature {
    fn name(&self) -> &str {
        "GSM"
    }
    fn extensions(&self) -> &[&str] {
        &["gsm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Validate consecutive 33-byte frame markers, matching header_check_gsm which
        // requires at least 3 valid frames.
        let mut frames = 0usize;
        while (frames + 1) * GSM_FRAME <= buf.len() {
            let marker = buf[frames * GSM_FRAME];
            if !(0xd0..=0xdf).contains(&marker) {
                return None;
            }
            frames += 1;
        }
        if frames < 3 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: GSM_FRAME as u64,
            extension: "gsm".to_string(),
            calculated_file_size: None,
        })
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
    // Frame marker bytes 0xd0..=0xdf are each a valid header start.
    for marker in 0xd0u8..=0xdf {
        registry.register(0, &[marker], Arc::new(GsmSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gsm_header_match() {
        let sig = GsmSignature;
        // three valid 33-byte frames, markers within 0xd0..=0xdf
        let mut buf = Vec::new();
        for marker in [0xd0u8, 0xd5, 0xdf] {
            buf.push(marker);
            buf.extend_from_slice(&[0u8; 32]);
        }
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_gsm_no_match() {
        let sig = GsmSignature;
        // only two valid frames -> too few
        let mut short = Vec::new();
        for _ in 0..2 {
            short.push(0xd0u8);
            short.extend_from_slice(&[0u8; 32]);
        }
        assert!(sig.header_check(&short, 0).is_none());
        // third frame has an out-of-range marker
        let mut bad = Vec::new();
        bad.push(0xd0u8);
        bad.extend_from_slice(&[0u8; 32]);
        bad.push(0xd1u8);
        bad.extend_from_slice(&[0u8; 32]);
        bad.push(0x00u8); // invalid marker
        bad.extend_from_slice(&[0u8; 32]);
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
