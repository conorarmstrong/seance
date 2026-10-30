use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MUS (Finale Music Score) carving signature. Header: ASCII "ENIGMA BINARY FILE" at offset 0.
/// Footer: "-^end" located via
/// file_search_footer, so recovery stops when the trailer is seen.
struct MusSignature;

const MUS_FOOTER: &[u8] = b"-^end";

impl FileSignature for MusSignature {
    fn name(&self) -> &str {
        "MUS"
    }
    fn extensions(&self) -> &[&str] {
        &["mus"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 18 && &buf[0..18] == b"ENIGMA BINARY FILE" {
            Some(RecoveryInit {
                min_filesize: 18,
                extension: "mus".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, MUS_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"ENIGMA BINARY FILE", Arc::new(MusSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mus_header_match() {
        let sig = MusSignature;
        assert!(sig.header_check(b"ENIGMA BINARY FILE\x00\x00", 0).is_some());
    }

    #[test]
    fn test_mus_no_match() {
        let sig = MusSignature;
        assert!(sig.header_check(b"ENIGMA TEXT FILE!!", 0).is_none());
        assert!(sig.header_check(b"ENIGMA", 0).is_none());
    }

    #[test]
    fn test_mus_footer_detection() {
        let sig = MusSignature;
        let mut recovery = FileRecovery {
            extension: "mus".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 18,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let buf = b"\x00\x00-^end\x00";
        let result = sig.data_check(buf, &mut recovery);
        // footer starts at index 2, length 5 -> 100 + 2 + 5 = 107
        assert_eq!(result, DataCheckResult::Stop(107));
    }
}
