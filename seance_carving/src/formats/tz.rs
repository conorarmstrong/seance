use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Timezone info (.tz, tzfile) carving signature. Ported from file_tz.c.
/// Header variant 1: "TZif" followed by 16 NUL bytes (20 bytes) at offset 0.
/// Header variant 2: "TZif2" followed by 15 NUL bytes (20 bytes) at offset 0.
/// No footer.
struct TzSignature;

const TZ1: &[u8] = &[
    b'T', b'Z', b'i', b'f', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const TZ2: &[u8] = &[
    b'T', b'Z', b'i', b'f', b'2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

impl FileSignature for TzSignature {
    fn name(&self) -> &str {
        "TZ"
    }

    fn extensions(&self) -> &[&str] {
        &["tz"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 20 && (&buf[0..20] == TZ1 || &buf[0..20] == TZ2) {
            Some(RecoveryInit {
                min_filesize: 20,
                extension: "tz".to_string(),
                calculated_file_size: None,
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
    registry.register(0, TZ1, Arc::new(TzSignature));
    registry.register(0, TZ2, Arc::new(TzSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tz_header_match() {
        let sig = TzSignature;
        assert!(sig.header_check(TZ1, 0).is_some());
        assert!(sig.header_check(TZ2, 0).is_some());
    }

    #[test]
    fn test_tz_no_match() {
        let sig = TzSignature;
        // "TZif" but a non-zero byte where a NUL is required.
        let mut buf = TZ1.to_vec();
        buf[10] = 0x01;
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOTZif00000000000000", 0).is_none());
    }
}
