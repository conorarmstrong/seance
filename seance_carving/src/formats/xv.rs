use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XV thumbnail image carving signature. Header: "P7 332\n" at offset 0. PhotoRec additionally
/// requires bytes 7, 8 and
/// 9 to be printable ASCII (part of the "#BUILTIN"/dimensions line). No footer.
struct XvSignature;

const XV_MAGIC: &[u8] = b"P7 332\n";

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

impl FileSignature for XvSignature {
    fn name(&self) -> &str {
        "XV"
    }
    fn extensions(&self) -> &[&str] {
        &["xv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 10
            && &buf[0..XV_MAGIC.len()] == XV_MAGIC
            && is_print(buf[7])
            && is_print(buf[8])
            && is_print(buf[9])
        {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "xv".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, XV_MAGIC, Arc::new(XvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xv_header_match() {
        // "P7 332\n" followed by printable dimensions text.
        assert!(XvSignature.header_check(b"P7 332\n640", 0).is_some());
    }

    #[test]
    fn test_xv_no_match() {
        // Wrong magic.
        assert!(XvSignature.header_check(b"P8 332\n640", 0).is_none());
        // Correct magic but non-printable bytes after it.
        assert!(XvSignature
            .header_check(b"P7 332\n\x00\x01\x02", 0)
            .is_none());
        // Buffer too short.
        assert!(XvSignature.header_check(b"P7 332\n", 0).is_none());
    }
}
