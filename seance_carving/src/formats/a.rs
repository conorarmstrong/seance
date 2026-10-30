use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Unix `ar` archive / Debian package carving signature. Header: "!<arch>\n" (8 bytes) at offset 0,
/// with the first member's magic
/// {0x60,0x0a} at offset 66. Files beginning with "!<arch>\ndebian" use the
/// "deb" extension. No footer or embedded size.
struct ASignature;

const AR_MAGIC: &[u8] = b"!<arch>\n";
const DEBIAN_MAGIC: &[u8] = b"!<arch>\ndebian";

impl FileSignature for ASignature {
    fn name(&self) -> &str {
        "AR"
    }

    fn extensions(&self) -> &[&str] {
        &["a", "deb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // 8-byte ar magic + first file_header (60 bytes); magic {0x60,0x0a}
        // sits at offset 8 + 58 = 66.
        if buf.len() >= 68
            && &buf[0..AR_MAGIC.len()] == AR_MAGIC
            && buf[66] == 0x60
            && buf[67] == 0x0a
        {
            let extension =
                if buf.len() >= DEBIAN_MAGIC.len() && &buf[0..DEBIAN_MAGIC.len()] == DEBIAN_MAGIC {
                    "deb"
                } else {
                    "a"
                };
            Some(RecoveryInit {
                min_filesize: 68,
                extension: extension.to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, AR_MAGIC, Arc::new(ASignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_header_match() {
        let sig = ASignature;
        let mut buf = vec![0u8; 68];
        buf[0..AR_MAGIC.len()].copy_from_slice(AR_MAGIC);
        buf[66] = 0x60;
        buf[67] = 0x0a;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "a");
    }

    #[test]
    fn test_a_debian_extension() {
        let sig = ASignature;
        let mut buf = vec![0u8; 68];
        buf[0..DEBIAN_MAGIC.len()].copy_from_slice(DEBIAN_MAGIC);
        buf[66] = 0x60;
        buf[67] = 0x0a;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "deb");
    }

    #[test]
    fn test_a_no_match() {
        let sig = ASignature;
        // Correct ar magic but wrong member magic at offset 66.
        let mut buf = vec![0u8; 68];
        buf[0..AR_MAGIC.len()].copy_from_slice(AR_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        assert!(sig
            .header_check(b"not an archive here padding pad", 0)
            .is_none());
    }
}
