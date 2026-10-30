use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Steuer 2014/... (German tax software) carving signature. Ported from file_steuer2014.c.
/// Header: {'R',0x26,'S',0x1a,0x11,0x01,0x01,0x00} at offset 0. Two 32-bit LE version
/// fields (offsets 8 and 12) must be equal; the version value selects the year extension.
/// No footer.
struct Steuer2014Signature;

impl Steuer2014Signature {
    fn extension_for(version1: u32) -> &'static str {
        match version1 {
            0x00..=0x12 => "steuer2014",
            0x13 => "steuer2015",
            0x14 => "steuer2016",
            0x15 => "steuer2017",
            0x16 => "steuer2018",
            0x17 => "steuer2019",
            _ => "steuer2020",
        }
    }
}

impl FileSignature for Steuer2014Signature {
    fn name(&self) -> &str {
        "STEUER2014"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "steuer2014",
            "steuer2015",
            "steuer2016",
            "steuer2017",
            "steuer2018",
            "steuer2019",
            "steuer2020",
        ]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[b'R', 0x26, b'S', 0x1a, 0x11, 0x01, 0x01, 0x00];
        if buf.len() >= 16 && &buf[0..8] == MAGIC {
            let version1 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
            let version2 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
            if version1 != version2 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 16,
                extension: Steuer2014Signature::extension_for(version1).to_string(),
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
    registry.register(
        0,
        &[b'R', 0x26, b'S', 0x1a, 0x11, 0x01, 0x01, 0x00],
        Arc::new(Steuer2014Signature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steuer2014_header_match() {
        let sig = Steuer2014Signature;
        let mut buf = vec![b'R', 0x26, b'S', 0x1a, 0x11, 0x01, 0x01, 0x00];
        buf.extend_from_slice(&[0, 0, 0, 0]); // version1 = 0 -> steuer2014
        buf.extend_from_slice(&[0, 0, 0, 0]); // version2 = 0 (equal)
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "steuer2014");
    }

    #[test]
    fn test_steuer2014_no_match() {
        let sig = Steuer2014Signature;
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        // Correct magic but version fields differ.
        let mut buf = vec![b'R', 0x26, b'S', 0x1a, 0x11, 0x01, 0x01, 0x00];
        buf.extend_from_slice(&[1, 0, 0, 0]);
        buf.extend_from_slice(&[2, 0, 0, 0]);
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
