use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Guitar Pro 4 & 5 (.gp4 / .gp5) carving signature. Header at offset 0: 0x18 "FICHIER GUITAR PRO
/// v" (21 bytes). Byte 21 is the version
/// digit ('4' -> gp4, '5' -> gp5) and byte 22 must be '.'.
/// Footer (gp5 only): 00 00 00 01 00 00 00 40 00 00 00 00 00 (13 bytes).
struct Gp5Signature;

const GP5_MAGIC: &[u8] = &[
    0x18, b'F', b'I', b'C', b'H', b'I', b'E', b'R', b' ', b'G', b'U', b'I', b'T', b'A', b'R', b' ',
    b'P', b'R', b'O', b' ', b'v',
];

const GP5_FOOTER: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
];

impl FileSignature for Gp5Signature {
    fn name(&self) -> &str {
        "Guitar Pro"
    }
    fn extensions(&self) -> &[&str] {
        &["gp5", "gp4"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 23 && &buf[0..21] == GP5_MAGIC {
            if buf[22] != b'.' {
                return None;
            }
            let ext = match buf[21] {
                b'4' => "gp4",
                b'5' => "gp5",
                _ => return None,
            };
            Some(RecoveryInit {
                min_filesize: 23,
                extension: ext.to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Only gp5 has a defined footer; gp4 relies on max_file_size.
        if recovery.extension != "gp5" {
            return DataCheckResult::Continue;
        }
        match footer_end_spanning(buf, recovery, GP5_FOOTER, 0) {
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
    registry.register(0, GP5_MAGIC, Arc::new(Gp5Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gp5_header_match() {
        let sig = Gp5Signature;
        let mut buf = GP5_MAGIC.to_vec();
        buf.push(b'5'); // version at index 21
        buf.push(b'.'); // index 22
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "gp5");

        let mut buf4 = GP5_MAGIC.to_vec();
        buf4.push(b'4');
        buf4.push(b'.');
        let init = sig.header_check(&buf4, 0).unwrap();
        assert_eq!(init.extension, "gp4");
    }

    #[test]
    fn test_gp5_no_match() {
        let sig = Gp5Signature;
        // missing '.' separator
        let mut buf = GP5_MAGIC.to_vec();
        buf.push(b'5');
        buf.push(b'x');
        assert!(sig.header_check(&buf, 0).is_none());
        // unsupported version
        let mut buf3 = GP5_MAGIC.to_vec();
        buf3.push(b'3');
        buf3.push(b'.');
        assert!(sig.header_check(&buf3, 0).is_none());
    }
}
