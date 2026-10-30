use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// X4A (Yamaha-YSFC) carving signature. Header: "YSFC" + {FF FF FF FF} at offset 0x30, with "Ver
/// 01.0" at 0x10.
/// The catalog kind at offset 6 selects the extension (ALL->x4a, SONG->x4s,
/// PATTERN->x4p, ARPEGGIO->x4g). min_filesize 0x200, no footer.
/// Note: PhotoRec's file_check_x4a recomputes the exact size from the catalog table
/// at the file head; the engine only runs file_check on a data_check Stop (tail
/// window), so that head scan is not implemented. Carves to the next header instead.
struct X4aSignature;

impl FileSignature for X4aSignature {
    fn name(&self) -> &str {
        "YSFC"
    }

    fn extensions(&self) -> &[&str] {
        &["x4a", "x4s", "x4p", "x4g"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic "YSFC" + FF FF FF FF is at offset 0x30; header check needs >= 0x38 bytes.
        if buf.len() < 0x38 {
            return None;
        }
        if &buf[0x30..0x34] != b"YSFC" {
            return None;
        }
        // "Ver 01.00" compared for 8 bytes -> "Ver 01.0".
        if &buf[0x10..0x18] != b"Ver 01.0" {
            return None;
        }
        let kind = &buf[6..14];
        let extension = if &kind[0..3] == b"ALL" {
            "x4a"
        } else if &kind[0..4] == b"SONG" {
            "x4s"
        } else if &kind[0..7] == b"PATTERN" {
            "x4p"
        } else if kind == b"ARPEGGIO" {
            "x4g"
        } else {
            "x4a"
        };
        Some(RecoveryInit {
            min_filesize: 0x200,
            extension: extension.to_string(),
            calculated_file_size: None,
        })
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
        0x30,
        &[b'Y', b'S', b'F', b'C', 0xff, 0xff, 0xff, 0xff],
        Arc::new(X4aSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_buf() -> [u8; 0x40] {
        let mut buf = [0u8; 0x40];
        buf[0x10..0x18].copy_from_slice(b"Ver 01.0");
        buf[0x30..0x34].copy_from_slice(b"YSFC");
        buf[0x34..0x38].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        buf
    }

    #[test]
    fn test_x4a_header_match() {
        let mut buf = base_buf();
        buf[6..9].copy_from_slice(b"ALL");
        let sig = X4aSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "x4a");
        assert_eq!(init.min_filesize, 0x200);
    }

    #[test]
    fn test_x4a_no_match() {
        let sig = X4aSignature;
        let mut buf = base_buf();
        // Corrupt the magic.
        buf[0x30..0x34].copy_from_slice(b"XSFC");
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
