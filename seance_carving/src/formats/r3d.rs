use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RED r3d camera footage carving signature. Header: "RED1"/"RED2" at offset 4, "R1"/"R2" at offset
/// 0xa; leading 4 bytes
/// are a big-endian atom size (>= 8).
/// NOTE: PhotoRec's data_check_r3d walks the RED atom chain (REO* end atom) to
/// compute the exact size; that stateful parser is not implemented here. This is a
/// faithful header-magic + max-size signature only.
struct R3dSignature;

impl FileSignature for R3dSignature {
    fn name(&self) -> &str {
        "R3D"
    }
    fn extensions(&self) -> &[&str] {
        &["r3d"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 {
            return None;
        }
        // First atom size (big-endian) must be at least 8.
        let atom_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if atom_size < 8 {
            return None;
        }
        // "RED1" + "R1" or "RED2" + "R2".
        if &buf[4..8] == b"RED1" && buf[0xa] == b'R' && buf[0xb] == b'1' {
            return Some(RecoveryInit {
                min_filesize: 12,
                extension: "r3d".to_string(),
                calculated_file_size: None,
            });
        }
        if &buf[4..8] == b"RED2" && buf[0xa] == b'R' && buf[0xb] == b'2' {
            return Some(RecoveryInit {
                min_filesize: 12,
                extension: "r3d".to_string(),
                calculated_file_size: None,
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(4, b"RED1", Arc::new(R3dSignature));
    registry.register(4, b"RED2", Arc::new(R3dSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r3d_header_match() {
        let sig = R3dSignature;
        // size=0x10, "RED1" at 4, "R1" at 0xa
        let buf = b"\x00\x00\x00\x10RED1\x00\x00R1\x00\x00";
        assert!(sig.header_check(buf, 0).is_some());
        let buf2 = b"\x00\x00\x00\x10RED2\x00\x00R2\x00\x00";
        assert!(sig.header_check(buf2, 0).is_some());
    }

    #[test]
    fn test_r3d_no_match() {
        let sig = R3dSignature;
        // atom size too small
        assert!(sig
            .header_check(b"\x00\x00\x00\x04RED1\x00\x00R1\x00\x00", 0)
            .is_none());
        // wrong secondary marker
        assert!(sig
            .header_check(b"\x00\x00\x00\x10RED1\x00\x00XX\x00\x00", 0)
            .is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
