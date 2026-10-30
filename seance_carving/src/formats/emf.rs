use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// EMF (Windows Enhanced MetaFile) carving signature. Header: literal " EMF" (0x20 'E' 'M' 'F') at
/// offset 0x28, with the record header
/// leading bytes {0x01,0x00,0x00,0x00}. PhotoRec walks EMF records (EMR_EOF footer)
/// via a stateful data_check across a double buffer; that record walk crosses block
/// boundaries and is not portable to the single-block data_check, so it is degraded to
/// a validated header-magic + max-size carve.
struct EmfSignature;

impl EmfSignature {
    const MAGIC: &'static [u8] = b" EMF";
}

impl FileSignature for EmfSignature {
    fn name(&self) -> &str {
        "EMF"
    }

    fn extensions(&self) -> &[&str] {
        &["emf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(struct EMF_HDR) == 88
        if buf.len() < 88 {
            return None;
        }
        // Record header for the EMF_HEADER record: iType == 1 (little-endian).
        if buf[0..4] != [0x01, 0x00, 0x00, 0x00] {
            return None;
        }
        // dSignature == " EMF" at offset 0x28.
        if &buf[0x28..0x2c] != Self::MAGIC {
            return None;
        }
        let atom_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let n_bytes = u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]);
        let s_reserved = u16::from_le_bytes([buf[58], buf[59]]);
        if atom_size >= 0x34 && atom_size.is_multiple_of(4) && n_bytes >= 88 && s_reserved == 0 {
            Some(RecoveryInit {
                min_filesize: 88,
                extension: "emf".to_string(),
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
    registry.register(0x28, EmfSignature::MAGIC, Arc::new(EmfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; 88];
        // iType == 1
        buf[0] = 0x01;
        // nSize (atom_size) == 0x34
        buf[4] = 0x34;
        // " EMF" signature at 0x28
        buf[0x28..0x2c].copy_from_slice(b" EMF");
        // nBytes == 88
        buf[48] = 88;
        // sReserved == 0 already
        buf
    }

    #[test]
    fn test_emf_header_match() {
        let sig = EmfSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_emf_no_match() {
        let sig = EmfSignature;
        // Missing signature bytes.
        let mut buf = valid_header();
        buf[0x28] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(b"\x01\x00\x00\x00", 0).is_none());
    }
}
