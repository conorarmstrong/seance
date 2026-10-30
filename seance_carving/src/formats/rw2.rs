use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Panasonic/Leica RAW (RW2) carving signature. Header at offset 0: "IIU" 00 (TIFF-like). Requires
/// little-endian dir offset (bytes 4..8) >= 8.
/// PhotoRec uses file_check_tiff_le to trim the trailing IFD chain; here we degrade to a
/// header + max-size check (data_check Continue) rather than parsing the full TIFF structure.
struct Rw2Signature;

const RW2_MAGIC: &[u8] = &[b'I', b'I', b'U', 0x00];

impl FileSignature for Rw2Signature {
    fn name(&self) -> &str {
        "RW2"
    }
    fn extensions(&self) -> &[&str] {
        &["rw2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // TIFFHeader is 8 bytes: byteOrder(2) version(2) tiff_diroff(4, LE).
        if buf.len() < 8 || &buf[0..RW2_MAGIC.len()] != RW2_MAGIC {
            return None;
        }
        let diroff = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if diroff < 8 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 8,
            extension: "rw2".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a carve
        // already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn header_confirmed_by_source(
        &self,
        source: &dyn crate::engine::CarvingDataSource,
        offset: u64,
    ) -> Option<bool> {
        // The directory usually lies past the header block (CARVE-015).
        crate::checks::tiff_ifd_plausible_at(source, offset, true)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024
    }
}

/// RW2 keeps TIFF's header layout with its own version word, so its first
/// directory must be plausible as a TIFF IFD: see `checks::tiff_ifd_plausible`.
fn header_block_plausible(buf: &[u8]) -> bool {
    crate::checks::tiff_ifd_plausible(buf, true)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, RW2_MAGIC, Arc::new(Rw2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rw2_header_match() {
        let sig = Rw2Signature;
        // "IIU\0" + diroff = 0x18 (LE, >= 8)
        let buf = [b'I', b'I', b'U', 0x00, 0x18, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rw2_no_match() {
        let sig = Rw2Signature;
        // Wrong magic
        assert!(sig.header_check(b"IIX\x00\x18\x00\x00\x00", 0).is_none());
        // diroff < 8
        let buf = [b'I', b'I', b'U', 0x00, 0x04, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
