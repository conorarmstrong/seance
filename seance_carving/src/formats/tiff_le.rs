use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TIFF (little-endian) carving signature. Header: "II*\0" (49 49 2a 00) at offset 0, followed by a
/// little-endian 32-bit
/// IFD offset (tiff_diroff) which must be >= sizeof(TIFFHeader) == 8.
/// PhotoRec computes the exact size by walking the IFD chain and refines the
/// extension (cr2/arw/sr2/nef/dng) from EXIF tags; that stateful logic is not
/// implemented here (degraded to a header-magic + max-size signature). Extension
/// kept as PhotoRec's base "tif".
struct TiffLeSignature;

impl FileSignature for TiffLeSignature {
    fn name(&self) -> &str {
        "TIFF_LE"
    }
    fn extensions(&self) -> &[&str] {
        &["tif"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && buf[0] == 0x49 && buf[1] == 0x49 && buf[2] == 0x2a && buf[3] == 0x00 {
            // tiff_diroff is a little-endian u32 at bytes 4..8; must be >= header size (8).
            let diroff = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if diroff >= 8 {
                return Some(RecoveryInit {
                    min_filesize: 8,
                    extension: "tif".to_string(),
                    calculated_file_size: None,
                });
            }
        }
        None
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
        // Raw camera TIFFs (CR2/NEF/DNG/ARW) can be large; PhotoRec treats >1GB
        // tif as suspicious, so cap at 1GB.
        1024 * 1024 * 1024
    }
}

/// The IFD the header points at must be plausible (TIFF 6.0 section 2): see
/// `checks::tiff_ifd_plausible`.
fn header_block_plausible(buf: &[u8]) -> bool {
    crate::checks::tiff_ifd_plausible(buf, true)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x49, 0x49, 0x2a, 0x00], Arc::new(TiffLeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiff_le_header_match() {
        let sig = TiffLeSignature;
        // "II*\0" + little-endian diroff 0x00000008
        let buf = [0x49, 0x49, 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tiff_le_no_match() {
        let sig = TiffLeSignature;
        // big-endian TIFF magic must not match the little-endian signature
        let buf = [0x4d, 0x4d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
        assert!(sig.header_check(&buf, 0).is_none());
        // valid magic but diroff too small (< 8)
        let buf2 = [0x49, 0x49, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf2, 0).is_none());
        // short buffer
        assert!(sig.header_check(b"II\x2a", 0).is_none());
    }
}
