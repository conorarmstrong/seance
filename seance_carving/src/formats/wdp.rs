use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// JPEG XR (Windows Media Photo) carving signature. Header: "II" 0xBC 0x01 at offset 0 (a TIFF-like
/// little-endian header). PhotoRec
/// additionally requires the TIFF directory offset (u32 LE at offset 4) to be at
/// least sizeof(TIFFHeader) = 8.
///
/// Note: PhotoRec runs file_check_tiff_le for final size validation via full TIFF
/// IFD parsing; that stateful check is not implemented. We keep the header magic plus
/// the directory-offset sanity check and cap at the image max size.
struct WdpSignature;

const WDP_MAGIC: &[u8] = &[b'I', b'I', 0xbc, 0x01];

impl FileSignature for WdpSignature {
    fn name(&self) -> &str {
        "WDP"
    }
    fn extensions(&self) -> &[&str] {
        &["wdp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..4] == WDP_MAGIC {
            let diroff = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if diroff >= 8 {
                return Some(RecoveryInit {
                    min_filesize: 0,
                    extension: "wdp".to_string(),
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
        64 * 1024 * 1024
    }
}

/// JPEG XR's container (ITU-T T.832 Annex A) is TIFF-like: its first IFD must
/// be plausible as a TIFF IFD: see `checks::tiff_ifd_plausible`.
fn header_block_plausible(buf: &[u8]) -> bool {
    crate::checks::tiff_ifd_plausible(buf, true)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WDP_MAGIC, Arc::new(WdpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wdp_header_match() {
        // Magic + directory offset of 8 (>= sizeof(TIFFHeader)).
        let buf = [b'I', b'I', 0xbc, 0x01, 0x08, 0x00, 0x00, 0x00];
        assert!(WdpSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_wdp_no_match() {
        // Wrong magic.
        assert!(WdpSignature
            .header_check(b"MM\x00\x2a\x08\x00\x00\x00", 0)
            .is_none());
        // Correct magic but directory offset < 8 -> rejected.
        let buf = [b'I', b'I', 0xbc, 0x01, 0x04, 0x00, 0x00, 0x00];
        assert!(WdpSignature.header_check(&buf, 0).is_none());
    }
}
