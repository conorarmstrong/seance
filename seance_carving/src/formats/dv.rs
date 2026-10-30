use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DIF Digital Video (.dv) carving signature. Header: registered magic {0x1f,0x07,0x00} at offset
/// 0; the full header check
/// also requires bytes 5..8 to be 0x78 0x78 0x78. Bit 0x80 of byte 3 selects
/// PAL vs NTSC frame sizing.
///
/// NOTE: PhotoRec walks fixed 120000-byte (NTSC) / 144000-byte (PAL) frames in
/// data_check and re-validates each frame's DIF id in file_check. That stateful
/// frame walk is not portable to a forward data_check, so it is degraded;
/// recovery is bounded by max_file_size.
struct DvSignature;

const DV_MAGIC: &[u8] = &[0x1f, 0x07, 0x00];

impl FileSignature for DvSignature {
    fn name(&self) -> &str {
        "DV"
    }

    fn extensions(&self) -> &[&str] {
        &["dv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0] != 0x1f
            || buf[1] != 0x07
            || buf[2] != 0x00
            || buf[5] != 0x78
            || buf[6] != 0x78
            || buf[7] != 0x78
        {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 120000, // one NTSC frame
            extension: "dv".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000 // video
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, DV_MAGIC, Arc::new(DvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dv_header_match() {
        let sig = DvSignature;
        let buf = [0x1f, 0x07, 0x00, 0x00, 0x00, 0x78, 0x78, 0x78];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dv_no_match() {
        let sig = DvSignature;
        // Correct 3-byte magic but bytes 5..8 not 0x78.
        let buf = [0x1f, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig
            .header_check(&[0x00, 0x07, 0x00, 0, 0, 0x78, 0x78, 0x78], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0x1f, 0x07, 0x00], 0).is_none());
    }
}
