use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Photoshop Large Document (PSB) carving signature. Ported from
/// PhotoRec file_psb.c. Header: `8BPS` + BE version 2 (`38 42 50 53 00 02`) at
/// offset 0, followed by validated dimensions (channels 1..56, height/width
/// 1..300000, depth in {1,8,16,32}). No footer. PhotoRec's layered size walk
/// (color-mode/image-resources/layer-info sections) is not ported (see note);
/// dimensions are validated and the file recovered up to max size.
struct PsbSignature;

const PSB_MAGIC: [u8; 6] = [b'8', b'B', b'P', b'S', 0x00, 0x02];

impl FileSignature for PsbSignature {
    fn name(&self) -> &str {
        "PSB"
    }
    fn extensions(&self) -> &[&str] {
        &["psb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 || buf[0..6] != PSB_MAGIC {
            return None;
        }
        let channels = u16::from_be_bytes([buf[12], buf[13]]);
        let height = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let width = u32::from_be_bytes([buf[18], buf[19], buf[20], buf[21]]);
        let depth = u16::from_be_bytes([buf[22], buf[23]]);
        if channels == 0
            || channels > 56
            || height == 0
            || height > 300000
            || width == 0
            || width > 300000
            || !(depth == 1 || depth == 8 || depth == 16 || depth == 32)
        {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 70,
            extension: "psb".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, &PSB_MAGIC, Arc::new(PsbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..6].copy_from_slice(&PSB_MAGIC);
        buf[12..14].copy_from_slice(&3u16.to_be_bytes()); // channels
        buf[14..18].copy_from_slice(&1024u32.to_be_bytes()); // height
        buf[18..22].copy_from_slice(&768u32.to_be_bytes()); // width
        buf[22..24].copy_from_slice(&8u16.to_be_bytes()); // depth
        buf
    }

    #[test]
    fn test_psb_header_match() {
        let sig = PsbSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_psb_no_match() {
        let sig = PsbSignature;
        // Wrong magic (PSD version 1)
        let mut buf = valid_header();
        buf[5] = 0x01;
        assert!(sig.header_check(&buf, 0).is_none());
        // Invalid depth
        let mut buf2 = valid_header();
        buf2[22..24].copy_from_slice(&7u16.to_be_bytes());
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
