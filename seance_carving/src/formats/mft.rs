use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// NTFS MFT record carving signature. Header: "FILE" at offset 0, followed by NTFS MFT record
/// header fields that
/// are structurally validated (usa/attrs offsets, bytes-in-use/allocated).
/// Size comes from the record's bytes_allocated field; no footer.
///
/// Note: PhotoRec's file_rename_mft (naming the record by its MFT number) is a
/// cosmetic rename not modelled here; carving is unaffected. calculated_file_size
/// uses max(512, bytes_allocated) to mirror td_max(blocksize, bytes_allocated).
struct MftSignature;

impl FileSignature for MftSignature {
    fn name(&self) -> &str {
        "NTFS MFT record"
    }
    fn extensions(&self) -> &[&str] {
        &["mft"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need through bytes_allocated at offset 28..32.
        if buf.len() < 32 || &buf[0..4] != b"FILE" {
            return None;
        }
        // Little-endian NTFS MFT record header fields.
        let usa_ofs = u16::from_le_bytes([buf[4], buf[5]]) as u32;
        let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as u32;
        let attrs_offset = u16::from_le_bytes([buf[20], buf[21]]) as u32;
        let bytes_in_use = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let bytes_allocated = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        if !(usa_ofs + usa_count <= attrs_offset
            && 42 <= attrs_offset
            && attrs_offset.is_multiple_of(8)
            && attrs_offset < bytes_in_use
            && bytes_in_use <= bytes_allocated)
        {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 42,
            extension: "mft".to_string(),
            calculated_file_size: Some((bytes_allocated as u64).max(512)),
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
    registry.register(0, b"FILE", Arc::new(MftSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid MFT record header.
    fn valid_mft() -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"FILE");
        // usa_ofs = 48, usa_count = 3 -> 51 <= attrs_offset
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        // attrs_offset = 56 (>=42, %8==0, > 51)
        buf[20..22].copy_from_slice(&56u16.to_le_bytes());
        // bytes_in_use = 512, bytes_allocated = 1024
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_mft_header_match() {
        let sig = MftSignature;
        let buf = valid_mft();
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "mft");
        assert_eq!(init.calculated_file_size, Some(1024));
    }

    #[test]
    fn test_mft_no_match() {
        let sig = MftSignature;
        // Wrong magic.
        let mut bad = valid_mft();
        bad[0..4].copy_from_slice(b"BAAD");
        assert!(sig.header_check(&bad, 0).is_none());
        // attrs_offset not 8-aligned.
        let mut bad2 = valid_mft();
        bad2[20..22].copy_from_slice(&57u16.to_le_bytes());
        assert!(sig.header_check(&bad2, 0).is_none());
        // Too short.
        assert!(sig.header_check(b"FILE", 0).is_none());
    }
}
