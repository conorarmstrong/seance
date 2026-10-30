use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Macintosh Picture (PICT v2) carving signature. Header: version bytes 00 11 02 ff 0c 00 (6 bytes)
/// at offset 0x20a, i.e. the
/// VersionOperator/VersionNumber/HeaderOpcode fields of the picture header at
/// 0x200. PhotoRec additionally validates the frame geometry and rounds the size
/// in file_check_pct; those are degraded here to a magic + min_filesize match.
struct PctSignature;

const PCT_MAGIC: &[u8] = &[0x00, 0x11, 0x02, 0xff, 0x0c, 0x00];
const PCT_MAGIC_OFFSET: usize = 0x20a;
/// 0x200 + sizeof(struct pct_file_entry) (40 bytes).
const PCT_MIN_FILESIZE: u64 = 0x200 + 40;

impl FileSignature for PctSignature {
    fn name(&self) -> &str {
        "PICT"
    }

    fn extensions(&self) -> &[&str] {
        &["pct"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = PCT_MAGIC_OFFSET + PCT_MAGIC.len();
        if buf.len() >= end && &buf[PCT_MAGIC_OFFSET..end] == PCT_MAGIC {
            Some(RecoveryInit {
                min_filesize: PCT_MIN_FILESIZE,
                extension: "pct".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    /// The magic lies past the engine's 512-byte block: ask to be shown that far.
    fn header_window(&self) -> usize {
        PCT_MAGIC_OFFSET + PCT_MAGIC.len()
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
    registry.register(PCT_MAGIC_OFFSET as u16, PCT_MAGIC, Arc::new(PctSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pct_header_match() {
        let sig = PctSignature;
        let mut buf = vec![0u8; PCT_MAGIC_OFFSET + PCT_MAGIC.len()];
        buf[PCT_MAGIC_OFFSET..].copy_from_slice(PCT_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_pct_no_match() {
        let sig = PctSignature;
        // Wrong bytes at the magic offset.
        let mut buf = vec![0u8; PCT_MAGIC_OFFSET + PCT_MAGIC.len()];
        buf[PCT_MAGIC_OFFSET] = 0xff;
        assert!(sig.header_check(&buf, 0).is_none());
        // Buffer too short to reach the magic offset.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
