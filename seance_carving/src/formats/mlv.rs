use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MLV (Magic Lantern Video) carving signature. Header: "MLVI" at offset 0, followed by a u32
/// blockSize (>= 0x34) and fileNum/fileCount
/// consistency checks. PhotoRec sizes the file by walking MLV block headers (blockType +
/// blockSize) across a double buffer; that block walk crosses block boundaries and is
/// degraded here to a validated header-magic + max-size carve.
struct MlvSignature;

impl FileSignature for MlvSignature {
    fn name(&self) -> &str {
        "MLV"
    }

    fn extensions(&self) -> &[&str] {
        &["mlv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 28 || &buf[0..4] != b"MLVI" {
            return None;
        }
        let block_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if block_size < 0x34 {
            return None;
        }
        let file_num = u16::from_le_bytes([buf[24], buf[25]]);
        let file_count = u16::from_le_bytes([buf[26], buf[27]]);
        let accepted = if file_count == 0 && file_num > 0 {
            true
        } else if file_num > file_count {
            false
        } else {
            !(file_num >= file_count && file_count > 0)
        };
        if accepted {
            Some(RecoveryInit {
                min_filesize: 0x34,
                extension: "mlv".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

/// The `MLVI` file header carries its format version as a NUL-padded string
/// at offset 8 (`v2.0` in every Magic Lantern build that writes MLV), and the
/// block after it, when it lies in this block, opens with a four-character
/// block type in upper-case letters and digits (`RAWI`, `IDNT`, `EXPO`, ...).
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return true;
    }
    if !(buf[8] == b'v' && buf[9].is_ascii_digit() && buf[10] == b'.' && buf[11].is_ascii_digit()) {
        return false;
    }
    let next = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    match buf.get(next..next.saturating_add(4)) {
        Some(t) => t
            .iter()
            .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        None => true,
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"MLVI", Arc::new(MlvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(block_size: u32, file_num: u16, file_count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        buf[0..4].copy_from_slice(b"MLVI");
        buf[4..8].copy_from_slice(&block_size.to_le_bytes());
        buf[24..26].copy_from_slice(&file_num.to_le_bytes());
        buf[26..28].copy_from_slice(&file_count.to_le_bytes());
        buf
    }

    #[test]
    fn test_mlv_header_match() {
        let sig = MlvSignature;
        // fileNum 0 of fileCount 1 is valid.
        assert!(sig.header_check(&header(0x40, 0, 1), 0).is_some());
    }

    #[test]
    fn test_mlv_no_match() {
        let sig = MlvSignature;
        // blockSize below 0x34.
        assert!(sig.header_check(&header(0x10, 0, 1), 0).is_none());
        // fileNum > fileCount.
        assert!(sig.header_check(&header(0x40, 5, 2), 0).is_none());
        // Wrong magic.
        assert!(sig
            .header_check(b"NOPEnothingnothingnothing!!!", 0)
            .is_none());
    }
}
