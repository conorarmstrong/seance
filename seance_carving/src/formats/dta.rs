use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SPSS/Stata DTA carving signature. Header at offset 0: ds_format byte (0x71 or 0x72), byteorder
/// 0x02 (LOHI),
/// filetype 0x01. No footer; header-only detection.
struct DtaSignature;

impl FileSignature for DtaSignature {
    fn name(&self) -> &str {
        "DTA"
    }
    fn extensions(&self) -> &[&str] {
        &["dta"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 3 && (buf[0] == 0x71 || buf[0] == 0x72) && buf[1] == 0x02 && buf[2] == 0x01
        {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "dta".to_string(),
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
        100 * 1024 * 1024
    }
}

/// Stata's `.dta` formats 113–115 (the `ds_format` bytes 0x71/0x72 this
/// signature matches) open with a fixed header: `ds_format`, `byteorder`,
/// `filetype` (1), one unused byte (0), `nvar` (u16), `nobs` (u32), then an
/// 81-byte NUL-terminated dataset label at offset 10 and an 18-byte
/// NUL-terminated time stamp at offset 91. A dataset has at least one
/// variable, and both strings end in a NUL with no control bytes before it.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 109 {
        return true;
    }
    let text_field = |field: &[u8]| match field.iter().position(|&b| b == 0) {
        Some(end) => field[..end].iter().all(|&b| b >= 0x20 && b != 0x7F),
        None => false,
    };
    // The byte order matched is LOHI, so `nvar` is little-endian.
    let nvar = u16::from_le_bytes([buf[4], buf[5]]);
    buf[3] == 0 && nvar >= 1 && text_field(&buf[10..91]) && text_field(&buf[91..109])
}

pub fn register(registry: &mut SignatureRegistry) {
    // ds_format 0x71
    registry.register(0, &[0x71, 0x02, 0x01], Arc::new(DtaSignature));
    // ds_format 0x72
    registry.register(0, &[0x72, 0x02, 0x01], Arc::new(DtaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dta_header_match() {
        let sig = DtaSignature;
        assert!(sig.header_check(&[0x71, 0x02, 0x01, 0x00], 0).is_some());
        assert!(sig.header_check(&[0x72, 0x02, 0x01, 0x00], 0).is_some());
    }

    #[test]
    fn test_dta_no_match() {
        let sig = DtaSignature;
        assert!(sig.header_check(&[0x71, 0x01, 0x01], 0).is_none());
        assert!(sig.header_check(&[0x70, 0x02, 0x01], 0).is_none());
        assert!(sig.header_check(&[0x71], 0).is_none());
    }
}
