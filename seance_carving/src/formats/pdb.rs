use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Protein Data Bank (PDB) carving signature. Header: "HEADER " (HEADER + 4 spaces, 10 bytes) at
/// offset 0. The first
/// record's fixed-position date/space fields are validated. PhotoRec then walks
/// fixed 81- or 82-byte lines in a stateful data_check; degraded here to the
/// header validation plus the corresponding min_filesize. No footer.
struct PdbSignature;

const PDB_MAGIC: &[u8] = b"HEADER    ";

impl FileSignature for PdbSignature {
    fn name(&self) -> &str {
        "PDB"
    }

    fn extensions(&self) -> &[&str] {
        &["pdb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need through buffer[81] for the line-ending discrimination.
        if buf.len() < 82 || &buf[0..10] != PDB_MAGIC {
            return None;
        }
        // Date: DD-MMM-YY at fixed offsets.
        if !buf[0x32].is_ascii_digit() || !buf[0x33].is_ascii_digit() {
            return None;
        }
        if buf[0x34] != b'-' {
            return None;
        }
        if !buf[0x35].is_ascii_uppercase()
            || !buf[0x36].is_ascii_uppercase()
            || !buf[0x37].is_ascii_uppercase()
        {
            return None;
        }
        if buf[0x38] != b'-' {
            return None;
        }
        if !buf[0x39].is_ascii_digit() || !buf[0x3a].is_ascii_digit() {
            return None;
        }
        // Fixed spaces in the HEADER record.
        if buf[59] != b' '
            || buf[60] != b' '
            || buf[61] != b' '
            || buf[66] != b' '
            || buf[67] != b' '
            || buf[68] != b' '
            || buf[69] != b' '
        {
            return None;
        }
        // Line ending determines the record stride (82 for CRLF, 81 for LF).
        let min_filesize = if buf[80] == b'\r' && buf[81] == b'\n' {
            82
        } else if buf[80] == b'\n' {
            81
        } else {
            return None;
        };
        Some(RecoveryInit {
            min_filesize,
            extension: "pdb".to_string(),
            calculated_file_size: None,
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
    registry.register(0, PDB_MAGIC, Arc::new(PdbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PDB HEADER record (LF-terminated first line).
    fn valid_pdb() -> Vec<u8> {
        let mut buf = vec![b' '; 82];
        buf[0..10].copy_from_slice(PDB_MAGIC);
        // Date DD-MMM-YY at 0x32.
        buf[0x32] = b'2';
        buf[0x33] = b'4';
        buf[0x34] = b'-';
        buf[0x35] = b'J';
        buf[0x36] = b'U';
        buf[0x37] = b'L';
        buf[0x38] = b'-';
        buf[0x39] = b'2';
        buf[0x3a] = b'6';
        // Fixed spaces already set by the fill.
        buf[80] = b'\n';
        buf
    }

    #[test]
    fn test_pdb_header_match() {
        let sig = PdbSignature;
        let init = sig.header_check(&valid_pdb(), 0).unwrap();
        assert_eq!(init.min_filesize, 81);
    }

    #[test]
    fn test_pdb_no_match() {
        let sig = PdbSignature;
        // Wrong magic.
        let mut bad = valid_pdb();
        bad[0] = b'X';
        assert!(sig.header_check(&bad, 0).is_none());
        // Too short.
        assert!(sig.header_check(PDB_MAGIC, 0).is_none());
    }
}
