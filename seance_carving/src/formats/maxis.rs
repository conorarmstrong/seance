use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Maxis games (e.g. The Sims) DBPF carving signature. Header: "DBPF" at offset 0, with bytes 5, 6
/// and 7 all zero. No footer.
struct MaxisSignature;

const MAXIS_MAGIC: &[u8] = b"DBPF";

impl FileSignature for MaxisSignature {
    fn name(&self) -> &str {
        "MAXIS"
    }
    fn extensions(&self) -> &[&str] {
        &["maxis"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..4] == MAXIS_MAGIC && buf[5] == 0 && buf[6] == 0 && buf[7] == 0
        {
            Some(RecoveryInit {
                min_filesize: 0x60,
                extension: "maxis".to_string(),
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

/// A DBPF header gives the format's major version (u32 LE at 4: 1 for The
/// Sims 2 and SimCity 4, 2 for The Sims 3, Spore and The Sims 4, 3 for
/// SimCity 2013) and a small minor version (u32 LE at 8).
fn header_block_plausible(buf: &[u8]) -> bool {
    buf.len() < 12
        || ((1..=3).contains(&buf[4])
            && u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) <= 15)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MAXIS_MAGIC, Arc::new(MaxisSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maxis_header_match() {
        let sig = MaxisSignature;
        assert!(sig.header_check(b"DBPF\x01\x00\x00\x00", 0).is_some());
    }

    #[test]
    fn test_maxis_no_match() {
        let sig = MaxisSignature;
        // Correct magic but non-zero byte at offset 6.
        assert!(sig.header_check(b"DBPF\x01\x00\x01\x00", 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(b"DBPX\x00\x00\x00\x00", 0).is_none());
    }
}
