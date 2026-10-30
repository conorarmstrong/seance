use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Impulse Tracker module (IT) carving signature. Header: magic "IMPM" at offset 0, with the 32-bit
/// Reserved field
/// at offset 58 equal to zero. No calculated size and no footer, so recovery
/// runs until the next header or the size cap (matches PhotoRec's default).
struct ItSignature;

impl FileSignature for ItSignature {
    fn name(&self) -> &str {
        "IT"
    }

    fn extensions(&self) -> &[&str] {
        &["it"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 62 && &buf[0..4] == b"IMPM" {
            let reserved = u32::from_le_bytes([buf[58], buf[59], buf[60], buf[61]]);
            if reserved != 0 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "it".to_string(),
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
        256 * 1024 * 1024
    }
}

/// Impulse Tracker's header (ITTECH.TXT) holds the global volume (0x30), mix
/// volume (0x31) and panning separation (0x34), each 0–128, an initial speed
/// (0x32) of at least 1 and an initial tempo (0x33) of at least 31.
fn header_block_plausible(buf: &[u8]) -> bool {
    buf.len() < 0x35
        || (buf[0x30] <= 128
            && buf[0x31] <= 128
            && buf[0x32] >= 1
            && buf[0x33] >= 31
            && buf[0x34] <= 128)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"IMPM", Arc::new(ItSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_it_header_match() {
        let sig = ItSignature;
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"IMPM");
        // Reserved (offset 58) stays zero.
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_it_no_match() {
        let sig = ItSignature;
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"IMPM");
        buf[58] = 1; // Reserved != 0
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
