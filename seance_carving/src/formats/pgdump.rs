use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PostgreSQL binary dump (pg_dump) carving signature. Header: "PGDMP" (5 bytes) at offset 0. The
/// intSize field at
/// offset 8 (after magic + version bytes) must be a plausible integer width
/// (1..=32). No footer; extension is "dump".
struct PgdumpSignature;

const PGDUMP_MAGIC: &[u8] = b"PGDMP";

impl FileSignature for PgdumpSignature {
    fn name(&self) -> &str {
        "PGDUMP"
    }

    fn extensions(&self) -> &[&str] {
        &["dump"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need through the intSize byte at offset 8.
        if buf.len() < 9 || &buf[0..5] != PGDUMP_MAGIC {
            return None;
        }
        let int_size = buf[8];
        if int_size == 0 || int_size > 32 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 9,
            extension: "dump".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PGDUMP_MAGIC, Arc::new(PgdumpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pgdump_header_match() {
        let sig = PgdumpSignature;
        // Magic + version bytes + intSize=4.
        let buf = b"PGDMP\x01\x0e\x00\x04";
        assert!(sig.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_pgdump_no_match() {
        let sig = PgdumpSignature;
        // Wrong magic.
        assert!(sig.header_check(b"XGDMP\x01\x0e\x00\x04", 0).is_none());
        // Invalid intSize (0).
        assert!(sig.header_check(b"PGDMP\x01\x0e\x00\x00", 0).is_none());
        // Too short.
        assert!(sig.header_check(b"PGDMP", 0).is_none());
    }
}
