use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Access Database carving signature. Header at offset 0: 00 01 00 00 "Standard Jet DB"
/// 00 (.mdb) or
/// 00 01 00 00 "Standard ACE DB" 00 (.accdb). No size in header, no footer.
struct MdbSignature;

const MDB_MAGIC: &[u8] = b"\x00\x01\x00\x00Standard Jet DB\x00";
const ACCDB_MAGIC: &[u8] = b"\x00\x01\x00\x00Standard ACE DB\x00";

impl FileSignature for MdbSignature {
    fn name(&self) -> &str {
        "Access Data Base"
    }
    fn extensions(&self) -> &[&str] {
        &["mdb", "accdb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= MDB_MAGIC.len() && &buf[0..MDB_MAGIC.len()] == MDB_MAGIC {
            return Some(RecoveryInit {
                min_filesize: 0,
                extension: "mdb".to_string(),
                calculated_file_size: None,
            });
        }
        if buf.len() >= ACCDB_MAGIC.len() && &buf[0..ACCDB_MAGIC.len()] == ACCDB_MAGIC {
            return Some(RecoveryInit {
                min_filesize: 0,
                extension: "accdb".to_string(),
                calculated_file_size: None,
            });
        }
        None
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
    registry.register(0, MDB_MAGIC, Arc::new(MdbSignature));
    registry.register(0, ACCDB_MAGIC, Arc::new(MdbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdb_header_match() {
        let sig = MdbSignature;
        let init = sig.header_check(MDB_MAGIC, 0).expect("mdb should match");
        assert_eq!(init.extension, "mdb");
        let init2 = sig
            .header_check(ACCDB_MAGIC, 0)
            .expect("accdb should match");
        assert_eq!(init2.extension, "accdb");
    }

    #[test]
    fn test_mdb_no_match() {
        let sig = MdbSignature;
        assert!(sig
            .header_check(b"\x00\x01\x00\x00Standard XXX DB\x00", 0)
            .is_none());
        assert!(sig.header_check(b"NOTACCESSDB", 0).is_none());
    }
}
