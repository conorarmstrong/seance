use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// McAfee Anti-Theft / FileVault (.vault) carving signature. Ported from file_vault.c.
/// Header: "SafeBootEncVol1" followed by {0x00,0x01,0x01} (18 bytes) at offset 0.
/// PhotoRec's data_check scans for a trailing GUID string (dashes at fixed offsets, a
/// terminating NUL) using half-buffer bookkeeping; that stateful terminator scan is NOT
/// ported here. Degrades to header + max-size.
struct VaultSignature;

const MAGIC: &[u8] = &[
    b'S', b'a', b'f', b'e', b'B', b'o', b'o', b't', b'E', b'n', b'c', b'V', b'o', b'l', b'1', 0x00,
    0x01, 0x01,
];

impl FileSignature for VaultSignature {
    fn name(&self) -> &str {
        "VAULT"
    }

    fn extensions(&self) -> &[&str] {
        &["vault"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= MAGIC.len() && &buf[0..MAGIC.len()] == MAGIC {
            Some(RecoveryInit {
                min_filesize: MAGIC.len() as u64,
                extension: "vault".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MAGIC, Arc::new(VaultSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_header_match() {
        let sig = VaultSignature;
        assert!(sig.header_check(MAGIC, 0).is_some());
    }

    #[test]
    fn test_vault_no_match() {
        let sig = VaultSignature;
        assert!(sig
            .header_check(b"SafeBootEncVol0\x00\x01\x01", 0)
            .is_none());
        assert!(sig.header_check(&[0u8; 18], 0).is_none());
    }
}
