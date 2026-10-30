use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WIN (Opera preferences) carving signature. Ported from file_win.c.
/// Header: UTF-8 BOM (EF BB BF) followed by "Opera Preferences version 2." (31
/// bytes total) at offset 0. PhotoRec's data_check_win walks UTF-encoded runs to
/// find the end; that stateful scan is degraded here to a header-magic + max-size
/// match (see note), so recovery stops at the next header or the size cap.
struct WinSignature;

const WIN_MAGIC: &[u8] = &[
    0xef, 0xbb, 0xbf, b'O', b'p', b'e', b'r', b'a', b' ', b'P', b'r', b'e', b'f', b'e', b'r', b'e',
    b'n', b'c', b'e', b's', b' ', b'v', b'e', b'r', b's', b'i', b'o', b'n', b' ', b'2', b'.',
];

impl FileSignature for WinSignature {
    fn name(&self) -> &str {
        "WIN"
    }
    fn extensions(&self) -> &[&str] {
        &["win"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= WIN_MAGIC.len() && &buf[..WIN_MAGIC.len()] == WIN_MAGIC {
            Some(RecoveryInit {
                min_filesize: WIN_MAGIC.len() as u64,
                extension: "win".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WIN_MAGIC, Arc::new(WinSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win_header_match() {
        let sig = WinSignature;
        assert!(sig.header_check(WIN_MAGIC, 0).is_some());
    }

    #[test]
    fn test_win_no_match() {
        let sig = WinSignature;
        assert!(sig
            .header_check(b"Opera Preferences version 2.", 0)
            .is_none());
        assert!(sig.header_check(b"\xef\xbb\xbf", 0).is_none());
    }
}
