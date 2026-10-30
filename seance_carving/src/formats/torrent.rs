use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// BitTorrent metainfo (torrent) carving signature. Header: "d8:announce" at offset 0, followed by
/// an ASCII
/// digit at byte 11. No footer.
struct TorrentSignature;

const TORRENT_MAGIC: &[u8] = b"d8:announce";

impl FileSignature for TorrentSignature {
    fn name(&self) -> &str {
        "Torrent"
    }
    fn extensions(&self) -> &[&str] {
        &["torrent"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..11] == TORRENT_MAGIC && buf[11].is_ascii_digit() {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "torrent".to_string(),
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
    registry.register(0, TORRENT_MAGIC, Arc::new(TorrentSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_torrent_header_match() {
        assert!(TorrentSignature
            .header_check(b"d8:announce7...", 0)
            .is_some());
    }

    #[test]
    fn test_torrent_no_match() {
        // byte 11 is not an ASCII digit
        assert!(TorrentSignature
            .header_check(b"d8:announcexxx", 0)
            .is_none());
        // wrong magic
        assert!(TorrentSignature
            .header_check(b"d8:announbe5xx", 0)
            .is_none());
        // too short
        assert!(TorrentSignature.header_check(b"d8:announce", 0).is_none());
    }
}
