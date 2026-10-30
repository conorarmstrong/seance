use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WEE (weecast) carving signature. Ported from file_wee.c.
/// Header: "WEEX" 21 01 00 (7 bytes) at offset 0, with 0x0A at 0x1A followed by
/// "onMetaData" at 0x1B. Footer: same 7-byte "WEEX!.." tag, with 17 trailing bytes.
struct WeeSignature;

const WEE_MAGIC: &[u8] = &[b'W', b'E', b'E', b'X', 0x21, 0x01, 0x00];
/// file_search_footer extra_length argument.
const WEE_FOOTER_EXTRA: u64 = 17;

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

impl FileSignature for WeeSignature {
    fn name(&self) -> &str {
        "WEE"
    }
    fn extensions(&self) -> &[&str] {
        &["wee"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need bytes through "onMetaData" at 0x1B..0x25.
        if buf.len() < 0x25 {
            return None;
        }
        if &buf[0..WEE_MAGIC.len()] != WEE_MAGIC {
            return None;
        }
        if buf[0x1a] != 0x0a || &buf[0x1b..0x25] != b"onMetaData" {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x25,
            extension: "wee".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        if let Some(pos) = find_sub(buf, WEE_MAGIC) {
            return DataCheckResult::Stop(
                recovery.file_size + pos as u64 + WEE_MAGIC.len() as u64 + WEE_FOOTER_EXTRA,
            );
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WEE_MAGIC, Arc::new(WeeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x25];
        buf[0..WEE_MAGIC.len()].copy_from_slice(WEE_MAGIC);
        buf[0x1a] = 0x0a;
        buf[0x1b..0x25].copy_from_slice(b"onMetaData");
        buf
    }

    #[test]
    fn test_wee_header_match() {
        let sig = WeeSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_wee_no_match() {
        let sig = WeeSignature;
        let mut buf = valid_header();
        buf[0x1a] = 0x00; // break the 0x0A marker
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"WEEX", 0).is_none());
    }
}
