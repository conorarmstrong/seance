use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XAR (eXtensible ARchive) carving signature. Header: "xar!" (0x78 0x61 0x72 0x21) at offset 0,
/// version 1 (big-endian).
/// min_filesize = header size + compressed TOC length; no footer.
struct XarSignature;

/// Matches PhotoRec's PHOTOREC_MAX_FILE_SIZE sanity bound used inside header_check.
const PHOTOREC_MAX_FILE_SIZE: u64 = (1u64 << 41) - 1;

impl FileSignature for XarSignature {
    fn name(&self) -> &str {
        "XAR"
    }

    fn extensions(&self) -> &[&str] {
        &["xar"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(struct xar_header) == 28
        if buf.len() < 28 || &buf[0..4] != b"xar!" {
            return None;
        }
        let hdr_size = u16::from_be_bytes([buf[4], buf[5]]) as u64;
        let version = u16::from_be_bytes([buf[6], buf[7]]);
        let size = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let cksum_alg = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        if version != 1 {
            return None;
        }
        if hdr_size < 28 {
            return None;
        }
        if cksum_alg == 3 && (hdr_size < 32 || !hdr_size.is_multiple_of(4)) {
            return None;
        }
        if cksum_alg > 4 {
            return None;
        }
        if size >= PHOTOREC_MAX_FILE_SIZE {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: hdr_size + size,
            extension: "xar".to_string(),
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
    registry.register(0, b"xar!", Arc::new(XarSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xar_header_match() {
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(b"xar!");
        buf[4..6].copy_from_slice(&28u16.to_be_bytes()); // header size
        buf[6..8].copy_from_slice(&1u16.to_be_bytes()); // version
        buf[8..16].copy_from_slice(&64u64.to_be_bytes()); // toc_length_compressed
        buf[24..28].copy_from_slice(&0u32.to_be_bytes()); // cksum_alg
        let sig = XarSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.min_filesize, 28 + 64);
    }

    #[test]
    fn test_xar_no_match() {
        let sig = XarSignature;
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(b"xar?");
        assert!(sig.header_check(&buf, 0).is_none());
        // Correct magic but wrong version.
        buf[0..4].copy_from_slice(b"xar!");
        buf[4..6].copy_from_slice(&28u16.to_be_bytes());
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
