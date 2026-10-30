use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Sun/NeXT audio (.au/.snd) carving signature. Header: ".snd" at offset 0, big-endian fields
/// validated. When the size field
/// is not 0xffffffff the exact file size is data-offset + data-size. No footer.
struct AuSignature;

const AU_MAGIC: &[u8] = b".snd";

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl FileSignature for AuSignature {
    fn name(&self) -> &str {
        "AU"
    }

    fn extensions(&self) -> &[&str] {
        &["au"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct header_au_s is 24 bytes.
        if buf.len() < 24 || &buf[0..4] != AU_MAGIC {
            return None;
        }
        let data_offset = be32(buf, 4);
        let size = be32(buf, 8);
        let encoding = be32(buf, 12);
        let channels = be32(buf, 20);
        if data_offset < 24 || !(1..=27).contains(&encoding) || !(1..=256).contains(&channels) {
            return None;
        }
        let calculated_file_size = if size != 0xffff_ffff {
            let cfs = data_offset as u64 + size as u64;
            if cfs < 111 {
                return None;
            }
            Some(cfs)
        } else {
            None
        };
        Some(RecoveryInit {
            min_filesize: 111,
            extension: "au".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, AU_MAGIC, Arc::new(AuSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_au_header_match() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(AU_MAGIC);
        buf[4..8].copy_from_slice(&24u32.to_be_bytes()); // data offset
        buf[8..12].copy_from_slice(&200u32.to_be_bytes()); // size -> cfs=224
        buf[12..16].copy_from_slice(&1u32.to_be_bytes()); // encoding
        buf[20..24].copy_from_slice(&2u32.to_be_bytes()); // channels
        let init = AuSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(224));
    }

    #[test]
    fn test_au_no_match() {
        // Wrong magic.
        assert!(AuSignature.header_check(&[0u8; 24], 0).is_none());
        // Correct magic but encoding out of range.
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(AU_MAGIC);
        buf[4..8].copy_from_slice(&24u32.to_be_bytes());
        buf[12..16].copy_from_slice(&99u32.to_be_bytes()); // encoding invalid
        buf[20..24].copy_from_slice(&2u32.to_be_bytes());
        assert!(AuSignature.header_check(&buf, 0).is_none());
    }
}
