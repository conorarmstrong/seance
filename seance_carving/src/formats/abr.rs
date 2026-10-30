use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Brush (ABR) carving signature. Header: magic
/// {0x00,0x02,'8','B','I','M','s','a','m','p',0x00} at offset 2.
/// The first 8BIM record's big-endian size lives at offset 12; min_filesize is
/// 16 + that size (4-byte prefix + 12-byte record header). No footer.
struct AbrSignature;

const ABR_MAGIC: &[u8] = &[
    0x00, 0x02, b'8', b'B', b'I', b'M', b's', b'a', b'm', b'p', 0x00,
];

impl FileSignature for AbrSignature {
    fn name(&self) -> &str {
        "ABR"
    }

    fn extensions(&self) -> &[&str] {
        &["abr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic sits at offset 2 (2-byte version prefix precedes "8BIM").
        if buf.len() >= 2 + ABR_MAGIC.len() && &buf[2..2 + ABR_MAGIC.len()] == ABR_MAGIC {
            // First 8BIM record header is at offset 4; its size field is at
            // offset 12 (magic[4] + info[4]).
            let min_filesize = if buf.len() >= 16 {
                let size = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
                4 + 12 + size
            } else {
                16
            };
            Some(RecoveryInit {
                min_filesize,
                extension: "abr".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(2, ABR_MAGIC, Arc::new(AbrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abr_header_match() {
        let sig = AbrSignature;
        let mut buf = vec![0u8; 16];
        buf[2..2 + ABR_MAGIC.len()].copy_from_slice(ABR_MAGIC);
        // size field at offset 12: big-endian 0x00000100 = 256.
        buf[12] = 0x00;
        buf[13] = 0x00;
        buf[14] = 0x01;
        buf[15] = 0x00;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.min_filesize, 16 + 256);
    }

    #[test]
    fn test_abr_no_match() {
        let sig = AbrSignature;
        // Magic bytes not at offset 2.
        let buf = vec![0u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short to contain the magic.
        assert!(sig.header_check(&[0x00, 0x02, b'8'], 0).is_none());
    }
}
