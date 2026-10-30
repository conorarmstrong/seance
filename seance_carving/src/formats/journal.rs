use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// systemd journal carving signature. Header: signature "LPKSHHRH" (8 bytes) at offset 0.
/// header_size (u64 LE at
/// offset 88) must be in [272, MAX] and the upper bytes of compatible_flags
/// (buffer[9..12]) must be zero. Size from header: header_size + arena_size
/// (arena_size u64 LE at offset 96). No footer.
struct JournalSignature;

/// PHOTOREC_MAX_FILE_SIZE for the 64-bit build: (1<<41)-1.
const PHOTOREC_MAX: u64 = (1u64 << 41) - 1;

impl FileSignature for JournalSignature {
    fn name(&self) -> &str {
        "Journal"
    }

    fn extensions(&self) -> &[&str] {
        &["journal"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 104 || &buf[0..8] != b"LPKSHHRH" {
            return None;
        }
        let header_size = u64::from_le_bytes(buf[88..96].try_into().unwrap());
        let arena_size = u64::from_le_bytes(buf[96..104].try_into().unwrap());
        if !(272..=PHOTOREC_MAX).contains(&header_size) {
            return None;
        }
        if arena_size > PHOTOREC_MAX {
            return None;
        }
        if buf[9] != 0 || buf[10] != 0 || buf[11] != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: header_size,
            extension: "journal".to_string(),
            calculated_file_size: Some(header_size + arena_size),
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
    registry.register(0, b"LPKSHHRH", Arc::new(JournalSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_header_match() {
        let sig = JournalSignature;
        let mut buf = vec![0u8; 128];
        buf[0..8].copy_from_slice(b"LPKSHHRH");
        buf[88..96].copy_from_slice(&272u64.to_le_bytes()); // header_size
        buf[96..104].copy_from_slice(&4096u64.to_le_bytes()); // arena_size
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(272 + 4096));
    }

    #[test]
    fn test_journal_no_match() {
        let sig = JournalSignature;
        let mut buf = vec![0u8; 128];
        buf[0..8].copy_from_slice(b"LPKSHHRH");
        buf[88..96].copy_from_slice(&100u64.to_le_bytes()); // header_size < 272
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOTJOURN", 0).is_none());
    }
}
