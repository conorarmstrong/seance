use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VMG (Nokia Text Message) carving signature. Ported from file_vmg.c.
/// Header: UTF-16LE "BEGIN:VMSG\nVERSION:1" (40 bytes) at offset 0.
/// Footer: UTF-16LE "\nEND:VMSG\n" (21 bytes) located via file_search_footer.
struct VmgSignature;

const VMG_MAGIC: &[u8] = &[
    b'B', 0, b'E', 0, b'G', 0, b'I', 0, b'N', 0, b':', 0, b'V', 0, b'M', 0, b'S', 0, b'G', 0,
    b'\n', 0, b'V', 0, b'E', 0, b'R', 0, b'S', 0, b'I', 0, b'O', 0, b'N', 0, b':', 0, b'1', 0,
];

const VMG_FOOTER: &[u8] = &[
    0x00, b'\n', 0x00, b'E', 0x00, b'N', 0x00, b'D', 0x00, b':', 0x00, b'V', 0x00, b'M', 0x00,
    b'S', 0x00, b'G', 0x00, b'\n', 0x00,
];

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

impl FileSignature for VmgSignature {
    fn name(&self) -> &str {
        "VMG"
    }
    fn extensions(&self) -> &[&str] {
        &["vmg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= VMG_MAGIC.len() && &buf[..VMG_MAGIC.len()] == VMG_MAGIC {
            Some(RecoveryInit {
                min_filesize: VMG_MAGIC.len() as u64,
                extension: "vmg".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        if let Some(pos) = find_sub(buf, VMG_FOOTER) {
            return DataCheckResult::Stop(
                recovery.file_size + pos as u64 + VMG_FOOTER.len() as u64,
            );
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, VMG_MAGIC, Arc::new(VmgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmg_header_match() {
        let sig = VmgSignature;
        assert!(sig.header_check(VMG_MAGIC, 0).is_some());
    }

    #[test]
    fn test_vmg_no_match() {
        let sig = VmgSignature;
        assert!(sig.header_check(b"BEGIN:VMSG plain", 0).is_none());
        assert!(sig.header_check(b"xx", 0).is_none());
    }

    #[test]
    fn test_vmg_footer_stop() {
        let sig = VmgSignature;
        let mut recovery = FileRecovery {
            extension: "vmg".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 40,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0xAAu8; 3];
        buf.extend_from_slice(VMG_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(100 + 3 + VMG_FOOTER.len() as u64)
        );
    }
}
