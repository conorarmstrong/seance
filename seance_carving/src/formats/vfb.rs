use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FontLab (VFB) font source carving signature. Header: 0x1a "WLF10" 0x03 0x00 at offset 0 (8-byte
/// magic).
/// Footer: 0x00 0x05 0x00 0x00 0x00 0x02 0x00 0x00 0x00.
struct VfbSignature;

const VFB_MAGIC: &[u8] = &[0x1a, b'W', b'L', b'F', b'1', b'0', 0x03, 0x00];
const VFB_FOOTER: &[u8] = &[0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];

impl FileSignature for VfbSignature {
    fn name(&self) -> &str {
        "FontLab"
    }
    fn extensions(&self) -> &[&str] {
        &["vfb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= VFB_MAGIC.len() && &buf[0..VFB_MAGIC.len()] == VFB_MAGIC {
            Some(RecoveryInit {
                min_filesize: VFB_MAGIC.len() as u64,
                extension: "vfb".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the VFB footer; stop just after it when found.
        if let Some(pos) = buf.windows(VFB_FOOTER.len()).position(|w| w == VFB_FOOTER) {
            return DataCheckResult::Stop(
                recovery.file_size + pos as u64 + VFB_FOOTER.len() as u64,
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
    registry.register(0, VFB_MAGIC, Arc::new(VfbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfb_header_match() {
        let mut buf = VFB_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(VfbSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_vfb_no_match() {
        let mut buf = VFB_MAGIC.to_vec();
        buf[0] = 0x00;
        assert!(VfbSignature.header_check(&buf, 0).is_none());
        assert!(VfbSignature.header_check(b"\x1aWLF", 0).is_none());
    }

    #[test]
    fn test_vfb_footer_detection() {
        let mut recovery = FileRecovery {
            extension: "vfb".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 8,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0xffu8, 0xff];
        buf.extend_from_slice(VFB_FOOTER);
        buf.push(0x00);
        let result = VfbSignature.data_check(&buf, &mut recovery);
        // footer starts at index 2, footer len 9 -> 100 + 2 + 9 = 111
        assert_eq!(result, DataCheckResult::Stop(111));
    }
}
