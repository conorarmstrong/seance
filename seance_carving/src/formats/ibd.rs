use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// InnoDB database file (IBD) carving signature. Header: magic "infimum" at offset 0xc063 (past the
/// engine's 512-byte block, so the signature asks for a header window, `header_window`). The FIL
/// header page type (BE uint16
/// at offset 24) and the FSP space flags (BE uint32 at offset 54) select the
/// InnoDB file format (Antelope / Barracuda). If enough data is present the
/// "supremum" marker at offset 0xc070 is also verified. No footer; size bounded
/// by max_file_size.
struct IbdSignature;

const FIL_PAGE_TYPE_FSP_HDR: u16 = 8;
const DICT_TF_FORMAT_MASK: u32 = 0x20;
const DICT_TF_FORMAT_SHIFT: u32 = 5;
const DICT_TF_FORMAT_ZIP: u32 = 1;

impl FileSignature for IbdSignature {
    fn name(&self) -> &str {
        "InnoDB"
    }
    fn extensions(&self) -> &[&str] {
        &["ibd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need the FIL header (through offset 25) and FSP flags (through 57).
        if buf.len() < 58 {
            return None;
        }
        let page_type = u16::from_be_bytes([buf[24], buf[25]]);
        let flags = u32::from_be_bytes([buf[54], buf[55], buf[56], buf[57]]);
        if page_type == 0 {
            // Antelope (pre-5.1.7) requires non-zero flags
            if flags == 0 {
                return None;
            }
        } else if page_type == FIL_PAGE_TYPE_FSP_HDR {
            let format = (flags & DICT_TF_FORMAT_MASK) >> DICT_TF_FORMAT_SHIFT;
            if flags == 0 {
                // Antelope (5.1.7 or newer)
            } else if format == DICT_TF_FORMAT_ZIP {
                // Barracuda
            } else {
                return None;
            }
        } else {
            return None;
        }
        if buf.len() >= 0xc078 && &buf[0xc070..0xc078] != b"supremum" {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0xc078,
            extension: "ibd".to_string(),
            calculated_file_size: None,
        })
    }

    fn header_window(&self) -> usize {
        0xc078
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
    // "infimum" at file offset 0xc063 (49251, fits u16).
    registry.register(0xc063, b"infimum", Arc::new(IbdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ibd_header_match() {
        let sig = IbdSignature;
        let mut buf = vec![0u8; 0xc078];
        // page_type == 0 (offset 24) with non-zero FSP flags (offset 54)
        buf[54..58].copy_from_slice(&1u32.to_be_bytes());
        buf[0xc063..0xc06a].copy_from_slice(b"infimum");
        buf[0xc070..0xc078].copy_from_slice(b"supremum");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "ibd");
        assert_eq!(init.min_filesize, 0xc078);
    }

    #[test]
    fn test_ibd_no_match() {
        let sig = IbdSignature;
        // page_type == 0 but flags == 0 -> rejected
        let mut buf = vec![0u8; 0xc078];
        buf[0xc070..0xc078].copy_from_slice(b"supremum");
        assert!(sig.header_check(&buf, 0).is_none());
        // unknown page type
        let mut buf2 = vec![0u8; 58];
        buf2[24..26].copy_from_slice(&5u16.to_be_bytes());
        assert!(sig.header_check(&buf2, 0).is_none());
        // too short
        assert!(sig.header_check(&[0u8; 10], 0).is_none());
    }
}
