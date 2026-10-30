use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple Icon Image (ICNS) carving signature. Header: magic "icns" at offset 0, followed by the
/// total size (BE uint32) at
/// offset 4. The first icon record at offset 8 must carry a recognised 4-byte
/// type and a plausible BE uint32 size. The header size gives the exact file size.
struct IcnsSignature;

const ICNS_MAGIC: &[u8] = b"icns";

fn check_icon_type(t: &[u8]) -> bool {
    const TYPES: [&[u8; 4]; 34] = [
        b"ICON", b"ICN#", b"icm#", b"icm4", b"icm8", b"ics#", b"ics4", b"ics8", b"is32", b"s8mk",
        b"icl4", b"icl8", b"il32", b"l8mk", b"ich#", b"ich4", b"ich8", b"ih32", b"h8mk", b"it32",
        b"t8mk", b"icp4", b"icp5", b"icp6", b"ic07", b"ic08", b"ic09", b"ic10", b"ic11", b"ic12",
        b"ic13", b"ic14", b"TOC ", b"icnV",
    ];
    TYPES.iter().any(|m| t == m.as_slice())
}

impl FileSignature for IcnsSignature {
    fn name(&self) -> &str {
        "ICNS"
    }
    fn extensions(&self) -> &[&str] {
        &["icns"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 16 || &buf[0..4] != ICNS_MAGIC {
            return None;
        }
        let hdr_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let icon_size = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if hdr_size < 8 || icon_size < 8 {
            return None;
        }
        if icon_size > hdr_size - 8 {
            return None;
        }
        if !check_icon_type(&buf[8..12]) {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 16,
            extension: "icns".to_string(),
            calculated_file_size: Some(hdr_size as u64),
        })
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
    registry.register(0, ICNS_MAGIC, Arc::new(IcnsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icns_header_match() {
        let sig = IcnsSignature;
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(b"icns");
        buf[4..8].copy_from_slice(&100u32.to_be_bytes()); // hdr_size
        buf[8..12].copy_from_slice(b"ic09"); // icon type
        buf[12..16].copy_from_slice(&40u32.to_be_bytes()); // icon_size
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(100));
    }

    #[test]
    fn test_icns_no_match() {
        let sig = IcnsSignature;
        // unknown icon type
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(b"icns");
        buf[4..8].copy_from_slice(&100u32.to_be_bytes());
        buf[8..12].copy_from_slice(b"XXXX");
        buf[12..16].copy_from_slice(&40u32.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong magic
        let mut buf2 = [0u8; 16];
        buf2[0..4].copy_from_slice(b"ICNS");
        assert!(sig.header_check(&buf2, 0).is_none());
        // too short
        assert!(sig.header_check(b"icns", 0).is_none());
    }
}
