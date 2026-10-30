use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PCAP (little-endian) network capture file signature detector.
/// Magic at offset 0: D4 C3 B2 A1 (little-endian byte order).
/// Version major (u16 LE) at offset 4 must be 2, minor (u16 LE) at offset 6 must be 4.
/// No reliable size calculation; uses max-size recovery.
/// Ref: libpcap file format specification
struct PcapLeSignature;

impl FileSignature for PcapLeSignature {
    fn name(&self) -> &str {
        "PCAP (LE)"
    }

    fn extensions(&self) -> &[&str] {
        &["pcap", "cap"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 {
            return None;
        }
        if buf[0..4] != [0xD4, 0xC3, 0xB2, 0xA1] {
            return None;
        }

        // Version major at offset 4 (u16 LE) must be 2
        let version_major = u16::from_le_bytes([buf[4], buf[5]]);
        // Version minor at offset 6 (u16 LE) must be 4
        let version_minor = u16::from_le_bytes([buf[6], buf[7]]);

        if version_major != 2 || version_minor != 4 {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 24,
            extension: "pcap".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// PCAP (big-endian) network capture file signature detector.
/// Magic at offset 0: A1 B2 C3 D4 (big-endian byte order).
/// Version major (u16 BE) at offset 4 must be 2, minor (u16 BE) at offset 6 must be 4.
/// No reliable size calculation; uses max-size recovery.
/// Ref: libpcap file format specification
struct PcapBeSignature;

impl FileSignature for PcapBeSignature {
    fn name(&self) -> &str {
        "PCAP (BE)"
    }

    fn extensions(&self) -> &[&str] {
        &["pcap", "cap"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 {
            return None;
        }
        if buf[0..4] != [0xA1, 0xB2, 0xC3, 0xD4] {
            return None;
        }

        // Version major at offset 4 (u16 BE) must be 2
        let version_major = u16::from_be_bytes([buf[4], buf[5]]);
        // Version minor at offset 6 (u16 BE) must be 4
        let version_minor = u16::from_be_bytes([buf[6], buf[7]]);

        if version_major != 2 || version_minor != 4 {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 24,
            extension: "pcap".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// PCAPNG network capture file signature detector.
/// Section Header Block magic at offset 0: 0A 0D 0D 0A.
/// Block Total Length (u32) at offset 4.
/// Byte-Order Magic at offset 8: 1A 2B 3C 4D (LE) or 4D 3C 2B 1A (BE).
/// No reliable size calculation; uses max-size recovery.
/// Ref: PCAPNG file format specification (draft-tuexen-opsawg-pcapng)
struct PcapngSignature;

impl FileSignature for PcapngSignature {
    fn name(&self) -> &str {
        "PCAPNG"
    }

    fn extensions(&self) -> &[&str] {
        &["pcapng"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 {
            return None;
        }
        if buf[0..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
            return None;
        }

        // Byte-Order Magic at offset 8 must be one of the two valid values
        let byte_order_magic = &buf[8..12];
        if byte_order_magic != [0x1A, 0x2B, 0x3C, 0x4D]
            && byte_order_magic != [0x4D, 0x3C, 0x2B, 0x1A]
        {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 12,
            extension: "pcapng".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0xD4, 0xC3, 0xB2, 0xA1], Arc::new(PcapLeSignature));
    registry.register(0, &[0xA1, 0xB2, 0xC3, 0xD4], Arc::new(PcapBeSignature));
    registry.register(0, &[0x0A, 0x0D, 0x0D, 0x0A], Arc::new(PcapngSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pcap_le_header(version_major: u16, version_minor: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        buf[4..6].copy_from_slice(&version_major.to_le_bytes());
        buf[6..8].copy_from_slice(&version_minor.to_le_bytes());
        buf
    }

    fn make_pcap_be_header(version_major: u16, version_minor: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&[0xA1, 0xB2, 0xC3, 0xD4]);
        buf[4..6].copy_from_slice(&version_major.to_be_bytes());
        buf[6..8].copy_from_slice(&version_minor.to_be_bytes());
        buf
    }

    fn make_pcapng_header(byte_order_magic: &[u8; 4]) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        buf[0..4].copy_from_slice(&[0x0A, 0x0D, 0x0D, 0x0A]);
        // Block Total Length at offset 4 (set to 28 for a minimal SHB)
        buf[4..8].copy_from_slice(&28u32.to_le_bytes());
        buf[8..12].copy_from_slice(byte_order_magic);
        buf
    }

    #[test]
    fn test_pcap_le_match_valid_version() {
        let sig = PcapLeSignature;
        let buf = make_pcap_le_header(2, 4);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "pcap");
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_pcap_be_match() {
        let sig = PcapBeSignature;
        let buf = make_pcap_be_header(2, 4);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "pcap");
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_pcap_wrong_version_rejected() {
        let sig = PcapLeSignature;
        // Version 3.0 is invalid
        let buf = make_pcap_le_header(3, 0);
        assert!(sig.header_check(&buf, 0).is_none());

        // Version 2.3 is invalid (minor must be 4)
        let buf = make_pcap_le_header(2, 3);
        assert!(sig.header_check(&buf, 0).is_none());

        // Also test BE variant with wrong version
        let sig_be = PcapBeSignature;
        let buf = make_pcap_be_header(1, 4);
        assert!(sig_be.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_pcapng_match_valid_byte_order_magic() {
        let sig = PcapngSignature;

        // Little-endian byte-order magic
        let buf = make_pcapng_header(&[0x1A, 0x2B, 0x3C, 0x4D]);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "pcapng");
        assert_eq!(init.calculated_file_size, None);

        // Big-endian byte-order magic
        let buf = make_pcapng_header(&[0x4D, 0x3C, 0x2B, 0x1A]);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "pcapng");
    }

    #[test]
    fn test_pcapng_invalid_byte_order_magic_rejected() {
        let sig = PcapngSignature;
        let buf = make_pcapng_header(&[0x00, 0x00, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_short_buffer() {
        let sig_le = PcapLeSignature;
        let sig_be = PcapBeSignature;
        let sig_ng = PcapngSignature;

        // PCAP needs at least 24 bytes
        let short_pcap = &[0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00];
        assert!(sig_le.header_check(short_pcap, 0).is_none());

        let short_pcap_be = &[0xA1, 0xB2, 0xC3, 0xD4, 0x00, 0x02];
        assert!(sig_be.header_check(short_pcap_be, 0).is_none());

        // PCAPNG needs at least 12 bytes
        let short_pcapng = &[0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00];
        assert!(sig_ng.header_check(short_pcapng, 0).is_none());
    }
}
