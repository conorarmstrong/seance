use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VHD (Virtual Hard Disk) file signature detector.
/// Footer magic: "conectix" (8 bytes: 63 6F 6E 65 63 74 69 78) at offset 0.
/// Fixed/dynamic VHDs have a copy of the footer at the beginning of the file.
/// File format version at offset 12: u32 BE, should be 0x00010000 (1.0).
/// Disk type at offset 60: u32 BE: 2=Fixed, 3=Dynamic, 4=Differencing.
/// Original size (virtual disk size) at offset 40: u64 BE.
/// For fixed VHD, actual file size = original_size + 512 (footer).
/// For dynamic/differencing, actual file is smaller; use max-size recovery.
/// Ref: Microsoft VHD specification
struct VhdSignature;

impl VhdSignature {
    /// Minimum header size needed for validation (through disk type at offset 60 + 4 bytes).
    const MIN_HEADER: usize = 64;
}

impl FileSignature for VhdSignature {
    fn name(&self) -> &str {
        "VHD"
    }

    fn extensions(&self) -> &[&str] {
        &["vhd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < Self::MIN_HEADER {
            return None;
        }

        // Check magic: "conectix"
        if &buf[0..8] != b"conectix" {
            return None;
        }

        // File format version at offset 12: u32 BE, must be 0x00010000 (version 1.0)
        let version = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if version != 0x00010000 {
            return None;
        }

        // Disk type at offset 60: u32 BE: 2=Fixed, 3=Dynamic, 4=Differencing
        let disk_type = u32::from_be_bytes([buf[60], buf[61], buf[62], buf[63]]);
        if disk_type != 2 && disk_type != 3 && disk_type != 4 {
            return None;
        }

        // Original size (virtual disk size) at offset 40: u64 BE
        let original_size = u64::from_be_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);

        let calculated_file_size = if disk_type == 2 {
            // Fixed VHD: actual file size = original_size + 512 (footer)
            let size = original_size.saturating_add(512);
            if size > self.max_file_size() {
                None
            } else {
                Some(size)
            }
        } else {
            // Dynamic or differencing: actual file is smaller, use max-size recovery
            None
        };

        Some(RecoveryInit {
            min_filesize: 512,
            extension: "vhd".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024 * 1024 * 1024 // 2 TB
    }
}

/// VHDX (Virtual Hard Disk v2) file signature detector.
/// Magic: "vhdxfile" (8 bytes: 76 68 64 78 66 69 6C 65) at offset 0.
/// No reliable size from header; use max-size recovery.
/// Ref: Microsoft VHDX specification
struct VhdxSignature;

impl FileSignature for VhdxSignature {
    fn name(&self) -> &str {
        "VHDX"
    }

    fn extensions(&self) -> &[&str] {
        &["vhdx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }

        // Check magic: "vhdxfile"
        if &buf[0..8] != b"vhdxfile" {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 1024,
            extension: "vhdx".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024 * 1024 * 1024 // 64 TB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78],
        Arc::new(VhdSignature),
    );
    registry.register(
        0,
        &[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65],
        Arc::new(VhdxSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal VHD header with the given version, disk type, and original size.
    fn make_vhd_header(version: u32, disk_type: u32, original_size: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        // Magic: "conectix"
        buf[0..8].copy_from_slice(b"conectix");
        // File format version at offset 12: u32 BE
        buf[12..16].copy_from_slice(&version.to_be_bytes());
        // Original size at offset 40: u64 BE
        buf[40..48].copy_from_slice(&original_size.to_be_bytes());
        // Disk type at offset 60: u32 BE
        buf[60..64].copy_from_slice(&disk_type.to_be_bytes());
        buf
    }

    #[test]
    fn test_vhd_match_valid_version_and_disk_type() {
        let sig = VhdSignature;

        // Fixed VHD (disk_type=2): file size = original_size + 512
        let buf = make_vhd_header(0x00010000, 2, 1024 * 1024);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1024 * 1024 + 512));
        assert_eq!(init.extension, "vhd");

        // Dynamic VHD (disk_type=3): no calculated file size
        let buf = make_vhd_header(0x00010000, 3, 10 * 1024 * 1024);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
        assert_eq!(init.extension, "vhd");

        // Differencing VHD (disk_type=4): no calculated file size
        let buf = make_vhd_header(0x00010000, 4, 10 * 1024 * 1024);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
        assert_eq!(init.extension, "vhd");
    }

    #[test]
    fn test_vhd_invalid_version_rejected() {
        let sig = VhdSignature;
        // Version 0x00020000 is not valid
        let buf = make_vhd_header(0x00020000, 2, 1024 * 1024);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_vhd_invalid_disk_type_rejected() {
        let sig = VhdSignature;
        // Disk type 0 is not valid (must be 2, 3, or 4)
        let buf = make_vhd_header(0x00010000, 0, 1024 * 1024);
        assert!(sig.header_check(&buf, 0).is_none());

        // Disk type 5 is not valid
        let buf = make_vhd_header(0x00010000, 5, 1024 * 1024);
        assert!(sig.header_check(&buf, 0).is_none());

        // Disk type 1 is not valid (Reserved/None)
        let buf = make_vhd_header(0x00010000, 1, 1024 * 1024);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_vhdx_match() {
        let sig = VhdxSignature;
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(b"vhdxfile");
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
        assert_eq!(init.extension, "vhdx");
    }

    #[test]
    fn test_no_match() {
        let vhd = VhdSignature;
        let vhdx = VhdxSignature;
        let buf = vec![0u8; 64];
        assert!(vhd.header_check(&buf, 0).is_none());
        assert!(vhdx.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_short_buffer() {
        let vhd = VhdSignature;
        let vhdx = VhdxSignature;

        // VHD needs at least 64 bytes
        let buf = b"conectix";
        assert!(vhd.header_check(buf, 0).is_none());

        // VHDX needs at least 8 bytes
        let buf = b"vhdx";
        assert!(vhdx.header_check(buf, 0).is_none());
    }
}
