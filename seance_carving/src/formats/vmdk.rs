use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VMDK v3 (COWD) virtual disk file signature detector.
/// Header: 43 4F 57 44 01 00 00 00 (8 bytes at offset 0).
/// Granularity (u32 LE) at offset 16: must be > 0 and <= 0x200000.
/// No reliable size calculation; uses max-size recovery.
/// Ref: reference/testdisk/src/file_vmdk.c
struct VmdkCowdSignature;

impl FileSignature for VmdkCowdSignature {
    fn name(&self) -> &str {
        "VMDK_COWD"
    }

    fn extensions(&self) -> &[&str] {
        &["vmdk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 20 {
            return None;
        }
        if buf[0..8] != [0x43, 0x4F, 0x57, 0x44, 0x01, 0x00, 0x00, 0x00] {
            return None;
        }

        // Granularity (u32 LE) at offset 16
        let granularity = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if granularity == 0 || granularity > 0x200000 {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 20,
            extension: "vmdk".to_string(),
            calculated_file_size: None,
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

/// VMDK v4 (KDMV) sparse virtual disk file signature detector.
/// Header: 4B 44 4D 56 + version (u32 LE, 1/2/3) at offset 0-7.
/// Granularity (u64 LE) at offset 16: must be > 0 and <= 0x200000.
/// num_gtes_per_gte (u32 LE) at offset 44: must be > 0 and <= 512.
/// No reliable size calculation; uses max-size recovery.
/// Ref: reference/testdisk/src/file_vmdk.c
struct VmdkSparseSignature;

impl FileSignature for VmdkSparseSignature {
    fn name(&self) -> &str {
        "VMDK_SPARSE"
    }

    fn extensions(&self) -> &[&str] {
        &["vmdk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 48 {
            return None;
        }
        // Verify KDMV magic
        if buf[0..4] != [0x4B, 0x44, 0x4D, 0x56] {
            return None;
        }

        // Version (u32 LE) at offset 4: must be 1, 2, or 3
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version == 0 || version > 3 {
            return None;
        }

        // Granularity (u64 LE) at offset 16
        let granularity = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        if granularity == 0 || granularity > 0x200000 {
            return None;
        }

        // num_gtes_per_gte (u32 LE) at offset 44
        let num_gtes_per_gte = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        if num_gtes_per_gte == 0 || num_gtes_per_gte > 512 {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 48,
            extension: "vmdk".to_string(),
            calculated_file_size: None,
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

pub fn register(registry: &mut SignatureRegistry) {
    // VMDK v3 (COWD) - version 1
    registry.register(
        0,
        &[0x43, 0x4F, 0x57, 0x44, 0x01, 0x00, 0x00, 0x00],
        Arc::new(VmdkCowdSignature),
    );

    // VMDK v4 (KDMV) - version 1
    let sparse: Arc<dyn FileSignature> = Arc::new(VmdkSparseSignature);
    registry.register(
        0,
        &[0x4B, 0x44, 0x4D, 0x56, 0x01, 0x00, 0x00, 0x00],
        Arc::clone(&sparse),
    );
    // VMDK v4 (KDMV) - version 2
    registry.register(
        0,
        &[0x4B, 0x44, 0x4D, 0x56, 0x02, 0x00, 0x00, 0x00],
        Arc::clone(&sparse),
    );
    // VMDK v4 (KDMV) - version 3
    registry.register(0, &[0x4B, 0x44, 0x4D, 0x56, 0x03, 0x00, 0x00, 0x00], sparse);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vmdk_v4_header(version: u32, granularity: u64, num_gtes: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(&[0x4B, 0x44, 0x4D, 0x56]);
        buf[4..8].copy_from_slice(&version.to_le_bytes());
        buf[16..24].copy_from_slice(&granularity.to_le_bytes());
        buf[44..48].copy_from_slice(&num_gtes.to_le_bytes());
        buf
    }

    fn make_vmdk_cowd_header(granularity: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0..8].copy_from_slice(&[0x43, 0x4F, 0x57, 0x44, 0x01, 0x00, 0x00, 0x00]);
        buf[16..20].copy_from_slice(&granularity.to_le_bytes());
        buf
    }

    #[test]
    fn test_vmdk_v4_version1_match() {
        let sig = VmdkSparseSignature;
        let buf = make_vmdk_v4_header(1, 128, 256);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "vmdk");
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_vmdk_v4_invalid_granularity() {
        let sig = VmdkSparseSignature;
        // Granularity of 0 should be rejected
        let buf = make_vmdk_v4_header(1, 0, 256);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_vmdk_cowd_match() {
        let sig = VmdkCowdSignature;
        let buf = make_vmdk_cowd_header(64);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "vmdk");
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_vmdk_no_match() {
        let sig = VmdkSparseSignature;
        let buf = vec![0u8; 48];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_vmdk_short_buffer() {
        let sig = VmdkSparseSignature;
        let buf = &[0x4B, 0x44, 0x4D, 0x56, 0x01, 0x00, 0x00, 0x00];
        assert!(sig.header_check(buf, 0).is_none());
    }
}
