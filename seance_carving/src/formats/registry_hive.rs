use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Registry hive file signature detector.
/// Header: "regf" (72 65 67 66) at offset 0.
/// Hive bins follow the base block (4096 bytes). Each bin starts with "hbin".
/// File size: base block length field at offset 0x28 (LE u32) + 4096 (base block).
/// Ref: reference/testdisk/src/file_reg.c
struct RegistryHiveSignature;

impl FileSignature for RegistryHiveSignature {
    fn name(&self) -> &str {
        "Registry"
    }

    fn extensions(&self) -> &[&str] {
        &["reg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x30 || &buf[0..4] != b"regf" {
            return None;
        }

        // Hive bins data size at offset 0x28 (LE u32)
        let hive_data_size =
            u32::from_le_bytes([buf[0x28], buf[0x29], buf[0x2A], buf[0x2B]]) as u64;

        // Total file size = 4096 (base block) + hive data
        let file_size = 4096 + hive_data_size;

        if file_size < 8192 || file_size > self.max_file_size() {
            // Minimum: base block + one hive bin (4096 each)
            return Some(RecoveryInit {
                min_filesize: 4096,
                extension: "reg".to_string(),
                calculated_file_size: None,
            });
        }

        Some(RecoveryInit {
            min_filesize: 4096,
            extension: "reg".to_string(),
            calculated_file_size: Some(file_size),
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024 // 512 MB — large SAM/SOFTWARE hives
    }
}

/// A `regf` base block states its format: major version 1 (u32 at 0x14),
/// minor version 1–6 (u32 at 0x18) and file format 1, "direct memory load"
/// (u32 at 0x20).
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 0x24 {
        return true;
    }
    let le32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
    le32(0x14) == 1 && (1..=6).contains(&le32(0x18)) && le32(0x20) == 1
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"regf", Arc::new(RegistryHiveSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regf_header(hive_data_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x30];
        buf[0..4].copy_from_slice(b"regf");
        buf[0x28..0x2C].copy_from_slice(&hive_data_size.to_le_bytes());
        buf
    }

    #[test]
    fn test_registry_header_match() {
        let sig = RegistryHiveSignature;
        let buf = make_regf_header(4096); // one hive bin
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(8192)); // 4096 + 4096
    }

    #[test]
    fn test_registry_large_hive() {
        let sig = RegistryHiveSignature;
        let buf = make_regf_header(10 * 1024 * 1024); // 10 MB data
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(4096 + 10 * 1024 * 1024));
    }

    #[test]
    fn test_registry_no_match() {
        let sig = RegistryHiveSignature;
        let buf = vec![0u8; 0x30];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_registry_too_short() {
        let sig = RegistryHiveSignature;
        let buf = b"regf";
        assert!(sig.header_check(buf, 0).is_none());
    }
}
