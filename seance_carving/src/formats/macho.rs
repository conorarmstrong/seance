use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mach-O 32-bit little-endian executable signature detector.
/// Header magic: CE FA ED FE (0xCEFAEDFE) at offset 0.
/// ncmds (u32 LE) at offset 16, sizeofcmds (u32 LE) at offset 20.
/// Minimum file size estimate: 28 (Mach-O 32-bit header) + sizeofcmds.
/// Actual file is larger; uses max-size recovery.
struct MachO32LeSignature;

impl FileSignature for MachO32LeSignature {
    fn name(&self) -> &str {
        "Mach-O 32-bit LE"
    }

    fn extensions(&self) -> &[&str] {
        &["macho", "dylib", "bundle", "kext"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // 32-bit Mach-O header is 28 bytes
        if buf.len() < 28 {
            return None;
        }
        if buf[0..4] != [0xCE, 0xFA, 0xED, 0xFE] {
            return None;
        }

        // ncmds at offset 16 (u32 LE)
        let ncmds = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if ncmds == 0 || ncmds >= 10000 {
            return None;
        }

        // sizeofcmds at offset 20 (u32 LE)
        let sizeofcmds = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);

        // Minimum file size = header (28) + sizeofcmds
        // sizeofcmds is a header field a damaged file gets wrong: clamped to the
        // size cap, so a corrupt value cannot make the carve unrecordable.
        let min_size = 28u64
            .saturating_add(sizeofcmds as u64)
            .min(self.max_file_size());

        Some(RecoveryInit {
            min_filesize: min_size,
            extension: "macho".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024 // 512 MB
    }
}

/// Mach-O 64-bit little-endian executable signature detector.
/// Header magic: CF FA ED FE (0xCFFAEDFE) at offset 0.
/// ncmds (u32 LE) at offset 16, sizeofcmds (u32 LE) at offset 20.
/// Minimum file size estimate: 32 (Mach-O 64-bit header) + sizeofcmds.
/// Actual file is larger; uses max-size recovery.
struct MachO64LeSignature;

impl FileSignature for MachO64LeSignature {
    fn name(&self) -> &str {
        "Mach-O 64-bit LE"
    }

    fn extensions(&self) -> &[&str] {
        &["macho", "dylib", "bundle", "kext"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // 64-bit Mach-O header is 32 bytes
        if buf.len() < 32 {
            return None;
        }
        if buf[0..4] != [0xCF, 0xFA, 0xED, 0xFE] {
            return None;
        }

        // ncmds at offset 16 (u32 LE)
        let ncmds = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if ncmds == 0 || ncmds >= 10000 {
            return None;
        }

        // sizeofcmds at offset 20 (u32 LE)
        let sizeofcmds = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);

        // Minimum file size = header (32) + sizeofcmds
        // Clamped to the size cap, as in the 32-bit signature.
        let min_size = 32u64
            .saturating_add(sizeofcmds as u64)
            .min(self.max_file_size());

        Some(RecoveryInit {
            min_filesize: min_size,
            extension: "macho".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024 // 512 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0xCE, 0xFA, 0xED, 0xFE], Arc::new(MachO32LeSignature));
    registry.register(0, &[0xCF, 0xFA, 0xED, 0xFE], Arc::new(MachO64LeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corrupt sizeofcmds (up to 4 GiB) must not set a minimum size above the
    /// signature's own cap, which no carve could ever reach.
    #[test]
    fn a_huge_sizeofcmds_does_not_set_an_unreachable_minimum() {
        let sig32 = MachO32LeSignature;
        let init = sig32
            .header_check(&make_macho32_header(5, 0xFFFF_FFF0), 0)
            .unwrap();
        assert!(init.min_filesize <= sig32.max_file_size());
        let sig64 = MachO64LeSignature;
        let init = sig64
            .header_check(&make_macho64_header(5, 0xFFFF_FFF0), 0)
            .unwrap();
        assert!(init.min_filesize <= sig64.max_file_size());
    }

    fn make_macho64_header(ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        // Magic: CF FA ED FE (64-bit LE)
        buf[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        // ncmds at offset 16
        buf[16..20].copy_from_slice(&ncmds.to_le_bytes());
        // sizeofcmds at offset 20
        buf[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
        buf
    }

    fn make_macho32_header(ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        // Magic: CE FA ED FE (32-bit LE)
        buf[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
        // ncmds at offset 16
        buf[16..20].copy_from_slice(&ncmds.to_le_bytes());
        // sizeofcmds at offset 20
        buf[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
        buf
    }

    #[test]
    fn test_macho64_le_match() {
        let sig = MachO64LeSignature;
        let buf = make_macho64_header(15, 2048);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "macho");
        assert_eq!(init.min_filesize, 32 + 2048);
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_macho32_le_match() {
        let sig = MachO32LeSignature;
        let buf = make_macho32_header(10, 1024);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "macho");
        assert_eq!(init.min_filesize, 28 + 1024);
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_macho_no_match() {
        let sig = MachO64LeSignature;
        let buf = vec![0u8; 32];
        assert!(sig.header_check(&buf, 0).is_none());

        let sig32 = MachO32LeSignature;
        let buf32 = vec![0u8; 28];
        assert!(sig32.header_check(&buf32, 0).is_none());
    }

    #[test]
    fn test_macho_short_buffer() {
        let sig64 = MachO64LeSignature;
        let buf = &[0xCF, 0xFA, 0xED, 0xFE];
        assert!(sig64.header_check(buf, 0).is_none());

        let sig32 = MachO32LeSignature;
        let buf32 = &[0xCE, 0xFA, 0xED, 0xFE];
        assert!(sig32.header_check(buf32, 0).is_none());
    }

    #[test]
    fn test_macho_invalid_ncmds_zero() {
        let sig64 = MachO64LeSignature;
        let buf = make_macho64_header(0, 2048);
        assert!(sig64.header_check(&buf, 0).is_none());

        let sig32 = MachO32LeSignature;
        let buf32 = make_macho32_header(0, 1024);
        assert!(sig32.header_check(&buf32, 0).is_none());
    }
}
