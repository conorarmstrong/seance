use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ELF (Executable and Linking Format) file signature detector.
/// Header: 7F 45 4C 46 ("\x7fELF") at offset 0.
/// Supports 32-bit and 64-bit ELF files in both little-endian and big-endian byte orders.
/// File size = e_shoff + (e_shnum * e_shentsize) when section headers are present.
/// Ref: ELF specification, System V ABI
struct ElfSignature;

impl ElfSignature {
    /// Minimum ELF header size (ELF64 header is 64 bytes, ELF32 is 52 bytes).
    const MIN_HEADER_32: usize = 0x34;
    const MIN_HEADER_64: usize = 0x40;

    /// Read a u16 from the buffer using the specified endianness.
    fn read_u16(buf: &[u8], offset: usize, little_endian: bool) -> u16 {
        let bytes = [buf[offset], buf[offset + 1]];
        if little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    }

    /// Read a u32 from the buffer using the specified endianness.
    fn read_u32(buf: &[u8], offset: usize, little_endian: bool) -> u32 {
        let bytes = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }

    /// Read a u64 from the buffer using the specified endianness.
    fn read_u64(buf: &[u8], offset: usize, little_endian: bool) -> u64 {
        let bytes = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ];
        if little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    }
}

impl FileSignature for ElfSignature {
    fn name(&self) -> &str {
        "ELF"
    }

    fn extensions(&self) -> &[&str] {
        &["elf", "so", "o", "ko"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need at least the ELF32 header to proceed
        if buf.len() < Self::MIN_HEADER_32 {
            return None;
        }

        // Check magic: 7F 45 4C 46
        if buf[0..4] != [0x7F, 0x45, 0x4C, 0x46] {
            return None;
        }

        // e_ident[EI_CLASS]: 1=32-bit, 2=64-bit
        let class = buf[4];
        if class != 1 && class != 2 {
            return None;
        }
        let is_64bit = class == 2;

        // e_ident[EI_DATA]: 1=little-endian, 2=big-endian
        let data = buf[5];
        if data != 1 && data != 2 {
            return None;
        }
        let little_endian = data == 1;

        // e_ident[EI_VERSION]: must be 1
        if buf[6] != 1 {
            return None;
        }

        // For 64-bit ELF we need a larger header
        if is_64bit && buf.len() < Self::MIN_HEADER_64 {
            return None;
        }

        // e_version at offset 0x14 (u32, both 32 and 64-bit): must be 1
        let e_version = Self::read_u32(buf, 0x14, little_endian);
        if e_version != 1 {
            return None;
        }

        // Calculate file size from section header table
        let calculated_file_size = if is_64bit {
            // ELF64: e_shoff (u64 at 0x28), e_shentsize (u16 at 0x3A), e_shnum (u16 at 0x3C)
            let e_shoff = Self::read_u64(buf, 0x28, little_endian);
            let e_shentsize = Self::read_u16(buf, 0x3A, little_endian) as u64;
            let e_shnum = Self::read_u16(buf, 0x3C, little_endian) as u64;

            if e_shoff == 0 || e_shnum == 0 {
                None
            } else {
                let size = e_shoff.saturating_add(e_shnum.saturating_mul(e_shentsize));
                if size > self.max_file_size() {
                    None
                } else {
                    Some(size)
                }
            }
        } else {
            // ELF32: e_shoff (u32 at 0x20), e_shentsize (u16 at 0x2E), e_shnum (u16 at 0x30)
            let e_shoff = Self::read_u32(buf, 0x20, little_endian) as u64;
            let e_shentsize = Self::read_u16(buf, 0x2E, little_endian) as u64;
            let e_shnum = Self::read_u16(buf, 0x30, little_endian) as u64;

            if e_shoff == 0 || e_shnum == 0 {
                None
            } else {
                let size = e_shoff.saturating_add(e_shnum.saturating_mul(e_shentsize));
                if size > self.max_file_size() {
                    None
                } else {
                    Some(size)
                }
            }
        };

        let min_filesize = if is_64bit {
            Self::MIN_HEADER_64 as u64
        } else {
            Self::MIN_HEADER_32 as u64
        };

        Some(RecoveryInit {
            min_filesize,
            extension: "elf".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024 // 256 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x7F, 0x45, 0x4C, 0x46], Arc::new(ElfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF32 little-endian header with the given section header values.
    fn make_elf32_le_header(e_shoff: u32, e_shentsize: u16, e_shnum: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 0x34];
        // ELF magic
        buf[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        // EI_CLASS = 1 (32-bit)
        buf[4] = 1;
        // EI_DATA = 1 (little-endian)
        buf[5] = 1;
        // EI_VERSION = 1
        buf[6] = 1;
        // e_version at 0x14 = 1 (LE)
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        // e_shoff at 0x20 (u32 LE)
        buf[0x20..0x24].copy_from_slice(&e_shoff.to_le_bytes());
        // e_shentsize at 0x2E (u16 LE)
        buf[0x2E..0x30].copy_from_slice(&e_shentsize.to_le_bytes());
        // e_shnum at 0x30 (u16 LE)
        buf[0x30..0x32].copy_from_slice(&e_shnum.to_le_bytes());
        buf
    }

    /// Build a minimal ELF64 little-endian header with the given section header values.
    fn make_elf64_le_header(e_shoff: u64, e_shentsize: u16, e_shnum: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 0x40];
        // ELF magic
        buf[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        // EI_CLASS = 2 (64-bit)
        buf[4] = 2;
        // EI_DATA = 1 (little-endian)
        buf[5] = 1;
        // EI_VERSION = 1
        buf[6] = 1;
        // e_version at 0x14 = 1 (LE)
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        // e_shoff at 0x28 (u64 LE)
        buf[0x28..0x30].copy_from_slice(&e_shoff.to_le_bytes());
        // e_shentsize at 0x3A (u16 LE)
        buf[0x3A..0x3C].copy_from_slice(&e_shentsize.to_le_bytes());
        // e_shnum at 0x3C (u16 LE)
        buf[0x3C..0x3E].copy_from_slice(&e_shnum.to_le_bytes());
        buf
    }

    #[test]
    fn test_elf32_le_header_match_with_size() {
        let sig = ElfSignature;
        // e_shoff=0x1000, e_shentsize=0x28 (40), e_shnum=10
        // size = 0x1000 + 10 * 0x28 = 4096 + 400 = 4496
        let buf = make_elf32_le_header(0x1000, 0x28, 10);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(4496));
        assert_eq!(init.extension, "elf");
        assert_eq!(init.min_filesize, 0x34);
    }

    #[test]
    fn test_elf64_le_header_match() {
        let sig = ElfSignature;
        // e_shoff=0x2000, e_shentsize=0x40 (64), e_shnum=20
        // size = 0x2000 + 20 * 0x40 = 8192 + 1280 = 9472
        let buf = make_elf64_le_header(0x2000, 0x40, 20);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(9472));
        assert_eq!(init.extension, "elf");
        assert_eq!(init.min_filesize, 0x40);
    }

    #[test]
    fn test_elf_no_match_wrong_magic() {
        let sig = ElfSignature;
        let mut buf = make_elf32_le_header(0x1000, 0x28, 10);
        buf[0] = 0x00; // corrupt magic
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_elf_short_buffer_returns_none() {
        let sig = ElfSignature;
        // Only 16 bytes — too short for even ELF32 header
        let buf = &[0x7F, 0x45, 0x4C, 0x46, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_elf_e_version_not_one_returns_none() {
        let sig = ElfSignature;
        let mut buf = make_elf32_le_header(0x1000, 0x28, 10);
        // Set e_version at 0x14 to 0 instead of 1
        buf[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
