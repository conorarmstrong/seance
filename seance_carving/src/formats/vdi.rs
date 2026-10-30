use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VDI (VirtualBox Virtual Disk Image) carving signature. Ported from file_vdi.c.
/// Header: signature bytes 7F 10 DA BE at offset 0x40, version 0x00010001 at 0x44.
/// Static images encode an exact size (blocks_in_image * block_size + offset_data);
/// dynamic images only get a minimum size (offset_data). No footer.
struct VdiSignature;

const VDI_MAGIC: &[u8] = &[0x7f, 0x10, 0xda, 0xbe];
const PHOTOREC_MAX_FILE_SIZE: u64 = (1u64 << 41) - 1;
/// sizeof(VdiHeader) in the C source.
const VDI_HEADER_SIZE: u64 = 512;

fn u32le(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

impl FileSignature for VdiSignature {
    fn name(&self) -> &str {
        "VDI"
    }
    fn extensions(&self) -> &[&str] {
        &["vdi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic + version live at 0x40 / 0x44.
        if buf.len() < 0x48 || &buf[0x40..0x44] != VDI_MAGIC {
            return None;
        }
        if u32le(buf, 0x44) != 0x0001_0001 {
            return None;
        }
        if buf.len() < 0x15c {
            return None;
        }
        let offset_data = u32le(buf, 0x158) as u64;
        if offset_data < VDI_HEADER_SIZE {
            return None;
        }
        let image_type = u32le(buf, 0x4c);
        // VDI_TYPE_STATIC == 2. Anything else is dynamic -> only a minimum size.
        if image_type != 2 {
            return Some(RecoveryInit {
                min_filesize: offset_data,
                extension: "vdi".to_string(),
                calculated_file_size: None,
            });
        }
        if buf.len() < 0x184 {
            return None;
        }
        let block_size = u32le(buf, 0x178) as u64;
        let blocks_in_image = u32le(buf, 0x180) as u64;
        let fs = blocks_in_image.saturating_mul(block_size);
        if fs > PHOTOREC_MAX_FILE_SIZE {
            return None;
        }
        let fs = fs + offset_data;
        if fs > PHOTOREC_MAX_FILE_SIZE {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: offset_data,
            extension: "vdi".to_string(),
            calculated_file_size: Some(fs),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0x40, VDI_MAGIC, Arc::new(VdiSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dynamic_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];
        buf[0x40..0x44].copy_from_slice(VDI_MAGIC);
        buf[0x44..0x48].copy_from_slice(&0x0001_0001u32.to_le_bytes()); // version
        buf[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes()); // dynamic
        buf[0x158..0x15c].copy_from_slice(&512u32.to_le_bytes()); // offset_data
        buf
    }

    #[test]
    fn test_vdi_header_match() {
        let sig = VdiSignature;
        let buf = dynamic_header();
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 512);
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_vdi_no_match() {
        let sig = VdiSignature;
        let mut buf = dynamic_header();
        buf[0x40] = 0x00; // corrupt magic
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
