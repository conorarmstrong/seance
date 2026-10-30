use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ASF Header Object GUID {75B22630-668E-11CF-A6D9-00AA0062CE6C}, on-disk bytes
/// (Data1-3 little-endian, Data4 big-endian). Shared by WMV/WMA/ASF.
const ASF_HEADER_GUID: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
/// ASF File Properties Object GUID {8CABDCA1-A947-11CF-8EE4-00C00C205365}. Its
/// File Size field (at +40) gives the exact total file size.
const ASF_FILE_PROPS_GUID: [u8; 16] = [
    0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11, 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65,
];

/// ASF container detector (Windows Media: WMV/WMA/ASF). Emits .wmv as the
/// common case; carves the exact size from the File Properties Object.
struct AsfSignature;

impl FileSignature for AsfSignature {
    fn name(&self) -> &str {
        "ASF"
    }

    fn extensions(&self) -> &[&str] {
        &["wmv", "wma", "asf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 30 || buf[0..16] != ASF_HEADER_GUID {
            return None;
        }
        // Header Object: GUID(16) + object_size(u64) + num_header_objects(u32)
        // + reserved(2); sub-objects begin at offset 30.
        let header_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let hdr_end = (header_size as usize).min(buf.len());

        // Scan the header's sub-objects for the File Properties Object.
        let mut pos = 30usize;
        let mut calculated: Option<u64> = None;
        // `pos` is advanced by an attacker-controlled object size, so every sum
        // with it is checked: a size near usize::MAX must end the walk, not
        // overflow (the release profile has overflow-checks on).
        while pos.checked_add(24).is_some_and(|end| end <= hdr_end) {
            let obj_size = u64::from_le_bytes(buf[pos + 16..pos + 24].try_into().unwrap());
            if obj_size < 24 {
                break;
            }
            if buf[pos..pos + 16] == ASF_FILE_PROPS_GUID && pos + 48 <= buf.len() {
                calculated = Some(u64::from_le_bytes(
                    buf[pos + 40..pos + 48].try_into().unwrap(),
                ));
                break;
            }
            match usize::try_from(obj_size)
                .ok()
                .and_then(|size| pos.checked_add(size))
            {
                Some(next) => pos = next,
                None => break,
            }
        }

        Some(RecoveryInit {
            min_filesize: header_size.max(30),
            extension: "wmv".to_string(),
            // Only trust a File Size that is at least the header size.
            calculated_file_size: calculated.filter(|&s| s >= header_size),
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
    registry.register(0, &ASF_HEADER_GUID, Arc::new(AsfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_asf(file_size: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        buf[0..16].copy_from_slice(&ASF_HEADER_GUID);
        buf[16..24].copy_from_slice(&96u64.to_le_bytes()); // header object size
        buf[24..28].copy_from_slice(&1u32.to_le_bytes()); // num header objects
                                                          // File Properties Object as the first sub-object at offset 30
        let p = 30;
        buf[p..p + 16].copy_from_slice(&ASF_FILE_PROPS_GUID);
        buf[p + 16..p + 24].copy_from_slice(&80u64.to_le_bytes()); // its size
        buf[p + 40..p + 48].copy_from_slice(&file_size.to_le_bytes()); // File Size
        buf
    }

    #[test]
    fn detects_asf_and_reads_file_size() {
        let buf = build_asf(123456);
        let init = AsfSignature.header_check(&buf, 0).expect("ASF header");
        assert_eq!(init.extension, "wmv");
        assert_eq!(init.calculated_file_size, Some(123456));
    }

    /// A sub-object size that carries `pos` to within 24 of usize::MAX used to
    /// overflow the loop condition and abort the carving thread.
    #[test]
    fn a_hostile_sub_object_size_ends_the_walk_without_overflow() {
        for hostile in [u64::MAX - 40, u64::MAX, usize::MAX as u64 - 40] {
            let mut buf = build_asf(123456);
            buf[30..46].copy_from_slice(&[0u8; 16]); // not the File Properties Object
            buf[46..54].copy_from_slice(&hostile.to_le_bytes());
            let init = AsfSignature.header_check(&buf, 0).expect("ASF header");
            assert_eq!(init.calculated_file_size, None);
        }
    }

    #[test]
    fn rejects_non_asf() {
        assert!(AsfSignature.header_check(&[0u8; 64], 0).is_none());
    }
}
