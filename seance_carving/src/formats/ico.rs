use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Icon (ICO) carving signature. Header: 6 bytes {0x00,0x00,0x01,0x00, count_lo, 0x00}
/// where reserved==0,
/// type==1 and count is 1..9. The file size is calculated from the icon
/// directory (max of bitmap_offset + bitmap_size). No footer; size from header.
struct IcoSignature;

impl IcoSignature {
    /// Number of directory entries the magic pins (1..9).
    fn variants() -> [[u8; 6]; 9] {
        let mut v = [[0u8; 6]; 9];
        for (i, entry) in v.iter_mut().enumerate() {
            *entry = [0x00, 0x00, 0x01, 0x00, (i + 1) as u8, 0x00];
        }
        v
    }
}

impl FileSignature for IcoSignature {
    fn name(&self) -> &str {
        "ICO"
    }

    fn extensions(&self) -> &[&str] {
        &["ico"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 6 {
            return None;
        }
        let reserved = u16::from_le_bytes([buf[0], buf[1]]);
        let typ = u16::from_le_bytes([buf[2], buf[3]]);
        let count = u16::from_le_bytes([buf[4], buf[5]]);
        if reserved != 0 || typ != 1 || count == 0 {
            return None;
        }
        let mut fs: u64 = 0;
        let mut i: usize = 0;
        let mut pos: usize = 6; // first icon_directory entry
        while i < count as usize && pos + 16 <= buf.len() {
            let e = &buf[pos..pos + 16];
            let width = e[0];
            let heigth = e[1];
            let dir_reserved = e[3];
            let color_planes = u16::from_le_bytes([e[4], e[5]]);
            let bits_per_pixel = u16::from_le_bytes([e[6], e[7]]);
            let bitmap_size = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
            let bitmap_offset = u32::from_le_bytes([e[12], e[13], e[14], e[15]]);
            if dir_reserved != 0 && dir_reserved != 255 {
                return None;
            }
            if color_planes > 1 {
                return None;
            }
            if width != heigth {
                return None; // reject non-square icon
            }
            match width {
                16 | 24 | 32 | 48 | 64 | 128 | 0 => {}
                _ => return None,
            }
            match bits_per_pixel {
                0 | 1 | 4 | 8 | 16 | 24 | 32 => {}
                _ => return None,
            }
            if bitmap_size == 0 {
                return None;
            }
            if (bitmap_offset as u64) < 6 + count as u64 * 16 {
                return None;
            }
            let candidate = bitmap_size as u64 + bitmap_offset as u64;
            if fs < candidate {
                fs = candidate;
            }
            i += 1;
            pos += 16;
        }
        Some(RecoveryInit {
            min_filesize: 22, // header + at least one directory entry
            extension: "ico".to_string(),
            calculated_file_size: Some(fs),
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
    for magic in IcoSignature::variants() {
        registry.register(0, &magic, Arc::new(IcoSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ico_header_match() {
        let sig = IcoSignature;
        // header: reserved=0, type=1, count=1; one square 16x16 directory entry.
        let buf = [
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, // header
            0x10, 0x10, 0x00, 0x00, // width, heigth, color_count, reserved
            0x01, 0x00, // color_planes = 1
            0x00, 0x00, // bits_per_pixel = 0
            0x00, 0x04, 0x00, 0x00, // bitmap_size = 1024
            0x16, 0x00, 0x00, 0x00, // bitmap_offset = 22
        ];
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1024 + 22));
    }

    #[test]
    fn test_ico_no_match() {
        let sig = IcoSignature;
        // type=2 is invalid
        let buf = [
            0x00u8, 0x00, 0x02, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(sig.header_check(&buf, 0).is_none());
        // count=0 is invalid
        let buf2 = [0x00u8, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
