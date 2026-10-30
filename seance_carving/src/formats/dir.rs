use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FAT subdirectory (DIR) carving signature. Header: a FAT directory whose first two entries are
/// the "." (dot + 10 spaces)
/// and ".." (two dots + 9 spaces) self/parent links, each carrying the ATTR_DIR
/// bit (0x10) and not the ATTR_EXT bits (0x0F). No footer.
///
/// NOTE: PhotoRec marks this format recover=0 (used only for FAT analysis) and
/// its data_check saves a single cluster (buffer_size/2), which is block-size
/// dependent. That single-cluster behaviour is not replicated; this port
/// performs the directory-entry validation and lets the engine carve normally.
struct DirSignature;

// "." then 10 spaces == 11 bytes (msdos name+ext field of the "." entry).
const DOT_ENTRY: &[u8] = b".          ";
// ".." then 9 spaces == 11 bytes (name+ext field of the ".." entry).
const DOTDOT_ENTRY: &[u8] = b"..         ";
const ATTR_EXT: u8 = 0x0F; // ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME
const ATTR_DIR: u8 = 0x10;

impl FileSignature for DirSignature {
    fn name(&self) -> &str {
        "DIR"
    }
    fn extensions(&self) -> &[&str] {
        &["fat"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need both 32-byte entries plus the second entry's attr byte at 0x2B.
        if buf.len() < 0x2C {
            return None;
        }
        let dot_ok = &buf[0..11] == DOT_ENTRY;
        let dotdot_ok = &buf[0x20..0x2B] == DOTDOT_ENTRY;
        let attr0 = buf[0x0B];
        let attr1 = buf[0x2B];
        if dot_ok
            && dotdot_ok
            && attr0 != ATTR_EXT
            && (attr0 & ATTR_DIR) != 0
            && attr1 != ATTR_EXT
            && (attr1 & ATTR_DIR) != 0
        {
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "fat".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, DOT_ENTRY, Arc::new(DirSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dir() -> Vec<u8> {
        assert_eq!(DOT_ENTRY.len(), 11);
        assert_eq!(DOTDOT_ENTRY.len(), 11);
        let mut buf = vec![0u8; 0x40];
        buf[0..11].copy_from_slice(DOT_ENTRY);
        buf[0x0B] = ATTR_DIR;
        buf[0x20..0x2B].copy_from_slice(DOTDOT_ENTRY);
        buf[0x2B] = ATTR_DIR;
        buf
    }

    #[test]
    fn test_dir_header_match() {
        assert!(DirSignature.header_check(&valid_dir(), 0).is_some());
    }

    #[test]
    fn test_dir_no_match() {
        // Missing directory attribute bit.
        let mut buf = valid_dir();
        buf[0x0B] = 0x00;
        assert!(DirSignature.header_check(&buf, 0).is_none());
        // Second entry is not "..".
        let mut buf2 = valid_dir();
        buf2[0x20] = b'X';
        assert!(DirSignature.header_check(&buf2, 0).is_none());
    }
}
