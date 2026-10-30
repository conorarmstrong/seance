use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ext2/ext3/ext4 superblock / directory-block carving signature.
/// Header: superblock magic 0x53 0xEF at offset 0x38, or a linked ".." directory
/// block magic {0x0c,0x00,0x01,0x02,'.',0x00,0x00,0x00} at offset 0x04.
/// Degraded: PhotoRec's test_EXT2 superblock validation and block-size derivation
/// are not implemented (this hint has recover=0 in PhotoRec; it is detection-only).
struct ExtSignature;

const EXT_SB_MAGIC: &[u8] = &[0x53, 0xEF];
const EXT_DIR_MAGIC: &[u8] = &[0x0c, 0x00, 0x01, 0x02, 0x2e, 0x00, 0x00, 0x00];

impl FileSignature for ExtSignature {
    fn name(&self) -> &str {
        "EXT"
    }

    fn extensions(&self) -> &[&str] {
        &["ext"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let sb_ok = buf.len() >= 0x3a && &buf[0x38..0x3a] == EXT_SB_MAGIC;
        let dir_ok = buf.len() >= 0x0c && &buf[0x04..0x0c] == EXT_DIR_MAGIC;
        if sb_ok || dir_ok {
            Some(RecoveryInit {
                min_filesize: 2,
                extension: "ext".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
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
        8_000_000_000
    }
}

/// What a genuine superblock or directory block carries beyond its magic
/// (the ext2/3/4 on-disk layout):
///
/// - a superblock has inodes, blocks and inodes per group, a first data
///   block of 0 or 1, a block size of 1–64 KiB (`s_log_block_size` ≤ 6), a
///   state of at most the three defined bits, an error policy of 1–3, a
///   creator OS of 0–4 and a revision of 0 or 1;
/// - a directory block opens with `.` and then `..`: an entry with a
///   non-zero inode, a record length of at least 12 that is a multiple of 4,
///   a name length of 2, the directory file type and the name `..`.
fn header_block_plausible(buf: &[u8]) -> bool {
    let le16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]) as u32;
    let le32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
    let superblock = buf.len() >= 0x3a && buf[0x38..0x3a] == *EXT_SB_MAGIC && {
        buf.len() < 0x50
            || (le32(0x00) != 0
                && le32(0x14) <= 1
                && le32(0x18) <= 6
                && le32(0x20) != 0
                && le32(0x28) != 0
                && le16(0x3A) <= 7
                && (1..=3).contains(&le16(0x3C))
                && le32(0x48) <= 4
                && le32(0x4C) <= 1)
    };
    let directory = buf.len() >= 0x0c && buf[0x04..0x0c] == *EXT_DIR_MAGIC && {
        buf.len() < 22
            || (le32(0) != 0
                && le32(12) != 0
                && le16(16) >= 12
                && le16(16) % 4 == 0
                && buf[18] == 2
                && buf[19] == 2
                && buf[20..22] == *b"..")
    };
    superblock || directory
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0x38, EXT_SB_MAGIC, Arc::new(ExtSignature));
    registry.register(0x4, EXT_DIR_MAGIC, Arc::new(ExtSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_header_match() {
        let sig = ExtSignature;
        // Superblock magic at 0x38.
        let mut buf = vec![0u8; 0x3a];
        buf[0x38..0x3a].copy_from_slice(EXT_SB_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
        // Directory magic at 0x04.
        let mut buf2 = vec![0u8; 0x0c];
        buf2[0x04..0x0c].copy_from_slice(EXT_DIR_MAGIC);
        assert!(sig.header_check(&buf2, 0).is_some());
    }

    #[test]
    fn test_ext_no_match() {
        let sig = ExtSignature;
        let buf = vec![0u8; 0x3a];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
