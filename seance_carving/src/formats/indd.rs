use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe InDesign document (INDD) carving signature. Header: 24-byte master-page GUID
/// {0x06,0x06,0xed,0xf5,...}
/// followed by the ASCII marker "DOCUMENT" at offset 0. The size is estimated
/// from the master page fFilePages field (fFilePages*4096). Only the primary
/// master page (at 0) is read: a file has a backup master page at 4096 too, and
/// PhotoRec uses whichever has the higher sequence number, but the engine hands
/// `header_check` one 512-byte block, which does not reach 4096. The size can
/// therefore differ from PhotoRec's where the backup page is the newer. PhotoRec's
/// file_check_indd also walks contiguous object markers on disk to extend the
/// size; that on-disk walk is not ported.
struct InddSignature;

/// Master-page GUID + "DOCUMENT" magic (24 bytes) at offset 0.
const INDD_MAGIC: [u8; 24] = [
    0x06, 0x06, 0xed, 0xf5, 0xd8, 0x1d, 0x46, 0xe5, 0xbd, 0x31, 0xef, 0xe7, 0xfe, 0x74, 0xb7, 0x1d,
    0x44, 0x4f, 0x43, 0x55, 0x4d, 0x45, 0x4e, 0x54,
];

/// Read (fObjectStreamEndian, fFilePages) from the master page starting at
/// `base`. Field offsets within InDesignMasterPage: endian at 24, fFilePages
/// (u32 LE) at 280.
fn read_master_page(buf: &[u8], base: usize) -> Option<(u8, u32)> {
    if base + 284 > buf.len() {
        return None;
    }
    let endian = buf[base + 24];
    let file_pages = u32::from_le_bytes(buf[base + 280..base + 284].try_into().unwrap());
    Some((endian, file_pages))
}

impl FileSignature for InddSignature {
    fn name(&self) -> &str {
        "INDD"
    }

    fn extensions(&self) -> &[&str] {
        &["indd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 || buf[0..24] != INDD_MAGIC {
            return None;
        }
        // The primary master page only (see the type's note on the backup).
        let (endian, file_pages) = read_master_page(buf, 0)?;
        if endian != 1 && endian != 2 {
            return None;
        }
        if file_pages == 0 {
            return None;
        }
        let size = file_pages as u64 * 4096;
        Some(RecoveryInit {
            min_filesize: 4096,
            extension: "indd".to_string(),
            calculated_file_size: Some(size),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &INDD_MAGIC, Arc::new(InddSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indd_header_match() {
        let sig = InddSignature;
        let mut buf = vec![0u8; 284];
        buf[0..24].copy_from_slice(&INDD_MAGIC);
        buf[24] = 2; // fObjectStreamEndian
        buf[280..284].copy_from_slice(&3u32.to_le_bytes()); // fFilePages = 3
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(3 * 4096));
    }

    #[test]
    fn test_indd_no_match() {
        let sig = InddSignature;
        // Correct magic but fFilePages == 0 and endian invalid.
        let mut buf = vec![0u8; 284];
        buf[0..24].copy_from_slice(&INDD_MAGIC);
        buf[24] = 0; // invalid endian
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let buf2 = vec![0u8; 284];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
