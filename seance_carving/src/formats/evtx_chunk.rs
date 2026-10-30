use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// A lone Windows Event Log chunk (`ElfChnk\0`), found without the `ElfFile`
/// header that would make it part of a whole `.evtx` file.
///
/// This is the rotated-log case: a chunk left in free space after its log was
/// rotated, cleared or deleted, or the tail of a log whose first cluster was
/// reused. Only the file header is the `EVTX` signature (`evtx.rs`), so such a
/// chunk was carved by nothing and never reached the EVTX module, whose
/// recovery pass reads a headerless chunk directly (`HUNT-163`).
///
/// Layout (EVTX chunk header): magic at 0, the four record numbers at 0x08 to
/// 0x27, `header_size` (always 128) at 0x28, `last_event_record_data_offset`
/// at 0x2C, `free_space_offset` at 0x30. The chunk is a fixed 65,536 bytes, so
/// the extent is known from the header alone; a chunk cut by the end of the
/// source is clamped by the engine and reported as not validated.
///
/// The magic alone is eight bytes and is refused unless `header_size` is 128
/// and `free_space_offset` lies between the end of the 512-byte header and
/// the end of the chunk. The checksums are NOT required to verify: a chunk
/// whose CRC fails is still evidence, and the EVTX recovery pass reports each
/// chunk's checksum states itself.
///
/// A chunk inside a whole `.evtx` carved by the `EVTX` signature overlaps that
/// carve and is dropped by the carver's overlap rule (largest match wins), so
/// the chunks of a whole log are not carved a second time.
struct EvtxChunkSignature;

const CHUNK_SIZE: u64 = 65_536;
const CHUNK_HEADER_SIZE: u32 = 512;

impl FileSignature for EvtxChunkSignature {
    fn name(&self) -> &str {
        "EVTX chunk (Windows event log)"
    }

    fn extensions(&self) -> &[&str] {
        &["elfchnk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x34 || &buf[0..8] != b"ElfChnk\x00" {
            return None;
        }
        let u32_at =
            |at: usize| u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        if u32_at(0x28) != 128 {
            return None;
        }
        let free_space_offset = u32_at(0x30);
        if !(CHUNK_HEADER_SIZE..=CHUNK_SIZE as u32).contains(&free_space_offset) {
            return None;
        }
        Some(RecoveryInit {
            // The header alone: fewer bytes than that and no record can be
            // located in it.
            min_filesize: CHUNK_HEADER_SIZE as u64,
            extension: "elfchnk".to_string(),
            calculated_file_size: Some(CHUNK_SIZE),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        CHUNK_SIZE
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"ElfChnk\x00", Arc::new(EvtxChunkSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(header_size: u32, free_space_offset: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..8].copy_from_slice(b"ElfChnk\x00");
        buf[0x28..0x2C].copy_from_slice(&header_size.to_le_bytes());
        buf[0x30..0x34].copy_from_slice(&free_space_offset.to_le_bytes());
        buf
    }

    #[test]
    fn a_chunk_header_declares_the_fixed_chunk_size() {
        let init = EvtxChunkSignature
            .header_check(&header(128, 30_264), 0)
            .unwrap();
        assert_eq!(init.calculated_file_size, Some(65_536));
        assert_eq!(init.extension, "elfchnk");
    }

    #[test]
    fn a_full_chunk_is_accepted() {
        assert!(EvtxChunkSignature
            .header_check(&header(128, 65_536), 0)
            .is_some());
    }

    #[test]
    fn a_wrong_header_size_or_free_space_offset_is_refused() {
        assert!(EvtxChunkSignature
            .header_check(&header(64, 30_264), 0)
            .is_none());
        assert!(EvtxChunkSignature
            .header_check(&header(128, 511), 0)
            .is_none());
        assert!(EvtxChunkSignature
            .header_check(&header(128, 65_537), 0)
            .is_none());
    }

    #[test]
    fn the_file_header_magic_is_not_a_chunk() {
        let mut buf = header(128, 30_264);
        buf[0..8].copy_from_slice(b"ElfFile\x00");
        assert!(EvtxChunkSignature.header_check(&buf, 0).is_none());
    }
}
