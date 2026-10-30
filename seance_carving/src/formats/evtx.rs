use crate::engine::CarvingDataSource;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Event Log (EVTX) file signature detector.
///
/// Header: `ElfFile\0` at offset 0 of a 4,096-byte file header block. The
/// header's own fields: `header_size` (128) as a u32 at 0x20, minor and major
/// version as u16s at 0x24 and 0x26, the header block size (4,096) as a u16
/// at 0x28 and the chunk count as a u16 at 0x2A. Each chunk is 65,536 bytes
/// and opens `ElfChnk\0`.
///
/// **The extent is the run of chunks, not the header's count** (CARVE-013).
/// The count is a claim that real logs contradict in both directions —
/// omerbenamram's `system.evtx` says 3 and holds 15, plaso's `System2.evtx`
/// says 96 and holds 3 — so the carve walks consecutive `ElfChnk\0` headers
/// from offset 4,096 and stops at the first 64 KiB block that does not open
/// with one (or that the source cannot supply). A log whose last chunk is cut
/// by the end of the source is clamped there by the engine and reported not
/// validated. Zeroed blocks a log preallocated past its last chunk are not
/// chunks and are not part of the carve. The header's count is not used; the
/// carve result has no field to carry it, so it is logged at debug level only.
struct EvtxSignature;

const HEADER_BLOCK: u64 = 4096;
const CHUNK_SIZE: u64 = 65_536;
const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";

impl FileSignature for EvtxSignature {
    fn name(&self) -> &str {
        "EVTX"
    }

    fn extensions(&self) -> &[&str] {
        &["evtx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x30 || &buf[0..8] != b"ElfFile\x00" {
            return None;
        }
        // Sized by `extent_from_source`, which walks the chunks.
        Some(RecoveryInit {
            min_filesize: HEADER_BLOCK,
            extension: "evtx".to_string(),
            calculated_file_size: None,
        })
    }

    fn extent_from_source(&self, source: &dyn CarvingDataSource, offset: u64) -> Option<u64> {
        let mut header = [0u8; 0x2C];
        let header_count = if read_exact_at(source, offset, &mut header) {
            Some(u16::from_le_bytes([header[0x2A], header[0x2B]]))
        } else {
            None
        };
        let max_chunks = (self.max_file_size() - HEADER_BLOCK) / CHUNK_SIZE;
        let mut chunks = 0u64;
        let mut magic = [0u8; 8];
        while chunks < max_chunks
            && read_exact_at(
                source,
                offset + HEADER_BLOCK + chunks * CHUNK_SIZE,
                &mut magic,
            )
            && &magic == CHUNK_MAGIC
        {
            chunks += 1;
        }
        tracing::debug!(
            "EVTX at offset {offset}: header chunk count {header_count:?}, {chunks} consecutive chunks walked"
        );
        Some(HEADER_BLOCK + chunks * CHUNK_SIZE)
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// Fill `buf` from `offset`, looping over short reads; false if the source
/// cannot supply every byte.
fn read_exact_at(source: &dyn CarvingDataSource, offset: u64, buf: &mut [u8]) -> bool {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => filled += n,
        }
    }
    true
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"ElfFile\x00", Arc::new(EvtxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);

    impl CarvingDataSource for Mem {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    fn log(header_count: u16, chunks: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0..8].copy_from_slice(b"ElfFile\x00");
        buf[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
        buf[0x2A..0x2C].copy_from_slice(&header_count.to_le_bytes());
        for _ in 0..chunks {
            let mut chunk = vec![0u8; 65_536];
            chunk[..8].copy_from_slice(CHUNK_MAGIC);
            buf.extend_from_slice(&chunk);
        }
        buf
    }

    #[test]
    fn the_header_matches_and_leaves_the_size_to_the_walk() {
        let init = EvtxSignature.header_check(&log(10, 0), 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
        assert_eq!(init.min_filesize, 4096);
    }

    #[test]
    fn the_extent_is_the_run_of_chunks_whatever_the_header_count_says() {
        for (count, chunks) in [(3u16, 5usize), (96, 2), (1, 1), (0, 0)] {
            let mut data = log(count, chunks);
            data.extend_from_slice(&[0x5A; 65_536]);
            assert_eq!(
                EvtxSignature.extent_from_source(&Mem(data), 0),
                Some(4096 + chunks as u64 * 65_536),
                "count {count} over {chunks} chunks"
            );
        }
    }

    #[test]
    fn a_chunk_cut_by_the_end_of_the_source_is_counted_for_the_engine_to_clamp() {
        let mut data = log(3, 2);
        data.truncate(4096 + 65_536 + 100);
        assert_eq!(
            EvtxSignature.extent_from_source(&Mem(data), 0),
            Some(4096 + 2 * 65_536)
        );
    }

    #[test]
    fn test_evtx_no_match() {
        let sig = EvtxSignature;
        let buf = vec![0u8; 0x30];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
