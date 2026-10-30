use crate::checks::join_carry;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Dahua DVR/NVR/camera export (`.dav`, "DHAV"): a run of frames, each a 24-byte header, a payload and
/// an 8-byte footer.
///
/// ```text
/// 0..4    "DHAV"
/// 4       frame type (0xF0, 0xF1, 0xFC, 0xFD seen)
/// 5..12   subtype, channel, frame number
/// 12..16  total frame length in bytes, header and footer included (little-endian)
/// 16..23  time, extension length
/// 23      checksum: the low byte of the sum of bytes 0..23
/// ...
/// end-8   "dhav", then the frame length again (little-endian)
/// ```
///
/// Read from two public files of different devices and years (FFmpeg's sample server, ticket 6144:
/// 2,042 and 25,778 frames, every header checksum, footer magic and repeated length holding) and from
/// the frame-header description in Rzayeva et al., *Information* 17(5):493 (2026, CC BY 4.0). No
/// FFmpeg code was read. A file is the chain of frames; it ends where the next block does not begin
/// a frame with a valid header. No footer of the file as a whole.
struct DadSignature;

/// A frame is at least its header and its footer.
const MIN_FRAME: u32 = 24 + 8;
/// No frame seen is over 100 KB; a frame's length field is refused above this.
const MAX_FRAME: u32 = 64 * 1024 * 1024;
/// `recovery.extra` once the frame walk found something it could not read.
const WALK_ABANDONED: u64 = u64::MAX;

/// What the bytes at the start of a frame say.
enum Parsed {
    /// Fewer than 24 bytes in view.
    Incomplete,
    /// Not the header of a frame: the chain ends here.
    NotAFrame,
    /// A frame of this many bytes. Its footer is checked only if the whole frame is in view.
    Whole(u64),
}

fn frame_at(rest: &[u8]) -> Parsed {
    let Some(h) = rest.get(..24) else {
        return Parsed::Incomplete;
    };
    if &h[..4] != b"DHAV" {
        return Parsed::NotAFrame;
    }
    let sum = h[..23].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    let len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]);
    if sum != h[23] || !(MIN_FRAME..=MAX_FRAME).contains(&len) {
        return Parsed::NotAFrame;
    }
    if let Some(frame) = rest.get(..len as usize) {
        let footer = &frame[len as usize - 8..];
        if &footer[..4] != b"dhav" || footer[4..] != len.to_le_bytes() {
            return Parsed::NotAFrame;
        }
    }
    Parsed::Whole(u64::from(len))
}

impl FileSignature for DadSignature {
    fn name(&self) -> &str {
        "DAD"
    }
    fn extensions(&self) -> &[&str] {
        &["dad"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        match frame_at(buf) {
            Parsed::Whole(len) => Some(RecoveryInit {
                min_filesize: len,
                extension: "dad".to_string(),
                calculated_file_size: None,
            }),
            // A header block shorter than a frame header is not shown a frame to judge.
            Parsed::Incomplete | Parsed::NotAFrame => None,
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        let block_start = recovery.file_size;
        let block_end = block_start + buf.len() as u64;
        let (data, carry_len) = join_carry(buf, recovery);
        let data_start = block_start - carry_len as u64;
        loop {
            let at = recovery.extra;
            if at == WALK_ABANDONED || at >= block_end {
                return DataCheckResult::Continue;
            }
            if at < data_start {
                recovery.extra = WALK_ABANDONED;
                return DataCheckResult::Continue;
            }
            let rest = &data[(at - data_start) as usize..];
            match frame_at(rest) {
                Parsed::Incomplete => {
                    recovery.extra_bytes = rest.to_vec();
                    return DataCheckResult::Continue;
                }
                // The first frame is the header block's own: a bad one is no file. Later, the chain
                // has simply ended.
                Parsed::NotAFrame if at == 0 => return DataCheckResult::Error,
                Parsed::NotAFrame => return DataCheckResult::Stop(at),
                Parsed::Whole(len) => recovery.extra = at + len,
            }
        }
    }

    /// A frame that starts right after a whole frame is the next frame of a chain, not a new file: its
    /// predecessor's footer ends exactly here and the predecessor's own header, one frame length back, is
    /// valid. Such a match inside a running carve does not end it. Two exports written back to back share
    /// that shape and are not told apart (a stated limit).
    fn header_confirmed_by_source(
        &self,
        source: &dyn crate::engine::CarvingDataSource,
        offset: u64,
    ) -> Option<bool> {
        let mut footer = [0u8; 8];
        let prev = offset.checked_sub(8)?;
        if source.read_at(prev, &mut footer).ok()? != 8 || &footer[..4] != b"dhav" {
            return None;
        }
        let len = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
        let start = offset.checked_sub(u64::from(len))?;
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return None;
        }
        let mut header = [0u8; 24];
        if source.read_at(start, &mut header).ok()? != 24 {
            return None;
        }
        let continues = matches!(frame_at(&header), Parsed::Whole(l) if l == u64::from(len));
        continues.then_some(false)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"DHAV", Arc::new(DadSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One frame of `len` bytes: a valid header (the checksum of bytes 0..23), `len - 32` payload bytes and a footer.
    fn frame(kind: u8, number: u32, len: u32) -> Vec<u8> {
        let mut f = vec![0u8; len as usize];
        f[..4].copy_from_slice(b"DHAV");
        f[4] = kind;
        f[8..12].copy_from_slice(&number.to_le_bytes());
        f[12..16].copy_from_slice(&len.to_le_bytes());
        f[22] = 8;
        f[23] = f[..23].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        for (i, b) in f[24..len as usize - 8].iter_mut().enumerate() {
            *b = (i * 7 + number as usize) as u8;
        }
        let end = len as usize;
        f[end - 8..end - 4].copy_from_slice(b"dhav");
        f[end - 4..].copy_from_slice(&len.to_le_bytes());
        f
    }

    fn chain() -> (Vec<u8>, u64) {
        let mut file = Vec::new();
        for (i, len) in [368u32, 368, 1700, 40, 900].into_iter().enumerate() {
            file.extend(frame(if i == 2 { 0xFC } else { 0xF0 }, i as u32, len));
        }
        let end = file.len() as u64;
        (file, end)
    }

    #[test]
    fn a_frame_header_with_its_checksum_matches() {
        let init = DadSignature.header_check(&frame(0xFD, 1, 100), 0).unwrap();
        assert_eq!(init.min_filesize, 100);
    }

    #[test]
    fn a_dhav_magic_that_is_not_a_frame_is_refused() {
        let mut bad_sum = frame(0xFD, 1, 100);
        bad_sum[23] ^= 1;
        assert!(DadSignature.header_check(&bad_sum, 0).is_none());
        // Wrong magic.
        let mut wrong = frame(0xFD, 1, 100);
        wrong[0] = b'X';
        assert!(DadSignature.header_check(&wrong, 0).is_none());
        // A length below header plus footer, and one past the cap.
        for len in [16u32, 31, MAX_FRAME + 1] {
            let mut f = frame(0xFD, 1, 100);
            f[12..16].copy_from_slice(&len.to_le_bytes());
            f[23] = f[..23].iter().fold(0u8, |a, b| a.wrapping_add(*b));
            assert!(DadSignature.header_check(&f, 0).is_none(), "{len}");
        }
        // A frame wholly in view whose footer is not the footer.
        let mut no_footer = frame(0xFD, 1, 100);
        no_footer[96] = 0;
        assert!(DadSignature.header_check(&no_footer, 0).is_none());
        let mut wrong_len = frame(0xFD, 1, 100);
        wrong_len[96] = 99;
        assert!(DadSignature.header_check(&wrong_len, 0).is_none());
        assert!(DadSignature.header_check(b"DHAV", 0).is_none());
    }

    fn walk(file: &[u8], block: usize) -> DataCheckResult {
        let sig = DadSignature;
        let init = sig.header_check(file, 0).expect("a DAD header");
        let mut recovery = FileRecovery::from_init(&init, 0);
        for (i, chunk) in file.chunks(block).enumerate() {
            recovery.file_size = (i * block) as u64;
            match sig.data_check(chunk, &mut recovery) {
                DataCheckResult::Continue => {}
                other => return other,
            }
        }
        DataCheckResult::Continue
    }

    /// The chain of frames, not the next magic, decides where the file ends, wherever the blocks split a
    /// header or a footer. Text that looks like a frame inside a payload does not end it.
    #[test]
    fn the_walk_stops_where_the_chain_of_frames_ends() {
        let (mut file, end) = chain();
        // A payload holding a frame-shaped run is skipped over with its frame.
        let lure = frame(0xFD, 99, 60);
        let at = 400;
        file[at..at + lure.len()].copy_from_slice(&lure);
        file.extend_from_slice(&[0xFF; 3000]);
        for block in [64usize, 100, 512, 4096] {
            assert_eq!(
                walk(&file, block),
                DataCheckResult::Stop(end),
                "block {block}"
            );
        }
    }

    /// A frame that begins a block inside a running carve is the next frame, not a new file: the carve is not cut at it.
    /// Block size 512 puts frame boundaries on block starts here (368 + 368 + 1700 ... is not a multiple of 512, so
    /// the frames are sized to land on one).
    #[test]
    fn a_frame_on_a_block_boundary_does_not_end_the_carve() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        let mut file = Vec::new();
        for (i, len) in [512u32, 512, 1024, 512, 700].into_iter().enumerate() {
            file.extend(frame(0xF0, i as u32, len));
        }
        let end = file.len() as u64;
        file.extend_from_slice(&[0x55; 4096]);
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        let src = crate::scan_tests::Mem(file);
        let files = CarvingEngine::new(Arc::new(registry)).scan(&src, src.size());
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!((files[0].offset, files[0].size), (0, end));
    }

    /// Through the engine: a DAD export ahead of unrelated bytes is carved to the end of its last frame.
    #[test]
    fn a_dad_export_is_carved_to_its_last_frame() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        let (mut file, end) = chain();
        file.extend_from_slice(&[0x55; 4096]);
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        let src = crate::scan_tests::Mem(file);
        let files = CarvingEngine::new(Arc::new(registry)).scan(&src, src.size());
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!((files[0].offset, files[0].size), (0, end));
    }

    /// Two real exports from different devices and years (`SEANCE_DAHUA_DAV_CORPUS`, FFmpeg's public sample server): each is carved as one
    /// file, to the byte where the chain of frames ends, which a separate walk fixed at 25,786,748 (of 25,788,416: 1,668 bytes of 0xFF
    /// follow the last frame) and 314,550,138 (the whole file). Skipped without the variable.
    #[test]
    fn two_real_dahua_exports_are_carved_to_the_end_of_their_frames() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        let Some(dir) = std::env::var_os("SEANCE_DAHUA_DAV_CORPUS") else {
            return;
        };
        struct File(std::fs::File, u64);
        impl CarvingDataSource for File {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                std::os::unix::fs::FileExt::read_at(&self.0, buf, offset)
            }
            fn size(&self) -> u64 {
                self.1
            }
        }
        let dir = std::path::Path::new(&dir);
        for (name, end) in [
            ("19.25.00-19.25.50[R].dav", 25_786_748u64),
            (
                "85aa0-amphi-salle-2_salle-2_main_20161105110831_20161105111959.dav",
                314_550_138,
            ),
        ] {
            let f = std::fs::File::open(dir.join(name)).unwrap();
            let len = f.metadata().unwrap().len();
            let mut registry = SignatureRegistry::new();
            register(&mut registry);
            let src = File(f, len);
            let files = CarvingEngine::new(Arc::new(registry)).scan(&src, len);
            assert_eq!(files.len(), 1, "{name}: {files:?}");
            assert_eq!((files[0].offset, files[0].size), (0, end), "{name}");
        }
    }
}
