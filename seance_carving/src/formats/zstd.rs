//! Zstandard (`.zst`) — RFC 8878.
//!
//! # Why it is worth carving
//!
//! Zstandard has become the default compressor in places a case routinely
//! touches: btrfs and OverlayFS transparent compression, `.tar.zst` archives,
//! Arch and Fedora packages, ZFS datasets, and Linux kernel modules
//! (`.ko.zst`). A carver that knows gzip, bzip2 and xz but not zstd misses the
//! compressed data on a modern Linux or Android device.
//!
//! # What is and is not recoverable
//!
//! A frame declares no total length that a carver can use — `Frame_Content_Size`
//! is the size of the *decompressed* content, not of the frame on disk — and
//! frames end with an optional checksum rather than a terminator. So the extent
//! is bounded by the engine, and [`FileSignature::verify_footer`] makes no
//! claim: there is no footer to check, and inventing a verdict would be worse
//! than declining to give one.

use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// `Magic_Number` for a Zstandard frame: 0xFD2FB528, little-endian on disk.
const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];

/// Skippable frames use 0x184D2A50 through 0x184D2A5F, so the first three bytes
/// on disk are fixed and the fourth carries the low nibble.
const SKIPPABLE_PREFIX: &[u8] = &[0x50, 0x2A, 0x4D, 0x18];

struct ZstdSignature;

impl FileSignature for ZstdSignature {
    fn name(&self) -> &str {
        "Zstandard"
    }

    fn extensions(&self) -> &[&str] {
        &["zst"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 5 || &buf[..4] != ZSTD_MAGIC {
            return None;
        }
        // `Frame_Header_Descriptor` reserved bit (bit 3) must be zero. It costs
        // one comparison and removes half of everything that reaches here by
        // chance, which matters for a four-byte magic swept across a whole
        // image.
        if buf[4] & 0b0000_1000 != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 8,
            extension: "zst".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !frame_plausible(buf) {
            return DataCheckResult::Error;
        }
        // A frame carries no on-disk length and no terminator, so there is
        // nothing here to decide on. The engine bounds the extent and marks it
        // unvalidated, which is the honest description of what was recovered.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

/// A stream that opens with a skippable frame.
///
/// # Why this is not carved as a file of its own
///
/// A skippable frame is a component of a stream, not a file. `pzstd` — the
/// parallel zstd that most systems actually invoke — writes one holding the
/// block index ahead of the data frames, so an archive commonly *starts* with
/// one.
///
/// Carving it as a standalone file with its own exact length was measured to
/// produce a 16-byte artifact and to lose the compressed data behind it
/// entirely: the engine recorded the header-declared extent and resumed at the
/// next block boundary, past the data frame. One small wrong file in place of
/// the archive.
///
/// So the frame is treated as what it is — the beginning of a stream — and the
/// carve runs on through the frames that follow.
///
/// # An ambiguity worth stating
///
/// LZ4 uses the same magic range for its own skippable frames, both formats
/// being Yann Collet's. A stream opening with one of these cannot be told apart
/// from LZ4 by its first four bytes alone, so the extension is a best guess
/// until a data frame settles it.
struct ZstdSkippableSignature;

impl FileSignature for ZstdSkippableSignature {
    fn name(&self) -> &str {
        "Zstandard (skippable frame first)"
    }

    fn extensions(&self) -> &[&str] {
        &["zst"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        // Bytes 1..4 are fixed; byte 0 carries the low nibble.
        if buf[1..4] != SKIPPABLE_PREFIX[1..4] || !(0x50..=0x5F).contains(&buf[0]) {
            return None;
        }
        let payload = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        Some(RecoveryInit {
            // The frame is at least this long, and the stream continues past
            // it. Declaring the frame's length as the FILE's length is what
            // lost the archive.
            min_filesize: 8 + payload,
            extension: "zst".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !skippable_plausible(buf) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

/// A Zstandard frame (RFC 8878 3.1.1) is its header and then blocks. The
/// header's length follows from the descriptor byte: a window descriptor
/// unless `Single_Segment` is set, a 0-, 1-, 2- or 4-byte dictionary ID, and
/// a 0-, 1-, 2-, 4- or 8-byte content size. The first block header (3 bytes,
/// little-endian) after it has a defined type (not 3, "reserved") and a size
/// no larger than the 128 KiB block maximum, and a block that is not the last
/// is not empty.
fn frame_plausible(buf: &[u8]) -> bool {
    let Some(&fhd) = buf.get(4) else {
        return true;
    };
    let single_segment = fhd & 0b0010_0000 != 0;
    let fcs = match fhd >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let did = [0, 1, 2, 4][(fhd & 0b11) as usize];
    let at = 5 + usize::from(!single_segment) + did + fcs;
    let Some(b) = buf.get(at..at + 3) else {
        return true;
    };
    let header = u32::from_le_bytes([b[0], b[1], b[2], 0]);
    let last = header & 1 != 0;
    let block_type = (header >> 1) & 0b11;
    let size = header >> 3;
    block_type != 3 && size <= 128 * 1024 && (size > 0 || last)
}

/// A skippable frame is followed by another frame, Zstandard or skippable,
/// when the next one lies in this block.
fn skippable_plausible(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return true;
    }
    let payload = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    match buf.get(8 + payload..8 + payload + 4) {
        Some(next) => {
            next == ZSTD_MAGIC
                || (next[1..4] == SKIPPABLE_PREFIX[1..4] && (0x50..=0x5F).contains(&next[0]))
        }
        None => true,
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ZSTD_MAGIC, Arc::new(ZstdSignature));
    // Registered on the three fixed bytes; `header_check` confirms the nibble.
    registry.register(1, &SKIPPABLE_PREFIX[1..4], Arc::new(ZstdSkippableSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zstandard_frame_is_recognised() {
        let sig = ZstdSignature;
        let mut buf = ZSTD_MAGIC.to_vec();
        buf.push(0x00); // frame header descriptor, reserved bit clear
        buf.extend_from_slice(&[0u8; 16]);
        let init = sig.header_check(&buf, 0).expect("a real zstd frame");
        assert_eq!(init.extension, "zst");
    }

    /// The reserved bit is defined as zero. Checking it costs nothing and
    /// halves what a four-byte magic admits by chance across a whole image.
    #[test]
    fn a_frame_with_the_reserved_bit_set_is_refused() {
        let sig = ZstdSignature;
        let mut buf = ZSTD_MAGIC.to_vec();
        buf.push(0b0000_1000);
        buf.extend_from_slice(&[0u8; 16]);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn other_bytes_are_not_a_zstd_frame() {
        let sig = ZstdSignature;
        assert!(sig
            .header_check(&[0x28, 0xB5, 0x2F, 0xFE, 0x00], 0)
            .is_none());
        assert!(sig
            .header_check(&[0x1F, 0x8B, 0x08, 0x00, 0x00], 0)
            .is_none());
        // Truncated input is refused rather than read past.
        assert!(sig.header_check(ZSTD_MAGIC, 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }

    /// All sixteen magic values identify a skippable frame — and none of them
    /// ends the file. Declaring the frame's own length as the file's length
    /// carved a 16-byte artifact and lost the archive behind it.
    #[test]
    fn a_leading_skippable_frame_begins_a_stream_rather_than_ending_a_file() {
        let sig = ZstdSkippableSignature;
        for low in 0x50u8..=0x5F {
            let mut buf = vec![low, 0x2A, 0x4D, 0x18];
            buf.extend_from_slice(&64u32.to_le_bytes());
            buf.extend_from_slice(&[0u8; 64]);
            let init = sig
                .header_check(&buf, 0)
                .unwrap_or_else(|| panic!("{low:#x} is a valid skippable magic"));
            assert_eq!(
                init.calculated_file_size, None,
                "a skippable frame's length is not the archive's length"
            );
            assert_eq!(
                init.min_filesize,
                8 + 64,
                "the archive is at least as long as the frame that opens it"
            );
        }
        // One past the range is not a skippable frame.
        let mut past = vec![0x60, 0x2A, 0x4D, 0x18];
        past.extend_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&past, 0).is_none());
        assert!(sig.header_check(&[0x50, 0x2A, 0x4D], 0).is_none());
    }
}
