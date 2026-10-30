//! ISO Base Media files — MP4, and everything else built on the same boxes.
//!
//! # Why one signature covers so many formats
//!
//! `ftyp` is not MP4's header. It is the header of the **ISO Base Media File
//! Format**, and a dozen formats are built on it: MP4, QuickTime, 3GP, Canon's
//! CR3 raw, and — the reason this matters most — **HEIC**, which has been the
//! default photo format on iPhones since iOS 11, and **AVIF**.
//!
//! The `ftyp` box says which one it is. Its first field after the type is the
//! **major brand**: four characters naming the specification the file follows.
//! Reading it costs four bytes and is the difference between a carved iPhone
//! photograph landing as `.heic` and landing as `.mp4`.
//!
//! That distinction is evidential rather than cosmetic. An examiner filtering
//! carved output for images, or opening the results in a viewer, finds neither
//! if every photograph on the device was written out as a video file.

use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// A major brand and the extension it means.
///
/// Brands are from ISO/IEC 14496-12 and 23008-12 and the registered-brand list.
/// Only unambiguous ones are listed; anything else falls back to `mp4`, which
/// is what every file got before this table existed and remains the safe answer
/// for an ISO Base Media file of unknown flavour.
const BRANDS: &[(&[u8; 4], &str)] = &[
    // HEIF still images and sequences (ISO/IEC 23008-12). `heic` and `heix` are
    // what an iPhone writes; the others are profile-specific variants.
    (b"heic", "heic"),
    (b"heix", "heic"),
    (b"heim", "heic"),
    (b"heis", "heic"),
    (b"hevc", "heic"),
    (b"hevx", "heic"),
    // Codec-agnostic HEIF. `mif1` is also used by AVIF, with `avif` among the
    // compatible brands — `brand_extension` checks for that first.
    (b"mif1", "heif"),
    (b"msf1", "heif"),
    // AV1 Image File Format.
    (b"avif", "avif"),
    (b"avis", "avif"),
    // Canon RAW v3. The brand carries a trailing space, as the format writes it.
    (b"crx ", "cr3"),
    // Apple. `qt  ` is QuickTime proper; the M4* brands are iTunes containers
    // that players and examiners alike treat as distinct from .mp4.
    (b"qt  ", "mov"),
    (b"M4A ", "m4a"),
    (b"M4B ", "m4b"),
    (b"M4P ", "m4p"),
    (b"M4V ", "m4v"),
    // 3GPP/3GPP2 mobile capture.
    (b"3gp4", "3gp"),
    (b"3gp5", "3gp"),
    (b"3gp6", "3gp"),
    (b"3gp7", "3gp"),
    (b"3g2a", "3g2"),
    (b"3g2b", "3g2"),
    (b"3g2c", "3g2"),
];

/// The extension a `ftyp` box's brands imply.
///
/// `buf` starts at the box. `None` when the major brand is not one this table
/// knows, which the caller reports as `mp4`.
fn brand_extension(buf: &[u8]) -> Option<&'static str> {
    let major = buf.get(8..12)?;

    // AVIF may declare `mif1` as its major brand and put `avif` in the
    // compatible-brand list. Checking the list first is what keeps those files
    // from being filed under an extension no tool associates with them.
    if (major == b"mif1" || major == b"msf1")
        && compatible_brands(buf).any(|b| b == *b"avif" || b == *b"avis")
    {
        return Some("avif");
    }

    BRANDS
        .iter()
        .find(|(brand, _)| major == brand.as_slice())
        .map(|(_, ext)| *ext)
}

/// The compatible brands listed in a `ftyp` box, after the major brand and
/// minor version.
fn compatible_brands(buf: &[u8]) -> impl Iterator<Item = [u8; 4]> + '_ {
    // The box's own declared size bounds the list. Reading to the end of the
    // buffer instead would walk into the following box and read its bytes as
    // brands.
    let declared = buf
        .get(..4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize)
        .unwrap_or(0);
    let end = declared.min(buf.len());
    buf.get(16..end)
        .unwrap_or(&[])
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| [c[0], c[1], c[2], c[3]])
}

/// Box types that occur at the top level of an ISO Base Media file.
///
/// # Why a list and not a character test
///
/// The first version of the walk accepted any four printable characters, on the
/// reasoning that whatever lies past a file would not read as a box type. It
/// does. Trailing bytes of `0x5A` spell `ZZZZ`, which is four alphanumeric
/// characters, so the walk read a 1.5 GB box size out of unallocated space and
/// carried straight on past the end of the photograph — caught only by driving
/// a whole carve through the engine rather than testing the callback alone.
///
/// Top-level boxes are a closed set in practice. Naming them is what makes the
/// end of the chain detectable, and an unlisted box simply ends the walk early,
/// which yields a short carve rather than a wrong one.
const TOP_LEVEL_BOXES: &[&[u8; 4]] = &[
    // ISO/IEC 14496-12 structural boxes.
    b"ftyp", b"styp", b"moov", b"moof", b"mfra", b"mdat", b"free", b"skip", b"wide", b"pnot",
    b"meta", b"uuid", b"pdin", b"bloc", b"sidx", b"ssix", b"prft", b"emsg", b"mere", b"strk",
    // HEIF still images.
    b"iloc", b"idat", b"iinf", b"iref", b"iprp",
    // Fragmented and streaming variants seen at top level.
    b"mfro", b"tfra", b"segm", // JPEG XL boxes, which share this container.
    b"jxlp", b"jxlc", b"jbrd", b"jumb",
];

/// Whether four bytes are a box type this walk will follow.
pub(super) fn plausible_box_type(t: &[u8]) -> bool {
    // QuickTime metadata atoms begin with 0xA9 and are real boxes, but they do
    // not appear at the top level, so they are not followed here.
    TOP_LEVEL_BOXES.iter().any(|known| t == known.as_slice())
}

/// The result of inspecting a (possibly partial) box header.
#[derive(Debug, PartialEq, Eq)]
enum BoxWalk {
    /// Not a box here: an implausible type, or a size below its own header.
    NotABox,
    /// A declared size of 0 means "to the end of the file"; it cannot advance a
    /// walk, so the caller lets the engine bound the extent.
    ToEndOfFile,
    /// The header is genuine but not fully present in `hdr` yet — a box header
    /// straddling a block boundary. The caller must resume on the next block
    /// rather than misread the truncated header as the end of the chain.
    NeedMoreBytes,
    /// A box of this many total bytes.
    Size(u64),
}

/// Measure a box from the bytes of `hdr`, which may be only a prefix of the
/// header (a header can straddle two engine blocks). A 32-bit size of 1 selects
/// the 64-bit extended size that follows, so up to 16 bytes are needed; fewer
/// yields [`BoxWalk::NeedMoreBytes`] rather than a false "not a box".
fn measure_box(hdr: &[u8]) -> BoxWalk {
    if hdr.len() < 8 {
        return BoxWalk::NeedMoreBytes;
    }
    if !plausible_box_type(&hdr[4..8]) {
        return BoxWalk::NotABox;
    }
    let short = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    match short {
        0 => BoxWalk::ToEndOfFile,
        // A size of 1 means the real, 64-bit size follows the 8-byte header.
        1 => {
            if hdr.len() < 16 {
                return BoxWalk::NeedMoreBytes;
            }
            let big = u64::from_be_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]);
            // Such a box must be at least as long as its own extended header.
            if big >= 16 {
                BoxWalk::Size(big)
            } else {
                BoxWalk::NotABox
            }
        }
        // Shorter than a header is not a box.
        s if s < 8 => BoxWalk::NotABox,
        s => BoxWalk::Size(s as u64),
    }
}

/// ISO Base Media detector: MP4, HEIC, AVIF, MOV, 3GP, CR3.
struct IsoBaseMediaSignature;

impl FileSignature for IsoBaseMediaSignature {
    fn name(&self) -> &str {
        "ISO Base Media"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "mp4", "m4a", "m4b", "m4p", "m4v", "mov", "heic", "heif", "avif", "cr3", "3gp", "3g2",
        ]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 || &buf[4..8] != b"ftyp" {
            return None;
        }
        let box_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        if box_size < 8 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: box_size,
            // The brand, not a guess. The module documentation records what
            // labelling all of these `mp4` costs an examiner.
            extension: brand_extension(buf).unwrap_or("mp4").to_string(),
            calculated_file_size: None,
        })
    }

    /// Walk the box chain to find where the file actually ends.
    ///
    /// # Why this is worth doing
    ///
    /// Without it this signature never stops: the engine runs the recovery to
    /// its 4 GiB ceiling, or until some other signature's header interrupts it,
    /// and emits whatever that covered. A 2 MiB photograph carved that way is
    /// the photograph followed by everything that happened to lie after it.
    ///
    /// An ISO Base Media file does not need guessing at. It is a chain of
    /// boxes, each declaring its own length, and the file ends where the chain
    /// does. `extra` carries the offset of the next box header across blocks.
    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !ftyp_plausible(buf) {
            return DataCheckResult::Error;
        }
        walk_box_chain(buf, recovery)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// Walk the top-level box chain one engine block at a time and stop where it
/// ends. Shared with the QuickTime signature for a file that opens with `moov`
/// rather than `ftyp`: both are the same chain of length-prefixed boxes.
///
/// `recovery.extra` carries the offset of the next box header across blocks, and
/// `recovery.extra_bytes` the leading bytes of a header that straddles a block
/// boundary.
pub(super) fn walk_box_chain(buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
    let block_start = recovery.file_size;

    // Resume a box header that straddled the previous block boundary: its
    // leading bytes were stashed in `extra_bytes` and `extra` holds the box's
    // absolute start. Complete the header from the head of this block so a
    // 64-bit (size-1) box split across blocks is measured, not misread as the
    // end of the chain (which would truncate the carve).
    let carry = std::mem::take(&mut recovery.extra_bytes);
    if !carry.is_empty() {
        let mut hdr = carry;
        let take = (16usize.saturating_sub(hdr.len())).min(buf.len());
        hdr.extend_from_slice(&buf[..take]);
        match measure_box(&hdr) {
            // Still short — only possible on a tiny final block. Keep waiting.
            BoxWalk::NeedMoreBytes => {
                recovery.extra_bytes = hdr;
                return DataCheckResult::Continue;
            }
            BoxWalk::NotABox => return DataCheckResult::Stop(recovery.extra),
            BoxWalk::ToEndOfFile => return DataCheckResult::Continue,
            BoxWalk::Size(size) => {
                recovery.extra = recovery.extra.saturating_add(size);
            }
        }
    }

    let mut next = recovery.extra;

    // `extra` starts at zero, which is also the offset of the first box, so
    // the walk begins correctly on the block holding the header. Were the
    // first call ever to arrive on a later block, the alignment would be
    // unknown and walking would be guesswork — so leave the extent to the
    // engine, exactly as it was before this walk existed. (A resolved carry
    // always leaves `next` at or past `block_start`, so it never trips here.)
    if next < block_start {
        return DataCheckResult::Continue;
    }

    loop {
        let in_block = (next - block_start) as usize;
        // The next boundary lies beyond this block; resume when it arrives.
        if in_block >= buf.len() {
            break;
        }
        match measure_box(&buf[in_block..]) {
            // Not a box: the chain ended at the previous boundary, and that
            // is where the file ends.
            BoxWalk::NotABox => {
                recovery.extra = next;
                return DataCheckResult::Stop(next);
            }
            // "To the end of the file" — the chain yields nothing further,
            // so let the engine bound the extent.
            BoxWalk::ToEndOfFile => return DataCheckResult::Continue,
            // This box's header straddles the end of the block. Stash the
            // bytes we have and resume on the next block instead of cutting
            // the carve at a header we simply have not fully read yet.
            BoxWalk::NeedMoreBytes => {
                recovery.extra = next;
                recovery.extra_bytes = buf[in_block..].to_vec();
                return DataCheckResult::Continue;
            }
            BoxWalk::Size(size) => next = next.saturating_add(size),
        }
    }

    recovery.extra = next;
    DataCheckResult::Continue
}

/// A `FileTypeBox` (ISO/IEC 14496-12 4.3) is its 8-byte header, a major brand,
/// a minor version and whole four-byte compatible brands, so its size is 16
/// plus a multiple of 4; no real one approaches 4 KiB. Brands are
/// four-character codes, printable ASCII; a compatible brand may also be
/// zero padding.
fn ftyp_plausible(buf: &[u8]) -> bool {
    if buf.len() < 16 {
        return true;
    }
    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let printable = |c: &[u8]| c.iter().all(|&b| (0x20..0x7F).contains(&b));
    (16..=4096).contains(&size)
        && size.is_multiple_of(4)
        && printable(&buf[8..12])
        && buf[16..size.min(buf.len())]
            .as_chunks::<4>()
            .0
            .iter()
            .all(|c| printable(c) || *c == [0, 0, 0, 0])
}

pub fn register(registry: &mut SignatureRegistry) {
    // The `ftyp` type sits at byte 4, after the box's own size.
    registry.register(4, b"ftyp", Arc::new(IsoBaseMediaSignature));
}

#[cfg(test)]
mod tests;
