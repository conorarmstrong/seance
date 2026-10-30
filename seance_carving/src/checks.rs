//! Structural checks shared by more than one signature's `data_check`.
//!
//! A loose magic (four bytes or fewer) matches inside other files' bodies at
//! block boundaries. Since CARVE-015 such a match ends a running carve only
//! when it survives its own `data_check` on the header block, so each loose
//! signature checks there what a genuine file of its format must carry. The
//! checks here are written from the formats' public specifications.

use crate::signature::FileRecovery;
use std::borrow::Cow;

/// Join the bytes carried over from the previous block onto `buf`, so a marker
/// that straddles the block boundary can be found. The carry lives in
/// `recovery.extra_bytes` and is taken (emptied) here; the caller puts the new
/// carry back with [`carry_tail`] when it finds nothing. Returns the joined
/// bytes and how many of them are carry: a position `p` in the joined bytes is
/// `p - carry_len` from the start of `buf`.
pub(crate) fn join_carry<'a>(buf: &'a [u8], recovery: &mut FileRecovery) -> (Cow<'a, [u8]>, usize) {
    let carry = std::mem::take(&mut recovery.extra_bytes);
    if carry.is_empty() {
        return (Cow::Borrowed(buf), 0);
    }
    let carry_len = carry.len();
    let mut joined = carry;
    joined.extend_from_slice(buf);
    (Cow::Owned(joined), carry_len)
}

/// Keep the last `keep` bytes of `data` as the carry for the next block.
pub(crate) fn carry_tail(data: &[u8], recovery: &mut FileRecovery, keep: usize) {
    recovery.extra_bytes = data[data.len().saturating_sub(keep)..].to_vec();
}

/// Find the first `footer` in the carved stream, across block boundaries.
///
/// `data_check` sees one engine block at a time, so a footer that begins in the
/// last bytes of one block and ends in the next is in neither. The last
/// `footer.len() - 1` bytes of every block are therefore carried in
/// `recovery.extra_bytes`. `skip` bytes at the head of `buf` are not searched
/// on the first block of the file (the header, which may hold the footer's
/// bytes). `recovery.file_size` is the file offset of the start of `buf`.
///
/// Returns the file offset just past the footer. A signature using this must
/// not use `extra_bytes` for anything else.
pub(crate) fn footer_end_spanning(
    buf: &[u8],
    recovery: &mut FileRecovery,
    footer: &[u8],
    skip: usize,
) -> Option<u64> {
    let (data, carry_len) = join_carry(buf, recovery);
    let from = if carry_len == 0 {
        skip.min(data.len())
    } else {
        0
    };
    match memchr::memmem::find(&data[from..], footer) {
        Some(rel) => {
            let end_in_data = (from + rel + footer.len()) as u64;
            Some(recovery.file_size + end_in_data - carry_len as u64)
        }
        None => {
            carry_tail(&data[from..], recovery, footer.len().saturating_sub(1));
            None
        }
    }
}

/// Whether the TIFF image file directory a TIFF-style header points at is
/// plausible on the header block (TIFF 6.0, section 2; also the layout of
/// JPEG XR's and Panasonic RW2's TIFF-like headers).
///
/// - The directory must start on a word boundary, after the 8-byte header.
/// - When its entry count lies inside the block, the count is not zero, and
///   every 12-byte entry fully inside the block has a field type the
///   specification defines (1–13, and BigTIFF's 16–18).
///
/// A directory beyond the block cannot be read from it and is accepted here;
/// `tiff_ifd_plausible_at` reads it from the source.
pub(crate) fn tiff_ifd_plausible(buf: &[u8], little_endian: bool) -> bool {
    if buf.len() < 8 {
        return true;
    }
    let u16_at = |o: usize| {
        let b = [buf[o], buf[o + 1]];
        if little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let b = [buf[4], buf[5], buf[6], buf[7]];
    let diroff = if little_endian {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    } as u64;
    if diroff < 8 || !diroff.is_multiple_of(2) {
        return false;
    }
    let diroff = diroff as usize;
    if diroff + 2 > buf.len() {
        return true;
    }
    let count = u16_at(diroff) as usize;
    if count == 0 {
        return false;
    }
    (0..count)
        .map(|i| diroff + 2 + i * 12)
        .take_while(|&entry| entry + 12 <= buf.len())
        .all(|entry| matches!(u16_at(entry + 2), 1..=13 | 16..=18))
}

/// At most this many directory entries are read from the source to judge a
/// TIFF directory: 3 KiB, enough to catch a stray magic's garbage without
/// reading a whole directory of a large file.
const TIFF_SOURCE_ENTRIES: usize = 256;

/// `tiff_ifd_plausible`, judged on the directory where it really lies: the
/// TIFF-style header at `offset` in `source` names a directory offset, and the
/// directory is read there, however far past the header block that is.
///
/// - `Some(false)` — the header's offset is malformed, or the directory was
///   read and has no entries, or an entry read in full has a field type the
///   specification does not define.
/// - `Some(true)` — the count and at least one entry were read, and every
///   entry read in full passes.
/// - `None` — the header, the directory's entry count, or every one of its
///   entries lies beyond the source, so the source cannot say.
pub(crate) fn tiff_ifd_plausible_at(
    source: &dyn crate::engine::CarvingDataSource,
    offset: u64,
    little_endian: bool,
) -> Option<bool> {
    let mut header = [0u8; 8];
    if crate::engine::read_full(source, offset, &mut header) < 8 {
        return None;
    }
    let b = [header[4], header[5], header[6], header[7]];
    let diroff = if little_endian {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    } as u64;
    if diroff < 8 || !diroff.is_multiple_of(2) {
        return Some(false);
    }
    let dir_at = offset.checked_add(diroff)?;
    let mut dir = vec![0u8; 2 + TIFF_SOURCE_ENTRIES * 12];
    let n = crate::engine::read_full(source, dir_at, &mut dir);
    if n < 2 {
        return None;
    }
    dir.truncate(n);
    let u16_at = |o: usize| {
        let b = [dir[o], dir[o + 1]];
        if little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let count = u16_at(0) as usize;
    if count == 0 {
        return Some(false);
    }
    let entries: Vec<usize> = (0..count.min(TIFF_SOURCE_ENTRIES))
        .map(|i| 2 + i * 12)
        .take_while(|&entry| entry + 12 <= dir.len())
        .collect();
    // No entry read in full: the directory was not looked at, so this is
    // unknown, not a confirmation.
    if entries.is_empty() {
        return None;
    }
    Some(
        entries
            .into_iter()
            .all(|entry| matches!(u16_at(entry + 2), 1..=13 | 16..=18)),
    )
}

/// XXH32 of `data` with `seed`, as the xxHash specification defines it. LZ4's
/// frame format checks its descriptor with the second byte of this hash.
pub(crate) fn xxh32(data: &[u8], seed: u32) -> u32 {
    const P1: u32 = 0x9E37_79B1;
    const P2: u32 = 0x85EB_CA77;
    const P3: u32 = 0xC2B2_AE3D;
    const P4: u32 = 0x27D4_EB2F;
    const P5: u32 = 0x1656_67B1;
    let round = |acc: u32, lane: u32| {
        acc.wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(13)
            .wrapping_mul(P1)
    };
    let word = |c: &[u8]| u32::from_le_bytes([c[0], c[1], c[2], c[3]]);

    let mut rest = data;
    let mut acc = if data.len() >= 16 {
        let mut v = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        while rest.len() >= 16 {
            for (i, lane) in v.iter_mut().enumerate() {
                *lane = round(*lane, word(&rest[i * 4..]));
            }
            rest = &rest[16..];
        }
        v[0].rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18))
    } else {
        seed.wrapping_add(P5)
    };
    acc = acc.wrapping_add(data.len() as u32);
    while rest.len() >= 4 {
        acc = acc
            .wrapping_add(word(rest).wrapping_mul(P3))
            .rotate_left(17)
            .wrapping_mul(P4);
        rest = &rest[4..];
    }
    for &b in rest {
        acc = acc
            .wrapping_add((b as u32).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    acc ^= acc >> 15;
    acc = acc.wrapping_mul(P2);
    acc ^= acc >> 13;
    acc = acc.wrapping_mul(P3);
    acc ^ (acc >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The xxHash reference values for the empty input and for "a".
    #[test]
    fn xxh32_matches_the_reference_vectors() {
        assert_eq!(xxh32(b"", 0), 0x02CC_5D05);
        assert_eq!(xxh32(b"a", 0), 0x550D_7456);
        assert_eq!(xxh32(b"abc", 0), 0x32D1_53FF);
        assert_eq!(
            xxh32(b"Nobody inspects the spammish repetition", 0),
            0xE229_3B2F
        );
    }

    struct Bytes(Vec<u8>);

    impl crate::engine::CarvingDataSource for Bytes {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let data = self.0.get(offset as usize..).unwrap_or(&[]);
            let n = buf.len().min(data.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// The directory is read where it lies: a good one passes, an empty one
    /// or one with an undefined field type is refused, and one whose entry
    /// count lies past the source is unknown, not refused.
    #[test]
    fn a_tiff_directory_is_judged_from_the_source_where_it_lies() {
        let mut data = vec![0x41u8; 8192];
        data[..8].copy_from_slice(&[0x49, 0x49, 0x2A, 0x00, 0x00, 0x10, 0, 0]);
        data[4096..4098].copy_from_slice(&[1, 0]);
        data[4098..4110].copy_from_slice(&[0x00, 0x01, 3, 0, 1, 0, 0, 0, 0x40, 0, 0, 0]);
        assert_eq!(
            tiff_ifd_plausible_at(&Bytes(data.clone()), 0, true),
            Some(true)
        );
        let mut bad = data.clone();
        bad[4100] = 0x77;
        assert_eq!(tiff_ifd_plausible_at(&Bytes(bad), 0, true), Some(false));
        let mut empty = data.clone();
        empty[4096] = 0;
        assert_eq!(tiff_ifd_plausible_at(&Bytes(empty), 0, true), Some(false));
        data.truncate(4097);
        assert_eq!(tiff_ifd_plausible_at(&Bytes(data), 0, true), None);
    }

    /// A directory whose count is read but none of whose entries is, because
    /// the source ends first, was not looked at: that is unknown, never
    /// confirmed.
    #[test]
    fn a_tiff_directory_with_no_entry_read_is_unknown_not_confirmed() {
        let mut data = vec![0x41u8; 4100];
        data[..8].copy_from_slice(&[0x49, 0x49, 0x2A, 0x00, 0x00, 0x10, 0, 0]);
        data[4096..4098].copy_from_slice(&[1, 0]);
        assert_eq!(tiff_ifd_plausible_at(&Bytes(data), 0, true), None);
    }

    #[test]
    fn a_tiff_directory_with_undefined_field_types_is_refused() {
        // "II*\0", IFD at 8, one entry: tag 0x0100, type 3 (SHORT), count 1.
        let mut good = vec![0x49, 0x49, 0x2A, 0x00, 8, 0, 0, 0, 1, 0];
        good.extend_from_slice(&[0x00, 0x01, 3, 0, 1, 0, 0, 0, 0x40, 0, 0, 0]);
        good.resize(512, 0);
        assert!(tiff_ifd_plausible(&good, true));
        let mut bad = good.clone();
        bad[12] = 0x77; // field type 0x77 is not defined
        assert!(!tiff_ifd_plausible(&bad, true));
        let mut odd = good.clone();
        odd[4] = 9; // a directory must start on a word boundary
        assert!(!tiff_ifd_plausible(&odd, true));
        let mut empty = good;
        empty[8] = 0; // a directory with no entries
        assert!(!tiff_ifd_plausible(&empty, true));
    }
}
