//! Parse a Linux `md` (software RAID) v1.x superblock to auto-detect geometry.
//!
//! An examiner should not have to guess a RAID's chunk size and disk count when
//! Linux wrote them into a superblock on every member. This parser reads the
//! fields the reconstructor needs — level, layout, chunk size, disk count — from
//! a v1 superblock (`mdp_superblock_1`, the format `md` has used since ~2004).
//!
//! The superblock lives at one of three places depending on sub-version (end of
//! device for 1.0, start for 1.1, 4 KiB in for 1.2). This parses the superblock
//! *bytes* once located; [`find_superblock`] does the locating for the common
//! 1.1/1.2 cases.

use crate::raid::RaidLevel;

/// The `md` superblock magic, little-endian.
const MD_MAGIC: u32 = 0xa92b4efc;

/// The md layout code for **left-symmetric** RAID 5/6 placement — the only
/// stripe mapping [`crate::raid::RaidDevice`] implements. Any other code
/// describes a different placement, so an array recording one cannot be
/// auto-assembled by this crate without serving wrong bytes.
pub const LAYOUT_LEFT_SYMMETRIC: u32 = 2;

/// Geometry recovered from a superblock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdGeometry {
    pub level: RaidLevel,
    /// Raw md layout code (left-symmetric is 2); carried for the record.
    pub layout: u32,
    /// Chunk size in bytes.
    pub chunk_bytes: u64,
    /// Number of member disks in the array.
    pub raid_disks: u32,
    /// Usable data size per component device, in bytes.
    pub member_size: u64,
    /// Byte offset of the array's data plane within this member image
    /// (`data_offset`, recorded in 512-byte sectors). `md` v1.1/v1.2 writes the
    /// superblock — and any write-intent bitmap — at the head of the member and
    /// starts array data this far in; mdadm's default is 1 MiB. A reconstruction
    /// that addresses members from byte 0 would therefore serve superblock and
    /// bitmap bytes as array data. Zero for v1.0 (superblock at the end).
    pub data_offset: u64,
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn le64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Offset of the `sb_csum` field in `mdp_superblock_1`.
const SB_CSUM_OFF: usize = 216;
/// Offset of the `max_dev` field (count of `dev_roles` entries that follow).
const MAX_DEV_OFF: usize = 220;
/// Bytes of the fixed superblock before the variable `dev_roles` array.
const SB_FIXED_LEN: usize = 256;
/// A cap on `max_dev` (an untrusted count). This is md's own real ceiling: the
/// `dev_roles` array must fit inside a 4 KiB superblock, so `256 + max_dev*2 <=
/// 4096`, i.e. `max_dev <= 1920` (and mdadm limits arrays to 1920 devices). At
/// this cap the checksum span is exactly 4096 bytes, which fits the head/tail
/// windows the callers read, so no genuine superblock is rejected for lack of
/// bytes. A value above it is not a real v1 superblock.
const MAX_DEV_CAP: u32 = 1920;

/// The checksum Linux `md` itself computes over a v1 superblock
/// (`calc_sb_1_csum`): the 32-bit words of the first `256 + max_dev*2` bytes,
/// with the `sb_csum` field treated as zero, folded 64→32. Validating it is what
/// tells a genuine superblock from a coincidental magic in carved/nested data.
pub fn calc_sb_csum(sb: &[u8]) -> u32 {
    let max_dev = le32(sb, MAX_DEV_OFF).unwrap_or(0) as usize;
    let size = (SB_FIXED_LEN + max_dev * 2).min(sb.len());
    let mut newcsum: u64 = 0;
    let mut i = 0;
    while i + 4 <= size {
        let w = if i == SB_CSUM_OFF {
            0
        } else {
            le32(sb, i).unwrap_or(0)
        };
        newcsum += w as u64;
        i += 4;
    }
    if size - i == 2 {
        newcsum += u16::from_le_bytes([sb[i], sb[i + 1]]) as u64;
    }
    ((newcsum & 0xffff_ffff) + (newcsum >> 32)) as u32
}

/// Parse an `md` v1 superblock from its bytes. Returns `None` if the magic is
/// wrong, the version is not 1, or the RAID level is one this crate does not
/// reconstruct.
pub fn parse_superblock(sb: &[u8]) -> Option<MdGeometry> {
    if le32(sb, 0)? != MD_MAGIC {
        return None;
    }
    if le32(sb, 4)? != 1 {
        return None; // only v1.x
    }
    // Validate the superblock checksum md itself computes, before trusting any
    // geometry. Magic + version alone match ~1-in-4-billion random data, but a
    // carved image, a nested member, or a stale/corrupt superblock can still
    // present them; the checksum is what md relies on and what stops a confident
    // record with fabricated geometry. If `max_dev` implies more bytes than we
    // were given (or is implausibly large), the superblock cannot be validated —
    // refuse rather than trust a partial computation.
    let max_dev = le32(sb, MAX_DEV_OFF)?;
    let needed = SB_FIXED_LEN.checked_add((max_dev as usize).checked_mul(2)?)?;
    if max_dev > MAX_DEV_CAP || needed > sb.len() {
        return None;
    }
    if le32(sb, SB_CSUM_OFF)? != calc_sb_csum(sb) {
        return None;
    }
    // Field offsets from md_p.h `mdp_superblock_1`.
    let level = le32(sb, 72)? as i32;
    let layout = le32(sb, 76)?;
    let size_sectors = le64(sb, 80)?; // component data size, in 512-byte sectors
    let chunk_sectors = le32(sb, 88)?;
    let raid_disks = le32(sb, 92)?;
    let data_offset_sectors = le64(sb, 128)?; // start of this member's data plane

    let level = match level {
        0 => RaidLevel::Raid0,
        1 => RaidLevel::Raid1,
        5 => RaidLevel::Raid5,
        6 => RaidLevel::Raid6,
        _ => return None,
    };
    // The sector counts are untrusted; converting to bytes must not overflow
    // (which panics in debug and wraps to a wrong size in release). A field that
    // does not fit is a malformed superblock, not a usable geometry.
    let member_size = size_sectors.checked_mul(512)?;
    let chunk_bytes = (chunk_sectors as u64).checked_mul(512)?;
    let data_offset = data_offset_sectors.checked_mul(512)?;
    // RAID 1 records chunksize 0; that is fine (unused).
    Some(MdGeometry {
        level,
        layout,
        chunk_bytes,
        raid_disks,
        member_size,
        data_offset,
    })
}

/// Locate and parse a v1.1 (offset 0) or v1.2 (offset 4096) superblock in the
/// leading bytes of a member image. Returns the geometry and where it was found.
///
/// Only the two *head* positions are searched here — v1.2 (4 KiB in) is `mdadm`'s
/// default and v1.1 sits at offset 0. A v1.0 superblock lives at the **end** of
/// the device: use [`v10_superblock_offset`] to locate it and [`parse_superblock`]
/// to read it (see [`crate::detect_raid_member`], which checks both). A legacy
/// v0.90 superblock (also end-of-device, a different on-disk format) is still not
/// parsed; an unlocated superblock returns `None` and the examiner supplies the
/// geometry to [`crate::raid::RaidDevice::new`] explicitly.
pub fn find_superblock(member_head: &[u8]) -> Option<(MdGeometry, usize)> {
    for &loc in &[0usize, 4096] {
        if let Some(sb) = member_head.get(loc..) {
            if let Some(g) = parse_superblock(sb) {
                return Some((g, loc));
            }
        }
    }
    None
}

/// Byte offset of a v1.0 superblock, which `md` writes near the **end** of the
/// device. Mirrors mdadm's placement: `((size_in_sectors - 16) & ~7) * 512`.
/// Returns `None` for a device too small to carry one. The caller reads from this
/// offset and hands the bytes to [`parse_superblock`], whose checksum check
/// rejects a false hit if the offset does not land on a real superblock.
pub fn v10_superblock_offset(dev_size_bytes: u64) -> Option<u64> {
    let sectors = dev_size_bytes / 512;
    if sectors < 24 {
        return None;
    }
    Some(((sectors - 16) & !7) * 512)
}

/// Build a minimal but checksum-valid v1 superblock with the given fields, for
/// tests and synthetic fixtures. Exposed to other crates via the `test-support`
/// feature so the RAID and partition test suites share one builder rather than
/// each re-deriving the field layout and checksum.
#[cfg(any(test, feature = "test-support"))]
pub fn build_superblock(
    level: i32,
    layout: u32,
    chunk_sectors: u32,
    disks: u32,
    size_sectors: u64,
) -> Vec<u8> {
    build_superblock_with_data_offset(level, layout, chunk_sectors, disks, size_sectors, 0)
}

/// As [`build_superblock`], but also setting `data_offset` (in 512-byte sectors)
/// — the field a real mdadm v1.1/v1.2 member carries and that assembly must
/// apply before reading the data plane.
#[cfg(any(test, feature = "test-support"))]
pub fn build_superblock_with_data_offset(
    level: i32,
    layout: u32,
    chunk_sectors: u32,
    disks: u32,
    size_sectors: u64,
    data_offset_sectors: u64,
) -> Vec<u8> {
    let mut sb = vec![0u8; SB_FIXED_LEN];
    sb[0..4].copy_from_slice(&MD_MAGIC.to_le_bytes());
    sb[4..8].copy_from_slice(&1u32.to_le_bytes()); // major version 1
    sb[72..76].copy_from_slice(&(level as u32).to_le_bytes());
    sb[76..80].copy_from_slice(&layout.to_le_bytes());
    sb[80..88].copy_from_slice(&size_sectors.to_le_bytes());
    sb[88..92].copy_from_slice(&chunk_sectors.to_le_bytes());
    sb[92..96].copy_from_slice(&disks.to_le_bytes());
    sb[128..136].copy_from_slice(&data_offset_sectors.to_le_bytes());
    // max_dev = 0, so the checksum spans the 256-byte fixed block. Compute and
    // store it, as md does, so parse_superblock's validation accepts it.
    let csum = calc_sb_csum(&sb);
    sb[SB_CSUM_OFF..SB_CSUM_OFF + 4].copy_from_slice(&csum.to_le_bytes());
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but valid v1 superblock with the given fields.
    fn make_sb(
        level: i32,
        layout: u32,
        chunk_sectors: u32,
        disks: u32,
        size_sectors: u64,
    ) -> Vec<u8> {
        build_superblock(level, layout, chunk_sectors, disks, size_sectors)
    }

    #[test]
    fn parses_a_raid5_left_symmetric_superblock() {
        // level 5, layout 2 (left-symmetric), 128 KiB chunk (256 sectors), 4 disks.
        let sb = make_sb(5, 2, 256, 4, 2_000_000);
        let g = parse_superblock(&sb).unwrap();
        assert_eq!(g.level, RaidLevel::Raid5);
        assert_eq!(g.layout, 2);
        assert_eq!(g.chunk_bytes, 128 * 1024);
        assert_eq!(g.raid_disks, 4);
        assert_eq!(g.member_size, 2_000_000 * 512);
    }

    #[test]
    fn parses_raid0_and_raid6() {
        assert_eq!(
            parse_superblock(&make_sb(0, 0, 128, 2, 100)).unwrap().level,
            RaidLevel::Raid0
        );
        assert_eq!(
            parse_superblock(&make_sb(6, 2, 128, 5, 100)).unwrap().level,
            RaidLevel::Raid6
        );
    }

    #[test]
    fn rejects_bad_magic_and_wrong_version() {
        let mut sb = make_sb(5, 2, 256, 4, 100);
        sb[0] ^= 0xff;
        assert!(parse_superblock(&sb).is_none());

        let mut sb = make_sb(5, 2, 256, 4, 100);
        sb[4..8].copy_from_slice(&0u32.to_le_bytes()); // version 0
        assert!(parse_superblock(&sb).is_none());
    }

    #[test]
    fn rejects_a_superblock_whose_checksum_does_not_match() {
        // A coincidental magic + version (carved image, nested member) or a
        // corrupt superblock must be refused: md validates the checksum, so do we.
        let mut sb = make_sb(5, 2, 256, 4, 2_000_000);
        // Corrupt a geometry byte AFTER the checksum was computed → csum mismatch.
        sb[92] ^= 0x01; // flip a raid_disks bit
        assert!(
            parse_superblock(&sb).is_none(),
            "a superblock whose checksum no longer matches must be rejected"
        );
        // Magic + version present but everything else zero (no valid csum) is not
        // a superblock either.
        let mut bogus = vec![0u8; 256];
        bogus[0..4].copy_from_slice(&MD_MAGIC.to_le_bytes());
        bogus[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_superblock(&bogus).is_none());
    }

    #[test]
    fn refuses_when_max_dev_exceeds_the_available_bytes() {
        // An untrusted max_dev that implies more bytes than provided cannot be
        // checksum-validated; refuse rather than trust a partial computation.
        let mut sb = make_sb(5, 2, 256, 4, 100);
        sb[MAX_DEV_OFF..MAX_DEV_OFF + 4].copy_from_slice(&100_000u32.to_le_bytes());
        assert!(parse_superblock(&sb).is_none());
    }

    #[test]
    fn accepts_max_dev_at_the_cap_and_rejects_above_it() {
        // md's real ceiling: a 1920-device array's checksum spans exactly
        // 256 + 1920*2 = 4096 bytes. Given that many bytes it must validate; one
        // device more overflows a 4 KiB superblock and is not a real md sb.
        let mut sb = vec![0u8; 256 + 1920 * 2];
        sb[0..4].copy_from_slice(&MD_MAGIC.to_le_bytes());
        sb[4..8].copy_from_slice(&1u32.to_le_bytes());
        sb[72..76].copy_from_slice(&5i32.to_le_bytes());
        sb[80..88].copy_from_slice(&100u64.to_le_bytes());
        sb[88..92].copy_from_slice(&256u32.to_le_bytes());
        sb[92..96].copy_from_slice(&4u32.to_le_bytes());
        sb[MAX_DEV_OFF..MAX_DEV_OFF + 4].copy_from_slice(&1920u32.to_le_bytes());
        let csum = calc_sb_csum(&sb);
        sb[SB_CSUM_OFF..SB_CSUM_OFF + 4].copy_from_slice(&csum.to_le_bytes());
        assert!(
            parse_superblock(&sb).is_some(),
            "a 1920-device superblock with its full checksum span must validate"
        );

        // max_dev = 1921 is above md's ceiling; refuse before trusting geometry.
        let mut over = sb.clone();
        over.extend_from_slice(&[0u8, 0]); // room for one more dev_role
        over[MAX_DEV_OFF..MAX_DEV_OFF + 4].copy_from_slice(&1921u32.to_le_bytes());
        assert!(
            parse_superblock(&over).is_none(),
            "max_dev above md's 1920 ceiling must be rejected"
        );
    }

    #[test]
    fn v10_offset_matches_mdadm_placement() {
        // ((sectors - 16) & ~7) * 512. A 1 MiB device = 2048 sectors →
        // (2032 & ~7) = 2032 → 2032*512.
        assert_eq!(v10_superblock_offset(1024 * 1024), Some(2032 * 512));
        // Too small for a superblock.
        assert_eq!(v10_superblock_offset(4096), None);
    }

    #[test]
    fn rejects_unsupported_level() {
        // level 10 (RAID 10) is not reconstructed by this crate.
        assert!(parse_superblock(&make_sb(10, 0, 128, 4, 100)).is_none());
    }

    #[test]
    fn negative_levels_are_rejected_not_misread() {
        // `level` is a *signed* __le32 in md_p.h: -1 is linear, -4 multipath.
        // Reading it unsigned would turn -1 into 4294967295 and could match a
        // bogus arm; it must decode as i32 and fall through to "unsupported".
        for level in [-1i32, -4] {
            let mut sb = make_sb(0, 0, 128, 2, 100);
            sb[72..76].copy_from_slice(&level.to_le_bytes());
            assert!(
                parse_superblock(&sb).is_none(),
                "level {level} must be rejected, not misread"
            );
        }
    }

    #[test]
    fn field_offsets_match_md_p_h() {
        // Pin every field to its md_p.h offset independently of `make_sb`, so a
        // typo in either the parser or the fixture is caught. A real mdadm
        // superblock places these fields at exactly these byte offsets.
        let mut sb = vec![0u8; 256];
        sb[0..4].copy_from_slice(&MD_MAGIC.to_le_bytes()); // magic @0
        sb[4..8].copy_from_slice(&1u32.to_le_bytes()); // major_version @4
        sb[72..76].copy_from_slice(&5i32.to_le_bytes()); // level @72
        sb[76..80].copy_from_slice(&2u32.to_le_bytes()); // layout @76
        sb[80..88].copy_from_slice(&123_456u64.to_le_bytes()); // size (sectors) @80
        sb[88..92].copy_from_slice(&256u32.to_le_bytes()); // chunksize (sectors) @88
        sb[92..96].copy_from_slice(&7u32.to_le_bytes()); // raid_disks @92
        let csum = calc_sb_csum(&sb); // sb_csum @216, over the 256-byte block
        sb[SB_CSUM_OFF..SB_CSUM_OFF + 4].copy_from_slice(&csum.to_le_bytes());
        let g = parse_superblock(&sb).unwrap();
        assert_eq!(g.level, RaidLevel::Raid5);
        assert_eq!(g.layout, 2);
        assert_eq!(g.member_size, 123_456 * 512);
        assert_eq!(g.chunk_bytes, 256 * 512);
        assert_eq!(g.raid_disks, 7);
    }

    /// `data_offset` says where the array's data plane starts inside the member.
    /// It must be read from byte 128 of `mdp_superblock_1` and converted from
    /// sectors, or every reconstructed byte comes from the wrong place. 2048
    /// sectors (1 MiB) is mdadm's v1.2 default.
    #[test]
    fn data_offset_is_parsed_from_byte_128_as_sectors() {
        let mut sb = vec![0u8; 256];
        sb[0..4].copy_from_slice(&MD_MAGIC.to_le_bytes()); // magic @0
        sb[4..8].copy_from_slice(&1u32.to_le_bytes()); // major_version @4
        sb[72..76].copy_from_slice(&5i32.to_le_bytes()); // level @72
        sb[76..80].copy_from_slice(&2u32.to_le_bytes()); // layout @76
        sb[80..88].copy_from_slice(&129_024u64.to_le_bytes()); // size @80
        sb[88..92].copy_from_slice(&1024u32.to_le_bytes()); // chunksize @88
        sb[92..96].copy_from_slice(&3u32.to_le_bytes()); // raid_disks @92
        sb[128..136].copy_from_slice(&2048u64.to_le_bytes()); // data_offset @128
        let csum = calc_sb_csum(&sb);
        sb[SB_CSUM_OFF..SB_CSUM_OFF + 4].copy_from_slice(&csum.to_le_bytes());
        let g = parse_superblock(&sb).unwrap();
        assert_eq!(
            g.data_offset,
            2048 * 512,
            "data_offset is a sector count at byte 128, converted to bytes"
        );
    }

    #[test]
    fn an_overflowing_data_offset_is_rejected_not_wrapped() {
        // Same reasoning as the size field: a hostile sector count that cannot be
        // expressed in bytes is a malformed superblock, not a usable geometry.
        let sb = build_superblock_with_data_offset(5, 2, 256, 4, 100, u64::MAX / 2);
        assert!(
            parse_superblock(&sb).is_none(),
            "data_offset overflow must be refused"
        );
    }

    #[test]
    fn finds_superblock_at_v1_2_offset() {
        let mut head = vec![0u8; 8192];
        let sb = make_sb(5, 2, 256, 4, 100);
        head[4096..4096 + sb.len()].copy_from_slice(&sb);
        let (g, loc) = find_superblock(&head).unwrap();
        assert_eq!(loc, 4096);
        assert_eq!(g.level, RaidLevel::Raid5);
    }

    #[test]
    fn returns_none_when_no_superblock_present() {
        assert!(find_superblock(&vec![0u8; 8192]).is_none());
    }

    #[test]
    fn an_overflowing_size_field_is_rejected_not_wrapped() {
        // size_sectors is a u64; near u64::MAX it would overflow `* 512`, so the
        // parser must reject the superblock rather than panic (debug) or wrap
        // (release) to a tiny/wrong member_size.
        let sb = make_sb(5, 2, 256, 4, u64::MAX / 2);
        assert!(
            parse_superblock(&sb).is_none(),
            "size overflow must be refused"
        );
    }
}
