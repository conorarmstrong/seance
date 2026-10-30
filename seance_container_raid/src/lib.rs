#![forbid(unsafe_code)]
//! Reconstruct a single logical block device from RAID/JBOD members or an LVM
//! logical volume, and present it as one [`seance_core::data_source::DataSource`]
//! so every downstream filesystem, carver and parser works unchanged.
//!
//! This closes the "no RAID/LVM reconstruction" gap from
//! `documentation/COMPARISON.md`: material seized from a server or NAS arrives as
//! a set of member images, and until now Séance could only look at one volume.
//!
//! - [`raid`] — RAID 0/1/5/6 + JBOD geometry, with single-member parity rebuild.
//! - [`md`] — auto-detect geometry from a Linux `md` v1 superblock.
//! - [`lvm`] — parse LVM2 metadata and map a logical volume onto its PV.
//!
//! The two auto-detectors mean an examiner usually does not specify geometry by
//! hand; when the array is foreign/proprietary and carries no superblock, the
//! [`raid::RaidDevice`] constructor takes the geometry explicitly.

pub mod gf;
pub mod lvm;
pub mod md;
pub mod raid;

pub use lvm::{parse_metadata, LvmVg};
pub use md::{find_superblock, parse_superblock, MdGeometry};
pub use raid::{RaidDevice, RaidLevel};

use seance_core::data_source::{DataSource, WindowSource};
use std::io;
use std::sync::Arc;

/// A member disk for [`assemble`], present or missing (a `None` marks a dead disk
/// whose data the parity levels reconstruct).
pub type AssemblyMember = Option<Arc<dyn DataSource>>;

/// How [`assemble`] determined the geometry, for the audit trail.
#[derive(Debug, Clone)]
pub struct AssemblyReport {
    /// The level used.
    pub level: RaidLevel,
    /// Stripe/chunk size in bytes (0 for RAID 1 / JBOD).
    pub chunk: u64,
    /// Per-member usable size in bytes.
    pub member_size: u64,
    /// Byte offset of the array's data plane within each member image, as the
    /// superblock recorded it (0 when no superblock was found, or for v1.0).
    pub data_offset: u64,
    /// True when the geometry came from a Linux `md` superblock rather than the
    /// examiner's explicit flags.
    pub auto_detected: bool,
}

/// Read up to `n` leading bytes of a source, tolerating short reads.
fn read_head(src: &dyn DataSource, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match src.read_at(got as u64, &mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(_) => break,
        }
    }
    buf.truncate(got);
    buf
}

/// Read up to `n` bytes of a source starting at `offset`, tolerating short reads.
fn read_at(src: &dyn DataSource, offset: u64, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match src.read_at(offset + got as u64, &mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(_) => break,
        }
    }
    buf.truncate(got);
    buf
}

/// Detect a member's md geometry from any superblock position: the head (v1.1 at
/// offset 0, v1.2 at 4 KiB) or the v1.0 superblock near the end of the device.
/// The v1.0 case is what [`detect_raid_member`] advertises but head-only search
/// would miss, so both paths are tried here.
fn detect_geometry(m: &dyn DataSource) -> Option<MdGeometry> {
    let head = read_head(m, 8192);
    if let Some((g, _)) = md::find_superblock(&head) {
        return Some(g);
    }
    // v1.0 lives at the end of the device; locate it and read enough to cover the
    // checksum span (256 + max_dev*2, capped so it fits this window).
    let off = md::v10_superblock_offset(m.size())?;
    let tail = read_at(m, off, 8192);
    md::parse_superblock(&tail)
}

/// The per-member usable size to trust: the superblock's figure, but never more
/// than the largest present member actually holds. A truncated member or a corrupt
/// superblock that declares more usable space than exists must NOT inflate the
/// array's logical size — that would present reads past the real bytes as valid
/// data. A superblock size of 0 (unknown) falls back to the largest member.
fn resolve_member_size(sb_member_size: u64, max_present_size: u64) -> u64 {
    if sb_member_size == 0 {
        max_present_size
    } else {
        sb_member_size.min(max_present_size)
    }
}

/// Assemble a virtual [`RaidDevice`] from ordered member sources, auto-detecting
/// the geometry from a Linux `md` v1 superblock when one is present.
///
/// `members` are in array order; a `None` marks a missing disk. If any present
/// member carries an `md` superblock, its level, chunk and per-member size are
/// used (this is the common case — the examiner names the members and nothing
/// else). `level_override`/`chunk_override` force the geometry for a foreign or
/// superblock-less array. Returns the device and an [`AssemblyReport`] of how the
/// geometry was decided, so the provenance is recorded rather than assumed.
///
/// The device is virtual: it reconstructs the logical block space on the fly and
/// is never written to disk, so scanning it costs no second copy of the array.
pub fn assemble(
    members: Vec<AssemblyMember>,
    level_override: Option<RaidLevel>,
    chunk_override: Option<u64>,
) -> Result<(RaidDevice, AssemblyReport), String> {
    if members.iter().all(|m| m.is_none()) {
        return Err("no present member to assemble from".into());
    }

    // Look for an md superblock on EVERY present member, checking both the head
    // positions (v1.1 at 0, v1.2 at 4 KiB) and the v1.0 location at the end of
    // the device. Detection (`detect_raid_member`) surfaces v1.0 members and
    // points the examiner here, so assembly must find them too. Each member is
    // read separately because `data_offset` is a per-device field: the first
    // member's superblock cannot be assumed to describe where the others' data
    // starts.
    let per_member: Vec<Option<MdGeometry>> = members
        .iter()
        .map(|m| m.as_ref().and_then(|s| detect_geometry(s.as_ref())))
        .collect();
    let detected = per_member.iter().flatten().next().cloned();

    if let Some(g) = &detected {
        // Only Linux's left-symmetric placement (layout 2) is implemented, and
        // stripe placement is layout-dependent: an array recording layout 0/1/3
        // would read back systematically wrong bytes with no other symptom.
        // Refuse it rather than auto-assemble a confident mis-mapping.
        let level = level_override.unwrap_or(g.level);
        if matches!(level, RaidLevel::Raid5 | RaidLevel::Raid6)
            && matches!(g.level, RaidLevel::Raid5 | RaidLevel::Raid6)
            && g.layout != md::LAYOUT_LEFT_SYMMETRIC
        {
            return Err(format!(
                "md superblock records layout {} for this {:?}; this reader implements \
                 left-symmetric placement (layout {}) only, and mapping another layout \
                 with it would return the wrong bytes for every stripe",
                g.layout,
                g.level,
                md::LAYOUT_LEFT_SYMMETRIC
            ));
        }
        // The superblock states the array's width. Member positions drive the
        // stripe mapping, the parity placement and the logical size, so a count
        // that disagrees reconstructs a different array than the one seized: a
        // dead disk must be named as a missing position, not left out. RAID 1 is
        // the exception — a mirror's width enters no mapping, so one disk of a
        // seized pair still reads the volume exactly.
        if level != RaidLevel::Raid1 && g.raid_disks > 0 && g.raid_disks as usize != members.len() {
            return Err(format!(
                "md superblock describes a {}-disk array but {} member positions were \
                 supplied; give every position in array order, marking each dead disk \
                 as missing",
                g.raid_disks,
                members.len()
            ));
        }
    }

    // Where the array's data plane starts inside each member. md v1.1/v1.2 keeps
    // the superblock — and any write-intent bitmap — at the head of the member and
    // starts array data `data_offset` bytes in (mdadm's default is 1 MiB), so
    // addressing members from byte 0 would serve that metadata as evidence and
    // shift every reconstructed byte. A present member carrying no superblock of
    // its own takes the array's offset: mdadm writes the same one to every member,
    // and reading it from a different base than its peers is certainly wrong.
    let array_data_offset = detected.as_ref().map(|g| g.data_offset).unwrap_or(0);
    let mut based: Vec<AssemblyMember> = Vec::with_capacity(members.len());
    for (m, g) in members.iter().zip(&per_member) {
        let Some(src) = m else {
            based.push(None);
            continue;
        };
        let base = g
            .as_ref()
            .map(|geom| geom.data_offset)
            .unwrap_or(array_data_offset);
        if base == 0 {
            based.push(Some(src.clone()));
            continue;
        }
        let size = src.size();
        if base >= size {
            return Err(format!(
                "member data starts {base} bytes in but the member image is only {size} \
                 bytes; it is truncated or does not belong to this array"
            ));
        }
        based.push(Some(
            Arc::new(WindowSource::new(src.clone(), base, size - base)) as Arc<dyn DataSource>,
        ));
    }
    let members = based;

    // The declared per-member size bounds the geometry; the largest present
    // member is the reference (a truncated member then reads short, as designed).
    // Sizes are taken AFTER the data offset is applied, so the superblock's
    // usable size is compared against usable bytes, not against the header too.
    let max_size = members
        .iter()
        .flatten()
        .map(|m| m.size())
        .max()
        .unwrap_or(0);

    let (level, chunk, member_size, auto_detected) = match detected {
        Some(g) => (
            level_override.unwrap_or(g.level),
            chunk_override.unwrap_or(g.chunk_bytes),
            resolve_member_size(g.member_size, max_size),
            true,
        ),
        None => {
            let level = level_override
                .ok_or("no md superblock found; --level is required for this array")?;
            let chunk = chunk_override.unwrap_or(0);
            (level, chunk, max_size, false)
        }
    };

    let device = RaidDevice::new(level, members, chunk, member_size)?;
    Ok((
        device,
        AssemblyReport {
            level,
            chunk,
            member_size,
            data_offset: array_data_offset,
            auto_detected,
        },
    ))
}

/// A logical volume presented as a DataSource over its backing PV device(s).
///
/// Maps each read through the parsed LVM extent map and routes it to the physical
/// volume that segment lives on. A volume whose segments span several PVs (a
/// striped or multi-PV linear LV) is supported by naming each PV's device via
/// [`LvDevice::new_multi`]; the single-PV case has the convenience
/// [`LvDevice::new`].
#[derive(Clone)]
pub struct LvDevice {
    vg: Arc<LvmVg>,
    lv_name: String,
    pvs: std::collections::HashMap<String, Arc<dyn DataSource>>,
    size: u64,
}

impl std::fmt::Debug for LvDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("LvDevice")
            .field("vg", &self.vg.name)
            .field("lv", &self.lv_name)
            .field("pvs", &self.pvs.len())
            .field("size", &self.size)
            .finish()
    }
}

impl LvDevice {
    /// Build an LV device over a single physical volume (which may itself be a
    /// [`RaidDevice`]). Requires the VG to have exactly one PV; use
    /// [`LvDevice::new_multi`] otherwise. Fails if the LV is unknown.
    pub fn new(vg: Arc<LvmVg>, lv_name: &str, pv: Arc<dyn DataSource>) -> Result<Self, String> {
        if vg.pvs.len() != 1 {
            return Err(format!(
                "volume group has {} physical volumes; use LvDevice::new_multi to name each",
                vg.pvs.len()
            ));
        }
        let pv_name = vg.pvs[0].name.clone();
        let pvs = std::iter::once((pv_name, pv)).collect();
        Self::new_multi(vg, lv_name, pvs)
    }

    /// Build an LV device over several physical volumes, keyed by the PV name used
    /// in the LVM metadata (`pv0`, `pv1`, …). Every PV a segment of the LV
    /// references must be present, or the read that reaches it fails honestly.
    pub fn new_multi(
        vg: Arc<LvmVg>,
        lv_name: &str,
        pvs: std::collections::HashMap<String, Arc<dyn DataSource>>,
    ) -> Result<Self, String> {
        let lv = vg
            .lvs
            .iter()
            .find(|l| l.name == lv_name)
            .ok_or_else(|| format!("no logical volume named {lv_name}"))?;
        // Refuse a genuinely striped LV up front rather than serve wrong bytes:
        // this reader maps linear/single-stripe segments only.
        if let Some(seg) = lv.segments.iter().find(|s| s.stripe_count > 1) {
            return Err(format!(
                "logical volume '{lv_name}' has a {}-way striped segment; this reader maps \
                 linear/single-stripe volumes only",
                seg.stripe_count
            ));
        }
        // Extent counts come straight from the LVM metadata text, so the volume
        // size must be computed with checked arithmetic: a wrapped product would
        // state a false volume length (and every read would be bounded by it)
        // instead of refusing metadata that cannot describe a real volume.
        let extents = lv
            .segments
            .iter()
            .try_fold(0u64, |acc, s| acc.checked_add(s.extent_count))
            .ok_or_else(|| {
                format!("logical volume '{lv_name}' declares more extents than a u64 can count")
            })?;
        let size = extents.checked_mul(vg.extent_bytes()).ok_or_else(|| {
            format!("logical volume '{lv_name}' declares a size that overflows 64 bits")
        })?;
        Ok(Self {
            vg,
            lv_name: lv_name.to_string(),
            pvs,
            size,
        })
    }
}

impl DataSource for LvDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.size - offset) as usize;
        let mut done = 0;
        let ebytes = self.vg.extent_bytes();
        let mut pos = offset;
        while done < want {
            // Map this position; read up to the end of its extent in one go, from
            // whichever PV this segment lives on.
            let (pv_name, pv_byte) = self
                .vg
                .map_lv_offset(&self.lv_name, pos)
                .ok_or_else(|| io::Error::other("unmapped LV offset"))?;
            let pv = self.pvs.get(&pv_name).ok_or_else(|| {
                io::Error::other(format!(
                    "LV segment references PV '{pv_name}', which was not supplied"
                ))
            })?;
            let intra = pos % ebytes;
            let n = ((ebytes - intra) as usize).min(want - done);
            let got = pv.read_at(pv_byte, &mut buf[done..done + n])?;
            if got == 0 {
                break;
            }
            done += got;
            pos += got as u64;
        }
        Ok(done)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use seance_core::data_source::ByteSliceDataSource;

    fn arc(v: Vec<u8>) -> AssemblyMember {
        Some(Arc::new(ByteSliceDataSource::new(v)) as Arc<dyn DataSource>)
    }

    #[test]
    fn assemble_with_explicit_geometry_builds_a_virtual_device() {
        // No superblock: the examiner supplies level + chunk. RAID 0 over two
        // 16-byte members → a 32-byte logical device, assembled without any
        // materialised image.
        let members = vec![arc(vec![0xAA; 16]), arc(vec![0xBB; 16])];
        let (dev, report) = assemble(members, Some(RaidLevel::Raid0), Some(8))
            .expect("explicit geometry assembles");
        assert!(!report.auto_detected, "no superblock → not auto-detected");
        assert_eq!(report.level, RaidLevel::Raid0);
        assert_eq!(report.chunk, 8);
        assert_eq!(dev.logical_size(), 32, "RAID0 logical size is the sum");
    }

    #[test]
    fn assemble_auto_detects_a_v1_0_end_of_device_superblock() {
        // detect_raid_member surfaces v1.0 members (superblock near the end of the
        // device) and points the examiner at scan-raid/assemble-raid, so assembly
        // must find that superblock too — head-only search would miss it.
        //
        // A 40-sector (20 KiB) member places its v1.0 superblock at
        // ((40-16) & ~7) * 512 = 12288, past the 8 KiB head window, so only the
        // tail path can locate it.
        let dev_bytes = 40u64 * 512;
        let off = md::v10_superblock_offset(dev_bytes).expect("device large enough") as usize;
        assert!(
            off > 8192,
            "test relies on the sb being past the head window"
        );
        let sb = md::build_superblock(1, 0, 0, 2, 24); // RAID1, 2 disks, 24-sector data
        let mut member = vec![0u8; dev_bytes as usize];
        member[off..off + sb.len()].copy_from_slice(&sb);

        let members = vec![arc(member.clone()), arc(member)];
        let (dev, report) = assemble(members, None, None)
            .expect("a v1.0 superblock must be auto-detected without --level");
        assert!(report.auto_detected, "geometry came from the superblock");
        assert_eq!(report.level, RaidLevel::Raid1);
        // RAID1 logical size is one member's usable size (24 sectors), clamped to
        // what the members hold.
        assert_eq!(dev.logical_size(), 24 * 512);
    }

    #[test]
    fn assemble_without_geometry_or_superblock_is_refused() {
        // No superblock and no --level: refuse rather than guess a layout.
        let members = vec![arc(vec![0u8; 16]), arc(vec![0u8; 16])];
        let err = assemble(members, None, None).expect_err("must refuse without geometry");
        assert!(
            err.contains("--level is required"),
            "explains what is missing: {err}"
        );
    }

    #[test]
    fn assemble_refuses_when_every_member_is_missing() {
        let members: Vec<AssemblyMember> = vec![None, None];
        assert!(assemble(members, Some(RaidLevel::Raid1), None).is_err());
    }

    #[test]
    fn member_size_is_clamped_to_what_the_members_actually_hold() {
        // A superblock (or truncated member) that declares MORE usable space than
        // the largest present member holds must not inflate the array size, or
        // reads past the real bytes would be presented as valid data.
        assert_eq!(
            resolve_member_size(100, 40),
            40,
            "an over-declared size is clamped to the largest member"
        );
        // The normal case: the member file is at least as large as its usable
        // size (superblock + data), so the superblock figure stands.
        assert_eq!(resolve_member_size(40, 100), 40);
        // Unknown superblock size falls back to the largest member.
        assert_eq!(resolve_member_size(0, 64), 64);
    }

    /// A real mdadm v1.1/v1.2 member keeps its superblock (and bitmap) at the head
    /// and starts the array's data `data_offset` bytes in. Assembly must read from
    /// there: from byte 0 the "reconstruction" is the member's own metadata,
    /// shifted by the offset, with no other symptom.
    #[test]
    fn assemble_reads_members_from_the_superblock_data_offset() {
        let data_offset_sectors = 16u64; // 8 KiB in
        let data_offset = data_offset_sectors * 512;
        let data: Vec<u8> = (0..4096).map(|i| (i % 251 + 1) as u8).collect();
        // RAID 1, 2 disks, 8 sectors (4 KiB) of usable data per member.
        let sb = md::build_superblock_with_data_offset(1, 0, 0, 2, 8, data_offset_sectors);
        // The header area is deliberately non-zero: reading from byte 0 would
        // return this filler, so the test can tell the two bases apart.
        let mut member = vec![0xEEu8; data_offset as usize];
        member[..sb.len()].copy_from_slice(&sb);
        member.extend_from_slice(&data);

        let members = vec![arc(member.clone()), arc(member)];
        let (dev, report) = assemble(members, None, None).expect("the array auto-detects");
        assert_eq!(
            report.data_offset, data_offset,
            "the applied offset is on the record"
        );
        assert_eq!(
            dev.logical_size(),
            data.len() as u64,
            "the logical size is the usable data, not the whole member image"
        );
        let mut out = vec![0u8; data.len()];
        let got = dev.read_at(0, &mut out).unwrap();
        assert_eq!(got, data.len());
        assert_eq!(
            out, data,
            "logical byte 0 must be the first byte of the DATA plane, not the superblock"
        );
    }

    /// A `data_offset` past the end of the member image means the data plane is
    /// not in this file: refuse rather than assemble something.
    #[test]
    fn assemble_refuses_a_member_shorter_than_its_data_offset() {
        let sb = md::build_superblock_with_data_offset(1, 0, 0, 2, 8, 64); // 32 KiB in
        let mut member = vec![0u8; 8192];
        member[..sb.len()].copy_from_slice(&sb);
        let err = assemble(vec![arc(member.clone()), arc(member)], None, None)
            .expect_err("a data_offset past the member end must be refused");
        assert!(
            err.contains("member image is only"),
            "message explains the refusal: {err}"
        );
    }

    /// Layout 0 (left-asymmetric) places the same disks' chunks differently. The
    /// reader maps left-symmetric only, so auto-assembling any other layout would
    /// return systematically wrong bytes with nothing to show for it.
    #[test]
    fn assemble_refuses_a_layout_this_reader_does_not_implement() {
        let with_layout = |layout: u32| {
            let sb = md::build_superblock(5, layout, 128, 3, 100);
            let mut member = vec![0u8; 8192];
            member[..sb.len()].copy_from_slice(&sb);
            vec![arc(member.clone()), arc(member.clone()), arc(member)]
        };
        let err = assemble(with_layout(0), None, None)
            .expect_err("a non-left-symmetric layout must be refused");
        assert!(
            err.contains("left-symmetric"),
            "message names the problem: {err}"
        );
        // The same array written left-symmetric (layout 2) still assembles.
        assert!(
            assemble(with_layout(2), None, None).is_ok(),
            "the implemented layout must still auto-assemble"
        );
    }

    /// The superblock states the array's width. Assembling a different number of
    /// member positions changes the stripe mapping, the parity placement and the
    /// logical size — a different array than the one seized.
    #[test]
    fn assemble_refuses_a_member_count_that_contradicts_the_superblock() {
        let sb = md::build_superblock(5, 2, 128, 4, 100); // four disks
        let mut member = vec![0u8; 8192];
        member[..sb.len()].copy_from_slice(&sb);
        let three = vec![
            arc(member.clone()),
            arc(member.clone()),
            arc(member.clone()),
        ];
        let err = assemble(three, None, None).expect_err("a width mismatch must be refused");
        assert!(
            err.contains("4-disk"),
            "message states the array width: {err}"
        );
        assert!(
            err.contains("member positions"),
            "message says what to supply instead: {err}"
        );

        // Naming the dead disk as a missing position assembles the real geometry.
        let four = vec![arc(member.clone()), arc(member.clone()), arc(member), None];
        assert!(
            assemble(four, None, None).is_ok(),
            "a missing position is how a dead disk is named"
        );

        // A mirror is the exception: its width enters no mapping, so one seized
        // disk of a pair still reconstructs the volume exactly.
        let sb1 = md::build_superblock(1, 0, 0, 2, 8);
        let mut mirror = vec![0u8; 8192];
        mirror[..sb1.len()].copy_from_slice(&sb1);
        assert!(
            assemble(vec![arc(mirror)], None, None).is_ok(),
            "one disk of a mirrored pair must still assemble"
        );
    }

    #[test]
    fn an_lv_size_that_overflows_is_refused_not_wrapped() {
        // extent_count comes straight from the metadata text; a hostile value must
        // not wrap to a small, plausible volume size.
        let meta = r#"
vg {
    extent_size = 2048
    physical_volumes { pv0 { pe_start = 0 } }
    logical_volumes {
        huge { segment1 { start_extent = 0
                          extent_count = 18446744073709551615
                          stripes = [ "pv0", 0 ] } }
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        let pv: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0; 512]));
        let err =
            LvDevice::new(vg, "huge", pv).expect_err("an unrepresentable LV size must be refused");
        assert!(
            err.contains("overflows"),
            "message explains the refusal: {err}"
        );
    }

    #[test]
    fn lv_device_reads_the_right_pv_bytes() {
        // A tiny VG: extent size 512 bytes (1 sector), pe_start 0, LV of 4 extents
        // starting at PV extent 2.
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes {
        pv0 { pe_start = 0 }
    }
    logical_volumes {
        lv0 {
            segment1 {
                start_extent = 0
                extent_count = 4
                stripes = [ "pv0", 2 ]
            }
        }
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        // PV device: 8 extents of 512 bytes, each filled with its extent number.
        let mut pv_bytes = Vec::new();
        for e in 0..8u8 {
            pv_bytes.extend(std::iter::repeat_n(e, 512));
        }
        let pv: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(pv_bytes));
        let lv = LvDevice::new(vg, "lv0", pv).unwrap();

        assert_eq!(lv.size(), 4 * 512);
        // LV extent 0 maps to PV extent 2 → all bytes == 2.
        let mut buf = [0u8; 512];
        lv.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 2));
        // LV extent 3 maps to PV extent 5 → all bytes == 5.
        lv.read_at(3 * 512, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 5));
    }

    #[test]
    fn lv_over_raid_composes() {
        // The real point: an LV whose PV is a reconstructed RAID device. Build a
        // 2-disk RAID0 PV, then an LV over it, and read through both layers.
        let chunk = 512u64;
        let pv_logical: Vec<u8> = (0..4096).map(|i| (i / 512) as u8).collect(); // 8 extents
        let mut m = vec![Vec::new(), Vec::new()];
        for (ci, c) in pv_logical.chunks(chunk as usize).enumerate() {
            m[ci % 2].extend_from_slice(c);
        }
        let raid = RaidDevice::new(
            RaidLevel::Raid0,
            m.into_iter()
                .map(|v| Some(Arc::new(ByteSliceDataSource::new(v)) as Arc<dyn DataSource>))
                .collect(),
            chunk,
            2048,
        )
        .unwrap();

        let meta = r#"
vg {
    extent_size = 1
    physical_volumes { pv0 { pe_start = 0 } }
    logical_volumes {
        lv0 { segment1 { start_extent = 0
                         extent_count = 2
                         stripes = [ "pv0", 3 ] } }
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        let lv = LvDevice::new(vg, "lv0", Arc::new(raid)).unwrap();
        let mut buf = [0u8; 512];
        // LV extent 0 → PV extent 3 → RAID0 logical bytes [1536..2048) == byte 3.
        lv.read_at(0, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 3),
            "LV-over-RAID must resolve through both layers"
        );
    }

    #[test]
    fn unknown_lv_is_rejected() {
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes {
        pv0 { pe_start = 0 }
    }
    logical_volumes {
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        let pv: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0; 10]));
        assert!(LvDevice::new(vg, "missing", pv).is_err());
    }

    #[test]
    fn multi_pv_lv_routes_reads_to_the_right_physical_volume() {
        // An LV whose first segment lives on pv0 and second on pv1 — the case
        // single-PV LvDevice could not serve.
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes {
        pv0 { pe_start = 0 }
        pv1 { pe_start = 0 }
    }
    logical_volumes {
        data {
            segment1 { start_extent = 0
                       extent_count = 2
                       stripes = [ "pv0", 0 ] }
            segment2 { start_extent = 2
                       extent_count = 2
                       stripes = [ "pv1", 0 ] }
        }
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        // pv0 is filled with 0xAA, pv1 with 0xBB (each 4 extents of 512 bytes).
        let pv0: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xAA; 4 * 512]));
        let pv1: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xBB; 4 * 512]));
        let mut pvs = std::collections::HashMap::new();
        pvs.insert("pv0".to_string(), pv0);
        pvs.insert("pv1".to_string(), pv1);
        let lv = LvDevice::new_multi(vg, "data", pvs).unwrap();

        assert_eq!(lv.size(), 4 * 512);
        let mut buf = [0u8; 512];
        // Extent 0 → pv0 → 0xAA.
        lv.read_at(0, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "segment 1 must read from pv0"
        );
        // Extent 2 → pv1 → 0xBB.
        lv.read_at(2 * 512, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "segment 2 must read from pv1"
        );
    }

    #[test]
    fn lv_device_refuses_a_multi_stripe_volume() {
        // A striped LV cannot be served as a linear mapping; construction must
        // fail with a clear message rather than silently returning wrong bytes.
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes { pv0 { pe_start = 0 } pv1 { pe_start = 0 } }
    logical_volumes {
        striped {
            segment1 { start_extent = 0 extent_count = 4
                       type = "striped" stripe_count = 2
                       stripes = [ "pv0", 0, "pv1", 0 ] }
        }
    }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        let mut pvs = std::collections::HashMap::new();
        pvs.insert(
            "pv0".to_string(),
            Arc::new(ByteSliceDataSource::new(vec![0; 4096])) as Arc<dyn DataSource>,
        );
        pvs.insert(
            "pv1".to_string(),
            Arc::new(ByteSliceDataSource::new(vec![0; 4096])) as Arc<dyn DataSource>,
        );
        let err = LvDevice::new_multi(vg, "striped", pvs).unwrap_err();
        assert!(err.contains("striped"), "message names the problem: {err}");
    }

    #[test]
    fn single_pv_new_rejects_a_multi_pv_group() {
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes { pv0 { pe_start = 0 } pv1 { pe_start = 0 } }
    logical_volumes { lv0 { segment1 { start_extent = 0 extent_count = 1 stripes = [ "pv0", 0 ] } } }
}
"#;
        let vg = Arc::new(parse_metadata(meta).unwrap());
        let pv: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0; 512]));
        let err = LvDevice::new(vg, "lv0", pv).unwrap_err();
        assert!(err.contains("new_multi"));
    }
}
