//! Validate the md-superblock and LVM parsers against artifacts produced by the
//! REAL tools — `mdadm --create` (v1.2 metadata) and `vgcfgbackup` — not by
//! hand-written fixtures. This is the check that caught the SquashFS
//! extended-inode bug: synthetic fixtures confirm round-trip, real output
//! confirms fidelity.
//!
//! Fixtures were captured from `mdadm`/`lvm` running on loop devices and then
//! committed:
//!   - `raid5_member_head.bin` / `raid6_member_head.bin` — first 8 KiB of a real
//!     array member (v1.2 superblock at byte 4096).
//!   - `lvm_metadata.txt` — genuine `vgcfgbackup` output (hostname scrubbed) with
//!     a linear LV and a real 2-way striped LV.

use seance_container_raid::lvm::parse_metadata;
use seance_container_raid::md::{find_superblock, MdGeometry};
use seance_container_raid::raid::RaidLevel;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

#[test]
fn parses_a_real_mdadm_raid6_superblock() {
    let head = fixture("raid6_member_head.bin");
    let (g, loc): (MdGeometry, usize) =
        find_superblock(&head).expect("locate the real v1.2 superblock");
    // `mdadm --examine` reported: Super Offset 8 sectors (4096 bytes), raid6,
    // 4 devices, 64K chunk, left-symmetric (layout code 2).
    assert_eq!(loc, 4096, "v1.2 superblock is at byte 4096");
    assert_eq!(g.level, RaidLevel::Raid6);
    assert_eq!(g.raid_disks, 4);
    assert_eq!(g.chunk_bytes, 64 * 1024);
    assert_eq!(g.layout, 2, "left-symmetric");
    // `mdadm --examine` also reported Data Offset 2048 sectors: the array's data
    // plane starts 1 MiB into each member, after the superblock and the bitmap.
    // Reconstructing from byte 0 would serve that metadata as array data.
    assert_eq!(g.data_offset, 2048 * 512, "real mdadm v1.2 data offset");
}

#[test]
fn parses_a_real_mdadm_raid5_superblock() {
    let head = fixture("raid5_member_head.bin");
    let (g, loc) = find_superblock(&head).expect("locate the real v1.2 superblock");
    assert_eq!(loc, 4096);
    assert_eq!(g.level, RaidLevel::Raid5);
    assert_eq!(g.raid_disks, 3);
    assert_eq!(g.chunk_bytes, 64 * 1024);
    assert_eq!(g.data_offset, 2048 * 512, "real mdadm v1.2 data offset");
}

#[test]
fn parses_real_vgcfgbackup_metadata_linear_and_striped() {
    let text = String::from_utf8(fixture("lvm_metadata.txt")).unwrap();
    let vg = parse_metadata(&text).expect("real vgcfgbackup metadata parses");

    assert_eq!(vg.name, "seance_audit_vg");
    assert_eq!(vg.extent_size_sectors, 8192);
    assert_eq!(vg.pvs.len(), 2);
    for pv in &vg.pvs {
        assert_eq!(pv.pe_start_sectors, 2048, "real pe_start");
    }

    // The linear LV: one stripe, wrapped `stripes = [ \n "pv0", 0 \n ]`. It must
    // parse (proving the wrapped-array handling) and map linearly.
    let linear = vg
        .lvs
        .iter()
        .find(|l| l.name == "linear")
        .expect("linear LV");
    assert_eq!(linear.segments.len(), 1);
    assert_eq!(linear.segments[0].stripe_count, 1);
    assert_eq!(linear.segments[0].stripe_pv, "pv0");
    let (pv, byte) = vg.map_lv_offset("linear", 0).expect("linear maps");
    assert_eq!(pv, "pv0");
    assert_eq!(byte, 2048 * 512); // pe_start + extent 0

    // The striped LV: real `stripe_count = 2` with two pairs `"pv0", 4, "pv1", 0`.
    // It must be recognised as multi-stripe and refused, not mismapped to pv0.
    let striped = vg
        .lvs
        .iter()
        .find(|l| l.name == "striped")
        .expect("striped LV");
    assert_eq!(striped.segments[0].stripe_count, 2, "real 2-way stripe");
    assert!(
        vg.map_lv_offset("striped", 0).is_none(),
        "a real striped LV must be refused, not linearly mismapped"
    );
}
