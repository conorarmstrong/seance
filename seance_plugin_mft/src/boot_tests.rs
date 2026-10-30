//! The NTFS boot sector — stated before it was decoded.
//!
//! # Ground truth
//!
//! `~/forensic_corpora/alihadi_ntfs/NTFS-HiddenFiles.E01`, cross-checked field
//! by field against `fsstat`. Every number below came off that image:
//!
//! ```text
//! bytes per sector      512
//! sectors per cluster   8        -> cluster size 4,096
//! total sectors         198,655  -> total clusters 24,831
//! $MFT cluster          8,277
//! $MFTMirr cluster      2
//! clusters/MFT record   0xF6 (-10) -> 1,024 bytes   (fsstat: "Size of MFT Entries: 1024 bytes")
//! clusters/index record 0x01       -> 4,096 bytes   (fsstat: "Size of Index Records: 4096 bytes")
//! volume serial         0xE0FA70C9FA709D8A
//! hidden sectors        128
//! ```
//!
//! `fsstat` prints the cluster **range** `0 - 24830`, which is `total_clusters
//! - 1`. The two agree, and neither is to be "corrected" into the other.

use super::boot::*;

/// A boot sector built to the ground truth above.
fn alihadi_boot_sector() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"NTFS    ");
    b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    b[0x0D] = 8;
    b[0x15] = 0xF8;
    b[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    b[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    b[0x1C..0x20].copy_from_slice(&128u32.to_le_bytes());
    b[0x24] = 0x80;
    b[0x26] = 0x80;
    b[0x28..0x30].copy_from_slice(&198_655u64.to_le_bytes());
    b[0x30..0x38].copy_from_slice(&8_277i64.to_le_bytes());
    b[0x38..0x40].copy_from_slice(&2i64.to_le_bytes());
    b[0x40] = 0xF6; // -10
    b[0x44] = 0x01;
    b[0x48..0x50].copy_from_slice(&0xE0FA_70C9_FA70_9D8Au64.to_le_bytes());
    b[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
    b
}

/// Every field decodes to what `fsstat` reports for the real volume.
#[test]
fn the_boot_sector_of_a_real_ntfs_volume_decodes_to_the_values_fsstat_reports() {
    let b = NtfsBootSector::parse(&alihadi_boot_sector()).expect("a valid NTFS boot sector");

    assert_eq!(b.bytes_per_sector, 512);
    assert_eq!(b.sectors_per_cluster, 8);
    assert_eq!(b.cluster_size(), 4_096);
    assert_eq!(b.total_sectors, 198_655);
    assert_eq!(
        b.total_clusters(),
        24_831,
        "fsstat prints the range 0 - 24830, which is this minus one"
    );
    assert_eq!(b.mft_cluster, 8_277);
    assert_eq!(b.mft_mirror_cluster, 2);
    assert_eq!(
        b.mft_record_size(),
        Some(1_024),
        "0xF6 is -10, so 1 << 10 BYTES — not 10 clusters"
    );
    assert_eq!(
        b.index_record_size(),
        Some(4_096),
        "0x01 is positive, so 1 * cluster_size"
    );
    assert_eq!(b.media_descriptor, 0xF8);
    assert_eq!(b.sectors_per_track, 63);
    assert_eq!(b.number_of_heads, 255);
    assert_eq!(b.hidden_sectors, 128);
    assert_eq!(b.volume_serial, 0xE0FA_70C9_FA70_9D8A);
}

/// The serial is reported in three **labelled** forms, because three tools
/// print three different things and an unlabelled "serial" invites a reader to
/// compare the wrong one.
#[test]
fn the_volume_serial_is_reported_in_three_labelled_forms() {
    let b = NtfsBootSector::parse(&alihadi_boot_sector()).expect("parse");
    assert_eq!(b.volume_serial, 0xE0FA_70C9_FA70_9D8A, "the raw u64");
    assert_eq!(
        b.volume_serial_hex(),
        "E0FA70C9FA709D8A",
        "sixteen uppercase hex digits, as fsstat prints it"
    );
    assert_eq!(
        b.volume_serial_short(),
        "FA70-9D8A",
        "the low dword, as Windows `vol` prints it"
    );
}

// --- The two signed fields -------------------------------------------------

/// A negative record-size byte is a power of two in **bytes**, and a hostile
/// one is refused rather than shifted.
///
/// `0x80` is −128. `1 << 128` panics under `overflow-checks`, and a panic here
/// unwinds `process()` and loses every file in the table rather than one field
/// — the same class as `compression_unit_bytes`.
#[test]
fn a_negative_clusters_per_record_byte_decodes_as_a_power_of_two_and_a_hostile_one_is_refused() {
    // The real value, and the neighbours either side of it.
    assert_eq!(record_size_bytes(-10, 4_096), Some(1_024));
    assert_eq!(record_size_bytes(-9, 4_096), Some(512));
    assert_eq!(record_size_bytes(-12, 4_096), Some(4_096));
    // Positive: a count of clusters.
    assert_eq!(record_size_bytes(1, 4_096), Some(4_096));
    assert_eq!(record_size_bytes(4, 512), Some(2_048));
    // Zero names no size.
    assert_eq!(record_size_bytes(0, 4_096), None);
    // And the hostile end of the range, which must not shift.
    for raw in [-128i8, -64, -32] {
        assert_eq!(
            record_size_bytes(raw, 4_096),
            None,
            "raw {raw} would shift past a u64 and must be refused"
        );
    }
}

/// The sectors-per-cluster byte's three ranges.
///
/// Above `0xF0` it is an exponent, not a count — and reading it as a count is
/// exactly the defect this module exists to prevent: the scan phase did, and
/// on a volume with large clusters it found no records at all.
#[test]
fn the_sectors_per_cluster_byte_is_an_exponent_above_f0() {
    assert_eq!(decode_sectors_per_cluster(8), Some(8));
    assert_eq!(decode_sectors_per_cluster(0x80), Some(128));
    // 0xF1 => 2^(256-241) = 2^15
    assert_eq!(decode_sectors_per_cluster(0xF1), Some(32_768));
    assert_eq!(decode_sectors_per_cluster(0xFF), Some(2));
    // Zero and the reserved range name nothing.
    assert_eq!(decode_sectors_per_cluster(0), None);
    for spc in [0x81u8, 0xA0, 0xF0] {
        assert_eq!(
            decode_sectors_per_cluster(spc),
            None,
            "0x{spc:02X} is reserved"
        );
    }
}

// --- What is not a boot sector ---------------------------------------------

/// A window that is not NTFS produces no record.
///
/// A bare `$MFT` extracted from a volume starts with `FILE`, and every MFT test
/// in this plugin relies on that producing `None` rather than a fabricated
/// geometry.
#[test]
fn a_boot_sector_window_that_is_not_ntfs_produces_no_record() {
    let mut fat = vec![0u8; 512];
    fat[3..11].copy_from_slice(b"MSDOS5.0");
    assert!(NtfsBootSector::parse(&fat).is_none());

    let mut mft = vec![0u8; 512];
    mft[0..4].copy_from_slice(b"FILE");
    assert!(NtfsBootSector::parse(&mft).is_none());

    // Short of a sector is not a sector.
    let b = alihadi_boot_sector();
    assert!(NtfsBootSector::parse(&b[..511]).is_none());
    assert!(NtfsBootSector::parse(&[]).is_none());
}

/// The gate is exactly the one the previous decoders applied, so nothing that
/// parsed before stops parsing: signature, a non-zero power-of-two sector
/// size, and a decodable sectors-per-cluster.
#[test]
fn the_parse_gate_is_unchanged_from_the_decoders_this_replaces() {
    // A sector size that is not a power of two.
    let mut odd = alihadi_boot_sector();
    odd[0x0B..0x0D].copy_from_slice(&520u16.to_le_bytes());
    assert!(NtfsBootSector::parse(&odd).is_none());

    // A zero sector size.
    let mut zero = alihadi_boot_sector();
    zero[0x0B..0x0D].copy_from_slice(&0u16.to_le_bytes());
    assert!(NtfsBootSector::parse(&zero).is_none());

    // A reserved sectors-per-cluster.
    let mut reserved = alihadi_boot_sector();
    reserved[0x0D] = 0x90;
    assert!(NtfsBootSector::parse(&reserved).is_none());

    // And a record-size byte this build cannot resolve does NOT stop the
    // sector parsing: the geometry is still good, and only that field is
    // absent. Refusing the whole sector would lose the volume over one field.
    let mut bad_record = alihadi_boot_sector();
    bad_record[0x40] = 0x80;
    let b = NtfsBootSector::parse(&bad_record).expect("the geometry still decodes");
    assert_eq!(b.cluster_size(), 4_096);
    assert_eq!(
        b.mft_record_size(),
        None,
        "the field is absent, and the volume is not lost with it"
    );
}

/// The backup boot sector sits immediately past the addressable range.
///
/// Verified on the real image: 101,711,872 bytes = 198,656 sectors, and sector
/// 198,655 begins `eb52904e5446532020202000 0208 0000` with OEM `NTFS    `.
#[test]
fn the_backup_boot_sector_offset_is_past_the_addressable_range() {
    let b = NtfsBootSector::parse(&alihadi_boot_sector()).expect("parse");
    assert_eq!(
        b.backup_boot_sector_offset(),
        Some(198_655 * 512),
        "the sector immediately past the volume's last addressable one"
    );

    // A crafted total_sectors must not overflow into a wrapped offset.
    let mut huge = alihadi_boot_sector();
    huge[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
    let b = NtfsBootSector::parse(&huge).expect("parse");
    assert_eq!(
        b.backup_boot_sector_offset(),
        None,
        "an offset that overflows is not an offset"
    );
}

// --- The record size came from a constant (HUNT-128) ------------------------

/// The MFT record size must come from the **volume**, not from a constant.
///
/// `lib.rs` hardcoded `let mft_record_size: u64 = 1024;` and never read BPB
/// `0x40`. 1,024 is what NTFS writes on every volume anyone has measured, so
/// the constant was right everywhere it was tested and still a guess: a volume
/// formatted with a different record size would have had every record read at
/// the wrong stride, and the table would have come back empty or garbled with
/// nothing to say why.
///
/// A 4K-native disk gets 4,096-byte records, and `0xFF4` — which is `-12` —
/// is how the BPB says so.
#[test]
fn the_mft_record_size_comes_from_the_boot_sector_and_not_from_a_constant() {
    // The real volume: 0xF6 is -10, so 1,024. The constant happened to match.
    let real = NtfsBootSector::parse(&alihadi_boot_sector()).expect("parse");
    assert_eq!(real.mft_record_size(), Some(1_024));

    // A volume that disagrees with the constant. Nothing in the old code could
    // have produced this number.
    let mut four_k = alihadi_boot_sector();
    four_k[0x40] = (-12i8) as u8;
    let b = NtfsBootSector::parse(&four_k).expect("parse");
    assert_eq!(
        b.mft_record_size(),
        Some(4_096),
        "a 4K-native volume's records are 4,096 bytes, and the BPB is where that is written"
    );

    // And the positive encoding: n clusters rather than a power of two.
    let mut clusters = alihadi_boot_sector();
    clusters[0x40] = 2;
    let b = NtfsBootSector::parse(&clusters).expect("parse");
    assert_eq!(
        b.mft_record_size(),
        Some(8_192),
        "positive means 2 * cluster_size, not 1 << 2"
    );
}

/// One decoder, asked twice, answers the same.
///
/// `mft_scan_phase` used to hand-decode `0x0B`, `0x0D` and `0x30` itself, and
/// on a volume with clusters above 64 KiB it read the sectors-per-cluster
/// exponent as a count — computing a bogus alignment and finding no records at
/// all. This pins that the two now come from one place.
#[test]
fn the_scan_alignment_and_the_geometry_come_from_the_same_decode() {
    let mut large = alihadi_boot_sector();
    large[0x0D] = 0xF1; // 2^15 sectors per cluster
    let b = NtfsBootSector::parse(&large).expect("parse");
    assert_eq!(b.sectors_per_cluster, 32_768);
    assert_eq!(
        b.cluster_size(),
        512 * 32_768,
        "read as a raw count this would be 241 sectors and every derived number would be wrong"
    );
}
