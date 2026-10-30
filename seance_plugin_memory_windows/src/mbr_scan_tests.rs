//! The MBR sweep: every sector-aligned `55 AA` candidate is decoded and held
//! to the partition table's own rules, and the sweep states its bounds.

use super::mbr_scan::*;
use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};

fn layer(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
}

/// A partition entry: status, type, first LBA, sector count. CHS fields are
/// left zero, which the checks do not read.
fn entry(status: u8, kind: u8, lba: u32, sectors: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = kind;
    e[8..12].copy_from_slice(&lba.to_le_bytes());
    e[12..16].copy_from_slice(&sectors.to_le_bytes());
    e
}

fn sector(signature: u32, entries: &[[u8; 16]]) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[..8].copy_from_slice(b"\x33\xc0\x8e\xd0\xbc\x00\x7c\xfb");
    s[440..444].copy_from_slice(&signature.to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        s[446 + i * 16..462 + i * 16].copy_from_slice(e);
    }
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

/// A well-formed MBR: one active NTFS partition.
fn ntfs_mbr() -> [u8; 512] {
    sector(0xDEAD_BEEF, &[entry(0x80, 0x07, 2048, 204_800)])
}

/// A GPT disk's protective MBR: one `0xEE` entry from LBA 1.
fn protective_mbr() -> [u8; 512] {
    sector(0, &[entry(0x00, 0xEE, 1, 134_217_727)])
}

fn image(sectors: &[(u64, [u8; 512])]) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8000];
    for (at, s) in sectors {
        bytes[*at as usize..*at as usize + 512].copy_from_slice(s);
    }
    bytes
}

fn scan(bytes: Vec<u8>) -> MbrScan {
    scan_for_mbrs(&*layer(bytes), &MbrScanConfig::default())
}

/// **A well-formed MBR is decoded whole**: the signature, every entry, and
/// each check it passed.
#[test]
fn a_well_formed_mbr_is_decoded_with_its_partitions_and_checks() {
    let out = scan(image(&[(0x1000, ntfs_mbr())]));
    assert_eq!(out.candidates.len(), 1);
    let mbr = &out.candidates[0];
    assert_eq!(mbr.offset, 0x1000);
    assert_eq!(mbr.disk_signature, 0xDEAD_BEEF);
    assert!(mbr.well_formed, "{:?}", mbr.checks);
    assert_eq!(mbr.kind, MbrKind::Mbr);
    let partitions: Vec<_> = mbr.partitions.iter().filter(|p| !p.is_empty()).collect();
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].partition_type, 0x07);
    assert!(partitions[0].active);
    assert_eq!(partitions[0].first_lba, 2048);
    assert_eq!(partitions[0].sectors, 204_800);
    assert_eq!(partitions[0].type_name, Some("NTFS/exFAT/HPFS (IFS)"));
    assert!(mbr.checks.iter().all(|c| c.passed), "{:?}", mbr.checks);
    assert_eq!(mbr.boot_code_sha256.len(), 64);
    assert!(!mbr.boot_code_empty);
}

/// **A GPT disk's protective MBR is recognised as one**, by its single `0xEE`
/// entry, and reported as that rather than as a one-partition MBR disk.
#[test]
fn a_protective_mbr_is_recognised_by_its_ee_entry() {
    let out = scan(image(&[(0x2000, protective_mbr())]));
    assert_eq!(out.candidates.len(), 1);
    let mbr = &out.candidates[0];
    assert_eq!(mbr.kind, MbrKind::GptProtective);
    assert!(mbr.well_formed);
    assert_eq!(mbr.partitions[0].first_lba, 1);
}

/// **A sector that ends in `55 AA` and is not an MBR** — a filesystem boot
/// sector, whose partition-table bytes are code — is a candidate that fails
/// its checks, reported with the checks it failed, never as a disk.
#[test]
fn a_boot_sector_that_is_not_an_mbr_fails_its_checks_and_is_still_reported() {
    let mut vbr = [0u8; 512];
    vbr[..11].copy_from_slice(b"\xebR\x90NTFS    ");
    for (i, b) in vbr[446..510].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    vbr[510] = 0x55;
    vbr[511] = 0xAA;
    let out = scan(image(&[(0x3000, vbr)]));
    assert_eq!(out.sectors_with_signature, 1);
    assert_eq!(out.candidates.len(), 1);
    let candidate = &out.candidates[0];
    assert!(!candidate.well_formed);
    assert_eq!(candidate.kind, MbrKind::NotAPartitionTable);
    assert!(candidate.checks.iter().any(|c| !c.passed));
    assert_eq!(out.well_formed(), 0);
}

/// **Only sector-aligned candidates are examined.** A `55 AA` that happens to
/// fall at byte 510 of nothing is not a sector, and a real MBR that is not
/// 512-byte aligned cannot have come from a disk buffer.
#[test]
fn only_sector_aligned_signatures_are_candidates() {
    let mut bytes = image(&[(0x1000, ntfs_mbr())]);
    // A second copy at an unaligned offset.
    bytes[0x4100..0x4300].copy_from_slice(&ntfs_mbr());
    let out = scan(bytes);
    assert_eq!(out.sectors_with_signature, 1);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(out.candidates[0].offset, 0x1000);
}

/// **Two entries that overlap fail the overlap check**, which is the check a
/// forged table most often fails.
#[test]
fn overlapping_partitions_fail_the_overlap_check() {
    let s = sector(
        1,
        &[
            entry(0x80, 0x07, 2048, 100_000),
            entry(0x00, 0x07, 50_000, 100_000),
        ],
    );
    let out = scan(image(&[(0x1000, s)]));
    let mbr = &out.candidates[0];
    assert!(!mbr.well_formed);
    let overlap = mbr
        .checks
        .iter()
        .find(|c| c.name == "no_overlap")
        .expect("the overlap check is made");
    assert!(!overlap.passed);
}

/// **The sweep states its bounds**: bytes examined, unread bytes, and the cap,
/// so an empty candidate list is a statement about the bytes examined.
#[test]
fn the_sweep_states_its_bounds() {
    let out = scan(image(&[]));
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.sectors_with_signature, 0);
    assert_eq!(out.scan.bytes_scanned, 0x8000);
    assert!(out.is_complete());
    let json = out.to_json();
    assert_eq!(json["bytes_scanned"], serde_json::json!(0x8000));
    assert_eq!(json["sectors_with_signature"], serde_json::json!(0));
    assert_eq!(json["content_complete"], serde_json::json!(true));
    assert!(json["basis"].as_str().unwrap_or_default().contains("512"));
}

/// **The candidate cap is a stated ceiling, not a silent truncation.**
#[test]
fn the_candidate_cap_is_reported() {
    let sectors: Vec<(u64, [u8; 512])> = (0..6u64)
        .map(|i| (0x1000 + i * 0x400, ntfs_mbr()))
        .collect();
    let out = scan_for_mbrs(
        &*layer(image(&sectors)),
        &MbrScanConfig {
            max_candidates: 4,
            ..MbrScanConfig::default()
        },
    );
    assert_eq!(out.sectors_with_signature, 6);
    assert_eq!(out.candidates.len(), 4);
    assert!(out.candidates_truncated);
    assert!(!out.is_complete());
}
