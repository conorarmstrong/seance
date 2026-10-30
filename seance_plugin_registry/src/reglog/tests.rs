//! Self-contained tests for registry transaction-log replay.
//!
//! Fixtures are built synthetically (minimal hive + log bytes) so the suite is
//! tiny and license-clean. Marvin32 is cross-checked against an independent
//! reference implementation (known-answer vectors).

use super::*;

const SEED: u64 = MARVIN32_SEED;

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// Build a minimal, checksum-valid primary hive: a 0x1000 base block plus one
/// 0x1000 hbin. A 4-byte marker is planted at file offset 0x1050 so a replayed
/// page can be observed to have overwritten it.
fn build_primary_hive(
    primary_seq: u32,
    secondary_seq: u32,
    last_written: u64,
    marker: u32,
) -> Vec<u8> {
    let mut buf = vec![0u8; 0x2000];
    buf[0..4].copy_from_slice(b"regf");
    buf[0x04..0x08].copy_from_slice(&primary_seq.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&secondary_seq.to_le_bytes());
    buf[0x0C..0x14].copy_from_slice(&last_written.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    buf[0x18..0x1C].copy_from_slice(&6u32.to_le_bytes()); // minor version
    buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // file type: primary
    buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // file format
    buf[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell offset
    buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes()); // hbins data size
    buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor

    // hbin at 0x1000.
    buf[0x1000..0x1004].copy_from_slice(b"hbin");
    buf[0x1008..0x100C].copy_from_slice(&0x1000u32.to_le_bytes());
    // Marker inside the hbin.
    buf[0x1050..0x1054].copy_from_slice(&marker.to_le_bytes());

    let checksum = checksum_xor32(&buf);
    buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    buf
}

struct EntrySpec {
    seq: u32,
    hbins_size: u32,
    /// (rel_offset, page bytes) pairs.
    pages: Vec<(u32, Vec<u8>)>,
    corrupt_hash1: bool,
}

/// Serialize one `HvLE` entry with correct Marvin32 hashes (Hash-1 optionally
/// corrupted while keeping Hash-2 valid, to model a partial/torn write).
fn build_hvle_entry(spec: &EntrySpec) -> Vec<u8> {
    let count = spec.pages.len();
    let body: Vec<u8> = spec.pages.iter().flat_map(|(_, b)| b.clone()).collect();
    let unpadded = HVLE_HEADER_LEN + count * 8 + body.len();
    let size = unpadded.next_multiple_of(512).max(512);

    let mut e = vec![0u8; size];
    e[0..4].copy_from_slice(b"HvLE");
    e[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    e[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags
    e[12..16].copy_from_slice(&spec.seq.to_le_bytes());
    e[16..20].copy_from_slice(&spec.hbins_size.to_le_bytes());
    e[20..24].copy_from_slice(&(count as u32).to_le_bytes());

    let mut off = HVLE_HEADER_LEN;
    for (rel, b) in &spec.pages {
        e[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        e[off + 4..off + 8].copy_from_slice(&(b.len() as u32).to_le_bytes());
        off += 8;
    }
    for (_, b) in &spec.pages {
        e[off..off + b.len()].copy_from_slice(b);
        off += b.len();
    }

    // Hash-1 over [40..size]; corrupt after computing so Hash-2 still validates.
    let mut h1 = marvin32(&e[HVLE_HEADER_LEN..size], SEED);
    if spec.corrupt_hash1 {
        h1 ^= 0x1;
    }
    e[0x18..0x20].copy_from_slice(&h1.to_le_bytes());
    // Hash-2 over [0..0x20] (includes Hash-1).
    let h2 = marvin32(&e[0..0x20], SEED);
    e[0x20..0x28].copy_from_slice(&h2.to_le_bytes());
    e
}

/// Build a new-format (`HvLE`) log: a 0x200 base block followed by entries.
fn build_hvle_log(
    primary_seq: u32,
    secondary_seq: u32,
    last_written: u64,
    entries: &[EntrySpec],
) -> Vec<u8> {
    let mut buf = vec![0u8; LOG_ENTRY_START];
    buf[0..4].copy_from_slice(b"regf");
    buf[0x04..0x08].copy_from_slice(&primary_seq.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&secondary_seq.to_le_bytes());
    buf[0x0C..0x14].copy_from_slice(&last_written.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&6u32.to_le_bytes()); // file type: new log
    buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes());
    let checksum = checksum_xor32(&buf);
    buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());

    for spec in entries {
        buf.extend_from_slice(&build_hvle_entry(spec));
    }
    buf
}

/// Build a legacy (`DIRT`) log with file type 1 (the common Vista..Win8 form).
fn build_dirt_log(
    primary_seq: u32,
    last_written: u64,
    hbins_size: u32,
    set_bits: &[usize],
    page_bodies: &[Vec<u8>],
) -> Vec<u8> {
    build_dirt_log_typed(
        1,
        primary_seq,
        last_written,
        hbins_size,
        set_bits,
        page_bodies,
    )
}

/// Build a legacy (`DIRT`) log: 0x200 base block, `DIRT` + bitmap at 0x200, then
/// one 512-byte page body per set bit at the next 512-aligned offset.
/// `file_type` is 1 or 2 (both are legacy logs; 2 is the very old variant).
fn build_dirt_log_typed(
    file_type: u32,
    primary_seq: u32,
    last_written: u64,
    hbins_size: u32,
    set_bits: &[usize],
    page_bodies: &[Vec<u8>],
) -> Vec<u8> {
    let page_count = (hbins_size as usize) / 512;
    let bitmap_bytes = page_count.div_ceil(8);
    let bitmap_start = LOG_ENTRY_START + 4;
    let body_start = (bitmap_start + bitmap_bytes).next_multiple_of(512);

    let mut buf = vec![0u8; body_start + 512 * page_bodies.len()];
    buf[0..4].copy_from_slice(b"regf");
    buf[0x04..0x08].copy_from_slice(&primary_seq.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&primary_seq.to_le_bytes());
    buf[0x0C..0x14].copy_from_slice(&last_written.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&file_type.to_le_bytes()); // file type: legacy log
    buf[0x28..0x2C].copy_from_slice(&hbins_size.to_le_bytes());
    let checksum = checksum_xor32(&buf[0..LOG_ENTRY_START]);
    buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());

    buf[LOG_ENTRY_START..LOG_ENTRY_START + 4].copy_from_slice(b"DIRT");
    for &p in set_bits {
        buf[bitmap_start + p / 8] |= 1 << (p % 8);
    }
    for (i, body) in page_bodies.iter().enumerate() {
        let start = body_start + 512 * i;
        buf[start..start + 512].copy_from_slice(body);
    }
    buf
}

fn read_u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------------------------------------------------------------------------
// Marvin32 known-answer vectors (independent Python reference, seed 0x82EF4D887A4E55C5)
// ---------------------------------------------------------------------------

#[test]
fn marvin32_known_answers() {
    assert_eq!(marvin32(b"", SEED), 0xB39E_FCA4_0396_6E08);
    assert_eq!(marvin32(b"a", SEED), 0x21A0_13C7_26F2_92F4);
    assert_eq!(marvin32(b"ab", SEED), 0x7911_DA00_3172_85F8);
    assert_eq!(marvin32(b"abc", SEED), 0xB9CF_3DFC_A419_14F7);
    assert_eq!(marvin32(b"abcd", SEED), 0x2009_4FB1_1A6C_D086);
    assert_eq!(marvin32(b"abcde", SEED), 0x187F_15F6_2504_6B86);
    assert_eq!(
        marvin32(b"The quick brown fox", SEED),
        0xF47D_A7D0_A5F3_7FB7
    );
}

// ---------------------------------------------------------------------------
// Base block parse + dirty detection
// ---------------------------------------------------------------------------

#[test]
fn base_block_parses_fields_and_checksum() {
    let hive = build_primary_hive(7, 7, 0, 0);
    let bb = parse_base_block(&hive).unwrap();
    assert_eq!(bb.primary_seq, 7);
    assert_eq!(bb.secondary_seq, 7);
    assert_eq!(bb.file_type, 0);
    assert_eq!(bb.hbins_size, 0x1000);
    assert!(bb.checksum_ok);
    assert!(!bb.dirty());
}

#[test]
fn truncated_base_block_is_none() {
    assert!(parse_base_block(&[0u8; 16]).is_none());
    let mut short = vec![0u8; 0x100];
    short[0..4].copy_from_slice(b"regf");
    assert!(parse_base_block(&short).is_none()); // < 0x200
}

#[test]
fn dirty_detection_matrix() {
    // Equal seq + good checksum => clean.
    let clean = build_primary_hive(5, 5, 0, 0);
    assert!(!parse_base_block(&clean).unwrap().dirty());

    // Mismatched seq => dirty.
    let mism = build_primary_hive(6, 4, 0, 0);
    assert!(parse_base_block(&mism).unwrap().dirty());

    // Equal seq but corrupted checksum => dirty.
    let mut badck = build_primary_hive(5, 5, 0, 0);
    badck[CHECKSUM_OFFSET] ^= 0xFF;
    let bb = parse_base_block(&badck).unwrap();
    assert!(!bb.checksum_ok);
    assert!(bb.dirty());
}

#[test]
fn hive_file_type_identifies_logs() {
    let hive = build_primary_hive(1, 1, 0, 0);
    assert_eq!(hive_file_type(&hive), Some(0));
    let newlog = build_hvle_log(1, 1, 0, &[]);
    assert_eq!(hive_file_type(&newlog), Some(6));
    let legacy = build_dirt_log(1, 0, 0x1000, &[], &[]);
    assert_eq!(hive_file_type(&legacy), Some(1));
}

// ---------------------------------------------------------------------------
// recover_hive: clean / missing / dirty-new / dirty-legacy / gap / hash / oob
// ---------------------------------------------------------------------------

#[test]
fn clean_hive_is_zero_copy_and_unmodified() {
    let hive = build_primary_hive(9, 9, 132_223_104_000_000_000, 0xAAAA);
    let (out, prov) = recover_hive(&hive, None, None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(out.as_ref(), hive.as_slice());
    assert!(!prov.dirty);
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "clean");
    assert_eq!(prov.log_format, "none");
}

#[test]
fn dirty_hive_with_no_logs_reports_no_logs_found() {
    let hive = build_primary_hive(4, 2, 0, 0xAAAA);
    let (out, prov) = recover_hive(&hive, None, None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(prov.dirty);
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "no_logs_found");
    // Fall-back parse still sees the original bytes.
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn dirty_new_format_recovers_across_both_logs() {
    // primary 4 / secondary 2: entries 3 and 4 pending, split across LOG1/LOG2.
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    // Each entry rewrites the 4-byte marker at rel offset 0x50 (file 0x1050).
    let log1 = build_hvle_log(
        4,
        2,
        130_000_000_000_000_000,
        &[EntrySpec {
            seq: 3,
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xAAAA_AAAAu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );
    let log2 = build_hvle_log(
        4,
        2,
        131_000_000_000_000_000,
        &[EntrySpec {
            seq: 4,
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xBBBB_BBBBu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );

    let (out, prov) = recover_hive(&hive, Some(&log1), Some(&log2));
    assert!(matches!(out, std::borrow::Cow::Owned(_)));
    assert!(prov.dirty);
    assert!(prov.replayed);
    assert_eq!(prov.reason, "recovered");
    assert_eq!(prov.log_format, "new_hvle");
    assert_eq!(prov.entries_applied, 2);
    assert_eq!(prov.pages_applied, 2);
    assert_eq!(prov.bytes_applied, 8);
    assert_eq!(prov.applied_start_seq, Some(3));
    assert_eq!(prov.applied_end_seq, Some(4));
    // Marker reflects the LAST applied entry (seq 4).
    assert_eq!(read_u32_at(&out, 0x1050), 0xBBBB_BBBB);
    // Base block was made consistent: primary == secondary == last applied.
    assert_eq!(read_u32_at(&out, 0x04), 4);
    assert_eq!(read_u32_at(&out, 0x08), 4);
    let bb = parse_base_block(&out).unwrap();
    assert!(
        bb.checksum_ok,
        "recovered base block checksum must validate"
    );
    // A real, citable last-flushed timestamp came from the last log's base block.
    assert!(prov.last_written_after.is_some());
}

#[test]
fn dirty_legacy_dirt_replays_bitmap_pages() {
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    // Page 0 covers file 0x1000..0x1200; rewrite the marker within a copy of it.
    let mut page0 = hive[0x1000..0x1200].to_vec();
    page0[0x50..0x54].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    let log = build_dirt_log(3, 129_000_000_000_000_000, 0x1000, &[0], &[page0]);

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(matches!(out, std::borrow::Cow::Owned(_)));
    assert!(prov.replayed);
    assert_eq!(prov.reason, "recovered");
    assert_eq!(prov.log_format, "legacy_dirt");
    assert_eq!(prov.pages_applied, 1);
    assert_eq!(prov.entries_applied, 1);
    assert_eq!(read_u32_at(&out, 0x1050), 0xCAFE_BABE);
    // hbin header inside the replayed page was preserved (not clobbered).
    assert_eq!(&out[0x1000..0x1004], b"hbin");
}

#[test]
fn sequence_gap_stops_after_last_contiguous_entry() {
    // secondary 2: LOG1 has seq 3, LOG2 has seq 5 (4 is missing).
    let hive = build_primary_hive(5, 2, 0, 0x1111_1111);
    let log1 = build_hvle_log(
        5,
        2,
        130_000_000_000_000_000,
        &[EntrySpec {
            seq: 3,
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xAAAA_AAAAu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );
    let log2 = build_hvle_log(
        5,
        2,
        131_000_000_000_000_000,
        &[EntrySpec {
            seq: 5,
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xBBBB_BBBBu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );

    let (out, prov) = recover_hive(&hive, Some(&log1), Some(&log2));
    assert_eq!(prov.reason, "sequence_gap");
    assert_eq!(prov.entries_applied, 1);
    assert_eq!(prov.pages_applied, 1);
    assert_eq!(prov.applied_end_seq, Some(3));
    // Only the seq-3 page was applied; the seq-5 page was NOT.
    assert_eq!(read_u32_at(&out, 0x1050), 0xAAAA_AAAA);
}

#[test]
fn corrupt_hash_entry_is_refused_fail_closed() {
    let hive = build_primary_hive(3, 2, 0, 0x1111_1111);
    let log = build_hvle_log(
        3,
        2,
        130_000_000_000_000_000,
        &[EntrySpec {
            seq: 3,
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xAAAA_AAAAu32.to_le_bytes().to_vec())],
            corrupt_hash1: true,
        }],
    );

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "hash_mismatch");
    assert_eq!(prov.entries_applied, 0);
    // The stale marker is untouched (no page from a bad-hash entry applied).
    assert_eq!(read_u32_at(&out, 0x1050), 0x1111_1111);
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn page_reference_out_of_range_is_refused() {
    let hive = build_primary_hive(3, 2, 0, 0x1111_1111);
    // rel offset 0x2000 lands past the declared hive-bins region (0x1000).
    let log = build_hvle_log(
        3,
        2,
        130_000_000_000_000_000,
        &[EntrySpec {
            seq: 3,
            hbins_size: 0x1000,
            pages: vec![(0x2000, 0xAAAA_AAAAu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "page_out_of_range");
    assert_eq!(prov.pages_applied, 0);
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn log_fed_as_hive_is_not_recovered() {
    // A .LOG1 handed in as the "hive": file_type 6, never treated as primary.
    let log = build_hvle_log(4, 4, 0, &[]);
    let (out, prov) = recover_hive(&log, None, None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(prov.reason, "not_a_primary_hive");
    assert!(!prov.replayed);
}

#[test]
fn growing_hive_page_extends_buffer() {
    // Entry declares a larger hive-bins region and writes a page into the new
    // area; the buffer must grow to receive it (region-grow, not fabrication).
    let hive = build_primary_hive(3, 2, 0, 0x1111_1111);
    assert_eq!(hive.len(), 0x2000);
    let new_page = vec![0x5Au8; 0x40];
    let log = build_hvle_log(
        3,
        2,
        130_000_000_000_000_000,
        &[EntrySpec {
            seq: 3,
            hbins_size: 0x2000,                      // hive grew by one hbin
            pages: vec![(0x1000, new_page.clone())], // file offset 0x2000
            corrupt_hash1: false,
        }],
    );

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(prov.replayed);
    assert_eq!(prov.reason, "recovered");
    assert!(out.len() >= 0x2040, "buffer should have grown");
    assert_eq!(&out[0x2000..0x2040], new_page.as_slice());
}

// ---------------------------------------------------------------------------
// Legacy log selection + eligibility (bugs.md BUG-216 .. BUG-219)
// ---------------------------------------------------------------------------

/// A 512-byte legacy dirty page: a copy of the hive's first page with the marker
/// at 0x50 rewritten, so an applied page is observable at file offset 0x1050.
fn legacy_page0(hive: &[u8], marker: u32) -> Vec<u8> {
    let mut page = hive[HBIN_BASE..HBIN_BASE + 512].to_vec();
    page[0x50..0x54].copy_from_slice(&marker.to_le_bytes());
    page
}

#[test]
fn legacy_dual_logs_replay_the_newer_log() {
    // BUG-216: LOG1 is the OLDER of the pair. Taking logs[0] blindly would apply
    // its stale page; the newer log (by base-block last_written) must win.
    let hive = build_primary_hive(4, 2, 127_000_000_000_000_000, 0x1111_1111);
    let older = build_dirt_log(
        3,
        128_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xAAAA_AAAA)],
    );
    let newer = build_dirt_log(
        3,
        130_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xBBBB_BBBB)],
    );

    let (out, prov) = recover_hive(&hive, Some(&older), Some(&newer));
    assert!(prov.replayed);
    assert_eq!(prov.reason, "recovered");
    assert_eq!(prov.log_format, "legacy_dirt");
    assert_eq!(prov.pages_applied, 1);
    assert_eq!(read_u32_at(&out, 0x1050), 0xBBBB_BBBB);
    // The citable post-replay timestamp comes from the log actually used.
    assert_eq!(prov.last_written_after, ft(130_000_000_000_000_000));
}

#[test]
fn legacy_falls_back_when_the_newer_log_is_unusable() {
    // BUG-216: newest candidate is structurally broken (no DIRT signature); the
    // older, valid log must still be replayed instead of failing outright.
    let hive = build_primary_hive(4, 2, 127_000_000_000_000_000, 0x1111_1111);
    let good = build_dirt_log(
        3,
        128_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xAAAA_AAAA)],
    );
    let mut broken = build_dirt_log(
        3,
        131_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xBBBB_BBBB)],
    );
    broken[LOG_ENTRY_START..LOG_ENTRY_START + 4].copy_from_slice(b"XXXX");

    let (out, prov) = recover_hive(&hive, Some(&broken), Some(&good));
    assert!(prov.replayed);
    assert_eq!(prov.reason, "recovered");
    assert_eq!(read_u32_at(&out, 0x1050), 0xAAAA_AAAA);
}

#[test]
fn legacy_refuses_replay_when_hive_is_clean() {
    // BUG-217: a clean primary is complete on disk. A DIRT snapshot beside it can
    // only revert pages, so it must not be applied or stamped `recovered`.
    let hive = build_primary_hive(5, 5, 130_000_000_000_000_000, 0x1111_1111);
    let log = build_dirt_log(
        5,
        131_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xCAFE_BABE)],
    );

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(!prov.dirty);
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "clean");
    assert_eq!(prov.pages_applied, 0);
    assert_eq!(read_u32_at(&out, 0x1050), 0x1111_1111);
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn legacy_refuses_log_older_than_the_hive() {
    // BUG-217: dirty hive, but the log predates it (last_written). Applying it
    // would overwrite newer pages with stale ones.
    let hive = build_primary_hive(4, 2, 132_000_000_000_000_000, 0x1111_1111);
    let stale = build_dirt_log(
        3,
        129_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xDEAD_BEEF)],
    );

    let (out, prov) = recover_hive(&hive, Some(&stale), None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(prov.dirty);
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "log_older_than_hive");
    assert_eq!(prov.pages_applied, 0);
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn legacy_refuses_log_with_invalid_base_block() {
    // BUG-217: the log's own base-block checksum fails => torn log header, so
    // nothing behind it is trustworthy.
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    let mut log = build_dirt_log(
        3,
        129_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xDEAD_BEEF)],
    );
    log[CHECKSUM_OFFSET] ^= 0xFF;

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert!(!prov.replayed);
    assert_eq!(prov.reason, "log_base_block_invalid");
    assert_eq!(out.as_ref(), hive.as_slice());
}

#[test]
fn legacy_file_type_two_is_recognised_as_a_log() {
    // BUG-218: file type 2 is the very old legacy log variant. It must be
    // suppressed as a standalone "hive" and offered to the legacy replay path.
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    let log = build_dirt_log_typed(
        2,
        3,
        129_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0x0BAD_F00D)],
    );

    assert_eq!(hive_file_type(&log), Some(2));
    assert!(is_log_file_type(2));
    // Fed directly as a "hive" it is never parsed as one.
    assert_eq!(
        recover_hive(&log, None, None).1.reason,
        "not_a_primary_hive"
    );

    let (out, prov) = recover_hive(&hive, Some(&log), None);
    assert!(prov.replayed);
    assert_eq!(prov.log_format, "legacy_dirt");
    assert_eq!(prov.reason, "recovered");
    assert_eq!(read_u32_at(&out, 0x1050), 0x0BAD_F00D);
}

#[test]
fn mixed_format_logs_do_not_hide_the_new_format_log() {
    // BUG-219: a legacy leftover ordered first must not force the whole pair down
    // the DIRT path and drop the HvLE chain.
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    let legacy = build_dirt_log(
        3,
        129_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xAAAA_AAAA)],
    );
    let hvle = build_hvle_log(
        4,
        2,
        131_000_000_000_000_000,
        &[
            EntrySpec {
                seq: 3,
                hbins_size: 0x1000,
                pages: vec![(0x50, 0xBBBB_BBBBu32.to_le_bytes().to_vec())],
                corrupt_hash1: false,
            },
            EntrySpec {
                seq: 4,
                hbins_size: 0x1000,
                pages: vec![(0x50, 0xCCCC_CCCCu32.to_le_bytes().to_vec())],
                corrupt_hash1: false,
            },
        ],
    );

    let (out, prov) = recover_hive(&hive, Some(&legacy), Some(&hvle));
    assert!(prov.replayed);
    assert_eq!(prov.log_format, "new_hvle");
    assert_eq!(prov.reason, "recovered");
    assert_eq!(prov.entries_applied, 2);
    assert_eq!(read_u32_at(&out, 0x1050), 0xCCCC_CCCC);
}

#[test]
fn mixed_format_falls_back_to_legacy_when_hvle_yields_nothing() {
    // BUG-219: the HvLE log holds only an already-committed entry, so the legacy
    // log beside it is still the best available evidence.
    let hive = build_primary_hive(4, 2, 0, 0x1111_1111);
    let hvle = build_hvle_log(
        4,
        2,
        131_000_000_000_000_000,
        &[EntrySpec {
            seq: 2, // <= secondary_seq: already in the hive
            hbins_size: 0x1000,
            pages: vec![(0x50, 0xBBBB_BBBBu32.to_le_bytes().to_vec())],
            corrupt_hash1: false,
        }],
    );
    let legacy = build_dirt_log(
        3,
        129_000_000_000_000_000,
        0x1000,
        &[0],
        &[legacy_page0(&hive, 0xAAAA_AAAA)],
    );

    let (out, prov) = recover_hive(&hive, Some(&hvle), Some(&legacy));
    assert!(prov.replayed);
    assert_eq!(prov.log_format, "legacy_dirt");
    assert_eq!(prov.reason, "recovered");
    assert_eq!(read_u32_at(&out, 0x1050), 0xAAAA_AAAA);
}
