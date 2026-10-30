//! Mechanism tests over volumes built in memory from ECMA-167 / OSTA UDF 1.02
//! (see `test_builder`). They pin how the reader behaves; they are not
//! validation on real evidence.

use super::*;
use crate::test_builder::{seal, Layout, UdfBuilder, BS};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;
use uuid::Uuid;

fn fs_artifact(img: Vec<u8>) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({"filesystem_type": "UDF", "subtype": "udf"}),
    )
}

fn run(img: Vec<u8>) -> Vec<Artifact> {
    UdfParser.process(&fs_artifact(img)).expect("process")
}

fn entries(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect()
}

fn volume(out: &[Artifact]) -> &serde_json::Value {
    &out.iter()
        .find(|a| {
            a.artifact_type == ArtifactType::ParsedRecord
                && a.metadata["type"].as_str() == Some("udf_volume")
        })
        .expect("a udf_volume record")
        .metadata
}

fn by_path<'a>(out: &'a [Artifact], path: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("no entry {path}"))
}

fn content(a: &Artifact) -> Vec<u8> {
    let ds = a.data.as_ref().expect("content");
    let mut buf = vec![0u8; ds.size() as usize];
    let n = ds.read_at(0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn corrupt(img: &mut [u8], sector: usize, byte: usize) {
    img[sector * BS + byte] ^= 0xFF;
}

fn basic() -> UdfBuilder {
    let mut b = UdfBuilder::new();
    b.file(0, "README.TXT", b"hello udf", Layout::Short);
    b
}

// --- S2: the descriptor layer ---------------------------------------------

#[test]
fn anchor_at_256_is_found() {
    let out = run(basic().build());
    let v = volume(&out);
    assert_eq!(v["anchor_sector"], 256);
    assert_eq!(v["volume_descriptor_sequence"], "main");
    assert_eq!(v["logical_volume_identifier"], "TESTLV");
    assert_eq!(v["volume_set_identifier"], "0123456789ABCDEFTESTSET");
    assert_eq!(v["domain_identifier"], "*OSTA UDF Compliant");
    assert_eq!(v["udf_revision"], "1.02");
    assert_eq!(v["partition_start"], 272);
    assert_eq!(entries(&out).len(), 1);
}

#[test]
fn anchor_falls_back_to_last_sector_when_256_is_blank() {
    let mut img = basic().build();
    img[256 * BS..257 * BS].fill(0);
    let last = img.len() / BS - 1;
    let out = run(img);
    assert_eq!(volume(&out)["anchor_sector"], last as u64);
    assert_eq!(entries(&out).len(), 1);
}

#[test]
fn tag_with_bad_crc_is_refused_with_reason() {
    let mut img = basic().build();
    let last = img.len() / BS - 1;
    // Damage a body byte of both anchors: the checksum still holds, the CRC
    // does not.
    corrupt(&mut img, 256, 40);
    corrupt(&mut img, last, 40);
    let out = run(img);
    let v = volume(&out);
    assert_eq!(v["udf_unreadable"], true);
    let why = v["udf_unreadable_reason"].as_str().unwrap();
    assert!(why.contains("descriptor_crc_mismatch"), "{why}");
    assert!(entries(&out).is_empty());
}

#[test]
fn main_vds_corrupt_falls_back_to_reserve() {
    let mut img = basic().build();
    corrupt(&mut img, 259, 100); // the main LVD's body
    let out = run(img);
    let v = volume(&out);
    assert_eq!(v["volume_descriptor_sequence"], "reserve");
    assert!(v["main_volume_descriptor_sequence_error"]
        .as_str()
        .unwrap()
        .contains("sector_259"));
    assert_eq!(entries(&out).len(), 1);
}

#[test]
fn type2_partition_map_of_an_unknown_kind_is_refused_and_named() {
    let mut b = basic();
    b.type2_map = Some("*UDF Imagined Partition");
    let out = run(b.build());
    let v = volume(&out);
    assert_eq!(
        v["udf_unsupported_partition_map"],
        "*UDF Imagined Partition"
    );
    assert_eq!(v["udf_unreadable"], true);
    assert!(
        entries(&out).is_empty(),
        "nothing is guessed past a refused map"
    );
}

#[test]
fn non_udf_filesystem_artifact_is_ignored() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(basic().build()));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({"filesystem_type": "ISO9660", "subtype": "iso9660"}),
    );
    assert!(UdfParser.process(&a).unwrap().is_empty());
}

#[test]
fn file_set_descriptor_names_are_published() {
    let out = run(basic().build());
    let v = volume(&out);
    assert_eq!(v["file_set_identifier"], "TESTSET");
    assert_eq!(v["block_size"], 2048);
}

// --- S3: the directory walk -----------------------------------------------

#[test]
fn root_with_two_files_emits_two_file_entries_with_paths() {
    let mut b = UdfBuilder::new();
    let d = b.dir(0, "docs");
    b.file(0, "a.txt", b"AAA", Layout::Short);
    b.file(d, "b.txt", b"BBBB", Layout::Short);
    let out = run(b.build());
    let e = entries(&out);
    assert_eq!(e.len(), 3);
    let a = by_path(&out, "/a.txt");
    assert_eq!(a.metadata["size"], 3);
    assert_eq!(a.metadata["is_directory"], false);
    assert_eq!(content(a), b"AAA");
    let docs = by_path(&out, "/docs");
    assert_eq!(docs.metadata["is_directory"], true);
    let bb = by_path(&out, "/docs/b.txt");
    assert_eq!(bb.metadata["parent_path"], "/docs");
    assert_eq!(content(bb), b"BBBB");
    assert_eq!(bb.metadata["uid"], 1000);
    assert_eq!(bb.metadata["gid"], 100);
    assert_eq!(bb.metadata["modified"], "2024-03-02T11:30:00+01:00");
    assert_eq!(bb.metadata["accessed"], "2024-03-01T10:00:00+00:00");
    assert!(
        bb.metadata.get("created").is_none(),
        "a plain FE has no creation time"
    );
    assert!(volume(&out).get("directory_parse_incomplete").is_none());
}

#[test]
fn cs0_16bit_name_decodes_utf16be() {
    let mut b = UdfBuilder::new();
    let f = b.file(0, "\u{3a9}mega.txt", b"x", Layout::Short);
    b.nodes[f].utf16 = true;
    let out = run(b.build());
    by_path(&out, "/\u{3a9}mega.txt");
}

#[test]
fn embedded_data_content_is_icb_tail() {
    let mut b = UdfBuilder::new();
    b.file(0, "tiny", b"inside the entry", Layout::Embedded);
    let out = run(b.build());
    let t = by_path(&out, "/tiny");
    assert_eq!(content(t), b"inside the entry");
    assert_eq!(t.metadata["size"], 16);
}

#[test]
fn long_ad_multi_extent_file_reads_contiguous_content() {
    let data: Vec<u8> = (0..3 * BS + 100).map(|i| (i * 7 % 251) as u8).collect();
    let mut b = UdfBuilder::new();
    b.file(0, "big.bin", &data, Layout::Long { split: 2 * BS });
    let out = run(b.build());
    let f = by_path(&out, "/big.bin");
    assert_eq!(content(f), data);
    assert_eq!(f.metadata["data_runs"].as_array().unwrap().len(), 2);
    assert_eq!(f.metadata["data_runs_complete"], true);
}

#[test]
fn allocation_extent_descriptor_chain_is_followed() {
    let data: Vec<u8> = (0..BS + 700).map(|i| (i % 13) as u8).collect();
    let mut b = UdfBuilder::new();
    b.file(0, "chained", &data, Layout::Continued);
    let out = run(b.build());
    let f = by_path(&out, "/chained");
    assert_eq!(content(f), data);
    assert!(f.metadata.get("content_incomplete").is_none());
}

#[test]
fn unrecorded_extent_reads_as_zero_hole() {
    let mut data = vec![0x11u8; BS];
    data.extend(vec![0u8; BS]);
    data.extend(vec![0x22u8; 300]);
    let mut b = UdfBuilder::new();
    b.file(0, "sparse", &data, Layout::HoleAfterFirstBlock);
    let out = run(b.build());
    let f = by_path(&out, "/sparse");
    // The hole block on disc holds 0xEE; it must read as zeros.
    assert_eq!(content(f), data);
    let runs = f.metadata["data_runs"].as_array().unwrap();
    assert!(runs[1][0].is_null(), "{runs:?}");
}

#[test]
fn deleted_fid_emitted_marked_deleted() {
    let mut b = UdfBuilder::new();
    let f = b.file(0, "gone.txt", b"was here", Layout::Short);
    b.nodes[f].deleted = true;
    let h = b.file(0, "quiet.txt", b"q", Layout::Short);
    b.nodes[h].hidden = true;
    let out = run(b.build());
    let g = by_path(&out, "/gone.txt");
    assert_eq!(g.metadata["deleted"], true);
    assert_eq!(g.metadata["deleted_icb_may_be_reused"], true);
    assert_eq!(by_path(&out, "/quiet.txt").metadata["hidden"], true);
}

#[test]
fn directory_icb_loop_cut_and_flagged_incomplete() {
    let mut b = UdfBuilder::new();
    let d = b.dir(0, "sub");
    b.loop_to_root(d, "back");
    b.file(0, "f", b"f", Layout::Short);
    let out = run(b.build());
    let back = by_path(&out, "/sub/back");
    assert_eq!(back.metadata["directory_parse_incomplete"], true);
    assert_eq!(
        back.metadata["directory_parse_incomplete_reason"],
        "cyclic_icb"
    );
    assert_eq!(volume(&out)["directory_parse_incomplete"], true);
    // Each real entry once: sub, sub/back, f.
    assert_eq!(entries(&out).len(), 3);
}

#[test]
fn extent_past_partition_end_flagged_content_incomplete() {
    let mut b = UdfBuilder::new();
    b.file(0, "past", &vec![1u8; 3 * BS], Layout::PastEnd);
    let out = run(b.build());
    let f = by_path(&out, "/past");
    assert_eq!(f.metadata["content_incomplete"], true);
    assert_eq!(
        f.metadata["udf_content_problem"],
        "extent_outside_partition"
    );
    assert_eq!(f.metadata["data_runs_complete"], false);
}

#[test]
fn extent_past_end_of_truncated_evidence_is_flagged_short_read() {
    // A truncated acquisition: the partition says the blocks exist, the
    // evidence ends before them. The entry must not claim full content.
    let mut b = UdfBuilder::new();
    b.file(0, "a", b"small", Layout::Short);
    b.file(0, "big", &vec![7u8; 4 * BS], Layout::Short);
    let img = b.build();
    let full = run(img.clone());
    let off = by_path(&full, "/big").metadata["data_runs"][0][0]
        .as_u64()
        .expect("big has a recorded run");
    assert_eq!(by_path(&full, "/big").metadata["data_runs_complete"], true);
    // Cut the image one block into big's content.
    let cut = img[..off as usize + BS].to_vec();
    let out = run(cut);
    let big = by_path(&out, "/big");
    assert_eq!(big.metadata["content_incomplete"], true);
    assert_eq!(big.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(
        big.metadata["udf_content_problem"],
        "extent_past_end_of_evidence"
    );
    assert_eq!(big.metadata["data_runs_complete"], false);
    let a = by_path(&out, "/a");
    assert!(a.metadata.get("content_incomplete").is_none());
    let v = volume(&out);
    assert_eq!(v["partition_extends_past_evidence"], true);
    assert!(v["evidence_size"].as_u64().is_some());
}

#[test]
fn nested_directory_failure_reason_reaches_the_volume_record() {
    let mut b = UdfBuilder::new();
    let d = b.dir(0, "sub");
    b.loop_to_root(d, "back");
    let out = run(b.build());
    let v = volume(&out);
    assert_eq!(v["directory_parse_incomplete"], true);
    assert_eq!(v["directory_parse_incomplete_reason"], "cyclic_icb");
}

#[test]
fn virtual_partition_without_a_vat_is_refused_and_named() {
    // A virtual map whose VAT is nowhere in the evidence: the volume is not
    // read through a table that was not found.
    let mut b = basic();
    b.type2_map = Some("*UDF Virtual Partition");
    let out = run(b.build());
    let v = volume(&out);
    assert_eq!(v["udf_unreadable"], true);
    assert!(
        v["udf_partition_map_unresolved"]
            .as_str()
            .unwrap()
            .starts_with("virtual_allocation_table_not_found"),
        "{v}"
    );
    assert!(entries(&out).is_empty());
}

#[test]
fn anchor_on_4k_sector_media_is_found_at_that_size() {
    // A 4 KiB-sector volume: the AVDP is at sector 256 of 4096 bytes. It is
    // found there, and the sequence it points at is read in 4096-byte
    // sectors (here there is none, so the refusal names the sequence, not
    // "no anchor"). Reading whole 4096-byte volumes is graded on the
    // makefs corpus (tests/udf_variants_corpus.rs).
    const S4K: usize = 4096;
    let mut img = vec![0u8; 300 * S4K];
    let d = &mut img[256 * S4K..257 * S4K];
    d[16..20].copy_from_slice(&(4 * S4K as u32).to_le_bytes());
    d[20..24].copy_from_slice(&257u32.to_le_bytes());
    seal(d, crate::tag::ident::AVDP, 256, 512);
    let out = run(img);
    let v = volume(&out);
    assert_eq!(v["udf_unreadable"], true);
    assert!(
        v["udf_unreadable_reason"]
            .as_str()
            .unwrap()
            .starts_with("main sequence:"),
        "{v}"
    );
    assert_eq!(v["sector_size"], 4096);
    assert_eq!(v["anchor_sector"], 256);
    assert!(entries(&out).is_empty());
}

#[test]
fn extended_allocation_descriptors_are_refused_and_named() {
    let mut b = UdfBuilder::new();
    b.file(0, "ext", b"12345", Layout::Extended);
    let out = run(b.build());
    let f = by_path(&out, "/ext");
    assert_eq!(
        f.metadata["icb_unreadable_reason"],
        "extended_allocation_descriptors_unsupported"
    );
    assert_eq!(f.metadata["content_incomplete"], true);
    assert!(f.data.is_none());
}

#[test]
fn icb_strategy_4096_is_refused_and_named() {
    let mut b = basic();
    b.strategy = 4096;
    let out = run(b.build());
    let v = volume(&out);
    assert_eq!(v["directory_parse_incomplete"], true);
    assert_eq!(
        v["directory_parse_incomplete_reason"],
        "icb_strategy_unsupported"
    );
}

#[test]
fn efe_creation_time_published() {
    let mut b = basic();
    b.efe = true;
    let out = run(b.build());
    let f = by_path(&out, "/README.TXT");
    assert_eq!(f.metadata["created"], "2023-12-25T08:00:00+00:00");
    assert_eq!(f.metadata["udf_extended_file_entry"], true);
    assert_eq!(content(f), b"hello udf");
}

#[test]
fn bad_fid_tag_stops_directory_and_says_so() {
    let mut b = UdfBuilder::new();
    b.file(0, "a", b"a", Layout::Short);
    let mut img = b.build();
    // Root directory FIDs sit at partition block 4 (FSD 0, spare 1, ICBs 2-3).
    let fids = (272 + 4) * BS;
    // The second FID (after the 40-byte parent FID) — damage its body.
    img[fids + 40 + 20] ^= 0xFF;
    let out = run(img);
    let v = volume(&out);
    assert_eq!(v["directory_parse_incomplete"], true);
    assert_eq!(
        v["directory_parse_incomplete_reason"],
        "file_identifier_descriptor_invalid"
    );
}

#[test]
fn builder_seal_matches_tag_verifier() {
    let mut d = vec![0u8; 64];
    seal(&mut d, crate::tag::ident::TD, 9, 64);
    crate::tag::verify(&d, Some(crate::tag::ident::TD), Some(9)).unwrap();
}

/// Writes the builder's volumes as a fuzz seed corpus. Run on demand:
/// `SEANCE_UDF_FUZZ_SEEDS=fuzz/corpus/udf cargo test -p seance_plugin_udf
/// write_fuzz_seeds -- --ignored`.
#[test]
#[ignore]
fn write_fuzz_seeds() {
    let Ok(dir) = std::env::var("SEANCE_UDF_FUZZ_SEEDS") else {
        return;
    };
    std::fs::create_dir_all(&dir).unwrap();
    let small = |mut b: UdfBuilder| {
        b.part_len = 64;
        b
    };
    let mut seeds: Vec<(&str, UdfBuilder)> = Vec::new();
    let mut b = UdfBuilder::new();
    let d = b.dir(0, "docs");
    b.file(d, "a.txt", b"AAA", Layout::Short);
    b.file(0, "tiny", b"embedded", Layout::Embedded);
    b.file(0, "big", &vec![7u8; 2 * BS + 5], Layout::Long { split: BS });
    seeds.push(("tree", b));
    let mut b = UdfBuilder::new();
    b.file(0, "c", &vec![1u8; BS + 9], Layout::Continued);
    b.file(
        0,
        "h",
        &[vec![1u8; BS], vec![0u8; BS], vec![2u8; 9]].concat(),
        Layout::HoleAfterFirstBlock,
    );
    b.efe = true;
    seeds.push(("efe_aed_hole", b));
    let mut b = UdfBuilder::new();
    let s = b.dir(0, "s");
    b.loop_to_root(s, "loop");
    seeds.push(("loop", b));
    for (name, b) in seeds {
        std::fs::write(format!("{dir}/{name}"), small(b).build()).unwrap();
    }
}

// --- Review fixes (2026-09-27) --------------------------------------------

/// Image byte offset of partition block `lbn` in a builder volume.
fn part_block(lbn: usize) -> usize {
    (crate::test_builder::PART_START as usize + lbn) * BS
}

#[test]
fn embedded_data_shorter_than_information_length_is_flagged() {
    // An embedded File Entry whose information length says 100 bytes while
    // the entry holds 16: the tail is not on the disc and must not be served
    // as silent zeros.
    let mut b = UdfBuilder::new();
    b.file(0, "tiny", b"inside the entry", Layout::Embedded);
    let mut img = b.build();
    // Root ICB is block 2, the file's is block 3.
    let o = part_block(3);
    img[o + 56..o + 64].copy_from_slice(&100u64.to_le_bytes());
    seal(&mut img[o..o + BS], crate::tag::ident::FE, 3, 176 + 16);
    let out = run(img);
    let t = by_path(&out, "/tiny");
    assert_eq!(t.metadata["size"], 100);
    assert_eq!(t.metadata["content_incomplete"], true);
    assert_eq!(
        t.metadata["udf_content_problem"],
        "allocation_shorter_than_information_length"
    );
    assert_eq!(t.metadata["data_runs_complete"], false);
}

#[test]
fn deleted_fid_with_zeroed_icb_says_icb_not_recorded() {
    // The Linux udf driver zeroes a deleted FID's ICB long_ad. That is "no
    // File Entry recorded", not a damaged one at partition block 0.
    let mut b = UdfBuilder::new();
    let f = b.file(0, "gone", b"was here", Layout::Short);
    b.nodes[f].deleted = true;
    let mut img = b.build();
    // Root FIDs at partition block 4: the 40-byte parent FID, then "gone"
    // ((38 + 5) rounded up to 44 bytes).
    let o = part_block(4) + 40;
    img[o + 20..o + 36].fill(0);
    seal(&mut img[o..o + 44], crate::tag::ident::FID, 0, 44);
    let out = run(img);
    let g = by_path(&out, "/gone");
    assert_eq!(g.metadata["deleted"], true);
    assert_eq!(g.metadata["icb_unreadable_reason"], "icb_not_recorded");
    assert_eq!(g.metadata["content_incomplete"], true);
    assert!(g.data.is_none());
}

#[test]
fn invalid_timestamp_is_named_not_silently_dropped() {
    let mut b = UdfBuilder::new();
    b.file(0, "t", b"t", Layout::Short);
    let mut img = b.build();
    let o = part_block(3);
    // FE modification time at 84; month is byte 4 of the timestamp.
    img[o + 84 + 4] = 13;
    seal(&mut img[o..o + BS], crate::tag::ident::FE, 3, 176 + 8);
    let out = run(img);
    let t = by_path(&out, "/t");
    assert!(t.metadata.get("modified").is_none());
    assert_eq!(t.metadata["timestamps_undecodable"], json!(["modified"]));
    assert_eq!(t.metadata["accessed"], "2024-03-01T10:00:00+00:00");
}

#[test]
fn anchor_on_512_byte_sector_media_is_found_at_that_size() {
    // UDF on 512-byte-sector media (Windows `format /fs:UDF` on a USB disk):
    // the VRS still sits in 2048-byte steps from 32 KiB, so the partition
    // layer calls it `udf`; the AVDP is at 512-byte sector 256 and is found
    // there, not reported missing.
    const S: usize = 512;
    let mut img = vec![0u8; 4096 * S];
    let d = &mut img[256 * S..257 * S];
    d[16..20].copy_from_slice(&(16 * S as u32).to_le_bytes());
    d[20..24].copy_from_slice(&257u32.to_le_bytes());
    seal(d, crate::tag::ident::AVDP, 256, 512);
    let out = run(img);
    let v = volume(&out);
    assert_eq!(v["udf_unreadable"], true);
    assert!(
        v["udf_unreadable_reason"]
            .as_str()
            .unwrap()
            .starts_with("main sequence:"),
        "{v}"
    );
    assert_eq!(v["sector_size"], 512);
    assert_eq!(v["anchor_sector"], 256);
    assert!(entries(&out).is_empty());
}
