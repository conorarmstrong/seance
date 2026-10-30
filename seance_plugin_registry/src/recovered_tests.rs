//! Recovered cells: keys and values a deletion marked free but did not
//! overwrite, read out of a hive's unallocated space through
//! `seance_hive::Hive::unallocated_cells` and published apart from the live
//! tree (`ROADMAP` §5.9).
//!
//! # Where the fixtures come from
//!
//! **Synthetic, from the published format** (`regf` as Suhanov documents it):
//! a hive the reader fully accepts, plus cells appended after the root with a
//! positive size field — the format's own sign for "free". No hive on this
//! machine has a deleted key whose bytes were hand-verified as a known
//! answer, so what these tests pin is that the code does what the
//! specification says and keeps the two kinds of evidence apart. A synthetic
//! fixture is not validation.

use super::recovered::*;
use super::tests::{art_with_data, build_parseable_hive};
use seance_core::module::ForensicsModule;

/// Append a cell after everything already laid out in the one bin, marked
/// free (positive size) or allocated (negative). Returns the bin-relative
/// offset the hive would store for it.
fn append_cell(buf: &mut [u8], cursor: &mut usize, payload: &[u8], free: bool) -> u32 {
    let size = (payload.len() + 4 + 7) & !7;
    let at = *cursor;
    assert!(at + size <= buf.len(), "fixture bin is full");
    let raw = if free { size as i32 } else { -(size as i32) };
    buf[at..at + 4].copy_from_slice(&raw.to_le_bytes());
    buf[at + 4..at + 4 + payload.len()].copy_from_slice(payload);
    *cursor += size;
    (at - 0x1000) as u32
}

fn nk_payload(name: &str, parent: u32, filetime: u64) -> Vec<u8> {
    let nb = name.as_bytes();
    let mut nk = vec![0u8; 76 + nb.len()];
    nk[0..2].copy_from_slice(b"nk");
    nk[2..4].copy_from_slice(&0x20u16.to_le_bytes()); // COMP_NAME
    nk[4..12].copy_from_slice(&filetime.to_le_bytes());
    nk[16..20].copy_from_slice(&parent.to_le_bytes());
    for off in [0x1C, 0x28, 0x2C, 0x30] {
        nk[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    nk[0x24..0x28].copy_from_slice(&1u32.to_le_bytes()); // declares one value
    nk[72..74].copy_from_slice(&(nb.len() as u16).to_le_bytes());
    nk[76..].copy_from_slice(nb);
    nk
}

/// A `vk` with four-byte inline data (the high bit of the size field set).
fn vk_inline_dword(name: &str, value: u32) -> Vec<u8> {
    let nb = name.as_bytes();
    let mut vk = vec![0u8; 20 + nb.len()];
    vk[0..2].copy_from_slice(b"vk");
    vk[2..4].copy_from_slice(&(nb.len() as u16).to_le_bytes());
    vk[4..8].copy_from_slice(&(4u32 | 0x8000_0000).to_le_bytes());
    vk[8..12].copy_from_slice(&value.to_le_bytes());
    vk[12..16].copy_from_slice(&4u32.to_le_bytes()); // REG_DWORD
    vk[16..18].copy_from_slice(&1u16.to_le_bytes()); // COMP_NAME
    vk[20..].copy_from_slice(nb);
    vk
}

/// A `vk` whose data sits in another cell at `data_offset`.
fn vk_external(name: &str, data_offset: u32, size: u32, data_type: u32) -> Vec<u8> {
    let nb = name.as_bytes();
    let mut vk = vec![0u8; 20 + nb.len()];
    vk[0..2].copy_from_slice(b"vk");
    vk[2..4].copy_from_slice(&(nb.len() as u16).to_le_bytes());
    vk[4..8].copy_from_slice(&size.to_le_bytes());
    vk[8..12].copy_from_slice(&data_offset.to_le_bytes());
    vk[12..16].copy_from_slice(&data_type.to_le_bytes());
    vk[16..18].copy_from_slice(&1u16.to_le_bytes());
    vk[20..].copy_from_slice(nb);
    vk
}

const FILETIME: u64 = 132_223_104_000_000_000;
/// Where `build_parseable_hive` leaves the bin's cursor: past the root NK.
const AFTER_ROOT: usize = 0x1020 + ((4 + 76 + 4 + 7) & !7);

/// The hive the parser fully accepts, with one deleted key under the live
/// root and one freed value beside it.
fn hive_with_deleted_key_and_value() -> (Vec<u8>, u32, u32) {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    let ghost = append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Ghost", 0x20, FILETIME),
        true,
    );
    let marker = append_cell(&mut buf, &mut cursor, &vk_inline_dword("Marker", 42), true);
    (buf, ghost, marker)
}

fn records_of(buf: Vec<u8>) -> Vec<serde_json::Value> {
    super::RegistryParser
        .process(&art_with_data("SOFTWARE", buf))
        .unwrap()
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

/// The point of the walk: a deleted key and a freed value come out as their
/// own record types, and the live tree does not gain them.
#[test]
fn a_deleted_key_and_a_freed_value_are_published_as_recovered_types_never_as_live() {
    let (buf, ghost_at, marker_at) = hive_with_deleted_key_and_value();
    let out = records_of(buf);

    let hive = out.iter().find(|r| r["type"] == "RegistryHive").unwrap();
    let live_names: Vec<&str> = hive["all_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key_name"].as_str().unwrap())
        .collect();
    assert!(
        !live_names.contains(&"Ghost"),
        "a recovered key must never appear among the live keys: {live_names:?}"
    );
    assert!(hive["all_values"].as_array().unwrap().is_empty());

    let key = out
        .iter()
        .find(|r| r["type"] == "RecoveredRegistryKey")
        .expect("one RecoveredRegistryKey record");
    assert_eq!(key["key_name"], "Ghost");
    assert_eq!(key["bin_offset"], ghost_at);
    assert_eq!(key["evidence_state"], "recovered");
    assert_eq!(key["last_written"], "2020-01-01T00:00:00+00:00");
    assert_eq!(key["value_count_declared"], 1);
    assert_eq!(key["hive"], "SOFTWARE");
    assert!(
        key["replay"].is_object(),
        "carries the hive's recovery state"
    );

    let value = out
        .iter()
        .find(|r| r["type"] == "RecoveredRegistryValue")
        .expect("one RecoveredRegistryValue record");
    assert_eq!(value["value_name"], "Marker");
    assert_eq!(value["bin_offset"], marker_at);
    assert_eq!(value["value_type"], "RegDWord");
    assert_eq!(value["data_read"], true);
    assert_eq!(value["value_data"], "0x0000002a (42)");
    assert_eq!(value["data_basis"], "inline in the freed vk cell itself");
    assert_eq!(value["evidence_state"], "recovered");
    // A freed vk does not say which key it belonged to.
    assert!(value["key_path"].is_null());
    assert!(value["key_association_note"].is_string());

    // The hive record counts what was recovered and says the walk ran whole.
    let summary = &hive["recovered_cells"];
    assert_eq!(summary["keys"], 1);
    assert_eq!(summary["values"], 1);
    assert_eq!(summary["undecodable"], 0);
    assert_eq!(summary["complete"], true);
    assert_eq!(summary["examined_cap"], 200_000);
    assert_eq!(summary["examined_capped"], false);
    assert_eq!(summary["walk_incomplete"], false);
}

/// A recovered key's path is rebuilt from its parent-offset chain through the
/// live cells and the other recovered ones. That is an inference — the
/// parent cell may have been reused since the deletion — and the record says
/// so; a chain that ends at an offset holding neither is a partial path.
#[test]
fn a_recovered_keys_path_is_an_inference_and_a_broken_chain_is_partial() {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    let parent = append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Gone", 0x20, FILETIME),
        true,
    );
    append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Child", parent, FILETIME),
        true,
    );
    append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Orphan", 0x7FF0, FILETIME),
        true,
    );
    let out = records_of(buf);
    let keys: Vec<_> = out
        .iter()
        .filter(|r| r["type"] == "RecoveredRegistryKey")
        .collect();
    assert_eq!(keys.len(), 3);

    let child = keys.iter().find(|k| k["key_name"] == "Child").unwrap();
    assert_eq!(child["key_path"], "ROOT\\Gone\\Child");
    assert_eq!(child["key_path_is_inference"], true);
    assert_eq!(child["key_path_complete"], true);
    assert!(child["key_path_basis"]
        .as_str()
        .unwrap()
        .contains("may have been reused"));

    let orphan = keys.iter().find(|k| k["key_name"] == "Orphan").unwrap();
    assert_eq!(orphan["key_path_complete"], false);
    assert_eq!(orphan["key_path"], "Orphan");
    assert_eq!(orphan["key_path_parent_offset_unresolved"], 0x7FF0);
}

/// Every recovered key with a readable time earns a timeline event of its
/// own kind — never the live "Registry Key Last Written" — so the two are
/// never one series.
#[test]
fn a_recovered_key_raises_a_timeline_event_of_its_own_kind() {
    let (buf, _, _) = hive_with_deleted_key_and_value();
    let out = records_of(buf);
    let ev = out
        .iter()
        .find(|r| r["timestamp_desc"] == "Recovered Registry Key Last Written")
        .expect("a recovered-key event");
    assert_eq!(ev["evidence_state"], "recovered");
    assert_eq!(ev["timestamp"], "2020-01-01T00:00:00+00:00");
    assert!(ev["short_desc"].as_str().unwrap().contains("Ghost"));
    assert!(
        !out.iter()
            .any(|r| r["timestamp_desc"] == "Registry Key Last Written"
                && r["key_path"].as_str().unwrap_or("").contains("Ghost")),
        "the live series must not carry the recovered key"
    );
}

/// A freed value whose data lived in another cell: that cell is freed too, so
/// the data is unread and the record says why. Where the data cell is still
/// allocated it is read, and the record says the cell may have been reused.
#[test]
fn a_freed_values_external_data_is_read_only_with_its_basis_stated() {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    let freed_data = append_cell(&mut buf, &mut cursor, b"gone\0", true);
    append_cell(
        &mut buf,
        &mut cursor,
        &vk_external("Freed", freed_data, 5, 3),
        true,
    );
    let live_data = append_cell(&mut buf, &mut cursor, b"live\0", false);
    append_cell(
        &mut buf,
        &mut cursor,
        &vk_external("Reused", live_data, 5, 3),
        true,
    );
    let out = records_of(buf);
    let values: Vec<_> = out
        .iter()
        .filter(|r| r["type"] == "RecoveredRegistryValue")
        .collect();
    assert_eq!(values.len(), 2);

    let freed = values.iter().find(|v| v["value_name"] == "Freed").unwrap();
    assert_eq!(freed["data_read"], false);
    assert!(freed["value_data"].is_null());
    assert!(freed["data_unread_reason"]
        .as_str()
        .unwrap()
        .contains("not allocated"));
    assert_eq!(freed["raw_data_size_declared"], 5);

    let reused = values.iter().find(|v| v["value_name"] == "Reused").unwrap();
    assert_eq!(reused["data_read"], true);
    assert_eq!(reused["value_data"], "6c 69 76 65 00");
    assert!(reused["data_basis"]
        .as_str()
        .unwrap()
        .contains("may have been reused"));
}

/// A freed `vk` whose non-inline size field is zero: `seance_hive` answers
/// with an empty slice **before it follows the offset field**, so no data cell
/// was read. The record used to say the bytes came from "an allocated data
/// cell the freed vk points at. The cell is in use now" — a claim about a
/// cell nobody looked at. Now `data_basis` says what was observed: the size
/// field was zero and no cell was read.
#[test]
fn a_freed_value_declaring_no_data_says_no_cell_was_read() {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    // An allocated cell the offset field points at, holding bytes that must
    // NOT be attributed to the value: the size field says there are none.
    let live_data = append_cell(&mut buf, &mut cursor, b"never read\0", false);
    append_cell(
        &mut buf,
        &mut cursor,
        &vk_external("Empty", live_data, 0, 3),
        true,
    );
    let out = records_of(buf);
    let value = out
        .iter()
        .find(|r| r["type"] == "RecoveredRegistryValue" && r["value_name"] == "Empty")
        .expect("the freed vk is recovered");

    assert_eq!(value["raw_data_size_declared"], 0);
    assert_eq!(value["data_read"], true);
    assert_eq!(value["value_data"], "");
    assert_eq!(value["raw_data_size"], 0);
    let basis = value["data_basis"].as_str().unwrap();
    assert!(
        basis.contains("size field is zero") && basis.contains("no data cell was read"),
        "the basis must state what was observed: {basis:?}"
    );
    assert!(
        !basis.contains("in use now") && !basis.contains("reused"),
        "no claim about a cell that was never read: {basis:?}"
    );
}

/// The walk's own ceiling, hit, is reported with its number: 200,000 cells
/// examined and the deleted key past them never reached.
#[test]
fn the_unallocated_walk_cap_is_reported_with_its_number() {
    // One bin big enough for 200,001 eight-byte free cells and the key.
    let bin_size = 0x1000usize * 0x200; // 2 MiB
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    buf.resize(0x1000 + bin_size, 0);
    buf[0x1008..0x100c].copy_from_slice(&(bin_size as u32).to_le_bytes());
    buf[0x28..0x2C].copy_from_slice(&(bin_size as u32).to_le_bytes());
    let mut cursor = AFTER_ROOT;
    for _ in 0..seance_hive::MAX_UNALLOCATED_CELLS {
        buf[cursor..cursor + 4].copy_from_slice(&8i32.to_le_bytes());
        cursor += 8;
    }
    append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Beyond", 0x20, FILETIME),
        true,
    );
    let hive = seance_hive::Hive::without_validation(&buf).unwrap();
    let scan = recover_unallocated_cells(&hive);
    assert!(scan.examined_capped);
    assert!(
        scan.keys.is_empty(),
        "the key past the cap was never reached"
    );
    let summary = scan.summary();
    assert_eq!(summary["examined_capped"], true);
    assert_eq!(summary["examined_cap"], seance_hive::MAX_UNALLOCATED_CELLS);
    assert_eq!(summary["complete"], false);
    assert!(summary["incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("200000"));
}

/// The record ceiling is separate from the walk's, and is reported with its
/// number too.
#[test]
fn the_recovered_record_cap_is_reported_with_its_number() {
    let scan = RecoveredCellScan {
        records_capped: true,
        ..RecoveredCellScan::default()
    };
    let summary = scan.summary();
    assert_eq!(summary["records_capped"], true);
    assert_eq!(summary["records_cap"], MAX_RECOVERED_RECORDS);
    assert_eq!(summary["complete"], false);
    assert!(summary["incomplete_reason"]
        .as_str()
        .unwrap()
        .contains(&MAX_RECOVERED_RECORDS.to_string()));
}

/// A cell that opens `nk` but will not decode is counted and reported at its
/// offset with the reader's reason, not dropped and not guessed at.
#[test]
fn an_undecodable_candidate_is_counted_and_reported_with_its_reason() {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    let mut fragment = vec![0u8; 16];
    fragment[0..2].copy_from_slice(b"nk");
    let at = append_cell(&mut buf, &mut cursor, &fragment, true);
    let out = records_of(buf);
    let hive = out.iter().find(|r| r["type"] == "RegistryHive").unwrap();
    assert_eq!(hive["recovered_cells"]["undecodable"], 1);
    let candidates = hive["recovered_cells"]["undecodable_cells"]
        .as_array()
        .unwrap();
    assert_eq!(candidates[0]["bin_offset"], at);
    assert_eq!(candidates[0]["signature"], "nk");
    assert!(candidates[0]["reason"].is_string());
}

/// The real `SAM` holds three freed `nk` cells named `Power Users`,
/// `Network Configuration Operators` and `Cryptographic Operators` under a
/// parent that resolves to the live `...\Aliases\Names` — and that live key
/// still has children of those names, at other offsets with other times.
/// They are earlier versions of live keys, not deletions, and a record
/// that did not say so would read as "these groups were removed". So a
/// recovered key whose resolved parent has a live child of the same name
/// says it.
#[test]
fn a_recovered_key_with_a_live_namesake_under_the_same_parent_says_so() {
    let mut buf = super::tests::build_hive_with_ri_children_for_tests();
    // The root's live children are Alpha, Beta, Gamma; the bin cursor sits
    // past them. Append a freed `nk` named `Beta` under the root, and one
    // named `Ghost` with no namesake.
    let mut cursor = super::tests::AFTER_RI_CHILDREN;
    append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Beta", 0x20, FILETIME),
        true,
    );
    append_cell(
        &mut buf,
        &mut cursor,
        &nk_payload("Ghost", 0x20, FILETIME),
        true,
    );
    let out = records_of(buf);
    let keys: Vec<_> = out
        .iter()
        .filter(|r| r["type"] == "RecoveredRegistryKey")
        .collect();
    let beta = keys.iter().find(|k| k["key_name"] == "Beta").unwrap();
    assert_eq!(beta["live_key_with_same_name_under_parent"], true);
    assert!(beta["live_namesake_note"]
        .as_str()
        .unwrap()
        .contains("not evidence that the key was deleted"));
    let ghost = keys.iter().find(|k| k["key_name"] == "Ghost").unwrap();
    assert_eq!(ghost["live_key_with_same_name_under_parent"], false);
    assert!(ghost["live_namesake_note"].is_null());
}

// --- The known answer, on a real hive --------------------------------------

/// The plaso corpus `SAM`, decoded by hand (a Python walk of the cell chain,
/// independent of `seance_hive`) before this assertion was written. Its
/// 20,480 bytes of bins hold fourteen free cells, six of them `nk`/`vk`:
///
/// ```text
/// 0x27b0  vk  name ""  inline, 0 bytes  type 546
/// 0x3218  nk  "Power Users"                      parent 0x9b0  130560137964065369
/// 0x3318  vk  name ""  inline, 0 bytes  type 556
/// 0x3520  nk  "Network Configuration Operators"  parent 0x9b0  130560137964065369
/// 0x3e90  vk  name ""  inline, 0 bytes  type 547
/// 0x4078  nk  "Cryptographic Operators"          parent 0x9b0  130560137964221369
/// ```
///
/// `0x9b0` is the live `SAM\Domains\Builtin\Aliases\Names`, and that key
/// still has live children of all three names (at `0x26b0`, `0x2628`,
/// `0x2728`, each last written 130560033663588374 — earlier than the freed
/// cells). So these are not deleted groups: they are other versions of keys
/// that exist, and the record has to say so or an examiner reads three
/// removed groups off a hive that removed none.
#[test]
fn the_real_sam_hive_yields_its_three_freed_alias_name_cells_as_recovered_not_deleted() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SAM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SAM", bytes);
    let hive = all.iter().find(|r| r["type"] == "RegistryHive").unwrap();
    let summary = &hive["recovered_cells"];
    assert_eq!(summary["keys"], 3);
    assert_eq!(summary["values"], 3);
    assert_eq!(summary["undecodable"], 0);
    assert_eq!(summary["complete"], true, "{summary}");

    let names_path =
        "CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\\SAM\\Domains\\Builtin\\Aliases\\Names";
    let keys: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "RecoveredRegistryKey")
        .collect();
    for (name, offset, filetime) in [
        ("Power Users", 0x3218u32, 130_560_137_964_065_369u64),
        (
            "Network Configuration Operators",
            0x3520,
            130_560_137_964_065_369,
        ),
        ("Cryptographic Operators", 0x4078, 130_560_137_964_221_369),
    ] {
        let k = keys
            .iter()
            .find(|k| k["bin_offset"] == offset)
            .unwrap_or_else(|| panic!("no recovered key at {offset:#x}"));
        assert_eq!(k["key_name"], name);
        assert_eq!(k["parent_offset"], 0x9b0);
        assert_eq!(k["last_written_filetime"], filetime);
        assert_eq!(k["key_path"], format!("{names_path}\\{name}"));
        assert_eq!(k["key_path_complete"], true);
        assert_eq!(k["key_path_is_inference"], true);
        assert_eq!(k["live_key_with_same_name_under_parent"], true);
        assert_eq!(k["evidence_state"], "recovered");
    }
    // And the live tree still holds all three, untouched by the walk.
    let live: Vec<&str> = hive["all_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["key_path"].as_str().unwrap_or("").starts_with(names_path))
        .map(|k| k["key_name"].as_str().unwrap())
        .collect();
    for name in [
        "Power Users",
        "Network Configuration Operators",
        "Cryptographic Operators",
    ] {
        assert_eq!(live.iter().filter(|n| **n == name).count(), 1, "{live:?}");
    }

    let values: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "RecoveredRegistryValue")
        .collect();
    for (offset, type_code) in [(0x27b0u32, 546u32), (0x3318, 556), (0x3e90, 547)] {
        let v = values
            .iter()
            .find(|v| v["bin_offset"] == offset)
            .unwrap_or_else(|| panic!("no recovered value at {offset:#x}"));
        assert_eq!(v["value_name"], "");
        assert_eq!(v["value_type"], format!("Unknown({type_code})"));
        assert_eq!(v["data_read"], true);
        assert_eq!(v["raw_data_size"], 0);
        assert_eq!(v["data_basis"], "inline in the freed vk cell itself");
        assert!(v["key_path"].is_null());
    }
    // Three recovered-key events, of their own kind.
    assert_eq!(
        all.iter()
            .filter(|r| r["timestamp_desc"] == "Recovered Registry Key Last Written")
            .count(),
        3
    );
}

/// `HUNT-167`. A freed default value — a `vk` whose name length is zero, which
/// is how the format stores a key's default value — rendered its display name
/// as `" (recovered)"`. It is named `(Default)`, the `regedit` convention, and
/// its `value_name` stays the empty string the cell holds.
#[test]
fn a_recovered_default_value_is_named_default_and_keeps_its_empty_value_name() {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    append_cell(&mut buf, &mut cursor, &vk_inline_dword("", 7), true);
    let out = records_of(buf);
    let value = out
        .iter()
        .find(|r| r["type"] == "RecoveredRegistryValue")
        .expect("one RecoveredRegistryValue record");
    assert_eq!(value["name"], "(Default) (recovered)");
    assert_eq!(value["value_name"], "");
}

/// `HUNT-159`. A recovered value carries its bytes too, through the same door
/// as a live one: before, only a binary value over 64 bytes did.
#[test]
fn a_recovered_value_carries_its_stored_bytes() {
    use base64::Engine as _;
    let (buf, _, _) = hive_with_deleted_key_and_value();
    let out = records_of(buf);
    let value = out
        .iter()
        .find(|r| r["type"] == "RecoveredRegistryValue")
        .expect("one RecoveredRegistryValue record");
    let b64 = value["value_data_b64"].as_str().expect("the bytes");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap(),
        42u32.to_le_bytes()
    );
}
