use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::{ForensicsModule, InputCapability};
use seance_core::test_support::TruncatedSource;
use std::sync::Arc;
use uuid::Uuid;

use seance_core::data_source::ByteSliceDataSource;

pub(crate) fn art_with_data(name: &str, data: Vec<u8>) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": name }),
    )
}

#[test]
fn test_registry_parser_module_metadata() {
    let parser = RegistryParser;

    assert_eq!(parser.id(), "plugin.windows.registry_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(parser.input_capability(), InputCapability::Stream);

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::RawEvidence));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));
}

#[test]
fn test_registry_parser_skips_non_hive_files() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        serde_json::json!({
            "name": "test.txt"
        }),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn missing_data_source_skips_silently() {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        None,
        serde_json::json!({ "name": "SYSTEM" }),
    );
    let out = RegistryParser.process(&art).unwrap();
    assert!(out.is_empty());
}

#[test]
fn non_registry_content_is_skipped_silently() {
    // Random bytes with no "regf" magic — content detection rejects.
    let art = art_with_data(
        "looks_real.dat",
        b"this is not a registry hive at all".to_vec(),
    );
    let out = RegistryParser.process(&art).unwrap();
    assert!(out.is_empty());
}

#[test]
fn empty_data_source_is_skipped_silently() {
    let art = art_with_data("empty.hive", Vec::new());
    let out = RegistryParser.process(&art).unwrap();
    assert!(out.is_empty());
}

/// The one marker a hive that could not be parsed must leave behind, or `None`.
fn parse_failure_of(out: &[Artifact]) -> Option<&Artifact> {
    out.iter()
        .find(|a| a.metadata["type"] == "RegistryHiveUnparsed")
}

#[test]
fn truncated_regf_header_does_not_panic_and_says_so_on_the_record() {
    // Build a buffer starting with the "regf" magic that content detection
    // recognises, but with nothing else valid behind it. The reader will either
    // return Err or panic; either way the module must swallow it — and then
    // say so, because an empty result is indistinguishable from a machine with
    // no registry (HUNT-053).
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"regf");
    let art = art_with_data("SYSTEM", buf);

    // Must not panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        RegistryParser.process(&art)
    }));
    let out = result
        .expect("process panicked despite catch_unwind in module")
        .unwrap();
    let marker = parse_failure_of(&out).expect("a hive that did not parse must be on the record");
    assert_eq!(marker.metadata["status"], "HiveNotParsed");
    assert_eq!(marker.metadata["hive_type"], "SYSTEM");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(
        marker.metadata["parse_error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "the reader's own reason is what tells a corrupt header apart from a dirty one"
    );
    assert!(
        marker.metadata["detail"]
            .as_str()
            .is_some_and(|d| d.contains("not evidence of absence")),
        "{:?}",
        marker.metadata["detail"]
    );
}

#[test]
fn corrupted_hive_with_random_payload_after_magic_is_safe() {
    // "regf" magic + 64KB of random-ish bytes — fuzz the catch_unwind path.
    let mut buf = vec![0u8; 65536];
    buf[0..4].copy_from_slice(b"regf");
    for (i, b) in buf.iter_mut().enumerate().skip(4) {
        *b = ((i * 31) ^ 0xA5) as u8;
    }
    let art = art_with_data("CORRUPTED", buf);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        RegistryParser.process(&art)
    }));
    let out = result.expect("process panicked").unwrap();
    assert!(
        parse_failure_of(&out).is_some(),
        "a hive detected and then refused must never produce silence"
    );
}

/// A registry hive that the reader will fully accept: a complete, checksummed
/// base block, one `hbin`, and a root NK with no children.
///
/// `primary_seq != secondary_seq` makes it **dirty** — the state a hive is in
/// whenever it is copied off a running machine.
pub(crate) fn build_parseable_hive(name: &str, primary_seq: u32, secondary_seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x2000]; // 0x1000 base block + one 0x1000 hbin
    buf[0..4].copy_from_slice(b"regf");
    buf[4..8].copy_from_slice(&primary_seq.to_le_bytes());
    buf[8..12].copy_from_slice(&secondary_seq.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version
    buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // file type: primary
    buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // file format: direct
    buf[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell offset
    buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes()); // hbins data size
    buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor

    // hbin header at 0x1000.
    buf[0x1000..0x1004].copy_from_slice(b"hbin");
    buf[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes()); // offset of this hbin
    buf[0x1008..0x100c].copy_from_slice(&0x1000u32.to_le_bytes()); // hbin size

    // Root NK cell at 0x1020.
    let cell = 0x1020usize;
    let name_bytes = name.as_bytes();
    let cell_len = (4 + 76 + name_bytes.len() + 7) & !7;
    buf[cell..cell + 4].copy_from_slice(&(-(cell_len as i32)).to_le_bytes());
    let d = cell + 4;
    buf[d..d + 2].copy_from_slice(b"nk");
    buf[d + 2..d + 4].copy_from_slice(&0x2Cu16.to_le_bytes()); // HIVE_ENTRY | COMP_NAME
    buf[d + 4..d + 12].copy_from_slice(&132_223_104_000_000_000u64.to_le_bytes());
    buf[d + 16..d + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // parent: none
    for off in [0x1C, 0x28, 0x2C, 0x30] {
        buf[d + off..d + off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    buf[d + 72..d + 74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf[d + 76..d + 76 + name_bytes.len()].copy_from_slice(name_bytes);

    // XOR-32 checksum over the base block, with the two values Windows never
    // stores.
    let mut sum: u32 = 0;
    for chunk in buf[..0x1FC].as_chunks::<4>().0.iter() {
        sum ^= u32::from_le_bytes(*chunk);
    }
    let sum = match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    };
    buf[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
    buf
}

/// The parseable hive above, given three subkeys under an index root (`ri`)
/// of three single-entry `li` leaves — the indirection a large key really
/// uses. With `damage_second`, the root's second `ri` entry points past the
/// end of the hive, so the sublist naming the second child will not read.
fn build_hive_with_ri_children(damage_second: bool) -> Vec<u8> {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    // Allocate cells after the root NK. Offsets stored in cells are relative to
    // the hbin data at 0x1000.
    let mut cursor = 0x1020usize + ((4 + 76 + 4 + 7) & !7);
    let end = build_ri_children(&mut buf, &mut cursor, damage_second);
    debug_assert_eq!(end, AFTER_RI_CHILDREN);
    buf
}

/// The undamaged `ri` hive, for a sibling test module.
pub(crate) fn build_hive_with_ri_children_for_tests() -> Vec<u8> {
    build_hive_with_ri_children(false)
}

/// Where `build_hive_with_ri_children` leaves the bin cursor: three NK cells
/// (88 bytes each), three 16-byte `li` leaves and one 24-byte `ri`.
pub(crate) const AFTER_RI_CHILDREN: usize = 0x1020 + 88 + 3 * (88 + 16) + 24;

fn build_ri_children(buf: &mut Vec<u8>, cursor: &mut usize, damage_second: bool) -> usize {
    let mut alloc = |buf: &mut Vec<u8>, payload: &[u8]| -> u32 {
        let size = (payload.len() + 4 + 7) & !7;
        let at = *cursor;
        buf[at..at + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
        buf[at + 4..at + 4 + payload.len()].copy_from_slice(payload);
        *cursor += size;
        (at - 0x1000) as u32
    };
    let mut leaves = Vec::new();
    for name in ["Alpha", "Beta", "Gamma"] {
        let nb = name.as_bytes();
        let mut nk = vec![0u8; 76 + nb.len()];
        nk[0..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x20u16.to_le_bytes()); // COMP_NAME
        nk[4..12].copy_from_slice(&132_223_104_000_000_000u64.to_le_bytes());
        nk[16..20].copy_from_slice(&0x20u32.to_le_bytes()); // parent: root
        for off in [0x1C, 0x28, 0x2C, 0x30] {
            nk[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }
        nk[72..74].copy_from_slice(&(nb.len() as u16).to_le_bytes());
        nk[76..].copy_from_slice(nb);
        let child = alloc(buf, &nk);
        let mut li = vec![0u8; 8];
        li[0..2].copy_from_slice(b"li");
        li[2..4].copy_from_slice(&1u16.to_le_bytes());
        li[4..8].copy_from_slice(&child.to_le_bytes());
        leaves.push(alloc(buf, &li));
    }
    if damage_second {
        leaves[1] = 0x7FFF_FFF0;
    }
    let mut ri = vec![0u8; 4 + 4 * leaves.len()];
    ri[0..2].copy_from_slice(b"ri");
    ri[2..4].copy_from_slice(&(leaves.len() as u16).to_le_bytes());
    for (i, leaf) in leaves.iter().enumerate() {
        ri[4 + i * 4..8 + i * 4].copy_from_slice(&leaf.to_le_bytes());
    }
    let ri_offset = alloc(buf, &ri);
    // Root NK: subkey count and subkeys-list offset.
    let d = 0x1020 + 4;
    buf[d + 0x14..d + 0x18].copy_from_slice(&3u32.to_le_bytes());
    buf[d + 0x1C..d + 0x20].copy_from_slice(&ri_offset.to_le_bytes());
    *cursor
}

/// HIVE-002. An index root names three subkey lists and one will not read.
/// The reader yields the two it can reach — one damaged list must not cost
/// the hive — but a key that then reports two subkeys where it declared three,
/// with nothing said, is a false absence on a court-facing surface. The key
/// record carries the shortfall and the hive record counts it.
#[test]
fn a_damaged_index_root_sublist_is_stamped_on_the_key_and_counted_on_the_hive() {
    let out = RegistryParser
        .process(&art_with_data(
            "SOFTWARE",
            build_hive_with_ri_children(true),
        ))
        .unwrap();
    let hive = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("hive record");
    let keys = hive.metadata["all_keys"].as_array().unwrap();
    let names: Vec<&str> = keys
        .iter()
        .map(|k| k["key_name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Alpha") && names.contains(&"Gamma"));
    assert!(
        !names.contains(&"Beta"),
        "the damaged list's key cannot be reached"
    );

    let root = keys.iter().find(|k| k["depth"] == 0).unwrap();
    assert_eq!(root["subkey_count"], 3, "what the key declared");
    assert_eq!(root["subkeys_incomplete"], true);
    assert_eq!(root["subkeys_incomplete_reason"], "unresolved_structure");
    assert_eq!(root["unresolved_sublists"].as_array().unwrap().len(), 1);
    assert!(root["subkeys_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("not from the hive"));

    assert_eq!(hive.metadata["walk_subkey_errors"], 1);
    assert_eq!(hive.metadata["inventory_incomplete"], true);

    // The undamaged hive reads whole and says nothing about loss, so the
    // marker's absence is a claim and not a default.
    let out = RegistryParser
        .process(&art_with_data(
            "SOFTWARE",
            build_hive_with_ri_children(false),
        ))
        .unwrap();
    let hive = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    let keys = hive.metadata["all_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 4);
    let root = keys.iter().find(|k| k["depth"] == 0).unwrap();
    assert!(root.get("subkeys_incomplete").is_none());
    assert_eq!(hive.metadata["walk_subkey_errors"], 0);
}

/// §2.2 detection 8. A key's own subkey count and the number of offsets its
/// index names are separate fields in the hive, and they can disagree: a
/// damaged index, or a key deleted without its parent's count being
/// decremented. The reader publishes both and reconciles neither, because a
/// listing presented as complete while the hive disagrees about it is a false
/// absence on a court-facing surface.
///
/// Distinct from the `subkeys_incomplete` case above: there, part of the index
/// could not be read at all. Here the index reads perfectly and is short.
#[test]
fn a_key_declaring_more_subkeys_than_its_index_names_records_both_numbers() {
    // The intact three-child hive, with the root declaring nine.
    let mut buf = build_hive_with_ri_children(false);
    let d = 0x1020 + 4;
    buf[d + 0x14..d + 0x18].copy_from_slice(&9u32.to_le_bytes());

    let out = RegistryParser
        .process(&art_with_data("SOFTWARE", buf))
        .unwrap();
    let hive = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("hive record");
    let keys = hive.metadata["all_keys"].as_array().unwrap();
    let root = keys.iter().find(|k| k["depth"] == 0).unwrap();

    assert_eq!(root["subkey_count"], 9, "what the key declared");
    assert_eq!(root["subkeys_listed"], 3, "what its index names");
    assert_eq!(root["subkey_count_disagrees_with_index"], true);
    assert!(root["subkey_count_disagreement"]
        .as_str()
        .unwrap()
        .contains("index names 3"));
    // The index read without error, so this is a discrepancy and not a hole:
    // the incompleteness keys must stay absent or the two are conflated.
    assert!(root.get("subkeys_incomplete").is_none());
    assert_eq!(hive.metadata["walk_subkey_errors"], 0);

    // The same hive with the honest count says nothing, so the marker's
    // absence is a claim and not a default.
    let out = RegistryParser
        .process(&art_with_data(
            "SOFTWARE",
            build_hive_with_ri_children(false),
        ))
        .unwrap();
    let hive = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    let keys = hive.metadata["all_keys"].as_array().unwrap();
    let root = keys.iter().find(|k| k["depth"] == 0).unwrap();
    assert_eq!(root["subkey_count"], 3);
    assert_eq!(root["subkeys_listed"], 3);
    assert!(root.get("subkey_count_disagrees_with_index").is_none());
    // A leaf key declares no subkeys, so it has no index to have counted:
    // `subkeys_listed` is null rather than 0, which would be an answer.
    let leaf = keys.iter().find(|k| k["key_name"] == "Alpha").unwrap();
    assert_eq!(leaf["subkey_count"], 0);
    assert!(leaf["subkeys_listed"].is_null());
    assert!(leaf.get("subkey_count_disagrees_with_index").is_none());
}

/// HUNT-053. A hive lifted off a running machine has its newest writes only in
/// the transaction logs, so its two sequence numbers differ. The reader refused
/// every such hive outright, and the refusal was logged at `debug!` and produced
/// no artifacts — so a domain controller imaged while running yielded no OS
/// name, no computer name, no installed software and no accounts, rendering
/// exactly like a machine that had none of them.
///
/// Against the unfixed code this yields no hive record at all.
#[test]
fn a_hive_that_was_never_flushed_is_parsed_and_flagged_rather_than_refused() {
    let clean = art_with_data(
        "SOFTWARE",
        build_parseable_hive("CMI-CreateHive{TEST}", 7, 7),
    );
    let out = RegistryParser.process(&clean).unwrap();
    let hive_record = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("a clean hive parses");
    assert_eq!(hive_record.metadata["hive_dirty"], false);

    // The same hive, one flush behind its logs.
    let dirty = art_with_data(
        "SOFTWARE",
        build_parseable_hive("CMI-CreateHive{TEST}", 8, 7),
    );
    let out = RegistryParser.process(&dirty).unwrap();
    let hive_record = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("a dirty hive holds every key a clean one does and must still be parsed");
    assert_eq!(
        hive_record.metadata["hive_dirty"], true,
        "parsing it must not quietly present it as the captured state"
    );
    assert_eq!(hive_record.metadata["logs_replayed"], false);
    assert_eq!(hive_record.metadata["replay_reason"], "no_logs_found");
    assert_eq!(hive_record.metadata["primary_sequence"], 8);
    assert_eq!(hive_record.metadata["secondary_sequence"], 7);
    assert!(
        parse_failure_of(&out).is_none(),
        "a dirty hive that parsed is not a parse failure"
    );
}

/// HUNT-062. A Windows volume holds the same hive several times over — live,
/// `RegBack`, shadow copies — and they are one machine at different times. A
/// consumer that cannot tell them apart weighs the backup as a second witness
/// and refuses an answer the live hive gives. The record says which it is.
#[test]
fn a_hive_record_says_whether_it_came_from_the_live_path_or_regback() {
    let bytes = build_parseable_hive("CMI-CreateHive{TEST}", 7, 7);
    let mut live = art_with_data("SYSTEM", bytes.clone());
    live.metadata["path"] = serde_json::json!("/Windows/System32/config/SYSTEM");
    let out = RegistryParser.process(&live).unwrap();
    let rec = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    assert_eq!(rec.metadata["hive_role"], "live");
    assert_eq!(
        rec.metadata["source_path"],
        "/Windows/System32/config/SYSTEM"
    );

    let mut backup = art_with_data("SYSTEM", bytes.clone());
    backup.metadata["path"] = serde_json::json!("/Windows/System32/config/RegBack/SYSTEM");
    let out = RegistryParser.process(&backup).unwrap();
    let rec = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    assert_eq!(rec.metadata["hive_role"], "regback");

    // Backslash paths, as a loose file or a ZIP entry would carry.
    let mut win = art_with_data("SYSTEM", bytes);
    win.metadata["path"] = serde_json::json!("C:\\Windows\\System32\\config\\RegBack\\SYSTEM");
    let out = RegistryParser.process(&win).unwrap();
    let rec = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    assert_eq!(rec.metadata["hive_role"], "regback");

    // No path at all is not "live"; it is not known.
    let out = RegistryParser
        .process(&art_with_data(
            "SYSTEM",
            build_parseable_hive("CMI-CreateHive{TEST}", 7, 7),
        ))
        .unwrap();
    let rec = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .unwrap();
    assert_eq!(rec.metadata["hive_role"], "unknown");
}

/// HUNT-061. A shadow copy of `SOFTWARE` on the NIST Data Leakage image holds
/// 216,960 fewer bytes of hive bins than its base block declares. Every key up
/// to the cut is intact; the reader refused all 48 MB of them. It is parsed
/// now, and the record says what is missing and why its silence past the cut
/// is not evidence of absence.
#[test]
fn a_hive_shorter_than_its_header_declares_is_parsed_and_stamped_short() {
    let mut bytes = build_parseable_hive("CMI-CreateHive{TEST}", 7, 7);
    // Declare a second hbin the file does not hold, and re-checksum.
    bytes[0x28..0x2C].copy_from_slice(&0x2000u32.to_le_bytes());
    let mut sum: u32 = 0;
    for chunk in bytes[..0x1FC].as_chunks::<4>().0.iter() {
        sum ^= u32::from_le_bytes(*chunk);
    }
    let sum = match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    };
    bytes[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());

    let out = RegistryParser
        .process(&art_with_data("SOFTWARE", bytes))
        .unwrap();
    let rec = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("the intact cells are parsed rather than the hive refused");
    assert_eq!(rec.metadata["hive_declared_data_bytes"], 0x2000);
    assert_eq!(rec.metadata["hive_present_data_bytes"], 0x1000);
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(rec.metadata["content_incomplete_reason"], "short_read");
    assert!(rec.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("4096 bytes"));
    assert!(
        parse_failure_of(&out).is_none(),
        "a hive that parsed is not a parse failure"
    );
}

/// Build a minimal registry hive containing a single NK (key node) cell with
/// the given name and last-write FILETIME. Enough structure for the raw NK
/// scanner: a `regf` base block, one `hbin`, and one allocated NK cell.
fn build_minimal_hive_with_key(name: &str, filetime: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 0x2000]; // 0x1000 base block + one 0x1000 hbin
    buf[0..4].copy_from_slice(b"regf");

    // hbin header at 0x1000.
    buf[0x1000..0x1004].copy_from_slice(b"hbin");
    buf[0x1008..0x100c].copy_from_slice(&0x1000u32.to_le_bytes()); // hbin size

    // NK cell at 0x1020 (first cell after the 0x20 hbin header).
    let cell = 0x1020usize;
    let name_bytes = name.as_bytes();
    let unaligned = 4 + 76 + name_bytes.len();
    let cell_len = (unaligned + 7) & !7;
    buf[cell..cell + 4].copy_from_slice(&(-(cell_len as i32)).to_le_bytes()); // allocated

    let d = cell + 4;
    buf[d..d + 2].copy_from_slice(b"nk");
    buf[d + 2..d + 4].copy_from_slice(&0x2Cu16.to_le_bytes()); // KEY_HIVE_ENTRY | KEY_COMP_NAME
    buf[d + 4..d + 12].copy_from_slice(&filetime.to_le_bytes()); // last-write time
    buf[d + 16..d + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // parent = none (root)
    buf[d + 72..d + 74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf[d + 76..d + 76 + name_bytes.len()].copy_from_slice(name_bytes);

    buf
}

/// The same minimal hive, but the key name is written as raw bytes rather than
/// UTF-8 -- which is how a real hive stores a KEY_COMP_NAME.
fn build_minimal_hive_with_key_bytes(name_bytes: &[u8], filetime: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 0x2000];
    buf[0..4].copy_from_slice(b"regf");
    buf[0x1000..0x1004].copy_from_slice(b"hbin");
    buf[0x1008..0x100c].copy_from_slice(&0x1000u32.to_le_bytes());

    let cell = 0x1020usize;
    let unaligned = 4 + 76 + name_bytes.len();
    let cell_len = (unaligned + 7) & !7;
    buf[cell..cell + 4].copy_from_slice(&(-(cell_len as i32)).to_le_bytes());

    let d = cell + 4;
    buf[d..d + 2].copy_from_slice(b"nk");
    buf[d + 2..d + 4].copy_from_slice(&0x2Cu16.to_le_bytes()); // KEY_COMP_NAME set
    buf[d + 4..d + 12].copy_from_slice(&filetime.to_le_bytes());
    buf[d + 16..d + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[d + 72..d + 74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf[d + 76..d + 76 + name_bytes.len()].copy_from_slice(name_bytes);
    buf
}

/// REG-001. A KEY_COMP_NAME is one byte per character in the system ANSI code
/// page. Decoding it with `b as char` is ISO-8859-1: correct from 0xA0 up, and
/// wrong across 0x80-0x9F, where CP1252 carries punctuation. Byte 0x92 became
/// U+0092, an unprintable C1 control, instead of the right single quotation
/// mark the key was actually named with -- so the key rendered as an
/// unprintable and matched no keyword search, on a hive where the key name is
/// frequently the whole finding.
///
/// Against the unfixed code the name holds U+0092 and the assertion fails.
#[test]
fn a_key_name_in_the_cp1252_punctuation_block_is_not_read_as_latin1() {
    let filetime = 132_223_104_000_000_000u64;
    // `Don<0x92>t Delete` -- a real shape for a key an owner named defensively.
    let buf = build_minimal_hive_with_key_bytes(b"Don\x92t Delete", filetime);

    let scan = extract_key_write_events(&buf, Uuid::new_v4(), Uuid::new_v4());
    let ev = &scan.events[0];
    let short = ev.metadata["short_desc"].as_str().unwrap();
    assert!(
        short.contains("Don\u{2019}t Delete"),
        "0x92 is a right single quotation mark in the ANSI code page, not a control \
         character; got {short:?}"
    );
    assert!(
        !short.contains('\u{0092}'),
        "a C1 control in a key name is the ISO-8859-1 misreading this fix removes: {short:?}"
    );
}

#[test]
fn test_extract_key_write_events_emits_timeline_event() {
    // FILETIME for 2020-01-01T00:00:00Z.
    let filetime = 132_223_104_000_000_000u64;
    let buf = build_minimal_hive_with_key("RootKey", filetime);

    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let scan = extract_key_write_events(&buf, case_id, parent_id);
    assert!(scan.complete(), "a small hive is scanned in full");
    assert_eq!(scan.cap_reason(), None);

    let events = scan.events;
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.artifact_type, ArtifactType::TimelineEvent);
    assert_eq!(ev.parent_id, Some(parent_id));
    assert_eq!(
        ev.metadata["source_module"],
        "plugin.windows.registry_parser"
    );
    let short = ev.metadata["short_desc"].as_str().unwrap();
    assert!(!short.is_empty());
    assert!(short.contains("RootKey"));
    let ts = ev.metadata["timestamp"].as_str().unwrap();
    assert!(
        ts.starts_with("2020-01-01T00:00:00"),
        "unexpected ts: {}",
        ts
    );
}

#[test]
fn a_cell_running_past_the_end_of_its_bin_stops_the_scan_and_says_so() {
    // A cell whose declared length overruns its bin makes every key stored
    // after it in that bin unreachable. Ending the bin quietly — which is what
    // the walk used to do — leaves the hive artifact asserting a complete
    // key-write timeline over cells nothing ever read, so "no key was written
    // after the last event shown" would be reading the damage.
    let filetime = 132_223_104_000_000_000u64;
    let mut buf = build_minimal_hive_with_key("RootKey", filetime);

    // The NK cell sits at 0x1020. Put a second cell straight after it that
    // claims to be longer than the bin has room for.
    let first_len = {
        let raw = i32::from_le_bytes([buf[0x1020], buf[0x1021], buf[0x1022], buf[0x1023]]);
        raw.unsigned_abs() as usize
    };
    let second = 0x1020 + first_len;
    buf[second..second + 4].copy_from_slice(&(-0x8000i32).to_le_bytes());

    let scan = extract_key_write_events(&buf, Uuid::new_v4(), Uuid::new_v4());
    assert!(
        !scan.complete(),
        "a bin the walk could not read to the end of is not a scanned bin"
    );
    assert!(
        scan.cap_reason().is_some(),
        "an incomplete scan must state why it is short"
    );
    // The keys read before the damage are still evidence and are still emitted.
    assert_eq!(scan.events.len(), 1);
}

#[test]
fn a_bin_whose_cells_tile_it_exactly_reports_a_complete_scan() {
    // The counterpart the fix must not break: unwritten tail bytes inside a bin
    // are not damage, so a small hive still reads as fully walked.
    let buf = build_minimal_hive_with_key("RootKey", 132_223_104_000_000_000u64);
    let scan = extract_key_write_events(&buf, Uuid::new_v4(), Uuid::new_v4());
    assert!(scan.complete());
    assert_eq!(scan.cap_reason(), None);
}

#[test]
fn test_extract_key_write_events_on_a_non_hive_reports_an_unwalked_scan() {
    let scan = extract_key_write_events(b"not a hive", Uuid::new_v4(), Uuid::new_v4());
    assert!(scan.events.is_empty());
    // No cell was ever examined. Reporting that as a complete scan would let
    // the hive artifact assert "no key was written after the last event shown"
    // about evidence nothing ever walked, so the scan must fail closed.
    assert!(
        !scan.complete(),
        "a buffer that is not a readable hive must not report a finished scan"
    );
    assert!(
        scan.cap_reason().is_some(),
        "an incomplete scan must state why it is short"
    );
}

#[test]
fn a_key_scan_that_hits_its_event_cap_reports_the_timeline_as_incomplete() {
    // The scan struct is the honesty contract: an examiner must be able to tell
    // a fully-walked hive from one the caps cut short.
    let complete = KeyWriteScan {
        events: Vec::new(),
        live_cells: HashMap::new(),
        cells_capped: false,
        events_capped: false,
        structure_stopped: false,
    };
    assert!(complete.complete());
    assert_eq!(complete.cap_reason(), None);

    let capped_cells = KeyWriteScan {
        events: Vec::new(),
        live_cells: HashMap::new(),
        cells_capped: true,
        events_capped: false,
        structure_stopped: false,
    };
    assert!(!capped_cells.complete());
    assert_eq!(capped_cells.cap_reason(), Some("nk_cell_cap"));

    let capped_events = KeyWriteScan {
        events: Vec::new(),
        live_cells: HashMap::new(),
        cells_capped: false,
        events_capped: true,
        structure_stopped: false,
    };
    assert!(!capped_events.complete());
    assert_eq!(capped_events.cap_reason(), Some("timeline_event_cap"));

    let both = KeyWriteScan {
        events: Vec::new(),
        live_cells: HashMap::new(),
        cells_capped: true,
        events_capped: true,
        structure_stopped: false,
    };
    assert_eq!(
        both.cap_reason(),
        Some("nk_cell_cap_and_timeline_event_cap")
    );

    // A bin chain that ended on non-bin bytes is neither cap, and used to end
    // the scan with nothing said: the keys stored past that point were never
    // examined, so "no key was written after X" would be reading the break.
    let broken = KeyWriteScan {
        events: Vec::new(),
        live_cells: HashMap::new(),
        cells_capped: false,
        events_capped: false,
        structure_stopped: true,
    };
    assert!(!broken.complete());
    assert_eq!(broken.cap_reason(), Some("hbin_chain_ended_early"));
}

// Note: Full integration test with actual registry hive file
// would be added in seance_tests/src/registry_full_chain_test.rs

/// Declares twice the bytes it can deliver: a hive truncated on disk, or one
/// whose backing extents run out part-way through the image.
fn art_with_short_data(name: &str, data: Vec<u8>) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(data));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": name }),
    )
}

/// B3-016: the hive buffer was loaded with `read_capped` and the shortfall
/// against the declared size was never compared, so a hive staged in part
/// parsed into a key set presented as the whole hive. What an examiner learns:
/// whether the keys shown are all the hive holds. A missing `Run` entry or USB
/// serial past the staged bytes would otherwise read as a program that was
/// never installed or a device that was never attached.
#[test]
fn a_hive_staged_short_is_reported_rather_than_returning_silence() {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"regf");
    let art = art_with_short_data("SYSTEM", buf);

    let out = RegistryParser.process(&art).unwrap();
    let marker = out
        .iter()
        .find(|a| a.metadata.get("status").and_then(|v| v.as_str()) == Some("HiveNotStagedInFull"))
        .expect("a hive that could not be staged in full must say so, not return an empty list");
    assert_eq!(
        marker.metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(marker.metadata["staged_bytes"], serde_json::json!(4096));
    assert_eq!(marker.metadata["declared_bytes"], serde_json::json!(8192));
}

/// The counterpart: a hive read whole and parsed must stay unmarked, or the
/// marker means nothing.
#[test]
fn a_hive_read_whole_carries_no_staging_marker() {
    let hive = build_parseable_hive("CMI-CreateHive{TEST}", 7, 7);
    let out = RegistryParser
        .process(&art_with_data("SYSTEM", hive))
        .unwrap();
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
    assert!(out
        .iter()
        .all(|a| a.metadata.get("status").and_then(|v| v.as_str()) != Some("HiveNotStagedInFull")));
}

/// The stamp is applied to records too, not only to the marker: a value read
/// out of a partial hive carries the fact wherever it is exported.
#[test]
fn the_staging_stamp_marks_records_as_well_as_emitting_a_marker() {
    let mut out = vec![Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({ "type": "RegistryHive", "hive_type": "SYSTEM" }),
    )];
    let case_id = out[0].case_id;
    stamp_staging_shortfall(
        Some(seance_core::io::IncompleteReason::CapReached),
        case_id,
        Uuid::new_v4(),
        "SYSTEM",
        1_073_741_824,
        536_870_912,
        &mut out,
    );
    assert_eq!(out.len(), 2, "records stamped, one marker appended");
    assert_eq!(
        out[0].metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(out[0].metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(out[1].metadata["subtype"], "parse_incomplete");
    assert!(out[1].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("536870912 of 1073741824 bytes"));

    // A complete staging leaves everything untouched.
    let mut whole = vec![Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({ "type": "RegistryHive" }),
    )];
    stamp_staging_shortfall(None, case_id, Uuid::new_v4(), "SYSTEM", 10, 10, &mut whole);
    assert_eq!(whole.len(), 1);
    assert!(whole[0].metadata.get("content_incomplete").is_none());
}

/// Same class as B3-016, found by sweeping the crate: the traversal depth limit
/// stopped the key walk with only a `warn!`, so the keys below it were absent
/// from `all_keys` with nothing to say the walk had stopped. An examiner
/// reading "no Run key" from a capped inventory would be reading a cap, not the
/// hive.
#[test]
fn a_key_walk_stopped_by_the_depth_limit_says_so_on_the_hive_record() {
    let mut meta = serde_json::json!({ "type": "RegistryHive", "total_keys": 12 });
    stamp_inventory_cap(&mut meta, &capped_ctx());
    assert_eq!(meta["inventory_incomplete"], serde_json::json!(true));
    assert_eq!(meta["content_incomplete"], serde_json::json!(true));
    assert_eq!(meta["content_incomplete_reason"], "cap_reached");
    assert!(meta["incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("not from the hive"));

    // A completed walk stays unmarked, or the marker means nothing.
    let mut whole = serde_json::json!({ "type": "RegistryHive" });
    stamp_inventory_cap(&mut whole, &clean_ctx());
    assert!(whole.get("inventory_incomplete").is_none());
    assert!(whole.get("content_incomplete").is_none());
    // The counts are always stated, so "nothing was lost" is a positive claim.
    assert_eq!(whole["walk_subkey_errors"], serde_json::json!(0));
    assert_eq!(whole["walk_value_errors"], serde_json::json!(0));
}

/// A walk whose iterator refused key or value nodes returns a shorter key list.
/// B4-032: those drops used to vanish into `flatten()`, so a hive missing whole
/// subtrees presented as a complete inventory.
#[test]
fn undecodable_key_nodes_are_counted_on_the_hive_record() {
    let mut meta = serde_json::json!({ "type": "RegistryHive" });
    let ctx = TraversalContext {
        all_keys: Vec::new(),
        all_values: Vec::new(),
        timeline_events: Vec::new(),
        usb_devices: Vec::new(),
        layered: crate::LayeredKeyCounts::default(),
        depth_capped: false,
        subkey_errors: 3,
        value_errors: 7,
        security: crate::security::SecurityInventory::default(),
        resident: crate::resident::ResidentCapture::default(),
        value_bytes: crate::ValueBytesBudget::with_limit(0),
    };
    stamp_inventory_cap(&mut meta, &ctx);
    assert_eq!(meta["walk_subkey_errors"], serde_json::json!(3));
    assert_eq!(meta["walk_value_errors"], serde_json::json!(7));
    assert_eq!(meta["content_incomplete"], serde_json::json!(true));
    assert_eq!(meta["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(meta["inventory_incomplete"], serde_json::json!(true));
}

fn clean_ctx() -> TraversalContext {
    TraversalContext {
        all_keys: Vec::new(),
        all_values: Vec::new(),
        timeline_events: Vec::new(),
        usb_devices: Vec::new(),
        layered: crate::LayeredKeyCounts::default(),
        depth_capped: false,
        subkey_errors: 0,
        value_errors: 0,
        security: crate::security::SecurityInventory::default(),
        resident: crate::resident::ResidentCapture::default(),
        value_bytes: crate::ValueBytesBudget::with_limit(0),
    }
}

fn capped_ctx() -> TraversalContext {
    TraversalContext {
        depth_capped: true,
        ..clean_ctx()
    }
}

/// The key walk now records *when* each key was last written, and how many
/// subkeys and values it holds.
///
/// Until 2026-09-13 the reader under this plugin kept the NK timestamp
/// private, so a key record carried a path and a depth and nothing about the
/// key itself — an examiner reading the key inventory could not tell a key
/// written during the incident from one written at install. `seance_hive`
/// exposes all three, and a record that omits what the evidence holds is a
/// silence this project does not leave.
#[test]
fn a_walked_key_carries_its_last_write_time_and_its_counts() {
    // 132,223,104,000,000,000 is the FILETIME `build_parseable_hive` writes.
    let hive = build_parseable_hive("ROOT", 7, 7);
    let art = art_with_data("SYSTEM", hive);
    let out = RegistryParser.process(&art).unwrap();
    let hive_record = out
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("a hive record");
    let keys = hive_record.metadata["all_keys"]
        .as_array()
        .expect("the key inventory");
    let root = keys.first().expect("the root key");
    assert_eq!(
        root["last_written"].as_str(),
        Some("2020-01-01T00:00:00+00:00"),
        "the key record must carry the time the key was last written"
    );
    assert_eq!(root["subkey_count"].as_u64(), Some(0));
    assert_eq!(root["value_count"].as_u64(), Some(0));
}

/// A real hive's root `nk` does not hold `0xFFFFFFFF` in its parent field —
/// the plaso `SAM`'s root points at `0x4f8`, whatever the kernel left there.
/// The chain has to end on the root's `KEY_HIVE_ENTRY` flag; ending only on
/// the sentinel means that when the stray offset lands on a live key, that
/// key's name is prepended to every path in the hive.
#[test]
fn a_key_path_ends_at_the_root_flag_not_at_whatever_the_roots_parent_field_holds() {
    let mut buf = build_hive_with_ri_children(false);
    // Point the root's parent field at its own child Alpha (the first cell
    // after the root, at bin offset 0x20 + 88).
    let d = 0x1020 + 4;
    buf[d + 16..d + 20].copy_from_slice(&(0x20u32 + 88).to_le_bytes());
    let scan = extract_key_write_events(&buf, Uuid::new_v4(), Uuid::new_v4());
    let paths: Vec<&str> = scan
        .events
        .iter()
        .map(|e| e.metadata["key_path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"ROOT"), "{paths:?}");
    assert!(paths.contains(&"ROOT\\Beta"), "{paths:?}");
    assert!(
        !paths.iter().any(|p| p.starts_with("Alpha\\")),
        "the root's stray parent offset must not become a path segment: {paths:?}"
    );
}

/// HUNT-277: a registry hive inside a shadow copy is opened, and nothing it
/// yields can be read as the live hive — every record repeats the snapshot
/// identity, and a timeline event says so in the text the timeline shows. A
/// `ParsedRecord` that is not a prior version is not read at all.
#[test]
fn a_shadow_copy_prior_version_hive_is_parsed_and_every_output_says_so() {
    let hive = build_hive_with_ri_children_for_tests();
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(hive));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src.clone()),
        json!({
            "type": "VssPriorVersion",
            "name": "SYSTEM [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "SYSTEM",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = RegistryParser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version's hive is parsed");
    let hive = out
        .iter()
        .find(|a| a.metadata["type"] == json!("RegistryHive"))
        .expect("the hive record");
    assert_eq!(
        hive.metadata["hive_type"],
        json!("SYSTEM"),
        "the hive is classified by its own name, not the shadow-copy label"
    );
    for a in &out {
        assert_eq!(
            a.metadata["vss_snapshot_id"],
            json!("snap-1"),
            "{}",
            a.metadata
        );
        assert_eq!(a.metadata["is_snapshot_version"], json!(true));
    }
    for ev in out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
    {
        assert!(
            ev.metadata["short_desc"]
                .as_str()
                .unwrap()
                .starts_with("[shadow copy 2015-03-23T00:00:00Z] "),
            "{}",
            ev.metadata
        );
    }

    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        json!({ "type": "SomethingElse" }),
    );
    assert!(RegistryParser.process(&other).unwrap().is_empty());
}

/// The ri hive with its base block set to minor version 6 and two of its three
/// children carrying layered-key bits: `Beta` a tombstone, `Gamma` a supersede
/// tree. What a container's differencing hive looks like to a reader of one
/// file.
fn differencing_hive() -> Vec<u8> {
    let mut buf = build_hive_with_ri_children_for_tests();
    buf[0x18..0x1C].copy_from_slice(&6u32.to_le_bytes());
    let nk_of = |buf: &Vec<u8>, name: &str| -> usize {
        let at = buf
            .windows(name.len())
            .position(|w| w == name.as_bytes())
            .unwrap_or_else(|| panic!("{name} is in the fixture"));
        at - 76 // the name follows the 76-byte nk header
    };
    let beta = nk_of(&buf, "Beta");
    let gamma = nk_of(&buf, "Gamma");
    buf[beta + 0x0D] = 1; // IsTombstone
    buf[gamma + 0x0D] = 3 | 0x80; // IsSupersedeTree, inherit class
    let mut sum: u32 = 0;
    for chunk in buf[..0x1FC].as_chunks::<4>().0.iter() {
        sum ^= u32::from_le_bytes(*chunk);
    }
    let sum = match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    };
    buf[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
    buf
}

fn hive_record(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == serde_json::json!("RegistryHive"))
        .expect("the hive record")
}

/// §5.9: a differencing hive is a list of one layer's changes, not a registry.
/// Read as an ordinary hive its tombstoned key looks live and every key it does
/// not hold looks absent, so the record says what it is, counts the layered
/// keys, and marks each one.
#[test]
fn a_differencing_hive_is_reported_as_changes_not_as_a_registry() {
    let out = RegistryParser
        .process(&art_with_data("System_Delta", differencing_hive()))
        .unwrap();
    let meta = &hive_record(&out).metadata;
    assert_eq!(meta["hive_minor_version"], serde_json::json!(6));
    assert_eq!(meta["differencing_hive"], serde_json::json!(true));
    assert_eq!(meta["layered_keys"]["tombstone"], serde_json::json!(1));
    assert_eq!(meta["layered_keys"]["supersede_tree"], serde_json::json!(1));
    assert_eq!(
        meta["layered_keys"]["supersede_local"],
        serde_json::json!(0)
    );
    let statement = meta["differencing_statement"]
        .as_str()
        .expect("says what it is");
    assert!(statement.contains("not a registry"), "{statement}");
    assert!(statement.contains("base"), "{statement}");

    let keys = meta["all_keys"].as_array().unwrap();
    let semantics = |name: &str| {
        keys.iter()
            .find(|k| k["key_name"] == serde_json::json!(name))
            .unwrap_or_else(|| panic!("{name} listed"))["layer_semantics"]
            .clone()
    };
    assert_eq!(semantics("Beta"), serde_json::json!("tombstone"));
    assert_eq!(semantics("Gamma"), serde_json::json!("supersede_tree"));
    assert_eq!(
        semantics("Alpha"),
        serde_json::Value::Null,
        "an ordinary key says nothing"
    );
}

#[test]
fn an_ordinary_hive_is_not_called_a_differencing_hive() {
    let out = RegistryParser
        .process(&art_with_data(
            "SYSTEM",
            build_hive_with_ri_children_for_tests(),
        ))
        .unwrap();
    let meta = &hive_record(&out).metadata;
    assert!(meta.get("differencing_hive").is_none());
    assert!(meta.get("differencing_statement").is_none());
    assert!(
        meta["hive_minor_version"].is_number(),
        "the version is always recorded"
    );
}

/// A minor-6 hive whose keys carry no layer bits is not claimed to be a
/// differencing hive: the version alone does not make it one.
#[test]
fn a_minor_6_hive_with_no_layered_keys_makes_no_differencing_claim() {
    let mut buf = build_hive_with_ri_children_for_tests();
    buf[0x18..0x1C].copy_from_slice(&6u32.to_le_bytes());
    let mut sum: u32 = 0;
    for chunk in buf[..0x1FC].as_chunks::<4>().0.iter() {
        sum ^= u32::from_le_bytes(*chunk);
    }
    buf[0x1FC..0x200].copy_from_slice(&(if sum == 0 { 1 } else { sum }).to_le_bytes());
    let out = RegistryParser
        .process(&art_with_data("SOFTWARE", buf))
        .unwrap();
    let meta = &hive_record(&out).metadata;
    assert_eq!(meta["hive_minor_version"], serde_json::json!(6));
    assert!(meta.get("differencing_hive").is_none());
}
