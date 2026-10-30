//! How a value's data reaches the hive record: the rendering an examiner reads,
//! and the stored bytes a consumer needs (`HUNT-158`, `HUNT-159`).
//!
//! # Where the fixtures come from
//!
//! Two kinds, and the difference matters:
//!
//! * **Synthetic, from the published format** — a hive the reader fully
//!   accepts (`tests::build_parseable_hive`) whose root key is given a value
//!   list and `vk` cells laid out as Suhanov's `regf` notes describe: data of
//!   four bytes or fewer inline in the offset field with the size's high bit
//!   set, larger data in its own allocated cell. **No hive on this machine
//!   holds a `REG_DWORD_BIG_ENDIAN` value** — a byte scan of every `vk` cell in
//!   the eight hives under `reference/plaso/test_data` found none — so the
//!   big-endian case is pinned on this synthetic hive only, and a synthetic
//!   fixture is not validation.
//! * **Real**: plaso's `NTUSER-WIN7.DAT` and `NTUSER.DAT`, through the whole
//!   parser, when `SEANCE_REGISTRY_CORPUS` names the directory.

use super::tests::{art_with_data, build_parseable_hive};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use seance_core::module::ForensicsModule;

const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

/// Where `build_parseable_hive("ROOT", ..)` leaves the bin's cursor: past the
/// root `nk`.
const AFTER_ROOT: usize = 0x1020 + ((4 + 76 + 4 + 7) & !7);

fn append_allocated_cell(buf: &mut [u8], cursor: &mut usize, payload: &[u8]) -> u32 {
    let size = (payload.len() + 4 + 7) & !7;
    let at = *cursor;
    assert!(at + size <= buf.len(), "fixture bin is full");
    buf[at..at + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
    buf[at + 4..at + 4 + payload.len()].copy_from_slice(payload);
    *cursor += size;
    (at - 0x1000) as u32
}

/// A parseable hive whose root key holds `values`, each `(name, type, data)`.
pub(crate) fn hive_with_values(values: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
    let mut buf = build_parseable_hive("ROOT", 7, 7);
    let mut cursor = AFTER_ROOT;
    let mut vk_offsets = Vec::new();
    for (name, data_type, data) in values {
        let nb = name.as_bytes();
        let mut vk = vec![0u8; 20 + nb.len()];
        vk[0..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(nb.len() as u16).to_le_bytes());
        if data.len() <= 4 {
            // Inline: the bytes sit in the offset field, the high bit of the
            // size says so.
            vk[4..8].copy_from_slice(&(data.len() as u32 | 0x8000_0000).to_le_bytes());
            vk[8..8 + data.len()].copy_from_slice(data);
        } else {
            let at = append_allocated_cell(&mut buf, &mut cursor, data);
            vk[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            vk[8..12].copy_from_slice(&at.to_le_bytes());
        }
        vk[12..16].copy_from_slice(&data_type.to_le_bytes());
        vk[16..18].copy_from_slice(&1u16.to_le_bytes()); // VALUE_COMP_NAME
        vk[20..].copy_from_slice(nb);
        vk_offsets.push(append_allocated_cell(&mut buf, &mut cursor, &vk));
    }
    let list: Vec<u8> = vk_offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
    let list_at = append_allocated_cell(&mut buf, &mut cursor, &list);
    // The root `nk`: value count at 0x24, value list offset at 0x28.
    let d = 0x1020 + 4;
    buf[d + 0x24..d + 0x28].copy_from_slice(&(values.len() as u32).to_le_bytes());
    buf[d + 0x28..d + 0x2C].copy_from_slice(&list_at.to_le_bytes());
    buf
}

fn hive_record(buf: Vec<u8>) -> serde_json::Value {
    super::RegistryParser
        .process(&art_with_data("NTUSER.DAT", buf))
        .unwrap()
        .into_iter()
        .map(|a| a.metadata)
        .find(|m| m["type"] == "RegistryHive")
        .expect("a hive record")
}

fn value<'a>(hive: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    hive["all_values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["value_name"] == name)
        .unwrap_or_else(|| panic!("value {name} in {hive}"))
}

fn utf16z(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend(p.encode_utf16().flat_map(u16::to_le_bytes));
        out.extend_from_slice(&[0, 0]);
    }
    out
}

/// `HUNT-158`. A `REG_DWORD_BIG_ENDIAN` value is a big-endian number. Its type
/// name contains `RegDWord`, and a substring match sent it down the
/// little-endian branch: bytes `00 00 01 00` rendered as 65536 where the value
/// is 256. The same four bytes as a `REG_DWORD` are 65536, and still must be.
#[test]
fn a_big_endian_dword_is_rendered_as_the_big_endian_number() {
    let bytes = vec![0x00, 0x00, 0x01, 0x00];
    let hive = hive_record(hive_with_values(&[
        ("Big", REG_DWORD_BIG_ENDIAN, bytes.clone()),
        ("Little", REG_DWORD, bytes),
    ]));
    let big = value(&hive, "Big");
    assert_eq!(big["value_type"], "RegDWordBigEndian");
    assert_eq!(big["value_data"], "0x00000100 (256)");
    let little = value(&hive, "Little");
    assert_eq!(little["value_type"], "RegDWord");
    assert_eq!(little["value_data"], "0x00010000 (65536)");
}

/// `HUNT-159`. Every value carries its stored bytes, not only a binary one
/// over 64 bytes: a string, a multi-string, a DWORD, a QWORD and a short binary
/// published a rendering and nothing a consumer could hash, scan or export
/// exactly. And a `REG_MULTI_SZ` whose element contains the display separator
/// `" | "` cannot be split back out of the rendering, so its elements are
/// published as an array beside it.
#[test]
fn every_value_publishes_its_stored_bytes_and_a_multi_string_its_elements() {
    let values: Vec<(&str, u32, Vec<u8>)> = vec![
        ("Str", REG_SZ, utf16z(&["hello"])),
        ("Multi", REG_MULTI_SZ, {
            let mut m = utf16z(&["a | b", "c"]);
            m.extend_from_slice(&[0, 0]); // the empty string that ends the list
            m
        }),
        ("Dw", REG_DWORD, 42u32.to_le_bytes().to_vec()),
        ("BigEndian", REG_DWORD_BIG_ENDIAN, vec![0, 0, 0, 7]),
        (
            "Qw",
            REG_QWORD,
            0x0102_0304_0506_0708u64.to_le_bytes().to_vec(),
        ),
        ("Bin", REG_BINARY, vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]),
        ("Large", REG_BINARY, (0..100u8).collect()),
    ];
    let hive = hive_record(hive_with_values(&values));
    for (name, _, bytes) in &values {
        let v = value(&hive, name);
        let b64 = v["value_data_b64"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} publishes no bytes: {v}"));
        assert_eq!(&BASE64.decode(b64).unwrap(), bytes, "{name}");
        assert_eq!(v["raw_data_size"], bytes.len(), "{name}");
    }
    // The rendering is unchanged, and the elements are exact beside it.
    let multi = value(&hive, "Multi");
    assert_eq!(multi["value_data"], "a | b | c");
    assert_eq!(multi["value_data_list"], serde_json::json!(["a | b", "c"]));
    // Only a multi-string has elements.
    assert!(value(&hive, "Str")["value_data_list"].is_null());
    // The cap is stated on the record, and that nothing was held back by it.
    assert!(hive["value_bytes_budget_bytes"].as_u64().unwrap() > 0);
    assert_eq!(hive["value_bytes_complete"], true);
    assert_eq!(hive["value_bytes_omitted"], 0);
}

/// The per-hive cap on published value bytes. A value of at most 64 bytes is
/// always published — its bytes cost less than most renderings — and a larger
/// value that would take the hive past the cap is published without them and
/// counted, never silently.
#[test]
fn the_value_byte_budget_admits_small_values_always_and_counts_what_it_refuses() {
    let mut budget = super::ValueBytesBudget::with_limit(150);
    assert!(budget.admit(64));
    assert!(budget.admit(100)); // 100 of 150
    assert!(!budget.admit(100)); // would pass the cap
    assert!(budget.admit(8), "a small value is never held back");
    assert!(budget.admit(50)); // exactly to the cap
    assert!(!budget.admit(65));
    assert_eq!(budget.omitted, 2);

    let mut hive = serde_json::json!({});
    budget.stamp(&mut hive);
    assert_eq!(hive["value_bytes_complete"], false);
    assert_eq!(hive["value_bytes_omitted"], 2);
    assert_eq!(hive["value_bytes_budget_bytes"], 150);
    assert!(hive["value_bytes_detail"]
        .as_str()
        .unwrap()
        .contains("2 values"));
}

/// The real hives. Every value the parser read carries exactly its stored
/// bytes, and every `REG_MULTI_SZ` its elements. Before `HUNT-159`, only the
/// binary values over 64 bytes did: on plaso's `NTUSER.DAT` YARA could scan
/// 2,033 of 5,602 values as exact bytes.
#[test]
fn every_value_on_the_real_hives_carries_its_stored_bytes() {
    for name in ["NTUSER-WIN7.DAT", "NTUSER.DAT"] {
        let Some(bytes) = super::userassist_tests::corpus_hive_for_tests(name) else {
            return;
        };
        let all = super::userassist_tests::records_for_tests(name, bytes);
        let hive = all.iter().find(|r| r["type"] == "RegistryHive").unwrap();
        let values = hive["all_values"].as_array().unwrap();
        assert_eq!(hive["value_bytes_complete"], true, "{name}");
        let mut with_bytes = 0usize;
        let mut multi = 0usize;
        for v in values {
            let at = format!("{name}: {} / {}", v["key_path"], v["value_name"]);
            let rendering = v["value_data"].as_str().unwrap_or("");
            if rendering.starts_with("(error ") {
                assert!(v["value_data_b64"].is_null(), "{at}");
                continue;
            }
            let decoded = BASE64
                .decode(
                    v["value_data_b64"]
                        .as_str()
                        .unwrap_or_else(|| panic!("{at}")),
                )
                .unwrap();
            assert_eq!(
                decoded.len() as u64,
                v["raw_data_size"].as_u64().unwrap(),
                "{at}"
            );
            with_bytes += 1;
            if v["value_type"] == "RegMultiSZ" {
                multi += 1;
                let list = v["value_data_list"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{at}"));
                // The rendering is the elements joined; the elements are exact.
                let joined: Vec<&str> = list.iter().map(|e| e.as_str().unwrap()).collect();
                assert_eq!(joined.join(" | "), rendering, "{at}");
            }
        }
        match name {
            // Counted on the hive before the assertion was written: 5,470
            // values, 304 of them `REG_MULTI_SZ`; none failed to read.
            "NTUSER-WIN7.DAT" => {
                assert_eq!(values.len(), 5470);
                assert_eq!(with_bytes, 5470);
                assert_eq!(multi, 304);
            }
            _ => {
                assert_eq!(values.len(), 5602);
                assert_eq!(with_bytes, 5602);
            }
        }
    }
}
