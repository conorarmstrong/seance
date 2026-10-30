//! The big-page pool tracker: every slot read, free slots told apart from
//! empty ones, and the kernel's own in-use counter compared with the walk.

use super::big_pool::*;
use crate::image_fixture::{Image, BASE_TYPES_X64, BASE_TYPES_X86};
use crate::poolscan::test_support::{profile, table};
use seance_memory::Architecture;

const POOL_BIG_PAGE_TABLE: u64 = 0x100;
const POOL_BIG_PAGE_TABLE_SIZE: u64 = 0x108;
const EXP_POOL_BIG_ENTRIES_IN_USE: u64 = 0x110;
const TABLE: u64 = 0x1_0000;
const ENTRY_SIZE: u64 = 32;

/// Which optional members this build declares.
#[derive(Clone, Copy)]
struct Declares {
    pool_type: bool,
    pool_flags: bool,
    in_use_counter: bool,
}

fn isf(d: Declares) -> String {
    let classification = if d.pool_type {
        r#","PoolType": {"offset": 12, "type": {"kind": "enum", "name": "_POOL_TYPE"}}"#.to_string()
    } else if d.pool_flags {
        r#","PoolFlags": {"offset": 12, "type": {"kind": "bitfield", "bit_position": 8, "bit_length": 12, "type": {"kind": "base", "name": "unsigned long"}}}"#.to_string()
    } else {
        String::new()
    };
    let counter = if d.in_use_counter {
        format!(r#","ExpPoolBigEntriesInUse": {{"address": {EXP_POOL_BIG_ENTRIES_IN_USE}}}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base},
  "user_types": {{
    "_POOL_TRACKER_BIG_PAGES": {{"size": {ENTRY_SIZE}, "kind": "struct", "fields": {{
      "Va": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Key": {{"offset": 8, "type": {{"kind": "base", "name": "unsigned long"}}}}{classification},
      "NumberOfBytes": {{"offset": 16, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "ProcessBilled": {{"offset": 24, "type": {{"kind": "pointer",
                        "subtype": {{"kind": "struct", "name": "_EPROCESS"}}}}}}
    }}}},
    "_EPROCESS": {{"size": 64, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": 0, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "base", "name": "void"}}}}}}
    }}}}
  }},
  "enums": {{
    "_POOL_TYPE": {{"base": "long", "size": 4, "constants": {{
      "NonPagedPool": 0, "PagedPool": 1, "NonPagedPoolNx": 512
    }}}}
  }},
  "symbols": {{
    "PoolBigPageTable": {{"address": {POOL_BIG_PAGE_TABLE}}},
    "PoolBigPageTableSize": {{"address": {POOL_BIG_PAGE_TABLE_SIZE}}}{counter}
  }}
}}"#,
        base = BASE_TYPES_X64,
    )
}

/// `(va, tag, bytes, pool type or flags)` per slot; `va == 0` is an empty slot.
fn image(slots: &[(u64, &[u8; 4], u64, u32)], in_use_counter: u64) -> Image {
    let mut img = Image::sized(0x2_0000);
    img.put_u64(POOL_BIG_PAGE_TABLE, TABLE);
    img.put_u64(POOL_BIG_PAGE_TABLE_SIZE, slots.len() as u64);
    // The counter is a 32-bit value the ISF leaves untyped. The dword after
    // it is deliberately non-zero so a reader that took it at pointer width
    // would fold `0xDEADBEEF` into the count and fail every comparison below.
    img.put_u32(EXP_POOL_BIG_ENTRIES_IN_USE, in_use_counter as u32);
    img.put_u32(EXP_POOL_BIG_ENTRIES_IN_USE + 4, 0xDEAD_BEEF);
    for (index, (va, tag, bytes, class)) in slots.iter().enumerate() {
        let at = TABLE + index as u64 * ENTRY_SIZE;
        img.put_u64(at, *va);
        img.write(at + 8, *tag);
        img.put_u32(at + 12, *class);
        img.put_u64(at + 16, *bytes);
    }
    img
}

fn survey(slots: &[(u64, &[u8; 4], u64, u32)], in_use: u64, d: Declares) -> BigPoolSurvey {
    let text = isf(d);
    let profile = profile(
        image(slots, in_use).layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols = BigPoolSymbols::from_profile(&profile).expect("this build declares the table");
    survey_big_pool(&profile, &symbols, &BigPoolConfig::default())
}

const ALL: Declares = Declares {
    pool_type: true,
    pool_flags: false,
    in_use_counter: true,
};

/// **Three kinds of slot, told apart by type**: in use, freed (the low bit of
/// `Va` set), and never used (all zero). Only the first two are allocations.
#[test]
fn in_use_freed_and_empty_slots_are_distinguished() {
    let out = survey(
        &[
            (0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0),
            (0xFFFF_8000_2000_0001, b"File", 0x1000, 1),
            (0, b"\0\0\0\0", 0, 0),
        ],
        1,
        ALL,
    );
    assert_eq!(out.entries_declared, 3);
    assert_eq!(out.entries_read, 3);
    assert_eq!(out.entries_in_use, 1);
    assert_eq!(out.entries_free, 1);
    assert_eq!(out.entries_empty, 1);
    assert_eq!(out.entries.len(), 2, "empty slots are not allocations");
    let live = &out.entries[0];
    assert_eq!(live.va, 0xFFFF_8000_1000_0000);
    assert!(!live.free);
    assert_eq!(live.tag, "Proc");
    assert_eq!(live.number_of_bytes, Some(0x2000));
    assert_eq!(
        live.pool_type.as_ref().map(|t| t.name.as_deref()),
        Some(Some("NonPagedPool"))
    );
    let freed = &out.entries[1];
    assert!(freed.free);
    assert_eq!(
        freed.va, 0xFFFF_8000_2000_0000,
        "the marker bit is stripped from the address"
    );
    assert_eq!(freed.tag, "File");
}

/// **The kernel's counter is compared with the walk.** `ExpPoolBigEntriesInUse`
/// says how many slots are live; when it disagrees with what was counted, both
/// numbers are on the record.
#[test]
fn the_in_use_counter_is_compared_with_the_walk() {
    let agreeing = survey(
        &[
            (0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0),
            (0xFFFF_8000_3000_0000, b"Thre", 0x3000, 0),
        ],
        2,
        ALL,
    );
    assert_eq!(agreeing.in_use_claimed, Some(2));
    assert_eq!(agreeing.counter_agrees(), Some(true));

    let disagreeing = survey(&[(0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0)], 5, ALL);
    assert_eq!(disagreeing.in_use_claimed, Some(5));
    assert_eq!(disagreeing.counter_agrees(), Some(false));
    let json = disagreeing.to_json();
    assert_eq!(json["in_use_counter_agrees"], serde_json::json!(false));
}

/// **The counter is read at 32 bits, and the record says so.** The ISF gives
/// `ExpPoolBigEntriesInUse` no type; the kernel keeps it as a 32-bit count,
/// and a reader taking it at pointer width would report whatever follows it
/// as part of the count.
#[test]
fn the_in_use_counter_is_read_at_thirty_two_bits_and_the_width_is_stated() {
    let out = survey(&[(0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0)], 1, ALL);
    assert_eq!(
        out.in_use_claimed,
        Some(1),
        "the adjacent dword is not the count"
    );
    assert_eq!(out.counter_agrees(), Some(true));
    let json = out.to_json();
    let basis = json["counter_basis"].as_str().expect("the width is stated");
    assert!(basis.contains("32-bit"), "{basis}");
    assert!(basis.contains("no declared type"), "{basis}");
}

/// **A build without the counter makes no claim about agreement.**
#[test]
fn without_the_counter_no_agreement_is_claimed() {
    let out = survey(
        &[(0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0)],
        1,
        Declares {
            in_use_counter: false,
            ..ALL
        },
    );
    assert_eq!(out.in_use_claimed, None);
    assert_eq!(out.counter_agrees(), None);
}

/// **Per-tag totals**, which is how an examiner reads a pool table: one tag
/// with a thousand allocations is a driver leaking, not a thousand facts.
#[test]
fn allocations_are_totalled_per_tag() {
    let out = survey(
        &[
            (0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0),
            (0xFFFF_8000_2000_0000, b"Proc", 0x1000, 0),
            (0xFFFF_8000_3000_0001, b"Proc", 0x4000, 0),
            (0xFFFF_8000_4000_0000, b"File", 0x1000, 1),
        ],
        3,
        ALL,
    );
    let proc_ = out.tags.get("Proc").expect("Proc is totalled");
    assert_eq!(proc_.in_use, 2);
    assert_eq!(proc_.free, 1);
    assert_eq!(proc_.bytes_in_use, 0x3000);
    let file = out.tags.get("File").expect("File is totalled");
    assert_eq!(file.in_use, 1);
    assert_eq!(file.bytes_in_use, 0x1000);
}

/// **A build that declares `PoolFlags` rather than `PoolType`** publishes the
/// raw flags and does not invent a pool type from them.
#[test]
fn pool_flags_are_published_raw_where_no_pool_type_is_declared() {
    let out = survey(
        &[(0xFFFF_8000_1000_0000, b"Proc", 0x2000, 0x40 << 8)],
        1,
        Declares {
            pool_type: false,
            pool_flags: true,
            in_use_counter: true,
        },
    );
    let entry = &out.entries[0];
    assert!(entry.pool_type.is_none());
    assert_eq!(entry.pool_flags, Some(0x40));
    let json = out.to_json();
    assert!(json["classification_basis"]
        .as_str()
        .unwrap_or_default()
        .contains("PoolFlags"));
}

/// **A non-printable tag is rendered as hex**, never as replacement characters
/// that could collide with a real tag.
#[test]
fn a_non_printable_tag_is_rendered_as_hex() {
    let out = survey(
        &[(0xFFFF_8000_1000_0000, &[0x01, 0x02, b'a', 0xff], 0x2000, 0)],
        1,
        ALL,
    );
    assert_eq!(out.entries[0].tag, "0x010261ff");
    assert_eq!(out.entries[0].tag_raw, 0xff61_0201);
}

/// **The publication cap is a cap on the rows, not on the totals.**
#[test]
fn the_publication_cap_leaves_the_totals_exact() {
    let slots: Vec<(u64, &[u8; 4], u64, u32)> = (0..10u64)
        .map(|i| (0xFFFF_8000_1000_0000 + i * 0x1000, b"Proc", 0x1000, 0))
        .collect();
    let text = isf(ALL);
    let profile = profile(
        image(&slots, 10).layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols = BigPoolSymbols::from_profile(&profile).expect("symbols");
    let out = survey_big_pool(
        &profile,
        &symbols,
        &BigPoolConfig {
            max_published_entries: 4,
        },
    );
    assert_eq!(out.entries_in_use, 10);
    assert_eq!(out.entries.len(), 4);
    assert!(out.entries_truncated);
    assert_eq!(out.tags["Proc"].in_use, 10);
    let json = out.to_json();
    assert_eq!(json["entries_published"], serde_json::json!(4));
    assert_eq!(json["entries_in_use"], serde_json::json!(10));
    assert!(
        out.is_complete(),
        "a publication cap is not an incomplete walk"
    );
}

/// A 32-bit build's tracker: `Va` and `NumberOfBytes` four bytes wide, the
/// slot sixteen bytes, as Windows 7 x86 declares it.
fn isf_x86() -> String {
    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrpamp.pdb", "machine_type": 332}}}}
  }},
  "base_types": {base},
  "user_types": {{
    "_POOL_TRACKER_BIG_PAGES": {{"size": 16, "kind": "struct", "fields": {{
      "Va": {{"offset": 0, "type": {{"kind": "pointer", "subtype": {{"kind": "base", "name": "void"}}}}}},
      "Key": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "PoolType": {{"offset": 8, "type": {{"kind": "enum", "name": "_POOL_TYPE"}}}},
      "NumberOfBytes": {{"offset": 12, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}}
  }},
  "enums": {{
    "_POOL_TYPE": {{"base": "long", "size": 4, "constants": {{
      "NonPagedPool": 0, "PagedPool": 1
    }}}}
  }},
  "symbols": {{
    "PoolBigPageTable": {{"address": {POOL_BIG_PAGE_TABLE}}},
    "PoolBigPageTableSize": {{"address": {POOL_BIG_PAGE_TABLE_SIZE}}},
    "ExpPoolBigEntriesInUse": {{"address": {EXP_POOL_BIG_ENTRIES_IN_USE}}}
  }}
}}"#,
        base = BASE_TYPES_X86,
    )
}

/// **On a 32-bit build every pointer-width field is read at four bytes.** The
/// slot is packed: eight bytes read at `Va` would fold the tag in, and eight
/// at `NumberOfBytes` would fold the next slot's `Va` in.
#[test]
fn a_thirty_two_bit_tracker_is_read_at_its_own_widths() {
    let mut img = Image::sized(0x2_0000);
    img.put_u32(POOL_BIG_PAGE_TABLE, TABLE as u32);
    img.put_u32(POOL_BIG_PAGE_TABLE_SIZE, 2);
    img.put_u32(EXP_POOL_BIG_ENTRIES_IN_USE, 1);
    img.put_u32(EXP_POOL_BIG_ENTRIES_IN_USE + 4, 0xDEAD_BEEF);
    // Slot 0: live, Proc, PagedPool, 0x2000 bytes.
    img.put_u32(TABLE, 0x8123_4000);
    img.write(TABLE + 4, b"Proc");
    img.put_u32(TABLE + 8, 1);
    img.put_u32(TABLE + 12, 0x2000);
    // Slot 1: freed (low bit set), Thre, 0x3000 bytes.
    img.put_u32(TABLE + 16, 0x8234_5001);
    img.write(TABLE + 20, b"Thre");
    img.put_u32(TABLE + 24, 0);
    img.put_u32(TABLE + 28, 0x3000);
    let profile = profile(
        img.layer(),
        table(&isf_x86()),
        Architecture::X86,
        6,
        1,
        Some(7601),
    );
    let symbols = BigPoolSymbols::from_profile(&profile).expect("this build declares the table");
    assert_eq!(symbols.pointer_bytes, 4);
    assert_eq!(symbols.entry_size, 16);
    let out = survey_big_pool(&profile, &symbols, &BigPoolConfig::default());
    assert_eq!(out.entries_declared, 2);
    assert_eq!(out.entries_read, 2);
    assert_eq!(out.entries_in_use, 1);
    assert_eq!(out.entries_free, 1);
    assert_eq!(out.in_use_claimed, Some(1));
    assert_eq!(out.counter_agrees(), Some(true));
    let live = &out.entries[0];
    assert_eq!(live.va, 0x8123_4000);
    assert_eq!(live.tag, "Proc");
    assert_eq!(live.number_of_bytes, Some(0x2000));
    assert_eq!(
        live.pool_type.as_ref().and_then(|p| p.name.as_deref()),
        Some("PagedPool")
    );
    let freed = &out.entries[1];
    assert!(freed.free);
    assert_eq!(freed.va, 0x8234_5000);
    assert_eq!(freed.number_of_bytes, Some(0x3000));
    assert_eq!(out.tags["Thre"].bytes_free, 0x3000);
    assert!(out.is_complete());
    let json = out.to_json();
    assert!(json["width_basis"]
        .as_str()
        .unwrap_or_default()
        .contains("4 byte"));
}
