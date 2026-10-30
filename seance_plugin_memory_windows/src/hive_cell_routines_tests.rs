//! Each hive's cell routines: named from the kernel's symbols where they land
//! there, flagged where they land outside every loaded module, and left
//! undetermined where the module map cannot support either claim.

use super::hive_cell_routines::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::kernel_hooks::{ModuleMap, ModuleRange};
use crate::poolscan::test_support::{profile, table};
use seance_memory::Architecture;

const HIVE_LIST_HEAD: u64 = 0x100;
const HVP_GET_CELL_PAGED: u64 = 0x5000;
const HVP_RELEASE_CELL_PAGED: u64 = 0x5200;
const KERNEL_END: u64 = 0xFFFF;
const CMHIVE_A: u64 = 0x1_0000;
const CMHIVE_B: u64 = 0x2_0000;
const NAME_A: u64 = 0x3_0000;
const NAME_B: u64 = 0x3_0100;
const HIVE_SIGNATURE: u32 = 0xBEE0_BEE0;

// `_HHIVE` / `_CMHIVE` offsets.
const HH_SIGNATURE: u64 = 0;
const HH_GET_CELL: u64 = 8;
const HH_RELEASE_CELL: u64 = 16;
const CM_FILE_FULL_PATH: u64 = 0x100;
const CM_HIVE_LIST: u64 = 0x120;

fn isf(with_release: bool) -> String {
    let release = if with_release {
        format!(
            r#","ReleaseCellRoutine": {{"offset": {HH_RELEASE_CELL}, "type": {{"kind": "pointer",
                                "subtype": {{"kind": "function"}}}}}}"#
        )
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
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_UNICODE_STRING": {{"size": 16, "kind": "struct", "fields": {{
      "Length": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "MaximumLength": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer", "subtype": {{"kind": "base", "name": "unsigned short"}}}}}}
    }}}},
    "_HHIVE": {{"size": 64, "kind": "struct", "fields": {{
      "Signature": {{"offset": {HH_SIGNATURE}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "GetCellRoutine": {{"offset": {HH_GET_CELL}, "type": {{"kind": "pointer",
                         "subtype": {{"kind": "function"}}}}}}{release}
    }}}},
    "_CMHIVE": {{"size": 512, "kind": "struct", "fields": {{
      "Hive": {{"offset": 0, "type": {{"kind": "struct", "name": "_HHIVE"}}}},
      "FileFullPath": {{"offset": {CM_FILE_FULL_PATH}, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}},
      "HiveList": {{"offset": {CM_HIVE_LIST}, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "CmpHiveListHead": {{"address": {HIVE_LIST_HEAD}}},
    "HvpGetCellPaged": {{"address": {HVP_GET_CELL_PAGED}}},
    "HvpReleaseCellPaged": {{"address": {HVP_RELEASE_CELL_PAGED}}}
  }}
}}"#,
        base = BASE_TYPES_X64,
    )
}

fn write_hive(img: &mut Image, cmhive: u64, name_at: u64, name: &str, get: u64, release: u64) {
    img.put_u32(cmhive + HH_SIGNATURE, HIVE_SIGNATURE);
    img.put_u64(cmhive + HH_GET_CELL, get);
    img.put_u64(cmhive + HH_RELEASE_CELL, release);
    let bytes = (name.encode_utf16().count() * 2) as u16;
    img.put_u16(cmhive + CM_FILE_FULL_PATH, bytes);
    img.put_u16(cmhive + CM_FILE_FULL_PATH + 2, bytes);
    img.put_u64(cmhive + CM_FILE_FULL_PATH + 8, name_at);
    img.put_utf16(name_at, name);
}

/// Two hives on the list. Hive B's routines are whatever the caller says.
fn image(b_get: u64, b_release: u64) -> Image {
    let mut img = Image::sized(0x4_0000);
    write_hive(
        &mut img,
        CMHIVE_A,
        NAME_A,
        "\\SystemRoot\\System32\\Config\\SOFTWARE",
        HVP_GET_CELL_PAGED,
        HVP_RELEASE_CELL_PAGED,
    );
    write_hive(
        &mut img,
        CMHIVE_B,
        NAME_B,
        "\\SystemRoot\\System32\\Config\\SAM",
        b_get,
        b_release,
    );
    // head -> A -> B -> head.
    let link_a = CMHIVE_A + CM_HIVE_LIST;
    let link_b = CMHIVE_B + CM_HIVE_LIST;
    img.put_u64(HIVE_LIST_HEAD, link_a);
    img.put_u64(HIVE_LIST_HEAD + 8, link_b);
    img.put_u64(link_a, link_b);
    img.put_u64(link_a + 8, HIVE_LIST_HEAD);
    img.put_u64(link_b, HIVE_LIST_HEAD);
    img.put_u64(link_b + 8, link_a);
    img
}

fn kernel_map() -> ModuleMap {
    ModuleMap::from_ranges(vec![
        ModuleRange {
            base: 0,
            end: KERNEL_END,
            name: Some("ntoskrnl.exe".to_string()),
            entry: 0,
        },
        ModuleRange {
            base: 0x8_0000,
            end: 0x8_FFFF,
            name: Some("evil.sys".to_string()),
            entry: 0,
        },
    ])
}

fn survey(
    b_get: u64,
    b_release: u64,
    with_release: bool,
    map: &ModuleMap,
) -> HiveCellRoutineSurvey {
    let text = isf(with_release);
    let profile = profile(
        image(b_get, b_release).layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols =
        HiveCellRoutineSymbols::from_profile(&profile).expect("this build declares the routine");
    survey_hive_cell_routines(&profile, &symbols, map)
}

/// **The ordinary case**: every hive's routines land in the kernel, at the
/// exact address of a named function, and the record says which.
#[test]
fn routines_in_the_kernel_are_named_from_its_symbols() {
    let out = survey(
        HVP_GET_CELL_PAGED,
        HVP_RELEASE_CELL_PAGED,
        true,
        &kernel_map(),
    );
    assert_eq!(out.hives.len(), 2);
    for hive in &out.hives {
        let get = hive.get_cell.as_ref().expect("read");
        assert_eq!(get.address, HVP_GET_CELL_PAGED);
        assert_eq!(get.symbol.as_deref(), Some("HvpGetCellPaged"));
        assert_eq!(get.symbol_offset, Some(0));
        assert_eq!(get.ownership.module(), Some("ntoskrnl.exe"));
        assert_eq!(get.outside_the_kernel, Some(false));
        let release = hive.release_cell.as_ref().expect("read");
        assert_eq!(release.symbol.as_deref(), Some("HvpReleaseCellPaged"));
    }
    assert_eq!(out.hives_with_a_routine_outside_the_kernel(), 0);
    assert!(out.is_complete());
    assert_eq!(
        out.hives[0].name.as_deref(),
        Some("\\SystemRoot\\System32\\Config\\SOFTWARE")
    );
}

/// **A routine pointing into another driver is the finding**, reported with
/// the driver's name and without a kernel symbol invented for it.
#[test]
fn a_routine_in_another_module_is_flagged_with_the_module_named() {
    let out = survey(0x8_0100, HVP_RELEASE_CELL_PAGED, true, &kernel_map());
    let sam = &out.hives[1];
    let get = sam.get_cell.as_ref().expect("read");
    assert_eq!(get.address, 0x8_0100);
    assert_eq!(
        get.symbol, None,
        "no kernel symbol names an address in another driver"
    );
    assert_eq!(get.ownership.module(), Some("evil.sys"));
    assert_eq!(get.outside_the_kernel, Some(true));
    assert_eq!(out.hives_with_a_routine_outside_the_kernel(), 1);
    assert!(sam.release_cell.as_ref().unwrap().outside_the_kernel == Some(false));
}

/// **A routine in no loaded module at all** is a stronger finding, and it is
/// only made when the module map is authoritative.
#[test]
fn a_routine_outside_every_module_is_a_claim_only_an_authoritative_map_supports() {
    let authoritative = survey(0x9_0000, HVP_RELEASE_CELL_PAGED, true, &kernel_map());
    let get = authoritative.hives[1].get_cell.as_ref().expect("read");
    assert!(get.ownership.is_outside_any_module());
    assert_eq!(get.outside_the_kernel, Some(true));

    let unavailable = ModuleMap::unavailable("the loaded-module list could not be walked");
    let undetermined = survey(0x9_0000, HVP_RELEASE_CELL_PAGED, true, &unavailable);
    let get = undetermined.hives[1].get_cell.as_ref().expect("read");
    assert_eq!(
        get.outside_the_kernel, None,
        "no claim without a map to rest it on"
    );
    assert_eq!(undetermined.hives_with_a_routine_outside_the_kernel(), 0);
    assert!(!undetermined.is_complete());
}

/// **A build without `ReleaseCellRoutine`** leaves that half unread and says
/// so, rather than reporting every hive's release routine as fine.
#[test]
fn an_undeclared_release_routine_is_not_read_and_the_record_says_so() {
    let out = survey(
        HVP_GET_CELL_PAGED,
        HVP_RELEASE_CELL_PAGED,
        false,
        &kernel_map(),
    );
    assert!(out.hives.iter().all(|h| h.release_cell.is_none()));
    let json = out.to_json();
    assert_eq!(
        json["release_cell_routine_declared"],
        serde_json::json!(false)
    );
    assert!(json["symbols"]["release_cell_routine"].is_null());
}

/// **A symbol inside a function, not at its start**, is reported as the
/// nearest symbol plus an offset — a hook that jumps into the middle of the
/// real routine — never as the function itself.
#[test]
fn a_pointer_into_the_middle_of_a_routine_carries_its_offset() {
    let out = survey(
        HVP_GET_CELL_PAGED + 0x10,
        HVP_RELEASE_CELL_PAGED,
        true,
        &kernel_map(),
    );
    let get = out.hives[1].get_cell.as_ref().expect("read");
    assert_eq!(get.symbol.as_deref(), Some("HvpGetCellPaged"));
    assert_eq!(get.symbol_offset, Some(0x10));
    assert!(!get.at_a_symbol());
    assert_eq!(get.outside_the_kernel, Some(false));
    assert_eq!(out.hives_with_a_routine_off_a_symbol(), 1);
}
