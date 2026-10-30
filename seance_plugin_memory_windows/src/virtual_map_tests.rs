//! The kernel's system virtual-address regions: one per declared slot, named
//! from the enumeration, with the profile's own kernel base placed in one.

use super::virtual_map::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::poolscan::test_support::{profile, table};
use seance_memory::Architecture;

const MI_STATE: u64 = 0x1_0000;
const VS_OFFSET: u64 = 0x100;
const REGIONS_OFFSET: u64 = 0x40;
const REGION_COUNT: u64 = 4;
const ASSIGNMENT_SIZE: u64 = 16;
/// The per-slice type map: eight bytes, one per 2^61-byte slice of a kernel
/// half that starts at zero (the fixture's `MmSystemRangeStart`).
const TYPES_OFFSET: u64 = 0x20;
const TYPE_SLICES: u64 = 8;
const MM_SYSTEM_RANGE_START: u64 = 0x200;
const MM_PFN_DATABASE: u64 = 0x208;
const MI_VA_BOOT_LOADED: u8 = 2;
const MI_VA_PFN_DATABASE: u8 = 3;

/// `Vs.SystemVaTypeCount`, one `u64` per enumeration value (four here).
const COUNTS_OFFSET: u64 = 0x100;
/// `_MI_SYSTEM_INFORMATION.SystemVa`, holding the boot-loaded region's
/// `_MI_DYNAMIC_BITMAP` at its start.
const SYSTEM_VA_OFFSET: u64 = 0x300;
/// Where the bitmap's buffer lies, and how many bits it declares.
const BITMAP_BUFFER: u64 = 0x1_8000;
const BITMAP_BITS: u64 = 128;
/// The boot-loaded region is 4 GiB; 2,048 units of 2 MiB.
const BITMAP_MAXIMUM: u64 = 2048;

fn isf(with_enum: bool) -> String {
    isf_with(with_enum, false)
}

fn isf_with(with_enum: bool, with_counts: bool) -> String {
    let counts_field = if with_counts {
        format!(
            r#","SystemVaTypeCount": {{"offset": {COUNTS_OFFSET}, "type": {{"kind": "array", "count": 4,
                       "subtype": {{"kind": "base", "name": "unsigned long long"}}}}}}"#
        )
    } else {
        String::new()
    };
    let system_va_field = if with_counts {
        format!(
            r#","SystemVa": {{"offset": {SYSTEM_VA_OFFSET}, "type": {{"kind": "struct", "name": "_MI_SYSTEM_VA_STATE"}}}}"#
        )
    } else {
        String::new()
    };
    let enums = if with_enum {
        r#""_MI_SYSTEM_VA_TYPE": {"base": "long", "size": 4, "constants": {
      "MiVaUnused": 0, "MiVaProcessSpace": 1, "MiVaBootLoaded": 2, "MiVaPfnDatabase": 3
    }}"#
    } else {
        ""
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
    "_MI_SYSTEM_VA_ASSIGNMENT": {{"size": {ASSIGNMENT_SIZE}, "kind": "struct", "fields": {{
      "BaseAddress": {{"offset": 0, "type": {{"kind": "pointer",
                      "subtype": {{"kind": "base", "name": "void"}}}}}},
      "NumberOfBytes": {{"offset": 8, "type": {{"kind": "base", "name": "unsigned long long"}}}}
    }}}},
    "_MI_VISIBLE_STATE": {{"size": 512, "kind": "struct", "fields": {{
      "SystemVaType": {{"offset": {TYPES_OFFSET}, "type": {{"kind": "array", "count": {TYPE_SLICES},
                       "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "SystemVaRegions": {{"offset": {REGIONS_OFFSET}, "type": {{"kind": "array", "count": {REGION_COUNT},
                          "subtype": {{"kind": "struct", "name": "_MI_SYSTEM_VA_ASSIGNMENT"}}}}}}
      {counts_field}
    }}}},
    "_RTL_BITMAP_EX": {{"size": 16, "kind": "struct", "fields": {{
      "SizeOfBitMap": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "base", "name": "unsigned long long"}}}}}}
    }}}},
    "_MI_DYNAMIC_BITMAP": {{"size": 72, "kind": "struct", "fields": {{
      "Bitmap": {{"offset": 0, "type": {{"kind": "struct", "name": "_RTL_BITMAP_EX"}}}},
      "MaximumSize": {{"offset": 16, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "BaseVa": {{"offset": 32, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "base", "name": "void"}}}}}}
    }}}},
    "_MI_SYSTEM_VA_STATE": {{"size": 128, "kind": "struct", "fields": {{
      "DynamicBitMapBootLoaded": {{"offset": 0, "type": {{"kind": "struct", "name": "_MI_DYNAMIC_BITMAP"}}}}
    }}}},
    "_MI_SYSTEM_INFORMATION": {{"size": 1024, "kind": "struct", "fields": {{
      "Vs": {{"offset": {VS_OFFSET}, "type": {{"kind": "struct", "name": "_MI_VISIBLE_STATE"}}}}
      {system_va_field}
    }}}}
  }},
  "enums": {{{enums}}},
  "symbols": {{
    "MiState": {{"address": {MI_STATE}}},
    "MmSystemRangeStart": {{"address": {MM_SYSTEM_RANGE_START}}},
    "MmPfnDatabase": {{"address": {MM_PFN_DATABASE}}}
  }}
}}"#,
        base = BASE_TYPES_X64,
    )
}

/// The kernel half starts at zero, so slice 0 holds the fixture's kernel
/// (base zero) and slice 7 holds everything at `0xE000_0000_0000_0000` and
/// above, which is where the PFN database is placed.
fn image(regions: &[(u64, u64)]) -> Image {
    let mut img = Image::sized(0x2_0000);
    let table = MI_STATE + VS_OFFSET + REGIONS_OFFSET;
    for (index, (base, bytes)) in regions.iter().enumerate() {
        let at = table + index as u64 * ASSIGNMENT_SIZE;
        img.put_u64(at, *base);
        img.put_u64(at + 8, *bytes);
    }
    let types = MI_STATE + VS_OFFSET + TYPES_OFFSET;
    img.put_u8(types, MI_VA_BOOT_LOADED);
    img.put_u8(types + 7, MI_VA_PFN_DATABASE);
    img.put_u64(MM_SYSTEM_RANGE_START, 0);
    img.put_u64(MM_PFN_DATABASE, PFN_DATABASE.0 + 0x1000);
    img
}

/// The boot-loaded region's count and its bitmap: `count` in
/// `SystemVaTypeCount[MiVaBootLoaded]`, and `bits_set` of the bitmap's 128
/// bits set.
fn survey_with_counts(count: u64, bits_set: u32) -> VirtualMapSurvey {
    let mut img = image(&layout(BOOT_LOADED, PFN_DATABASE));
    let counts = MI_STATE + VS_OFFSET + COUNTS_OFFSET;
    img.put_u64(counts + 8 * u64::from(MI_VA_BOOT_LOADED), count);
    let bitmap = MI_STATE + SYSTEM_VA_OFFSET;
    img.put_u64(bitmap, BITMAP_BITS);
    img.put_u64(bitmap + 8, BITMAP_BUFFER);
    img.put_u64(bitmap + 16, BITMAP_MAXIMUM);
    img.put_u64(bitmap + 32, BOOT_LOADED.0);
    // Scatter the set bits across both words of the buffer.
    let (mut low, mut high) = (0u64, 0u64);
    for bit in 0..bits_set {
        if bit % 2 == 0 {
            low |= 1 << (bit / 2);
        } else {
            high |= 1 << (bit / 2);
        }
    }
    img.put_u64(BITMAP_BUFFER, low);
    img.put_u64(BITMAP_BUFFER + 8, high);
    let text = isf_with(true, true);
    let profile = profile(
        img.layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols = VirtualMapSymbols::from_profile(&profile).expect("this build declares MiState");
    survey_virtual_map(&profile, &symbols)
}

/// The fixture profile's kernel base is zero (its symbols are RVAs off it),
/// so a region that holds the kernel is one that starts at zero.
fn survey(regions: &[(u64, u64)], with_enum: bool) -> VirtualMapSurvey {
    let text = isf(with_enum);
    let profile = profile(
        image(regions).layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols = VirtualMapSymbols::from_profile(&profile).expect("this build declares MiState");
    survey_virtual_map(&profile, &symbols)
}

/// A boot-loaded region that holds the fixture's kernel base of zero.
const BOOT_LOADED: (u64, u64) = (0, 0x1_0000_0000);
/// One that does not.
const BOOT_LOADED_ELSEWHERE: (u64, u64) = (0xFFFF_F800_0000_0000, 0x1_0000_0000);
const PFN_DATABASE: (u64, u64) = (0xFFFF_FA80_0000_0000, 0x10_0000_0000);

/// The slot each region occupies in the fixture's array. Neither equals the
/// region's type (`MiVaBootLoaded` = 2 sits in slot 3, `MiVaPfnDatabase` = 3
/// in slot 1), so an implementation that named a slot from its index would
/// name both wrongly and fail the tests below -- the property the real
/// image forced (on 26200 the kernel lies in slot 17, typed
/// `MiVaDriverImages`, not what index 17 would name).
const BOOT_LOADED_SLOT: usize = 3;
const PFN_DATABASE_SLOT: usize = 1;

/// The four-slot array with the boot-loaded region in slot 3 and the PFN
/// database in slot 1, slots 0 and 2 empty.
fn layout(boot_loaded: (u64, u64), pfn_database: (u64, u64)) -> [(u64, u64); 4] {
    let mut slots = [(0, 0); 4];
    slots[BOOT_LOADED_SLOT] = boot_loaded;
    slots[PFN_DATABASE_SLOT] = pfn_database;
    slots
}

/// **Every declared slot is a region, named from the kernel's own per-slice
/// type map** -- never from the slot's index -- with the base and the byte
/// count as the kernel recorded them.
#[test]
fn each_declared_slot_is_read_and_named_from_the_type_map() {
    let out = survey(&layout(BOOT_LOADED, PFN_DATABASE), true);
    assert_eq!(out.regions_declared, 4);
    assert_eq!(out.regions.len(), 4);
    assert_eq!(out.slice_bytes, Some(1 << 61));
    assert!(
        out.naming_unavailable.is_none(),
        "{:?}",
        out.naming_unavailable
    );
    // The map types slot 3 as MiVaBootLoaded (2) and slot 1 as
    // MiVaPfnDatabase (3). Named by index, slot 3 would be "MiVaPfnDatabase"
    // and slot 1 "MiVaProcessSpace" -- both wrong, and both caught here.
    let boot = &out.regions[BOOT_LOADED_SLOT];
    assert_eq!(boot.index, BOOT_LOADED_SLOT as u64);
    assert_eq!(boot.type_value, Some(u64::from(MI_VA_BOOT_LOADED)));
    assert_ne!(boot.type_value, Some(boot.index));
    assert_eq!(boot.type_name.as_deref(), Some("MiVaBootLoaded"));
    assert_eq!(boot.type_uniform, Some(true));
    assert_eq!(boot.base, BOOT_LOADED.0);
    assert_eq!(boot.bytes, BOOT_LOADED.1);
    let pfn = &out.regions[PFN_DATABASE_SLOT];
    assert_eq!(pfn.index, PFN_DATABASE_SLOT as u64);
    assert_eq!(pfn.type_value, Some(u64::from(MI_VA_PFN_DATABASE)));
    assert_ne!(pfn.type_value, Some(pfn.index));
    assert_eq!(pfn.type_name.as_deref(), Some("MiVaPfnDatabase"));
    assert_eq!(pfn.base, PFN_DATABASE.0);
    assert_eq!(pfn.bytes, PFN_DATABASE.1);
    assert!(out.regions[0].is_empty());
    assert_eq!(out.regions[0].type_value, None, "an empty slot has no type");
    assert!(out.regions[2].is_empty());
    assert_eq!(out.regions_in_use(), 2);
    assert!(
        out.checks.iter().all(|c| c.passed == Some(true)),
        "{:?}",
        out.checks
    );
    assert!(out.is_complete());
}

/// **The profile's kernel base is placed in a region**, which is the one
/// cross-check this record can make against something established elsewhere:
/// a map whose boot-loaded region does not hold the kernel is a map read
/// through the wrong offsets.
#[test]
fn the_kernel_base_is_placed_in_the_region_that_holds_it() {
    let inside = survey(&layout(BOOT_LOADED, PFN_DATABASE), true);
    let placed = inside.kernel_base_region.as_ref().expect("placed");
    assert_eq!(placed.index, BOOT_LOADED_SLOT as u64);
    assert_eq!(placed.type_name.as_deref(), Some("MiVaBootLoaded"));

    let outside = survey(&layout(BOOT_LOADED_ELSEWHERE, PFN_DATABASE), true);
    assert!(outside.kernel_base_region.is_none());
    let json = outside.to_json();
    assert_eq!(json["kernel_base_in_a_region"], serde_json::json!(false));
    let check = outside
        .checks
        .iter()
        .find(|c| c.name == "kernel_in_an_image_region")
        .expect("the check is made");
    assert_eq!(check.passed, Some(false));
    assert!(
        !outside.is_complete(),
        "a kernel outside every region is a map that does not check out"
    );
}

/// **The PFN database pointer is placed too**, and a map whose typed region
/// does not hold it fails that check rather than passing on the kernel alone.
#[test]
fn the_pfn_database_pointer_is_placed_in_the_region_typed_for_it() {
    let out = survey(&layout(BOOT_LOADED, PFN_DATABASE), true);
    let check = out
        .checks
        .iter()
        .find(|c| c.name == "pfn_database_in_its_region")
        .expect("the check is made");
    assert_eq!(check.passed, Some(true), "{check:?}");
    assert!(
        check.detail.contains(&format!("slot {PFN_DATABASE_SLOT}")),
        "{check:?}"
    );

    // No region covers the pointer: the check fails and the map is incomplete.
    let without = survey(&layout(BOOT_LOADED, (0, 0)), true);
    let check = without
        .checks
        .iter()
        .find(|c| c.name == "pfn_database_in_its_region")
        .expect("the check is made");
    assert_eq!(check.passed, Some(false), "{check:?}");
    assert!(!without.is_complete());
}

/// **Without the enumeration, slots carry their type number and no name is
/// invented** -- and the checks that need a name are left unmade, not passed.
#[test]
fn without_the_enumeration_regions_carry_their_type_number_only() {
    let out = survey(&layout(BOOT_LOADED, PFN_DATABASE), false);
    assert!(out.regions.iter().all(|r| r.type_name.is_none()));
    let boot = &out.regions[BOOT_LOADED_SLOT];
    assert_eq!(boot.type_value, Some(u64::from(MI_VA_BOOT_LOADED)));
    assert_eq!(boot.index, BOOT_LOADED_SLOT as u64);
    assert!(
        out.checks.iter().all(|c| c.passed.is_none()),
        "{:?}",
        out.checks
    );
    let json = out.to_json();
    assert!(json["naming_basis"]
        .as_str()
        .unwrap_or_default()
        .contains("SystemVaType"));
}

/// **Overlapping regions are reported**: two assignments that share address
/// space are not a layout the kernel produces, and a reader that summed their
/// sizes would double-count.
#[test]
fn overlapping_regions_are_reported() {
    let out = survey(
        &[
            (0, 0),
            (0, 0x2_0000_0000),
            (0x1_0000_0000, 0x1_0000_0000),
            (0, 0),
        ],
        true,
    );
    assert_eq!(out.overlaps.len(), 1);
    assert_eq!(out.overlaps[0], (1, 2));
}

/// **The type counts are published in the bitmaps' own units, and only when
/// no count falls below its bitmap.** A synthetic fixture pins the mechanism;
/// the relation itself was measured on the build 26200 capture (see
/// `the_virtual_map_type_counts_agree_with_the_dynamic_bitmaps_on_the_win11_capture`),
/// where the slice-count hypothesis the stage was first planned around proved
/// false.
#[test]
fn type_counts_are_published_only_when_they_agree_with_the_bitmaps() {
    let out = survey_with_counts(5, 5);
    assert!(
        out.type_counts_withheld.is_none(),
        "{:?}",
        out.type_counts_withheld
    );
    assert_eq!(out.type_counts, Some(vec![0, 0, 5, 0]));
    assert_eq!(out.type_count_granule, Some(0x20_0000), "4 GiB / 2,048");
    assert_eq!(out.type_count_checks.len(), 1);
    let check = &out.type_count_checks[0];
    assert_eq!(check.type_name.as_deref(), Some("MiVaBootLoaded"));
    assert_eq!(check.bits_set, Some(5));
    assert_eq!(check.holds, Some(true));
    assert!(out.is_complete());
    let json = out.to_json();
    assert_eq!(
        json["type_counts"]["granule_bytes"],
        serde_json::json!(0x20_0000)
    );
    assert!(json["type_counts"]["basis"]
        .as_str()
        .unwrap_or_default()
        .contains("26200"));

    // A count above its bitmap is still published -- on 26200 the system-PTE
    // and non-cached counts exceed their bitmaps -- and the check says so.
    let above = survey_with_counts(7, 5);
    assert_eq!(above.type_counts, Some(vec![0, 0, 7, 0]));
    let json = above.to_json();
    assert_eq!(
        json["type_counts"]["checks"][0]["exact"],
        serde_json::json!(false)
    );
    assert!(above.is_complete());

    // Without the declarations, nothing is published and nothing is marked.
    let without = survey(&layout(BOOT_LOADED, PFN_DATABASE), true);
    assert!(without.type_counts.is_none());
    assert!(without.type_counts_withheld.is_some());
    assert!(without.is_complete());
}

/// **A count below the kernel's own bitmap is reported, not published**: the
/// counts were read through offsets that do not check out.
#[test]
fn a_count_that_disagrees_with_the_bitmap_is_reported_not_published() {
    let out = survey_with_counts(3, 5);
    assert!(out.type_counts.is_none());
    let why = out.type_counts_withheld.as_deref().expect("a reason");
    assert!(why.contains("MiVaBootLoaded"), "{why}");
    assert_eq!(out.type_count_checks[0].holds, Some(false));
    assert!(!out.is_complete());
    assert!(out
        .incomplete()
        .iter()
        .any(|i| i.to_json().to_string().contains("SystemVaTypeCount")));
}

fn pool_region(index: u64, name: &str, base: u64, bytes: u64) -> VirtualMapRegion {
    VirtualMapRegion {
        index,
        type_value: Some(index),
        type_name: Some(name.to_string()),
        type_uniform: Some(true),
        base,
        bytes,
    }
}

const NONPAGED: u64 = 0xffff_dc00_0000_0000;
const PAGED: u64 = 0xffff_ba00_0000_0000;
const SLICE: u64 = 1 << 39;

/// Where the type map and the pool headers agree, the labelled region is swept, as before.
#[test]
fn the_labelled_pool_region_is_swept_when_the_loader_entries_lie_in_it() {
    let regions = [
        pool_region(0, "MiVaNonPagedPool", NONPAGED, SLICE),
        pool_region(1, "MiVaPagedPool", PAGED, SLICE),
    ];
    let entries = [NONPAGED + 0x1000, NONPAGED + 0x2000, PAGED + 0x10];
    let (region, basis) = pool_sweep_region(&regions, &entries).unwrap();
    assert_eq!((region.base, basis), (NONPAGED, PoolRegionBasis::Label));
}

/// Windows Server 2022 build 20348.587: every loader entry (a non-paged allocation) lies in the region the type
/// map names `MiVaPagedPool`, and the capture's key schedules lie there too. The labelled region holds none.
#[test]
fn the_region_holding_the_loader_entries_is_swept_when_the_labelled_one_holds_none() {
    let regions = [
        pool_region(0, "MiVaNonPagedPool", NONPAGED, SLICE),
        pool_region(1, "MiVaPagedPool", PAGED, SLICE),
    ];
    let entries = [PAGED + 0x1000, PAGED + 0x2000, PAGED + 0x3000];
    let (region, basis) = pool_sweep_region(&regions, &entries).unwrap();
    assert_eq!(
        (region.base, basis),
        (PAGED, PoolRegionBasis::LoaderEntries)
    );
}

/// With no entry placed in any region the label is all there is, and with no label there is nothing to sweep.
#[test]
fn without_placed_loader_entries_the_label_decides() {
    let regions = [
        pool_region(0, "MiVaNonPagedPool", NONPAGED, SLICE),
        pool_region(1, "MiVaPagedPool", PAGED, SLICE),
    ];
    let (region, basis) = pool_sweep_region(&regions, &[1, 2, 3]).unwrap();
    assert_eq!((region.base, basis), (NONPAGED, PoolRegionBasis::Label));
    let unlabelled = [pool_region(1, "MiVaPagedPool", PAGED, SLICE)];
    assert!(pool_sweep_region(&unlabelled, &[1, 2, 3]).is_none());
}
