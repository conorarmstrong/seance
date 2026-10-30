//! `MmUnloadedDrivers`, and the circular arithmetic that is the thing to get
//! right.
//!
//! # Ground truth for the layout
//!
//! Measured across **1,724** `ntkrnlmp.pdb` ISFs on this machine:
//! `_UNLOADED_DRIVERS` is declared in **46** of them, all x64
//! (`machine_type` 34404), and **all 46 agree on exactly one layout** — size
//! 40, `Name` at 0x00, `StartAddress` at 0x10, `EndAddress` at 0x18,
//! `CurrentTime` at 0x20. So the x64 fallback is validated against real
//! symbols rather than merely documented.
//!
//! No x86 ISF in that corpus declares it, so the x86 fallback is documented
//! and **unvalidated**, and every record read through it says so.

use super::tamper_unloaded::*;
use crate::image_fixture::Image;
use crate::kernel_hooks::test_support::{hook_isf, hook_profile};
use crate::kernel_hooks::{ModuleMap, ModuleRange};
use crate::tamper::UnloadedSymbols;

/// Where the fixture puts the table and its two symbols.
///
/// Plain image offsets rather than kernel addresses: `poolscan`'s `profile`
/// hands the same layer as both the kernel space and the physical one, so the
/// reader resolves a pointer value straight onto an image offset. A
/// `0xFFFF_F800_…` address would be written at its folded offset by the
/// fixture and then read at its unfolded one by the stage, which is the
/// failure the first draft of these tests hit.
const TABLE: u64 = 0x20_0000;
const NAMES: u64 = 0x21_0000;
const TABLE_PTR: u64 = 0x22_0000;
const COUNTER: u64 = 0x22_0008;

/// FILETIME for 2026-09-15T10:00:00Z, so a rendered time is checkable.
const UNLOAD_TIME: u64 = 134_339_400_000_000_000;

/// Build an image holding a table of `entries` as
/// `(name, start, end, filetime)`, with `write_count` in the counter.
fn image_with(entries: &[(&str, u64, u64, u64)], write_count: u64) -> Image {
    let mut img = Image::sized(0x30_0000);
    img.put_u64(TABLE_PTR, TABLE);
    img.put_u64(COUNTER, write_count);
    for (i, (name, start, end, time)) in entries.iter().enumerate() {
        let at = TABLE + (i * Fields::X64.size) as u64;
        // `_UNICODE_STRING`: Length, MaximumLength, then the buffer pointer at
        // offset 8.
        let name_at = NAMES + (i * 0x100) as u64;
        let bytes = name.encode_utf16().count() * 2;
        img.put_u16(at, bytes as u16);
        img.put_u16(at + 2, bytes as u16);
        img.put_u64(at + 8, name_at);
        img.put_utf16(name_at, name);
        img.put_u64(at + Fields::X64.start as u64, *start);
        img.put_u64(at + Fields::X64.end as u64, *end);
        img.put_u64(at + Fields::X64.time as u64, *time);
    }
    img
}

fn symbols() -> UnloadedSymbols {
    UnloadedSymbols {
        table_pointer: TABLE_PTR,
        counter: COUNTER,
    }
}

fn read(entries: &[(&str, u64, u64, u64)], write_count: u64) -> UnloadedTable {
    let profile = hook_profile(image_with(entries, write_count), &hook_isf());
    read_table(&profile, &symbols(), 512).expect("the table reads")
}

// --- the layout ------------------------------------------------------------

/// The x64 fallback is the layout all 46 declaring ISFs carry.
#[test]
fn the_x64_fallback_is_the_layout_the_real_isfs_agree_on() {
    let f = Fields::X64;
    assert_eq!(f.size, 40, "size 40, measured on 46 ISFs");
    assert_eq!(f.name, 0x00);
    assert_eq!(f.start, 0x10);
    assert_eq!(f.end, 0x18);
    assert_eq!(f.time, 0x20);
    assert_eq!(f.pointer, 8);
    assert!(
        f.layout.is_validated(),
        "validated against real symbols, not merely documented"
    );
    assert!(f.layout.basis().contains("all 46 agree"));
}

/// **The x86 fallback is unvalidated and says so**, because no ISF in the
/// corpus declares the type for it.
#[test]
fn the_x86_fallback_is_unvalidated_and_every_record_says_so() {
    let f = Fields::X86;
    assert_eq!(f.size, 0x18);
    assert_eq!(f.pointer, 4);
    assert!(!f.layout.is_validated());
    let basis = f.layout.basis();
    assert!(
        basis.contains("UNVALIDATED") && basis.contains("NO x86 ISF"),
        "got {basis}"
    );
    // And a record read through it is stamped, not merely commented.
    let d = UnloadedDriver {
        slot: 0,
        newest: true,
        name: Some("x.sys".into()),
        name_unavailable: None,
        start: 0x1000,
        end: 0x2000,
        unloaded_filetime: UNLOAD_TIME,
        layout: RecordLayout::DocumentedX86,
    };
    let j = d.to_json();
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unvalidated")
    );
}

// --- the circular arithmetic ----------------------------------------------

/// **The counter is a write count, not a length.** A machine that has unloaded
/// 63 drivers has fifty in the table, not 63.
#[test]
fn a_count_above_the_capacity_reads_fifty_entries_and_says_the_table_wrapped() {
    let entries: Vec<(String, u64, u64, u64)> = (0..TABLE_CAPACITY)
        .map(|i| {
            (
                format!("drv{i}.sys"),
                0x1_0000 + (i as u64 * 0x1000),
                0x1_0000 + (i as u64 * 0x1000) + 0x800,
                UNLOAD_TIME,
            )
        })
        .collect();
    let refs: Vec<(&str, u64, u64, u64)> = entries
        .iter()
        .map(|(n, s, e, t)| (n.as_str(), *s, *e, *t))
        .collect();
    let table = read(&refs, 63);

    assert_eq!(
        table.drivers.len(),
        TABLE_CAPACITY,
        "fifty slots, not sixty-three"
    );
    assert_eq!(table.write_count, 63, "the raw counter is still reported");
    assert!(table.wrapped);
    let said = table.describe();
    assert!(
        said.contains("WRAPPED") && said.contains("13 earlier unload(s) have been overwritten"),
        "got {said}"
    );
    assert!(
        said.contains("may simply have been pushed out"),
        "an absent driver is not an absent unload: {said}"
    );
    // The newest is (63 - 1) % 50 = 12.
    assert!(table.drivers[12].newest);
    assert_eq!(table.drivers.iter().filter(|d| d.newest).count(), 1);
}

/// A count within the capacity has overwritten nothing, and the record says
/// that rather than leaving a reader to assume either way.
#[test]
fn a_count_within_the_capacity_says_nothing_was_overwritten() {
    let table = read(
        &[
            ("first.sys", 0x1000, 0x2000, UNLOAD_TIME),
            ("second.sys", 0x3000, 0x4000, UNLOAD_TIME),
            ("third.sys", 0x5000, 0x6000, UNLOAD_TIME),
        ],
        3,
    );
    assert_eq!(table.drivers.len(), 3);
    assert!(!table.wrapped);
    assert!(
        table.describe().contains("nothing has been overwritten"),
        "got {}",
        table.describe()
    );
    // (3 - 1) % 50 = 2.
    assert!(table.drivers[2].newest);
    assert!(!table.drivers[0].newest);
}

/// A table written exactly to capacity has not wrapped, which is the boundary.
#[test]
fn a_count_equal_to_the_capacity_has_not_wrapped() {
    let entries: Vec<(String, u64, u64, u64)> = (0..TABLE_CAPACITY)
        .map(|i| {
            (
                format!("d{i}.sys"),
                0x1000 + i as u64 * 16,
                0x1008 + i as u64 * 16,
                UNLOAD_TIME,
            )
        })
        .collect();
    let refs: Vec<(&str, u64, u64, u64)> = entries
        .iter()
        .map(|(n, s, e, t)| (n.as_str(), *s, *e, *t))
        .collect();
    let table = read(&refs, TABLE_CAPACITY as u64);
    assert!(!table.wrapped, "50 writes fill 50 slots and overwrite none");
    assert_eq!(table.drivers.len(), TABLE_CAPACITY);
    assert!(table.drivers[TABLE_CAPACITY - 1].newest, "(50-1) % 50 = 49");
}

/// A table nothing has ever been written to yields nothing, and is not an
/// error.
#[test]
fn a_counter_of_zero_yields_no_entries_and_is_not_a_failure() {
    let table = read(&[], 0);
    assert!(table.drivers.is_empty());
    assert!(!table.wrapped);
    assert!(table.drivers.iter().all(|d| !d.newest));
}

// --- the contents ----------------------------------------------------------

/// The name, the range and the unload time come off a real-shaped record.
#[test]
fn an_entry_yields_its_name_its_range_and_its_unload_time() {
    let table = read(
        &[(
            "mydriver.sys",
            0xFFFF_F800_1000_0000,
            0xFFFF_F800_1000_8000,
            UNLOAD_TIME,
        )],
        1,
    );
    let d = &table.drivers[0];
    assert_eq!(d.name.as_deref(), Some("mydriver.sys"));
    assert_eq!(d.start, 0xFFFF_F800_1000_0000);
    assert_eq!(d.end, 0xFFFF_F800_1000_8000);
    assert!(d.has_range());
    let j = d.to_json();
    assert_eq!(j["driver_name"], "mydriver.sys");
    assert_eq!(j["start_address"], "0xfffff80010000000");
    assert!(
        j["unloaded_at"]
            .as_str()
            .unwrap_or("")
            .starts_with("2026-09-15T10:00:00"),
        "got {:?}",
        j["unloaded_at"]
    );
    assert_eq!(j["record_layout"], "documented_x64");
}

/// **A slot of zeros is an empty slot, not a range.** A containment test
/// against 0..0 would match every null pointer in the kernel.
#[test]
fn a_zero_filled_slot_is_empty_rather_than_a_range_containing_everything() {
    let table = read(
        &[("real.sys", 0x1_0000, 0x1_8000, UNLOAD_TIME), ("", 0, 0, 0)],
        2,
    );
    let empty = &table.drivers[1];
    assert!(!empty.has_range());
    assert!(!empty.contains(0), "0..0 must not contain the null address");
    assert!(!empty.contains(0x1234));
    let j = empty.to_json();
    assert_eq!(j["has_range"], serde_json::json!(false));
    assert!(
        j["range_note"]
            .as_str()
            .unwrap_or("")
            .contains("match every null pointer"),
        "got {:?}",
        j["range_note"]
    );
    // And it is not counted among the populated slots.
    assert_eq!(
        table.to_json()["drivers_with_a_range"],
        serde_json::json!(1)
    );
}

/// An end at or below the start is not a range either.
#[test]
fn a_slot_whose_end_is_not_above_its_start_is_not_a_range() {
    for (start, end) in [(0x2000u64, 0x1000u64), (0x2000, 0x2000)] {
        let table = read(&[("odd.sys", start, end, UNLOAD_TIME)], 1);
        assert!(
            !table.drivers[0].has_range(),
            "{start:#x}..{end:#x} is not a range"
        );
        assert!(!table.drivers[0].contains(start));
    }
}

/// A zero time is no time, not 1601.
#[test]
fn a_zero_unload_time_is_absent_and_says_why() {
    let table = read(&[("d.sys", 0x1000, 0x2000, 0)], 1);
    let d = &table.drivers[0];
    assert_eq!(d.unload_time(), UnloadTime::NeverWritten);
    let j = d.to_json();
    assert!(j["unloaded_at"].is_null());
    assert!(
        j["unloaded_at_absent_reason"]
            .as_str()
            .unwrap_or("")
            .contains("never been written"),
        "got {:?}",
        j["unloaded_at_absent_reason"]
    );
}

/// **The field is not a FILETIME on a modern kernel, and this build says so
/// rather than dating the unload to 1601.**
///
/// Measured on the Windows 11 26200 capture in this corpus: all nine slots
/// hold values between `0x00e393cb` and `0x03728e86`, monotonically increasing
/// with the slot order — 1.491 s to 5.784 s in 100-nanosecond units, which is
/// what a since-boot interval looks like and is nothing like a FILETIME. Read
/// as one, `0x00e393cb` is 1601-01-01T00:00:01Z, which is what Volatility 3's
/// `unloadedmodules` prints for it.
#[test]
fn a_time_below_the_filetime_floor_is_an_interval_since_boot_and_never_a_1601_date() {
    // The exact value slot 0 of the corpus capture holds.
    const MEASURED: u64 = 0x00e3_93cb;
    let table = read(&[("hwpolicy.sys", 0x1000, 0x2000, MEASURED)], 1);
    let d = &table.drivers[0];
    assert_eq!(d.unload_time(), UnloadTime::SinceBoot { units: MEASURED });

    let j = d.to_json();
    assert!(
        j["unloaded_at"].is_null(),
        "no absolute time is claimed: {:?}",
        j["unloaded_at"]
    );
    // 14,914,507 * 100ns = 1.4914507 s.
    let seconds = j["unloaded_seconds_after_boot"]
        .as_f64()
        .expect("an interval");
    assert!(
        (seconds - 1.491_450_7).abs() < 1e-6,
        "got {seconds} s after boot"
    );
    let basis = j["unloaded_time_basis"].as_str().unwrap_or_default();
    assert!(
        basis.to_ascii_lowercase().contains("since boot") && basis.contains("1601"),
        "the basis must say what the number is and what reading it as a FILETIME would give: \
         {basis}"
    );
    // No time-bearing field may carry a 1601 date. The basis prose names that
    // date deliberately — it is what the number would read as if converted —
    // so the assertion is about the fields a consumer renders, not about the
    // sentence that explains them.
    for field in ["unloaded_at", "unloaded_at_absent_reason"] {
        assert!(
            !j[field].as_str().unwrap_or_default().contains("1601-"),
            "{field} must not carry a 1601 date: {:?}",
            j[field]
        );
    }
}

/// A value that IS a plausible FILETIME is rendered as one. The classifier
/// must not swallow the case it was written for.
#[test]
fn a_plausible_filetime_is_still_rendered_as_an_absolute_time() {
    let table = read(&[("d.sys", 0x1000, 0x2000, UNLOAD_TIME)], 1);
    let d = &table.drivers[0];
    assert!(matches!(d.unload_time(), UnloadTime::Absolute(_)));
    let j = d.to_json();
    assert!(
        j["unloaded_at"]
            .as_str()
            .unwrap_or_default()
            .starts_with("2026-09-15T10:00:00"),
        "got {:?}",
        j["unloaded_at"]
    );
    assert!(j["unloaded_seconds_after_boot"].is_null());
}

/// A value that is neither a FILETIME nor a credible uptime is reported raw,
/// with no claim made about it.
#[test]
fn a_value_that_is_neither_a_time_nor_an_uptime_is_reported_and_not_interpreted() {
    // Above the uptime ceiling and below the FILETIME floor.
    let absurd = MAX_SINCE_BOOT + 1;
    let table = read(&[("d.sys", 0x1000, 0x2000, absurd)], 1);
    let d = &table.drivers[0];
    assert_eq!(d.unload_time(), UnloadTime::Unrenderable);
    let j = d.to_json();
    assert!(j["unloaded_at"].is_null());
    assert!(j["unloaded_seconds_after_boot"].is_null());
    let why = j["unloaded_at_absent_reason"].as_str().unwrap_or_default();
    assert!(
        why.contains(&format!("{absurd:#018x}")),
        "the raw value is on the record: {why}"
    );
}

/// A null table pointer is the kernel saying it never allocated the table —
/// an answer, not a failure.
#[test]
fn a_null_table_pointer_is_an_absence_in_the_evidence_and_not_a_failure() {
    let mut img = Image::sized(0x30_0000);
    img.put_u64(TABLE_PTR, 0);
    img.put_u64(COUNTER, 7);
    let profile = hook_profile(img, &hook_isf());
    let table = read_table(&profile, &symbols(), 512).expect("a null pointer is not an error");
    assert!(table.drivers.is_empty());
    assert!(
        table
            .capped
            .as_deref()
            .unwrap_or("")
            .contains("absence in the evidence and not a failure to read it"),
        "got {:?}",
        table.capped
    );
}

/// The cap is stated rather than silent: a table read short must not read as a
/// shorter table.
#[test]
fn a_record_cap_is_stated_and_the_table_is_not_reported_as_shorter() {
    let entries: Vec<(String, u64, u64, u64)> = (0..10)
        .map(|i| {
            (
                format!("d{i}.sys"),
                0x1000 + i as u64 * 16,
                0x1008 + i as u64 * 16,
                UNLOAD_TIME,
            )
        })
        .collect();
    let refs: Vec<(&str, u64, u64, u64)> = entries
        .iter()
        .map(|(n, s, e, t)| (n.as_str(), *s, *e, *t))
        .collect();
    let profile = hook_profile(image_with(&refs, 10), &hook_isf());
    let table = read_table(&profile, &symbols(), 4).expect("reads");
    assert_eq!(table.drivers.len(), 4);
    let why = table.capped.as_deref().unwrap_or("");
    assert!(
        why.contains("4 of 10 populated slots"),
        "the cap says what it stopped at: {why}"
    );
    let j = table.to_json();
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("cap_reached")
    );
    // The counter is still the truth about how many unloads there were.
    assert_eq!(j["write_count"], serde_json::json!(10));
}

// --- the cross-reference, which is the forensic point ----------------------

/// **An address inside an unloaded driver's range is a lead, never a verdict**,
/// and both sides are reported.
#[test]
fn an_address_inside_an_unloaded_range_is_reported_with_both_sides_and_no_verdict() {
    let mut table = read(
        &[(
            "gone.sys",
            0xFFFF_F800_1000_0000,
            0xFFFF_F800_1001_0000,
            UNLOAD_TIME,
        )],
        1,
    );
    // The loaded-module map says something about the same address, and both
    // answers go on the record side by side.
    let modules = ModuleMap::from_ranges(vec![ModuleRange {
        base: 0xFFFF_F800_2000_0000,
        end: 0xFFFF_F800_2001_0000,
        name: Some("live.sys".to_string()),
        entry: 0,
    }]);
    cross_reference(
        &mut table,
        &[("a notification callback".to_string(), 0xFFFF_F800_1000_0100)],
        &modules,
    );
    assert_eq!(table.hits.len(), 1);
    let j = table.hits[0].to_json();
    assert_eq!(j["unloaded_driver"], "gone.sys");
    assert_eq!(j["what"], "a notification callback");
    assert_eq!(j["is_a_verdict"], serde_json::json!(false));
    let basis = j["basis"].as_str().unwrap_or("");
    assert!(
        basis.contains("FREED") && basis.contains("lead to follow and not a finding"),
        "got {basis}"
    );
    assert!(
        j["also_owned_by"].is_object(),
        "what the LOADED modules say about the same address is beside it"
    );
}

/// An address outside every unloaded range produces nothing, so a hit means
/// something.
#[test]
fn an_address_outside_every_unloaded_range_produces_no_hit() {
    let mut table = read(&[("gone.sys", 0x1_0000, 0x1_8000, UNLOAD_TIME)], 1);
    let modules = ModuleMap::from_ranges(vec![]);
    cross_reference(
        &mut table,
        &[
            ("a timer DPC".to_string(), 0x9_0000),
            // The boundary: `end` is exclusive.
            ("another".to_string(), 0x1_8000),
        ],
        &modules,
    );
    assert!(table.hits.is_empty(), "got {:?}", table.hits);
}

/// **A null candidate address is not a pointer into anything**, and must not
/// match an empty slot.
#[test]
fn a_null_candidate_address_matches_nothing() {
    let mut table = read(
        &[("", 0, 0, 0), ("real.sys", 0x1000, 0x2000, UNLOAD_TIME)],
        2,
    );
    let modules = ModuleMap::from_ranges(vec![]);
    cross_reference(&mut table, &[("a thread start".to_string(), 0)], &modules);
    assert!(
        table.hits.is_empty(),
        "a null start address is an absent one: {:?}",
        table.hits
    );
}

// --- a declaration that cannot be read ------------------------------------

/// **A declared `_UNLOADED_DRIVERS` that is not the record is refused, and the
/// refusal is stated.**
///
/// This is not hypothetical and it is not a corrupt file: Volatility's own
/// bundled layout declares `_UNLOADED_DRIVERS` as the **array container** — a
/// struct holding an `UnloadedDrivers` array — rather than as one record. A
/// reader that took a declaration by name alone would find no `Name` member
/// and, if it went on regardless, would read a stride from the container's
/// size.
///
/// The related failure of a size that does not contain its own members cannot
/// reach this code at all: `seance_symbols`' structural admission gate refuses
/// the whole document, with the violation named ("declares a size of 0 but has
/// 4 member(s) that occupy bytes"). Proved by attempting it — the earlier
/// draft of this test built such an ISF and `compile_source` rejected it. The
/// guard in `Fields::resolve` stays as the belt to that brace.
#[test]
fn a_declared_layout_that_is_not_a_record_is_refused_and_the_fallback_says_so() {
    let isf = hook_isf().replace(
        "\"_POOL_HEADER\": {",
        "\"_UNLOADED_DRIVERS\": {\"size\": 2000, \"kind\": \"struct\", \"fields\": {
      \"UnloadedDrivers\": {\"offset\": 0, \"type\": {\"kind\": \"array\", \"count\": 50,
                           \"subtype\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}}
    }},
    \"_POOL_HEADER\": {",
    );
    let profile = hook_profile(
        image_with(&[("a.sys", 0x1000, 0x2000, UNLOAD_TIME)], 1),
        &isf,
    );
    let table = read_table(&profile, &symbols(), 512).expect("the table still reads");

    assert_eq!(
        table.layout,
        RecordLayout::DocumentedX64,
        "the fallback answered, not the refused declaration"
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("declaration was refused")),
        "the refusal is stated rather than silently worked around: {:?}",
        table.notes
    );
    // And the stride is the fallback's, so one slot is one driver rather than
    // fifty copies of one.
    assert_eq!(table.drivers.len(), 1);
    assert_eq!(table.drivers[0].name.as_deref(), Some("a.sys"));
}

/// A declaration that IS a record is used, and the record says the build's own
/// symbols answered. The guard must not refuse a good declaration.
#[test]
fn a_declared_layout_that_is_a_record_is_used_and_named_as_the_builds_own() {
    let isf = hook_isf().replace(
        "\"_POOL_HEADER\": {",
        "\"_UNLOADED_DRIVERS\": {\"size\": 40, \"kind\": \"struct\", \"fields\": {
      \"Name\": {\"offset\": 0, \"type\": {\"kind\": \"struct\", \"name\": \"_UNICODE_STRING\"}},
      \"StartAddress\": {\"offset\": 16, \"type\": {\"kind\": \"pointer\",
                        \"subtype\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}},
      \"EndAddress\": {\"offset\": 24, \"type\": {\"kind\": \"pointer\",
                      \"subtype\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}},
      \"CurrentTime\": {\"offset\": 32, \"type\": {\"kind\": \"base\",
                       \"name\": \"unsigned long long\"}}
    }},
    \"_POOL_HEADER\": {",
    );
    let profile = hook_profile(
        image_with(&[("b.sys", 0x1000, 0x2000, UNLOAD_TIME)], 1),
        &isf,
    );
    let table = read_table(&profile, &symbols(), 512).expect("the table reads");
    assert_eq!(table.layout, RecordLayout::Isf);
    assert!(
        table.notes.is_empty(),
        "nothing to state: {:?}",
        table.notes
    );
    assert!(table.layout.is_validated());
    assert_eq!(table.drivers[0].name.as_deref(), Some("b.sys"));
}

/// **A table pointer near the top of the address space is not a table**, and
/// computing its slots' addresses is a refusal, not a panic (`MEM-052`'s
/// audit: `table_at + slot * size + member` was unchecked arithmetic on a
/// pointer read from the image).
#[test]
fn a_slot_past_the_top_of_the_address_space_is_refused_not_a_panic() {
    let ok = slot_addresses(TABLE, 1, Fields::X64).expect("an ordinary slot");
    assert_eq!(
        ok.start,
        TABLE + Fields::X64.size as u64 + Fields::X64.start as u64
    );
    let err = slot_addresses(0xFFFF_FFFF_FFFF_FFE0, 0, Fields::X64)
        .expect_err("slot 0's members lie past 2^64");
    assert!(
        err.to_string()
            .contains("past the top of the address space"),
        "{err}"
    );
}
