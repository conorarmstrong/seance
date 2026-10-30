//! The timer walk: the bucket count, `CONTAINING_RECORD`, and the two things
//! that would read plausibly if they were wrong.
//!
//! # The fixture declares its own build
//!
//! These tests build their own ISF rather than extending the shared hook
//! fixture, because the thing under test IS the layout: the bucket count comes
//! from nested array dimensions, `_KTIMER_TABLE_ENTRY.Entry` sits at a
//! different offset on different builds, and a fixture that hardcoded one
//! shape could not fail when the reader hardcoded the same one.
//!
//! Dimensions here are `[2][4]` — eight buckets — for the same reason the real
//! build's are `[2][256]`: a reader that takes the outer dimension walks two of
//! them, finds the timer in bucket 1, and looks right.

use std::sync::Arc;

use super::tamper_timers::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::kernel_hooks::test_support::hook_profile;
use crate::kernel_hooks::{ModuleMap, ModuleRange};
use crate::tamper::{DpcKeySymbols, TimerSymbols};

/// Offsets the fixture writes at, mirroring the real Windows 11 build:
/// `_KPRCB.TimerTable` at 0x100 (16640 on the real build), `TimerEntries` at
/// 0x40 inside the table, a 32-byte entry whose list head is at 8.
const PRCB_TIMER_TABLE: u64 = 0x100;
const TIMER_ENTRIES: u64 = 0x40;
const ENTRY_SIZE: u64 = 32;
const ENTRY_LIST: u64 = 8;
const ENTRY_TIME: u64 = 24;
pub(crate) const BUCKETS: u64 = 8;

/// `_KTIMER`: `TimerListEntry` at 32, so a walk that treats the link as the
/// structure base reads 32 bytes early — into `DueTime` and the dispatcher
/// header, which parse.
const TIMER_LIST_ENTRY: u64 = 32;
const TIMER_DPC: u64 = 48;
const TIMER_PERIOD: u64 = 60;
const DPC_ROUTINE: u64 = 24;
const DPC_CONTEXT: u64 = 32;

/// Where the fixture puts things. Plain image offsets: the fixture's kernel and
/// physical spaces are the same layer.
pub(crate) const PRCB_ARRAY: u64 = 0x1_0000;
pub(crate) const PROCESSOR_COUNT: u64 = 0x1_0100;
pub(crate) const PRCB0: u64 = 0x2_0000;
pub(crate) const PRCB1: u64 = 0x3_0000;
pub(crate) const TIMER_A: u64 = 0x4_0000;
pub(crate) const TIMER_B: u64 = 0x4_1000;
pub(crate) const DPC_A: u64 = 0x5_0000;
pub(crate) const DPC_B: u64 = 0x5_1000;
const LEGACY_HEAD: u64 = 0x6_0000;

/// A routine inside the fixture's one loaded module, and one outside every
/// module.
pub(crate) const IN_MODULE: u64 = 0x7_0800;
pub(crate) const OUTSIDE_ANY_MODULE: u64 = 0x9_0000;
pub(crate) const MODULE_BASE: u64 = 0x7_0000;
pub(crate) const MODULE_END: u64 = 0x7_1000;

/// `pub(crate)` so the stage-level test in `tamper_tests` can splice the
/// unloaded-driver symbols into the same build rather than declaring a second
/// copy of these four types. One definition, two users.
pub(crate) fn isf(dims: &str) -> String {
    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "3A4B5C6D7E8F90A1B2C3D4E5F6071829", "age": 1,
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
    "_KTIMER_TABLE_ENTRY": {{"size": {entry_size}, "kind": "struct", "fields": {{
      "Lock": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Entry": {{"offset": {entry_list}, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "Time": {{"offset": {entry_time}, "type": {{"kind": "base",
               "name": "unsigned long long"}}}}
    }}}},
    "_KTIMER_TABLE": {{"size": {table_size}, "kind": "struct", "fields": {{
      "TimerEntries": {{"offset": {entries}, "type": {dims}}}
    }}}},
    "_KTIMER": {{"size": 64, "kind": "struct", "fields": {{
      "DueTime": {{"offset": 24, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "TimerListEntry": {{"offset": {timer_list}, "type": {{"kind": "struct",
                         "name": "_LIST_ENTRY"}}}},
      "Dpc": {{"offset": {timer_dpc}, "type": {{"kind": "pointer",
              "subtype": {{"kind": "struct", "name": "_KDPC"}}}}}},
      "Period": {{"offset": {timer_period}, "type": {{"kind": "base",
                 "name": "unsigned long"}}}}
    }}}},
    "_KDPC": {{"size": 64, "kind": "struct", "fields": {{
      "DeferredRoutine": {{"offset": {dpc_routine}, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "function"}}}}}},
      "DeferredContext": {{"offset": {dpc_context}, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "base", "name": "void"}}}}}}
    }}}},
    "_KPRCB": {{"size": {prcb_size}, "kind": "struct", "fields": {{
      "TimerTable": {{"offset": {prcb_table}, "type": {{"kind": "struct",
                     "name": "_KTIMER_TABLE"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "KiProcessorBlock": {{"address": {prcb_array}}},
    "KeNumberProcessors": {{"address": {count_at}}}
  }}
}}"#,
        base = BASE_TYPES_X64,
        entry_size = ENTRY_SIZE,
        entry_list = ENTRY_LIST,
        entry_time = ENTRY_TIME,
        entries = TIMER_ENTRIES,
        table_size = TIMER_ENTRIES + ENTRY_SIZE * BUCKETS,
        timer_list = TIMER_LIST_ENTRY,
        timer_dpc = TIMER_DPC,
        timer_period = TIMER_PERIOD,
        dpc_routine = DPC_ROUTINE,
        dpc_context = DPC_CONTEXT,
        prcb_size = PRCB_TIMER_TABLE + TIMER_ENTRIES + ENTRY_SIZE * BUCKETS,
        prcb_table = PRCB_TIMER_TABLE,
        prcb_array = PRCB_ARRAY,
        count_at = PROCESSOR_COUNT,
        dims = dims,
    )
}

/// `[2][4]`: eight buckets declared as nested dimensions, as build 26200 does.
pub(crate) const NESTED: &str = r#"{"kind": "array", "count": 2,
        "subtype": {"kind": "array", "count": 4,
                    "subtype": {"kind": "struct", "name": "_KTIMER_TABLE_ENTRY"}}}"#;

/// `[8]`: the same eight buckets declared flat, as the older builds do.
const FLAT: &str = r#"{"kind": "array", "count": 8,
        "subtype": {"kind": "struct", "name": "_KTIMER_TABLE_ENTRY"}}"#;

/// The ISF with no `_KPRCB.TimerTable` and no global symbol either — the 64 of
/// 1,724 builds that can run nothing.
fn isf_without_either_shape() -> String {
    isf(NESTED).replace(
        "\"TimerTable\": {\"offset\": 256, \"type\": {\"kind\": \"struct\",\n                     \"name\": \"_KTIMER_TABLE\"}}",
        "\"Spare\": {\"offset\": 256, \"type\": {\"kind\": \"base\", \"name\": \"unsigned long\"}}",
    )
}

/// The ISF with the legacy global symbol instead of `_KPRCB.TimerTable`.
fn isf_legacy() -> String {
    isf_without_either_shape().replace(
        "\"KiProcessorBlock\":",
        &format!(
            "\"KiTimerTableListHead\": {{\"address\": {LEGACY_HEAD}}},\n    \"KiProcessorBlock\":"
        ),
    )
}

fn symbols(legacy: Option<u64>) -> TimerSymbols {
    TimerSymbols {
        prcb_array: PRCB_ARRAY,
        processor_count: PROCESSOR_COUNT,
        legacy_table_head: legacy,
        dpc_keys: None,
    }
}

fn modules() -> ModuleMap {
    ModuleMap::from_ranges(vec![ModuleRange {
        base: MODULE_BASE,
        end: MODULE_END,
        name: Some("loaded.sys".to_string()),
        entry: 0,
    }])
}

/// An empty bucket points at itself, which is what a live kernel's
/// uninitialised-looking bucket really holds.
pub(crate) fn empty_bucket(img: &mut Image, base: u64, bucket: u64) {
    let head = base + bucket * ENTRY_SIZE + ENTRY_LIST;
    img.put_u64(head, head);
    img.put_u64(head + 8, head);
}

/// Link one timer into a bucket, with a DPC whose routine is `routine`
/// (`None` for a timer that carries no DPC at all).
pub(crate) fn link_timer(
    img: &mut Image,
    base: u64,
    bucket: u64,
    timer: u64,
    dpc: Option<(u64, u64)>,
    period: u32,
) {
    let head = base + bucket * ENTRY_SIZE + ENTRY_LIST;
    let link = timer + TIMER_LIST_ENTRY;
    img.put_u64(head, link);
    img.put_u64(head + 8, link);
    img.put_u64(link, head);
    img.put_u64(link + 8, head);
    img.put_u32(timer + TIMER_PERIOD, period);
    match dpc {
        Some((dpc_at, routine)) => {
            img.put_u64(timer + TIMER_DPC, dpc_at);
            img.put_u64(dpc_at + DPC_ROUTINE, routine);
            img.put_u64(dpc_at + DPC_CONTEXT, 0xDEAD_BEEF);
        }
        None => img.put_u64(timer + TIMER_DPC, 0),
    }
}

/// One processor, eight empty buckets, and whatever the caller links in.
pub(crate) fn image(processors: u64) -> Image {
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, processors as u32);
    for (i, prcb) in [PRCB0, PRCB1].iter().enumerate().take(processors as usize) {
        img.put_u64(PRCB_ARRAY + i as u64 * 8, *prcb);
        let base = prcb + PRCB_TIMER_TABLE + TIMER_ENTRIES;
        for b in 0..BUCKETS {
            empty_bucket(&mut img, base, b);
        }
    }
    img
}

pub(crate) fn table_base(prcb: u64) -> u64 {
    prcb + PRCB_TIMER_TABLE + TIMER_ENTRIES
}

fn read(img: Image, isf_text: &str, legacy: Option<u64>) -> TimerTable {
    let profile = hook_profile(img, isf_text);
    read_timers(&profile, &symbols(legacy), &modules(), 65_536).expect("the tables read")
}

// --- the bucket count ------------------------------------------------------

/// **The bucket count is the product of the declared dimensions.**
///
/// The timer is in the LAST bucket. A reader that took the outer dimension of
/// `[2][4]` would walk buckets 0 and 1, find nothing, and report a machine with
/// no timers — which is exactly what would happen on build 26200, whose real
/// declaration is `[2][256]`.
#[test]
fn the_bucket_count_is_the_product_of_every_declared_dimension() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        BUCKETS - 1,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);

    match &table.layout.shape {
        TableShape::PerProcessor { buckets, dims, .. } => {
            assert_eq!(*buckets, 8, "2 x 4, not 2");
            assert_eq!(dims, &vec![2, 4], "both dimensions are on the record");
        }
        other => panic!("expected the per-processor shape, got {other:?}"),
    }
    assert_eq!(table.buckets_walked, 8);
    assert_eq!(table.timers.len(), 1, "the timer in the last bucket");
    assert_eq!(table.timers[0].bucket, BUCKETS - 1);
}

/// The same eight buckets declared flat read the same way, so the older builds
/// are not a special case in the reader.
#[test]
fn a_flat_declaration_of_the_same_size_reads_the_same_table() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        BUCKETS - 1,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(FLAT), None);
    match &table.layout.shape {
        TableShape::PerProcessor { buckets, dims, .. } => {
            assert_eq!(*buckets, 8);
            assert_eq!(dims, &vec![8]);
        }
        other => panic!("expected the per-processor shape, got {other:?}"),
    }
    assert_eq!(table.timers.len(), 1);
}

// --- CONTAINING_RECORD -----------------------------------------------------

/// **The timer address is the structure, not the link.**
///
/// `TimerListEntry` is at 32, so a walk that reported the link address would be
/// 32 bytes early — inside the dispatcher header and `DueTime`, which parse.
#[test]
fn the_timer_address_is_recovered_by_containing_record_and_not_the_link() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        250,
    );
    let table = read(img, &isf(NESTED), None);
    let t = &table.timers[0];
    assert_eq!(t.timer, TIMER_A, "the _KTIMER, not the link at +32");
    assert_eq!(t.dpc, Some(DPC_A));
    assert_eq!(t.routine, Some(IN_MODULE));
    assert_eq!(t.period_ms, Some(250));
    let j = t.to_json();
    assert_eq!(j["periodic"], serde_json::json!(true));
    assert_eq!(j["timer_address"], format!("{TIMER_A:#018x}"));
}

// --- the signal, and what is not one ---------------------------------------

/// **A null DPC is ordinary and is not a signal.** Most timers signal an event
/// and name no routine; a rule that flagged them would fire thousands of times
/// on a clean machine.
#[test]
fn a_timer_with_no_dpc_is_ordinary_and_the_record_says_so() {
    let mut img = image(1);
    link_timer(&mut img, table_base(PRCB0), 2, TIMER_A, None, 0);
    let table = read(img, &isf(NESTED), None);
    let t = &table.timers[0];
    assert_eq!(t.dpc, None);
    assert_eq!(t.routine, None);
    assert!(!t.is_signal());
    let j = t.to_json();
    assert!(
        j["no_dpc_note"]
            .as_str()
            .unwrap_or_default()
            .contains("ordinary"),
        "got {:?}",
        j["no_dpc_note"]
    );
    assert_eq!(table.with_dpc(), 0);
    assert_eq!(table.signals(), 0);
}

/// A routine inside a loaded module is attributed to it and is not a signal.
#[test]
fn a_routine_inside_a_loaded_module_is_attributed_and_is_not_a_signal() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);
    assert!(!table.timers[0].is_signal());
    let j = table.timers[0].to_json();
    assert_eq!(
        j["routine_ownership"]["kind"],
        serde_json::json!("in_module")
    );
    assert_eq!(
        j["routine_ownership"]["module"],
        serde_json::json!("loaded.sys")
    );
}

/// **A routine in no loaded module is the signal — and only when the map is
/// authoritative.**
#[test]
fn a_routine_outside_every_module_is_the_signal_only_on_an_authoritative_map() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        3,
        TIMER_B,
        Some((DPC_B, OUTSIDE_ANY_MODULE)),
        0,
    );
    let profile = hook_profile(img, &isf(NESTED));
    let table = read_timers(&profile, &symbols(None), &modules(), 65_536).expect("read");
    assert!(table.timers[0].is_signal());
    assert_eq!(table.signals(), 1);
    assert_eq!(
        table.timers[0].to_json()["is_signal"],
        serde_json::json!(true)
    );

    // The same bytes against a map that could not be built: the answer must be
    // "undetermined", never "outside every module". Reporting this as a finding
    // would manufacture a rootkit out of an incomplete acquisition.
    let empty = ModuleMap::from_ranges(Vec::new());
    assert!(!empty.is_authoritative());
    let table = read_timers(&profile, &symbols(None), &empty, 65_536).expect("read");
    assert!(!table.timers[0].is_signal());
    assert_eq!(table.signals(), 0);
    assert_eq!(
        table.timers[0].to_json()["routine_ownership"]["kind"],
        serde_json::json!("undetermined")
    );
}

// --- what is deliberately not reported -------------------------------------

/// **`DueTime` appears nowhere, and the record says why.**
///
/// A later reader must not 'fix' this by printing the raw value: the encoding
/// is not established by any source in this tree, and a number rendered as a
/// date would be fabrication.
#[test]
fn no_due_time_is_reported_and_the_omission_is_stated() {
    let mut img = image(1);
    // A DueTime that would render as a plausible-looking date if anyone
    // converted it.
    img.put_u64(TIMER_A + 24, 134_339_400_000_000_000);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);
    let row = table.timers[0].to_json().to_string();
    assert!(
        !row.contains("134339400000000000"),
        "the raw DueTime must not reach the record: {row}"
    );
    let j = table.timers[0].to_json();
    let note = j["due_time_note"].as_str().unwrap_or_default();
    assert!(note.contains("KiWaitNever"), "got {note}");
    assert!(note.contains("NOT reported"), "got {note}");
    // And the table-level record carries it too, so a consumer showing only
    // the summary still states it.
    assert!(table.to_json()["due_time_note"].is_string());
}

/// **The bucket's own `Time` member was assessed, not ignored.** It is read and
/// published as the raw number it is, with no epoch claimed — which is a
/// different thing from `DueTime`, and the note says which.
#[test]
fn the_buckets_own_time_is_published_raw_with_no_epoch_claimed() {
    let mut img = image(1);
    let base = table_base(PRCB0);
    img.put_u64(base + ENTRY_SIZE + ENTRY_TIME, 0x0000_1234_5678_9ABC);
    link_timer(&mut img, base, 1, TIMER_A, Some((DPC_A, IN_MODULE)), 0);
    let table = read(img, &isf(NESTED), None);
    let t = &table.timers[0];
    assert_eq!(t.bucket_time_raw, Some(0x0000_1234_5678_9ABC));
    let j = t.to_json();
    assert_eq!(
        j["bucket_time_raw"],
        serde_json::json!(0x0000_1234_5678_9ABCu64)
    );
    let note = j["bucket_time_note"].as_str().unwrap_or_default();
    assert!(note.contains("BUCKET"), "got {note}");
    assert!(note.contains("no epoch is claimed"), "got {note}");
    // Nothing on the row renders it as a time.
    assert!(!j.to_string().contains("1970-"), "{j}");
}

// --- the processor count ---------------------------------------------------

/// **The processor count is validated against the array, not trusted.**
///
/// `KeNumberProcessors` carries no declared type in any ISF measured, and on
/// the smeared captures in this corpus it reads 0 on machines that plainly had
/// processors.
#[test]
fn a_processor_count_that_disagrees_with_the_array_is_stated_and_the_array_wins() {
    let mut img = image(2);
    // The kernel claims 7; the array holds 2.
    img.put_u32(PROCESSOR_COUNT, 7);
    link_timer(
        &mut img,
        table_base(PRCB1),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);
    assert_eq!(table.processors_claimed, Some(7));
    assert_eq!(table.processors_walked, 2, "the array is what was walked");
    let note = table.processor_count_note.clone().unwrap_or_default();
    assert!(note.contains("reads 7"), "got {note}");
    assert!(note.contains("2 usable"), "got {note}");
    // And the second processor's table was walked, so the timer in it is here.
    assert_eq!(table.timers.len(), 1);
    assert_eq!(table.timers[0].processor, Some(1));
    assert_eq!(table.buckets_walked, 16, "eight buckets per processor");
}

/// A count of zero is not the end of it: the array is probed regardless.
#[test]
fn a_claimed_count_of_zero_does_not_stop_the_walk() {
    let mut img = image(1);
    img.put_u32(PROCESSOR_COUNT, 0);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);
    assert_eq!(table.processors_claimed, Some(0));
    assert_eq!(table.processors_walked, 1);
    assert_eq!(table.timers.len(), 1);
}

// --- the caps and the stops ------------------------------------------------

/// The timer cap is reported as a cap, never as the end of the table.
#[test]
fn the_timer_cap_is_stated_rather_than_read_as_the_end_of_the_table() {
    let mut img = image(1);
    let base = table_base(PRCB0);
    link_timer(&mut img, base, 0, TIMER_A, Some((DPC_A, IN_MODULE)), 0);
    link_timer(&mut img, base, 1, TIMER_B, Some((DPC_B, IN_MODULE)), 0);
    let profile = hook_profile(img, &isf(NESTED));
    let table = read_timers(&profile, &symbols(None), &modules(), 1).expect("read");
    assert_eq!(table.timers.len(), 1);
    let capped = table.capped.clone().expect("a cap fired");
    assert!(capped.contains("cap of 1"), "got {capped}");
    let j = table.to_json();
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("cap_reached")
    );
}

/// A bucket whose chain points into itself ends with a stop reason, and the
/// count of such buckets is on the record.
#[test]
fn a_cycle_in_a_bucket_is_counted_and_named() {
    let mut img = image(1);
    let base = table_base(PRCB0);
    let head = base + ENTRY_LIST;
    let link = TIMER_A + TIMER_LIST_ENTRY;
    // head -> timer -> itself: a chain that never returns to the head.
    img.put_u64(head, link);
    img.put_u64(link, link);
    img.put_u64(TIMER_A + TIMER_DPC, 0);
    let table = read(img, &isf(NESTED), None);
    assert!(
        table.notes.iter().any(|n| n.contains("cycle")),
        "got {:?}",
        table.notes
    );
}

// --- the shapes ------------------------------------------------------------

/// **A build with neither shape does not run, and says which symbols were
/// absent.** 64 of the 1,724 ISFs measured are in that state.
#[test]
fn a_build_with_neither_table_shape_is_refused_with_both_names() {
    let profile = hook_profile(image(1), &isf_without_either_shape());
    let err = read_timers(&profile, &symbols(None), &modules(), 65_536)
        .expect_err("no table can be located");
    assert_eq!(err.class(), "unsupported_build");
    let detail = err.detail();
    assert!(detail.contains("_KPRCB.TimerTable"), "got {detail}");
    assert!(detail.contains("KiTimerTableListHead"), "got {detail}");
    assert!(detail.contains("64 of the 1,724"), "got {detail}");
}

/// **The legacy global table's extent is derived from the evidence**, because
/// nothing declares it: the probe stops at the first entry that is neither a
/// self-referential head nor a head whose first link points back at it.
#[test]
fn the_legacy_global_extent_is_derived_and_the_derivation_is_stated() {
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    // Five buckets that look like bucket heads, then bytes that do not.
    for b in 0..5 {
        empty_bucket(&mut img, LEGACY_HEAD, b);
    }
    img.put_u64(LEGACY_HEAD + 5 * ENTRY_SIZE + ENTRY_LIST, 0x1234);
    link_timer(
        &mut img,
        LEGACY_HEAD,
        2,
        TIMER_A,
        Some((DPC_A, OUTSIDE_ANY_MODULE)),
        0,
    );

    let table = read(img, &isf_legacy(), Some(LEGACY_HEAD));
    assert!(matches!(
        table.layout.shape,
        TableShape::LegacyGlobal { .. }
    ));
    assert_eq!(
        table.buckets_walked, 5,
        "derived, not a documented constant"
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("DERIVED") && n.contains("cites neither")),
        "got {:?}",
        table.notes
    );
    // The table is not per-processor, so no row claims a processor.
    assert_eq!(table.timers.len(), 1);
    assert_eq!(table.timers[0].processor, None);
    assert!(table.timers[0].is_signal());
}

/// The ISF of an NT 5.1 build: the legacy global symbol, and **no
/// `_KTIMER_TABLE_ENTRY` type at all**. XP SP2 and SP3's `ntkrnlpa.pdb` /
/// `ntoskrnl.pdb` are in this state; their `KiTimerTableListHead` is an array
/// of bare `_LIST_ENTRY` bucket heads.
fn isf_legacy_bare_list_heads() -> String {
    let with_entry = isf_legacy();
    let start = with_entry
        .find("\"_KTIMER_TABLE_ENTRY\"")
        .expect("the fixture declares the entry type");
    let end = with_entry[start..]
        .find("\"_KTIMER_TABLE\":")
        .expect("followed by the table type")
        + start;
    let bare = format!("{}{}", &with_entry[..start], &with_entry[end..]);
    // The table type now names an entry type nothing declares; the per-processor
    // shape is absent in this ISF, so nothing reads it.
    assert!(!bare.contains("\"_KTIMER_TABLE_ENTRY\": {"));
    bare
}

/// **An XP-era table of bare `_LIST_ENTRY` heads is walked, not refused**
/// (found 2026-09-24 on the Malware Cookbook's XP SP2 captures, where the
/// group refused every image with "this build does not declare
/// `_KTIMER_TABLE_ENTRY`").
///
/// NT 5.1 declares no bucket-entry type: each bucket is the list head itself.
/// The stride is therefore the declared size of `_LIST_ENTRY` and the head is
/// at offset 0, both from the build's own symbols, and the evidence then checks
/// them — a wrong stride would fail the extent probe at bucket 1, because the
/// middle of one head is not a head.
#[test]
fn a_legacy_table_of_bare_list_heads_is_walked_with_the_list_entry_stride() {
    const HEAD_SIZE: u64 = 16; // the fixture's declared `_LIST_ENTRY` size
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    for b in 0..5 {
        let head = LEGACY_HEAD + b * HEAD_SIZE;
        img.put_u64(head, head);
        img.put_u64(head + 8, head);
    }
    img.put_u64(LEGACY_HEAD + 5 * HEAD_SIZE, 0x1234);
    // One timer in bucket 2, with a DPC whose routine lands in no module.
    let head = LEGACY_HEAD + 2 * HEAD_SIZE;
    let link = TIMER_A + TIMER_LIST_ENTRY;
    img.put_u64(head, link);
    img.put_u64(head + 8, link);
    img.put_u64(link, head);
    img.put_u64(link + 8, head);
    img.put_u64(TIMER_A + TIMER_DPC, DPC_A);
    img.put_u64(DPC_A + DPC_ROUTINE, OUTSIDE_ANY_MODULE);

    let profile = hook_profile(img, &isf_legacy_bare_list_heads());
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("an NT 5.1 table of bare list heads must be walked, not refused");
    assert!(matches!(
        table.layout.shape,
        TableShape::LegacyGlobal { .. }
    ));
    assert_eq!(
        table.layout.entry_size, HEAD_SIZE,
        "the stride is `_LIST_ENTRY`'s size"
    );
    assert_eq!(
        table.layout.entry_list_offset, 0,
        "the bucket IS the list head"
    );
    assert_eq!(
        table.layout.entry_time_offset, None,
        "there is no bucket time to read"
    );
    assert_eq!(table.buckets_walked, 5, "derived from the evidence");
    assert_eq!(table.timers.len(), 1);
    assert_eq!(table.timers[0].bucket, 2);
    assert_eq!(table.timers[0].timer, TIMER_A);
    assert!(table.timers[0].is_signal());
    let j = table.layout.to_json();
    assert!(
        j["entry_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("_LIST_ENTRY"),
        "the record says the bucket is a bare list head and why: {j}"
    );
}

/// **The legacy extent stops at the next symbol this build declares**, because
/// the bytes after the table can be list heads too (found 2026-09-24).
///
/// On XP SP2 and SP3 the 256 timer buckets are followed directly by
/// `KiDispatcherReadyListHead` — 32 more `_LIST_ENTRY` heads, self-referential
/// when empty — so the heads-only probe derived **288** buckets on all four
/// captures, and walked scheduler ready lists as though they held timers. The
/// symbol table itself says where the next object starts, and that is a bound
/// taken from the build rather than a constant.
#[test]
fn the_legacy_extent_is_bounded_by_the_next_declared_symbol() {
    const HEAD_SIZE: u64 = 16;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    // Six heads in a row: three timer buckets, then three heads that belong
    // to the NEXT symbol and are indistinguishable from buckets by their bytes.
    for b in 0..6 {
        let head = LEGACY_HEAD + b * HEAD_SIZE;
        img.put_u64(head, head);
        img.put_u64(head + 8, head);
    }
    let next_symbol = LEGACY_HEAD + 3 * HEAD_SIZE;
    let isf_text = isf_legacy_bare_list_heads().replace(
        "\"KiProcessorBlock\":",
        &format!("\"KiDispatcherReadyListHead\": {{\"address\": {next_symbol}}},\n    \"KiProcessorBlock\":"),
    );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    assert_eq!(
        table.buckets_walked, 3,
        "the heads after `KiDispatcherReadyListHead` are that symbol's, not the timer table's"
    );
    let note = table
        .notes
        .iter()
        .find(|n| n.contains("DERIVED"))
        .expect("the derivation is stated");
    assert!(
        note.contains("KiDispatcherReadyListHead") && note.contains("48 byte(s)"),
        "the record names the symbol that bounded the table and the distance: {note}"
    );
}

/// **A torn bucket head does not end the legacy table** (`MEM-058`, found
/// 2026-09-27 on the Cookbook's `prolaco.vmem`).
///
/// In a capture taken while the kernel was relinking timers, a bucket head's
/// first link can hold a `Blink` that names a different bucket. On
/// `prolaco.vmem` that happens at bucket 37 of 256 (its first link points
/// back at 0x80550a18), and the heads-only probe read it as the end of the
/// table: 37 buckets walked, 43 of the 50 real DPC timers not
/// reached, and a list from inside the 37 that ran into bucket 68's head
/// published that head as a timer "outside any module" -- a false signal. The
/// symbol table bounds the array, so a well-formed head beyond the torn one
/// shows the table goes on. Synthetic: it pins the mechanism, the real image
/// is graded in `tests/legacy_xp_corpus.rs`.
#[test]
fn a_torn_bucket_head_does_not_end_the_legacy_table() {
    const HEAD_SIZE: u64 = 16;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    for b in 0..6 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    // Bucket 1 holds TIMER_A, whose Flink runs on into bucket 3's head.
    let link_a = TIMER_A + TIMER_LIST_ENTRY;
    img.put_u64(head(1), link_a);
    img.put_u64(head(1) + 8, link_a);
    img.put_u64(link_a, head(3));
    img.put_u64(link_a + 8, head(1));
    img.put_u64(TIMER_A + TIMER_DPC, DPC_A);
    img.put_u64(DPC_A + DPC_ROUTINE, IN_MODULE);
    // Bucket 2 is torn: its first link's Blink names bucket 4.
    let link_b = TIMER_B + TIMER_LIST_ENTRY;
    img.put_u64(head(2), link_b);
    img.put_u64(head(2) + 8, link_b);
    img.put_u64(link_b, head(4));
    img.put_u64(link_b + 8, head(4));
    img.put_u64(TIMER_B + TIMER_DPC, DPC_B);
    img.put_u64(DPC_B + DPC_ROUTINE, IN_MODULE);
    let next_symbol = head(6);
    let isf_text = isf_legacy_bare_list_heads().replace(
        "\"KiProcessorBlock\":",
        &format!("\"KiDispatcherReadyListHead\": {{\"address\": {next_symbol}}},\n    \"KiProcessorBlock\":"),
    );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    assert_eq!(
        table.buckets_walked, 6,
        "a torn head inside the symbol-bounded array is a bucket, not the end: {:?}",
        table.notes
    );
    assert!(
        !table
            .timers
            .iter()
            .any(|t| t.timer == head(3) - TIMER_LIST_ENTRY),
        "bucket 3's head is not a timer: {:?}",
        table.timers.iter().map(|t| t.timer).collect::<Vec<_>>()
    );
    assert!(
        !table.timers.iter().any(|t| t.is_signal()),
        "no false signal"
    );
    assert!(
        table.timers.iter().any(|t| t.timer == TIMER_B),
        "the torn bucket's own list is still walked"
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("torn") && n.contains("bucket 2")),
        "the torn head is named: {:?}",
        table.notes
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("DERIVED") && n.contains("1 of them torn")),
        "the derivation does not claim every head is well-formed: {:?}",
        table.notes
    );
}

/// **A torn run at the end of the bounded table is named, not dropped**
/// (`MEM-058`, the adversarial review). Torn heads that no well-formed head
/// follows inside the bound are not counted as buckets -- nothing in the bytes
/// says the table reaches them -- but they may be real buckets whose timers
/// were not reached, so the record names them, and a list that runs into one
/// of their heads stops there rather than publishing the head as a timer.
/// Synthetic: it pins the mechanism.
#[test]
fn a_torn_run_at_the_end_of_the_bounded_table_is_named_and_stops_walks() {
    const HEAD_SIZE: u64 = 16;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    for b in 0..6 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    // Bucket 1 holds TIMER_A, whose Flink runs on into bucket 4's head.
    let link_a = TIMER_A + TIMER_LIST_ENTRY;
    img.put_u64(head(1), link_a);
    img.put_u64(head(1) + 8, link_a);
    img.put_u64(link_a, head(4));
    img.put_u64(link_a + 8, head(1));
    img.put_u64(TIMER_A + TIMER_DPC, DPC_A);
    img.put_u64(DPC_A + DPC_ROUTINE, IN_MODULE);
    // Buckets 4 and 5 are torn, and nothing well-formed follows them.
    for (b, link) in [
        (4u64, TIMER_B + TIMER_LIST_ENTRY),
        (5, TIMER_B + 0x800 + TIMER_LIST_ENTRY),
    ] {
        img.put_u64(head(b), link);
        img.put_u64(link + 8, head(0));
    }
    let next_symbol = head(6);
    let isf_text = isf_legacy_bare_list_heads().replace(
        "\"KiProcessorBlock\":",
        &format!("\"KiDispatcherReadyListHead\": {{\"address\": {next_symbol}}},\n    \"KiProcessorBlock\":"),
    );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    assert_eq!(table.buckets_walked, 4, "{:?}", table.notes);
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("bucket 4") && n.contains("bucket 5") && n.contains("not walked")),
        "the trailing torn heads are named: {:?}",
        table.notes
    );
    assert!(
        !table
            .timers
            .iter()
            .any(|t| t.timer == head(4) - TIMER_LIST_ENTRY),
        "bucket 4's head is not a timer: {:?}",
        table.timers.iter().map(|t| t.timer).collect::<Vec<_>>()
    );
}

/// **The kernel's own `KiTimerTableSize` is the extent when the build declares it** (`MEM-059`). A
/// capture taken while the system ran leaves torn heads at the end of the table (the M57 "Terry" Vista
/// image: 56 torn heads, and a probe that stopped at 353 of 512 buckets, missing 17 timers Volatility
/// 2 reports). The variable says 6 here, so six buckets are walked, the torn ones named, and the
/// timer in the last bucket is reached. SYNTHETIC: the same shape on a tiny table.
#[test]
fn the_kernels_own_table_size_is_the_extent_when_the_build_declares_it() {
    const HEAD_SIZE: u64 = 16;
    const SIZE_VAR: u64 = 0x9_0000;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    img.put_u32(SIZE_VAR, 8);
    for b in 0..8 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    // Bucket 7, the last, holds TIMER_A with a DPC in a module, and its head is torn too: the timer's
    // Blink does not point back at the head (the capture caught it mid-relink).
    let link_a = TIMER_A + TIMER_LIST_ENTRY;
    img.put_u64(head(7), link_a);
    img.put_u64(head(7) + 8, link_a);
    img.put_u64(link_a, head(7));
    img.put_u64(link_a + 8, head(0));
    img.put_u64(TIMER_A + TIMER_DPC, DPC_A);
    img.put_u64(DPC_A + DPC_ROUTINE, IN_MODULE);
    // Buckets 3 and 4 are torn: their first links' Blinks point elsewhere.
    for (b, link) in [
        (3u64, TIMER_B + TIMER_LIST_ENTRY),
        (4, TIMER_B + 0x800 + TIMER_LIST_ENTRY),
    ] {
        img.put_u64(head(b), link);
        img.put_u64(link + 8, head(0));
    }
    let next_symbol = head(8);
    let isf_text = isf_legacy_bare_list_heads().replace(
        "\"KiProcessorBlock\":",
        &format!(
            "\"KiDispatcherReadyListHead\": {{\"address\": {next_symbol}}},\n    \
             \"KiTimerTableSize\": {{\"address\": {SIZE_VAR}}},\n    \"KiProcessorBlock\":"
        ),
    );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    assert_eq!(table.buckets_walked, 8, "{:?}", table.notes);
    assert!(
        table.timers.iter().any(|t| t.timer == TIMER_A),
        "the timer in the last bucket is reached: {:?}",
        table.timers.iter().map(|t| t.timer).collect::<Vec<_>>()
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("KiTimerTableSize") && n.contains("holds 8")),
        "the extent says where it came from: {:?}",
        table.notes
    );
    assert!(
        table.notes.iter().any(|n| n.contains("bucket 3")
            && n.contains("bucket 4")
            && n.contains("bucket 7")
            && n.contains("torn")),
        "{:?}",
        table.notes
    );
}

/// A `KiTimerTableSize` that does not fit the room the symbol table leaves is not believed: the
/// extent falls back to the heads' shape.
#[test]
fn a_table_size_that_does_not_fit_the_symbol_bound_is_ignored() {
    const HEAD_SIZE: u64 = 16;
    const SIZE_VAR: u64 = 0x9_0000;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    img.put_u32(SIZE_VAR, 512); // room for 8 buckets only
    for b in 0..6 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    let next_symbol = head(8);
    let isf_text = isf_legacy_bare_list_heads().replace(
        "\"KiProcessorBlock\":",
        &format!(
            "\"KiDispatcherReadyListHead\": {{\"address\": {next_symbol}}},\n    \
             \"KiTimerTableSize\": {{\"address\": {SIZE_VAR}}},\n    \"KiProcessorBlock\":"
        ),
    );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    assert_eq!(table.buckets_walked, 6, "{:?}", table.notes);
    assert!(
        !table.notes.iter().any(|n| n.contains("kernel's own")),
        "{:?}",
        table.notes
    );
}

/// **A list item whose `Header.Type` is not a timer's is not a timer** (`MEM-059`). A capture taken
/// while the system ran leaves a torn bucket whose list runs into memory that is no `_KTIMER`; Volatility
/// 2 skips an item unless its dispatcher header says notification (8) or synchronisation (9) timer. The
/// M57 "Terry" Vista image published three such rows (routines `0x24b25548`, `0x1cccfd60`,
/// `0x850a0ca4`, period 0) before this check. Only where the build declares the header: an ISF without
/// `_KTIMER.Header` is walked as before. SYNTHETIC: one real timer and one junk item.
#[test]
fn a_list_item_that_is_not_a_timer_by_its_header_is_skipped_and_counted() {
    const HEAD_SIZE: u64 = 16;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    for b in 0..4 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    // Bucket 1: TIMER_A, Type 8 (a notification timer), DPC in a module.
    let link_a = TIMER_A + TIMER_LIST_ENTRY;
    img.put_u64(head(1), link_a);
    img.put_u64(head(1) + 8, link_a);
    img.put_u64(link_a, head(1));
    img.put_u64(link_a + 8, head(1));
    img.put_u8(TIMER_A, 8);
    img.put_u64(TIMER_A + TIMER_DPC, DPC_A);
    img.put_u64(DPC_A + DPC_ROUTINE, IN_MODULE);
    // Bucket 2: an item that is not a timer (Type 0x41) with a plausible-looking DPC.
    let link_b = TIMER_B + TIMER_LIST_ENTRY;
    img.put_u64(head(2), link_b);
    img.put_u64(head(2) + 8, link_b);
    img.put_u64(link_b, head(2));
    img.put_u64(link_b + 8, head(2));
    img.put_u8(TIMER_B, 0x41);
    img.put_u64(TIMER_B + TIMER_DPC, DPC_A);
    let isf_text = isf_legacy_bare_list_heads()
        .replace(
            "\"_KTIMER\": {\"size\": 64, \"kind\": \"struct\", \"fields\": {",
            "\"_DISPATCHER_HEADER\": {\"size\": 24, \"kind\": \"struct\", \"fields\": {\"Type\": {\"offset\": 0, \"type\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}}},\n    \"_KTIMER\": {\"size\": 64, \"kind\": \"struct\", \"fields\": {\n      \"Header\": {\"offset\": 0, \"type\": {\"kind\": \"struct\", \"name\": \"_DISPATCHER_HEADER\"}},",
        )
        .replace(
            "\"KiProcessorBlock\":",
            &format!("\"KiDispatcherReadyListHead\": {{\"address\": {}}},\n    \"KiProcessorBlock\":", head(4)),
        );
    let profile = hook_profile(img, &isf_text);
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    let reported: Vec<u64> = table.timers.iter().map(|t| t.timer).collect();
    assert_eq!(reported, vec![TIMER_A], "{:?}", table.notes);
    assert_eq!(table.not_timers, 1);
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("dispatcher header") && n.contains("not timers")),
        "{:?}",
        table.notes
    );
    assert_eq!(table.to_json()["items_not_timers"], 1);
}

/// **Without a symbol bound, a torn head still ends the probe**: nothing but
/// the bytes says where the array stops, so a head that is not well-formed is
/// not assumed to be part of it.
#[test]
fn without_a_symbol_bound_a_torn_head_still_ends_the_legacy_probe() {
    const HEAD_SIZE: u64 = 16;
    let head = |b: u64| LEGACY_HEAD + b * HEAD_SIZE;
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    for b in 0..6 {
        img.put_u64(head(b), head(b));
        img.put_u64(head(b) + 8, head(b));
    }
    let link_b = TIMER_B + TIMER_LIST_ENTRY;
    img.put_u64(head(2), link_b);
    img.put_u64(link_b + 8, head(4));
    // The plain bare ISF declares nothing above the head.
    let profile = hook_profile(img, &isf_legacy_bare_list_heads());
    let table = read_timers(&profile, &symbols(Some(LEGACY_HEAD)), &modules(), 65_536)
        .expect("the table reads");
    let note = table
        .notes
        .iter()
        .find(|n| n.contains("DERIVED"))
        .expect("the derivation is stated");
    assert!(
        note.contains("No symbol is declared above the head"),
        "{note}"
    );
    assert_eq!(table.buckets_walked, 2, "{note}");
}

/// **A signed `Period` is still read** (found 2026-09-24): XP SP2 declares
/// `_KTIMER.Period` as `long`, and an unsigned-only read published no period
/// for the 12 periodic DPC timers Volatility 3 prints on `tigger.vmem`.
#[test]
fn a_period_the_build_declares_signed_is_read() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        60_000,
    );
    let signed = isf(NESTED).replace(
        "\"Period\": {\"offset\": 60, \"type\": {\"kind\": \"base\",\n                 \"name\": \"unsigned long\"}}",
        "\"Period\": {\"offset\": 60, \"type\": {\"kind\": \"base\",\n                 \"name\": \"long\"}}",
    );
    assert!(
        signed.contains("\"name\": \"long\"}}"),
        "the fixture declares Period signed"
    );
    let table = read(img, &signed, None);
    assert_eq!(table.timers.len(), 1);
    assert_eq!(table.timers[0].period_ms, Some(60_000));
}

/// Every offset the walk used is on the record, so a report can be checked
/// against the build's own symbols rather than against this source file.
#[test]
fn the_resolved_offsets_are_published_with_their_basis() {
    let table = read(image(1), &isf(NESTED), None);
    let j = table.layout.to_json();
    assert_eq!(j["shape"], serde_json::json!("per_processor"));
    assert_eq!(j["entry_list_offset"], serde_json::json!(ENTRY_LIST));
    assert_eq!(
        j["timer_list_entry_offset"],
        serde_json::json!(TIMER_LIST_ENTRY)
    );
    assert_eq!(j["dpc_routine_offset"], serde_json::json!(DPC_ROUTINE));
    assert_eq!(j["buckets_declared"], serde_json::json!(8));
    assert!(
        j["offsets_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("own symbol table"),
        "got {:?}",
        j["offsets_basis"]
    );
}

/// Arc is used by the reader construction inside `read_timers`; this keeps the
/// import honest in the test module without a second walk.
#[test]
fn the_module_map_is_shared_rather_than_rebuilt() {
    let shared = Arc::new(modules());
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    let profile = hook_profile(img, &isf(NESTED));
    let table = read_timers(&profile, &symbols(None), &shared, 65_536).expect("read");
    assert_eq!(table.timers.len(), 1);
}

// --- MEM-052: evidence values are never trusted as addresses ---------------

/// Where the fixture keeps the two obfuscation keys.
const WAIT_NEVER_AT: u64 = 0x1_0200;
const WAIT_ALWAYS_AT: u64 = 0x1_0208;
/// Key values chosen so the rotate is not a multiple of eight bits and no
/// byte of either key is zero.
const WAIT_NEVER: u64 = 0x1C2B_3A49_5867_7613;
const WAIT_ALWAYS: u64 = 0x8F7E_6D5C_4B3A_2918;
/// `_KOBJECTS.DpcObject` as the fixture's enum declares it. Deliberately not
/// the value real builds use (19), so a reader holding a constant fails.
const DPC_OBJECT: u8 = 0x2A;

/// The fixture build, declaring the two keys, `_KDPC.Type` and the
/// `_KOBJECTS` enumeration — what an x64 Windows 8+ ISF carries.
fn isf_encoded() -> String {
    isf(NESTED)
        .replace(
            "\"_KDPC\": {\"size\": 64, \"kind\": \"struct\", \"fields\": {",
            "\"_KDPC\": {\"size\": 64, \"kind\": \"struct\", \"fields\": {\n      \"Type\": {\"offset\": 0, \"type\": {\"kind\": \"base\", \"name\": \"unsigned char\"}},",
        )
        .replace(
            "\"enums\": {}",
            &format!(
                "\"enums\": {{\"_KOBJECTS\": {{\"base\": \"long\", \"size\": 4, \"constants\": \
                 {{\"DpcObject\": {DPC_OBJECT}, \"ThreadedDpcObject\": 43}}}}}}"
            ),
        )
        .replace(
            "\"KiProcessorBlock\":",
            &format!(
                "\"KiWaitNever\": {{\"address\": {WAIT_NEVER_AT}}},\n    \
                 \"KiWaitAlways\": {{\"address\": {WAIT_ALWAYS_AT}}},\n    \"KiProcessorBlock\":"
            ),
        )
}

fn encoded_symbols() -> TimerSymbols {
    TimerSymbols {
        dpc_keys: Some(DpcKeySymbols {
            wait_never: WAIT_NEVER_AT,
            wait_always: WAIT_ALWAYS_AT,
        }),
        ..symbols(None)
    }
}

/// The kernel's encoding of a `_KDPC` pointer into `_KTIMER.Dpc`, written as
/// the inverse of the published decode (Skape, *Uninformed* vol. 8 art. 5;
/// debugwar.com, "Iterate DPC timers from Win7 to Win11"): XOR `KiWaitAlways`,
/// byte-swap, XOR the timer's address, rotate right by `KiWaitNever`'s low
/// byte, XOR `KiWaitNever`. Written independently here so the test does not
/// share code with the reader it tests.
fn encode(dpc: u64, timer: u64) -> u64 {
    let x = (dpc ^ WAIT_ALWAYS).swap_bytes() ^ timer;
    x.rotate_right(u32::from(WAIT_NEVER as u8)) ^ WAIT_NEVER
}

fn encoded_image(dpc_field: u64, dpc_type: u8) -> Image {
    let mut img = image(1);
    img.put_u64(WAIT_NEVER_AT, WAIT_NEVER);
    img.put_u64(WAIT_ALWAYS_AT, WAIT_ALWAYS);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, OUTSIDE_ANY_MODULE)),
        0,
    );
    img.put_u8(DPC_A, dpc_type);
    img.put_u64(TIMER_A + TIMER_DPC, dpc_field);
    img
}

/// **`MEM-052`: a `Dpc` value whose members lie past the top of the address
/// space is unreadable, not a panic.** On DFIR Madness Case 001's
/// `citadeldc01.mem` (Server 2012 R2) `dpc + DeferredRoutine` overflowed and
/// the panic took the whole Windows memory pipeline with it. The row is kept,
/// with the field as read and the reason.
#[test]
fn a_dpc_value_whose_members_overflow_is_unreadable_and_not_a_panic() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        0,
        TIMER_A,
        Some((DPC_A, IN_MODULE)),
        0,
    );
    img.put_u64(TIMER_A + TIMER_DPC, 0xFFFF_FFFF_FFFF_FFF0);
    let table = read(img, &isf(NESTED), None);
    assert_eq!(table.timers.len(), 1, "the timer is still published");
    let t = &table.timers[0];
    assert_eq!(t.routine, None, "nothing was read through a non-address");
    assert_eq!(t.dpc, None, "the field is not published as a DPC address");
    assert_eq!(t.dpc_field_raw, Some(0xFFFF_FFFF_FFFF_FFF0));
    let why = t.dpc_unreadable.as_deref().unwrap_or_default();
    assert!(why.contains("overflow"), "the reason is stated: {why:?}");
    assert!(!t.is_signal());
    let j = table.to_json();
    assert_eq!(j["dpc_unreadable"], serde_json::json!(1));
    assert_eq!(j["timers_with_a_dpc"], serde_json::json!(0));
}

/// **An encoded `Dpc` is decoded with this build's own keys**, and the result
/// is checked against the `_KDPC` it must point at before anything is read
/// through it.
#[test]
fn an_encoded_dpc_is_decoded_with_this_builds_keys() {
    let field = encode(DPC_A, TIMER_A);
    assert_ne!(field, DPC_A);
    let profile = hook_profile(encoded_image(field, DPC_OBJECT), &isf_encoded());
    let table = read_timers(&profile, &encoded_symbols(), &modules(), 65_536).expect("read");
    let t = &table.timers[0];
    assert_eq!(t.dpc_field_raw, Some(field), "the field as read is kept");
    assert_eq!(t.dpc, Some(DPC_A), "decoded to the _KDPC");
    assert_eq!(t.routine, Some(OUTSIDE_ANY_MODULE));
    assert!(t.is_signal());
    let j = table.to_json();
    assert_eq!(j["dpc_encoding"]["state"], "decoded");
    assert_eq!(j["dpc_pointers_decoded"], serde_json::json!(1));
    assert_eq!(j["dpc_unreadable"], serde_json::json!(0));
}

/// A decoded pointer that does not land on a `_KDPC` of this build's declared
/// type is unreadable with that reason: no routine is read through it and it
/// is never a signal. Nothing falls back to the undecoded value.
#[test]
fn a_decoded_dpc_that_is_not_a_kdpc_is_unreadable_with_the_reason() {
    let field = encode(DPC_A, TIMER_A);
    let profile = hook_profile(encoded_image(field, 0x07), &isf_encoded());
    let table = read_timers(&profile, &encoded_symbols(), &modules(), 65_536).expect("read");
    let t = &table.timers[0];
    assert_eq!(t.routine, None);
    assert_eq!(t.dpc, None);
    let why = t.dpc_unreadable.as_deref().unwrap_or_default();
    assert!(
        why.contains("_KOBJECTS") && why.contains("0x07"),
        "the reason names the check and the byte: {why:?}"
    );
    assert!(!t.is_signal());
}

/// Keys the image does not hold make every encoded row unreadable, and the
/// table says so once.
#[test]
fn unreadable_keys_leave_every_encoded_dpc_unreadable_and_say_why() {
    let field = encode(DPC_A, TIMER_A);
    let profile = hook_profile(encoded_image(field, DPC_OBJECT), &isf_encoded());
    let mut symbols = encoded_symbols();
    symbols.dpc_keys = Some(DpcKeySymbols {
        wait_never: 0x7FFF_FFFF_0000,
        wait_always: 0x7FFF_FFFF_0008,
    });
    let table = read_timers(&profile, &symbols, &modules(), 65_536).expect("read");
    assert_eq!(table.timers[0].routine, None);
    assert!(table.timers[0].dpc_unreadable.is_some());
    assert_eq!(table.to_json()["dpc_encoding"]["state"], "keys_unreadable");
}

/// A legacy bucket whose first link is the top of the address space ends the
/// probe; it does not overflow reading the link's `Blink`.
#[test]
fn a_legacy_link_at_the_top_of_the_address_space_ends_the_probe_without_a_panic() {
    let mut img = Image::sized(0x10_0000);
    img.put_u32(PROCESSOR_COUNT, 1);
    empty_bucket(&mut img, LEGACY_HEAD, 0);
    img.put_u64(LEGACY_HEAD + ENTRY_SIZE + ENTRY_LIST, 0xFFFF_FFFF_FFFF_FFF8);
    let table = read(img, &isf_legacy(), Some(LEGACY_HEAD));
    assert_eq!(table.buckets_walked, 1);
}

/// A `_KPRCB` pointer so close to the top of the address space that the
/// timer table's offset runs past it is skipped with a note, not added.
#[test]
fn a_prcb_pointer_whose_table_runs_past_the_address_space_is_skipped_and_stated() {
    let mut img = image(1);
    img.put_u64(PRCB_ARRAY, 0xFFFF_FFFF_FFFF_FF80);
    let table = read(img, &isf(NESTED), None);
    assert_eq!(table.buckets_walked, 0);
    assert!(
        table.notes.iter().any(|n| n.contains("past the top")),
        "got {:?}",
        table.notes
    );
}

/// **An encoded null is a timer with no DPC**, not an unreadable one. On an
/// encoding build a timer that names no DPC still stores a non-zero field —
/// the encoding of 0 — and it decodes to 0. Measured on the Windows 11 26200
/// capture: 157 of 209 timers, every one decoding to exactly 0.
#[test]
fn an_encoded_null_dpc_is_a_timer_with_no_dpc() {
    let field = encode(0, TIMER_A);
    assert_ne!(field, 0, "the encoding of null is not null");
    let profile = hook_profile(encoded_image(field, DPC_OBJECT), &isf_encoded());
    let table = read_timers(&profile, &encoded_symbols(), &modules(), 65_536).expect("read");
    let t = &table.timers[0];
    assert_eq!(t.dpc_unreadable, None, "an ordinary timer: {t:?}");
    assert_eq!(t.dpc, None);
    assert_eq!(t.routine, None);
    assert_eq!(t.dpc_field_raw, Some(field));
    let j = t.to_json();
    assert!(j["no_dpc_note"].is_string(), "{j}");
    assert_eq!(table.to_json()["dpc_unreadable"], serde_json::json!(0));
}

// --- the PatchGuard shape (`MEM-054`) ----------------------------------------

/// `DeferredContext` as read from the Case 001 desktop's PatchGuard-shaped
/// timer: non-canonical on x64.
const NON_CANONICAL_CONTEXT: u64 = 0x5a47_4314_a0a2_2080;
/// A `_KTIMER` address that is not 8-aligned, as the Case 001 desktop's
/// PatchGuard-shaped timer was (0xffffbe8e7105d5ab).
const UNALIGNED_TIMER: u64 = TIMER_B + 3;

/// One timer in bucket 3 whose routine is outside every module, at `timer`,
/// with `context` as its `DeferredContext`.
fn outside_timer(timer: u64, context: u64) -> TimerTable {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        3,
        timer,
        Some((DPC_B, OUTSIDE_ANY_MODULE)),
        0,
    );
    img.put_u64(DPC_B + DPC_CONTEXT, context);
    read(img, &isf(NESTED), None)
}

/// **`MEM-054`: a timer with PatchGuard's shape is published, named, and not
/// graded.** All three conditions hold: the `_KTIMER` is not 8-aligned, the
/// routine lands in no loaded module on an authoritative map, and
/// `DeferredContext` is non-canonical. The row stays on the record — it is
/// counted separately, not suppressed — and the record says the shape is a
/// shape, which a rootkit could imitate. A synthetic fixture: it pins the
/// mechanism, not a validation on real evidence.
#[test]
fn a_patchguard_shaped_timer_is_published_and_not_graded() {
    let table = outside_timer(UNALIGNED_TIMER, NON_CANONICAL_CONTEXT);
    assert_eq!(table.timers.len(), 1, "the row is published");
    let t = &table.timers[0];
    assert_eq!(t.timer, UNALIGNED_TIMER);
    assert_eq!(t.context, Some(NON_CANONICAL_CONTEXT));
    assert!(t.patchguard_shaped());
    assert!(!t.is_signal(), "the shape is not graded");
    let j = t.to_json();
    assert_eq!(j["patchguard_shaped"], serde_json::json!(true));
    assert_eq!(j["is_signal"], serde_json::json!(false));
    let basis = j["patchguard_shape_basis"].as_str().unwrap_or_default();
    assert!(
        basis.contains("aligned") && basis.contains("canonical") && basis.contains("imitate"),
        "the basis names the conditions and the limit: {basis:?}"
    );
    // The basis travels on every shaped row of every capture: it states the
    // rule, never which corpus the rule was measured on (that is validation
    // prose, and lives in VALIDATION.md / KNOWN_ANSWERS.md).
    assert!(
        !basis.contains("Case 001") && !basis.contains("DFIR Madness"),
        "the per-row basis carries no corpus-specific measurement: {basis:?}"
    );
    assert_eq!(table.signals(), 0);
    let tj = table.to_json();
    assert_eq!(tj["patchguard_shaped"], serde_json::json!(1));
    assert_eq!(tj["routines_outside_any_module"], serde_json::json!(0));
    assert!(
        table.describe().contains("PatchGuard"),
        "{}",
        table.describe()
    );
}

/// Break the alignment condition alone: an 8-aligned timer outside every
/// module with a non-canonical context is still the signal, so the
/// recognition cannot become a blanket suppression.
#[test]
fn an_aligned_timer_outside_every_module_is_still_the_signal() {
    let table = outside_timer(TIMER_B, NON_CANONICAL_CONTEXT);
    let t = &table.timers[0];
    assert!(!t.patchguard_shaped());
    assert!(t.is_signal());
    assert_eq!(t.to_json()["patchguard_shaped"], serde_json::json!(false));
    assert_eq!(table.to_json()["patchguard_shaped"], serde_json::json!(0));
    assert_eq!(table.signals(), 1);
}

/// Break the context condition alone: an unaligned timer outside every module
/// whose context is an ordinary canonical pointer is still the signal.
#[test]
fn a_canonical_context_keeps_the_signal() {
    let table = outside_timer(UNALIGNED_TIMER, 0xffff_be8e_7000_1000);
    let t = &table.timers[0];
    assert!(!t.patchguard_shaped());
    assert!(t.is_signal());
    assert_eq!(table.signals(), 1);
}

/// Break the ownership condition alone: the shape is never claimed for a
/// routine that could not be attributed (an incomplete module map), because
/// "outside every module" was never established.
#[test]
fn an_undetermined_owner_is_neither_the_signal_nor_the_shape() {
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        3,
        UNALIGNED_TIMER,
        Some((DPC_B, OUTSIDE_ANY_MODULE)),
        0,
    );
    img.put_u64(DPC_B + DPC_CONTEXT, NON_CANONICAL_CONTEXT);
    let profile = hook_profile(img, &isf(NESTED));
    let empty = ModuleMap::from_ranges(Vec::new());
    let table = read_timers(&profile, &symbols(None), &empty, 65_536).expect("read");
    let t = &table.timers[0];
    assert!(!t.patchguard_shaped());
    assert!(!t.is_signal());
}

/// **A PatchGuard-shaped row is still offered to the unloaded-driver
/// cross-reference.** Not grading the shape must not also hide its routine
/// from the check that would name an unloaded driver whose range holds it —
/// a rootkit imitating the shape would otherwise escape both. The pair is
/// labelled as the shaped row it is. Synthetic fixture: it pins the
/// mechanism, not a validation on real evidence.
#[test]
fn a_patchguard_shaped_row_is_still_offered_to_the_unloaded_driver_cross_reference() {
    let table = outside_timer(UNALIGNED_TIMER, NON_CANONICAL_CONTEXT);
    let candidates = table.unloaded_cross_reference_candidates();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!(candidates[0].1, OUTSIDE_ANY_MODULE);
    assert!(
        candidates[0].0.contains("PatchGuard"),
        "the pair says which kind of row it came from: {candidates:?}"
    );
    // A graded row is offered as before.
    let graded = outside_timer(TIMER_B, NON_CANONICAL_CONTEXT);
    let candidates = graded.unloaded_cross_reference_candidates();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(!candidates[0].0.contains("PatchGuard"), "{candidates:?}");
    // A routine that could not be attributed is offered by neither route.
    let mut img = image(1);
    link_timer(
        &mut img,
        table_base(PRCB0),
        3,
        UNALIGNED_TIMER,
        Some((DPC_B, OUTSIDE_ANY_MODULE)),
        0,
    );
    img.put_u64(DPC_B + DPC_CONTEXT, NON_CANONICAL_CONTEXT);
    let profile = hook_profile(img, &isf(NESTED));
    let empty = ModuleMap::from_ranges(Vec::new());
    let undetermined = read_timers(&profile, &symbols(None), &empty, 65_536).expect("read");
    assert!(undetermined
        .unloaded_cross_reference_candidates()
        .is_empty());
}

/// **Each row's `signal_basis` states the rule the row is graded by**,
/// including the PatchGuard-shape exception, so a shaped row with
/// `is_signal: false` does not contradict its own basis.
#[test]
fn the_signal_basis_states_the_patchguard_shape_exception() {
    let table = outside_timer(UNALIGNED_TIMER, NON_CANONICAL_CONTEXT);
    let basis = table.timers[0].to_json()["signal_basis"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        basis.contains("PatchGuard") && basis.contains("patchguard_shaped"),
        "{basis}"
    );
}

/// **The table's sentence counts distinct timers, and says so.** Until
/// `MEM-055` it counted rows (a timer linked into two buckets was two), and
/// said so; now a timer is one row whatever reached it, and the sentence names
/// both numbers.
#[test]
fn the_description_counts_distinct_timers_and_names_the_rows_walked() {
    let table = outside_timer(UNALIGNED_TIMER, NON_CANONICAL_CONTEXT);
    let text = table.describe();
    assert!(
        text.contains("1 more have the shape of PatchGuard"),
        "{text}"
    );
    assert!(text.contains("1 distinct timer(s)"), "{text}");
    assert!(text.contains("from 1 row(s) walked"), "{text}");
    assert!(text.contains("MEM-055"), "{text}");
}

// --- one row per `_KTIMER` (`MEM-055`) --------------------------------------

/// The head of `bucket` in the table at `base`.
fn bucket_head(base: u64, bucket: u64) -> u64 {
    base + bucket * ENTRY_SIZE + ENTRY_LIST
}

/// Link `TIMER_A` (DPC routine outside every module) so that it is reached
/// from bucket 3 of BOTH processors' tables: both heads point at its link,
/// and its link closes onto processor 1's head, as a timer relinked from one
/// table to another while the image was taken would look. A synthetic
/// fixture: it pins the mechanism, not a validation on real evidence.
fn a_timer_in_two_tables() -> Image {
    let mut img = image(2);
    link_timer(
        &mut img,
        table_base(PRCB1),
        3,
        TIMER_A,
        Some((DPC_A, OUTSIDE_ANY_MODULE)),
        0,
    );
    let head0 = bucket_head(table_base(PRCB0), 3);
    img.put_u64(head0, TIMER_A + TIMER_LIST_ENTRY);
    img.put_u64(head0 + 8, TIMER_A + TIMER_LIST_ENTRY);
    img
}

/// **`MEM-055`: a `_KTIMER` reached from two lists is one timer, and both
/// sightings are kept.** Before the fix it was two rows and two signals, so
/// the Case 001 desktop's one PatchGuard-shaped timer was two rows and every
/// count was a count of rows.
#[test]
fn a_timer_reached_from_two_tables_is_one_timer_and_both_sightings_are_kept() {
    let table = read(a_timer_in_two_tables(), &isf(NESTED), None);
    let rows: Vec<_> = table.timers.iter().filter(|t| t.timer == TIMER_A).collect();
    assert_eq!(rows.len(), 1, "one row for the one timer");
    assert_eq!(rows[0].reached_from, vec![(Some(0), 3), (Some(1), 3)]);
    assert!(rows[0].reached_more_than_once_reason.is_some());
    assert_eq!(table.signals(), 1, "one signal, not one per sighting");
    let j = table.to_json();
    assert_eq!(j["timers_reported"], table.timers.len());
    assert_eq!(j["timers_reached_more_than_once"], 1);
    let rows_walked: usize = table.timers.iter().map(|t| t.reached_from.len()).sum();
    assert_eq!(j["rows_walked"], rows_walked);
    assert_eq!(
        j["timers"]
            .as_array()
            .and_then(|rows| rows
                .iter()
                .find(|r| r["timer_address"] == serde_json::json!(format!("{TIMER_A:#018x}"))))
            .map(|r| r["reached_from"].clone()),
        Some(serde_json::json!([
            {"processor": 0, "bucket": 3},
            {"processor": 1, "bucket": 3}
        ]))
    );
    assert!(
        table.describe().contains("distinct"),
        "{}",
        table.describe()
    );
}

/// **`MEM-055` (i): two `KiProcessorBlock` slots naming the same `_KPRCB` walk
/// its table once, and the record names the repeat.** A smeared array (the
/// LoneWolf capture's `KeNumberProcessors` reads 0, so the probe decides
/// alone) otherwise walks one table twice and reports every timer in it
/// twice. Synthetic: it pins the mechanism.
#[test]
fn a_duplicate_prcb_pointer_is_walked_once_and_named() {
    let mut img = image(2);
    img.put_u64(PRCB_ARRAY + 8, PRCB0);
    link_timer(
        &mut img,
        table_base(PRCB0),
        3,
        TIMER_A,
        Some((DPC_A, OUTSIDE_ANY_MODULE)),
        0,
    );
    let table = read(img, &isf(NESTED), None);
    assert_eq!(table.processors_walked, 1);
    assert_eq!(table.timers.len(), 1);
    assert_eq!(table.timers[0].reached_from, vec![(Some(0), 3)]);
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("KiProcessorBlock") && n.contains("same `_KPRCB`")),
        "got {:?}",
        table.notes
    );
}

/// **`MEM-055` (ii): a bucket's list that leads into another bucket's head
/// stops there, and the head is not published as a timer.** Bucket 0's head
/// points at `TIMER_A`, whose link leads to bucket 3's head, whose list holds
/// `TIMER_A`. Before the fix bucket 3's head was published as a "timer" at
/// `head - TimerListEntry` and bucket 0's walk ended in a cycle. Synthetic: it
/// pins the mechanism.
#[test]
fn a_bucket_list_that_leads_into_another_bucket_stops_there_and_says_so() {
    let mut img = image(1);
    let base = table_base(PRCB0);
    link_timer(&mut img, base, 3, TIMER_A, Some((DPC_A, IN_MODULE)), 0);
    let head0 = bucket_head(base, 0);
    let head3 = bucket_head(base, 3);
    img.put_u64(head0, TIMER_A + TIMER_LIST_ENTRY);
    img.put_u64(head0 + 8, TIMER_A + TIMER_LIST_ENTRY);
    let table = read(img, &isf(NESTED), None);
    assert!(
        !table
            .timers
            .iter()
            .any(|t| t.timer == head3 - TIMER_LIST_ENTRY),
        "a bucket head is not a timer: {:?}",
        table.timers.iter().map(|t| t.timer).collect::<Vec<_>>()
    );
    assert_eq!(table.timers.len(), 1);
    assert_eq!(
        table.timers[0].reached_from,
        vec![(Some(0), 0), (Some(0), 3)]
    );
    let reason = table.timers[0]
        .reached_more_than_once_reason
        .clone()
        .unwrap_or_default();
    assert!(
        reason.contains("bucket 0") && reason.contains("bucket 3"),
        "{reason}"
    );
    assert!(
        table
            .notes
            .iter()
            .any(|n| n.contains("entered_another_bucket") && n.contains("bucket 3")),
        "got {:?}",
        table.notes
    );
    assert!(
        !table.notes.iter().any(|n| n.contains("cycle")),
        "the walk stopped at the head, not in a cycle: {:?}",
        table.notes
    );
}

/// The reason for the cross-table case names both tables.
#[test]
fn a_timer_reached_from_two_tables_says_which_list_led_where() {
    let table = read(a_timer_in_two_tables(), &isf(NESTED), None);
    let row = table.timers.iter().find(|t| t.timer == TIMER_A).unwrap();
    let reason = row
        .reached_more_than_once_reason
        .clone()
        .unwrap_or_default();
    assert!(
        reason.contains("processor 0") && reason.contains("processor 1"),
        "{reason}"
    );
    assert_eq!(
        table.timers.len(),
        1,
        "the other table's head is not a timer"
    );
}
