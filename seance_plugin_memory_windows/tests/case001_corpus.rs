//! The Windows memory pipeline on DFIR Madness Case 001 ("The Stolen Szechuan
//! Sauce"), and a measurement helper for any other capture (`MEM-051`,
//! `MEM-052`, and the silent Desktop run).
//!
//! # The images
//!
//! DFIR Madness Case 001 publishes two 2 GiB raw memory captures, taken
//! 2020-09-18/19: `citadeldc01.mem` (Windows Server 2012 R2 x64, the domain
//! controller) and `DESKTOP-SDN1RPT.mem` (Windows 10 x64). Provenance and the
//! published MD5s: `~/forensic_corpora/dfir_madness_case001/PROVENANCE.md`.
//! They ship as `DC01-memory.zip` and `DESKTOP-SDN1RPT-memory.zip`; unzip both
//! into one directory and point `SEANCE_CASE001_MEM` at it.
//!
//! # What these tests pin
//!
//! - `MEM-052`: the domain controller's pipeline panicked with "attempt to add
//!   with overflow" in `tamper_timers.rs`, adding a `_KDPC` member offset to a
//!   `_KTIMER.Dpc` value that on this build is not a pointer at all but an
//!   encoded one. The whole Windows memory pipeline died with it.
//! - That both captures produce a tamper-checks record, or a record saying
//!   why the stage could not run — never nothing.
//!
//! # Measuring another image
//!
//! `SEANCE_TAMPER_IMAGE` (a file) and `SEANCE_TAMPER_OUT` (a file to write)
//! run the pipeline over any capture and write the tamper-checks record, or
//! every record's type when there is none, as JSON. That is how the per-image
//! before/after counts in `seance_memory/tests/KNOWN_ANSWERS.md` were taken.
//!
//! Release-only, like every whole-pipeline corpus test here. `SEANCE_SYMBOL_DIRS`
//! names the extracted Volatility Windows symbol pack.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_memory::analysis::MemoryAnalysisModule;
use seance_plugin_memory_windows::WindowsMemoryAnalysis;
use serde_json::Value;

const CASE001: &str = "SEANCE_CASE001_MEM";

fn symbol_dirs() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
        let dirs: Vec<PathBuf> = list
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits directly under the workspace root")
        .join("reference/volatility3/volatility3/symbols")]
}

/// Every record the whole Windows pipeline produces over one image.
fn pipeline(path: &Path) -> Vec<Value> {
    let source: Arc<dyn DataSource> = Arc::new(
        seance_core::data_source::FileDataSource::new(path.to_path_buf())
            .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display())),
    );
    let image = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
    );
    MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()))
        .process(&image)
        .unwrap_or_else(|e| {
            panic!(
                "{}: the pipeline failed, which is the finding: {e}",
                path.display()
            )
        })
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

/// The tamper-checks record, or the stage's own failure record.
fn tamper_outcome(records: &[Value]) -> Option<&Value> {
    records.iter().find(|r| {
        r["record_type"] == "MemoryTamperChecks"
            || (r["record_type"] == "MemoryStageFailure" && r["stage"] == "tamper_checks")
    })
}

static DC: OnceLock<Option<Vec<Value>>> = OnceLock::new();
static DESKTOP: OnceLock<Option<Vec<Value>>> = OnceLock::new();

macro_rules! require {
    ($cell:ident, $name:expr) => {
        match $cell
            .get_or_init(|| {
                seance_core::test_support::corpus::file(CASE001, $name).map(|p| pipeline(&p))
            })
            .as_ref()
        {
            Some(records) => records,
            None => return,
        }
    };
}

fn group<'a>(record: &'a Value, name: &str) -> &'a Value {
    record["groups"]
        .as_array()
        .expect("one status per group")
        .iter()
        .find(|g| g["group"] == name)
        .unwrap_or_else(|| panic!("group {name} is reported"))
}

/// **`MEM-052`: the domain controller's pipeline completes.**
///
/// Before the fix this panicked inside `read_timers` — `dpc +
/// layout.dpc_routine` overflowed on an encoded `_KTIMER.Dpc` — and the panic
/// took every stage after it down too. Now the timers group runs, and every
/// timer whose DPC field the walk could not turn into an address is published
/// as unreadable with its reason rather than dropped or guessed.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_domain_controllers_pipeline_completes_and_reads_its_timers() {
    let records = require!(DC, "citadeldc01.mem");
    let record = tamper_outcome(records).expect("a tamper-checks record or its failure");
    assert_eq!(
        record["record_type"], "MemoryTamperChecks",
        "the stage ran: {record}"
    );
    let status = group(record, "timers");
    assert_eq!(status["ran"], true, "timers ran: {}", status["detail"]);
    let timers = &record["timers"];
    let rows = timers["timers"].as_array().expect("rows");
    eprintln!(
        "citadeldc01: {} timer(s), {} with a DPC, {} decoded, {} unreadable, {} outside any module",
        rows.len(),
        timers["timers_with_a_dpc"],
        timers["dpc_pointers_decoded"],
        timers["dpc_unreadable"],
        timers["routines_outside_any_module"]
    );
    // Measured 2026-09-24 (`--release`, the Volatility Windows pack). Server
    // 2012 R2 encodes `_KTIMER.Dpc`; decoded and checked, 40 rows carry a DPC
    // (39 distinct timers, one listed twice), and every one of the 39 is a
    // row of Volatility 3's `windows.timers` with the same routine. 35 rows
    // decoded to a non-canonical value and were published as unreadable with
    // that reason; Volatility prints none of them either (2 after `MEM-055`,
    // below).
    //
    // `MEM-055`, re-measured 2026-09-26: 237 rows were 179 distinct timers.
    // 196 sightings remain once a list that leads into another bucket's head
    // stops there; the other 41 "rows" were bucket heads read as `_KTIMER`s,
    // and the unreadable count fell from 35 to 2 with them. 12 timers are still
    // reached from two lists: 4 where the walk saw the lists join, 8 where it
    // did not, and those say the reason is not established.
    assert_eq!(
        rows.len(),
        179,
        "distinct timers read (237 rows before MEM-055)"
    );
    assert_eq!(timers["timers_reported"].as_u64(), Some(179));
    assert_eq!(timers["rows_walked"].as_u64(), Some(196));
    assert_eq!(timers["timers_reached_more_than_once"].as_u64(), Some(12));
    assert_eq!(timers["dpc_encoding"]["state"], "decoded");
    // `MEM-055`: counts are of distinct timers. The 40 DPC rows were 39
    // timers, one reached from two buckets, and Volatility 3 lists 39.
    assert_eq!(timers["timers_with_a_dpc"].as_u64(), Some(39));
    assert_eq!(timers["dpc_unreadable"].as_u64(), Some(2));
    assert_eq!(timers["routines_outside_any_module"].as_u64(), Some(0));
    // `MEM-054`, measured 2026-09-26: no row here has PatchGuard's shape.
    assert_eq!(timers["patchguard_shaped"].as_u64(), Some(0));
    // Every routine that is published is a kernel address: a routine read
    // through an undecoded DPC pointer is exactly what must not reach a row.
    for row in rows {
        if let Some(routine) = row["deferred_routine"].as_str() {
            let value = u64::from_str_radix(routine.trim_start_matches("0x"), 16).unwrap_or(0);
            assert!(value >= 0xFFFF_8000_0000_0000, "{row}");
        }
    }
}

/// **The Desktop capture says something about tamper checks.**
///
/// On 2026-09-24 the pipeline produced no tamper-checks record at all for
/// `DESKTOP-SDN1RPT.mem`. Whatever the stage can or cannot do on this image,
/// a report with no line for it reads as a stage that was never part of the
/// product.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_desktop_capture_reports_on_its_tamper_checks() {
    let records = require!(DESKTOP, "DESKTOP-SDN1RPT.mem");
    let outcome = tamper_outcome(records);
    let types: Vec<String> = records
        .iter()
        .map(|r| {
            format!(
                "{}{}",
                r["record_type"].as_str().unwrap_or("?"),
                r["stage"]
                    .as_str()
                    .map(|s| format!("[{s}]"))
                    .unwrap_or_default()
            )
        })
        .collect();
    assert!(
        outcome.is_some(),
        "no tamper-checks record and no failure record for the stage; records: {types:?}"
    );
}

/// **`MEM-054`: the Desktop's PatchGuard-shaped timer is published and not
/// graded.**
///
/// Once encoded DPCs were read (`MEM-053`), this clean Windows 10 capture
/// yielded one timer whose routine lies in no loaded module: the `_KTIMER` at
/// 0xffffbe8e7105d5ab, not 8-aligned, with a non-canonical `DeferredContext`
/// — the shape of PatchGuard's own timer, which Volatility also prints with
/// no module. It was graded as a signal and reached the findings as a lead
/// on a clean machine. It must stay on the record, named, and not be graded.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_desktops_patchguard_shaped_timer_is_not_a_signal() {
    let records = require!(DESKTOP, "DESKTOP-SDN1RPT.mem");
    let record = tamper_outcome(records).expect("a tamper-checks record or its failure");
    assert_eq!(record["record_type"], "MemoryTamperChecks", "{record}");
    let timers = &record["timers"];
    let rows = timers["timers"].as_array().expect("rows");
    eprintln!(
        "DESKTOP-SDN1RPT: {} row(s), {} with a DPC, {} outside any module (graded), {} \
         PatchGuard-shaped",
        rows.len(),
        timers["timers_with_a_dpc"],
        timers["routines_outside_any_module"],
        timers["patchguard_shaped"]
    );
    assert_eq!(timers["routines_outside_any_module"].as_u64(), Some(0));
    // `MEM-055`: the one timer was reached from two buckets and was two
    // rows until rows were de-duplicated by timer address. It is one now, and
    // its row names both places it was reached.
    assert_eq!(timers["patchguard_shaped"].as_u64(), Some(1));
    // `MEM-055`, measured 2026-09-26: 367 rows before are 187 distinct timers
    // from 245 sightings (the rest were bucket heads read as timers); 38 carry
    // a DPC, as Volatility 3 lists; 27 were reached from two or more lists, 11
    // where the walk saw the lists join and 16 where the reason is not
    // established.
    assert_eq!(timers["timers_reported"].as_u64(), Some(187));
    assert_eq!(rows.len(), 187);
    assert_eq!(timers["rows_walked"].as_u64(), Some(245));
    assert_eq!(timers["timers_reached_more_than_once"].as_u64(), Some(27));
    assert_eq!(timers["timers_with_a_dpc"].as_u64(), Some(38));
    assert_eq!(timers["dpc_unreadable"].as_u64(), Some(3));
    let shaped: Vec<&Value> = rows
        .iter()
        .filter(|r| r["timer_address"] == "0xffffbe8e7105d5ab")
        .collect();
    assert_eq!(shaped.len(), 1, "the timer is published once");
    assert!(
        shaped[0]["reached_from"].as_array().map_or(0, Vec::len) >= 2,
        "{}",
        shaped[0]
    );
    for row in shaped {
        assert_eq!(row["patchguard_shaped"], true, "{row}");
        assert_eq!(row["is_signal"], false, "{row}");
        assert!(row["patchguard_shape_basis"].is_string(), "{row}");
    }
}

/// Measure any capture: write its tamper-checks record to `SEANCE_TAMPER_OUT`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn measure_the_tamper_checks_on_any_capture() {
    let Some(image) = seance_core::test_support::corpus::path("SEANCE_TAMPER_IMAGE") else {
        return;
    };
    let out = std::env::var("SEANCE_TAMPER_OUT").expect("SEANCE_TAMPER_OUT names the output");
    let records = pipeline(&image);
    let value = match tamper_outcome(&records) {
        Some(record) => record.clone(),
        None => serde_json::json!({
            "no_tamper_record": true,
            "records": records,
        }),
    };
    std::fs::write(&out, serde_json::to_vec_pretty(&value).expect("json")).expect("write");
}

/// `MEM-054`, re-measured 2026-10-20 on every further Windows capture held:
/// none has a timer routine outside every module and none has a
/// PatchGuard-shaped timer. Each capture has its own variable and an unset one
/// is skipped, so the test runs on whichever of them a machine holds. The
/// figures are measurements taken with `measure_the_tamper_checks_on_any_capture`,
/// not answers taken from another tool, and the test was not run red: no code
/// changed. The Windows 11 captures need the 26200 ISF as well as the pack, so
/// `SEANCE_SYMBOL_DIRS` is a colon-separated list holding both. None of these
/// images holds a timer rootkit, so this pins the absence of a false positive
/// and tests nothing about a true one.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn further_captures_read_no_graded_and_no_patchguard_shaped_timer() {
    // (variable, label, timers, rows walked, with a DPC, unreadable)
    const CAPTURES: &[(&str, &str, u64, u64, u64, u64)] = &[
        (
            "SEANCE_WINMEM2020",
            "winmem2020 memdump-001 (Win 7 SP1 x64)",
            452,
            611,
            85,
            79,
        ),
        (
            "SEANCE_SERVER2008_MEM",
            "samsclass Server 2008 SP1 x86",
            173,
            192,
            57,
            0,
        ),
        ("SEANCE_ZAPFTIS_MEM", "0zapftis XP x86", 205, 205, 55, 0),
        (
            "SEANCE_WIN11_CONSOLE_MEM",
            "Win 11 26200 console VM",
            157,
            157,
            53,
            0,
        ),
        (
            "SEANCE_WIN11_VC_MEM",
            "Win 11 26200 VeraCrypt VM",
            168,
            168,
            52,
            0,
        ),
    ];
    for &(var, label, reported, rows, with_dpc, unreadable) in CAPTURES {
        let Some(image) = seance_core::test_support::corpus::path(var) else {
            continue;
        };
        let records = pipeline(&image);
        let record = tamper_outcome(&records).expect("a tamper-checks record or its failure");
        assert_eq!(
            record["record_type"], "MemoryTamperChecks",
            "{label}: {record}"
        );
        let timers = &record["timers"];
        assert_eq!(
            timers["routines_outside_any_module"].as_u64(),
            Some(0),
            "{label}"
        );
        assert_eq!(timers["patchguard_shaped"].as_u64(), Some(0), "{label}");
        assert_eq!(
            timers["timers_reported"].as_u64(),
            Some(reported),
            "{label}"
        );
        assert_eq!(timers["rows_walked"].as_u64(), Some(rows), "{label}");
        assert_eq!(
            timers["timers_with_a_dpc"].as_u64(),
            Some(with_dpc),
            "{label}"
        );
        assert_eq!(
            timers["dpc_unreadable"].as_u64(),
            Some(unreadable),
            "{label}"
        );
        assert!(
            timers["timers"]
                .as_array()
                .expect("rows")
                .iter()
                .all(|r| r["patchguard_shaped"] != true && r["is_signal"] != true),
            "{label}: no row is shaped or a signal"
        );
    }
}

/// The suspicious-threads record, or `None` when the stage did not run.
fn threads_record(records: &[Value]) -> Option<&Value> {
    records
        .iter()
        .find(|r| r["record_type"] == "MemorySuspiciousThreads")
}

/// One line per headline count, then one per finding, on stderr.
fn print_threads(label: &str, m: &Value) {
    eprintln!(
        "THREADS {label}: judged {} analysed {} starts_tested {} evidence {} {:?} gaps {} \
         outside_tree {} kernel_starts {} kernel_not_system {} lpc {} complete {}",
        m["processes_judged"],
        m["processes_analysed"],
        m["starts_tested"],
        m["evidence_count"],
        m["evidence_by_kind"],
        m["gap_count"],
        m["starts_outside_the_tree"],
        m["starts_in_kernel_space"],
        m["kernel_starts_on_threads_not_known_as_system"],
        m["win32_starts_holding_an_lpc_message_id"],
        m["complete"],
    );
    for process in m["processes"].as_array().into_iter().flatten() {
        for finding in process["findings"].as_array().into_iter().flatten() {
            let kinds: Vec<&str> = finding["suspicions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s["kind"].as_str())
                .collect();
            eprintln!(
                "THREADS {label} finding: {} {} tid {} {} {:#x} in {} -> {:?}",
                process["pid"],
                process["image_file_name"],
                finding["tid"],
                finding["which"],
                finding["address"].as_u64().unwrap_or(0),
                finding["region"],
                kinds
            );
        }
    }
}

/// Measure any capture: write its suspicious-threads record to
/// `SEANCE_THREADS_OUT`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn measure_the_suspicious_threads_on_any_capture() {
    let Some(image) = seance_core::test_support::corpus::path("SEANCE_THREADS_IMAGE") else {
        return;
    };
    let out = std::env::var("SEANCE_THREADS_OUT").expect("SEANCE_THREADS_OUT names the output");
    let records = pipeline(&image);
    let record = threads_record(&records).expect("the suspicious-thread stage produced a record");
    print_threads(&image.display().to_string(), record);
    std::fs::write(&out, serde_json::to_vec_pretty(record).expect("json")).expect("write");
}

/// What the suspicious-threads stage measured on one held capture (`MEM-024`).
///
/// **Observed, not graded.** No published key names an injected user thread in
/// any of these captures. The numbers are what the stage printed on
/// 2026-10-20, compared with Volatility 3 2.28.2
/// `windows.malware.suspicious_threads` run on the same file
/// (`documentation/VALIDATION.md`, `MEM-THR-2`). A change in a count is a
/// change to be explained, not a failure of a key.
struct ThreadsPin {
    /// Findings the stage publishes as evidence (a start in a private region,
    /// or in a region with an unexpected protection).
    evidence: u64,
    /// Starts it could not place because the backing file was unreadable.
    gaps: u64,
    /// Kernel-mode starts on threads whose `SystemThread` flag is clear.
    kernel_not_system: u64,
}

fn check_threads(
    label: &str,
    records: &[Value],
    pin: &ThreadsPin,
    evidence_threads: &[(u64, u64)],
) {
    let m = threads_record(records).expect("the suspicious-thread stage produced a record");
    print_threads(label, m);
    assert_eq!(m["evidence_count"], pin.evidence, "{label}: evidence");
    assert_eq!(m["gap_count"], pin.gaps, "{label}: gaps");
    assert_eq!(
        m["kernel_starts_on_threads_not_known_as_system"], pin.kernel_not_system,
        "{label}: kernel starts on threads not known as system"
    );
    let mut found: Vec<(u64, u64)> = Vec::new();
    for process in m["processes"].as_array().into_iter().flatten() {
        for finding in process["findings"].as_array().into_iter().flatten() {
            let evidential = finding["suspicions"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|s| s["kind"] != "backing_unknown");
            if evidential {
                found.push((
                    process["pid"].as_u64().unwrap_or(0),
                    finding["tid"].as_u64().unwrap_or(0),
                ));
            }
        }
    }
    found.sort_unstable();
    assert_eq!(found, evidence_threads, "{label}: which threads");
}

/// The Case 001 domain controller: one finding, spoolsv's `Win32StartAddress`
/// in a private `PAGE_EXECUTE_READWRITE` range. Volatility prints the same
/// thread and address (as two rows). The capture is not clean, so this is an
/// observation, not a false-positive count.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_case001_domain_controller() {
    let records = require!(DC, "citadeldc01.mem");
    let pin = ThreadsPin {
        evidence: 1,
        gaps: 0,
        kernel_not_system: 69,
    };
    check_threads("case001 dc", records, &pin, &[(3724, 2508)]);
}

/// The Case 001 desktop: powershell's start in a private RWX range is the one
/// finding. 61 more starts sit in `PAGE_EXECUTE_WRITECOPY` ranges whose file
/// name the stage could not read (a swapped-out `_FILE_OBJECT`, a name with an
/// embedded NUL); they are published as gaps, not as evidence. Volatility
/// prints 48 distinct rows for the same capture, one of them this thread, and
/// calls the rest "not file backed" for the same unreadable names.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_case001_desktop() {
    let records = require!(DESKTOP, "DESKTOP-SDN1RPT.mem");
    let pin = ThreadsPin {
        evidence: 1,
        gaps: 61,
        kernel_not_system: 85,
    };
    check_threads("case001 desktop", records, &pin, &[(3316, 3892)]);
}

fn threads_pinned_on(var: &str, pin: &ThreadsPin) {
    let Some(image) = seance_core::test_support::corpus::path(var) else {
        return;
    };
    let records = pipeline(&image);
    check_threads(var, &records, pin, &[]);
}

/// 13Cubed mini-memory CTF (Windows 10, a rogue svchost planted): no start in
/// a private or unexpectedly protected range. Volatility prints no row either.
/// `SEANCE_CUBED13_MEM` names the `memdump.mem`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_13cubed_capture() {
    let pin = ThreadsPin {
        evidence: 0,
        gaps: 0,
        kernel_not_system: 183,
    };
    threads_pinned_on("SEANCE_CUBED13_MEM", &pin);
}

/// LoneWolf (Windows 10 1803): no finding. Volatility not run on it.
/// `SEANCE_LONEWOLF_MEM` names the `memdump.mem`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_lonewolf_capture() {
    let pin = ThreadsPin {
        evidence: 0,
        gaps: 0,
        kernel_not_system: 211,
    };
    threads_pinned_on("SEANCE_LONEWOLF_MEM", &pin);
}

/// samsclass Server 2008 SP1 x86, a clean lab VM capture: no finding, so the
/// false-positive count here is 0. Three starts are gaps (a swapped-out
/// `_FILE_OBJECT`). `SEANCE_SAMSCLASS_MEM` names the `memdump.mem`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_clean_samsclass_server_2008_capture() {
    let pin = ThreadsPin {
        evidence: 0,
        gaps: 3,
        kernel_not_system: 61,
    };
    threads_pinned_on("SEANCE_SAMSCLASS_MEM", &pin);
}

/// CFReDS `boomer-win2003-2006-03-17.img` (Server 2003 SP0, Notepad running,
/// no malware described): no finding, false-positive count 0. 24 starts are
/// LPC message ids, which the stage does not place. `SEANCE_BOOMER2003_MEM`
/// names the image.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_clean_cfreds_server_2003_capture() {
    let pin = ThreadsPin {
        evidence: 0,
        gaps: 0,
        kernel_not_system: 0,
    };
    threads_pinned_on("SEANCE_BOOMER2003_MEM", &pin);
}
