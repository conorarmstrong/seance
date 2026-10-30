//! The kernel-side tamper checks on real Windows XP x86 captures (`MEM-020`,
//! `MEM-021`), graded against published answers and Volatility 3.
//!
//! # Why these images
//!
//! Every other Windows capture on this machine is a build with the
//! per-processor timer table, so the legacy `KiTimerTableListHead` path had
//! fixture coverage and no evidence coverage (`MEM-021`), and none of the seven
//! tamper groups had ever been seen firing on evidence whose answer is known
//! (`MEM-020`). These are real rootkit-era captures of the legacy shape:
//!
//! - **Malware Analyst's Cookbook** (Ligh et al., Wiley 2010), three of its
//!   eight XP SP2 x86 PAE `.vmem` images: `tigger.vmem`, `be2.vmem`,
//!   `zeus.vmem`. Kernel `ntkrnlpa.pdb` `BD8F451F3E754ED8A34B50560CEB08E3-1`,
//!   build 2600.xpsp_sp2_rtm.040803-2158. **Not redistributable**, and they
//!   hold live malware in memory: they are read as data and never executed.
//!   Published answer for `tigger.vmem` (M. H. Ligh, *Investigating Windows
//!   Threads with Volatility*, 2011-04-18): an orphan system thread, Pid 4,
//!   Tid 1648, `_ETHREAD` 0xff1f92b0, StartAddress 0xf2edd150.
//!   The other five (`coreflood`, `laqma`, `prolaco`, `sality`,
//!   `silentbanker`) were graded against Volatility 3 on 2026-09-27; no
//!   published answer ties them to these groups, so there they are agreement
//!   with the oracle and a count of false positives, never a true positive.
//!   Volatility's rows for them are in `legacy_xp_oracle/`.
//! - **Stuxnet** (Ligh, *Stuxnet's Footprint in Memory*, 2011-06-03): one XP
//!   SP3 x86 capture, `stuxnet.vmem`. **Not redistributable.** Its published
//!   answer covers callbacks and IRP hooks, not these groups, so here it is a
//!   second build and a negative control.
//!
//! # The independent reading
//!
//! Volatility 3.2.28.2 (`reference/volatility3`, run as an oracle only) on the
//! same files: `windows.timers`, `windows.orphan_kernel_threads`,
//! `windows.unloadedmodules`, `windows.debugregisters`. The procedure and every
//! number are in `documentation/VALIDATION.md` and
//! `seance_memory/tests/KNOWN_ANSWERS.md`. None of the expected values below
//! came from Séance.
//!
//! # Provisioning
//!
//! Unzip the images (they ship as `*.vmem.zip`) and point:
//!
//! - `SEANCE_COOKBOOK_MEM` at a directory holding `tigger.vmem`, `be2.vmem`
//!   and `zeus.vmem` (and, for the five-image grading below, `coreflood.vmem`,
//!   `laqma.vmem`, `prolaco.vmem`, `sality.vmem`, `silentbanker.vmem`);
//! - `SEANCE_STUXNET_MEM` at a directory holding `stuxnet.vmem`;
//! - `SEANCE_NIST_BASIC_MEM` at a directory holding
//!   `boomer-win2003-2006-03-17.img`, extracted from NIST CFReDS "Basic Memory
//!   Images" (`memory-images.rar`, opened with 7-Zip 23.01's RAR codec);
//! - `SEANCE_SYMBOL_DIRS` at the Volatility Windows symbol pack, extracted
//!   (the directory holding `ntkrnlpa.pdb/`).
//!
//! An unset corpus variable skips loudly; a set one whose file is missing
//! fails. Release-only, like every whole-pipeline corpus test here.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_memory::analysis::MemoryAnalysisModule;
use seance_plugin_memory_windows::WindowsMemoryAnalysis;
use serde_json::Value;

const COOKBOOK: &str = "SEANCE_COOKBOOK_MEM";
const STUXNET: &str = "SEANCE_STUXNET_MEM";
const NIST_BASIC: &str = "SEANCE_NIST_BASIC_MEM";
const SAMSCLASS: &str = "SEANCE_SAMSCLASS_2008_MEM";
const M57_VISTA: &str = "SEANCE_M57_VISTA_MEM";
const W2K3_X64: &str = "SEANCE_W2K3_X64_MEM";

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

/// The whole Windows pipeline over one image: its `MemoryTamperChecks` record
/// and its `MemorySuspiciousThreads` record, from the one run.
fn tamper_record(var: &str, name: &str) -> Option<(Value, Value)> {
    let path = seance_core::test_support::corpus::file(var, name)?;
    let source: Arc<dyn DataSource> = Arc::new(
        seance_core::data_source::FileDataSource::new(path.clone())
            .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display())),
    );
    let image = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
    );
    let out =
        MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()))
            .process(&image)
            .unwrap_or_else(|e| panic!("{name}: the pipeline failed, which is the finding: {e}"));
    let record = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .unwrap_or_else(|| panic!("{name}: no tamper-checks record"));
    let threads = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemorySuspiciousThreads")
        .unwrap_or_else(|| panic!("{name}: no suspicious-threads record"));
    Some((record.metadata.clone(), threads.metadata.clone()))
}

type Records = Option<(Value, Value)>;

static TIGGER: OnceLock<Records> = OnceLock::new();
static BE2: OnceLock<Records> = OnceLock::new();
static ZEUS: OnceLock<Records> = OnceLock::new();
static STUX: OnceLock<Records> = OnceLock::new();
static BOOMER: OnceLock<Records> = OnceLock::new();
static SAMSCLASS_2008: OnceLock<Records> = OnceLock::new();
static M57_VISTA_REC: OnceLock<Records> = OnceLock::new();
static W2K3_X64_REC: OnceLock<Records> = OnceLock::new();
static COREFLOOD: OnceLock<Records> = OnceLock::new();
static LAQMA: OnceLock<Records> = OnceLock::new();
static PROLACO: OnceLock<Records> = OnceLock::new();
static SALITY: OnceLock<Records> = OnceLock::new();
static SILENTBANKER: OnceLock<Records> = OnceLock::new();

#[path = "legacy_xp_oracle/cookbook_volatility.rs"]
mod cookbook_volatility;
use cookbook_volatility::*;

#[path = "legacy_xp_oracle/vista_terry_volatility2.rs"]
mod vista_terry_volatility2;

#[path = "legacy_xp_oracle/w2k3_x64_volatility2.rs"]
mod w2k3_x64_volatility2;

macro_rules! require {
    ($cell:ident, $var:expr, $name:expr) => {
        match $cell.get_or_init(|| tamper_record($var, $name)).as_ref() {
            Some((record, _)) => record,
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

fn hex(value: &Value) -> u64 {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is not a hex string"));
    u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("hex")
}

/// What the legacy global table must look like on an XP x86 capture, and the
/// counts Volatility 3 agrees with.
fn assert_legacy_timers(name: &str, record: &Value, rows: usize, with_dpc: u64) {
    assert_legacy_timers_bounded_by(name, record, rows, with_dpc, "KiDispatcherReadyListHead");
}

/// As [`assert_legacy_timers`], with the declared symbol that bounds the
/// derived extent named: `KiDispatcherReadyListHead` on XP, `KiBiosFrame` on
/// Server 2003 RTM.
fn assert_legacy_timers_bounded_by(
    name: &str,
    record: &Value,
    rows: usize,
    with_dpc: u64,
    bound: &str,
) {
    let status = group(record, "timers");
    assert_eq!(
        status["ran"],
        serde_json::json!(true),
        "{name}: the legacy timer table must be walked on XP: {}",
        status["detail"]
    );
    let timers = &record["timers"];
    let layout = &timers["layout"];
    assert_eq!(layout["shape"], "legacy_global", "{name}");
    assert_eq!(
        layout["entry"], "bare_list_entry",
        "{name}: XP declares no `_KTIMER_TABLE_ENTRY`; each bucket is a `_LIST_ENTRY`"
    );
    assert_eq!(
        layout["entry_size"].as_u64(),
        Some(8),
        "{name}: an x86 `_LIST_ENTRY`"
    );
    // **The derived extent, graded.** Volatility 3 uses 256 for XP x86 as a
    // constant; here it is derived, and on real bytes the heads-only probe ran
    // on through `KiDispatcherReadyListHead`'s 32 heads to 288 until the next
    // declared symbol bounded it.
    assert_eq!(
        timers["buckets_walked"].as_u64(),
        Some(256),
        "{name}: the derived bucket count"
    );
    let note = timers["notes"]
        .as_array()
        .and_then(|n| {
            n.iter()
                .find_map(|n| n.as_str().filter(|s| s.contains("DERIVED")))
        })
        .unwrap_or_else(|| panic!("{name}: the derivation is stated"));
    assert!(
        note.contains(bound) && note.contains("2048 byte(s)"),
        "{name}: the bound is named: {note}"
    );
    assert!(
        !timers["notes"].as_array().expect("notes").iter().any(|n| n
            .as_str()
            .unwrap_or_default()
            .contains("rather than at their head")),
        "{name}: every bucket list closed at its head: {:?}",
        timers["notes"]
    );
    assert_eq!(
        timers["timers_reported"].as_u64(),
        Some(rows as u64),
        "{name}: timers read"
    );
    // `MEM-055`, measured 2026-09-26: every XP bucket list closes at its own
    // head, so no timer is reached twice and the sightings equal the timers.
    assert_eq!(
        timers["rows_walked"].as_u64(),
        Some(rows as u64),
        "{name}: no timer reached from two lists"
    );
    assert_eq!(timers["timers_reached_more_than_once"].as_u64(), Some(0));
    assert_eq!(
        timers["timers_with_a_dpc"].as_u64(),
        Some(with_dpc),
        "{name}: timers carrying a DPC -- Volatility 3's `windows.timers` row count"
    );
    assert_eq!(
        timers["routines_outside_any_module"].as_u64(),
        Some(0),
        "{name}: no DPC routine outside a loaded module"
    );
    for row in timers["timers"].as_array().expect("rows") {
        assert!(
            row["bucket"].as_u64().unwrap_or(u64::MAX) < 256,
            "{name}: {row}"
        );
        assert!(
            row["processor"].is_null(),
            "the legacy table is not per-processor"
        );
        if let Some(routine) = row["deferred_routine"].as_str() {
            let value = u64::from_str_radix(routine.trim_start_matches("0x"), 16).unwrap_or(0);
            assert!(
                (0x8000_0000..=0xFFFF_FFFF).contains(&value),
                "{name}: a DPC routine outside x86 kernel space means the offsets are wrong: {row}"
            );
        }
    }
}

/// Find a timer row by its `_KTIMER` address.
fn timer_row(record: &Value, address: u64) -> &Value {
    record["timers"]["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| hex(&r["timer_address"]) == address)
        .unwrap_or_else(|| panic!("no timer at {address:#x}"))
}

fn unloaded_names(record: &Value) -> Vec<String> {
    record["unloaded_modules"]["drivers"]
        .as_array()
        .expect("drivers")
        .iter()
        .map(|d| d["driver_name"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn orphans(record: &Value) -> &Vec<Value> {
    record["threads"]["orphan_kernel_threads"]
        .as_array()
        .expect("orphan rows")
}

/// **The published answer: Tigger's orphan kernel thread, reproduced.**
///
/// Ligh's `threads -F OrphanThread` prints Pid 4, Tid 1648, `_ETHREAD`
/// 0xff1f92b0, StartAddress 0xf2edd150. Volatility 3's
/// `windows.orphan_kernel_threads` prints that thread and two more from the
/// same pool region (Tid 1720 at 0xf2edc54e, Tid 1992 at 0xf2edba46). Séance
/// publishes exactly those three rows.
///
/// **They are observations, not graded findings**, and that is the bound this
/// build imposes rather than a miss: XP declares no
/// `_ETHREAD.StartAddressInvalid`, so one of the four exclusions cannot be
/// assessed and the group grades nothing on this build, by design.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn tiggers_orphan_kernel_thread_is_published_with_the_answer_ligh_printed() {
    let record = require!(TIGGER, COOKBOOK, "tigger.vmem");
    assert_eq!(group(record, "orphan_kernel_threads")["ran"], true);
    let rows = orphans(record);
    let mut tids: Vec<u64> = rows
        .iter()
        .map(|o| o["tid"].as_u64().unwrap_or(0))
        .collect();
    tids.sort_unstable();
    assert_eq!(
        tids,
        [1648, 1720, 1992],
        "Volatility 3 prints exactly these three"
    );

    let published = rows
        .iter()
        .find(|o| o["tid"] == 1648)
        .expect("the published thread");
    assert_eq!(published["pid"], 4);
    assert_eq!(published["process_name"], "System");
    assert_eq!(hex(&published["thread_address"]), 0xff1f_92b0);
    assert_eq!(hex(&published["start_address"]), 0xf2ed_d150);
    assert_eq!(
        published["start_address_ownership"]["kind"],
        "outside_any_module"
    );
    let exclusions = &published["exclusions"];
    for satisfied in [
        "is_kernel_thread",
        "not_terminated",
        "not_in_an_unloaded_range",
    ] {
        assert_eq!(
            exclusions[satisfied]["state"], "satisfied",
            "{satisfied}: {exclusions}"
        );
    }
    assert_eq!(
        exclusions["start_address_valid"]["state"], "not_assessed",
        "XP declares no `_ETHREAD.StartAddressInvalid`"
    );
    assert_eq!(published["is_graded_finding"], false);
    assert_eq!(record["threads"]["orphan_graded"], 0);
    assert_eq!(record["threads"]["orphan_observations"], 3);

    for (tid, start) in [(1720u64, 0xf2ed_c54eu64), (1992, 0xf2ed_ba46)] {
        let row = rows.iter().find(|o| o["tid"] == tid).expect("row");
        assert_eq!(hex(&row["start_address"]), start, "tid {tid}");
    }
}

/// The legacy timer table on `tigger.vmem`: 256 buckets, 233 timers, and the
/// 60 carrying a DPC are exactly Volatility 3's 60 rows — same `_KTIMER`
/// addresses, same routines, same periods.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn tiggers_legacy_timer_table_agrees_with_volatility() {
    let record = require!(TIGGER, COOKBOOK, "tigger.vmem");
    assert_legacy_timers("tigger.vmem", record, 233, 60);
    // Spot values from `windows.timers`: the netbt timer, and a periodic one.
    let netbt = timer_row(record, 0x80ff_0d58);
    assert_eq!(hex(&netbt["deferred_routine"]), 0xf3b8_148a);
    assert_eq!(netbt["routine_ownership"]["module"], "netbt.sys");
    let expired = timer_row(record, 0xff26_6390);
    assert_eq!(
        hex(&expired["deferred_routine"]),
        0x8053_4016,
        "ExpTimerDpcRoutine"
    );
    // Period is declared `long` on this build; 12 of the 60 are periodic.
    let periodic = record["timers"]["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["deferred_routine"].is_string() && r["period_ms"].as_u64().unwrap_or(0) > 0)
        .count();
    assert_eq!(
        periodic, 12,
        "Volatility 3 prints 12 DPC timers with a non-zero period"
    );
}

/// The unloaded-driver table on `tigger.vmem`: ten records, the same names and
/// ranges Volatility 3's `windows.unloadedmodules` prints, in slot order.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn tiggers_unloaded_drivers_agree_with_volatility() {
    let record = require!(TIGGER, COOKBOOK, "tigger.vmem");
    assert_eq!(
        unloaded_names(record),
        [
            "Sfloppy.SYS",
            "Cdaudio.SYS",
            "vmdebug.sys",
            "splitter.sys",
            "aec.sys",
            "swmidi.sys",
            "DMusic.sys",
            "kmixer.sys",
            "drmkaud.sys",
            "kmixer.sys"
        ]
    );
    let last = &record["unloaded_modules"]["drivers"][9];
    assert_eq!(hex(&last["start_address"]), 0xf2fe_0000);
    assert_eq!(hex(&last["end_address"]), 0xf300_a000);
}

/// **The debug-register group on XP reads the thread's own flag and four-byte
/// registers** (both fixed 2026-09-24 on this image), and what it then finds
/// is recorded as measured.
///
/// One `winlogon.exe` thread (Tid 636) carries `_KTHREAD.DebugActive` = 0x8f
/// with `Dr7` = 0x555 (L0-L3 enabled) and `Dr0`-`Dr3` = 1, 2, 1, 0xa — every
/// address in the null page, which no code executes from. The same shape is on
/// all four XP captures here, malware or not. Volatility 3 prints nothing for
/// it because its plugin keeps only addresses that land in a file-backed VAD.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn tiggers_winlogon_debug_registers_are_read_at_four_bytes_under_the_threads_flag() {
    let record = require!(TIGGER, COOKBOOK, "tigger.vmem");
    let threads = &record["threads"];
    assert_eq!(threads["symbols"]["debug_active_path"], "Tcb.DebugActive");
    let rows = threads["debug_register_threads"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["process_name"], "winlogon.exe");
    assert_eq!(row["tid"], 636);
    assert_eq!(row["debug_active"], 0x8f);
    let dr: Vec<u64> = row["dr"].as_array().expect("dr").iter().map(hex).collect();
    assert_eq!(dr, [1, 2, 1, 0xa], "each register is its own four bytes");
    assert_eq!(hex(&row["dr7"]), 0x555);
    assert_eq!(hex(&row["dr6"]), 0xffff_0ff0);
    // MEM-050, decided 2026-09-24: every armed address is in the null page, so
    // the row is published and not graded.
    assert_eq!(row["armed_slots"], 4);
    assert_eq!(row["armed_only_in_the_null_page"], true);
    assert_eq!(row["has_breakpoint"], false);
    assert!(row["not_graded_reason"]
        .as_str()
        .is_some_and(|r| r.contains("MM_LOWEST_USER_ADDRESS")));
    assert_eq!(threads["threads_with_a_breakpoint"], 0);
}

/// **No XP capture grades a breakpoint** (`MEM-050`): each carries the one
/// null-page `winlogon.exe` row, published and not graded.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn no_xp_capture_grades_the_null_page_winlogon_breakpoint() {
    for (cell, var, name) in [
        (&BE2, COOKBOOK, "be2.vmem"),
        (&ZEUS, COOKBOOK, "zeus.vmem"),
        (&STUX, STUXNET, "stuxnet.vmem"),
    ] {
        let Some((record, _)) = cell.get_or_init(|| tamper_record(var, name)).as_ref() else {
            continue;
        };
        let threads = &record["threads"];
        let rows = threads["debug_register_threads"].as_array().expect("rows");
        assert_eq!(rows.len(), 1, "{name}");
        assert_eq!(rows[0]["process_name"], "winlogon.exe", "{name}");
        assert_eq!(rows[0]["armed_only_in_the_null_page"], true, "{name}");
        assert_eq!(threads["threads_with_a_breakpoint"], 0, "{name}");
    }
}

/// `be2.vmem` (BlackEnergy 2): the legacy timer table agrees with Volatility 3,
/// and no orphan thread is published — Volatility 3 prints none either. Its
/// published answer is SSDT hooks, which are not one of these groups.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn be2_timers_agree_with_volatility_and_it_has_no_orphan_thread() {
    let record = require!(BE2, COOKBOOK, "be2.vmem");
    assert_legacy_timers("be2.vmem", record, 227, 60);
    assert!(orphans(record).is_empty(), "{:?}", orphans(record));
    assert_eq!(unloaded_names(record).len(), 9);
}

/// `zeus.vmem`: the same build, a third count of the same table. The 64
/// timers carrying a DPC are Volatility 3's 64 rows, same routines and periods,
/// and neither tool prints an orphan thread.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn zeus_legacy_timer_table_is_walked() {
    let record = require!(ZEUS, COOKBOOK, "zeus.vmem");
    assert_legacy_timers("zeus.vmem", record, 242, 64);
    assert!(orphans(record).is_empty());
}

/// `stuxnet.vmem`, XP SP3: a second build of the legacy shape. 256 buckets,
/// 176 timers, 58 with a DPC — Volatility 3's 58 rows, same routines and
/// periods — and no orphan thread (Volatility 3: none). Sixteen unloaded
/// drivers, as Volatility 3 prints.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn stuxnets_legacy_timer_table_agrees_with_volatility() {
    let record = require!(STUX, STUXNET, "stuxnet.vmem");
    assert_legacy_timers("stuxnet.vmem", record, 176, 58);
    assert!(orphans(record).is_empty());
    assert_eq!(unloaded_names(record).len(), 16);
    let periodic = timer_row(record, 0x8055_16d0);
    assert_eq!(hex(&periodic["deferred_routine"]), 0x804f_3eae);
    assert_eq!(periodic["period_ms"], 60_000);
}

/// Suspicious-thread evidence on each XP capture (MEM-024), as `(cell, corpus
/// variable, file, evidence count)`, measured 2026-09-27.
///
/// These are rootkit-era captures, and no published answer names a user
/// thread starting in injected memory on any of them (the writeups name kernel
/// orphan threads only), so the counts are **observed** and compared with
/// Volatility 3.2.28.2's `windows.malware.suspicious_threads` on the same
/// files -- not graded against ground truth.
///
/// Every Séance finding is a Volatility row, all of them a Win32StartAddress
/// in a private PAGE_EXECUTE_READWRITE range: be2 1 (svchost 856), zeus 10
/// (winlogon 632 x2, svchost 856 x8), stuxnet 9 (services 668, svchost 940
/// x2, lsass 868 x2, lsass 1928 x4). Volatility prints more rows (be2 4, zeus
/// 13, stuxnet 25 distinct), and every extra one is either a Win32StartAddress
/// of 0 or a small integer (0x66ae, 0x685f, 0x35178 ...) landing in a
/// read-write range at the bottom of the address space. On XP that field is a
/// union with `LpcReceivedMessageId`, and each of those threads has
/// `LpcReceivedMsgIdValid` set: they are LPC message ids, not addresses, and
/// Séance does not judge them.
const XP_SUSPICIOUS_THREAD_EVIDENCE: [(&OnceLock<Records>, &str, &str, u64); 3] = [
    (&BE2, COOKBOOK, "be2.vmem", 1),
    (&ZEUS, COOKBOOK, "zeus.vmem", 10),
    (&STUX, STUXNET, "stuxnet.vmem", 9),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_runs_on_every_xp_capture() {
    for (cell, var, name, expected) in XP_SUSPICIOUS_THREAD_EVIDENCE {
        let Some((_, m)) = cell.get_or_init(|| tamper_record(var, name)).as_ref() else {
            continue;
        };
        let mut rows = Vec::new();
        for process in m["processes"].as_array().into_iter().flatten() {
            if process["starts_outside_the_tree"].as_u64().unwrap_or(0) > 0 {
                for note in process["notes"].as_array().into_iter().flatten().take(2) {
                    eprintln!(
                        "  {} {}: {note}",
                        process["pid"], process["image_file_name"]
                    );
                }
            }
            for finding in process["findings"].as_array().into_iter().flatten() {
                let kinds: Vec<&str> = finding["suspicions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s["kind"].as_str())
                    .collect();
                rows.push(format!(
                    "{} {} tid {} {} {:#x} -> {:?} evidence {}",
                    process["pid"],
                    process["image_file_name"],
                    finding["tid"],
                    finding["which"],
                    finding["address"].as_u64().unwrap_or(0),
                    kinds,
                    finding["evidence"]
                ));
            }
        }
        eprintln!(
            "{name}: {} judged ({} analysed), {} out of scope, {} skipped, {} starts tested, \
             evidence {} {}, gaps {}, outside {}, kernel {}, kernel on threads not known as \
             system {}, lpc ids {}, complete {}\n  {}",
            m["processes_judged"],
            m["processes_analysed"],
            m["out_of_scope_total"],
            m["skipped_total"],
            m["starts_tested"],
            m["evidence_count"],
            m["evidence_by_kind"],
            m["gap_count"],
            m["starts_outside_the_tree"],
            m["starts_in_kernel_space"],
            m["kernel_starts_on_threads_not_known_as_system"],
            m["win32_starts_holding_an_lpc_message_id"],
            m["complete"],
            rows.join("\n  ")
        );
        assert_eq!(m["stage_ran"], true, "{name}");
        assert_eq!(m["protections_available"], true, "{name}");
        assert!(
            m["processes_analysed"].as_u64().unwrap_or(0) > 10,
            "{name}: an XP desktop has more than ten user processes"
        );
        assert_eq!(
            m["evidence_count"].as_u64(),
            Some(expected),
            "{name}: {rows:#?}"
        );
        // Measured 2026-09-27: no kernel-mode start on any of the three, so
        // nothing here is set aside for want of a SystemThread bit.
        assert_eq!(
            m["kernel_starts_on_threads_not_known_as_system"].as_u64(),
            Some(0),
            "{name}"
        );
    }
}

/// Volatility 3.2.28.2 `windows.timers` on `boomer-win2003-2006-03-17.img`,
/// run 2026-09-27 against the extracted symbol pack: every row as
/// `(_KTIMER address, DPC routine, period in ms)`. Copied from its CSV output;
/// nothing here came from Séance.
const BOOMER_VOLATILITY_TIMERS: &[(u64, u64, u64)] = &[
    (0x80582ec0, 0x8055ca80, 0),     // ntoskrnl ExpTimeRefreshDpcRoutine
    (0x80578dc0, 0x804f1660, 1000),  // ntoskrnl IopTimerDispatch
    (0xf6e7cbf0, 0xf6e333d0, 100),   // tcpip -
    (0xf6e7cc48, 0xf6e333d0, 100),   // tcpip -
    (0xf6db3ba0, 0xf6dabd64, 0),     // rdbss -
    (0x80578c90, 0x804f3b70, 60000), // ntoskrnl IopIrpStackProfilerTimer
    (0x8607c6c0, 0xf711c124, 0),     // USBPORT -
    (0x85eef858, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x860716c0, 0xf711c124, 0),     // USBPORT -
    (0x8603b460, 0xf71dd4d0, 60000), // NDIS -
    (0x860666c0, 0xf711c124, 0),     // USBPORT -
    (0x8057b520, 0x80510dc0, 0),     // ntoskrnl MiModifiedPageWriterTimerDispatch
    (0x8605b6c0, 0xf711c124, 0),     // USBPORT -
    (0x86042a10, 0xf7518242, 10000), // watchdog -
    (0x85f70828, 0xf7518242, 10000), // watchdog -
    (0x85efc568, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x85ea8a98, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x85f3e188, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x85fee558, 0xf7598054, 0),     // TDI _imp__HalHandleNMI
    (0x80577a08, 0x804f25f0, 0),     // ntoskrnl CcScanDpc
    (0x80581080, 0x804f17d0, 1000),  // ntoskrnl PopScanIdleList
    (0xf7222650, 0xf7202740, 0),     // Ntfs -
    (0x805785a0, 0x804f81b0, 0),     // ntoskrnl CmpLazyFlushDpcRoutine
    (0x85f40b30, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf790ad78, 0x804ef630, 1000),  // ntoskrnl KiScanReadyQueues
    (0xf6ea8720, 0xf6e98130, 60000), // ipsec -
    (0xf6ea8288, 0xf6e98260, 0),     // ipsec -
    (0xf6ea82f0, 0xf6e98260, 0),     // ipsec -
    (0x85f4b300, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0xf6e788b0, 0xf7598054, 0),     // TDI _imp__HalHandleNMI
    (0x80570288, 0x804f82e0, 60000), // ntoskrnl WmipPollingDpcRoutine
    (0x85ed7bd8, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x85ea7c58, 0xf62b8970, 0),     // srv -
    (0x85ea7e98, 0xf62b8970, 0),     // srv -
    (0x85f0efa8, 0xf65bf0c0, 30000), // afd -
    (0x85f48020, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
    (0x80582fc0, 0x8055cab0, 0),     // ntoskrnl ExpTimeZoneDpcRoutine
    (0x80582f40, 0x8055cae0, 0),     // ntoskrnl ExpCenturyDpcRoutine
    (0x805817c0, 0x804ed600, 0),     // ntoskrnl PspJobTimeLimitsDpcRoutine
    (0xf62caa38, 0xf62b8db0, 0),     // srv -
    (0x861a9938, 0xf73b143a, 0),     // volsnap -
    (0xf72226b0, 0xf7201590, 0),     // Ntfs -
    (0x85f358e0, 0x804f3870, 0),     // ntoskrnl ExpTimerDpcRoutine
];

/// **Server 2003 RTM, the NIST CFReDS "boomer" capture** (`MEM-021`): a
/// third build of the legacy global table, and the first outside XP. Its ISF
/// (3790.srv03_rtm) declares no `_KTIMER_TABLE_ENTRY`, so it is still the bare
/// `_LIST_ENTRY` form; the derived extent is 256 buckets, bounded by
/// `KiBiosFrame` +2,048 bytes above the table. A clean capture ("not engaged
/// in any malicious or even network based activity"), so no DPC routine should
/// fall outside a loaded module. This is real evidence graded against
/// Volatility 3; it does **not** cover the declared-entry form (Server 2003
/// SP1+, Vista, XP x64), which no capture on this host with symbols holds.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_server_2003_rtm_legacy_table_matches_volatility() {
    let record = require!(BOOMER, NIST_BASIC, "boomer-win2003-2006-03-17.img");
    assert_eq!(
        BOOMER_VOLATILITY_TIMERS.len(),
        43,
        "Volatility 3 printed 43 rows (VALIDATION.md, MEM-XP-1)"
    );
    let with_dpc = BOOMER_VOLATILITY_TIMERS.len() as u64;
    assert_legacy_timers_bounded_by(
        "boomer-win2003-2006-03-17.img",
        record,
        156,
        with_dpc,
        "KiBiosFrame",
    );
    let mut ours: Vec<(u64, u64, u64)> = record["timers"]["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["deferred_routine"].is_string())
        .map(|r| {
            (
                hex(&r["timer_address"]),
                hex(&r["deferred_routine"]),
                r["period_ms"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    ours.sort_unstable();
    let mut theirs = BOOMER_VOLATILITY_TIMERS.to_vec();
    theirs.sort_unstable();
    assert_eq!(
        ours, theirs,
        "the same _KTIMER set, routines and periods as Volatility 3"
    );
}

/// Volatility 3.2.28.2 `windows.timers` on the Samsclass Server 2008 SP1 x86
/// PAE capture (`memdump.mem`), run 2026-09-27 against the extracted symbol
/// pack: every row as `(_KTIMER address, DPC routine, period in ms)`. Copied
/// by hand from `vol3/windows.timers.txt`; nothing here came from Seance.
/// DPC timers reachable only from buckets 256..511, measured 2026-10-20.
const UPPER_ONLY: usize = 41;

const SAMSCLASS_VOLATILITY_TIMERS: &[(u64, u64, u64)] = &[
    (0x8196eb10, 0x818684fb, 60000), // IopIrpStackProfilerTimer
    (0x8193c500, 0x8191f417, 0),     // ExpCenturyDpcRoutine
    (0x929a9680, 0x92985187, 0),     // HTTP
    (0x836884a8, 0x81ecb2f1, 0),     // NDIS
    (0x836ad158, 0x81ecb2f1, 0),     // NDIS
    (0x836aa158, 0x81ecb2f1, 0),     // NDIS
    (0x836ab158, 0x81ecb2f1, 0),     // NDIS
    (0x83fb8200, 0x88cca005, 0),     // netbt
    (0x8193c400, 0x8191f3b7, 0),     // ExpTimeRefreshDpcRoutine
    (0x8196f560, 0x818fcd8f, 0),     // CmpPeriodicBackupFlushDpcRoutine
    (0x8193c480, 0x8191f447, 0),     // ExpNextYearDpcRoutine
    (0x929a6cc0, 0x929857a7, 30000), // HTTP
    (0x85a443a0, 0x85a10723, 0),     // Ntfs
    (0x83f5ed30, 0x88c822da, 30000), // afd
];

/// **Server 2008 SP1 x86 PAE, the Samsclass capture** (`MEM-021`): the first
/// real read of the declared `_KTIMER_TABLE_ENTRY` form. Its ISF declares
/// `_KTIMER_TABLE_ENTRY`, `KiTimerTableListHead` and `KiTimerTableSize` and
/// has no `_KPRCB.TimerTable`, so the table is the legacy global one with a
/// 16-byte declared entry. A clean lab VM capture. Graded against Volatility
/// 3, a second implementation and not ground truth.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_server_2008_declared_entry_legacy_table_matches_volatility() {
    let record = require!(SAMSCLASS_2008, SAMSCLASS, "memdump.mem");
    let name = "memdump.mem";
    let status = group(record, "timers");
    assert_eq!(
        status["ran"],
        serde_json::json!(true),
        "{name}: the declared-entry table must be walked: {}",
        status["detail"]
    );
    let timers = &record["timers"];
    let layout = &timers["layout"];
    assert_eq!(layout["shape"], "legacy_global", "{name}");
    assert_eq!(
        layout["entry"], "declared_ktimer_table_entry",
        "{name}: this ISF declares `_KTIMER_TABLE_ENTRY`, so each bucket is that struct"
    );
    assert_eq!(
        layout["entry_size"].as_u64(),
        Some(16),
        "{name}: `_KTIMER_TABLE_ENTRY` is {{Entry, Time}} = 16 bytes in this ISF"
    );
    // **The derived extent, graded against the kernel's own value.** The
    // image's `KiTimerTableSize` (RVA 0x137b30 in ntkrpamp.pdb
    // 37D328E3BAE5460F8E662756ED80951D-2, read from physical 0x01971b30 with
    // a one-off script on 2026-10-20) holds 0x200. Séance derives the count
    // from the bytes and the next declared symbol and must land on it.
    assert_eq!(
        timers["buckets_walked"].as_u64(),
        Some(512),
        "{name}: the derived bucket count must equal the kernel's KiTimerTableSize"
    );
    let notes = timers["notes"].to_string();
    assert!(
        notes.contains("AlpcpNPLookasides"),
        "{name}: the extent note names the bounding symbol: {notes}"
    );
    // Measured, not graded: Séance's own counts, pinned against regression.
    // 171 since `MEM-059` (2026-10-22), 173 before: two list items in torn bucket 346 (dispatcher
    // header types 0x1 and 0x8d) are no timers and are skipped, as Volatility skips them.
    assert_eq!(timers["timers_reported"].as_u64(), Some(171), "{name}");
    assert_eq!(timers["items_not_timers"].as_u64(), Some(2), "{name}");
    assert_eq!(timers["rows_walked"].as_u64(), Some(190), "{name}");
    assert_eq!(timers["timers_with_a_dpc"].as_u64(), Some(55), "{name}");
    assert_eq!(
        timers["timers_reached_more_than_once"].as_u64(),
        Some(17),
        "{name}: pinned; each carries its own reached_from"
    );
    assert_eq!(
        timers["routines_outside_any_module"].as_u64(),
        Some(0),
        "{name}: a clean capture; every DPC routine is in a loaded module"
    );
    // **Where Volatility 3 and Séance differ, and why.** Volatility 3
    // (windows/timers.py) walks `KiTimerTableListHead` on Vista as an array of
    // 512 `_LIST_ENTRY` (8 bytes each), but each element is a 16-byte
    // `_KTIMER_TABLE_ENTRY`, so it reads only the first 256 buckets. The
    // kernel's own `KiTimerTableSize` is 512. The two agree exactly on the
    // timers reachable from buckets 0..255; the rest are Séance's alone and
    // are pinned, with every routine in a module, not graded.
    let rows: Vec<(u64, u64, u64, u64)> = timers["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["deferred_routine"].is_string())
        .map(|r| {
            let lowest = r["reached_from"]
                .as_array()
                .expect("reached_from")
                .iter()
                .filter_map(|p| p["bucket"].as_u64())
                .min()
                .expect("a timer is reached from some bucket");
            (
                hex(&r["timer_address"]),
                hex(&r["deferred_routine"]),
                r["period_ms"].as_u64().unwrap_or(0),
                lowest,
            )
        })
        .collect();
    let mut ours: Vec<(u64, u64, u64)> = rows
        .iter()
        .filter(|r| r.3 < 256)
        .map(|r| (r.0, r.1, r.2))
        .collect();
    ours.sort_unstable();
    let mut theirs = SAMSCLASS_VOLATILITY_TIMERS.to_vec();
    theirs.sort_unstable();
    assert_eq!(
        ours, theirs,
        "the same _KTIMER set, routines and periods as Volatility 3 over buckets 0..255"
    );
    assert_eq!(
        rows.iter().filter(|r| r.3 >= 256).count(),
        UPPER_ONLY,
        "{name}: DPC timers reachable only from buckets 256..511 (pinned, ungraded)"
    );
}

/// The five Cookbook captures graded on 2026-09-27 (`MEM-020`, VALIDATION.md
/// MEM-XP-3), as `(cell, file, Volatility 3 timer rows, Volatility 3
/// unloaded-driver rows, timers Séance reads from the table)`.
///
/// The oracle tables are Volatility 3's output (`legacy_xp_oracle/`); the
/// last column is Séance's own count of every `_KTIMER` on the table, DPC or
/// not, which Volatility does not print (it drops a timer with no DPC), so it
/// is a measurement pinned against regression, not an independent answer.
///
/// **No published answer ties any of these five to these groups**
/// (`~/forensic_corpora/malware_cookbook_mem/PROVENANCE.md`): they are the
/// book's user-mode recipes. Every agreement below is agreement with
/// Volatility, and absence is absence on this evidence, not a true negative.
type CookbookCase = (
    &'static OnceLock<Records>,
    &'static str,
    &'static [(u64, u64, i64)],
    &'static [(&'static str, u64, u64)],
    usize,
);
const FIVE_COOKBOOK_CAPTURES: [CookbookCase; 5] = [
    (
        &COREFLOOD,
        "coreflood.vmem",
        COREFLOOD_VOLATILITY_TIMERS,
        COREFLOOD_VOLATILITY_UNLOADED,
        176,
    ),
    (
        &LAQMA,
        "laqma.vmem",
        LAQMA_VOLATILITY_TIMERS,
        LAQMA_VOLATILITY_UNLOADED,
        190,
    ),
    (
        &PROLACO,
        "prolaco.vmem",
        PROLACO_VOLATILITY_TIMERS,
        PROLACO_VOLATILITY_UNLOADED,
        140,
    ),
    (
        &SALITY,
        "sality.vmem",
        SALITY_VOLATILITY_TIMERS,
        SALITY_VOLATILITY_UNLOADED,
        242,
    ),
    (
        &SILENTBANKER,
        "silentbanker.vmem",
        SILENTBANKER_VOLATILITY_TIMERS,
        SILENTBANKER_VOLATILITY_UNLOADED,
        175,
    ),
];

/// Séance's DPC-carrying timers as `(_KTIMER, routine, period)`, sorted.
fn dpc_timers(record: &Value) -> Vec<(u64, u64, i64)> {
    let mut ours: Vec<(u64, u64, i64)> = record["timers"]["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["deferred_routine"].is_string())
        .map(|r| {
            (
                hex(&r["timer_address"]),
                hex(&r["deferred_routine"]),
                r["period_ms"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    ours.sort_unstable();
    ours
}

/// **The legacy timer table on four of the five ungraded Cookbook captures**
/// agrees with Volatility 3's `windows.timers`, row for row: the same
/// `_KTIMER` addresses, DPC routines and periods, 256 buckets, and no routine
/// outside a module. `prolaco.vmem` is graded on its own, below.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn coreflood_laqma_sality_silentbanker_timers_agree_with_volatility() {
    for (cell, name, oracle, _, rows) in FIVE_COOKBOOK_CAPTURES {
        if name == "prolaco.vmem" {
            continue;
        }
        let Some((record, _)) = cell.get_or_init(|| tamper_record(COOKBOOK, name)).as_ref() else {
            continue;
        };
        let mut theirs = oracle.to_vec();
        theirs.sort_unstable();
        assert_eq!(
            dpc_timers(record),
            theirs,
            "{name}: the same rows as Volatility 3"
        );
        assert_legacy_timers(name, record, rows, oracle.len() as u64);
    }
}

/// **`prolaco.vmem` is a torn capture, and the table is still walked whole**
/// (`MEM-058`, found here 2026-09-27, red first in `tamper_timers_tests.rs`).
///
/// Twelve of its 256 bucket heads have a first link whose `Blink` names a
/// different bucket -- the kernel was relinking timers as the image was taken.
/// Before the fix the extent probe read bucket 37's torn head as the end of
/// the table: 37 buckets, 7 of the 50 real DPC timers reached, and
/// bucket 68's head published as a timer with a routine "outside any module"
/// -- a false signal. Now: 256 buckets, the twelve torn heads named, and
/// Séance's 50 DPC timers are Volatility's rows less two things Volatility
/// gets wrong on this image: four timers it prints twice (reached from two
/// joined bucket lists) and one row at 0x80552408, which is bucket 68's
/// `_LIST_ENTRY` head at 0x80552420 read as a `_KTIMER`'s `TimerListEntry`
/// (its "DueTime" is the head's own two self-pointers).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn prolacos_torn_timer_table_is_walked_whole_and_agrees_with_volatilitys_distinct_timers() {
    let record = require!(PROLACO, COOKBOOK, "prolaco.vmem");
    let timers = &record["timers"];
    assert_eq!(timers["buckets_walked"].as_u64(), Some(256));
    let notes: Vec<&str> = timers["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let torn = notes
        .iter()
        .find(|n| n.contains("bucket head(s) inside the table are torn"))
        .unwrap_or_else(|| panic!("the torn heads are named: {notes:?}"));
    for bucket in [37, 70, 99, 101, 199, 201, 202, 204, 209, 211, 224, 252] {
        assert!(torn.contains(&format!("bucket {bucket}")), "{torn}");
    }
    assert!(torn.starts_with("12 bucket head(s)"), "{torn}");
    assert_eq!(timers["timers_reported"].as_u64(), Some(140));
    assert_eq!(
        timers["rows_walked"].as_u64(),
        Some(148),
        "joined bucket lists reach some timers twice"
    );
    assert_eq!(timers["timers_reached_more_than_once"].as_u64(), Some(7));
    assert_eq!(timers["timers_with_a_dpc"].as_u64(), Some(50));
    assert_eq!(
        timers["routines_outside_any_module"].as_u64(),
        Some(0),
        "no bucket head published as a timer"
    );

    const BUCKET_68_HEAD_AS_A_TIMER: u64 = 0x8055_2408;
    let mut theirs: Vec<(u64, u64, i64)> = PROLACO_VOLATILITY_TIMERS
        .iter()
        .copied()
        .filter(|(timer, _, _)| *timer != BUCKET_68_HEAD_AS_A_TIMER)
        .collect();
    assert_eq!(PROLACO_VOLATILITY_TIMERS.len() - theirs.len(), 1);
    theirs.sort_unstable();
    let printed = theirs.len();
    theirs.dedup();
    assert_eq!(
        printed - theirs.len(),
        4,
        "Volatility prints four timers twice"
    );
    assert_eq!(dpc_timers(record), theirs);
}

/// **The unloaded-driver table on the five captures**: the same names and
/// ranges Volatility 3's `windows.unloadedmodules` prints, in slot order.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn coreflood_laqma_prolaco_sality_silentbanker_unloaded_drivers_agree_with_volatility() {
    for (cell, name, _, oracle, _) in FIVE_COOKBOOK_CAPTURES {
        let Some((record, _)) = cell.get_or_init(|| tamper_record(COOKBOOK, name)).as_ref() else {
            continue;
        };
        let ours: Vec<(String, u64, u64)> = record["unloaded_modules"]["drivers"]
            .as_array()
            .expect("drivers")
            .iter()
            .map(|d| {
                (
                    d["driver_name"].as_str().unwrap_or_default().to_string(),
                    hex(&d["start_address"]),
                    hex(&d["end_address"]),
                )
            })
            .collect();
        let theirs: Vec<(String, u64, u64)> = oracle
            .iter()
            .map(|(n, s, e)| ((*n).to_string(), *s, *e))
            .collect();
        assert_eq!(ours, theirs, "{name}: Volatility 3's rows, in slot order");
    }
}

/// **Neither tool finds an orphan kernel thread on the five captures**, and
/// no breakpoint is graded under the `MEM-050` null-page rule. Volatility 3
/// prints no row for either plugin on any of them.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn coreflood_laqma_prolaco_sality_silentbanker_orphan_threads_match_volatility() {
    for (cell, name, _, _, _) in FIVE_COOKBOOK_CAPTURES {
        let Some((record, _)) = cell.get_or_init(|| tamper_record(COOKBOOK, name)).as_ref() else {
            continue;
        };
        assert_eq!(
            group(record, "orphan_kernel_threads")["ran"],
            true,
            "{name}"
        );
        assert!(orphans(record).is_empty(), "{name}: {:?}", orphans(record));
        // The same null-page `winlogon.exe` row every XP capture carries,
        // published and not graded (`MEM-050`); Volatility prints none.
        let threads = &record["threads"];
        let rows = threads["debug_register_threads"].as_array().expect("rows");
        assert_eq!(rows.len(), 1, "{name}");
        assert_eq!(rows[0]["process_name"], "winlogon.exe", "{name}");
        assert_eq!(rows[0]["armed_only_in_the_null_page"], true, "{name}");
        assert_eq!(threads["threads_with_a_breakpoint"], 0, "{name}");
        // Measured 2026-09-27: a suspend count of 1 on one `VMUpgradeHelper`
        // thread (coreflood, laqma, silentbanker), a listing and never a
        // finding; ETW and Skeleton Key assess nothing on XP, as on the
        // other four captures.
        let suspended = threads["suspended_threads"].as_array().expect("rows");
        assert!(
            suspended
                .iter()
                .all(|t| t["process_name"] == "VMUpgradeHelper" && t["is_a_finding"] == false),
            "{name}: {suspended:?}"
        );
        assert_eq!(record["etw"]["processes_assessed"], 0, "{name}");
        assert_eq!(record["skeleton_key"]["lsass_examined"], 0, "{name}");
    }
}

/// **A Vista SP2 x86 non-PAE capture the table walk could not reach before** (`MEM-059`, 2026-10-22).
///
/// `terry-2009-11-16.mddramimage` (M57-Patents, Digital Corpora, 535,130,112 bytes of a 512 MiB machine,
/// kernel `ntkrnlmp.pdb` `79682A989AB049B491E4E18B258C7A1C-2`, 6.0.6002.18082) was refused at discovery
/// ("no usable directory table base"): the capture stops 1.7 MiB short of the top of RAM and its real
/// directory names three page tables above its last byte. It was then walked to 353 of its 512 buckets,
/// 56 of them torn, because the extent was derived from the heads and the capture was taken while the
/// system ran. Fixed: a directory with a few tables in unacquired memory is a candidate, the kernel's own
/// `KiTimerTableSize` (512) is the extent, and an item whose dispatcher header is no timer's is skipped.
///
/// **Oracle.** Volatility 2.6.1 `timers`, `VistaSP2x86`: 51 rows. Volatility 3 cannot stack this image.
/// The test requires every one of Volatility's 51 `_KTIMER`s with the same routine and period, and pins
/// Séance's one extra (a timer in a loaded module that Volatility 2 does not print).
#[test]
fn the_vista_capture_declared_entry_table_contains_every_volatility2_timer() {
    let record = require!(M57_VISTA_REC, M57_VISTA, "terry-2009-11-16.mddramimage");
    let name = "terry-2009-11-16.mddramimage";
    let status = group(record, "timers");
    assert_eq!(
        status["ran"],
        serde_json::json!(true),
        "{name}: {}",
        status["detail"]
    );
    let timers = &record["timers"];
    assert_eq!(timers["layout"]["shape"], "legacy_global", "{name}");
    assert_eq!(
        timers["layout"]["entry"], "declared_ktimer_table_entry",
        "{name}"
    );
    assert_eq!(
        timers["buckets_walked"].as_u64(),
        Some(512),
        "{name}: the kernel's own KiTimerTableSize"
    );
    let notes = timers["notes"].to_string();
    assert!(notes.contains("KiTimerTableSize"), "{name}: {notes}");
    assert_eq!(
        timers["routines_outside_any_module"].as_u64(),
        Some(0),
        "{name}: every DPC routine lies in a loaded module"
    );
    let ours: std::collections::BTreeSet<(u64, u64, u64)> = timers["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["deferred_routine"].is_string())
        .map(|r| {
            (
                hex(&r["timer_address"]),
                hex(&r["deferred_routine"]),
                r["period_ms"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let theirs: std::collections::BTreeSet<(u64, u64, u64)> =
        vista_terry_volatility2::VISTA_VOLATILITY2_TIMERS
            .iter()
            .copied()
            .collect();
    assert_eq!(theirs.len(), 51);
    let missing: Vec<_> = theirs
        .difference(&ours)
        .map(|r| format!("{:#x}", r.0))
        .collect();
    assert!(
        missing.is_empty(),
        "{name}: Volatility 2 timers Séance did not reach: {missing:?}"
    );
    let extra: Vec<_> = ours.difference(&theirs).copied().collect();
    assert_eq!(
        extra,
        vec![(0x82f78e68, 0x8577ef1e, 60000)],
        "{name}: pinned, ungraded: a timer in a loaded module Volatility 2 does not print"
    );
    // The torn lists that ran into memory that is no `_KTIMER` (three rows with routines such as
    // 0x24b25548 before the header check) are skipped and counted, not published.
    // Measured, not graded: Séance's own counts, pinned against regression.
    assert_eq!(timers["timers_reported"].as_u64(), Some(188), "{name}: pin");
    assert_eq!(timers["rows_walked"].as_u64(), Some(214), "{name}: pin");
    assert_eq!(
        timers["timers_with_a_dpc"].as_u64(),
        Some(54),
        "{name}: pin"
    );
    assert_eq!(timers["items_not_timers"].as_u64(), Some(17), "{name}: pin");
}

/// `MEM-059`: Windows Server 2003 R2 SP2 **x64** (build 3790, Microsoft's 180-day evaluation, installed under
/// KVM and dumped with QMP; `VALIDATION.md` `MEM-XP-6`). The kernel's PDB (`ntkrnlmp.pdb`, GUID
/// `03185083233249D9BB747EA777B80C98`, age 2) comes from Microsoft's symbol server through `seance
/// fetch-symbols`; point `SEANCE_SYMBOL_DIRS` at it.
///
/// The table is the declared `_KTIMER_TABLE_ENTRY` form (24 bytes, 512 buckets, 256 of them used by the
/// kernel's own size on older builds) and every `_KTIMER.Dpc` is encoded with the boot-random globals.
/// **Oracle:** Volatility 2.6.1's address space walks the same table independently
/// (`scripts/oracle/vol2_legacy_timers.py`; its `timers` plugin cannot find the table on this build): 211 timers,
/// every header of type 8 or 9. The test requires the same 211 `_KTIMER`s in the same buckets with the same
/// periods, and the decoded DPC routines to land in loaded modules.
#[test]
fn the_server_2003_x64_capture_timer_table_equals_the_volatility2_walk() {
    let record = require!(W2K3_X64_REC, W2K3_X64, "mem.raw");
    let name = "w2k3 r2 sp2 x64";
    let status = group(record, "timers");
    assert_eq!(
        status["ran"],
        serde_json::json!(true),
        "{name}: {}",
        status["detail"]
    );
    let timers = &record["timers"];
    assert_eq!(timers["layout"]["shape"], "legacy_global", "{name}");
    assert_eq!(
        timers["layout"]["entry"], "declared_ktimer_table_entry",
        "{name}"
    );
    assert_eq!(timers["buckets_walked"].as_u64(), Some(512), "{name}");
    assert_eq!(timers["dpc_encoding"]["state"], "decoded", "{name}");
    assert_eq!(
        timers["routines_outside_any_module"].as_u64(),
        Some(0),
        "{name}"
    );
    let ours: std::collections::BTreeSet<(u64, u64, u64)> = timers["timers"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                hex(&r["timer_address"]),
                r["bucket"].as_u64().expect("bucket"),
                r["period_ms"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let theirs: std::collections::BTreeSet<(u64, u64, u64)> = w2k3_x64_volatility2::W2K3_X64_TIMERS
        .iter()
        .copied()
        .collect();
    assert_eq!(theirs.len(), 211);
    assert_eq!(
        ours, theirs,
        "{name}: Seance's timers and the Volatility 2 walk"
    );
    // Measured, not graded: 54 timers carry a DPC and every routine lies in a loaded module.
    assert_eq!(
        timers["timers_with_a_dpc"].as_u64(),
        Some(54),
        "{name}: pin"
    );
    assert_eq!(timers["items_not_timers"].as_u64(), Some(0), "{name}: pin");
}
