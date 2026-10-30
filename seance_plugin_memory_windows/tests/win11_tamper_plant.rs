//! The user-mode tamper checks graded against a capture with a **planted**
//! answer (`MEM-020`, 2026-10-20).
//!
//! # SYNTHETIC, and what that bounds
//!
//! The capture is guest RAM of this repo's own Windows 11 build 26200 VM, taken
//! after `test_data/win11_tamper_plant/plant.ps1` ran four processes that
//! tampered with themselves:
//!
//! | role   | what the planter did                                              |
//! |--------|-------------------------------------------------------------------|
//! | `etw1` | `ntdll!EtwEventWrite` first byte := `c3` (`ret`)                  |
//! | `etw2` | `ntdll!EtwEventWrite` first bytes := `33 c0 c3` (`xor eax,eax; ret`) |
//! | `dr`   | worker thread given `Dr0` = `kernel32!CreateMailslotW`, `Dr7` = 1 |
//! | `susp` | worker thread left `SuspendThread`-ed                             |
//!
//! The planter printed the pid, tid and addresses inside the guest; that file
//! (`plant-truth.json`) is the answer key. This grades whether the checks can
//! SEE the technique when it is present and stay silent elsewhere on the same
//! machine. It says nothing about how often real attackers use the technique,
//! and nothing about kernel-side tamper (timers, unloaded modules, the
//! skeleton-key patch), which a user-mode plant cannot reach.
//!
//! # Provisioning
//!
//! `SEANCE_WIN11_TAMPER_MEMORY` (default
//! `~/forensic_corpora/win11_tamper_plant/tamper-plant.raw`) and
//! `SEANCE_WIN11_TAMPER_TRUTH` (default `plant-truth.json` beside it). The ISF
//! is the one `win11_corpus_analysis.rs` uses. Absent capture: the tests skip.
//!
//! ```text
//! CARGO_TARGET_DIR=... cargo test --release -p seance_plugin_memory_windows \
//!     --test win11_tamper_plant
//! ```

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_memory::analysis::MemoryAnalysisModule;
use seance_plugin_memory_windows::WindowsMemoryAnalysis;
use serde_json::Value;

fn default_capture() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("forensic_corpora/win11_tamper_plant/tamper-plant.raw")
}

fn capture_path() -> Option<PathBuf> {
    let p = std::env::var("SEANCE_WIN11_TAMPER_MEMORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_capture());
    p.exists().then_some(p)
}

fn truth() -> Option<Value> {
    let p = std::env::var("SEANCE_WIN11_TAMPER_TRUTH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| capture_path().unwrap().with_file_name("plant-truth.json"));
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate sits under the workspace root")
        .to_path_buf();
    vec![
        root.join("test_data/win11_bitlocker/symbols"),
        root.join("reference/volatility3/volatility3/symbols"),
    ]
}

static RECORD: OnceLock<Option<Value>> = OnceLock::new();

/// The `MemoryTamperChecks` metadata, from one pass over the capture.
fn record() -> Option<&'static Value> {
    RECORD
        .get_or_init(|| {
            let path = capture_path()?;
            let source: Arc<dyn DataSource> =
                Arc::new(seance_core::data_source::FileDataSource::new(path).ok()?);
            let image = Artifact::new(
                uuid::Uuid::new_v4(),
                ArtifactType::ParsedRecord,
                Some(source),
                serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
            );
            let out = MemoryAnalysisModule::new(
                WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()),
            )
            .process(&image)
            .ok()?;
            out.into_iter()
                .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
                .map(|a| a.metadata.clone())
        })
        .as_ref()
}

macro_rules! require_capture {
    () => {
        match (record(), capture_path().and_then(|_| truth())) {
            (Some(r), Some(t)) => (r, t),
            _ => {
                eprintln!("skipping: tamper-plant.raw / plant-truth.json not present");
                return;
            }
        }
    };
}

fn planted<'a>(truth: &'a Value, role: &str) -> &'a Value {
    truth["planted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["role"] == role)
        .unwrap_or_else(|| panic!("no planted role {role}"))
}

fn eq_hex(a: &Value, b: &Value) -> bool {
    let p = |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).ok();
    p(a).is_some() && p(a) == p(b)
}

/// `ntdll!EtwEventWrite` patched in two processes, one by each patch shape.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_planted_etw_patch_is_seen_by_both_routes_and_nothing_else_is() {
    let (rec, truth) = require_capture!();
    let etw = &rec["etw"];
    assert!(
        etw.is_object(),
        "the ETW group must have run: {:?}",
        rec["groups"]
    );
    let rows = etw["exports"].as_array().expect("export rows");
    eprintln!(
        "etw: {} rows, {} signals, {} assessed, {} unassessed",
        rows.len(),
        etw["signals"],
        etw["processes_assessed"],
        etw["unassessed_total"]
    );

    for role in ["etw1", "etw2"] {
        let want = planted(&truth, role);
        let pid = want["pid"].as_u64().unwrap();
        let row = rows
            .iter()
            .find(|r| r["pid"] == pid && r["export"] == "EtwEventWrite")
            .unwrap_or_else(|| panic!("{role}: no EtwEventWrite row for pid {pid}"));
        eprintln!("{role}: {row}");
        assert!(eq_hex(&row["address"], &want["address"]), "{role}: address");
        assert_eq!(
            row["prologue"].as_str().unwrap(),
            want["patched"].as_str().unwrap(),
            "{role}: the bytes read are the bytes planted"
        );
        assert_eq!(row["classification"], "returns_immediately", "{role}");
        assert_eq!(row["agrees_with_the_mode"], false, "{role}: 1 against N");
        assert_eq!(row["is_signal"], true, "{role}");
        assert_eq!(row["route"], "both", "{role}: classification AND modal");
        let n = row["mode_population"].as_u64().unwrap();
        assert!(
            n > 10,
            "{role}: the mode is taken over many processes, got {n}"
        );
    }

    // The false-positive count on the same capture: every other row is silent.
    let planted_pids: Vec<u64> = ["etw1", "etw2"]
        .iter()
        .map(|r| planted(&truth, r)["pid"].as_u64().unwrap())
        .collect();
    let stray: Vec<&Value> = rows
        .iter()
        .filter(|r| r["is_signal"] == true && !planted_pids.contains(&r["pid"].as_u64().unwrap()))
        .collect();
    assert!(
        stray.is_empty(),
        "a signal outside the planted processes is a false positive: {stray:?}"
    );
    // The two planted processes patched exactly one export each.
    let in_planted: Vec<&Value> = rows.iter().filter(|r| r["is_signal"] == true).collect();
    assert_eq!(in_planted.len(), 2, "{in_planted:?}");
    assert_eq!(etw["signals"].as_u64(), Some(2));
}

/// A hardware breakpoint set through `SetThreadContext` on one thread.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_planted_hardware_breakpoint_is_the_only_graded_debug_register_row() {
    let (rec, truth) = require_capture!();
    let threads = &rec["threads"];
    assert!(threads.is_object(), "the thread walk must have run");
    let want = planted(&truth, "dr");
    let (pid, tid) = (want["pid"].as_u64().unwrap(), want["tid"].as_u64().unwrap());
    let rows = threads["debug_register_threads"].as_array().unwrap();
    eprintln!(
        "debug rows: {}, with a breakpoint: {}, claiming debug state: {}",
        rows.len(),
        threads["threads_with_a_breakpoint"],
        threads["threads_claiming_debug_state"]
    );
    let row = rows
        .iter()
        .find(|r| r["pid"] == pid && r["tid"] == tid)
        .unwrap_or_else(|| panic!("no debug-register row for pid {pid} tid {tid}"));
    eprintln!("{row}");
    assert_eq!(row["has_breakpoint"], true);
    assert_eq!(row["claim"], "confirmed_by_the_thread's_own_flags");
    let bps = row["breakpoints"].as_array().unwrap();
    assert_eq!(bps.len(), 1, "only Dr0 was armed: {bps:?}");
    assert_eq!(bps[0]["slot"], 0);
    assert!(eq_hex(&bps[0]["address"], &want["dr0"]), "{bps:?}");

    let graded: Vec<&Value> = rows
        .iter()
        .filter(|r| r["has_breakpoint"] == true)
        .collect();
    assert_eq!(
        graded.len(),
        1,
        "every other thread on this machine must stay ungraded: {graded:?}"
    );
    assert_eq!(threads["threads_with_a_breakpoint"].as_u64(), Some(1));
}

/// A suspended thread is listed, and the listing is never a finding.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_planted_suspended_thread_is_listed_and_is_never_a_finding() {
    let (rec, truth) = require_capture!();
    let want = planted(&truth, "susp");
    let (pid, tid) = (want["pid"].as_u64().unwrap(), want["tid"].as_u64().unwrap());
    let rows = rec["threads"]["suspended_threads"].as_array().unwrap();
    eprintln!("suspended rows: {}", rows.len());
    let row = rows
        .iter()
        .find(|r| r["pid"] == pid && r["tid"] == tid)
        .unwrap_or_else(|| panic!("pid {pid} tid {tid} not in the suspended listing"));
    assert_eq!(row["suspend_count"], 1);
    for r in rows {
        assert_eq!(r["is_a_finding"], false, "a suspension is never a finding");
    }
}
