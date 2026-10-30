//! A **machine-wide** `EtwEventWrite` patch graded against a capture with a planted answer (`MEM-020`, 2026-10-23).
//!
//! # SYNTHETIC, and what that bounds
//!
//! The capture is guest RAM of the repo's Windows 11 build 26100 lab VM after `test_data/win11_tamper_plant/plant.ps1 -Role etwall`
//! wrote `c3` (`ret`) over `ntdll!EtwEventWrite` in every 64-bit process the planting account could open: 107 of 130, the rest
//! being protected, 32-bit or gone. The patched pids, with the original 16 bytes of each, are the answer key
//! (`plant-truth.json`). It grades the case the earlier plant could not: **the mode is itself the patch**, so the modal route
//! has nothing to say and only the classification route can. It says nothing about how often attackers patch machine-wide.
//!
//! # What it found
//!
//! Before the fix every genuine copy that differed from the patched mode (18 of 117 voting) was published as a signal on the
//! modal route, while the record's own note said such copies "may be the clean ones". The route now ignores a mode that is
//! itself the patch (`mode_is_patched`).
//!
//! # Provisioning
//!
//! `SEANCE_WIN11_ETWALL_MEMORY` (default `~/forensic_corpora/win11_tamper_plant_etwall/tamper-etwall.raw`) and
//! `SEANCE_WIN11_ETWALL_TRUTH` (default `plant-truth.json` beside it). This kernel (`ntkrnlmp.pdb` GUID
//! `B661C6FE72991D160FE37C48B8BC5470`, age 1) has its ISF under `reference/volatility3` (made with `pdbconv`, `VALIDATION.md`
//! `MEM-VC-6`); `SEANCE_SYMBOL_DIRS` names others. Absent capture: the tests skip. Release only.

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
        .join("forensic_corpora/win11_tamper_plant_etwall/tamper-etwall.raw")
}

fn capture_path() -> Option<PathBuf> {
    let p = std::env::var("SEANCE_WIN11_ETWALL_MEMORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_capture());
    p.exists().then_some(p)
}

fn truth() -> Option<Value> {
    let p = std::env::var("SEANCE_WIN11_ETWALL_TRUTH")
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

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_machine_wide_etw_patch_is_seen_on_the_classification_route_and_the_clean_copies_are_not_flagged(
) {
    let (rec, truth) = require_capture!();
    let etw = &rec["etw"];
    assert!(
        etw.is_object(),
        "the ETW group must have run: {:?}",
        rec["groups"]
    );
    let rows = etw["exports"].as_array().expect("export rows");
    let patched: std::collections::HashSet<u64> = truth["patched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pid"].as_u64().unwrap())
        .collect();
    assert!(
        patched.len() > 50,
        "the plant reached many processes: {}",
        patched.len()
    );
    let want = truth["address"].as_str().unwrap();

    let etw_rows: Vec<&Value> = rows
        .iter()
        .filter(|r| r["export"] == "EtwEventWrite")
        .collect();
    let mut seen_patched = 0usize;
    for r in &etw_rows {
        let pid = r["pid"].as_u64().unwrap();
        if patched.contains(&pid) {
            seen_patched += 1;
            assert_eq!(r["classification"], "returns_immediately", "pid {pid}");
            assert_eq!(
                r["route"], "classification",
                "pid {pid}: the modal route is silent, the mode being the patch"
            );
            assert_eq!(r["agrees_with_the_mode"], true, "pid {pid}");
            assert_eq!(
                r["prologue"].as_str().unwrap().split(' ').next(),
                Some("c3"),
                "pid {pid}"
            );
            let got =
                u64::from_str_radix(r["address"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            assert_eq!(
                got,
                u64::from_str_radix(want, 16).unwrap(),
                "pid {pid}: one ntdll address everywhere"
            );
        } else {
            assert_eq!(
                r["is_signal"], false,
                "pid {pid} was not patched and must not be a signal: {r}"
            );
            assert_eq!(r["route"], Value::Null, "pid {pid}");
        }
        assert_eq!(r["mode_is_patched"], true, "pid {pid}");
    }
    // Most of what was planted was assessed (some processes ended or could not be walked), and every assessed one was seen.
    assert!(seen_patched >= 90, "patched copies seen: {seen_patched}");
    assert_eq!(etw["signals"].as_u64(), Some(seen_patched as u64));
    let notes = etw["notes"].to_string();
    assert!(notes.contains("the mode is patched"), "{notes}");
}
