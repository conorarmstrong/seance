//! An examiner's pattern over a **swap area**, which is a blob with no address
//! space at all (`ROADMAP` §3.8).
//!
//! `SEANCE_LINUX_SWAP_MEM` must name a directory holding `swap-area.raw`: the
//! swap area of a Linux guest whose workload filled a 16 MiB anonymous mapping
//! with a known per-page marker (`b"SWAPMARK" + le64(page_index)`) and then
//! `madvise(MADV_PAGEOUT)`-ed it. Absent, this skips; named and missing, it
//! fails.
//!
//! # Why this route exists at all
//!
//! A swap area has no page tables in it and names no process: a slot holds a
//! page that *was* somewhere, and what maps it is recorded in a process's page
//! table elsewhere. So the per-process scan cannot be pointed at it, and the
//! only honest thing to do with an examiner's pattern is to search the bytes
//! and say exactly that about what was found — which is what the record's
//! `offset_meaning` and its statement do.
//!
//! The richer answer is already elsewhere and is not what this tests: with the
//! swap area **attached** to a Linux or Windows address space, a swapped page
//! is read through the process's own page table, so a match in it is found in
//! that process's context with the allocation that held it. That is
//! `seance_plugin_memory_linux/tests/swap_real_capture_test.rs` and the
//! Windows pagefile path. This test is the other case: a blob on its own.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_memory::patterns::{ImagePatternScan, PatternSet};
use seance_memory::scan::SingleStringScanner;

fn swap_area() -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var("SEANCE_LINUX_SWAP_MEM").ok()?);
    let p = d.join("swap-area.raw");
    p.exists().then_some(p)
}

/// **The markers in the swap area are found, and the record says what their
/// offsets are not.**
///
/// Measured 2026-09-15 on the corpus swap area: **4,587** occurrences of
/// `SWAPMARK`, every one at a 4 KiB boundary. The count is pinned because it
/// is a fact about that file; what it is *not* is a count of pages the workload
/// wrote (it wrote 4,096), because a swap area is reused and holds slots from
/// earlier runs as well. The test says so rather than asserting the workload's
/// number and quietly meaning the file's.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "reads a 2 GiB corpus file; run with --release"
)]
fn a_pattern_is_found_in_a_swap_area_and_the_record_says_what_the_offsets_are_not() {
    let Some(path) = swap_area() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to a directory holding swap-area.raw");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open swap-area.raw"));

    // The record an ingest produces for a blob the case DECLARED to be a flat
    // capture: `image_format: raw`. Nothing in these bytes says they are
    // memory, which is exactly what the record has to carry.
    let record = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({
            "type": "MemoryImage",
            "subtype": "memory_image",
            "image_format": "raw",
        }),
    );

    let set = PatternSet {
        kind: "regex",
        source: "SWAPMARK".to_string(),
        pattern_names: vec!["SWAPMARK".to_string()],
        diagnostics: None,
        scanner: Arc::new(SingleStringScanner::new("needle", b"SWAPMARK").expect("a valid needle")),
        scope_note: None,
    };

    let out = ImagePatternScan::new(vec![set])
        .expect("one set is a module")
        .process(&record)
        .expect("the blob is readable");
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    eprintln!(
        "swap area: {} match(es) over {} byte(s); pass {}",
        md["matches_total"], md["bytes_scanned"], md["passes"][0]
    );

    assert_eq!(
        md["matches_total"].as_u64(),
        Some(4_587),
        "the measured answer for this file"
    );
    assert_eq!(md["content_complete"], serde_json::json!(true));
    // Every recorded match is at a page boundary, which is what a swap slot is.
    for row in md["matches"].as_array().expect("rows") {
        let address = row["address"].as_u64().expect("an address");
        assert_eq!(address % 4096, 0, "{address:#x} is not a slot boundary");
    }
    // **And the record does not call these memory addresses.** The case
    // declared this file to be a flat capture; nothing in the bytes did.
    let meaning = md["offset_meaning"].as_str().expect("a statement");
    assert!(
        meaning.contains("only if that declaration is true"),
        "{meaning}"
    );
    assert!(md["statement"]
        .as_str()
        .is_some_and(|s| s.contains("are NOT established here")));
}
