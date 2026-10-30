//! The pattern scan: where a match is looked for, what a ceiling says, and the
//! three claims an empty match list must not carry.

use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::scan::{Hit, RefusedChunk, ScanConfig, ScannerDiagnostics, SingleStringScanner};
use seance_memory::PhysicalLayer;

use super::pattern_scan::*;
use crate::process::ProcessInventory;
use crate::vad::{MappedFile, Vad, VadKind, VadRootShape, VadStop, VadTree};

const NEEDLE: &[u8] = b"FORENSIC-W11";

fn flat(bytes: Vec<u8>) -> PhysicalLayer {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    PhysicalLayer::raw(source).expect("a non-empty image is a physical layer")
}

/// A set of one fixed needle, with no engine diagnostics: the scanner cannot
/// refuse a chunk and cannot match without an address.
fn needle_set() -> PatternSet {
    PatternSet {
        kind: "regex",
        source: "FORENSIC-W11".to_string(),
        pattern_names: vec!["marker".to_string()],
        scanner: Arc::new(SingleStringScanner::new("needle", NEEDLE).expect("valid needle")),
        diagnostics: None,
        scope_note: None,
    }
}

/// One region, as a slice. Written this way rather than inline because
/// `&[a..b]` reads to clippy as a range-filled array.
fn one(range: std::ops::Range<u64>) -> Vec<std::ops::Range<u64>> {
    Vec::from([range])
}

/// Small chunks, so a boundary can be exercised without a 16 MiB fixture.
fn config(chunk_size: u64) -> PatternScanConfig {
    PatternScanConfig {
        caps: PatternCaps {
            scan: ScanConfig {
                chunk_size,
                ..ScanConfig::default()
            },
            ..PatternCaps::default()
        },
        ..PatternScanConfig::default()
    }
}

// ── Surveys, built the way the stage builds them ─────────────────────────────

/// A complete process list of one, so a survey's own verdict is the only thing
/// under test.
fn inventory() -> ProcessInventory {
    ProcessInventory {
        head: 0xFFFF_8000_0000_0100,
        listed: 1,
        complete: true,
        incomplete: Vec::new(),
    }
}

fn empty_survey() -> PatternScanSurvey {
    PatternScanSurvey::new(Vec::new(), Some(inventory()))
}

fn survey_with_sets(sets: Vec<PatternSet>) -> PatternScanSurvey {
    PatternScanSurvey::new(sets, Some(inventory()))
}

fn survey_with_one_set() -> PatternScanSurvey {
    survey_with_sets(vec![needle_set()])
}

fn hits_at(addresses: &[u64]) -> Vec<Hit> {
    addresses
        .iter()
        .map(|address| Hit {
            address: *address,
            pattern_id: 0,
            length: NEEDLE.len() as u32,
        })
        .collect()
}

/// Rows as the record carries them, for matches in one process's space.
fn rows_for_test(
    set: &PatternSet,
    addresses: &[u64],
    tree: Option<&VadTree>,
) -> Vec<serde_json::Value> {
    let mut survey = survey_with_sets(vec![set.clone()]);
    record_hits(
        &mut survey,
        set,
        &hits_at(addresses),
        &MatchScope::Process {
            process: 0xFFFF_8000_0000_1000,
            pid: Some(4708),
            name: Some("taskhostw.exe".to_string()),
        },
        tree,
        &PatternScanConfig::default(),
    );
    survey.matches.iter().map(MatchRow::to_json).collect()
}

/// The same, for matches in the kernel's own space.
fn kernel_rows_for_test(set: &PatternSet, addresses: &[u64]) -> Vec<serde_json::Value> {
    let mut survey = survey_with_sets(vec![set.clone()]);
    record_hits(
        &mut survey,
        set,
        &hits_at(addresses),
        &MatchScope::Kernel,
        None,
        &PatternScanConfig::default(),
    );
    survey.matches.iter().map(MatchRow::to_json).collect()
}

fn survey_recording(
    set: &PatternSet,
    addresses: &[u64],
    config: &PatternScanConfig,
) -> PatternScanSurvey {
    let mut survey = survey_with_sets(vec![set.clone()]);
    record_hits(
        &mut survey,
        set,
        &hits_at(addresses),
        &MatchScope::Process {
            process: 0xFFFF_8000_0000_1000,
            pid: Some(4708),
            name: Some("taskhostw.exe".to_string()),
        },
        None,
        config,
    );
    survey
}

// ── What is searched, and what is not ───────────────────────────────────────

// ── Ceilings ────────────────────────────────────────────────────────────────

// ── The budget arithmetic ───────────────────────────────────────────────────

// ── Attribution ─────────────────────────────────────────────────────────────

fn vad(address: u64, start: u64, end: u64, tag: &str, file: MappedFile) -> Vad {
    Vad {
        address,
        depth: 0,
        tag: tag.to_string(),
        kind: VadKind::Long,
        start,
        end,
        parent: None,
        commit_charge: None,
        private_memory: Some(true),
        protection: Some(6),
        protection_names: Some("PAGE_EXECUTE_READWRITE".to_string()),
        file,
        notes: Vec::new(),
    }
}

fn tree(vads: Vec<Vad>) -> VadTree {
    VadTree {
        process: 0xFFFF_8000_0000_1000,
        root: vads.first().map(|v| v.address).unwrap_or(0),
        root_shape: VadRootShape::AvlTreeRoot,
        visited: vads.len(),
        max_depth: 0,
        vads,
        skipped: Vec::new(),
        skipped_total: 0,
        stop: VadStop::Exhausted,
    }
}

/// **A match carries the allocation its first byte fell in**, with the
/// protection and the mapped file that make it readable as a finding.
#[test]
fn a_match_is_attributed_to_the_allocation_that_held_it() {
    let vads = vec![
        vad(0x1000, 0x1_0000, 0x1_0FFF, "VadS", MappedFile::None),
        vad(
            0x2000,
            0x2_0000,
            0x2_0FFF,
            "Vad ",
            MappedFile::Name("\\Windows\\System32\\ntdll.dll".to_string()),
        ),
    ];
    let rows = rows_for_test(&needle_set(), &[0x2_0040, 0x1_0010], Some(&tree(vads)));

    assert_eq!(rows.len(), 2);
    let first = &rows[0];
    assert_eq!(first["address_hex"], "0x20040");
    assert_eq!(first["region"]["start_hex"], "0x20000");
    assert_eq!(first["region"]["protection"], "PAGE_EXECUTE_READWRITE");
    assert_eq!(first["region"]["mapped_file"]["kind"], "name");
    assert_eq!(rows[1]["region"]["start_hex"], "0x10000");
    assert_eq!(
        rows[1]["region"]["mapped_file"]["kind"], "no_mapped_file",
        "private memory is a different claim from a name that could not be read"
    );
}

/// A kernel-space match has no allocation of that kind, and says so rather
/// than leaving a null field to be read as "unbacked".
#[test]
fn a_kernel_match_states_why_it_has_no_allocation_rather_than_leaving_a_null() {
    let rows = kernel_rows_for_test(&needle_set(), &[0xFFFF_8000_0000_2000]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["scope"], "kernel");
    assert!(rows[0]["region"].is_null());
    assert!(
        rows[0]["attribution"]
            .as_str()
            .is_some_and(|s| s.contains("no allocation of that kind")),
        "{}",
        rows[0]["attribution"]
    );
    assert!(rows[0]["pid"].is_null());
}

// ── The empty answers ───────────────────────────────────────────────────────

/// **With nothing named, nothing is searched for — and the record says exactly
/// that.** An empty match list from a scan with no pattern must not read like
/// an empty match list from a scan with one.
#[test]
fn a_survey_with_no_pattern_set_claims_nothing_about_the_image() {
    let survey = empty_survey();
    let json = survey.to_json();

    assert_eq!(json["matches_total"], 0);
    assert_eq!(json["pattern_sets"], 0);
    assert_eq!(json["content_complete"], serde_json::json!(false));
    let statement = json["statement"].as_str().expect("a statement");
    assert!(
        statement.contains("nothing was searched for"),
        "{statement}"
    );
    assert!(
        statement.contains("not a statement about what is in this image"),
        "{statement}"
    );
    assert!(!survey.is_complete());
    assert_eq!(survey.incomplete().len(), 1);
    assert_eq!(survey.incomplete()[0].reason.as_str(), "unvalidated");
}

/// A scan that found nothing says what that does and does not mean.
#[test]
fn no_match_is_not_reported_as_nothing_to_find() {
    let survey = survey_with_one_set();
    let statement = survey.describe();
    assert!(
        statement.contains("No match is not the same as nothing to find"),
        "{statement}"
    );
}

/// A refused chunk reaches the record. An engine that would not scan half the
/// image and an image with nothing in it are opposite claims.
#[test]
fn a_chunk_the_engine_refused_is_on_the_record_and_costs_the_completeness_claim() {
    #[derive(Debug)]
    struct Refuses;
    impl ScannerDiagnostics for Refuses {
        fn take_refused_chunks(&self) -> Vec<RefusedChunk> {
            vec![RefusedChunk {
                address: 0x7FF8_0000_0000,
                bytes: 4096,
                detail: "timeout".to_string(),
            }]
        }
        fn take_matched_without_address(&self) -> Vec<String> {
            Vec::new()
        }
    }

    let mut survey = survey_with_one_set();
    let refused = Refuses.take_refused_chunks();
    survey
        .refused_chunks
        .push(("FORENSIC-W11".to_string(), refused[0].clone()));

    assert!(!survey.is_complete());
    let incomplete = survey.incomplete();
    assert!(
        incomplete
            .iter()
            .any(|i| i.detail.contains("refused 4096 byte(s) at 0x7ff800000000")),
        "{incomplete:?}"
    );
    let json = survey.to_json();
    assert_eq!(json["refused_chunks"][0]["bytes"], 4096);
    assert_eq!(json["refused_chunks"][0]["detail"], "timeout");
}

/// A pattern that matched with no address to report is named, with why. It
/// produced no row, and silence would be the examiner's rule firing invisibly.
#[test]
fn a_pattern_that_matched_without_an_address_is_named_with_the_reason() {
    let mut survey = survey_with_one_set();
    survey
        .matched_without_address
        .push(("rules.yar".to_string(), "conditionless".to_string()));
    let json = survey.to_json();
    assert_eq!(
        json["matched_without_address"][0]["pattern"],
        "conditionless"
    );
    assert!(json["matched_without_address"][0]["why"]
        .as_str()
        .is_some_and(|s| s.contains("no address to report")));
}

/// The row ceiling keeps the totals exact. Rows and totals taken from the same
/// capped list would report the ceiling as the number of matches.
#[test]
fn past_the_row_ceiling_the_totals_stay_exact_and_the_rows_say_they_are_a_sample() {
    let mut config = config(64);
    config.caps.max_recorded_matches = 2;
    let addresses: Vec<u64> = (0..5).map(|i| 0x1000 + i * 0x10).collect();
    let survey = survey_recording(&needle_set(), &addresses, &config);

    assert_eq!(survey.matches_total, 5, "the total is every match");
    assert_eq!(survey.matches.len(), 2, "the rows stop at the ceiling");
    assert!(survey.rows_capped);
    assert_eq!(survey.matches_by_pattern.get("marker"), Some(&5));
    assert!(!survey.is_complete());
    let incomplete = survey.incomplete();
    assert!(
        incomplete
            .iter()
            .any(|i| i.detail.contains("5 match(es) were found and 2 are listed")),
        "{incomplete:?}"
    );
}

/// A process that could not be examined is a row saying so, and it costs the
/// survey's completeness claim.
#[test]
fn a_process_that_could_not_be_examined_is_a_row_and_not_a_silence() {
    let mut survey = survey_with_one_set();
    survey.processes.push(ProcessScan::not_examined(
        0xFFFF_8000_0000_3000,
        Some(1234),
        Some("suspect.exe".to_string()),
        "this process has no readable address space",
    ));
    assert_eq!(survey.processes_not_scanned(), 1);
    assert!(!survey.is_complete());
    let json = survey.to_json();
    assert_eq!(json["processes_not_scanned"], 1);
    assert!(json["processes"][0]["not_scanned"]
        .as_str()
        .is_some_and(|s| s.contains("no readable address space")));
    assert!(json["statement"]
        .as_str()
        .is_some_and(|s| s.contains("were not examined at all")));
}

/// A YARA set's chunk-scope caveat travels with the record. It is the
/// limitation an examiner reading these rows most needs and is least likely to
/// guess.
#[test]
fn the_scope_note_of_a_set_is_published_on_the_record() {
    let mut set = needle_set();
    set.scope_note = Some("each rule was evaluated against one chunk".to_string());
    let survey = survey_with_sets(vec![set]);
    let json = survey.to_json();
    assert_eq!(
        json["scope_notes"][0],
        "each rule was evaluated against one chunk"
    );
    assert_eq!(
        json["patterns"][0]["scope_note"],
        "each rule was evaluated against one chunk"
    );
}

/// **A process list that exists and fell short is declared.** Every process
/// handed in may have been searched in full while the process doing the hiding
/// was never on the list — and the survey's own verdict must not read as a
/// complete answer about the machine.
#[test]
fn a_short_process_list_costs_the_completeness_claim_and_says_why() {
    let short = ProcessInventory {
        head: 0xFFFF_8000_0000_0100,
        listed: 12,
        complete: false,
        incomplete: vec![seance_memory::Incomplete::new(
            seance_core::io::IncompleteReason::CapReached,
            "the active process list stopped at its cap of 12",
        )],
    };
    let survey = PatternScanSurvey::new(vec![needle_set()], Some(short));

    assert!(!survey.is_complete());
    let incomplete = survey.incomplete();
    assert!(
        incomplete.iter().any(|i| i
            .detail
            .contains("held 12 process(es) and did not walk end to end")),
        "{incomplete:?}"
    );
    // And the inventory's own reason travels with it rather than being
    // summarised away.
    assert!(
        incomplete
            .iter()
            .any(|i| i.detail.contains("stopped at its cap of 12")),
        "{incomplete:?}"
    );
    assert!(survey.describe().contains("are a floor"));
}

/// With no process list at all the kernel's space is still searched, and the
/// record says no process's was.
#[test]
fn with_no_process_list_the_survey_says_only_the_kernel_space_was_searched() {
    let survey = PatternScanSurvey::new(vec![needle_set()], None);
    assert!(!survey.is_complete());
    assert!(survey.incomplete().iter().any(|i| i
        .detail
        .contains("no process's own address space was searched")));
    assert!(survey.describe().contains("could not be walked"));
    assert!(survey.to_json()["process_inventory"].is_null());
}

/// **A regular expression over memory is a byte match, and the record says
/// what that costs.** The two differences from `grep` that change what an
/// empty result means: no Unicode, so an ASCII pattern misses the UTF-16 the
/// same string is stored as in most of a Windows process, and no bounded match
/// length, so a match across a chunk boundary is not guaranteed.
#[test]
fn a_regex_set_publishes_what_a_byte_match_is_not() {
    let set = PatternSet {
        kind: "regex",
        source: "FORENSIC-W1[0-9]".to_string(),
        pattern_names: vec!["FORENSIC-W1[0-9]".to_string()],
        scanner: Arc::new(
            seance_memory::scan::RegexScanner::new("regex", "FORENSIC-W1[0-9]")
                .expect("a valid pattern"),
        ),
        diagnostics: None,
        scope_note: Some(REGEX_SCOPE.to_string()),
    };
    // It finds the bytes, at the address they are at.
    let mut bytes = vec![b'.'; 256];
    bytes[64..76].copy_from_slice(b"FORENSIC-W11");
    let layer = flat(bytes);
    let pass = scan_space(&layer, &one(0x0..0x100), &set, u64::MAX, &config(64).caps);
    assert_eq!(
        pass.hits.iter().map(|h| h.address).collect::<Vec<_>>(),
        vec![64]
    );
    assert!(pass.pattern_may_exceed_overlap, "no bounded match length");

    let survey = survey_with_sets(vec![set]);
    let json = survey.to_json();
    assert_eq!(json["patterns"][0]["kind"], "regex");
    assert_eq!(
        json["patterns"][0]["match_length_bounded"],
        serde_json::json!(false)
    );
    let note = json["scope_notes"][0].as_str().expect("the scope note");
    assert!(note.contains("RAW BYTES"), "{note}");
    assert!(note.contains("UTF-16"), "{note}");
}
