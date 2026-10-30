use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;
use tempfile::TempDir;

const RULES: &str = r#"
rule eicar_like : malware test {
    meta:
        description = "test marker"
    strings:
        $a = "X5O!P%@AP-MARKER"
    condition:
        $a
}
rule has_mz : pe {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
"#;

/// Write `files` into a fresh temp directory and load a scanner from it.
fn rule_dir(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    for (name, body) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, body).expect("write rule file");
    }
    dir
}

fn scanner_with(files: &[(&str, &str)]) -> (TempDir, YaraScanner) {
    let dir = rule_dir(files);
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("rules must load");
    (dir, scanner)
}

fn default_scanner() -> (TempDir, YaraScanner) {
    scanner_with(&[("base.yar", RULES)])
}

fn run(scanner: &YaraScanner, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "sample.bin" }),
    );
    scanner.process(&art).unwrap()
}

fn records_of<'a>(out: &'a [Artifact], kind: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == kind).collect()
}

// --- Rule loading -------------------------------------------------------------

#[test]
fn rules_load_from_a_single_file() {
    let dir = rule_dir(&[("base.yar", RULES)]);
    let scanner = YaraScanner::from_rule_path(&dir.path().join("base.yar")).unwrap();
    assert_eq!(scanner.rule_count(), 2);
}

#[test]
fn rules_load_recursively_from_a_directory() {
    let (_dir, scanner) = scanner_with(&[
        ("top.yar", "rule a { condition: true }"),
        ("nested/deeper/b.yara", "rule b { condition: false }"),
        // Not a rule extension: must be ignored rather than fed to the compiler.
        ("notes.txt", "this is not YARA at all"),
    ]);
    assert_eq!(scanner.rule_count(), 2);
}

/// A rule path that does not exist is a configuration error, not a scanner that
/// quietly matches nothing.
#[test]
fn a_missing_rule_path_is_an_error() {
    let dir = TempDir::new().unwrap();
    let err = YaraScanner::from_rule_path(&dir.path().join("nope")).unwrap_err();
    assert!(matches!(err, RuleLoadError::Io { .. }), "{err}");
}

/// An empty rule directory must fail loudly. Loading it as an empty rule set
/// would produce a module that reports "no matches" on every artifact in the
/// case while never having tested anything.
#[test]
fn a_directory_with_no_rule_files_is_an_error() {
    let dir = rule_dir(&[("readme.md", "no rules here")]);
    let err = YaraScanner::from_rule_path(dir.path()).unwrap_err();
    assert!(matches!(err, RuleLoadError::NoRuleFiles { .. }), "{err}");
}

/// Source that compiles but declares nothing is the same trap by another route.
#[test]
fn a_rule_file_declaring_no_rules_is_an_error() {
    let dir = rule_dir(&[("empty.yar", "// only a comment\n")]);
    let err = YaraScanner::from_rule_path(dir.path()).unwrap_err();
    assert!(matches!(err, RuleLoadError::EmptyRuleSet { .. }), "{err}");
}

/// A broken rule must fail the whole load. Skipping it would leave the examiner
/// believing a detection ran that never did.
#[test]
fn a_broken_rule_fails_the_load_and_the_error_names_the_file() {
    let dir = rule_dir(&[
        ("good.yar", "rule good { condition: true }"),
        ("broken.yar", "rule broken { condition: }"),
    ]);
    let err = YaraScanner::from_rule_path(dir.path()).unwrap_err();
    assert!(matches!(err, RuleLoadError::Compile { .. }), "{err}");
    let rendered = err.to_string();
    assert!(
        rendered.contains("broken.yar"),
        "the diagnostic must name the offending file, got: {rendered}"
    );
}

/// Every broken file is reported, not just the first one encountered.
#[test]
fn all_broken_rule_files_are_reported_together() {
    let dir = rule_dir(&[
        ("a_broken.yar", "rule one { condition: }"),
        ("b_broken.yar", "rule two { condition: }"),
    ]);
    let err = YaraScanner::from_rule_path(dir.path()).unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("a_broken.yar"), "{rendered}");
    assert!(rendered.contains("b_broken.yar"), "{rendered}");
}

/// A rule file reached through a symlink is a rule the examiner believes is
/// loaded. Dropping it because the *link* is not a regular file would shrink
/// the rule set with no diagnostic, and every later "no matches" would then be
/// partly an answer about rules that never ran.
#[test]
#[cfg(unix)]
fn a_symlinked_rule_file_is_loaded() {
    let store = rule_dir(&[("real.yar", RULES)]);
    let dir = TempDir::new().unwrap();
    std::os::unix::fs::symlink(store.path().join("real.yar"), dir.path().join("linked.yar"))
        .expect("symlink");
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("a symlinked rule file must load");
    assert_eq!(scanner.rule_count(), 2);
}

/// Following links must not let a cycle trap the walk, and must not stop the
/// real rules beside it from loading.
#[test]
#[cfg(unix)]
fn a_symlink_cycle_terminates() {
    let dir = rule_dir(&[("base.yar", RULES)]);
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).expect("symlink");
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("rules must load");
    assert_eq!(scanner.rule_count(), 2);
}

/// A dangling link that would have been a rule is a hard failure. Silently
/// ignoring it is how a rule set shrinks without anyone being told.
#[test]
#[cfg(unix)]
fn a_dangling_rule_symlink_is_an_error() {
    let dir = rule_dir(&[("base.yar", RULES)]);
    std::os::unix::fs::symlink(dir.path().join("gone.yar"), dir.path().join("apt.yar"))
        .expect("symlink");
    let err = YaraScanner::from_rule_path(dir.path()).unwrap_err();
    assert!(matches!(err, RuleLoadError::Io { .. }), "{err}");
}

/// The other half of that: a broken link that was never going to be a rule must
/// not block the load. A check that fires on ordinary directories is a check
/// examiners learn to route around.
#[test]
#[cfg(unix)]
fn a_dangling_non_rule_symlink_is_ignored() {
    let dir = rule_dir(&[("base.yar", RULES)]);
    std::os::unix::fs::symlink(dir.path().join("gone.txt"), dir.path().join("notes.txt"))
        .expect("symlink");
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("rules must load");
    assert_eq!(scanner.rule_count(), 2);
}

// --- Module identity ----------------------------------------------------------

#[test]
fn module_identity() {
    let (_dir, s) = default_scanner();
    assert_eq!(s.id(), MODULE_ID);
    assert_eq!(s.id(), "plugin.detection.yara");
    assert!(s.subscribes_to().contains(&ArtifactType::FileEntry));
}

/// Scanning every artifact in a case through a JIT-compiled rule set is far too
/// expensive for a baseline ingest, so this module is examiner-triggered like
/// the deep carver and OCR.
#[test]
fn execution_mode_is_opt_in() {
    let (_dir, s) = default_scanner();
    assert_eq!(s.execution_mode(), ExecutionMode::OptIn);
}

// --- Matching -----------------------------------------------------------------

#[test]
fn matches_a_string_rule() {
    let (_dir, scanner) = default_scanner();
    assert_eq!(scanner.rule_count(), 2);
    let out = run(&scanner, b"prefix X5O!P%@AP-MARKER suffix".to_vec());
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "YaraMatch");
    assert_eq!(m["rule"], "eicar_like");
    assert_eq!(m["rules_in_set"], json!(2));
    let tags: Vec<String> = m["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    assert!(tags.contains(&"malware".to_string()));
    assert_eq!(out[0].artifact_type, ArtifactType::ParsedRecord);
    assert!(out[0].parent_id.is_some());
}

#[test]
fn matches_a_hex_rule_at_offset() {
    let (_dir, scanner) = default_scanner();
    let out = run(&scanner, b"MZ\x90\x00 rest of a fake PE".to_vec());
    let rules: Vec<&str> = out
        .iter()
        .map(|a| a.metadata["rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, vec!["has_mz"]);
}

/// The one case where an empty result set is honest: the whole object was read
/// and no rule fired.
#[test]
fn a_fully_scanned_non_matching_object_yields_nothing() {
    let (_dir, scanner) = default_scanner();
    assert!(run(&scanner, b"nothing interesting here".to_vec()).is_empty());
}

// --- Coverage honesty ---------------------------------------------------------

use seance_core::test_support::TruncatedSource;

fn process_source(scanner: &YaraScanner, ds: Option<Arc<dyn DataSource>>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        ds,
        json!({ "name": "target.bin" }),
    );
    scanner.process(&art).unwrap()
}

/// A file scanned end to end must not claim it was only partly examined.
#[test]
fn a_fully_scanned_file_emits_no_coverage_record() {
    let (_dir, scanner) = default_scanner();
    let out = run(&scanner, b"nothing interesting here".to_vec());
    assert!(records_of(&out, "YaraPartialScan").is_empty());
    assert!(records_of(&out, "YaraNotScanned").is_empty());
}

/// When only a prefix was scanned, "no matches" is not "clean": the record says
/// so, so an empty result set cannot be read as an all-clear.
#[test]
fn a_partially_scanned_file_says_only_a_prefix_was_examined() {
    let (_dir, scanner) = default_scanner();
    let bytes = b"nothing interesting here".to_vec();
    let declared = bytes.len() as u64 * 4;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes.clone(), declared));
    let out = process_source(&scanner, Some(ds));
    let marker = records_of(&out, "YaraPartialScan")
        .into_iter()
        .next()
        .expect("a partial scan must be reported");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(marker.metadata["bytes_scanned"], json!(bytes.len() as u64));
    assert_eq!(marker.metadata["declared_size"], json!(declared));
    assert_eq!(marker.metadata["matches_in_scanned_prefix"], json!(0));
}

/// An artifact with no attached content was NOT scanned. Returning nothing here
/// is indistinguishable from a completed scan that found nothing.
#[test]
fn an_artifact_without_content_is_reported_as_not_scanned() {
    let (_dir, scanner) = default_scanner();
    let out = process_source(&scanner, None);
    let rec = records_of(&out, "YaraNotScanned")
        .into_iter()
        .next()
        .expect("an unscanned artifact must say so");
    assert_eq!(rec.metadata["content_incomplete"], json!(true));
    assert_eq!(rec.metadata["rules_in_set"], json!(2));
    assert!(rec.parent_id.is_some());
}

/// A source that declares bytes but yields none was not scanned either.
#[test]
fn unreadable_content_is_reported_as_not_scanned() {
    let (_dir, scanner) = default_scanner();
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(Vec::new(), 4096));
    let out = process_source(&scanner, Some(ds));
    let rec = records_of(&out, "YaraNotScanned")
        .into_iter()
        .next()
        .expect("an unreadable artifact must say so");
    assert_eq!(rec.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(rec.metadata["declared_size"], json!(4096u64));
    // Crucially it is NOT reported as a completed, match-free scan.
    assert!(records_of(&out, "YaraMatch").is_empty());
}

/// `matches_in_scanned_prefix` is read as "this many rules fired in the part
/// that was examined", so it must count match records and nothing else. The
/// engine-failure record travels on its own channel out of `scan` precisely so
/// it can never be swept into this number.
#[test]
fn the_partial_scan_count_counts_matches_only() {
    let (_dir, scanner) = default_scanner();
    let bytes = b"prefix X5O!P%@AP-MARKER suffix".to_vec();
    let declared = bytes.len() as u64 * 4;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let out = process_source(&scanner, Some(ds));
    let matches = records_of(&out, "YaraMatch").len();
    assert_eq!(matches, 1, "the marker is inside the readable prefix");
    let marker = records_of(&out, "YaraPartialScan")
        .into_iter()
        .next()
        .expect("a partial scan must be reported");
    assert_eq!(
        marker.metadata["matches_in_scanned_prefix"],
        json!(matches),
        "the reported count must equal the match records actually emitted"
    );
}

/// A genuinely empty file is scanned (yielding nothing) rather than reported as
/// unscanned — the distinction the coverage records exist to preserve.
#[test]
fn a_genuinely_empty_file_is_scanned_not_flagged() {
    let (_dir, scanner) = default_scanner();
    let out = run(&scanner, Vec::new());
    assert!(out.is_empty(), "unexpected records: {out:?}");
}
