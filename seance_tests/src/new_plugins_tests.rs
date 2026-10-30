use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::FileDataSource,
    module::ForensicsModule,
};
use seance_plugin_jumplists::JumpListParser;
use seance_plugin_lnk::LnkParser;
use seance_plugin_shellbags::ShellBagsPlugin;
use std::path::Path;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

/// True when this artifact is a parser DISCLOSURE record — a statement about
/// what the parse or carve covered, not something recovered from the evidence.
///
/// These share one shape across the plugins: a data-less `ParsedRecord` whose
/// metadata carries both a `record_type` naming it (`lnk_parse_status`,
/// `jumplist_carve_status`, `registry_hive_parse_status`,
/// `shellbag_walk_truncated`, `logfile_parse_status`) and the `message`
/// sentence explaining the shortfall. No record recovered from evidence carries
/// `message`.
///
/// They exist so that "scanned and found nothing" stops looking like "never
/// examined", which means every one of these parsers now emits at least one
/// artifact on the paths where it recovers nothing at all. Counting them as
/// output is therefore the one thing that must not happen here.
fn is_disclosure_record(a: &Artifact) -> bool {
    a.artifact_type == ArtifactType::ParsedRecord
        && a.data.is_none()
        && a.metadata
            .get("record_type")
            .and_then(|v| v.as_str())
            .is_some()
        && a.metadata
            .get("message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| !m.is_empty())
}

/// Run a parser against a real fixture and require at least `min_artifacts`
/// RECOVERED results. Skip-if-absent is preserved, but when the fixture IS
/// present this is a real known-answer check, not a smoke test that passes on
/// zero output.
///
/// `min_artifacts` deliberately counts only recovered artifacts. Asserting on
/// `artifacts.len()` was a known-answer check until these parsers gained their
/// disclosure records (B5-040 and siblings); after that, a JumpList that carved
/// no shortcut, an unreadable `.lnk` and a hive that yielded no bags each
/// produce exactly one artifact, so `len() >= 1` could no longer fail and the
/// behaviour in each test's name went untested.
fn run_parser_test<M: ForensicsModule>(
    parser: M,
    file_path: &Path,
    artifact_type: ArtifactType,
    metadata: serde_json::Value,
    test_name: &str,
    min_artifacts: usize,
) {
    if !file_path.exists() {
        eprintln!("Skipping {} test: {:?} not found", test_name, file_path);
        return;
    }

    info!("Testing {} on: {:?}", test_name, file_path);
    let case_id = Uuid::new_v4();
    let source = FileDataSource::new(file_path.to_path_buf())
        .unwrap_or_else(|e| panic!("Failed to open {:?}: {}", file_path, e));
    let artifact = Artifact::new(case_id, artifact_type, Some(Arc::new(source)), metadata);

    let artifacts = parser
        .process(&artifact)
        .unwrap_or_else(|e| panic!("{} parsing failed: {}", test_name, e));

    let (disclosures, recovered): (Vec<&Artifact>, Vec<&Artifact>) =
        artifacts.iter().partition(|a| is_disclosure_record(a));
    println!(
        "{} produced {} artifacts ({} recovered, {} disclosure)",
        test_name,
        artifacts.len(),
        recovered.len(),
        disclosures.len()
    );

    assert!(
        recovered.len() >= min_artifacts,
        "{}: expected >= {} RECOVERED artifacts from {:?}, got {} \
         ({} of the {} produced were disclosure records, which state what the \
         parse covered and are not evidence recovered from it)",
        test_name,
        min_artifacts,
        file_path,
        recovered.len(),
        disclosures.len(),
        artifacts.len()
    );

    // Every recovered artifact must be traceable to the file it came from and
    // to the case: an untraceable record cannot be put in front of a court.
    for a in &recovered {
        assert_eq!(
            a.case_id, case_id,
            "{}: a recovered artifact left the parser under a different case",
            test_name
        );
        assert_eq!(
            a.parent_id,
            Some(artifact.id),
            "{}: a recovered artifact does not name the file it was parsed from",
            test_name
        );
    }
}

#[test]
fn test_lnk_parser() {
    run_parser_test(
        LnkParser,
        Path::new("../test_data/example.lnk"),
        ArtifactType::FileEntry,
        serde_json::json!({ "name": "example.lnk" }),
        "LNK Parser",
        1,
    );
}

#[test]
fn test_jumplist_parser() {
    run_parser_test(
        JumpListParser,
        Path::new("../test_data/automatic_destinations/1b4dd67f29cb1962.automaticDestinations-ms"),
        ArtifactType::FileEntry,
        serde_json::json!({ "name": "1b4dd67f29cb1962.automaticDestinations-ms" }),
        "JumpList Parser",
        1,
    );
}

#[test]
fn test_shellbags_parser() {
    // NTUSER.DAT carries the BagMRU shellbag keys; the parser handles both the
    // NTUSER (Software\...\Shell\BagMRU) and UsrClass paths. Previously this
    // probed a non-existent UsrClass.dat, so ShellBags had zero real coverage.
    run_parser_test(
        ShellBagsPlugin,
        Path::new("../test_data/NTUSER.DAT"),
        ArtifactType::FileEntry,
        serde_json::json!({ "name": "NTUSER.DAT" }),
        "ShellBags Parser",
        1,
    );
}
