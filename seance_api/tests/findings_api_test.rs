//! The ranked triage list (§2.2).
//!
//! Two assertions here carry most of the weight, and neither is about ranking.
//!
//! [`an_empty_list_says_what_this_build_can_even_look_for`] — "no findings"
//! means either "nothing matched the detections this build has" or "nothing
//! here looks for what you are after". While this layer is being built out the
//! second is usually the truth, and a screen that cannot tell them apart
//! invites an examiner to conclude the case is clean.
//!
//! [`every_finding_is_graded_a_lead_and_keeps_its_inference_separate`] — a
//! finding is this tool's own claim about the evidence. Part VI of the roadmap
//! forbids rendering that beside a parsed artifact as though the two were
//! established the same way, and the grade plus the observation/inference split
//! are how that is kept true at the API boundary rather than by convention in
//! each screen.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    finding::{Confidence, EvidenceItem, Finding},
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn finding(kind: &str, title: &str, confidence: Confidence) -> Finding {
    Finding {
        kind: kind.to_string(),
        title: title.to_string(),
        subject_artifact: Uuid::new_v4(),
        confidence,
        observation: format!("the invariant behind {title} broke"),
        evidence: vec![EvidenceItem::new("si_modified", "2019-03-02T11:14:08Z")],
        inference: Some("this is what tampering looks like".to_string()),
        qualification: "it is also what a restore from backup looks like".to_string(),
        device_offset: Some(4096),
        source_module: "plugin.findings.timestomp".to_string(),
    }
}

async fn setup(findings: Vec<Finding>) -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Findings", "examiner").await.unwrap();

    for f in &findings {
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            f.to_metadata(),
        ))
        .await
        .unwrap();
    }
    // An ordinary record, which must never appear in the findings list.
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({"type": "WhatsApp", "body": "hello"}),
    ))
    .await
    .unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: None,
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    (app, case_id)
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn findings_are_ranked_most_confident_first_and_counted_by_kind() {
    let (app, case_id) = setup(vec![
        finding("timestomp", "b weak one", Confidence::Weak),
        finding("pe_in_ads", "a strong one", Confidence::Strong),
        finding("timestomp", "a notable one", Confidence::Notable),
        finding("timestomp", "z notable one", Confidence::Notable),
    ])
    .await;

    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = body["findings"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        4,
        "the ordinary record is not a finding: {body}"
    );

    // Strongest first; within a confidence, by kind then title, so a list
    // quoted into a statement reads the same tomorrow.
    let order: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(
        order,
        [
            "a strong one",
            "a notable one",
            "z notable one",
            "b weak one"
        ],
        "{body}"
    );

    assert_eq!(body["by_confidence"]["strong"], 1);
    assert_eq!(body["by_confidence"]["notable"], 2);
    assert_eq!(body["by_confidence"]["weak"], 1);
    assert_eq!(body["by_kind"]["timestomp"], 3);
    assert_eq!(body["by_kind"]["pe_in_ads"], 1);
    assert_eq!(body["total"], 4);
    assert_eq!(body["truncated"], false);

    // Each row can be opened and cited.
    assert!(Uuid::parse_str(rows[0]["artifact_id"].as_str().unwrap()).is_ok());
}

#[tokio::test]
async fn every_finding_is_graded_a_lead_and_keeps_its_inference_separate() {
    let (app, case_id) = setup(vec![finding(
        "timestomp",
        "reordered timestamps",
        Confidence::Notable,
    )])
    .await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;

    // Said once for the list...
    assert_eq!(body["grade"], "investigative_lead");
    assert!(body["grade_note"]
        .as_str()
        .unwrap()
        .contains("never a conclusion"));

    // ...and on every row, so a client rendering one row in isolation cannot
    // lose it.
    let row = &body["findings"][0];
    assert_eq!(row["grade"], "investigative_lead");
    // The checkable part and the opinion are separate fields. A renderer that
    // shows only `observation` shows only what can be verified.
    assert!(row["observation"].as_str().unwrap().contains("invariant"));
    assert!(row["inference"].as_str().unwrap().contains("tampering"));
    assert!(row["qualification"]
        .as_str()
        .unwrap()
        .contains("restore from backup"));
    // The values it rests on, addressable by name.
    assert_eq!(row["evidence"][0]["name"], "si_modified");
    assert_eq!(row["evidence"][0]["value"], "2019-03-02T11:14:08Z");
    // And what it is about.
    assert!(Uuid::parse_str(row["subject_artifact_id"].as_str().unwrap()).is_ok());
}

#[tokio::test]
async fn an_empty_list_says_what_this_build_can_even_look_for() {
    let (app, case_id) = setup(vec![]).await;
    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["total"], 0);
    assert!(body["findings"].as_array().unwrap().is_empty());

    // The detections this build carries are named, so "no findings" cannot be
    // read as "nothing is wrong with this case".
    let detections = body["detections"].as_array().unwrap();
    assert!(!detections.is_empty(), "{body}");
    assert!(
        detections
            .iter()
            .any(|d| d["kind"] == "timestomp" && d["looks_for"].as_str().is_some()),
        "a detection must say what it looks for: {body}"
    );
    // And the sentence spells out what the emptiness does and does not mean.
    let note = body["absence_note"].as_str().unwrap();
    assert!(note.contains("No findings"), "{note}");
    assert!(
        note.contains("says nothing about patterns no detection here looks for"),
        "{note}"
    );
}

#[tokio::test]
async fn a_populated_list_still_says_what_it_did_not_look_for() {
    // The same honesty in the other direction: four findings must not read as
    // "these are the four things wrong with this case".
    let (app, case_id) = setup(vec![finding("timestomp", "one", Confidence::Notable)]).await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    let note = body["absence_note"].as_str().unwrap();
    assert!(note.contains("detection(s) this build carries"), "{note}");
    assert!(
        note.contains("would not appear whatever the evidence holds"),
        "{note}"
    );
}

/// Every declared detection must be a module this build actually registers,
/// and every findings module must be declared.
///
/// The declaration is what makes an empty list readable, so a detection added
/// without a line in `FINDING_DETECTIONS` would silently go back to the state
/// this whole mechanism exists to prevent: a screen that cannot say what it
/// looked for. The reverse matters too — a declared detection whose module is
/// not registered would promise an examiner a check that never runs.
#[test]
fn findings_detections_match_registered_modules() {
    use seance_core::orchestrator::Orchestrator;

    let dir = tempfile::tempdir().expect("temp dir");
    let search = Arc::new(seance_search::SearchService::new(dir.path()).expect("search service"));
    let orchestrator = Orchestrator::new(None, 10);
    let modules = seance_api::modules::build_module_set(
        &orchestrator,
        seance_api::modules::ModuleSetOptions {
            search_service: search,
            carver_defs: None,
            unlock: Default::default(),
            yara_rules: None,
            memory_regex: None,
            memory_strings: None,
        },
    )
    .expect("module set builds");

    let registered: Vec<String> = modules
        .iter()
        .map(|m| m.id().to_string())
        .filter(|id| id.starts_with("plugin.findings."))
        .collect();

    // The cross-view detections (§2.2 items 3 and 6) are not modules and
    // cannot be: a module sees artifacts as they are produced, so "no file
    // entry for this program" would be true of most of a healthy system
    // directory until the filesystem walk finished. They are checked against
    // `CROSS_VIEW_KINDS` below instead, which is what stands in for the module
    // registry for them.
    let declared: Vec<String> = seance_api::FINDING_DETECTIONS
        .iter()
        .map(|(_, module, _)| (*module).to_string())
        .filter(|m| m.starts_with("plugin.findings."))
        .collect();

    let mut missing_declaration: Vec<&String> = registered
        .iter()
        .filter(|m| !declared.contains(m))
        .collect();
    missing_declaration.sort();
    assert!(
        missing_declaration.is_empty(),
        "these findings modules are registered but not declared in FINDING_DETECTIONS, so an \
         empty findings list would not name what they look for: {missing_declaration:?}"
    );

    let mut missing_module: Vec<&String> = declared
        .iter()
        .filter(|m| !registered.contains(m))
        .collect();
    missing_module.sort();
    assert!(
        missing_module.is_empty(),
        "these detections are declared but their module is not registered, so the response \
         promises a check that never runs: {missing_module:?}"
    );

    assert!(
        !declared.is_empty(),
        "the findings layer must declare at least one detection"
    );

    // The cross-view half. Same obligation, different register: the kinds the
    // response promises must be exactly the kinds the pass can raise, or an
    // empty list either hides a detection or advertises one that does not
    // exist.
    let mut declared_cross: Vec<&str> = seance_api::FINDING_DETECTIONS
        .iter()
        .filter(|(_, module, _)| {
            *module == seance_plugin_findings::cross_view::CROSS_VIEW_MODULE_ID
        })
        .map(|(kind, _, _)| *kind)
        .collect();
    declared_cross.sort_unstable();
    let mut real_cross: Vec<&str> = seance_plugin_findings::cross_view::CROSS_VIEW_KINDS.to_vec();
    real_cross.sort_unstable();
    assert_eq!(
        declared_cross, real_cross,
        "the cross-view detections the response names must be exactly the ones the pass raises"
    );

    // And nothing may be declared against a module that is neither.
    let stray: Vec<&str> = seance_api::FINDING_DETECTIONS
        .iter()
        .map(|(_, module, _)| *module)
        .filter(|m| {
            !m.starts_with("plugin.findings.")
                && *m != seance_plugin_findings::cross_view::CROSS_VIEW_MODULE_ID
        })
        .collect();
    assert!(
        stray.is_empty(),
        "these detections name neither a registered module nor the cross-view pass, so nothing checks that they exist: {stray:?}"
    );
}

// --- the cross-view detections (§2.2 items 3 and 6) --------------------------
//
// These are computed when the list is requested, over the completed
// populations, because a module resolving "is this program's file on the
// volume" against an index built as the walk proceeds would answer from
// whatever had been walked when the prefetch file happened to be parsed. So
// they are tested here, end to end against a database, rather than as pure
// rules — the rules themselves are tested in `seance_plugin_findings`.

/// A case with the artifacts named, and no persisted findings.
async fn setup_records(records: Vec<Artifact>) -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Cross view", "examiner").await.unwrap();
    for a in &records {
        let mut a = a.clone();
        a.case_id = case_id;
        db.record_artifact(&a).await.unwrap();
    }
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: None,
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    (app, case_id, db)
}

fn file_entry(name: &str, path: &str, deleted: bool) -> Artifact {
    let mut m = serde_json::json!({ "name": name, "path": path, "size": 4096 });
    if deleted {
        m["deleted"] = serde_json::json!(true);
    }
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, m)
}

fn mft_file_entry(name: &str, record: u64, sequence: u64, deleted: bool) -> Artifact {
    let mut m = serde_json::json!({
        "name": name,
        "path": format!("/Users/jsmith/{name}"),
        "record_number": record,
        "sequence_number": sequence,
    });
    if deleted {
        m["deleted"] = serde_json::json!(true);
    }
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, m)
}

fn prefetch_record(name: &str) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({
            "type": "PrefetchEntry",
            "executable_name": name,
            "run_count": 3,
            "last_execution_time": "2026-03-02T11:14:08Z",
        }),
    )
}

fn usn_delete_record(reference: &str, file_name: &str) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({
            "type": "UsnJournalEntry",
            "record_type": "usn_journal",
            "usn": "184549376",
            "file_reference": reference,
            "file_name": file_name,
            "primary_operation": "FILE_DELETE",
            "reason_flags": "0x00000200",
            "timestamp": "2026-03-02T11:14:08Z",
        }),
    )
}

fn rows_of_kind<'a>(body: &'a Value, kind: &str) -> Vec<&'a Value> {
    body["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["finding_kind"] == kind)
        .collect()
}

#[tokio::test]
async fn a_program_that_ran_with_no_file_entry_reaches_the_triage_list() {
    let (app, case_id, _db) = setup_records(vec![
        prefetch_record("DROPPER.EXE"),
        prefetch_record("SVCHOST.EXE"),
        // The volume: svchost is there, the dropper is not.
        file_entry("svchost.exe", "/Windows/System32/svchost.exe", false),
        file_entry("notes.txt", "/Users/jsmith/notes.txt", false),
    ])
    .await;

    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let absent = rows_of_kind(&body, "execution_of_absent_binary");
    assert_eq!(absent.len(), 1, "{body}");
    assert!(absent[0]["name"].as_str().unwrap().contains("DROPPER.EXE"));
    // A case-insensitive comparison, because Windows is one and the sources
    // disagree about case as a matter of course: the prefetch file says
    // SVCHOST.EXE and the MFT holds svchost.exe.
    assert_eq!(
        rows_of_kind(&body, "execution_of_absent_binary")
            .iter()
            .filter(|r| r["name"].as_str().unwrap().contains("SVCHOST"))
            .count(),
        0,
        "an exact-case comparison would call most of System32 absent: {body}"
    );

    // A cross-view row has no artifact of its own and says so, because it is
    // not in the database, the search index or the timeline.
    assert_eq!(absent[0]["persisted"], serde_json::json!(false));
    assert!(absent[0]["not_persisted_note"]
        .as_str()
        .unwrap()
        .contains("no artifact of its own"));
    assert!(absent[0]["subject_artifact_id"].is_string());

    // And the response accounts for the pass itself.
    assert_eq!(body["cross_view"]["ran"], serde_json::json!(true));
    assert_eq!(body["cross_view"]["complete"], serde_json::json!(true));
    assert_eq!(
        body["cross_view"]["file_entries_compared_against"],
        serde_json::json!(2)
    );
    assert_eq!(body["total"], serde_json::json!(1));
}

#[tokio::test]
async fn a_program_whose_only_file_entry_is_deleted_is_a_different_finding() {
    let (app, case_id, _db) = setup_records(vec![
        prefetch_record("DROPPER.EXE"),
        file_entry("dropper.exe", "/Windows/Temp/dropper.exe", true),
        file_entry("notes.txt", "/Users/jsmith/notes.txt", false),
    ])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert!(
        rows_of_kind(&body, "execution_of_absent_binary").is_empty(),
        "the file entry is there; it is deleted, which is a different fact: {body}"
    );
    let deleted = rows_of_kind(&body, "execution_of_deleted_binary");
    assert_eq!(deleted.len(), 1, "{body}");
    assert!(deleted[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["name"] == "deleted_entry"
            && e["value"].as_str().unwrap().contains("dropper.exe")));
}

/// A live copy anywhere in the case answers the question, and the answer is
/// "it is there". Most of a real case is this.
#[tokio::test]
async fn a_program_with_a_live_copy_raises_nothing_even_if_another_copy_is_deleted() {
    let (app, case_id, _db) = setup_records(vec![
        prefetch_record("APP.EXE"),
        file_entry("app.exe", "/Program Files/Vendor/app.exe", false),
        file_entry("app.exe", "/Windows/Temp/app.exe", true),
    ])
    .await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert_eq!(
        body["cross_view"]["findings"],
        serde_json::json!(0),
        "{body}"
    );
}

/// A case with no filesystem cannot be asked whether a program's file is on
/// the volume, and answering anyway would report every program the machine
/// ever ran as absent from a volume nobody looked at.
#[tokio::test]
async fn a_case_with_no_file_entries_declines_the_question_rather_than_answering_it() {
    let (app, case_id, _db) = setup_records(vec![prefetch_record("DROPPER.EXE")]).await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;

    assert_eq!(body["cross_view"]["ran"], serde_json::json!(false));
    assert_eq!(body["cross_view"]["findings"], serde_json::json!(0));
    let why = body["cross_view"]["declined"].as_str().unwrap();
    assert!(why.contains("the question was not asked"), "{why}");
    // And the absence note carries it, so a reader of the list alone is told.
    assert!(body["absence_note"]
        .as_str()
        .unwrap()
        .contains("the question was not asked"));
}

#[tokio::test]
async fn a_journal_delete_the_mft_contradicts_reaches_the_triage_list() {
    let (app, case_id, _db) = setup_records(vec![
        usn_delete_record("4712-3", "notes.txt"),
        // Same record, same sequence, still in use: a contradiction.
        mft_file_entry("notes.txt", 4712, 3, false),
        // Same record at the next sequence holding a different file: the
        // ordinary case, and reporting it would fire on every busy volume.
        usn_delete_record("9001-2", "old.tmp"),
        mft_file_entry("recycled.dat", 9001, 3, false),
        file_entry("other.txt", "/Users/jsmith/other.txt", false),
    ])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    let rows = rows_of_kind(&body, "usn_delete_contradicts_mft");
    assert_eq!(rows.len(), 1, "{body}");
    assert!(rows[0]["name"].as_str().unwrap().contains("notes.txt"));
    assert!(rows[0]["observation"]
        .as_str()
        .unwrap()
        .contains("sequence 3"));
    // The finding opens the MFT entry, which is the record to read against the
    // journal.
    assert!(rows[0]["subject_artifact_id"].is_string());
}

/// A reused record is the normal state of a busy volume, and the sequence
/// number is the only thing that separates it from a contradiction.
#[tokio::test]
async fn a_reused_mft_record_does_not_contradict_the_journal() {
    let (app, case_id, _db) = setup_records(vec![
        usn_delete_record("4712-3", "notes.txt"),
        mft_file_entry("notes.txt", 4712, 4, false),
        file_entry("other.txt", "/Users/jsmith/other.txt", false),
    ])
    .await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    assert!(
        rows_of_kind(&body, "usn_delete_contradicts_mft").is_empty(),
        "{body}"
    );
}

/// The persisted and the computed rows are ranked together — an examiner
/// reading top-down wants the strongest lead first, whichever half raised it —
/// and each row says which it is.
#[tokio::test]
async fn cross_view_rows_rank_alongside_the_persisted_ones_and_are_labelled() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Mixed", "examiner").await.unwrap();

    // A persisted Strong finding, raised during ingest by a module.
    let mut strong = finding("pe_signature_mismatch", "a strong one", Confidence::Strong);
    strong.source_module = "plugin.findings.pe".into();
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        strong.to_metadata(),
    ))
    .await
    .unwrap();

    for a in [
        prefetch_record("DROPPER.EXE"),
        file_entry("notes.txt", "/Users/jsmith/notes.txt", false),
    ] {
        let mut a = a;
        a.case_id = case_id;
        db.record_artifact(&a).await.unwrap();
    }

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app = router_with_auth(
        AppState {
            db: db.clone(),
            orchestrator_sender: orchestrator.task_submitter(),
            event_sender: orchestrator.event_sender(),
            ad_hoc_sender: orchestrator.ad_hoc_submitter(),
            status_sender: orchestrator.status_sender(),
            active_tasks: orchestrator.active_tasks(),
            search_service: None,
            ingestion_service: orchestrator.ingestion_service(),
            module_registry: vec![],
            signing_config: None,
            evidence_roots: EvidenceRootPolicy::unrestricted(),
            cancellation: CancellationHandle::new(),
        },
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/findings")).await;
    let rows = body["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{body}");
    // Strong first, whichever half raised it.
    assert_eq!(rows[0]["confidence"], serde_json::json!("strong"));
    assert_eq!(rows[0]["persisted"], serde_json::json!(true));
    assert!(rows[0]["artifact_id"].is_string());
    assert_eq!(rows[1]["persisted"], serde_json::json!(false));
    assert!(
        rows[1].get("artifact_id").is_none(),
        "a computed row must not offer an artifact id it does not have: {body}"
    );
    // The totals count both halves, or the list would read as truncated.
    assert_eq!(body["total"], serde_json::json!(2));
    assert_eq!(body["truncated"], serde_json::json!(false));
    assert_eq!(body["by_confidence"]["strong"], serde_json::json!(1));
    assert_eq!(body["by_confidence"]["notable"], serde_json::json!(1));
}
