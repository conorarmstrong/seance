//! The investigative leads must reach the report, and must reach it labelled.
//!
//! §2.2 of `ROADMAP.md` sets three conditions on a finding, and Part VI is
//! where they come from: every lead is **graded**, **qualified in the report's
//! Limitations**, and **never rendered beside a parsed artifact as though
//! established the same way**. This file is those three conditions at the one
//! boundary where breaking them matters most — the document that is quoted
//! under oath.
//!
//! The condition with the sharpest edge is the second. A report carrying leads
//! and no qualification of them reads as a report whose author had no caveat to
//! make, so the qualification is generated from the presence of the section
//! rather than supplied by the examiner: there is no code path that produces
//! the leads without it.

use seance_api::{gather_report_data, AppState, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    finding::{Confidence, EvidenceItem, Finding},
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

async fn setup() -> (AppState, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Leads", "examiner").await.unwrap();
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let state = AppState {
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
    (state, case_id, db)
}

fn timestomp_finding() -> Finding {
    Finding {
        kind: "timestomp".into(),
        title: "Timestamps reordered on svchost.exe".into(),
        subject_artifact: Uuid::new_v4(),
        confidence: Confidence::Notable,
        observation: "The $SI and $FN timestamps of svchost.exe are inconsistent.".into(),
        evidence: vec![EvidenceItem::new("si_modified", "2019-03-02T11:14:08Z")],
        inference: Some("Rewriting $SI is how the time of an action is hidden.".into()),
        qualification: "It is also what a restore from backup looks like.".into(),
        device_offset: Some(4096),
        source_module: "plugin.findings.timestomp".into(),
    }
}

async fn record_finding(db: &SqliteConnection, case_id: Uuid, f: &Finding) {
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        f.to_metadata(),
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn a_lead_reaches_the_report_with_its_grade_and_its_three_parts() {
    let (state, case_id, db) = setup().await;
    record_finding(&db, case_id, &timestomp_finding()).await;

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert_eq!(data.leads.len(), 1, "the lead must reach the report");
    let lead = &data.leads[0];

    // Graded, in words a person reads aloud rather than the machine token.
    assert_eq!(lead.confidence, "Notable");
    assert_eq!(lead.kind, "timestomp");
    // The three parts arrive as three fields; nothing merged them on the way.
    assert!(lead.observation.contains("timestamps of svchost.exe"));
    assert!(lead
        .inference
        .as_deref()
        .unwrap()
        .contains("how the time of an action is hidden"));
    assert!(lead.qualification.contains("restore from backup"));
    // And the values it rests on, and where to look.
    assert_eq!(
        lead.evidence,
        vec![(
            "si_modified".to_string(),
            "2019-03-02T11:14:08Z".to_string()
        )]
    );
    assert_eq!(lead.device_offset, Some(4096));
    assert!(lead.stored_as_a_record, "this one was raised during ingest");

    // What the build could look for at all, so an empty section can be told
    // from a build that looks for nothing.
    assert!(
        data.lead_detections.len() >= 9,
        "every registered detection must be named: {:?}",
        data.lead_detections.len()
    );
    assert!(data
        .lead_detections
        .iter()
        .any(|d| d.kind == "timestomp" && d.looks_for.contains("$STANDARD_INFORMATION")));
}

/// §2.2's Limitations condition. Generated from the presence of the section, so
/// no code path produces the leads without it.
#[tokio::test]
async fn a_report_carrying_leads_always_qualifies_them_in_its_limitations() {
    let (state, case_id, db) = setup().await;
    record_finding(&db, case_id, &timestomp_finding()).await;

    let data = gather_report_data(&state, case_id).await.unwrap();
    let q = data
        .method_qualifications
        .iter()
        .find(|q| q.subject == "Investigative leads raised by the tool")
        .unwrap_or_else(|| {
            panic!(
                "a report carrying leads must qualify them: {:?}",
                data.method_qualifications
                    .iter()
                    .map(|q| &q.subject)
                    .collect::<Vec<_>>()
            )
        });
    assert!(q.statement.contains("1 investigative lead(s)"));
    assert!(q.statement.contains("have not been corroborated"));
    assert!(q.statement.contains("not that anything was established"));
    assert!(q
        .statement
        .contains("is not evidence that the pattern is absent"));
    assert_eq!(
        q.affects.as_deref(),
        Some("The Investigative Leads section only."),
        "it bears on the leads section and not on the transcriptions"
    );

    // And it survives into both rendered formats.
    let html = seance_reporting::render_html(&data);
    assert!(html.contains("Investigative Leads"), "{html}");
    assert!(html.contains("Investigative leads raised by the tool"));
    assert!(html.contains("Observation (checkable against the evidence)"));
    assert!(html.contains("What it does not establish"));
    seance_reporting::render_pdf(&data).expect("the PDF renders");
}

/// A case with no leads carries no qualification about them, because a caveat
/// invented for every examination is one a reader learns to skip.
#[tokio::test]
async fn a_report_with_no_leads_does_not_qualify_leads_it_does_not_have() {
    let (state, case_id, _db) = setup().await;
    let data = gather_report_data(&state, case_id).await.unwrap();
    assert!(data.leads.is_empty());
    assert!(!data
        .method_qualifications
        .iter()
        .any(|q| q.subject == "Investigative leads raised by the tool"));
    // The checks are still named, though: "no leads" and "nothing here looks
    // for that" are different statements about the case.
    assert!(!data.lead_detections.is_empty());
    let html = seance_reporting::render_html(&data);
    assert!(html.contains("No leads were raised"), "{html}");
    assert!(html.contains("What this build can look for"));
}

/// A whole-case check that could not be run is carried into the report's own
/// qualification. A report that shows "the checks ran and found nothing" when
/// they could not be run tells a court the machine is clean on a question
/// nobody asked.
#[tokio::test]
async fn a_report_says_when_the_whole_case_checks_could_not_be_run() {
    let (state, case_id, db) = setup().await;
    record_finding(&db, case_id, &timestomp_finding()).await;
    // A prefetch record and no filesystem: the cross-view question cannot be
    // asked at all.
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "PrefetchEntry",
            "executable_name": "DROPPER.EXE",
            "run_count": 3,
        }),
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert!(data
        .leads_coverage_note
        .as_deref()
        .unwrap()
        .contains("the question was not asked"));
    let q = data
        .method_qualifications
        .iter()
        .find(|q| q.subject == "Investigative leads raised by the tool")
        .expect("the leads qualification");
    assert!(
        q.statement.contains("the question was not asked"),
        "the coverage note must travel into Limitations: {}",
        q.statement
    );
}

/// The cross-view leads are computed for the report rather than stored, so a
/// reviewer cannot re-open the lead itself — only the subject it names. A
/// citation nobody can follow is worse than one labelled as such.
#[tokio::test]
async fn a_computed_lead_reaches_the_report_marked_as_not_stored() {
    let (state, case_id, db) = setup().await;
    // A program that ran, a filesystem that does not hold it.
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({ "type": "PrefetchEntry", "executable_name": "DROPPER.EXE", "run_count": 3 }),
    ))
    .await
    .unwrap();
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "notes.txt", "path": "/Users/jsmith/notes.txt" }),
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let lead = data
        .leads
        .iter()
        .find(|l| l.kind == "execution_of_absent_binary")
        .unwrap_or_else(|| {
            panic!(
                "the cross-view lead must reach the report: {:?}",
                data.leads
            )
        });
    assert!(
        !lead.stored_as_a_record,
        "a computed lead must not claim to be a record"
    );
    assert!(lead.title.contains("DROPPER.EXE"));

    let html = seance_reporting::render_html(&data);
    assert!(html.contains("not stored as an artifact"), "{html}");
}
