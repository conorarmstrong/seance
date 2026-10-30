//! The decompression ceiling reaches the report's method-qualifications section.
//!
//! `seance_container_archive` stamps every successfully expanded gzip/bzip2/xz
//! container with the ceiling that admitted it. That stamp is the only place the
//! figure survives: a CLI ingest and the process that renders the report are
//! different programs, and the reporting one reading its own environment would
//! quote a number that governed none of this evidence. These tests pin that the
//! report takes the figure off the artifact, says whether an examiner chose it,
//! and says it once however many containers were expanded.

use seance_api::{gather_report_data, AppState, EvidenceRootPolicy};
use seance_container_archive::limits;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

async fn setup() -> (AppState, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Decompression Ceiling", "examiner")
        .await
        .unwrap();
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

/// One expanded container's child, stamped as the expanders stamp it.
fn expanded(case_id: Uuid, name: &str, bytes: u64, source: &str) -> Artifact {
    let mut metadata = json!({ "name": name });
    let obj = metadata.as_object_mut().unwrap();
    obj.insert(limits::CEILING_BYTES_KEY.to_string(), json!(bytes));
    obj.insert(limits::CEILING_SOURCE_KEY.to_string(), json!(source));
    Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
}

/// The entries that state a ceiling. Told apart by subject rather than by a
/// phrase in the prose, because the census's own disclosure below talks about
/// decompression ceilings too and the two must never be counted as one.
fn ceiling_qualifications(
    data: &seance_reporting::ReportData,
) -> Vec<&seance_reporting::MethodQualification> {
    data.method_qualifications
        .iter()
        .filter(|q| q.subject == seance_api::CEILING_QUALIFICATION_SUBJECT)
        .collect()
}

/// The entry that says the ceilings above were read from part of the case only.
fn census_gap(
    data: &seance_reporting::ReportData,
) -> Option<&seance_reporting::MethodQualification> {
    data.method_qualifications
        .iter()
        .find(|q| q.subject == seance_api::CEILING_CENSUS_GAP_SUBJECT)
}

/// A case holding `count` stamped containers, all admitted under `bytes`.
async fn record_expanded(
    db: &SqliteConnection,
    case_id: Uuid,
    count: u32,
    bytes: u64,
    source: &str,
) {
    // Recorded in batches so a test that has to cross a paging boundary is
    // still a test rather than a wait.
    for batch in 0..count.div_ceil(1_000) {
        let first = batch * 1_000;
        let last = (first + 1_000).min(count);
        let artifacts: Vec<Artifact> = (first..last)
            .map(|i| expanded(case_id, &format!("part{i}.gz"), bytes, source))
            .collect();
        db.record_artifacts_batch(&artifacts).await.unwrap();
    }
}

#[tokio::test]
async fn a_case_with_no_expanded_container_says_nothing_about_a_ceiling() {
    let (state, case_id, db) = setup().await;
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "loose.txt"}),
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    // The keys never appear on a refusal, so their absence means nothing was
    // expanded under a ceiling — and a run-scoped setting that governed no
    // evidence is not a fact about this evidence.
    assert!(ceiling_qualifications(&data).is_empty());
}

#[tokio::test]
async fn the_default_ceiling_is_reported_as_nobody_having_chosen_it() {
    let (state, case_id, db) = setup().await;
    db.record_artifact(&expanded(
        case_id,
        "payload.tar",
        limits::DEFAULT_MAX_DECOMPRESSED,
        "default",
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let quals = ceiling_qualifications(&data);
    assert_eq!(quals.len(), 1, "{:?}", data.method_qualifications);

    let statement = &quals[0].statement;
    // The wording lives in one place so the admission and the refusal cannot
    // drift apart; the report quotes it rather than composing a second version.
    assert_eq!(
        *statement,
        limits::ceiling_statement(limits::Ceiling {
            bytes: limits::DEFAULT_MAX_DECOMPRESSED,
            from_env: false,
        })
    );
    assert!(statement.contains(&limits::DEFAULT_MAX_DECOMPRESSED.to_string()));
    assert!(
        statement.contains("built-in default"),
        "must distinguish 10 GiB by default from 10 GiB by choice: {statement}"
    );
    assert!(
        quals[0].affects.is_some(),
        "a ceiling bears on part of the report, not all of it"
    );
}

#[tokio::test]
async fn a_ceiling_an_examiner_set_is_reported_as_a_decision() {
    let (state, case_id, db) = setup().await;
    let chosen = 40 * 1024 * 1024 * 1024;
    db.record_artifact(&expanded(
        case_id,
        "backup.tar.gz",
        chosen,
        limits::MAX_DECOMPRESSED_VAR,
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let quals = ceiling_qualifications(&data);
    assert_eq!(quals.len(), 1, "{:?}", data.method_qualifications);
    assert_eq!(
        quals[0].statement,
        limits::ceiling_statement(limits::Ceiling {
            bytes: chosen,
            from_env: true,
        })
    );
    assert!(
        quals[0].statement.contains(limits::MAX_DECOMPRESSED_VAR),
        "must name the knob that was turned: {}",
        quals[0].statement
    );
    assert!(
        quals[0].statement.contains(&chosen.to_string()),
        "must quote the figure off the artifact, not this process's environment: {}",
        quals[0].statement
    );
}

#[tokio::test]
async fn a_figure_with_no_recognised_source_is_not_stated_at_all() {
    let (state, case_id, db) = setup().await;
    let mut metadata = json!({ "name": "orphan.gz" });
    metadata.as_object_mut().unwrap().insert(
        limits::CEILING_BYTES_KEY.to_string(),
        json!(40 * 1024 * 1024 * 1024u64),
    );
    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        metadata,
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    // Every sentence about the ceiling turns on whether an examiner chose it.
    // With the source half missing, the figure alone cannot be stated without
    // inventing the answer to that question.
    assert!(
        ceiling_qualifications(&data).is_empty(),
        "{:?}",
        data.method_qualifications
    );
}

#[tokio::test]
async fn one_ceiling_is_stated_once_however_many_containers_it_admitted() {
    let (state, case_id, db) = setup().await;
    for i in 0..12 {
        db.record_artifact(&expanded(
            case_id,
            &format!("part{i}.gz"),
            limits::DEFAULT_MAX_DECOMPRESSED,
            "default",
        ))
        .await
        .unwrap();
    }

    let data = gather_report_data(&state, case_id).await.unwrap();
    // A run-scoped setting restated per artifact would bury the report.
    assert_eq!(ceiling_qualifications(&data).len(), 1);
}

#[tokio::test]
async fn two_different_ceilings_are_both_stated() {
    let (state, case_id, db) = setup().await;
    db.record_artifact(&expanded(
        case_id,
        "first.gz",
        limits::DEFAULT_MAX_DECOMPRESSED,
        "default",
    ))
    .await
    .unwrap();
    db.record_artifact(&expanded(
        case_id,
        "second.gz",
        40 * 1024 * 1024 * 1024,
        limits::MAX_DECOMPRESSED_VAR,
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    // A case ingested across two runs was governed by two ceilings, and
    // collapsing them would put one figure over evidence it never admitted.
    let quals = ceiling_qualifications(&data);
    assert_eq!(quals.len(), 2, "{:?}", data.method_qualifications);
}

/// The ordinary shape of the mixed-ceiling case: a first ingest expands a great
/// many containers under the default, a later one raises the ceiling for a
/// handful. The raised ceiling's containers sort last, so a census that reads
/// only an opening window of stamped artifacts never sees them and the report
/// states the default alone — as a fact about the case.
#[tokio::test]
async fn a_ceiling_raised_after_a_hundred_default_containers_is_still_stated() {
    let (state, case_id, db) = setup().await;
    let mut first = Vec::new();
    for i in 0..100 {
        first.push(expanded(
            case_id,
            &format!("log{i}.gz"),
            limits::DEFAULT_MAX_DECOMPRESSED,
            "default",
        ));
    }
    db.record_artifacts_batch(&first).await.unwrap();
    let mut second = Vec::new();
    for i in 0..5 {
        second.push(expanded(
            case_id,
            &format!("backup{i}.tar.gz"),
            64 * 1024 * 1024 * 1024,
            limits::MAX_DECOMPRESSED_VAR,
        ));
    }
    db.record_artifacts_batch(&second).await.unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let quals = ceiling_qualifications(&data);
    assert_eq!(
        quals.len(),
        2,
        "the raised ceiling admitted five containers of this evidence and has to be \
         stated: {:?}",
        data.method_qualifications
    );
    assert!(
        quals
            .iter()
            .any(|q| q.statement.contains(limits::MAX_DECOMPRESSED_VAR)
                && q.statement.contains("set for this run")),
        "{:?}",
        data.method_qualifications
    );
    // The whole case was read, so nothing is owed to the reader about gaps.
    assert!(census_gap(&data).is_none());
}

/// The census reads the stamps a page at a time. A ceiling whose containers all
/// sort past the first page is still a ceiling this evidence was opened under.
#[tokio::test]
async fn a_ceiling_stamped_past_the_first_page_of_the_census_is_still_stated() {
    let (state, case_id, db) = setup().await;
    record_expanded(
        &db,
        case_id,
        seance_api::CEILING_CENSUS_PAGE,
        limits::DEFAULT_MAX_DECOMPRESSED,
        "default",
    )
    .await;
    db.record_artifact(&expanded(
        case_id,
        "late.tar.gz",
        64 * 1024 * 1024 * 1024,
        limits::MAX_DECOMPRESSED_VAR,
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let quals = ceiling_qualifications(&data);
    assert_eq!(
        quals.len(),
        2,
        "the ceiling on the far side of the page boundary governed real evidence: {:?}",
        data.method_qualifications
    );
    // Every stamped container was read, so each entry's count is a total and
    // says so, and there is no gap to disclose.
    assert!(census_gap(&data).is_none());
    let default_entry = quals
        .iter()
        .find(|q| q.statement.contains("the built-in default:"))
        .expect("the default ceiling is one of the two");
    let affects = default_entry.affects.as_deref().unwrap();
    assert!(
        affects.contains(&seance_api::CEILING_CENSUS_PAGE.to_string())
            && !affects.contains("at least"),
        "a complete census counts, it does not estimate: {affects}"
    );
}

/// Past the census's budget the answer is genuinely partial, and the report has
/// to say so rather than let the ceilings it did find stand as the case's.
#[tokio::test]
async fn a_census_that_could_not_read_every_container_says_so() {
    let (state, case_id, db) = setup().await;
    let budget = seance_api::CEILING_CENSUS_PAGE * seance_api::CEILING_CENSUS_MAX_PAGES;
    record_expanded(
        &db,
        case_id,
        budget,
        limits::DEFAULT_MAX_DECOMPRESSED,
        "default",
    )
    .await;
    // Stamped last, so it lies beyond everything the census will read.
    db.record_artifact(&expanded(
        case_id,
        "beyond.tar.gz",
        64 * 1024 * 1024 * 1024,
        limits::MAX_DECOMPRESSED_VAR,
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let gap = census_gap(&data).expect("a partial census has to be disclosed as one");
    assert!(
        gap.statement.contains(&budget.to_string()),
        "the reader is owed the size of the part that was read: {}",
        gap.statement
    );
    assert!(
        gap.statement
            .contains("cannot be relied on as all of the ceilings"),
        "{}",
        gap.statement
    );
    // The ceilings that were found are still stated — but as a floor, never as
    // the whole of what governed the case.
    for qual in ceiling_qualifications(&data) {
        assert!(
            qual.affects.as_deref().unwrap().contains("at least"),
            "a count taken from part of the case is a floor: {:?}",
            qual.affects
        );
    }
}

/// A ceiling this build cannot attribute still governed the evidence.
///
/// `limits::stamp_ceiling` writes the figure and its source together, so a
/// figure carrying a source neither of this build's two recognised strings —
/// a stamp written by a later version, or a record damaged in the store — is a
/// record that cannot be read whole. The report rightly refuses to state such
/// a ceiling, because doing so would have to invent the answer to the one
/// question that matters about it: whether an examiner chose it. What it must
/// not do is fall silent as well. A section that states no ceiling and no gap
/// reads as a case no ceiling ever governed, which is the opposite of the
/// truth; the only record of it used to be a `tracing::warn!` no reader of the
/// report will ever see.
#[tokio::test]
async fn a_ceiling_whose_source_is_not_recognised_is_disclosed_as_a_gap() {
    let (state, case_id, db) = setup().await;
    db.record_artifact(&expanded(
        case_id,
        "written_by_a_later_build.gz",
        40 * 1024 * 1024 * 1024,
        "a source string this build has never heard of",
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();

    assert!(
        ceiling_qualifications(&data).is_empty(),
        "an unattributable figure must not be stated as a ceiling: {:?}",
        data.method_qualifications
    );
    let gap = census_gap(&data)
        .expect("a ceiling that could not be attributed must still reach the report as a gap");
    assert!(
        gap.statement
            .contains("cannot be relied on as all of the ceilings"),
        "the disclosure has to say what it costs the reader: {}",
        gap.statement
    );
}

/// The gap entry has to distinguish the two ways a ceiling goes unstated, since
/// the reader's next step differs: a census that ran out of budget can be
/// re-run over a narrower case, while a stamp nobody recognises is evidence
/// about the tooling that wrote it.
#[tokio::test]
async fn the_gap_entry_says_how_many_stamps_could_not_be_attributed() {
    let (state, case_id, db) = setup().await;
    for i in 0..3 {
        db.record_artifact(&expanded(
            case_id,
            &format!("unknown{i}.gz"),
            40 * 1024 * 1024 * 1024,
            "a source string this build has never heard of",
        ))
        .await
        .unwrap();
    }
    // One good stamp beside them, so the entry that IS stated must read as a
    // floor rather than as the whole of what governed the case.
    db.record_artifact(&expanded(
        case_id,
        "attributable.gz",
        limits::DEFAULT_MAX_DECOMPRESSED,
        "default",
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let gap = census_gap(&data).expect("three unattributable stamps must be disclosed");
    assert!(
        gap.statement.contains('3'),
        "the reader is owed the size of the part that could not be attributed: {}",
        gap.statement
    );
    for qual in ceiling_qualifications(&data) {
        assert!(
            qual.affects.as_deref().unwrap().contains("at least"),
            "a count taken beside records that could not be read is a floor: {:?}",
            qual.affects
        );
    }
}
