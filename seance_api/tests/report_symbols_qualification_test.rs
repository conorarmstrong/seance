//! The symbol-provenance qualification must describe the whole case.
//!
//! A memory image analysed from symbols derived out of the image itself rather
//! than from a matching symbol file is a weaker footing, and the report says so.
//! The entry is drawn from artifacts stamped `symbols_origin = "image_derived"`,
//! and until now that draw was a single 64-row window with its `total` thrown
//! away — so a case with more image-derived artifacts than that silently lost
//! every provenance statement past the sixty-fourth, with nothing on the record
//! to say a statement had been dropped.
//!
//! That is the same defect the decompression-ceiling census was fixed for, on
//! the block next to it. Its consequence is milder — an omitted qualification
//! rather than a positively false one — but a report that omits a caveat reads
//! as a report that had none to make.

use seance_api::{gather_report_data, AppState, EvidenceRootPolicy};
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
        .create_case("Symbol Provenance", "examiner")
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

/// One analysed memory image, stamped as the Linux memory tier stamps it.
async fn record_image_derived(db: &SqliteConnection, case_id: Uuid, banner: &str) {
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": format!("{banner}.mem"),
            "symbols_origin": "image_derived",
            "banner": banner,
            "symbols_provenance_statement":
                "The symbols used to read this image were derived from the image itself.",
        }),
    );
    db.record_artifact(&artifact).await.unwrap();
}

fn symbol_qualifications(
    data: &seance_reporting::ReportData,
) -> Vec<&seance_reporting::MethodQualification> {
    data.method_qualifications
        .iter()
        .filter(|q| q.subject == "Symbol source — Linux memory image")
        .collect()
}

/// The ordinary case, and the one that must not regress: one image, one entry
/// naming the kernel it belongs to.
#[tokio::test]
async fn one_image_derived_capture_states_its_symbol_source() {
    let (state, case_id, db) = setup().await;
    record_image_derived(&db, case_id, "Linux version 5.15.0-generic").await;

    let data = gather_report_data(&state, case_id).await.unwrap();
    let stated = symbol_qualifications(&data);

    assert_eq!(stated.len(), 1, "one image, one qualification: {stated:?}");
    assert!(
        stated[0]
            .affects
            .as_deref()
            .is_some_and(|a| a.contains("5.15.0-generic")),
        "the entry has to name the image it qualifies: {:?}",
        stated[0].affects
    );
}

/// **The defect.** Past the window, the statements were simply gone. A case with
/// a hundred image-derived captures reported sixty-four and said nothing about
/// the rest, so a reader counting qualifications against captures would conclude
/// thirty-six had been analysed from a matching symbol file when none had.
#[tokio::test]
async fn every_image_derived_capture_is_stated_however_many_there_are() {
    let (state, case_id, db) = setup().await;
    const CAPTURES: usize = 100;
    for n in 0..CAPTURES {
        record_image_derived(&db, case_id, &format!("Linux version 5.15.0-{n}")).await;
    }

    let data = gather_report_data(&state, case_id).await.unwrap();
    let stated = symbol_qualifications(&data);

    assert_eq!(
        stated.len(),
        CAPTURES,
        "{CAPTURES} image-derived captures produced {} qualifications; a window that \
         stops at 64 drops the rest with nothing on the record to say so",
        stated.len()
    );
    for n in 0..CAPTURES {
        let wanted = format!("5.15.0-{n}");
        assert!(
            stated
                .iter()
                .any(|q| q.affects.as_deref().is_some_and(|a| a.contains(&wanted))),
            "no qualification names the capture {wanted}"
        );
    }
}

/// The census must cross a page boundary correctly.
///
/// The previous test uses a hundred captures, which is above the old 64-row
/// window but far below `CEILING_CENSUS_PAGE`, so it never leaves page zero: an
/// off-by-one in the page offset — a capture dropped or counted twice at the
/// seam — would pass it. This one puts a full page of captures in front of a
/// distinct one, so the last entry can only be found by asking for a second
/// page and applying the offset correctly.
#[tokio::test]
async fn a_capture_past_the_first_page_of_the_census_is_still_stated() {
    let (state, case_id, db) = setup().await;
    for n in 0..seance_api::CEILING_CENSUS_PAGE {
        record_image_derived(&db, case_id, &format!("Linux version 5.15.0-{n}")).await;
    }
    record_image_derived(&db, case_id, "Linux version 6.8.0-LATE").await;

    let data = gather_report_data(&state, case_id).await.unwrap();
    let stated = symbol_qualifications(&data);

    assert!(
        stated.iter().any(|q| q
            .affects
            .as_deref()
            .is_some_and(|a| a.contains("6.8.0-LATE"))),
        "the capture stamped after a full page was never reached: {} entries stated",
        stated.len()
    );
    // And the seam must not have duplicated anything on the way past it.
    assert_eq!(
        stated.len(),
        seance_api::CEILING_CENSUS_PAGE as usize + 1,
        "one entry per distinct capture, across the page boundary"
    );
}

/// A case whose scan could not be read whole says so, rather than presenting the
/// prefix it managed as the whole answer. This is the disclosure the first
/// version of this census dropped when it was copied from the ceiling one.
#[tokio::test]
async fn a_census_that_could_not_be_read_whole_says_so() {
    let (state, case_id, db) = setup().await;
    for n in 0..(seance_api::CEILING_CENSUS_PAGE * seance_api::CEILING_CENSUS_MAX_PAGES + 1) {
        record_image_derived(&db, case_id, &format!("Linux version 5.15.0-{n}")).await;
    }

    let data = gather_report_data(&state, case_id).await.unwrap();
    let gap = data
        .method_qualifications
        .iter()
        .find(|q| q.subject == seance_api::SYMBOL_CENSUS_GAP_SUBJECT)
        .expect("a census that ran out of budget must say the list above is partial");

    assert!(
        gap.statement.contains("cannot be relied on as all of"),
        "the disclosure has to say what it costs the reader: {:?}",
        gap.statement
    );
}

/// A capture marked image-derived whose provenance statement is missing.
///
/// `symbols_origin` and `symbols_provenance_statement` are written together by
/// the Linux memory tier, exactly as the decompression ceiling's two keys are,
/// so an artifact carrying the first without the second is a record this report
/// cannot read whole. The capture really was analysed from symbols taken out of
/// the image — the marker that selected it says so — and the section above
/// cannot say it. Falling silent leaves a reader counting entries against
/// captures to conclude the difference was analysed from a matching symbol
/// file, which is the very inference this section exists to prevent.
#[tokio::test]
async fn a_capture_with_no_provenance_statement_is_disclosed_as_a_gap() {
    let (state, case_id, db) = setup().await;
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "half-stamped.mem",
            "symbols_origin": "image_derived",
            "banner": "Linux version 5.15.0-generic",
        }),
    );
    db.record_artifact(&artifact).await.unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();

    assert!(
        symbol_qualifications(&data).is_empty(),
        "a statement that is not there must not be invented: {:?}",
        data.method_qualifications
    );
    let gap = data
        .method_qualifications
        .iter()
        .find(|q| q.subject == seance_api::SYMBOL_CENSUS_GAP_SUBJECT)
        .expect("a capture whose symbol source could not be read must still reach the report");
    assert!(
        gap.statement.contains("cannot be relied on as all of"),
        "the disclosure has to say what it costs the reader: {:?}",
        gap.statement
    );
}

/// The census that CAN be read whole says nothing, which is what keeps the gap
/// entry above meaningful: a caveat printed over every report is one a reader
/// learns to skip.
#[tokio::test]
async fn a_census_read_whole_adds_no_gap_entry() {
    let (state, case_id, db) = setup().await;
    record_image_derived(&db, case_id, "Linux version 5.15.0-generic").await;

    let data = gather_report_data(&state, case_id).await.unwrap();

    assert!(
        !data
            .method_qualifications
            .iter()
            .any(|q| q.subject == seance_api::SYMBOL_CENSUS_GAP_SUBJECT),
        "nothing was missed, so nothing is disclosed as missed: {:?}",
        data.method_qualifications
    );
}
