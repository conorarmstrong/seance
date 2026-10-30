//! A record listing counts one run, not two.
//!
//! When a module is run again on an artifact, what the earlier run wrote is
//! marked superseded (`HUNT-107`). Those records stay in the case — the first
//! run's answer is part of its history — but a listing that shows them beside
//! the current ones makes every number on the screen the sum of two runs: the
//! Magnet 2022 Linux mailbox read "163 records" where the case held 110 current
//! ones and 53 answered.
//!
//! A record whose metadata will not parse cannot have been superseded, and the
//! exclusion is guarded so that it stays listed rather than taking the whole
//! statement down —
//! `record_query_filter_test::a_record_whose_metadata_will_not_parse_is_counted_not_hidden`
//! is the test that pins that, and it runs through this predicate.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{RecordListingQuery, RecordOrder, SqliteConnection};
use serde_json::json;
use uuid::Uuid;

async fn case_with_records() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Superseded listing", "Examiner").await?;
    let rows = vec![
        json!({"type": "EmailMessage", "subject": "current one"}),
        json!({"type": "EmailMessage", "subject": "current two"}),
        json!({"type": "EmailMessage", "subject": "answered", "superseded": true,
               "superseded_reason": "plugin.email.parser was run again on this artifact"}),
        json!({"type": "BrowserHistory", "title": "another type entirely"}),
    ];
    let artifacts: Vec<Artifact> = rows
        .into_iter()
        .map(|metadata| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata,
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&artifacts).await?;
    Ok((db, case_id))
}

fn query(record_type: &str) -> RecordListingQuery<'_> {
    RecordListingQuery {
        record_type,
        source_id: None,
        search: None,
        sort: None,
        order: RecordOrder::OldestIngestedFirst,
        page: 1,
        page_size: 100,
        include_superseded: false,
    }
}

#[tokio::test]
async fn a_listing_leaves_out_what_a_later_run_answered_and_says_how_many() -> Result<()> {
    let (db, case_id) = case_with_records().await?;
    let page = db
        .list_records_filtered(case_id, &query("EmailMessage"))
        .await?;
    assert_eq!(page.records.len(), 2, "only the current run's records");
    assert_eq!(page.total, 2);
    assert_eq!(page.type_total, 2);
    // Silence here would read as "that is all the case ever held".
    assert_eq!(page.superseded_total, Some(1));
    Ok(())
}

#[tokio::test]
async fn an_examiner_can_ask_for_the_earlier_runs_records() -> Result<()> {
    let (db, case_id) = case_with_records().await?;
    let page = db
        .list_records_filtered(
            case_id,
            &RecordListingQuery {
                include_superseded: true,
                ..query("EmailMessage")
            },
        )
        .await?;
    assert_eq!(page.records.len(), 3);
    assert_eq!(page.total, 3);
    // Nothing was excluded, so there is no exclusion to describe.
    assert_eq!(page.superseded_total, None);
    Ok(())
}

#[tokio::test]
async fn a_type_with_nothing_superseded_is_unchanged() -> Result<()> {
    let (db, case_id) = case_with_records().await?;
    let page = db
        .list_records_filtered(case_id, &query("BrowserHistory"))
        .await?;
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.total, 1);
    assert_eq!(page.superseded_total, Some(0));
    Ok(())
}

#[tokio::test]
async fn a_scoped_listing_excludes_them_too() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Scoped", "Examiner").await?;
    let source = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "image.E01"}),
    );
    db.record_artifact(&source).await?;
    for metadata in [
        json!({"type": "EmailMessage", "subject": "current"}),
        json!({"type": "EmailMessage", "subject": "answered", "superseded": true}),
    ] {
        let art = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(source.id);
        db.record_artifact(&art).await?;
    }
    let page = db
        .list_records_filtered(
            case_id,
            &RecordListingQuery {
                source_id: Some(source.id),
                ..query("EmailMessage")
            },
        )
        .await?;
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.total, 1);
    assert_eq!(page.superseded_total, Some(1));
    Ok(())
}

#[tokio::test]
async fn the_type_census_counts_the_same_population_the_listing_shows() -> Result<()> {
    // The index said "Email — 163 records" and the listing it opened said 110:
    // the census counted both runs. A census and a drill-down that disagree is
    // the failure the listing's own type counts exist to prevent (HUNT-107).
    let (db, case_id) = case_with_records().await?;
    let counts = db.record_type_counts(case_id, None).await?;
    let email = counts
        .iter()
        .find(|(t, _)| t == "EmailMessage")
        .expect("EmailMessage counted");
    assert_eq!(email.1, 2, "the superseded record is not counted again");

    let page = db
        .list_records_filtered(case_id, &query("EmailMessage"))
        .await?;
    assert_eq!(page.total, email.1, "the census and the listing agree");
    Ok(())
}
