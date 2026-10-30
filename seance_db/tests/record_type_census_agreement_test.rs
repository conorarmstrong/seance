//! The record-type census and the record listing must describe ONE population.
//!
//! The census is what an examiner reads as "this case contains N records of
//! type T"; the listing is what they get when they click T. If the two count
//! different rows, one of the two screens is making a claim about the evidence
//! that the other contradicts, and there is no way for the examiner to tell
//! which one is wrong.
//!
//! The discriminator is JSON, so its SQL type is whatever the parser wrote:
//! `{"subtype": 1}` extracts as INTEGER, `{"subtype": "1"}` as TEXT. The census
//! coerces both to the text "1" and reports one type; SQLite, meanwhile, never
//! equates an INTEGER with a TEXT, so a listing that compares the raw
//! discriminator to a TEXT parameter finds only half of them. These tests pin
//! the agreement in both directions and in both source scopes.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Census", "Examiner").await?;
    Ok((db, case_id))
}

async fn record(
    db: &SqliteConnection,
    case_id: Uuid,
    parent_id: Option<Uuid>,
    metadata: serde_json::Value,
) -> Result<Uuid> {
    let a = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id,
        artifact_type: ArtifactType::ParsedRecord,
        metadata,
        data: None,
    };
    db.record_artifact(&a).await?;
    Ok(a.id)
}

/// The exact scenario the review names: one record whose `subtype` is the
/// number 1 and one whose `subtype` is the string "1". The census folds them
/// into a single "1" worth two records, so the drill-down must return both.
#[tokio::test]
async fn a_numeric_and_a_string_discriminator_agree_between_census_and_listing() -> Result<()> {
    let (db, case_id) = setup().await?;

    let numeric = record(&db, case_id, None, json!({ "subtype": 1 })).await?;
    let textual = record(&db, case_id, None, json!({ "subtype": "1" })).await?;

    let counts = db.record_type_counts(case_id, None).await?;
    let census: i64 = counts
        .iter()
        .find(|(t, _)| t == "1")
        .map(|(_, n)| *n)
        .unwrap_or(0);
    assert_eq!(
        census, 2,
        "the census folds the numeric and the string form into one type; counts were {counts:?}"
    );
    assert_eq!(
        counts.iter().filter(|(t, _)| t == "1").count(),
        1,
        "and it must report that type exactly once; counts were {counts:?}"
    );

    let (rows, total) = db.list_records_by_type(case_id, "1", None, 1, 50).await?;
    assert_eq!(
        total, census,
        "the listing's total must be the number the census showed"
    );
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert!(
        ids.contains(&numeric),
        "the record whose subtype is the NUMBER 1 must be reachable from the type the census showed"
    );
    assert!(
        ids.contains(&textual),
        "the record whose subtype is the STRING \"1\" must be reachable too"
    );

    Ok(())
}

/// The same agreement under a source scope, which is a different statement with
/// its own count: a scoped page carries its total from a window function, so a
/// predicate that matched the wrong rows would be wrong there independently.
#[tokio::test]
async fn the_scoped_listing_agrees_with_the_scoped_census() -> Result<()> {
    let (db, case_id) = setup().await?;

    let source = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        metadata: json!({ "name": "image.dd" }),
        data: None,
    };
    db.record_artifact(&source).await?;

    record(&db, case_id, Some(source.id), json!({ "subtype": 7 })).await?;
    record(&db, case_id, Some(source.id), json!({ "subtype": "7" })).await?;
    // Outside the subtree: must be counted by neither the scoped census nor the
    // scoped listing.
    record(&db, case_id, None, json!({ "subtype": 7 })).await?;

    let counts = db.record_type_counts(case_id, Some(source.id)).await?;
    let census: i64 = counts
        .iter()
        .find(|(t, _)| t == "7")
        .map(|(_, n)| *n)
        .unwrap_or(0);
    assert_eq!(
        census, 2,
        "the scoped census sees both forms inside the subtree and nothing outside it; \
         counts were {counts:?}"
    );

    let (rows, total) = db
        .list_records_by_type(case_id, "7", Some(source.id), 1, 50)
        .await?;
    assert_eq!(total, census, "scoped listing total must match its census");
    assert_eq!(rows.len(), 2, "and it must return the rows it counted");

    Ok(())
}

/// A REAL discriminator is the third JSON number shape, and the one where a
/// Rust-side guess at SQLite's text coercion would drift. The census renders it
/// with SQLite's own CAST, so the listing has to match on the same coercion
/// rather than on anything reconstructed in Rust.
#[tokio::test]
async fn a_real_discriminator_is_listable_under_the_label_the_census_shows() -> Result<()> {
    let (db, case_id) = setup().await?;

    record(&db, case_id, None, json!({ "subtype": 2.5 })).await?;

    let counts = db.record_type_counts(case_id, None).await?;
    assert_eq!(
        counts.len(),
        1,
        "one type in the case; counts were {counts:?}"
    );
    let (label, census) = counts[0].clone();

    let (rows, total) = db
        .list_records_by_type(case_id, &label, None, 1, 50)
        .await?;
    assert_eq!(
        total, census,
        "the label the census printed ({label:?}) must open the records it counted"
    );
    assert_eq!(rows.len(), 1);

    Ok(())
}

/// Every ordinary type name is unaffected: the fix must not make a record
/// findable under a type it does not bear.
#[tokio::test]
async fn a_text_discriminator_still_matches_only_itself() -> Result<()> {
    let (db, case_id) = setup().await?;

    record(&db, case_id, None, json!({ "type": "WhatsApp" })).await?;
    record(&db, case_id, None, json!({ "type": "iMessage" })).await?;
    record(&db, case_id, None, json!({})).await?;

    for (ty, expected) in [("WhatsApp", 1), ("iMessage", 1), ("Unknown", 1), ("Kik", 0)] {
        let (rows, total) = db.list_records_by_type(case_id, ty, None, 1, 50).await?;
        assert_eq!(total, expected, "listing total for {ty}");
        assert_eq!(rows.len() as i64, expected, "listing rows for {ty}");
    }

    Ok(())
}
