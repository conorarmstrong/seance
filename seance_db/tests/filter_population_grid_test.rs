//! Opening a saved filter's population IN THE FILE GRID.
//!
//! The compound filter engine could return a page of matches, but that page was
//! its own listing: it had none of the grid's sort, paging, selection or export.
//! So a filter — the one instrument in this product that DEFINES a population —
//! could not be handed to the view that works on populations.
//!
//! The mechanism is deliberately not a second evaluator. Compiling a
//! `FilterCondition` into SQL would give the grid an uncapped population, and it
//! would also give the product two engines that have to agree about what a
//! filter means; where they disagreed, the grid would show a different set of
//! files from the one `/filters/:id/apply` counted, and nothing on either screen
//! would say which was right. Instead the SAME evaluator resolves the population
//! to an id set, and the grid lists exactly that set. The population agrees by
//! construction, and the price — a bounded id set — is a number the response
//! states.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::filter::{FilterCondition, FilterOp};
use seance_db::{FileEntryFilters, FileListScope, SqliteConnection};
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Grid", "examiner").await?;

    let files = [
        ("alpha.jpg", 5_000_000i64, true),
        ("bravo.jpg", 9_000_000, false),
        ("charlie.jpg", 10, true),
        ("delta.txt", 8_000_000, false),
    ];
    let artifacts: Vec<Artifact> = files
        .iter()
        .map(|(name, size, deleted)| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::FileEntry,
            metadata: json!({"name": name, "size": size, "deleted": deleted}),
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&artifacts).await?;
    Ok((db, case_id))
}

fn big_files() -> FilterCondition {
    FilterCondition::Simple {
        field: "size".to_string(),
        operator: FilterOp::Gt,
        value: json!(1_000_000),
    }
}

#[tokio::test]
async fn a_resolved_population_is_the_same_set_the_filter_apply_counts() -> Result<()> {
    let (db, case_id) = setup().await?;

    let resolved = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;
    let applied = db
        .get_filtered_artifacts(case_id, None, &big_files(), 1_000, 0)
        .await?;

    assert_eq!(
        resolved.total, applied.total,
        "the grid's population and the filter apply's count must come from one \
         evaluator, or the two screens state different facts about the case"
    );
    let mut resolved_ids = resolved.ids.clone();
    let mut applied_ids: Vec<Uuid> = applied.items.iter().map(|a| a.id).collect();
    resolved_ids.sort();
    applied_ids.sort();
    assert_eq!(resolved_ids, applied_ids);
    Ok(())
}

#[tokio::test]
async fn the_grid_lists_exactly_the_filters_population() -> Result<()> {
    let (db, case_id) = setup().await?;

    let resolved = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;
    assert_eq!(resolved.total, 3, "alpha, bravo and delta are over 1 MB");

    let filters = FileEntryFilters {
        restrict_to_ids: Some(resolved.ids.clone()),
        ..Default::default()
    };
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::CaseWide,
            &filters,
            Some("name"),
            Some("asc"),
            1,
            100,
            false,
        )
        .await?;

    let names: Vec<String> = rows.iter().filter_map(|r| r.name.clone()).collect();
    assert_eq!(names, vec!["alpha.jpg", "bravo.jpg", "delta.txt"]);
    assert_eq!(total, 3);
    Ok(())
}

#[tokio::test]
async fn the_grids_own_filters_still_narrow_the_population() -> Result<()> {
    let (db, case_id) = setup().await?;
    let resolved = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;

    // The saved filter's population intersected with the grid's extension box.
    let filters = FileEntryFilters {
        restrict_to_ids: Some(resolved.ids.clone()),
        extension: Some("jpg".to_string()),
        ..Default::default()
    };
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::CaseWide,
            &filters,
            Some("name"),
            Some("asc"),
            1,
            100,
            false,
        )
        .await?;
    assert_eq!(
        total, 2,
        "alpha.jpg and bravo.jpg; delta.txt is filtered out"
    );
    assert_eq!(rows.len(), 2);
    Ok(())
}

#[tokio::test]
async fn an_empty_population_lists_nothing_rather_than_everything() -> Result<()> {
    let (db, case_id) = setup().await?;

    // The trap: an empty id restriction rendered as an absent restriction would
    // turn "this filter matched no files" into "here is the whole case", which
    // is the worst possible failure for a population-defining instrument.
    let filters = FileEntryFilters {
        restrict_to_ids: Some(Vec::new()),
        ..Default::default()
    };
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::CaseWide,
            &filters,
            None,
            None,
            1,
            100,
            false,
        )
        .await?;
    assert_eq!(total, 0);
    assert!(rows.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_population_larger_than_the_id_ceiling_says_so() -> Result<()> {
    let (db, case_id) = setup().await?;

    let capped = db
        .filtered_artifact_ids(case_id, None, &big_files(), 2)
        .await?;
    assert_eq!(capped.ids.len(), 2);
    assert!(
        capped.id_cap_reached,
        "a population cut down to fit the grid must say it was cut"
    );
    assert_eq!(
        capped.total, 3,
        "and it must still report how big the population really is"
    );
    assert_eq!(capped.id_cap, 2);

    let whole = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;
    assert!(!whole.id_cap_reached);
    Ok(())
}

#[tokio::test]
async fn a_population_carries_the_scan_flags_the_apply_path_reports() -> Result<()> {
    let (db, case_id) = setup().await?;
    let resolved = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;
    assert!(resolved.scan_complete);
    assert_eq!(resolved.undecodable, 0);
    Ok(())
}

#[tokio::test]
async fn a_population_never_reaches_across_cases() -> Result<()> {
    let (db, case_id) = setup().await?;
    let other = db.create_case("Somebody else's", "examiner").await?;
    let intruder = Artifact {
        id: Uuid::new_v4(),
        case_id: other,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        metadata: json!({"name": "theirs.jpg", "size": 20_000_000}),
        data: None,
    };
    db.record_artifact(&intruder).await?;

    let resolved = db
        .filtered_artifact_ids(case_id, None, &big_files(), 1_000)
        .await?;
    assert!(!resolved.ids.contains(&intruder.id));

    // And an id smuggled into the restriction directly cannot pull the other
    // case's file into this case's grid either.
    let filters = FileEntryFilters {
        restrict_to_ids: Some(vec![intruder.id]),
        ..Default::default()
    };
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::CaseWide,
            &filters,
            None,
            None,
            1,
            100,
            false,
        )
        .await?;
    assert_eq!(total, 0);
    assert!(rows.is_empty());
    Ok(())
}
