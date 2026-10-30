//! The processing log keeps its statement and loses its rows.
//!
//! "Module X ran over this artifact and produced nothing" is provenance a
//! report may need, and the difference between it and "module X never ran" is
//! exactly the silence this project refuses to let collapse. Written one row per
//! module it was 23.4 million rows on a 3.3-million-artifact case (98.5% of the
//! log) and 27 rows per artifact on a phone extraction (HUNT-074). It is now one
//! row per artifact per status, expanded on every read, so the log says the same
//! thing and the case costs a fraction of the disk.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::{DatabaseConnection, ProcessingLogRow};
use seance_db::SqliteConnection;
use serde_json::json;

async fn db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

#[tokio::test]
async fn twenty_modules_that_found_nothing_cost_one_row_and_still_say_so() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Fold", "Examiner").await?;
    let art = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
    db.record_artifact(&art).await?;

    let ran_and_found_nothing: Vec<(String, u64)> = (0..20)
        .map(|i| (format!("plugin.quiet.{i:02}"), i as u64))
        .collect();

    db.record_processing_log_batch(&[
        // The module that actually did something keeps its own row.
        ProcessingLogRow::single(
            case_id,
            art.id,
            "plugin.loud".to_string(),
            "complete".to_string(),
            7,
            None,
            123,
        ),
        ProcessingLogRow {
            case_id,
            artifact_id: art.id,
            module_id: String::new(),
            status: "complete".to_string(),
            artifacts_produced: 0,
            error_message: None,
            duration_ms: ran_and_found_nothing.iter().map(|(_, d)| d).sum(),
            zero_yield: Some(ran_and_found_nothing.clone()),
        },
    ])
    .await?;

    // Two rows on disk for twenty-one module runs.
    assert_eq!(db.count_processing_log_rows(case_id).await?, 2);

    // And the history still lists every one of them, with its own duration.
    let page = db
        .get_processing_log_for_artifact_page(art.id, Some(100), 0)
        .await?;
    assert_eq!(page.items.len(), 21, "every module run is still listed");
    for (module_id, duration) in &ran_and_found_nothing {
        let entry = page
            .items
            .iter()
            .find(|e| &e.module_id == module_id)
            .unwrap_or_else(|| panic!("{module_id} is missing from the history"));
        assert_eq!(entry.status, "complete");
        assert_eq!(entry.artifacts_produced, 0);
        assert_eq!(
            entry.duration_ms, *duration,
            "each module keeps its own duration, not a share of a total"
        );
    }
    let loud = page
        .items
        .iter()
        .find(|e| e.module_id == "plugin.loud")
        .expect("the module that produced something is still there");
    assert_eq!(loud.artifacts_produced, 7);
    assert_eq!(loud.duration_ms, 123);

    // The case summary groups by module the way it always did.
    let (groups, total) = db.get_processing_log_for_case(case_id, 100).await?;
    assert_eq!(total, 21, "one group per module");
    assert_eq!(groups.len(), 21);
    assert!(groups.iter().any(|g| g.module_id == "plugin.quiet.07"));

    Ok(())
}

/// A module that declined the input is a different statement from one that ran
/// and found nothing, so the two fold separately and keep their statuses.
#[tokio::test]
async fn the_two_kinds_of_silence_are_not_merged() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Fold", "Examiner").await?;
    let art = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
    db.record_artifact(&art).await?;

    db.record_processing_log_batch(&[
        ProcessingLogRow {
            case_id,
            artifact_id: art.id,
            module_id: String::new(),
            status: "complete".to_string(),
            artifacts_produced: 0,
            error_message: None,
            duration_ms: 2,
            zero_yield: Some(vec![("plugin.ran".to_string(), 2)]),
        },
        ProcessingLogRow {
            case_id,
            artifact_id: art.id,
            module_id: String::new(),
            status: "skipped".to_string(),
            artifacts_produced: 0,
            error_message: None,
            duration_ms: 1,
            zero_yield: Some(vec![("plugin.declined".to_string(), 1)]),
        },
    ])
    .await?;

    let page = db
        .get_processing_log_for_artifact_page(art.id, Some(100), 0)
        .await?;
    let status_of = |module: &str| {
        page.items
            .iter()
            .find(|e| e.module_id == module)
            .map(|e| e.status.clone())
    };
    assert_eq!(status_of("plugin.ran").as_deref(), Some("complete"));
    assert_eq!(status_of("plugin.declined").as_deref(), Some("skipped"));
    Ok(())
}

/// Every module expanded from one folded row shares its `id` and `created_at`,
/// so paging through them needs a tie-break that is total: no module may repeat
/// across pages or go missing, and the count must equal what the pages list.
#[tokio::test]
async fn paging_through_one_folded_row_lists_every_module_once() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Fold", "Examiner").await?;
    let art = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
    db.record_artifact(&art).await?;
    let modules: Vec<(String, u64)> = (0..25).map(|i| (format!("plugin.q.{i:02}"), 1)).collect();
    db.record_processing_log_batch(&[ProcessingLogRow {
        case_id,
        artifact_id: art.id,
        module_id: String::new(),
        status: "complete".to_string(),
        artifacts_produced: 0,
        error_message: None,
        duration_ms: 25,
        zero_yield: Some(modules.clone()),
    }])
    .await?;

    assert_eq!(db.count_processing_log_for_artifact(art.id).await?, 25);

    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let page = db
            .get_processing_log_for_artifact_page(art.id, Some(7), offset)
            .await?;
        seen.extend(page.items.iter().map(|e| e.module_id.clone()));
        if !page.has_more {
            break;
        }
        offset += 7;
    }
    let mut expected: Vec<String> = modules.into_iter().map(|(m, _)| m).collect();
    let mut got = seen.clone();
    got.sort();
    expected.sort();
    assert_eq!(got, expected, "each module exactly once across the pages");
    Ok(())
}
