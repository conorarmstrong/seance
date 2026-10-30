//! record_artifacts_batch must derive the timeline_events row correctly for a
//! TimelineEvent artifact in a batch. Guards the refactor that removed the
//! per-row metadata re-parse and clone (reads straight from artifact.metadata).

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;

#[tokio::test]
async fn batch_insert_derives_timeline_event_row() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Batch", "Examiner").await?;

    // A plain file plus a timeline event, inserted together via the batch path.
    let file = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "f.txt", "path": "/f.txt" }),
    );
    let event = Artifact::new(
        case,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_123,
            "timestamp_desc": "File Created",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": "f.txt created",
            "full_details": "{\"filename\": \"f.txt\"}",
        }),
    );
    db.record_artifacts_batch(&[file, event.clone()]).await?;

    // The timeline row must exist with the fields taken from the event metadata.
    let events = db.get_timeline_events(case, Some(10), Some(0)).await?;
    let row = events
        .iter()
        .find(|e| e.artifact_id == event.id)
        .expect("timeline row created for the batched event");
    assert_eq!(row.timestamp, 1_700_000_123);
    assert_eq!(row.timestamp_desc, "File Created");
    assert_eq!(row.source_module, "plugin.ntfs.mft_parser");
    assert_eq!(row.short_desc, "f.txt created");
    assert!(row.full_details.contains("f.txt"));

    Ok(())
}
