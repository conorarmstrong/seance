//! Characterization guard for stream_export_timeline's tag handling. The export
//! LEFT JOINs timeline_tags; the optimization skips that join when the case has
//! no tags. Output must be identical either way: exactly one row per event with
//! NULL tag columns when untagged, and the note carried when a tag exists. These
//! tests pass before AND after the skip-join change (behavior-preserving).

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

fn timeline_artifact(case: Uuid, ts: i64, name: &str) -> Artifact {
    Artifact::new(
        case,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": ts,
            "timestamp_desc": "File Created",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": name,
            "full_details": "{}",
        }),
    )
}

/// Timeline event with an explicit event type and a `filename` in full_details,
/// so the column filters have something to match.
fn detailed_artifact(case: Uuid, ts: i64, name: &str, desc: &str, filename: &str) -> Artifact {
    Artifact::new(
        case,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": ts,
            "timestamp_desc": desc,
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": name,
            "full_details": json!({ "filename": filename }).to_string(),
        }),
    )
}

async fn drain(
    mut rx: tokio::sync::mpsc::Receiver<
        std::result::Result<seance_core::models::TimelineEventResponse, String>,
    >,
) -> Vec<seance_core::models::TimelineEventResponse> {
    let mut out = Vec::new();
    while let Some(item) = rx.recv().await {
        out.push(item.expect("timeline export row must be Ok"));
    }
    out
}

#[tokio::test]
async fn export_without_tags_streams_each_event_once_untagged() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Export", "Examiner").await?;

    let a = timeline_artifact(case, 100, "a");
    let b = timeline_artifact(case, 200, "b");
    let c = timeline_artifact(case, 300, "c");
    db.record_artifacts_batch(&[a.clone(), b.clone(), c.clone()])
        .await?;

    let events =
        drain(db.stream_export_timeline(case, None, None, None, None, None, None, None)).await;

    // One row per event, newest first, none tagged.
    assert_eq!(events.len(), 3);
    let ts: Vec<i64> = events.iter().map(|e| e.timestamp).collect();
    assert_eq!(ts, vec![300, 200, 100]);
    assert!(events.iter().all(|e| e.is_tagged == Some(false)));
    assert!(events.iter().all(|e| e.tag_note.is_none()));
    Ok(())
}

#[tokio::test]
async fn export_with_a_tag_carries_the_note() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Export", "Examiner").await?;

    let a = timeline_artifact(case, 100, "a");
    let b = timeline_artifact(case, 200, "b");
    db.record_artifacts_batch(&[a.clone(), b.clone()]).await?;
    db.create_timeline_tag(case, b.id, Some("examiner"), Some("suspicious"))
        .await?;

    let events =
        drain(db.stream_export_timeline(case, None, None, None, None, None, None, None)).await;

    assert_eq!(events.len(), 2);
    let tagged = events
        .iter()
        .find(|e| e.artifact_id == b.id)
        .expect("tagged event present");
    assert_eq!(tagged.is_tagged, Some(true));
    assert_eq!(tagged.tag_note.as_deref(), Some("suspicious"));
    let untagged = events
        .iter()
        .find(|e| e.artifact_id == a.id)
        .expect("untagged event present");
    assert_eq!(untagged.is_tagged, Some(false));
    assert!(untagged.tag_note.is_none());
    Ok(())
}

// ── BUG-231: the export must apply the SAME filters as the on-screen list ────

#[tokio::test]
async fn export_honours_tagged_only_filename_and_event_type() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Export", "Examiner").await?;

    let a = detailed_artifact(case, 100, "a", "File Created", "report.docx");
    let b = detailed_artifact(case, 200, "b", "File Deleted", "secret.docx");
    let c = detailed_artifact(case, 300, "c", "File Created", "photo.jpg");
    db.record_artifacts_batch(&[a.clone(), b.clone(), c.clone()])
        .await?;

    // tagged_only: only the tagged event's id is passed through.
    let tagged_ids = vec![b.id.as_bytes().to_vec()];
    let events = drain(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(tagged_ids),
    ))
    .await;
    assert_eq!(events.len(), 1, "tagged_only must not export untagged rows");
    assert_eq!(events[0].artifact_id, b.id);

    // filename filter (json_extract on full_details).
    let events = drain(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        None,
        Some("photo".into()),
        None,
        None,
    ))
    .await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].artifact_id, c.id);

    // event-type filter (timestamp_desc).
    let events = drain(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        None,
        None,
        Some("Deleted".into()),
        None,
    ))
    .await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].artifact_id, b.id);

    Ok(())
}

#[tokio::test]
async fn export_with_tagged_only_and_no_tags_is_empty() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Export", "Examiner").await?;

    db.record_artifacts_batch(&[
        timeline_artifact(case, 100, "a"),
        timeline_artifact(case, 200, "b"),
    ])
    .await?;

    // "tagged only" with an EMPTY id set must export nothing, not everything.
    let events = drain(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Vec::new()),
    ))
    .await;
    assert!(events.is_empty(), "empty tag set must export zero rows");

    // The list/count path agrees.
    let empty: Vec<Vec<u8>> = Vec::new();
    let count = db
        .get_timeline_events_count(case, None, None, None, None, None, None, Some(&empty))
        .await?;
    assert_eq!(count, 0);
    let page = db
        .get_timeline_events_filtered(
            case,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&empty),
        )
        .await?;
    assert!(page.is_empty());
    Ok(())
}
