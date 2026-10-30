//! Tests for the timeline timestamp contract (C6) and single-insert
//! transactional atomicity (M2).
//!
//! Plugins store `metadata["timestamp"]` as either i64 unix seconds or an
//! RFC3339 string. Both must produce a timeline_events row; only garbage may
//! be rejected (error on the single path, skip-with-warning on the batch path).

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

fn timeline_artifact(case_id: Uuid, timestamp: serde_json::Value) -> Artifact {
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: json!({
            "timestamp": timestamp,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": "Test event",
            "full_details": "{}",
        }),
        data: None,
    }
}

#[tokio::test]
async fn single_insert_accepts_i64_timestamp() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let artifact = timeline_artifact(case_id, json!(1234567890i64));
    db.record_artifact(&artifact).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1234567890);
    Ok(())
}

#[tokio::test]
async fn single_insert_accepts_rfc3339_timestamp() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // 2009-02-13T23:31:30Z == 1234567890
    let artifact = timeline_artifact(case_id, json!("2009-02-13T23:31:30Z"));
    db.record_artifact(&artifact).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1234567890);
    Ok(())
}

#[tokio::test]
async fn single_insert_rejects_garbage_timestamp() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let artifact = timeline_artifact(case_id, json!("not a timestamp"));
    let result = db.record_artifact(&artifact).await;
    assert!(
        result.is_err(),
        "garbage timestamp must error on single path"
    );
    Ok(())
}

/// M2: the artifact insert and timeline_events insert must be atomic. When the
/// timeline insert fails (garbage timestamp), the artifact row must roll back.
#[tokio::test]
async fn single_insert_is_transactional() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let artifact = timeline_artifact(case_id, json!("garbage"));
    let artifact_id = artifact.id;
    assert!(db.record_artifact(&artifact).await.is_err());

    // No orphaned artifact row may remain
    let fetched = db.get_artifact(artifact_id).await?;
    assert!(
        fetched.is_none(),
        "artifact insert must roll back when timeline insert fails"
    );
    Ok(())
}

/// Batch path: i64 and RFC3339 timestamps both produce timeline rows; garbage
/// is skipped (with a warning) but the artifact itself is still recorded.
#[tokio::test]
async fn batch_insert_handles_i64_rfc3339_and_garbage() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let a_i64 = timeline_artifact(case_id, json!(1234567890i64));
    let a_rfc = timeline_artifact(case_id, json!("2009-02-13T23:31:30Z"));
    let a_bad = timeline_artifact(case_id, json!("garbage"));
    let bad_id = a_bad.id;

    db.record_artifacts_batch(&[a_i64, a_rfc, a_bad]).await?;

    // Both parseable timestamps produce timeline rows
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        2,
        "i64 and RFC3339 timestamps must both produce timeline rows"
    );
    assert!(events.iter().all(|e| e.timestamp == 1234567890));

    // The garbage artifact is still recorded as an artifact (only its timeline row is skipped)
    let fetched = db.get_artifact(bad_id).await?;
    assert!(
        fetched.is_some(),
        "artifact with bad timestamp must still be persisted"
    );

    // ...and it says, on the artifact itself, that it is missing from the
    // timeline and why, so an absent event is not read as "no such event".
    // The examiner-supplied metadata is left as it was.
    let fetched = fetched.unwrap();
    assert_eq!(fetched.metadata["timestamp"], json!("garbage"));
    assert_eq!(
        fetched.metadata["timeline_omitted"]["raw_timestamp"],
        json!("garbage")
    );
    assert!(fetched.metadata["timeline_omitted"]["reason"]
        .as_str()
        .is_some_and(|r| r.contains("timestamp")));

    // Events that did reach the timeline carry no such marker.
    let ok = db.get_artifact(events[0].artifact_id).await?.unwrap();
    assert!(ok.metadata.get("timeline_omitted").is_none());
    Ok(())
}

/// D5/D6: an RFC3339 timestamp with fractional seconds and a non-UTC offset
/// must preserve BOTH the sub-second nanoseconds and the source UTC offset,
/// rather than collapsing to whole UTC seconds (the pre-0021 behaviour).
#[tokio::test]
async fn single_insert_preserves_subsecond_and_source_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // Wall clock 2009-02-13T23:31:30.123456789 at +05:00.
    // UTC instant = 1234567890 - 18000 = 1234549890 s; 123456789 ns; +18000 s.
    let artifact = timeline_artifact(case_id, json!("2009-02-13T23:31:30.123456789+05:00"));
    db.record_artifact(&artifact).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1234549890);
    assert_eq!(events[0].timestamp_subsec_nanos, 123456789);
    assert_eq!(events[0].source_utc_offset_seconds, Some(18000));
    Ok(())
}

/// A bare Unix-integer timestamp carries no sub-second or timezone information;
/// those fields must read back as 0 / None (unknown), never a fabricated offset.
#[tokio::test]
async fn single_insert_i64_reports_no_subsecond_or_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    db.record_artifact(&timeline_artifact(case_id, json!(1234567890i64)))
        .await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events[0].timestamp, 1234567890);
    assert_eq!(events[0].timestamp_subsec_nanos, 0);
    assert_eq!(events[0].source_utc_offset_seconds, None);
    Ok(())
}

/// A `Z`-suffixed RFC3339 time is explicitly UTC: the offset is known to be 0
/// (distinct from the unknown bare-integer offset of None).
#[tokio::test]
async fn single_insert_utc_zulu_records_zero_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    db.record_artifact(&timeline_artifact(case_id, json!("2009-02-13T23:31:30.5Z")))
        .await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events[0].timestamp, 1234567890);
    assert_eq!(events[0].timestamp_subsec_nanos, 500_000_000);
    assert_eq!(events[0].source_utc_offset_seconds, Some(0));
    Ok(())
}

/// Batch path must preserve precision + offset identically to the single path.
#[tokio::test]
async fn batch_insert_preserves_subsecond_and_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    // -08:00 => UTC instant = 1234567890 + 28800 = 1234596690.
    let a = timeline_artifact(case_id, json!("2009-02-13T23:31:30.123456789-08:00"));
    db.record_artifacts_batch(&[a]).await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1234596690);
    assert_eq!(events[0].timestamp_subsec_nanos, 123456789);
    assert_eq!(events[0].source_utc_offset_seconds, Some(-28800));
    Ok(())
}

/// timeline_events.filename is a generated column using json_extract on
/// full_details (migration 0005), so full_details must always be stored as
/// valid JSON — even when the plugin omitted it or wrote plain text.
#[tokio::test]
async fn single_insert_accepts_missing_full_details() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("t", "e").await?;
    let mut artifact = timeline_artifact(case_id, json!(1700000000));
    artifact
        .metadata
        .as_object_mut()
        .unwrap()
        .remove("full_details");
    db.record_artifact(&artifact).await?;
    let events = db.get_timeline_events(case_id, Some(10), Some(0)).await?;
    assert_eq!(events.len(), 1);
    Ok(())
}

#[tokio::test]
async fn batch_insert_accepts_missing_and_plaintext_full_details() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("t", "e").await?;
    let mut missing = timeline_artifact(case_id, json!(1700000000));
    missing
        .metadata
        .as_object_mut()
        .unwrap()
        .remove("full_details");
    let mut plaintext = timeline_artifact(case_id, json!(1700000001));
    plaintext.metadata["full_details"] = json!("not json at all");
    db.record_artifacts_batch(&[missing, plaintext]).await?;
    let events = db.get_timeline_events(case_id, Some(10), Some(0)).await?;
    assert_eq!(events.len(), 2);
    Ok(())
}

// --- Chat messages on the unified timeline ------------------------------------
//
// A `chat_message` ParsedRecord (iMessage, WhatsApp, SMS, Messenger, recovered,
// ...) with a real `date` earns a timeline_events row from either write path,
// direction-labelled and namespaced by platform. Undated recovered bodies do
// NOT get pinned to the epoch.

fn chat_message_artifact(case_id: Uuid, date: serde_json::Value, direction: &str) -> Artifact {
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata: json!({
            "type": "iMessage",
            "subtype": "chat_message",
            "date": date,
            "direction": direction,
            "contact": "+420731485450",
            "text": "Ahoj Jirko, v kolik budes na vlakaci?",
        }),
        data: None,
    }
}

#[tokio::test]
async fn chat_message_on_timeline_single_path() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("t", "e").await?;
    db.record_artifact(&chat_message_artifact(
        case_id,
        json!(1234567890i64),
        "sent",
    ))
    .await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1234567890);
    assert_eq!(events[0].timestamp_desc, "Message Sent");
    assert_eq!(events[0].source_module, "chat.iMessage");
    assert!(events[0].short_desc.contains("+420731485450"));
    Ok(())
}

#[tokio::test]
async fn chat_message_on_timeline_batch_path() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("t", "e").await?;
    db.record_artifacts_batch(&[chat_message_artifact(
        case_id,
        json!(1234567890i64),
        "received",
    )])
    .await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp_desc, "Message Received");
    Ok(())
}

/// A recovered body with no timestamp is still stored as an artifact, but must
/// never be pinned to the epoch on the timeline.
#[tokio::test]
async fn undated_chat_message_stays_off_timeline() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("t", "e").await?;
    let a = chat_message_artifact(case_id, serde_json::Value::Null, "sent");
    let id = a.id;
    db.record_artifact(&a).await?;
    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        0,
        "undated chat must not appear on the timeline"
    );
    assert!(
        db.get_artifact(id).await?.is_some(),
        "the message artifact itself must still be recorded"
    );
    Ok(())
}

/// CR-048: an event kept as an artifact but absent from the timeline is
/// counted by the incompleteness census, so a report can say how many.
#[tokio::test]
async fn the_incompleteness_census_counts_timeline_events_with_no_timestamp() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let good = timeline_artifact(case_id, json!(1234567890i64));
    let bad = timeline_artifact(case_id, json!("garbage"));
    let mut superseded_bad = timeline_artifact(case_id, json!("also garbage"));
    superseded_bad.metadata["superseded"] = json!(true);
    db.record_artifacts_batch(&[good, bad, superseded_bad])
        .await?;

    let census = db.get_case_incompleteness(case_id).await?;
    assert_eq!(
        census.timeline_omitted, 1,
        "only the live omitted event counts"
    );
    assert!(
        census.any(),
        "an omitted timeline event is an incompleteness"
    );
    assert_eq!(census.content_incomplete, 0);

    let clean = db.create_case("Clean", "Examiner").await?;
    db.record_artifacts_batch(&[timeline_artifact(clean, json!(1234567890i64))])
        .await?;
    let census = db.get_case_incompleteness(clean).await?;
    assert_eq!(census.timeline_omitted, 0);
    assert!(!census.any());
    Ok(())
}
