mod common;

use anyhow::Result;
use common::file_db;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

/// Helper to create an in-memory test database
async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

/// Helper to create a test case
async fn create_test_case(db: &SqliteConnection) -> Result<Uuid> {
    db.create_case("Test Case", "Test Examiner").await
}

/// Helper to create a test timeline event
async fn create_test_event(db: &SqliteConnection, case_id: Uuid) -> Result<Uuid> {
    use seance_core::artifact::{Artifact, ArtifactType};
    use serde_json::json;

    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: json!({
            "timestamp": 1234567890i64,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": "Test event",
            "full_details": r#"{"filename": "test.txt"}"#,
        }),
        data: None,
    };

    let event_id = artifact.id;
    db.record_artifact(&artifact).await?;
    Ok(event_id)
}

#[tokio::test]
async fn test_create_timeline_tag() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create a tag
    let tag_id = db
        .create_timeline_tag(
            case_id,
            event_id,
            Some("test_examiner"),
            Some("This is a suspicious event"),
        )
        .await?;

    // Fetch the tag and verify fields
    let tag = db.get_timeline_tag(case_id, event_id).await?;
    assert!(tag.is_some());

    let tag = tag.unwrap();
    assert_eq!(tag.id, tag_id);
    assert_eq!(tag.case_id, case_id);
    assert_eq!(tag.event_id, event_id);
    assert_eq!(tag.examiner, Some("test_examiner".to_string()));
    assert_eq!(tag.note, Some("This is a suspicious event".to_string()));
    assert!(tag.created_at > 0);

    Ok(())
}

#[tokio::test]
async fn test_create_tag_without_note() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create a tag without a note
    let tag_id = db
        .create_timeline_tag(case_id, event_id, None, None)
        .await?;

    // Verify tag exists but has no note
    let tag = db.get_timeline_tag(case_id, event_id).await?;
    assert!(tag.is_some());

    let tag = tag.unwrap();
    assert_eq!(tag.id, tag_id);
    assert_eq!(tag.note, None);
    assert_eq!(tag.examiner, None);

    Ok(())
}

#[tokio::test]
async fn test_create_tag_idempotent() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create a tag twice (the second updates the note of the one row)
    db.create_timeline_tag(case_id, event_id, None, Some("First note"))
        .await?;
    db.create_timeline_tag(case_id, event_id, None, Some("Second note"))
        .await?;

    // Should only have one tag with the second note
    let tags = db.list_timeline_tags(case_id).await?;
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].note, Some("Second note".to_string()));

    Ok(())
}

#[tokio::test]
async fn retagging_keeps_the_first_examiner_id_and_note() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    let first = db
        .create_timeline_tag(case_id, event_id, Some("alice"), Some("Alice's note"))
        .await?;
    let before = db.get_timeline_tag(case_id, event_id).await?.unwrap();
    let second = db
        .create_timeline_tag(case_id, event_id, Some("bob"), None)
        .await?;

    assert_eq!(second, first, "the surviving id is returned");
    let after = db.get_timeline_tag(case_id, event_id).await?.unwrap();
    assert_eq!(after.id, first);
    assert_eq!(after.examiner.as_deref(), Some("alice"));
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(
        after.note.as_deref(),
        Some("Alice's note"),
        "a null note must not erase an existing one"
    );
    Ok(())
}

#[tokio::test]
async fn test_delete_timeline_tag() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create and then delete a tag
    db.create_timeline_tag(case_id, event_id, None, Some("Test note"))
        .await?;

    let deleted = db.delete_timeline_tag(case_id, event_id).await?;
    assert!(deleted);

    // Verify tag is gone
    let tag = db.get_timeline_tag(case_id, event_id).await?;
    assert!(tag.is_none());

    Ok(())
}

#[tokio::test]
async fn test_delete_nonexistent_tag() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = Uuid::new_v4(); // Non-existent event

    // Try to delete a tag that doesn't exist
    let deleted = db.delete_timeline_tag(case_id, event_id).await?;
    assert!(!deleted);

    Ok(())
}

#[tokio::test]
async fn test_update_timeline_tag_note() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create a tag with initial note
    db.create_timeline_tag(case_id, event_id, None, Some("Original note"))
        .await?;

    // Update the note
    let updated = db
        .update_timeline_tag_note(case_id, event_id, "Updated note")
        .await?;
    assert!(updated);

    // Verify note was updated
    let tag = db.get_timeline_tag(case_id, event_id).await?;
    assert_eq!(tag.unwrap().note, Some("Updated note".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_update_nonexistent_tag() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = Uuid::new_v4();

    // Try to update a tag that doesn't exist
    let updated = db
        .update_timeline_tag_note(case_id, event_id, "Note")
        .await?;
    assert!(!updated);

    Ok(())
}

#[tokio::test]
async fn test_list_timeline_tags() -> Result<()> {
    // File-backed so a raw pool can give the tags distinct, controlled
    // `created_at` values (the API stamps whole seconds, so back-to-back tags
    // would tie and prove nothing about the ordering).
    let (db, path) = file_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create multiple events and tag some of them
    let event1 = create_test_event(&db, case_id).await?;
    let _event2 = create_test_event(&db, case_id).await?;
    let event3 = create_test_event(&db, case_id).await?;

    // Tag events 1 and 3
    db.create_timeline_tag(case_id, event1, None, Some("Note 1"))
        .await?;
    db.create_timeline_tag(case_id, event3, None, Some("Note 3"))
        .await?;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    for (event, created_at) in [(event1, 1000_i64), (event3, 2000_i64)] {
        sqlx::query("UPDATE timeline_tags SET created_at = ? WHERE event_id = ?")
            .bind(created_at)
            .bind(event)
            .execute(&pool)
            .await?;
    }
    pool.close().await;

    // List all tags: newest first.
    let tags = db.list_timeline_tags(case_id).await?;
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].event_id, event3);
    assert_eq!(tags[1].event_id, event1);

    Ok(())
}

#[tokio::test]
async fn test_list_tags_empty_case() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // List tags for case with no tags
    let tags = db.list_timeline_tags(case_id).await?;
    assert_eq!(tags.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_tags_isolated_by_case() -> Result<()> {
    let db = setup_test_db().await?;
    let case1_id = create_test_case(&db).await?;
    let case2_id = create_test_case(&db).await?;

    let event1 = create_test_event(&db, case1_id).await?;
    let event2 = create_test_event(&db, case2_id).await?;

    // Tag events in different cases
    db.create_timeline_tag(case1_id, event1, None, Some("Case 1 tag"))
        .await?;
    db.create_timeline_tag(case2_id, event2, None, Some("Case 2 tag"))
        .await?;

    // Verify each case only sees its own tags
    let case1_tags = db.list_timeline_tags(case1_id).await?;
    let case2_tags = db.list_timeline_tags(case2_id).await?;

    assert_eq!(case1_tags.len(), 1);
    assert_eq!(case2_tags.len(), 1);
    assert_eq!(case1_tags[0].note, Some("Case 1 tag".to_string()));
    assert_eq!(case2_tags[0].note, Some("Case 2 tag".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_timeline_query_includes_tags() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    let event1 = create_test_event(&db, case_id).await?;
    let event2 = create_test_event(&db, case_id).await?;

    // Tag only event1
    db.create_timeline_tag(case_id, event1, None, Some("Tagged event"))
        .await?;

    // Fetch timeline events
    let events = db
        .get_timeline_events_filtered(
            case_id, None, // from_ts
            None, // to_ts
            None, // source_modules
            None, // search_text
            None, // filename_filter
            None, // event_type_filter
            None, // limit
            None, // offset
            None, // sort_by
            None, // sort_order
            None, // dynamic_columns
            None, // event_ids
        )
        .await?;

    // Find the tagged event
    let tagged_event = events.iter().find(|e| e.artifact_id == event1);
    let untagged_event = events.iter().find(|e| e.artifact_id == event2);

    assert!(tagged_event.is_some());
    assert!(untagged_event.is_some());

    // Verify tag status
    assert_eq!(tagged_event.unwrap().is_tagged, Some(true));
    assert_eq!(
        tagged_event.unwrap().tag_note,
        Some("Tagged event".to_string())
    );

    assert_eq!(untagged_event.unwrap().is_tagged, Some(false));
    assert_eq!(untagged_event.unwrap().tag_note, None);

    Ok(())
}

#[tokio::test]
async fn test_cascade_delete_tags_with_case() -> Result<()> {
    // Note: This test verifies that when a case is deleted,
    // all associated tags are also deleted (ON DELETE CASCADE)

    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let event_id = create_test_event(&db, case_id).await?;

    // Create a tag
    db.create_timeline_tag(case_id, event_id, None, Some("Tag"))
        .await?;

    // Verify tag exists
    let tags_before = db.list_timeline_tags(case_id).await?;
    assert_eq!(tags_before.len(), 1);

    // Delete the case
    db.delete_case(case_id).await?;

    // Attempt to list tags for deleted case should return empty
    // (case doesn't exist, so query returns nothing)
    let tags_after = db.list_timeline_tags(case_id).await?;
    assert_eq!(tags_after.len(), 0);

    Ok(())
}

/// Tags are keyed by the ARTIFACT id. A file's MAC-time rows carry a derived row
/// id, so the report path must join on `artifact_id` or a tagged file event never
/// reaches the report.
#[tokio::test]
async fn tagged_file_entry_events_reach_the_report_query() -> Result<()> {
    use seance_core::artifact::{Artifact, ArtifactType};
    use serde_json::json;

    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "a.doc", "path": "/a.doc", "modified": 1_700_000_100i64,
               "created": 1_700_000_000i64}),
    );
    db.record_artifact(&file).await?;
    db.create_timeline_tag(case_id, file.id, Some("ex"), Some("n"))
        .await?;

    let tagged = db.get_tagged_timeline_events(case_id).await?;
    assert_eq!(tagged.len(), 2, "both projected rows of the tagged file");
    assert!(tagged.iter().all(|(e, _, _)| e.artifact_id == file.id));
    Ok(())
}
