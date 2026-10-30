use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

/// Helper to setup test database
async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

/// Helper to create a test case
async fn create_test_case(db: &SqliteConnection) -> Result<Uuid> {
    db.create_case("Test Case", "Test Examiner").await
}

/// Helper to create a test artifact and timeline event with custom JSON
async fn create_test_event(
    db: &SqliteConnection,
    case_id: Uuid,
    full_details: &str,
) -> Result<Uuid> {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: serde_json::json!({
            "timestamp": 1234567890i64,
            "timestamp_desc": "Test Event",
            "source_module": "TestModule",
            "short_desc": "Test description",
            "full_details": full_details,
        }),
        data: None,
    };

    let event_id = artifact.id;
    db.record_artifact(&artifact).await?;
    Ok(event_id)
}

#[tokio::test]
async fn test_dynamic_columns_none() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await?;

    // Query without dynamic columns - should have None for dynamic_fields
    let events = db
        .get_timeline_events_filtered(
            case_id, None, None, None, None, None, None, None, None, None, None,
            None, // No dynamic columns
            None, // event_ids
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].dynamic_fields.is_none());
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_single_field() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await?;

    // Query with single dynamic column
    let columns = vec!["$.filename".to_string()];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    let dynamic = events[0].dynamic_fields.as_ref().unwrap();
    assert_eq!(dynamic.len(), 1);
    assert_eq!(
        dynamic.get("filename").unwrap().as_str().unwrap(),
        "test.txt"
    );
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_multiple_fields() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024, "is_hidden": true}"#,
    )
    .await?;

    // Query with multiple dynamic columns
    let columns = vec![
        "$.filename".to_string(),
        "$.file_size".to_string(),
        "$.is_hidden".to_string(),
    ];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    let dynamic = events[0].dynamic_fields.as_ref().unwrap();
    assert_eq!(dynamic.len(), 3);
    assert_eq!(
        dynamic.get("filename").unwrap().as_str().unwrap(),
        "test.txt"
    );
    assert_eq!(dynamic.get("file_size").unwrap().as_i64().unwrap(), 1024);
    assert!(dynamic.get("is_hidden").unwrap().as_bool().unwrap());
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_missing_field() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(&db, case_id, r#"{"filename": "test.txt"}"#).await?;

    // Request a field that doesn't exist
    let columns = vec!["$.filename".to_string(), "$.nonexistent".to_string()];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    let dynamic = events[0].dynamic_fields.as_ref().unwrap();
    // Should only have the field that exists
    assert_eq!(dynamic.len(), 1);
    assert!(dynamic.contains_key("filename"));
    assert!(!dynamic.contains_key("nonexistent"));
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_different_types() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{
            "str_field": "text",
            "num_field": 42,
            "bool_field": true,
            "array_field": [1, 2, 3],
            "object_field": {"nested": "value"}
        }"#,
    )
    .await?;

    let columns = vec![
        "$.str_field".to_string(),
        "$.num_field".to_string(),
        "$.bool_field".to_string(),
        "$.array_field".to_string(),
        "$.object_field".to_string(),
    ];

    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    let dynamic = events[0].dynamic_fields.as_ref().unwrap();

    assert_eq!(dynamic.get("str_field").unwrap().as_str().unwrap(), "text");
    assert_eq!(dynamic.get("num_field").unwrap().as_i64().unwrap(), 42);
    assert!(dynamic.get("bool_field").unwrap().as_bool().unwrap());
    assert!(dynamic.get("array_field").unwrap().is_array());
    assert!(dynamic.get("object_field").unwrap().is_object());
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_multiple_events() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "file1.txt", "file_size": 100}"#,
    )
    .await?;
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "file2.txt", "file_size": 200}"#,
    )
    .await?;
    create_test_event(&db, case_id, r#"{"filename": "file3.txt"}"#).await?; // Missing file_size

    let columns = vec!["$.filename".to_string(), "$.file_size".to_string()];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 3);

    // Identical timestamps make result order arbitrary (stable, but keyed on
    // random event UUIDs) — match events by filename instead of position.
    for event in &events {
        let dynamic = event.dynamic_fields.as_ref().unwrap();
        let filename = dynamic.get("filename").and_then(|v| v.as_str()).unwrap();
        match filename {
            // file1 and file2 have both fields
            "file1.txt" | "file2.txt" => assert_eq!(dynamic.len(), 2),
            // file3 is missing file_size
            "file3.txt" => assert_eq!(dynamic.len(), 1),
            other => panic!("unexpected filename: {}", other),
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_invalid_json() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Non-JSON full_details is preserved (wrapped as a JSON string) rather
    // than rejected -- rejecting would silently discard plugin evidence.
    create_test_event(&db, case_id, "not valid json").await?;

    // A JSON string has no extractable paths, so dynamic columns are empty.
    let columns = vec!["$.filename".to_string()];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;
    assert_eq!(events.len(), 1);
    assert!(events[0]
        .dynamic_fields
        .as_ref()
        .is_none_or(|f| f.is_empty()));

    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_with_filters() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await?;
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "other.txt", "file_size": 2048}"#,
    )
    .await?;

    let columns = vec!["$.filename".to_string(), "$.file_size".to_string()];

    // Apply filename filter
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            None,         // search_text
            Some("test"), // filename_filter
            None,         // event_type_filter
            None,
            None,
            None,
            None,
            Some(&columns),
            None,
        )
        .await?;

    // Should only get the filtered event
    assert_eq!(events.len(), 1);
    let dynamic = events[0].dynamic_fields.as_ref().unwrap();
    assert_eq!(
        dynamic.get("filename").unwrap().as_str().unwrap(),
        "test.txt"
    );
    Ok(())
}

#[tokio::test]
async fn test_dynamic_columns_empty_list() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(&db, case_id, r#"{"filename": "test.txt"}"#).await?;

    // Empty columns list should result in None for dynamic_fields
    let columns: Vec<String> = vec![];
    let events = db
        .get_timeline_events_filtered(
            case_id,
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
            Some(&columns),
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].dynamic_fields.is_none());
    Ok(())
}

/// An update that matches no row (missing id, another case's column, a built-in
/// column) must say so: `Ok(false)`, not a success the UI reports as saved.
#[tokio::test]
async fn update_virtual_column_reports_whether_a_row_matched() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;
    let other_case = db.create_case("Other", "Examiner").await?;
    let def: seance_core::virtual_columns::VirtualColumnDef =
        serde_json::from_value(serde_json::json!({
            "id": "vc_custom_x", "name": "X", "description": "d", "type": "string",
            "sources": [{"path": "$.x", "artifact_types": []}],
            "default_visible": false, "built_in": false
        }))?;
    db.create_virtual_column(case_id, &def).await?;

    assert!(db.update_virtual_column(case_id, &def).await?);
    assert!(
        !db.update_virtual_column(other_case, &def).await?,
        "another case's column is not updated"
    );
    let mut missing = def.clone();
    missing.id = "vc_custom_missing".to_string();
    assert!(!db.update_virtual_column(case_id, &missing).await?);
    Ok(())
}
