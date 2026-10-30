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
async fn test_schema_discovery_empty_case() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    let schema = db.get_timeline_schema(case_id).await?;

    assert_eq!(schema.available_fields.len(), 0);
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_single_field() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(&db, case_id, r#"{"filename": "test.txt"}"#).await?;

    let schema = db.get_timeline_schema(case_id).await?;

    assert_eq!(schema.available_fields.len(), 1);
    assert_eq!(schema.available_fields[0].path, "$.filename");
    assert_eq!(schema.available_fields[0].field_type, "string");
    assert_eq!(schema.available_fields[0].frequency, 1);
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_multiple_fields() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024, "is_hidden": true}"#,
    )
    .await?;

    let schema = db.get_timeline_schema(case_id).await?;

    assert_eq!(schema.available_fields.len(), 3);

    // Check each field type
    let filename = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.filename")
        .unwrap();
    assert_eq!(filename.field_type, "string");

    let file_size = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.file_size")
        .unwrap();
    assert_eq!(file_size.field_type, "number");

    let is_hidden = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.is_hidden")
        .unwrap();
    assert_eq!(is_hidden.field_type, "boolean");
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_field_frequency() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create 3 events, filename appears in all, file_size in 2, is_hidden in 1
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test1.txt", "file_size": 1024, "is_hidden": true}"#,
    )
    .await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test2.txt", "file_size": 2048}"#,
    )
    .await?;

    create_test_event(&db, case_id, r#"{"filename": "test3.txt"}"#).await?;

    let schema = db.get_timeline_schema(case_id).await?;

    let filename = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.filename")
        .unwrap();
    assert_eq!(filename.frequency, 3);

    let file_size = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.file_size")
        .unwrap();
    assert_eq!(file_size.frequency, 2);

    let is_hidden = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.is_hidden")
        .unwrap();
    assert_eq!(is_hidden.frequency, 1);
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_sorted_by_frequency() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events where some fields appear more frequently
    for _ in 0..5 {
        create_test_event(&db, case_id, r#"{"common": "value", "rare": "data"}"#).await?;
    }

    for _ in 0..3 {
        create_test_event(&db, case_id, r#"{"common": "value"}"#).await?;
    }

    let schema = db.get_timeline_schema(case_id).await?;

    // Should be sorted by frequency descending
    assert_eq!(schema.available_fields[0].path, "$.common");
    assert_eq!(schema.available_fields[0].frequency, 8);

    assert_eq!(schema.available_fields[1].path, "$.rare");
    assert_eq!(schema.available_fields[1].frequency, 5);
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_sample_values() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await?;

    let schema = db.get_timeline_schema(case_id).await?;

    let filename = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.filename")
        .unwrap();
    assert!(filename.sample_value.is_some());
    assert_eq!(
        filename.sample_value.as_ref().unwrap().as_str().unwrap(),
        "test.txt"
    );

    let file_size = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.file_size")
        .unwrap();
    assert!(file_size.sample_value.is_some());
    assert_eq!(
        file_size.sample_value.as_ref().unwrap().as_i64().unwrap(),
        1024
    );
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_different_types() -> Result<()> {
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

    let schema = db.get_timeline_schema(case_id).await?;

    assert_eq!(schema.available_fields.len(), 5);

    let str_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.str_field")
        .unwrap();
    assert_eq!(str_field.field_type, "string");

    let num_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.num_field")
        .unwrap();
    assert_eq!(num_field.field_type, "number");

    let bool_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.bool_field")
        .unwrap();
    assert_eq!(bool_field.field_type, "boolean");

    let array_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.array_field")
        .unwrap();
    assert_eq!(array_field.field_type, "array");

    let object_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.object_field")
        .unwrap();
    assert_eq!(object_field.field_type, "object");
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_ignores_null_values() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(&db, case_id, r#"{"field": null}"#).await?;

    let schema = db.get_timeline_schema(case_id).await?;

    // Should still track the field even if null
    let field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.field")
        .unwrap();
    assert_eq!(field.frequency, 1);
    assert!(field.sample_value.is_none()); // No sample value for null
    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_invalid_json() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Non-JSON full_details is preserved (wrapped as a JSON string) rather
    // than rejected -- rejecting would silently discard plugin evidence.
    create_test_event(&db, case_id, "not valid json").await?;

    // A JSON string exposes no object keys, so schema discovery finds nothing.
    let schema = db.get_timeline_schema(case_id).await?;
    assert!(
        schema.available_fields.is_empty(),
        "wrapped plain-text details should expose no fields: {:?}",
        schema.available_fields
    );

    Ok(())
}

#[tokio::test]
async fn test_schema_discovery_isolated_by_case() -> Result<()> {
    let db = setup_test_db().await?;
    let case1_id = create_test_case(&db).await?;
    let case2_id = db.create_case("Case 2", "Examiner").await?;

    // Create event in case 1
    create_test_event(&db, case1_id, r#"{"case1_field": "value"}"#).await?;

    // Create event in case 2
    create_test_event(&db, case2_id, r#"{"case2_field": "value"}"#).await?;

    let schema1 = db.get_timeline_schema(case1_id).await?;
    let schema2 = db.get_timeline_schema(case2_id).await?;

    // Each case should only see its own fields
    assert_eq!(schema1.available_fields.len(), 1);
    assert_eq!(schema1.available_fields[0].path, "$.case1_field");

    assert_eq!(schema2.available_fields.len(), 1);
    assert_eq!(schema2.available_fields[0].path, "$.case2_field");
    Ok(())
}

/// B4-021: schema discovery reads a bounded sample and returned only the field
/// list. A field present solely in the unread remainder was simply absent from
/// the schema, every `frequency` was a count within the sample rather than a
/// prevalence in the case, and nothing said either thing — so a filter UI
/// presented a partial field list as the complete schema of the evidence.
#[tokio::test]
async fn a_sampled_schema_says_that_it_is_a_sample() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // One past the sample size, so discovery cannot have read them all.
    for _ in 0..1001 {
        create_test_event(&db, case_id, r#"{"filename": "test.txt"}"#).await?;
    }

    let schema = db.get_timeline_schema(case_id).await?;
    assert!(
        schema.sampled,
        "a schema built from part of the case must declare itself a sample"
    );
    assert_eq!(schema.sample_size, 1000, "events actually read");
    assert_eq!(schema.total_events, 1001, "events the case holds");
    assert_eq!(
        schema.undecodable_events, 0,
        "every sampled event parsed here"
    );
    // The frequency is a count within the sample, never the case total.
    assert_eq!(schema.available_fields[0].frequency, 1000);

    Ok(())
}

/// A case small enough to read whole must NOT be labelled a sample, or the
/// disclosure stops meaning anything.
#[tokio::test]
async fn a_complete_schema_is_not_labelled_a_sample() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event(&db, case_id, r#"{"filename": "a.txt"}"#).await?;
    create_test_event(&db, case_id, r#"{"filename": "b.txt"}"#).await?;

    let schema = db.get_timeline_schema(case_id).await?;
    assert!(!schema.sampled);
    assert_eq!(schema.sample_size, 2);
    assert_eq!(schema.total_events, 2);
    Ok(())
}
