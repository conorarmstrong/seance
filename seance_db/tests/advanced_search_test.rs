use anyhow::Result;
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

/// Helper to create a test timeline event with specific details
async fn create_test_event_with_details(
    db: &SqliteConnection,
    case_id: Uuid,
    timestamp_desc: &str,
    source_module: &str,
    short_desc: &str,
    full_details: &str,
) -> Result<Uuid> {
    use seance_core::artifact::{Artifact, ArtifactType};
    use serde_json::json;

    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: json!({
            "timestamp": 1234567890i64,
            "timestamp_desc": timestamp_desc,
            "source_module": source_module,
            "short_desc": short_desc,
            "full_details": full_details,
        }),
        data: None,
    };

    let event_id = artifact.id;
    db.record_artifact(&artifact).await?;
    Ok(event_id)
}

#[tokio::test]
async fn test_simple_search() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz executed",
        r#"{"filename": "mimikatz.exe"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "notepad executed",
        r#"{"filename": "notepad.exe"}"#,
    )
    .await?;

    // Simple search for "mimikatz"
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("mimikatz"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].short_desc.contains("mimikatz"));

    Ok(())
}

#[tokio::test]
async fn test_required_terms() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz with lsass",
        r#"{"details": "mimikatz dumping lsass process"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz only",
        r#"{"details": "mimikatz running"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "lsass only",
        r#"{"details": "lsass process"}"#,
    )
    .await?;

    // Search for "+mimikatz +lsass" (both required)
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("+mimikatz +lsass"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    // Should only match the first event
    assert_eq!(events.len(), 1);
    assert!(events[0].short_desc.contains("mimikatz with lsass"));

    Ok(())
}

#[tokio::test]
async fn test_excluded_terms() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz activity",
        r#"{"details": "mimikatz detected but marked as false_positive in notes"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz execution detected",
        r#"{"details": "mimikatz process running"}"#,
    )
    .await?;

    // Search for "+mimikatz -false_positive" (must have mimikatz, must not have false_positive)
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("+mimikatz -false_positive"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    // Should only match the second event
    assert_eq!(events.len(), 1);
    assert!(events[0].short_desc.contains("execution"));

    Ok(())
}

#[tokio::test]
async fn test_exact_phrase() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "lateral movement detected",
        r#"{"details": "lateral movement attack"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "lateral and movement",
        r#"{"details": "movement after lateral shift"}"#,
    )
    .await?;

    // Search for exact phrase "lateral movement"
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some(r#""lateral movement""#),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    // Only the event holding the phrase literally matches; the split-term
    // event ("lateral and movement") must not.
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].short_desc, "lateral movement detected");

    Ok(())
}

#[tokio::test]
async fn test_column_filter_event_type() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events with different event types
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "file created",
        r#"{"filename": "test.txt"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Modified",
        "test.module",
        "file modified",
        r#"{"filename": "test.txt"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Deleted",
        "test.module",
        "file deleted",
        r#"{"filename": "test.txt"}"#,
    )
    .await?;

    // Search for EventType:Created
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("EventType:Created"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].timestamp_desc.contains("Created"));

    Ok(())
}

#[tokio::test]
async fn test_column_filter_source() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events from different modules
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "plugin.mft",
        "MFT entry",
        r#"{"filename": "test.txt"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "plugin.prefetch",
        "Prefetch file",
        r#"{"filename": "test.pf"}"#,
    )
    .await?;

    // Search for Source:mft
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("Source:mft"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].source_module.contains("mft"));

    Ok(())
}

#[tokio::test]
async fn test_wildcard_in_column_filter() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events with different resources
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "executable created",
        r#"{"Resource": "malware.exe"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "dll created",
        r#"{"Resource": "library.dll"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "text file created",
        r#"{"Resource": "document.txt"}"#,
    )
    .await?;

    // Search for Resource:*.exe
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("Resource:*.exe"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);
    assert!(events[0].full_details.contains(".exe"));

    Ok(())
}

#[tokio::test]
async fn test_complex_query() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create various events
    create_test_event_with_details(
        &db,
        case_id,
        "Modified",
        "plugin.mft",
        "DLL modified",
        r#"{"Resource": "system32.dll", "details": "modified"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Modified",
        "plugin.prefetch",
        "DLL modified prefetch",
        r#"{"Resource": "prefetch.dll", "details": "prefetch modified"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "plugin.mft",
        "DLL created",
        r#"{"Resource": "new.dll", "details": "created"}"#,
    )
    .await?;

    // Complex query: +EventType:Modified +Resource:*.dll -prefetch
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("+EventType:Modified +Resource:*.dll -prefetch"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    // Should match only the first event (Modified + .dll + not prefetch)
    assert_eq!(events.len(), 1);
    assert!(events[0].timestamp_desc.contains("Modified"));
    assert!(events[0].full_details.contains(".dll"));
    assert!(!events[0].full_details.contains("prefetch"));

    Ok(())
}

#[tokio::test]
async fn test_fallback_to_simple_search_on_parse_error() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "test event",
        r#"{"details": "some details"}"#,
    )
    .await?;

    // A second event whose text literally contains `""`.
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        r#"empty quotes "" here"#,
        r#"{"details": "other"}"#,
    )
    .await?;

    // Invalid query (empty phrase) - falls back to a LIKE search on the raw
    // text, so only the event containing `""` matches (not all, not none).
    let search = Some(r#""""#);
    let events = db
        .get_timeline_events_filtered(
            case_id, None, None, None, search, None, None, None, None, None, None, None, None,
        )
        .await?;
    assert_eq!(events.len(), 1);
    assert!(events[0].short_desc.contains(r#""""#));

    // The count must agree with the page.
    let count = db
        .get_timeline_events_count(case_id, None, None, None, search, None, None, None)
        .await?;
    assert_eq!(count, 1);

    Ok(())
}

#[tokio::test]
async fn test_case_insensitive_search() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "MIMIKATZ executed",
        r#"{"details": "MimiKatz.exe"}"#,
    )
    .await?;

    // Search with different case
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("mimikatz"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_search_in_both_short_desc_and_full_details() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create event with search term in short_desc
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "malware detected",
        r#"{"details": "some other info"}"#,
    )
    .await?;

    // Create event with search term in full_details
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "file created",
        r#"{"details": "malware analysis"}"#,
    )
    .await?;

    // Search for "malware"
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("malware"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    // Should match both events
    assert_eq!(events.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_count_with_advanced_search() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create multiple events
    for i in 0..10 {
        create_test_event_with_details(
            &db,
            case_id,
            "Created",
            "test.module",
            &format!("event {}", i),
            r#"{"details": "mimikatz"}"#,
        )
        .await?;
    }

    for i in 0..5 {
        create_test_event_with_details(
            &db,
            case_id,
            "Created",
            "test.module",
            &format!("event {}", i + 10),
            r#"{"details": "other"}"#,
        )
        .await?;
    }

    // Count events matching "mimikatz"
    let count = db
        .get_timeline_events_count(
            case_id,
            None,
            None,
            None,
            Some("mimikatz"),
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(count, 10);

    // Count events matching advanced search "+mimikatz"
    let count_advanced = db
        .get_timeline_events_count(
            case_id,
            None,
            None,
            None,
            Some("+mimikatz"),
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(count_advanced, 10);

    Ok(())
}

#[tokio::test]
async fn test_empty_search_query() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "test event",
        r#"{"details": "some details"}"#,
    )
    .await?;

    // Empty search should return all events
    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some(""),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;

    assert_eq!(events.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_multiple_optional_terms() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Create events
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "mimikatz detected",
        r#"{"details": "mimikatz.exe"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "lsass dumped",
        r#"{"details": "lsass.exe"}"#,
    )
    .await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "notepad opened",
        r#"{"details": "notepad.exe"}"#,
    )
    .await?;

    // Without special syntax the whole text is one literal substring, so two
    // words that no single event holds together match nothing.
    let plain = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("mimikatz lsass"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(plain.len(), 0);

    // On the advanced path (`-` routes there) unprefixed terms are optional
    // and combine with OR: both events match, the excluded one does not.
    let advanced = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("mimikatz lsass -notepad"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(advanced.len(), 2);
    assert!(advanced.iter().all(|e| !e.short_desc.contains("notepad")));

    Ok(())
}

// ── BUG-246 / BUG-247: advanced search must be literal ──────────────────────

#[tokio::test]
async fn test_advanced_search_underscore_is_literal() -> Result<()> {
    // `+` puts the query on the advanced path, where `_` used to stay a LIKE
    // wildcard: `report_final` also matched `reportxfinal`, silently widening
    // list, count, histogram and export results (BUG-246).
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "report_final.docx written",
        r#"{"filename": "report_final.docx"}"#,
    )
    .await?;
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "reportxfinal.docx written",
        r#"{"filename": "reportxfinal.docx"}"#,
    )
    .await?;

    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("+report_final"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(events.len(), 1, "underscore must match literally");
    assert!(events[0].short_desc.starts_with("report_final"));

    let count = db
        .get_timeline_events_count(
            case_id,
            None,
            None,
            None,
            Some("+report_final"),
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(count, 1, "the count must agree with the list");

    Ok(())
}

#[tokio::test]
async fn test_advanced_search_windows_path_is_searched_literally() -> Result<()> {
    // A drive letter makes the query "advanced" because of the ':'. It must be
    // searched as text, not parsed as a filter on a column called `C` (BUG-247).
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "opened C:\\Users\\alice\\report.docx",
        r#"{"filename": "report.docx"}"#,
    )
    .await?;
    create_test_event_with_details(
        &db,
        case_id,
        "Created",
        "test.module",
        "opened D:\\Users\\bob\\report.docx",
        r#"{"filename": "report.docx"}"#,
    )
    .await?;

    let events = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            Some("C:\\Users\\alice"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(events.len(), 1, "the Windows path must find its own event");
    assert!(events[0].short_desc.contains("C:\\Users\\alice"));

    Ok(())
}
