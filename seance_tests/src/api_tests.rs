use anyhow::Result;
use reqwest::Client;
use seance_api::{
    router_with_auth, AppState, AuthConfig, BookmarkCategoryResponse, CaseResponse, CaseStats,
    ErrorResponse, IngestResponse, PaginatedTimelineResponse, ProcessingCensus,
};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::module::ModuleInfo;
use seance_core::orchestrator::Orchestrator;
use seance_db::SqliteConnection;
use seance_plugin_mft::MftParser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn spawn_test_api() -> Result<(Client, String, Arc<SqliteConnection>)> {
    let db_url = "sqlite::memory:".to_string();

    let db_conn = Arc::new(SqliteConnection::new(&db_url).await?);
    db_conn.initialize().await?;

    let orchestrator_db_clone = db_conn.clone();
    let mut orchestrator =
        Orchestrator::new(Some(orchestrator_db_clone), 100).with_exit_on_idle(false);
    orchestrator.register_module(Arc::new(MftParser::new()));
    let orchestrator_sender = orchestrator.task_submitter();
    let event_sender = orchestrator.event_sender();
    let ad_hoc_sender = orchestrator.ad_hoc_submitter();
    let status_sender = orchestrator.status_sender();
    let active_tasks = orchestrator.active_tasks();
    let case_census = orchestrator.case_census();
    let ingestion_service = orchestrator.ingestion_service();

    tokio::spawn(async move {
        orchestrator.run().await;
    });

    let app_state = AppState {
        db: db_conn.clone(),
        orchestrator_sender,
        event_sender,
        ad_hoc_sender,
        status_sender,
        active_tasks,
        search_service: None,
        ingestion_service,
        module_registry: vec![
            ModuleInfo {
                id: "plugin.ntfs.mft".to_string(),
                version: "1.0.0".to_string(),
                subscribes_to: vec!["FileSystem".to_string()],
                execution_mode: "Automatic".to_string(),
            },
            ModuleInfo {
                id: "plugin.ntfs.usnjrnl".to_string(),
                version: "1.0.0".to_string(),
                subscribes_to: vec!["FileEntry".to_string()],
                execution_mode: "Automatic".to_string(),
            },
        ],
        signing_config: None,
        evidence_roots: seance_api::EvidenceRootPolicy::from_env(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };

    let auth_config = AuthConfig {
        enabled: false,
        ..AuthConfig::from_env()
    };
    // Layered as seance_api/src/main.rs layers it, so `GET /api/v1/status`
    // answers here with the per-case census the served binary gives and not
    // with the `cases_unavailable` reason a census-less embedding gets.
    let app = router_with_auth(app_state, Some(auth_config))
        .layer(axum::Extension(ProcessingCensus(case_census)));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let client = Client::new();
    let api_base = format!("http://127.0.0.1:{}", port);

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("Test API server failed to start");
    });

    Ok((client, api_base, db_conn))
}

/// The rows of a capped-listing envelope, with the disclosure fields checked.
///
/// Every paged endpoint answers with an object, never a bare array, because a
/// listing that stopped at its ceiling and a listing that is genuinely complete
/// must not look the same on the wire (B8-006/007, B8-019, B8-027, B8-030,
/// B8-031). Two unrelated shortfalls are carried separately:
///
/// * `truncated`/`has_more` -- the query stopped early; further rows exist and
///   paging reaches them.
/// * `undecodable` -- rows inside this page's window would not decode, so they
///   are missing from every page and paging never recovers them. `null` means
///   the query has no channel for the fact, which reads as "not determined",
///   never as zero.
///
/// Asserting the fields are present is the point: a change that computes the
/// flags and then drops them before the wire has to fail here rather than pass
/// by looking like a complete answer.
fn listing_items(body: &serde_json::Value, what: &str) -> Vec<serde_json::Value> {
    let items = body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{what} listing must carry its rows under `items`: {body}"))
        .clone();
    for field in [
        "limit",
        "offset",
        "has_more",
        "truncated",
        "count_is_lower_bound",
        // Present even when null: `undecodable` null means "not determined",
        // and `inventory_incomplete_reason` null means "nothing was lost".
        // Omitting either would let a reader supply the reassuring default.
        "undecodable",
        "inventory_incomplete",
        "inventory_incomplete_reason",
    ] {
        assert!(
            body.get(field).is_some(),
            "{what} listing must disclose `{field}`"
        );
    }
    items
}

/// The rows of a listing that claims to be the whole answer, with that claim
/// checked rather than assumed.
fn complete_listing_items(body: &serde_json::Value, what: &str) -> Vec<serde_json::Value> {
    let items = listing_items(body, what);
    assert_eq!(
        body["truncated"],
        serde_json::json!(false),
        "{what} listing was not expected to be capped"
    );
    assert_eq!(
        body["has_more"],
        serde_json::json!(false),
        "{what} listing was not expected to be capped"
    );
    assert_eq!(
        body["count_is_lower_bound"],
        serde_json::json!(false),
        "{what} row count was not expected to be a floor"
    );
    assert_eq!(
        body["undecodable"],
        serde_json::json!(0),
        "{what} listing was not expected to drop rows"
    );
    assert_eq!(
        body["inventory_incomplete"],
        serde_json::json!(false),
        "{what} listing holds everything that matched"
    );
    assert_eq!(
        body["inventory_incomplete_reason"],
        serde_json::Value::Null,
        "{what} listing is whole, so it must name no shortfall"
    );
    items
}

/// Insert a test artifact directly into the database and return its UUID.
/// Bookmarks require a real artifact due to foreign key constraints.
async fn create_test_artifact(db: &Arc<SqliteConnection>, case_id: Uuid) -> Result<Uuid> {
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        serde_json::json!({"name": "test_evidence.dat", "size": 1024}),
    );
    let artifact_id = artifact.id;
    db.record_artifact(&artifact).await?;
    Ok(artifact_id)
}

/// Create a case and return its CaseResponse. Used as boilerplate in most tests.
async fn create_test_case(client: &Client, api_base: &str) -> Result<CaseResponse> {
    let res = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({
            "name": "Integration Test Case",
            "examiner_name": "Test Examiner"
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200, "Failed to create test case");
    Ok(res.json().await?)
}

// ===========================================================================
// Case CRUD (6 tests)
// ===========================================================================

#[tokio::test]
async fn test_create_case() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    let create_case_url = format!("{}/api/v1/cases", api_base);
    let payload = serde_json::json!({
        "name": "Test Case 1",
        "examiner_name": "John Doe"
    });

    let response = client.post(&create_case_url).json(&payload).send().await?;

    assert_eq!(response.status(), 200);

    let case: CaseResponse = response.json().await?;
    assert_eq!(case.name, "Test Case 1");
    assert_eq!(case.status, "active");
    assert!(!case.id.is_nil());

    Ok(())
}

#[tokio::test]
async fn test_list_cases() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // Initially empty
    let res = client
        .get(format!("{}/api/v1/cases", api_base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let cases: Vec<CaseResponse> = res.json().await?;
    assert!(cases.is_empty(), "Expected no cases initially");

    // Create two cases
    create_test_case(&client, &api_base).await?;
    let _ = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({"name": "Second Case"}))
        .send()
        .await?;

    let res = client
        .get(format!("{}/api/v1/cases", api_base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let cases: Vec<CaseResponse> = res.json().await?;
    assert_eq!(cases.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_get_case() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let fetched: CaseResponse = res.json().await?;
    assert_eq!(fetched.id, case.id);
    assert_eq!(fetched.name, case.name);

    Ok(())
}

#[tokio::test]
async fn test_update_case() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .put(format!("{}/api/v1/cases/{}", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Updated Name",
            "reference_number": "REF-001",
            "examiner_name": "New Examiner"
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let updated: CaseResponse = res.json().await?;
    assert_eq!(updated.name, "Updated Name");
    assert_eq!(updated.reference_number.as_deref(), Some("REF-001"));
    assert_eq!(updated.examiner_name.as_deref(), Some("New Examiner"));

    Ok(())
}

#[tokio::test]
async fn test_delete_case() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Accepted and marked; the rows go in the background (HUNT-072).
    let res = client
        .delete(format!("{}/api/v1/cases/{}", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 202);

    // Verify it is gone from the API at once
    let res = client
        .get(format!("{}/api/v1/cases/{}", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 404);

    Ok(())
}

#[tokio::test]
async fn test_get_or_create_default_case() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // With no cases, a default should be created
    let res = client
        .get(format!("{}/api/v1/cases/default_case", api_base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let default_case: CaseResponse = res.json().await?;
    assert!(!default_case.id.is_nil());

    // Calling again returns the same case (or at least a case)
    let res2 = client
        .get(format!("{}/api/v1/cases/default_case", api_base))
        .send()
        .await?;
    assert_eq!(res2.status(), 200);
    let second: CaseResponse = res2.json().await?;
    assert!(!second.id.is_nil());

    Ok(())
}

// ===========================================================================
// Timeline (4 tests)
// ===========================================================================

#[tokio::test]
async fn test_get_timeline_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/timeline", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: PaginatedTimelineResponse = res.json().await?;
    assert!(body.events.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_get_timeline_source_modules_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/timeline/modules",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert!(body.as_object().is_none_or(|m| m.is_empty()));

    Ok(())
}

#[tokio::test]
async fn test_get_timeline_tags_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/timeline/tags",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let tags: Vec<serde_json::Value> = res.json().await?;
    assert!(tags.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_get_timeline_schema() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/timeline/schema",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let schema: serde_json::Value = res.json().await?;
    // Schema should be a valid JSON object
    assert!(schema.is_object());

    Ok(())
}

// ===========================================================================
// Bookmarks (6 tests)
// ===========================================================================

#[tokio::test]
async fn test_create_bookmark_category() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .json(&serde_json::json!({"name": "Important", "color": "#ff0000"}))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let cat: serde_json::Value = res.json().await?;
    assert_eq!(cat["name"].as_str(), Some("Important"));

    Ok(())
}

#[tokio::test]
async fn test_list_bookmark_categories() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create two categories
    client
        .post(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .json(&serde_json::json!({"name": "Suspicious", "color": "#ff0000"}))
        .send()
        .await?;
    client
        .post(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .json(&serde_json::json!({"name": "Evidence", "color": "#00ff00"}))
        .send()
        .await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let cats: Vec<BookmarkCategoryResponse> = res.json().await?;
    assert_eq!(cats.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_create_bookmark() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Bookmarks require a real artifact due to FK constraints
    let artifact_id = create_test_artifact(&db, case.id).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({
            "artifact_id": artifact_id,
            "note": "Suspicious file found"
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let bookmark: serde_json::Value = res.json().await?;
    assert_eq!(
        bookmark["artifact_id"].as_str(),
        Some(artifact_id.to_string().as_str())
    );

    Ok(())
}

#[tokio::test]
async fn test_list_bookmarks() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create a bookmark (requires a real artifact due to FK constraints)
    let artifact_id = create_test_artifact(&db, case.id).await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({"artifact_id": artifact_id, "note": "Test"}))
        .send()
        .await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    // An object carrying `items` plus the completeness flags, not a bare array
    // (B8-031): an examiner reads a bookmark list as the complete set of things
    // someone deliberately marked, so a list that stopped at its ceiling must
    // say so on the wire.
    let body: serde_json::Value = res.json().await?;
    let bookmarks = complete_listing_items(&body, "bookmarks");
    assert_eq!(bookmarks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_get_bookmarked_artifact_ids() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create real artifacts for FK constraints
    let art1 = create_test_artifact(&db, case.id).await?;
    let art2 = create_test_artifact(&db, case.id).await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({"artifact_id": art1}))
        .send()
        .await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({"artifact_id": art2}))
        .send()
        .await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/bookmarks/ids",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let ids: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(ids.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_delete_bookmark() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create a real artifact for FK constraints
    let artifact_id = create_test_artifact(&db, case.id).await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({"artifact_id": artifact_id, "note": "To delete"}))
        .send()
        .await?;

    let res = client
        .delete(format!(
            "{}/api/v1/cases/{}/bookmarks/{}",
            api_base, case.id, artifact_id
        ))
        .send()
        .await?;
    // Should succeed (200 or 204)
    assert!(
        res.status().is_success(),
        "Delete bookmark failed: {}",
        res.status()
    );

    // Verify it is gone. "No bookmarks" and "we could not tell you how many
    // bookmarks" must not render alike, so the flags are checked here too: an
    // empty `items` only means the case has none when the listing also says it
    // is whole.
    let res = client
        .get(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let bookmarks = complete_listing_items(&body, "bookmarks");
    assert!(bookmarks.is_empty());

    Ok(())
}

// ===========================================================================
// Search (1 test)
// ===========================================================================

#[tokio::test]
async fn test_search_no_service() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // With search_service: None, the search endpoint should return 500
    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/search?q=test",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 500);
    let body: ErrorResponse = res.json().await?;
    assert_eq!(body.error.code, "JOB_FAILED");

    Ok(())
}

// ===========================================================================
// Profiles (5 tests)
// ===========================================================================

#[tokio::test]
async fn test_create_profile() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Triage Profile",
            "description": "Quick scan",
            "enabled_modules": ["plugin.ntfs.mft"],
            "disabled_modules": []
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    // ProfileResponseWithWarnings uses #[serde(flatten)] so fields are at top level
    assert_eq!(body["name"].as_str(), Some("Triage Profile"));

    Ok(())
}

#[tokio::test]
async fn test_list_profiles() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Initially empty
    let res = client
        .get(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let profiles: Vec<serde_json::Value> = res.json().await?;
    assert!(profiles.is_empty());

    // Create one
    client
        .post(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Deep Scan",
            "description": "Full analysis",
            "enabled_modules": [],
            "disabled_modules": []
        }))
        .send()
        .await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let profiles: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(profiles.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_get_active_profile_none() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/profiles/active",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert!(body.is_null(), "Expected null when no active profile");

    Ok(())
}

#[tokio::test]
async fn test_delete_profile() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create
    let res = client
        .post(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .json(&serde_json::json!({
            "name": "To Delete",
            "description": "Ephemeral",
            "enabled_modules": [],
            "disabled_modules": []
        }))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    // ProfileResponseWithWarnings uses #[serde(flatten)] so fields are at top level
    let profile_id = body["id"].as_str().unwrap().to_string();

    // Delete
    let res = client
        .delete(format!(
            "{}/api/v1/cases/{}/profiles/{}",
            api_base, case.id, profile_id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 204);

    // Verify gone
    let res = client
        .get(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .send()
        .await?;
    let profiles: Vec<serde_json::Value> = res.json().await?;
    assert!(profiles.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_create_profile_with_unknown_modules() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/profiles", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Profile with unknowns",
            "description": "Testing warnings",
            "enabled_modules": ["plugin.nonexistent.module"],
            "disabled_modules": []
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    // Should have warnings about unknown modules
    let warnings = body["warnings"].as_array();
    assert!(
        warnings.is_some(),
        "Expected warnings for unknown module IDs"
    );
    assert!(!warnings.unwrap().is_empty());

    Ok(())
}

// ===========================================================================
// Jobs (1 test)
// ===========================================================================

#[tokio::test]
async fn test_list_jobs_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/jobs", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    // The job list is a capped-listing envelope, not a bare array (B8-030). An
    // examiner reads it to answer "was this analysis ever run", and a list that
    // stopped at its ceiling without saying so invites the answer "no".
    let body: serde_json::Value = res.json().await?;
    let jobs = complete_listing_items(&body, "jobs");
    assert!(jobs.is_empty());

    Ok(())
}

// ===========================================================================
// Hash Sets (3 tests)
// ===========================================================================

#[tokio::test]
async fn test_create_hash_set() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .json(&serde_json::json!({"name": "Known Bad Hashes"}))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert!(body["id"].as_str().is_some());
    assert_eq!(body["status"].as_str(), Some("created"));

    Ok(())
}

#[tokio::test]
async fn test_list_hash_sets() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create one
    client
        .post(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .json(&serde_json::json!({"name": "NSRL"}))
        .send()
        .await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let sets: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(sets.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_delete_hash_set() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create
    let res = client
        .post(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .json(&serde_json::json!({"name": "To Delete"}))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let hash_set_id = body["id"].as_str().unwrap();

    // Delete
    let res = client
        .delete(format!(
            "{}/api/v1/cases/{}/hash_sets/{}",
            api_base, case.id, hash_set_id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let del: serde_json::Value = res.json().await?;
    assert_eq!(del["status"].as_str(), Some("deleted"));

    // Verify gone
    let res = client
        .get(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .send()
        .await?;
    let sets: Vec<serde_json::Value> = res.json().await?;
    assert!(sets.is_empty());

    Ok(())
}

// ===========================================================================
// Audit Log (1 test)
// ===========================================================================

#[tokio::test]
async fn test_get_audit_log() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Creating a case should produce at least one audit event
    let res = client
        .get(format!("{}/api/v1/cases/{}/audit_log", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert!(body["events"].is_array());
    assert!(body["total"].is_number());
    // At least one event from case creation
    assert!(body["total"].as_i64().unwrap() >= 1);

    Ok(())
}

// ===========================================================================
// Filters (4 tests)
// ===========================================================================

#[tokio::test]
async fn test_create_filter() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "File Entries Only",
            "description": "Show only file entry artifacts",
            "filter": {"type": "simple", "field": "artifact_type", "operator": "eq", "value": "FileEntry"}
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert_eq!(body["name"].as_str(), Some("File Entries Only"));
    assert!(body["id"].as_str().is_some());

    Ok(())
}

#[tokio::test]
async fn test_list_filters() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create a filter
    client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Test Filter",
            "description": "",
            "filter": {"type": "simple", "field": "artifact_type", "operator": "eq", "value": "FileEntry"}
        }))
        .send()
        .await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let filters: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0]["name"].as_str(), Some("Test Filter"));

    Ok(())
}

#[tokio::test]
async fn test_get_filter() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "My Filter",
            "description": "Desc",
            "filter": {"type": "simple", "field": "artifact_type", "operator": "eq", "value": "FileEntry"}
        }))
        .send()
        .await?;
    let created: serde_json::Value = res.json().await?;
    let filter_id = created["id"].as_str().unwrap();

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/filters/{}",
            api_base, case.id, filter_id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert_eq!(body["name"].as_str(), Some("My Filter"));

    Ok(())
}

#[tokio::test]
async fn test_delete_filter() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Ephemeral Filter",
            "description": "",
            "filter": {"type": "simple", "field": "artifact_type", "operator": "eq", "value": "FileEntry"}
        }))
        .send()
        .await?;
    let created: serde_json::Value = res.json().await?;
    let filter_id = created["id"].as_str().unwrap();

    let res = client
        .delete(format!(
            "{}/api/v1/cases/{}/filters/{}",
            api_base, case.id, filter_id
        ))
        .send()
        .await?;
    assert!(res.status().is_success());

    // Verify gone
    let res = client
        .get(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .send()
        .await?;
    let filters: Vec<serde_json::Value> = res.json().await?;
    assert!(filters.is_empty());

    Ok(())
}

// ===========================================================================
// Status / Modules (2 tests)
// ===========================================================================

#[tokio::test]
async fn test_get_processing_status() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    let res = client
        .get(format!("{}/api/v1/status", api_base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert!(body["active_tasks"].is_number());
    assert_eq!(body["active_tasks"].as_i64().unwrap(), 0);
    // `active_tasks` counts every case this process serves, and the response
    // says so, so a client cannot present it as one case's progress.
    assert_eq!(body["scope"], serde_json::json!("process"));

    // The per-case census (B2-115): this harness layers it the way the server
    // binary does, so the route answers with a map — empty, because nothing
    // is queued — and not with the `cases_unavailable` reason an embedding
    // without the census gets. Idle work is `0`, never `null`.
    assert_eq!(
        body["cases"],
        serde_json::json!({}),
        "an idle server has no case with outstanding work: {body}"
    );
    assert_eq!(body["unattributed_tasks"], serde_json::json!(0));
    assert!(
        body.get("cases_unavailable").is_none(),
        "the census was supplied, so nothing may say it was not: {body}"
    );

    Ok(())
}

#[tokio::test]
async fn test_list_modules() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    let res = client
        .get(format!("{}/api/v1/modules", api_base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let modules: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(modules.len(), 2);
    let ids: Vec<&str> = modules.iter().filter_map(|m| m["id"].as_str()).collect();
    assert!(ids.contains(&"plugin.ntfs.mft"));
    assert!(ids.contains(&"plugin.ntfs.usnjrnl"));

    Ok(())
}

#[tokio::test]
async fn test_list_modules_filter_by_artifact_type() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // Filter for FileSystem subscribers only
    let res = client
        .get(format!(
            "{}/api/v1/modules?artifact_type=FileSystem",
            api_base
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let modules: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0]["id"].as_str(), Some("plugin.ntfs.mft"));

    // Filter for FileEntry subscribers
    let res = client
        .get(format!(
            "{}/api/v1/modules?artifact_type=FileEntry",
            api_base
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let modules: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0]["id"].as_str(), Some("plugin.ntfs.usnjrnl"));

    // Filter for non-existent type returns empty
    let res = client
        .get(format!(
            "{}/api/v1/modules?artifact_type=NonExistent",
            api_base
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let modules: Vec<serde_json::Value> = res.json().await?;
    assert!(modules.is_empty());

    Ok(())
}

// ===========================================================================
// Error Cases (4 tests)
// ===========================================================================

#[tokio::test]
async fn test_get_nonexistent_case_404() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let random_id = Uuid::new_v4();

    let res = client
        .get(format!("{}/api/v1/cases/{}", api_base, random_id))
        .send()
        .await?;
    assert_eq!(res.status(), 404);
    let body: ErrorResponse = res.json().await?;
    assert_eq!(body.error.code, "RESOURCE_NOT_FOUND");

    Ok(())
}

#[tokio::test]
async fn test_update_case_invalid_body() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Send a request with a body that is not valid JSON for UpdateCaseRequest
    let res = client
        .put(format!("{}/api/v1/cases/{}", api_base, case.id))
        .header("Content-Type", "application/json")
        .body("{invalid json}")
        .send()
        .await?;
    // Axum will reject malformed JSON with 400 or 422
    assert!(
        res.status() == 400 || res.status() == 422,
        "Expected 400 or 422, got {}",
        res.status()
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_nonexistent_hash_set_404() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;
    let random_id = Uuid::new_v4();

    let res = client
        .delete(format!(
            "{}/api/v1/cases/{}/hash_sets/{}",
            api_base, case.id, random_id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 404);

    Ok(())
}

#[tokio::test]
async fn test_get_nonexistent_filter_404() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;
    let random_id = Uuid::new_v4();

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/filters/{}",
            api_base, case.id, random_id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 404);

    Ok(())
}

// ===========================================================================
// Artifacts / Analysis (empty-state tests, 4 tests)
// ===========================================================================

#[tokio::test]
async fn test_get_analysis_tree_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/analysis/tree",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let tree: serde_json::Value = res.json().await?;
    assert!(tree.is_object());
    assert!(tree["children"].is_array());

    Ok(())
}

#[tokio::test]
async fn test_list_child_artifacts_root() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/artifacts/root/children",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    // FileEntries are stored flat under their FileSystem, so this listing pages
    // rather than loading a whole volume; the envelope is how a capped page says
    // the rest of the tree still exists (B8-027).
    let body: serde_json::Value = res.json().await?;
    let children = complete_listing_items(&body, "child artifacts");
    assert!(children.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_get_case_stats_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/stats", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let stats: CaseStats = res.json().await?;
    assert_eq!(stats.total_artifacts, 0);

    Ok(())
}

#[tokio::test]
async fn test_get_recent_artifacts_empty() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!("{}/api/v1/cases/{}/recent", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let recent: Vec<serde_json::Value> = res.json().await?;
    assert!(recent.is_empty());

    Ok(())
}

// ===========================================================================
// Ingestion (2 tests -- original tests preserved)
// ===========================================================================

#[tokio::test]
async fn test_ingest_source_bad_path() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // Create case
    let create_res: CaseResponse = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({"name": "Ingest Test", "examiner_name": "Jane"}))
        .send()
        .await?
        .json()
        .await?;

    // Ingest bad path
    let ingest_url = format!("{}/api/v1/cases/{}/ingest", api_base, create_res.id);
    let response = client
        .post(&ingest_url)
        .json(&serde_json::json!({"path": "/non/existent/path"}))
        .send()
        .await?;

    assert_eq!(response.status(), 400);

    let error_body: ErrorResponse = response.json().await?;
    assert_eq!(error_body.error.code, "INVALID_REQUEST");

    Ok(())
}

#[tokio::test]
async fn test_ingest_source_success() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // Create dummy file
    let file_path = PathBuf::from(format!("test_artifact_{}.dat", Uuid::new_v4()));
    std::fs::write(&file_path, b"test data").unwrap();
    let abs_path = std::fs::canonicalize(&file_path).unwrap();

    // Create case
    let create_res: CaseResponse = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({"name": "Ingest Success", "examiner_name": "Jane"}))
        .send()
        .await?
        .json()
        .await?;

    // Ingest
    let ingest_url = format!("{}/api/v1/cases/{}/ingest", api_base, create_res.id);
    let response = client
        .post(&ingest_url)
        .json(&serde_json::json!({"path": abs_path.to_str().unwrap()}))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    let ingest_res: IngestResponse = response.json().await?;
    // Ingest is now asynchronous: the response returns while acquisition
    // hashing runs in the background.
    assert_eq!(ingest_res.status, "hashing");

    // Give the background hash/persist task time to finish before removing
    // the source file.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Cleanup
    std::fs::remove_file(file_path).unwrap();

    Ok(())
}

// ===========================================================================
// Bookmark with category (1 test)
// ===========================================================================

#[tokio::test]
async fn test_create_bookmark_with_category() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create a category first
    let cat_res = client
        .post(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .json(&serde_json::json!({"name": "High Priority", "color": "#ff6600"}))
        .send()
        .await?;
    assert_eq!(cat_res.status(), 200);
    let cat: serde_json::Value = cat_res.json().await?;
    let category_id = cat["id"].as_str().unwrap();

    // Create bookmark with category (requires a real artifact due to FK constraints)
    let artifact_id = create_test_artifact(&db, case.id).await?;
    let res = client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({
            "artifact_id": artifact_id,
            "category_id": category_id,
            "note": "Critical evidence"
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    // Verify the bookmark count on the category
    let cats_res = client
        .get(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .send()
        .await?;
    let cats: Vec<BookmarkCategoryResponse> = cats_res.json().await?;
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].bookmark_count, 1);

    Ok(())
}

// ===========================================================================
// Case CRUD edge cases (2 more tests)
// ===========================================================================

#[tokio::test]
async fn test_create_case_minimal_fields() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;

    // All fields optional in CreateCaseRequest
    let res = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let case: CaseResponse = res.json().await?;
    assert!(!case.id.is_nil());

    Ok(())
}

#[tokio::test]
async fn test_update_case_partial_fields() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Update only the name
    let res = client
        .put(format!("{}/api/v1/cases/{}", api_base, case.id))
        .json(&serde_json::json!({"name": "Only Name Changed"}))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let updated: CaseResponse = res.json().await?;
    assert_eq!(updated.name, "Only Name Changed");

    Ok(())
}

// ===========================================================================
// Filter edge case (1 test)
// ===========================================================================

#[tokio::test]
async fn test_create_filter_invalid_condition() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "Bad Filter",
            "description": "",
            "filter": {"type": "NonExistentCondition"}
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 400);
    let body: ErrorResponse = res.json().await?;
    assert_eq!(body.error.code, "INVALID_REQUEST");

    Ok(())
}

// ===========================================================================
// Search without q parameter (1 test)
// ===========================================================================

#[tokio::test]
async fn test_search_missing_query_param() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // No q= parameter
    let res = client
        .get(format!("{}/api/v1/cases/{}/search", api_base, case.id))
        .send()
        .await?;
    // Should fail with 400 because "q" is required
    assert_eq!(res.status(), 400);

    Ok(())
}

// ===========================================================================
// Delete cascade verification (1 test)
// ===========================================================================

#[tokio::test]
async fn test_delete_case_cleans_up_related_data() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    // Create some related data
    client
        .post(format!(
            "{}/api/v1/cases/{}/bookmarks/categories",
            api_base, case.id
        ))
        .json(&serde_json::json!({"name": "Cat1"}))
        .send()
        .await?;
    // Bookmarks require a real artifact due to FK constraints
    let artifact_id = create_test_artifact(&db, case.id).await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case.id))
        .json(&serde_json::json!({"artifact_id": artifact_id}))
        .send()
        .await?;
    client
        .post(format!("{}/api/v1/cases/{}/hash_sets", api_base, case.id))
        .json(&serde_json::json!({"name": "HS1"}))
        .send()
        .await?;
    client
        .post(format!("{}/api/v1/cases/{}/filters", api_base, case.id))
        .json(&serde_json::json!({
            "name": "F1",
            "description": "",
            "filter": {"type": "simple", "field": "artifact_type", "operator": "eq", "value": "FileEntry"}
        }))
        .send()
        .await?;

    // Delete the case: accepted and marked, rows removed in the background
    // (HUNT-072).
    let res = client
        .delete(format!("{}/api/v1/cases/{}", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 202);

    // Case should be gone from the API at once
    let res = client
        .get(format!("{}/api/v1/cases/{}", api_base, case.id))
        .send()
        .await?;
    assert_eq!(res.status(), 404);

    // And the related rows do go once the background purge has run.
    let mut remaining = None;
    for _ in 0..200 {
        remaining = Some(db.case_status(case.id).await?);
        if remaining == Some(None) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(
        remaining,
        Some(None),
        "the case row must be removed by the purge"
    );
    assert_eq!(db.count_total_artifacts(case.id).await?, 0);

    Ok(())
}

// ===========================================================================
// Timeline pagination parameters (1 test)
// ===========================================================================

#[tokio::test]
async fn test_get_timeline_with_pagination_params() -> Result<()> {
    let (client, api_base, _db) = spawn_test_api().await?;
    let case = create_test_case(&client, &api_base).await?;

    let res = client
        .get(format!(
            "{}/api/v1/cases/{}/timeline?page=1&page_size=10",
            api_base, case.id
        ))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: PaginatedTimelineResponse = res.json().await?;
    assert!(body.events.is_empty());
    assert_eq!(body.pagination.page, 1);
    assert_eq!(body.pagination.page_size, 10);

    Ok(())
}

// ===========================================================================
// Multiple cases isolation (1 test)
// ===========================================================================

#[tokio::test]
async fn test_bookmarks_isolated_between_cases() -> Result<()> {
    let (client, api_base, db) = spawn_test_api().await?;

    let case1 = create_test_case(&client, &api_base).await?;
    let case2: CaseResponse = client
        .post(format!("{}/api/v1/cases", api_base))
        .json(&serde_json::json!({"name": "Case 2"}))
        .send()
        .await?
        .json()
        .await?;

    // Bookmark in case1 (requires a real artifact due to FK constraints)
    let artifact_id = create_test_artifact(&db, case1.id).await?;
    client
        .post(format!("{}/api/v1/cases/{}/bookmarks", api_base, case1.id))
        .json(&serde_json::json!({"artifact_id": artifact_id, "note": "case1 only"}))
        .send()
        .await?;

    // Case2 should have no bookmarks. Isolation is only proven when the empty
    // listing also declares itself whole: a capped or damaged listing would be
    // empty for reasons that have nothing to do with case scoping.
    let res = client
        .get(format!("{}/api/v1/cases/{}/bookmarks", api_base, case2.id))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let bookmarks = complete_listing_items(&body, "case 2 bookmarks");
    assert!(bookmarks.is_empty(), "Case 2 should have no bookmarks");

    // Case1 should have one
    let res = client
        .get(format!("{}/api/v1/cases/{}/bookmarks", api_base, case1.id))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let bookmarks = complete_listing_items(&body, "case 1 bookmarks");
    assert_eq!(bookmarks.len(), 1);

    Ok(())
}
