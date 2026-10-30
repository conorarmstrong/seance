use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// Reusable test harness: spins up an in-memory SQLite database, creates a
/// single case, and returns (Router, case_id, db).  The Router has auth
/// disabled so every request is accepted without a JWT.
async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("Integration Test Case", "Test Examiner")
        .await
        .unwrap();

    // Minimal orchestrator channels -- we never consume from the receivers.
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let app_state = AppState {
        db: db.clone(),
        // A counted submitter over the test channel; the counter is the test's own
        // because nothing here submits through it.
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ),
        ad_hoc_sender: ad_hoc_tx,
        event_sender: event_tx.clone(),
        status_sender: status_tx,
        active_tasks: active_tasks.clone(),
        search_service: None,
        ingestion_service: seance_core::ingestion::IngestionService::new(
            Some(db.clone()),
            task_tx,
            event_tx,
            active_tasks,
        ),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: seance_api::EvidenceRootPolicy::from_env(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };

    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db)
}

/// Helper: read the full response body as `serde_json::Value`.
async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: read a capped listing envelope and return its rows.
///
/// Every paged endpoint answers with an object, never a bare array, because a
/// listing that stopped at its ceiling and a listing that is genuinely complete
/// must not look the same on the wire (B8-006/007, B8-019, B8-027, B8-030,
/// B8-031). The two shortfalls are distinct and both are checked here:
///
/// * `truncated`/`has_more` -- the query stopped early; further rows exist.
/// * `undecodable` -- rows inside the window would not decode and are gone from
///   every page. `null` means the query has no channel for the fact, which a
///   reader must treat as "not determined", never as zero.
///
/// Asserting their presence is the point: a future change that drops the flags
/// has to fail here rather than pass by looking like a complete answer.
fn listing_items(body: &Value, what: &str) -> Vec<Value> {
    let items = body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{what} listing must carry its rows under `items`"))
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
fn complete_listing_items(body: &Value, what: &str) -> Vec<Value> {
    let items = listing_items(body, what);
    assert_eq!(
        body["truncated"],
        json!(false),
        "{what} listing was not expected to be capped"
    );
    assert_eq!(
        body["has_more"],
        json!(false),
        "{what} listing was not expected to be capped"
    );
    assert_eq!(
        body["count_is_lower_bound"],
        json!(false),
        "{what} row count was not expected to be a floor"
    );
    assert_eq!(
        body["undecodable"],
        json!(0),
        "{what} listing was not expected to drop rows"
    );
    assert_eq!(body["inventory_incomplete"], json!(false));
    assert_eq!(
        body["inventory_incomplete_reason"],
        Value::Null,
        "{what} listing is whole, so it must name no shortfall"
    );
    items
}

/// The rows of a listing that stopped at its ceiling, with the disclosure the
/// examiner acts on checked rather than assumed.
///
/// This is the other half of the contract from [`complete_listing_items`] and
/// the half that actually matters: a `has_more` that is computed and then never
/// set true is indistinguishable, to every caller, from an endpoint that always
/// returns everything. The capping fact must reach the wire under all three
/// names the clients read, and it must NOT be confused with damage --
/// `undecodable` stays 0 here because every row inside the window decoded, so
/// the shortfall is repairable by paging and the reason says exactly that.
fn truncated_listing_items(body: &Value, what: &str) -> Vec<Value> {
    let items = listing_items(body, what);
    assert_eq!(
        body["has_more"],
        json!(true),
        "{what} listing stopped short of the matching rows and must say so"
    );
    assert_eq!(
        body["truncated"],
        json!(true),
        "{what} listing must carry the capping fact under `truncated` too"
    );
    assert_eq!(
        body["count_is_lower_bound"],
        json!(true),
        "{what} row count is a floor, not a total"
    );
    assert_eq!(
        body["undecodable"],
        json!(0),
        "{what} rows all decoded: capped is not damaged"
    );
    assert_eq!(body["inventory_incomplete"], json!(true));
    assert_eq!(
        body["inventory_incomplete_reason"],
        json!("capped"),
        "{what} shortfall is a ceiling, reachable by paging"
    );
    items
}

/// Helper: insert a dummy artifact directly into the database so we can test
/// bookmark and artifact endpoints that require an existing artifact row.
async fn insert_test_artifact(db: &SqliteConnection, case_id: Uuid) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        data: None,
        metadata: serde_json::json!({
            "name": "test_evidence.dd",
            "size": 1024,
        }),
    };
    db.record_artifact(&artifact).await.unwrap();
    artifact.id
}

// ============================================================
//  1. Case CRUD
// ============================================================

#[tokio::test]
async fn test_create_case() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cases")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "New Case",
                        "reference_number": "REF-001",
                        "examiner_name": "Examiner A"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["name"].as_str().unwrap(), "New Case");
    assert_eq!(body["reference_number"].as_str().unwrap(), "REF-001");
    assert_eq!(body["examiner_name"].as_str().unwrap(), "Examiner A");
    assert!(body["id"].as_str().is_some(), "response must contain an id");
}

#[tokio::test]
async fn test_create_case_defaults() {
    let (app, _case_id, _db) = setup_test_app().await;

    // All fields are Optional -- the API should still accept an empty object.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cases")
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["id"].as_str().is_some());
    // name is auto-generated when not provided
    assert!(body["name"].as_str().is_some());
}

#[tokio::test]
async fn test_list_cases() {
    let (app, _case_id, _db) = setup_test_app().await;

    // The setup already created one case.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/cases")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    let cases = body.as_array().expect("response should be an array");
    assert!(
        !cases.is_empty(),
        "should have at least the case created in setup"
    );
    // Verify structure of the first case
    let first = &cases[0];
    assert!(first["id"].as_str().is_some());
    assert!(first["name"].as_str().is_some());
    assert!(first["status"].as_str().is_some());
}

#[tokio::test]
async fn test_get_case_detail() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["id"].as_str().unwrap(), case_id.to_string());
    assert_eq!(body["name"].as_str().unwrap(), "Integration Test Case");
}

#[tokio::test]
async fn test_get_case_nonexistent_returns_404() {
    let (app, _case_id, _db) = setup_test_app().await;

    let fake_id = Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_case() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/cases/{}", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Updated Case Name",
                        "reference_number": "REF-UPD"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["name"].as_str().unwrap(), "Updated Case Name");
    assert_eq!(body["reference_number"].as_str().unwrap(), "REF-UPD");
}

#[tokio::test]
async fn test_delete_case() {
    let (app, case_id, db) = setup_test_app().await;

    // Delete it. The rows go in the background (HUNT-072): the request is
    // accepted, the case is marked, and from that moment it is gone from the
    // API whatever the background task has reached.
    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/cases/{}", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_resp.status(), StatusCode::ACCEPTED);
    let body = body_json(delete_resp).await;
    assert_eq!(body["status"], "deleting");

    // A subsequent GET should 404 at once, not after the rows are gone.
    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

    // And the rows do go: the background purge finishes and the case row is
    // gone, with the completion audit row written.
    let mut audited = 0;
    for _ in 0..200 {
        audited = db
            .count_audit_actions_for_resource("case_deleted", case_id)
            .await
            .unwrap();
        if audited > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(
        audited, 1,
        "case_deleted must be audited once the rows are gone"
    );
    assert_eq!(
        db.case_status(case_id).await.unwrap(),
        None,
        "the background purge must remove the case row"
    );
}

/// HUNT-072: while a case is marked `deleting` — the rows not yet reached,
/// or a restart having interrupted the purge — it is absent from the case
/// list and every case-scoped route answers 404. Before this, a delete that
/// outran the request timeout was rolled back after the search index had
/// been purged, and the case stayed live answering "no results" for
/// evidence it still held.
#[tokio::test]
async fn a_case_being_deleted_is_absent_from_the_list_and_refuses_its_routes() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "still-here.txt"}),
    );
    db.record_artifact(&artifact).await.unwrap();

    db.mark_case_deleting(case_id).await.unwrap();

    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/cases")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list = body_json(list_resp).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(
        !ids.contains(&case_id.to_string().as_str()),
        "a case being deleted must not be listed: {ids:?}"
    );

    for path in [
        format!("/api/v1/cases/{}", case_id),
        format!("/api/v1/cases/{}/stats", case_id),
        format!("/api/v1/cases/{}/search?q=still", case_id),
        format!("/api/v1/cases/{}/artifacts/{}", case_id, artifact.id),
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // The rows are still there — the mark, not the purge, is what hid them.
    assert_eq!(db.count_total_artifacts(case_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_get_case_stats() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/stats", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    // CaseStats has total_artifacts and artifact_counts_by_type
    assert!(body["total_artifacts"].is_number());
    assert!(body["artifact_counts_by_type"].is_object());
}

// ============================================================
//  2. Bookmarks
// ============================================================

#[tokio::test]
async fn test_list_bookmarks_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    // The listing is an object, not a bare array: the rows travel with the
    // flags that say whether they are all of them (B8-031). "No bookmarks" and
    // "we could not tell you how many bookmarks" must not render alike.
    let bookmarks = complete_listing_items(&body, "bookmarks");
    assert!(bookmarks.is_empty());
}

#[tokio::test]
async fn test_list_bookmarks_capped_page_reports_has_more() {
    // The claim an examiner relies on. Two bookmarks exist; the page holds one.
    // Without `has_more` the response is byte-for-byte what a case with exactly
    // one bookmark returns, and "these are the findings someone marked" would
    // be read off a list that silently omits half of them.
    let (app, case_id, db) = setup_test_app().await;

    let first = insert_test_artifact(&db, case_id).await;
    let second = insert_test_artifact(&db, case_id).await;
    for artifact_id in [first, second] {
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "artifact_id": artifact_id.to_string() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
    }

    let capped = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks?limit=1", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capped.status(), StatusCode::OK);
    let capped_body = body_json(capped).await;
    let page_one = truncated_listing_items(&capped_body, "bookmarks");
    assert_eq!(page_one.len(), 1);
    // The ceiling actually applied, which is what a client must compare its
    // page length against -- not the value it asked for.
    assert_eq!(capped_body["limit"], json!(1));
    assert_eq!(capped_body["offset"], json!(0));

    // `has_more` has to mean a row is really there: page on and it appears, and
    // it is a different bookmark, not the same one served twice.
    let rest = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks?limit=1&offset=1",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rest_body = body_json(rest).await;
    let page_two = complete_listing_items(&rest_body, "bookmarks");
    assert_eq!(page_two.len(), 1);
    assert_eq!(rest_body["offset"], json!(1));
    let first_id = page_one[0]["bookmark"]["artifact_id"].as_str().unwrap();
    let second_id = page_two[0]["bookmark"]["artifact_id"].as_str().unwrap();
    assert_ne!(
        first_id, second_id,
        "the second page must hold the bookmark the first one withheld"
    );
}

#[tokio::test]
async fn test_bookmark_rejects_another_cases_category() {
    // The schema's foreign key only requires the category UUID to exist, so a
    // category belonging to case B was accepted on a case A bookmark: the wrong
    // taxonomy on exports, and deleting it in B cleared it in A (BUG-279).
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    let other_case = db.create_case("Other Case", "Test Examiner").await.unwrap();
    let foreign_category = db
        .create_bookmark_category(other_case, "Other case label", None)
        .await
        .unwrap();

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "artifact_id": artifact_id.to_string(),
                        "category_id": foreign_category.to_string(),
                        "note": "cross-case label"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        create_resp.status(),
        StatusCode::NOT_FOUND,
        "a category from another case must not be accepted"
    );

    // The same category created in THIS case is accepted.
    let own_category = db
        .create_bookmark_category(case_id, "Suspicious", None)
        .await
        .unwrap();
    let ok_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "artifact_id": artifact_id.to_string(),
                        "category_id": own_category.to_string(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);

    // Update is gated the same way.
    let update_resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/{}",
                    case_id, artifact_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "category_id": foreign_category.to_string() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_bookmark_create_list_delete_lifecycle() {
    let (app, case_id, db) = setup_test_app().await;

    // Insert a real artifact so foreign keys are satisfied.
    let artifact_id = insert_test_artifact(&db, case_id).await;

    // 1. Create bookmark
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "artifact_id": artifact_id.to_string(),
                        "note": "Important evidence"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_resp.status(), StatusCode::OK);
    let created = body_json(create_resp).await;
    assert_eq!(
        created["artifact_id"].as_str().unwrap(),
        artifact_id.to_string()
    );
    assert_eq!(created["note"].as_str().unwrap(), "Important evidence");

    // 2. List bookmarks -- should contain the one we just created.
    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = body_json(list_resp).await;
    let bookmarks = complete_listing_items(&list_body, "bookmarks");
    assert_eq!(bookmarks.len(), 1);

    // 3. Get individual bookmark
    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/{}",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(get_resp.status(), StatusCode::OK);
    let fetched = body_json(get_resp).await;
    assert_eq!(fetched["note"].as_str().unwrap(), "Important evidence");

    // 4. Update bookmark
    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/{}",
                    case_id, artifact_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "note": "Updated note" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(update_resp.status(), StatusCode::OK);
    let updated = body_json(update_resp).await;
    assert_eq!(updated["note"].as_str().unwrap(), "Updated note");

    // 5. Delete bookmark
    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/{}",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_resp.status(), StatusCode::OK);

    // 6. List again -- should be empty.
    let list_resp2 = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_resp2.status(), StatusCode::OK);
    let list2 = body_json(list_resp2).await;
    // Empty because the bookmark was deleted -- and the envelope has to say so
    // rather than leave "none left" indistinguishable from "capped at zero".
    assert!(complete_listing_items(&list2, "bookmarks").is_empty());
}

#[tokio::test]
async fn test_bookmark_category_lifecycle() {
    let (app, case_id, _db) = setup_test_app().await;

    // 1. List categories -- starts empty.
    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/categories", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let categories = body_json(list_resp).await;
    assert!(categories.as_array().unwrap().is_empty());

    // 2. Create a category.
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks/categories", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "Suspicious", "color": "#ff0000" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let cat = body_json(create_resp).await;
    assert_eq!(cat["name"].as_str().unwrap(), "Suspicious");
    let category_id = cat["id"].as_str().unwrap().to_string();

    // 3. Update the category.
    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/categories/{}",
                    case_id, category_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "Very Suspicious", "color": "#ff5500" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);

    // 4. Delete the category.
    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/bookmarks/categories/{}",
                    case_id, category_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::OK);

    // 5. List again -- empty.
    let list2 = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/categories", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list2.status(), StatusCode::OK);
    let cats = body_json(list2).await;
    assert!(cats.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_bookmarked_artifact_ids() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    // Initially no bookmarks.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/ids", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let ids = body_json(resp1).await;
    assert!(ids.as_array().unwrap().is_empty());

    // Create a bookmark, then the IDs list should contain our artifact.
    let _create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "artifact_id": artifact_id.to_string() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp2 = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/ids", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let ids2 = body_json(resp2).await;
    let id_array = ids2.as_array().unwrap();
    assert_eq!(id_array.len(), 1);
    assert_eq!(id_array[0].as_str().unwrap(), artifact_id.to_string());
}

// ============================================================
//  3. Hash Sets
// ============================================================

#[tokio::test]
async fn test_hash_set_create_and_list() {
    let (app, case_id, _db) = setup_test_app().await;

    // 1. List -- empty initially.
    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let sets = body_json(list_resp).await;
    assert!(sets.as_array().unwrap().is_empty());

    // 2. Create a hash set.
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Known Good",
                        "description": "NSRL whitelist",
                        "set_type": "known",
                        "hash_algorithm": "md5"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let created = body_json(create_resp).await;
    assert!(created["id"].as_str().is_some());

    // 3. List again -- should have one.
    let list2 = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list2.status(), StatusCode::OK);
    let sets2 = body_json(list2).await;
    assert_eq!(sets2.as_array().unwrap().len(), 1);
    assert_eq!(sets2[0]["name"].as_str().unwrap(), "Known Good");
    assert_eq!(sets2[0]["set_type"].as_str().unwrap(), "known");
}

#[tokio::test]
async fn test_hash_set_delete() {
    let (app, case_id, _db) = setup_test_app().await;

    // Create a hash set.
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": "Temp Set" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let created = body_json(create_resp).await;
    let hash_set_id = created["id"].as_str().unwrap();

    // Delete it.
    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/hash_sets/{}",
                    case_id, hash_set_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::OK);

    // List should now be empty.
    let list = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let sets = body_json(list).await;
    assert!(sets.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_vics_import_and_export_round_trip() {
    let (app, case_id, _db) = setup_test_app().await;

    // A small VICS document with one pertinent (category 1) media item.
    let vics = json!({
        "odata.metadata": "http://projectvic.org/$metadata#Media",
        "value": [
            {
                "MediaID": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                "Category": 1,
                "MD5": "D41D8CD98F00B204E9800998ECF8427E",
                "SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "VictimIdentified": false,
                "Series": "Operation Example",
                "Tags": ["reviewed"]
            },
            { "Category": 0, "MD5": "5d41402abc4b2a76b9719d911017c592" }
        ]
    });

    // Import.
    let import = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets/vics_import", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "VIC set", "vics_json": vics.to_string() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(import.status(), StatusCode::OK);
    let imported = body_json(import).await;
    // A pertinent category makes the whole set notable.
    assert_eq!(imported["set_type"].as_str().unwrap(), "notable");
    // Media 1 carries BOTH an MD5 and a SHA-1 (2 matchable entries); media 2 has
    // only an MD5 (1). Both digests must be stored so a file hashed with either
    // is findable — hence 3 entries, not 2.
    assert_eq!(imported["entries_imported"].as_i64().unwrap(), 3);
    let hash_set_id = imported["id"].as_str().unwrap().to_string();

    // The set is now listed.
    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sets = body_json(list).await;
    assert_eq!(sets.as_array().unwrap().len(), 1);
    assert_eq!(sets[0]["entry_count"].as_i64().unwrap(), 3);

    // Export and confirm the category and attributes survived the round trip.
    let export = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/hash_sets/{}/vics_export",
                    case_id, hash_set_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    let exported = body_json(export).await;
    let media = exported["value"].as_array().unwrap();
    // Two source media: the both-digest one is stored as two matchable entries
    // but must export ONCE (deduped), so the round trip does not double it.
    assert_eq!(
        media.len(),
        2,
        "both-digest media must not be duplicated on export"
    );
    let cat1 = media
        .iter()
        .find(|m| m["MD5"].as_str() == Some("d41d8cd98f00b204e9800998ecf8427e"))
        .expect("category-1 media present after round trip");
    assert_eq!(cat1["Category"].as_i64().unwrap(), 1);
    // The same media still carries its SHA-1 (both digests preserved on one record).
    assert_eq!(
        cat1["SHA1"].as_str(),
        Some("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        "the SHA-1 digest must survive on the same media record"
    );
    assert_eq!(cat1["Series"].as_str().unwrap(), "Operation Example");
    assert_eq!(cat1["VictimIdentified"].as_bool(), Some(false));
}

#[tokio::test]
async fn test_vics_import_rejects_non_vics_json() {
    let (app, case_id, _db) = setup_test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets/vics_import", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "bad", "vics_json": "{\"not\":\"vics\"}" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // A valid-JSON-but-not-VICS document is a client error, not a 500.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_vics_export_labels_sha1_digests_as_sha1_not_md5() {
    let (app, case_id, _db) = setup_test_app().await;

    // A plain SHA-1 hash set imported the ordinary way (no VICS attributes).
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "SHA1 set", "hash_algorithm": "sha1" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let hash_set_id = body_json(create).await["id"].as_str().unwrap().to_string();

    let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 hex chars
    let boundary = "----VicsExportBoundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"h.csv\"\r\nContent-Type: text/csv\r\n\r\n{sha1},known\r\n--{boundary}--\r\n"
    );
    let imp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/hash_sets/{}/import",
                    case_id, hash_set_id
                ))
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(imp.status(), StatusCode::OK);

    // Export to VICS: the 40-hex value must land in the SHA1 field, never MD5.
    let export = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/hash_sets/{}/vics_export",
                    case_id, hash_set_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    let doc = body_json(export).await;
    let m = &doc["value"].as_array().unwrap()[0];
    assert_eq!(
        m["SHA1"].as_str(),
        Some(sha1),
        "SHA-1 must export in the SHA1 field"
    );
    assert!(
        m.get("MD5").is_none(),
        "a SHA-1 must not be mislabelled as MD5"
    );
}

#[tokio::test]
async fn test_hash_set_import_csv() {
    let (app, case_id, _db) = setup_test_app().await;

    // Create a hash set first.
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "Import Test", "hash_algorithm": "md5" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let hash_set_id = body_json(create_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Import via multipart -- the endpoint expects a multipart form with a
    // field named "file" containing CSV data.
    let boundary = "----TestBoundary123";
    let csv_data =
        "d41d8cd98f00b204e9800998ecf8427e,empty_file\nab56b4d92b40713acc5af89985d4b786,test_file";
    let multipart_body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hashes.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv_data}\r\n--{boundary}--\r\n",
        boundary = boundary,
        csv_data = csv_data,
    );

    let import_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/hash_sets/{}/import",
                    case_id, hash_set_id
                ))
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(multipart_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(import_resp.status(), StatusCode::OK);
    let import_body = body_json(import_resp).await;
    assert_eq!(import_body["imported"].as_i64().unwrap(), 2);
    assert_eq!(import_body["total_parsed"].as_i64().unwrap(), 2);
}

// ============================================================
//  4. Search
// ============================================================

#[tokio::test]
async fn test_search_requires_query_param() {
    let (app, case_id, _db) = setup_test_app().await;

    // Missing `q` parameter should return 400 (INVALID_REQUEST).
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/search", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_search_with_no_search_service() {
    let (app, case_id, _db) = setup_test_app().await;

    // search_service is None in our test setup, so this should return a
    // graceful error or an empty result set rather than panic.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/search?q=test", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // search_service is None in test setup, so the handler returns 500
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "search without service should return 500, got {}",
        response.status()
    );
}

// ============================================================
//  5. Artifacts
// ============================================================

#[tokio::test]
async fn test_list_child_artifacts_root() {
    let (app, case_id, _db) = setup_test_app().await;

    // List root-level artifacts (using "root" as parent_id).
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/artifacts/root/children", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    // An object carrying `items` plus the completeness flags, not a bare
    // array: a child listing that stopped at its ceiling has to say so
    // (B8-027), because FileEntries are stored flat under their FileSystem and
    // this listing pages rather than loading a whole volume.
    let children = complete_listing_items(&body, "child artifacts");
    assert!(
        children.is_empty(),
        "nothing has been ingested into this case"
    );
}

#[tokio::test]
async fn test_list_child_artifacts_with_test_artifact() {
    let (app, case_id, db) = setup_test_app().await;

    let _artifact_id = insert_test_artifact(&db, case_id).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/artifacts/root/children", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let artifacts = complete_listing_items(&body, "child artifacts");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        artifacts[0]["artifact_type"].as_str().unwrap(),
        "RawEvidence"
    );
}

#[tokio::test]
async fn test_list_child_artifacts_capped_page_reports_has_more() {
    // FileEntries are stored flat under their FileSystem, so a child listing is
    // a page of a volume rather than a directory (B8-027). A capped page that
    // did not say so would put the rest of the tree out of reach with nothing
    // on the wire to show anything was left out.
    let (app, case_id, db) = setup_test_app().await;

    let first = insert_test_artifact(&db, case_id).await;
    let second = insert_test_artifact(&db, case_id).await;
    assert_ne!(first, second);

    let capped = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/root/children?limit=1",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capped.status(), StatusCode::OK);
    let capped_body = body_json(capped).await;
    let page_one = truncated_listing_items(&capped_body, "child artifacts");
    assert_eq!(page_one.len(), 1);
    assert_eq!(capped_body["limit"], json!(1));

    // The withheld child is reachable, and it is the other one.
    let rest = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/root/children?limit=1&offset=1",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rest_body = body_json(rest).await;
    let page_two = complete_listing_items(&rest_body, "child artifacts");
    assert_eq!(page_two.len(), 1);
    assert_eq!(rest_body["offset"], json!(1));
    assert_ne!(
        page_one[0]["id"].as_str().unwrap(),
        page_two[0]["id"].as_str().unwrap(),
        "the second page must hold the child the first one withheld"
    );
}

#[tokio::test]
async fn test_get_artifact_detail() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["id"].as_str().unwrap(), artifact_id.to_string());
    assert_eq!(body["case_id"].as_str().unwrap(), case_id.to_string());
    assert_eq!(body["artifact_type"].as_str().unwrap(), "RawEvidence");
}

#[tokio::test]
async fn test_get_artifact_nonexistent() {
    let (app, case_id, _db) = setup_test_app().await;
    let fake_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/artifacts/{}", case_id, fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // get_artifact_details uses fetch_one, which errors on no rows → mapped to 500
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "nonexistent artifact should return 500, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_delete_artifact() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Successful deletion returns 200 with deletion stats.
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["deleted_artifacts"].is_number());
}

// ============================================================
//  6. Audit Log
// ============================================================

#[tokio::test]
async fn test_audit_log() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/audit_log", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["events"].is_array());
    assert!(body["total"].is_number());
}

// ============================================================
//  7. Miscellaneous Endpoints
// ============================================================

#[tokio::test]
async fn test_version_endpoint() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_processing_status_endpoint() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_modules_endpoint() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/modules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    // module_registry is empty in our test setup
    assert!(body.as_array().is_some());
}

// ============================================================
//  8. Export Endpoints (Bookmarks)
// ============================================================

#[tokio::test]
async fn test_export_bookmarks_json_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/export/json", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // The export is drained page by page and becomes a court exhibit, so the
    // file itself has to record whether the walk reached the end. A short
    // exhibit that cannot say it is short outlives the request that made it.
    let body = body_json(response).await;
    assert_eq!(body["bookmarks"].as_array().map(|a| a.len()), Some(0));
    assert_eq!(body["truncated"], json!(false));
    assert_eq!(body["has_more"], json!(false));
    assert_eq!(body["count_is_lower_bound"], json!(false));
    assert_eq!(body["undecodable"], json!(0));
    // Presence FIRST, then the value. `body["missing"]` yields `Value::Null`
    // for a key that is not there, so asserting only `== Value::Null` is
    // satisfied by the export dropping the field entirely -- which is the exact
    // regression this assertion exists to catch. Indexing cannot tell the two
    // apart; `get` can.
    for field in [
        "limit",
        "offset",
        "has_more",
        "truncated",
        "count_is_lower_bound",
        "undecodable",
        "inventory_incomplete",
        "inventory_incomplete_reason",
        "export_incomplete_notice",
    ] {
        assert!(
            body.get(field).is_some(),
            "the bookmark export must carry `{field}`, not omit it"
        );
    }
    assert_eq!(body["inventory_incomplete"], json!(false));
    assert_eq!(
        body["export_incomplete_notice"],
        Value::Null,
        "a whole export must say so with a null notice, not by omitting the field"
    );
}

#[tokio::test]
async fn test_export_bookmarks_csv_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/bookmarks/export/csv", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // A CSV has no envelope to hang the flags on, so the same two facts travel
    // as response headers and, when either is true, as a notice row inside the
    // file. Asserting only the status is exactly how the JSON sibling's shape
    // changed unnoticed; the headers must be present and must read "whole"
    // rather than be absent, because an absent header is indistinguishable from
    // a header this build forgot to send.
    assert_eq!(
        response
            .headers()
            .get("X-Export-Incomplete")
            .and_then(|v| v.to_str().ok()),
        Some("false"),
        "a whole export must say so, not omit the header"
    );
    assert_eq!(
        response
            .headers()
            .get("X-Export-Undecodable")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "the dropped-row count must reach the caller of the export too"
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let csv = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !csv.contains("EXPORT INCOMPLETE"),
        "a complete export must not carry an incompleteness notice"
    );
}

// ============================================================
//  8b. Processing history (per-artifact provenance)
// ============================================================

/// The per-artifact processing log is what an examiner reads to answer "was
/// this artifact ever analysed, and by what". It is a capped listing, so it
/// answers with the same envelope as every other one: a log that stopped at its
/// ceiling and a module that never ran must not render alike (B8-019).
#[tokio::test]
async fn processing_history_is_an_envelope_that_discloses_its_completeness() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    db.record_processing_log(
        case_id,
        artifact_id,
        "plugin.filesystem.ntfs",
        "success",
        7,
        None,
        42,
    )
    .await
    .unwrap();
    db.record_processing_log(
        case_id,
        artifact_id,
        "plugin.recovery.file_carver",
        "failed",
        0,
        Some("signature table unavailable"),
        3,
    )
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}/processing-history",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let entries = complete_listing_items(&body, "processing history");
    assert_eq!(entries.len(), 2);
    let modules: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["module_id"].as_str())
        .collect();
    assert!(modules.contains(&"plugin.filesystem.ntfs"));
    assert!(
        modules.contains(&"plugin.recovery.file_carver"),
        "a failed run is provenance too and must not be dropped from the log"
    );
}

/// The log query is keyed by artifact id alone, so the handler's case scope is
/// the only thing standing between one case's exhibit list and another's.
#[tokio::test]
async fn processing_history_of_another_case_artifact_is_not_served() {
    let (app, case_id, db) = setup_test_app().await;
    let other_case = db
        .create_case("Other Case", "Other Examiner")
        .await
        .unwrap();
    let foreign = insert_test_artifact(&db, other_case).await;

    db.record_processing_log(
        other_case,
        foreign,
        "plugin.filesystem.ntfs",
        "success",
        1,
        None,
        1,
    )
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}/processing-history",
                    case_id, foreign
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a cross-case artifact id must 404 rather than serve another case's provenance"
    );
}

// ============================================================
//  9. Timeline Endpoints
// ============================================================

#[tokio::test]
async fn test_get_timeline_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/timeline", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// The related-events list for one artifact stops at `RELATED_TIMELINE_CAP`, so
/// it answers with an object carrying that ceiling and whether it was hit. A
/// bare array here would let a capped list read as the artifact's whole history
/// -- the reading an examiner draws when nothing says otherwise. Nothing pinned
/// this shape, which is how the bookmark and job listings changed underneath
/// their callers unnoticed.
#[tokio::test]
async fn related_timeline_events_carry_their_ceiling_and_whether_it_was_hit() {
    let (app, case_id, db) = setup_test_app().await;
    let artifact_id = insert_test_artifact(&db, case_id).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{}/timeline/related/{}",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(
        body["events"].as_array().is_some(),
        "related events travel under `events`, not as a bare array body"
    );
    assert_eq!(
        body["truncated"],
        json!(false),
        "this artifact has no events at all, so nothing was cut off"
    );
    assert_eq!(
        body["cap"],
        json!(seance_db::RELATED_TIMELINE_CAP),
        "the applied ceiling is named so a client can compare its page against it"
    );
}

#[tokio::test]
async fn test_get_timeline_source_modules() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/timeline/modules", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================
//  10. Profiles
// ============================================================

#[tokio::test]
async fn test_profiles_list_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_create_profile() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Triage Profile",
                        "description": "Quick scan",
                        "enabled_modules": [],
                        "disabled_modules": []
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["id"].as_str().is_some());
    assert_eq!(body["name"].as_str().unwrap(), "Triage Profile");
}

// ============================================================
//  11. Analysis Tree
// ============================================================

#[tokio::test]
async fn test_analysis_tree() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/analysis/tree", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    // AnalysisTreeNode has children array at top level
    assert!(body.as_array().is_some() || body.is_object());
}

// ============================================================
//  12. Filters
// ============================================================

#[tokio::test]
async fn test_filters_list_empty() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/filters", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body.as_array().is_some());
}

// ============================================================
//  13. Edge Cases / Error Handling
// ============================================================

#[tokio::test]
async fn test_invalid_uuid_in_path() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/cases/not-a-valid-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_case_malformed_json() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cases")
                .header("content-type", "application/json")
                .body(Body::from("{not valid json}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_bookmark_missing_artifact_id() {
    let (app, case_id, _db) = setup_test_app().await;

    // artifact_id is required in CreateBookmarkRequest
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/bookmarks", case_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "note": "no artifact" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Axum returns 422 Unprocessable Entity for deserialization failures.
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_create_hash_set_missing_name() {
    let (app, case_id, _db) = setup_test_app().await;

    // name is required in CreateHashSetRequest
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/hash_sets", case_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "description": "no name" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Axum returns 422 Unprocessable Entity for deserialization failures.
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_delete_nonexistent_hash_set() {
    let (app, case_id, _db) = setup_test_app().await;

    let fake_id = Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/cases/{}/hash_sets/{}", case_id, fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The handler checks if deleted == false and returns NOT_FOUND.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Examiner detail set through the API survives the round trip.
///
/// These five columns exist for exactly one consumer -- the declaration block of
/// a court-standard report -- so a silent failure to persist them would surface
/// as a report that omits the examiner's qualifications and looks, to a reader,
/// exactly like a report for a case where nobody recorded them.
#[tokio::test]
async fn test_update_case_persists_examiner_details() {
    let (app, case_id, db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/cases/{}", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "examiner_role": "Senior Digital Forensic Analyst",
                        "examiner_organisation": "Example Forensics Ltd",
                        "examiner_contact": "a.examiner@example.test",
                        "examiner_qualifications": "BCS CITP, GCFE",
                        "report_classification": "RESTRICTED"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let details = db
        .get_case_examiner_details(case_id)
        .await
        .expect("the case exists");
    assert_eq!(
        details.role.as_deref(),
        Some("Senior Digital Forensic Analyst")
    );
    assert_eq!(
        details.organisation.as_deref(),
        Some("Example Forensics Ltd")
    );
    assert_eq!(details.contact.as_deref(), Some("a.examiner@example.test"));
    assert_eq!(details.qualifications.as_deref(), Some("BCS CITP, GCFE"));
    assert_eq!(details.report_classification.as_deref(), Some("RESTRICTED"));
}

/// A case where nothing was recorded reports every field absent.
///
/// The counterweight: if these came back as empty strings the report would
/// render "Role:" with nothing after it, which reads as a fact that was
/// recorded and is blank rather than one that was never recorded at all.
#[tokio::test]
async fn test_unset_examiner_details_are_absent_not_empty() {
    let (_app, case_id, db) = setup_test_app().await;

    let details = db
        .get_case_examiner_details(case_id)
        .await
        .expect("the case exists");
    assert!(details.role.is_none());
    assert!(details.organisation.is_none());
    assert!(details.contact.is_none());
    assert!(details.qualifications.is_none());
    assert!(details.report_classification.is_none());
}

/// Whitespace-only input is treated as absent.
#[tokio::test]
async fn test_whitespace_examiner_details_are_treated_as_absent() {
    let (app, case_id, db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/cases/{}", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "examiner_role": "   ", "examiner_qualifications": "" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let details = db.get_case_examiner_details(case_id).await.unwrap();
    assert!(
        details.role.is_none(),
        "a field someone tabbed through and left blank is not a recorded fact"
    );
    assert!(details.qualifications.is_none());
}

// ============================================================
//  Near-duplicate images (PDQ perceptual clustering)
// ============================================================

/// Insert a PerceptualHash ParsedRecord tied to an image artifact.
async fn insert_perceptual_hash(db: &SqliteConnection, case_id: Uuid, pdq_hex: &str) -> Uuid {
    let image_id = Uuid::new_v4();
    let record = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: Some(image_id),
        artifact_type: ArtifactType::ParsedRecord,
        data: None,
        metadata: json!({
            "type": "PerceptualHash",
            "algorithm": "pdq",
            "pdq_hex": pdq_hex,
        }),
    };
    db.record_artifact(&record).await.unwrap();
    image_id
}

#[tokio::test]
async fn test_near_duplicate_images_groups_close_pdq_hashes() {
    let (app, case_id, db) = setup_test_app().await;

    // A and B differ by one bit (0xAA vs 0xAB in the last byte) → near-duplicates.
    // C is 0xFF throughout → 128 bits from A, well outside the threshold.
    let a = "aa".repeat(32);
    let mut b = "aa".repeat(31);
    b.push_str("ab");
    let c = "ff".repeat(32);
    insert_perceptual_hash(&db, case_id, &a).await;
    insert_perceptual_hash(&db, case_id, &b).await;
    insert_perceptual_hash(&db, case_id, &c).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/near_duplicate_images?threshold=31",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["images_scanned"], 3);
    assert_eq!(
        body["group_count"], 1,
        "A and B form one near-duplicate group"
    );
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(
        groups[0]["count"], 2,
        "the group has exactly the two close images"
    );
    // Each member carries the image artifact id for the gallery to render.
    assert!(groups[0]["members"][0]["image_artifact_id"]
        .as_str()
        .is_some());
    assert_eq!(
        body["grade"], "scanned",
        "a perceptual match is a lead, not an ID"
    );
}

#[tokio::test]
async fn test_near_duplicate_images_empty_when_all_distinct() {
    let (app, case_id, db) = setup_test_app().await;
    insert_perceptual_hash(&db, case_id, &"00".repeat(32)).await;
    insert_perceptual_hash(&db, case_id, &"ff".repeat(32)).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/near_duplicate_images", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["group_count"], 0, "two distinct images form no group");
}

// --- nested bookmark folders (ROADMAP §3.15) ---

async fn folder_request(
    app: &axum::Router,
    method: &str,
    uri: String,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_folder_can_be_created_under_another_and_a_foreign_parent_is_refused() {
    let (app, case_id, db) = setup_test_app().await;
    let base = format!("/api/v1/cases/{case_id}/bookmarks/categories");

    let (status, parent) =
        folder_request(&app, "POST", base.clone(), json!({"name": "Emails"})).await;
    assert_eq!(status, StatusCode::OK, "{parent}");
    assert_eq!(parent["parent_id"], Value::Null);
    let parent_id = parent["id"].as_str().unwrap().to_string();

    let (status, child) = folder_request(
        &app,
        "POST",
        base.clone(),
        json!({"name": "Suspect", "parent_id": parent_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{child}");
    assert_eq!(child["parent_id"], json!(parent_id));

    // A parent that belongs to another case is refused, and nothing is created.
    let other = db.create_case("Other", "Examiner").await.unwrap();
    let theirs = db
        .create_bookmark_category(other, "Theirs", None)
        .await
        .unwrap();
    let (status, body) = folder_request(
        &app,
        "POST",
        base.clone(),
        json!({"name": "Sneaky", "parent_id": theirs.to_string()}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("parent"), "{body}");
    assert_eq!(db.list_bookmark_categories(case_id).await.unwrap().len(), 2);
}

#[tokio::test]
async fn the_category_listing_carries_each_folders_parent() {
    let (app, case_id, db) = setup_test_app().await;
    let root = db
        .create_bookmark_category(case_id, "Root", None)
        .await
        .unwrap();
    let child = db
        .create_bookmark_folder(case_id, "Child", None, Some(root))
        .await
        .unwrap()
        .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/bookmarks/categories"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = body_json(resp).await;
    let find = |id: Uuid| {
        listed
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap()
            .clone()
    };
    assert_eq!(find(root)["parent_id"], Value::Null);
    assert_eq!(find(child)["parent_id"], json!(root));
}

#[tokio::test]
async fn a_folder_is_moved_and_a_cycle_is_refused() {
    let (app, case_id, db) = setup_test_app().await;
    let base = format!("/api/v1/cases/{case_id}/bookmarks/categories");
    let a = db
        .create_bookmark_category(case_id, "A", None)
        .await
        .unwrap();
    let b = db
        .create_bookmark_folder(case_id, "B", None, Some(a))
        .await
        .unwrap()
        .unwrap();

    // Under its own descendant: 400 naming the cycle; nothing moves.
    let (status, body) = folder_request(
        &app,
        "PUT",
        format!("{base}/{a}"),
        json!({"parent_id": b.to_string()}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().to_lowercase().contains("itself"), "{body}");

    // B to the top level.
    let (status, body) = folder_request(
        &app,
        "PUT",
        format!("{base}/{b}"),
        json!({"move_to_root": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = db.list_bookmark_categories(case_id).await.unwrap();
    assert_eq!(listed.iter().find(|c| c.id == b).unwrap().parent_id, None);

    // Both a parent and move_to_root is ambiguous and refused.
    let (status, _) = folder_request(
        &app,
        "PUT",
        format!("{base}/{b}"),
        json!({"parent_id": a.to_string(), "move_to_root": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
