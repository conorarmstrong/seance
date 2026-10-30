//! Integration tests for the browse/stats/histogram/verify/cancel endpoints.

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

const MD5_HELLO: &str = "5d41402abc4b2a76b9719d911017c592";
const SHA1_HELLO: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

async fn setup_test_app() -> (
    axum::Router,
    Uuid,
    Arc<SqliteConnection>,
    seance_core::orchestrator::CancellationHandle,
) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("New Endpoints Test Case", "Test Examiner")
        .await
        .unwrap();

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellation = seance_core::orchestrator::CancellationHandle::new();

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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: cancellation.clone(),
    };

    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db, cancellation)
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

async fn insert_artifact(
    db: &SqliteConnection,
    case_id: Uuid,
    parent_id: Option<Uuid>,
    artifact_type: ArtifactType,
    metadata: Value,
) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id,
        artifact_type,
        data: None,
        metadata,
    };
    db.record_artifact(&artifact).await.unwrap();
    artifact.id
}

/// Seed a source with one directory and files. Returns (source_id, dir_id).
async fn seed_file_tree(db: &SqliteConnection, case_id: Uuid) -> (Uuid, Uuid) {
    let source_id = insert_artifact(
        db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk.dd", "size": 4096,
        }),
    )
    .await;
    let fs_id = insert_artifact(
        db,
        case_id,
        Some(source_id),
        ArtifactType::FileSystem,
        json!({
            "name": "NTFS", "filesystem_type": "NTFS",
        }),
    )
    .await;
    let dir_id = insert_artifact(
        db,
        case_id,
        Some(fs_id),
        ArtifactType::FileEntry,
        json!({
            "name": "Windows", "path": "/Windows", "is_directory": true,
        }),
    )
    .await;
    insert_artifact(
        db,
        case_id,
        Some(dir_id),
        ArtifactType::FileEntry,
        json!({
            "name": "notepad.exe", "path": "/Windows/notepad.exe", "size": 100,
            "modified": "2024-01-02 03:04:05", "created": "2023-12-31 00:00:00",
            "accessed": "2024-02-02 00:00:00",
        }),
    )
    .await;
    insert_artifact(
        db,
        case_id,
        Some(dir_id),
        ArtifactType::FileEntry,
        json!({
            "name": "deleted.tmp", "path": "/Windows/deleted.tmp", "size": 5000,
            "deleted": true,
        }),
    )
    .await;
    insert_artifact(
        db,
        case_id,
        Some(fs_id),
        ArtifactType::FileEntry,
        json!({
            "name": "readme.txt", "path": "/readme.txt", "size": 42,
        }),
    )
    .await;
    (source_id, dir_id)
}

// ============================================================
//  Files listing (list_file_entries backed)
// ============================================================

#[tokio::test]
async fn files_subtree_listing_and_envelope() {
    let (app, case_id, db, _) = setup_test_app().await;
    let (source_id, _) = seed_file_tree(&db, case_id).await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{}/sources/{}/files", case_id, source_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Envelope keys preserved
    assert_eq!(body["total_count"].as_u64().unwrap(), 4);
    assert_eq!(body["page"].as_u64().unwrap(), 1);
    assert_eq!(body["page_size"].as_u64().unwrap(), 100);
    assert_eq!(body["total_pages"].as_u64().unwrap(), 1);
    assert!(!body["has_next"].as_bool().unwrap());
    assert!(!body["has_previous"].as_bool().unwrap());

    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);

    // Rows include path/parent_id/is_directory/is_deleted; no metadata by default
    let notepad = items.iter().find(|i| i["name"] == "notepad.exe").unwrap();
    assert_eq!(notepad["path"].as_str().unwrap(), "/Windows/notepad.exe");
    assert!(notepad["parent_id"].as_str().is_some());
    assert!(!notepad["is_directory"].as_bool().unwrap());
    assert!(!notepad["is_deleted"].as_bool().unwrap());
    assert_eq!(notepad["size"].as_i64().unwrap(), 100);
    assert_eq!(notepad["extension"].as_str().unwrap(), "exe");
    assert_eq!(notepad["modified"].as_str().unwrap(), "2024-01-02 03:04:05");
    assert_eq!(notepad["created"].as_str().unwrap(), "2023-12-31 00:00:00");
    assert_eq!(notepad["accessed"].as_str().unwrap(), "2024-02-02 00:00:00");
    assert!(notepad.get("metadata").is_none());

    let dir = items.iter().find(|i| i["name"] == "Windows").unwrap();
    assert!(dir["is_directory"].as_bool().unwrap());
    let deleted = items.iter().find(|i| i["name"] == "deleted.tmp").unwrap();
    assert!(deleted["is_deleted"].as_bool().unwrap());
}

#[tokio::test]
async fn files_direct_children_scope() {
    let (app, case_id, db, _) = setup_test_app().await;
    let (source_id, dir_id) = seed_file_tree(&db, case_id).await;

    let (status, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/sources/{}/files?parent_id={}",
            case_id, source_id, dir_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"notepad.exe"));
    assert!(names.contains(&"deleted.tmp"));
}

#[tokio::test]
async fn files_filters_sorting_and_pagination() {
    let (app, case_id, db, _) = setup_test_app().await;
    let (source_id, _) = seed_file_tree(&db, case_id).await;
    let base = format!("/api/v1/cases/{}/sources/{}/files", case_id, source_id);

    // extension filter
    let (_, body) = get(&app, format!("{}?extension=exe", base)).await;
    assert_eq!(body["total_count"].as_u64().unwrap(), 1);
    assert_eq!(body["items"][0]["name"], "notepad.exe");

    // name substring filter
    let (_, body) = get(&app, format!("{}?name=read", base)).await;
    assert_eq!(body["total_count"].as_u64().unwrap(), 1);
    assert_eq!(body["items"][0]["name"], "readme.txt");

    // deleted_only
    let (_, body) = get(&app, format!("{}?deleted_only=true", base)).await;
    assert_eq!(body["total_count"].as_u64().unwrap(), 1);
    assert_eq!(body["items"][0]["name"], "deleted.tmp");

    // dirs=only / dirs=exclude
    let (_, body) = get(&app, format!("{}?dirs=only", base)).await;
    assert_eq!(body["total_count"].as_u64().unwrap(), 1);
    assert_eq!(body["items"][0]["name"], "Windows");
    let (_, body) = get(&app, format!("{}?dirs=exclude", base)).await;
    assert_eq!(body["total_count"].as_u64().unwrap(), 3);
    let (status, _) = get(&app, format!("{}?dirs=bogus", base)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // sort by size desc
    let (_, body) = get(&app, format!("{}?dirs=exclude&sort=size&order=desc", base)).await;
    let sizes: Vec<i64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["size"].as_i64().unwrap())
        .collect();
    assert_eq!(sizes, vec![5000, 100, 42]);

    // pagination + page_size clamp
    let (_, body) = get(&app, format!("{}?page=2&page_size=2", base)).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["total_pages"].as_u64().unwrap(), 2);
    assert!(body["has_previous"].as_bool().unwrap());
    let (_, body) = get(&app, format!("{}?page_size=99999", base)).await;
    assert_eq!(body["page_size"].as_u64().unwrap(), 500);

    // Default projection is slim: the full metadata document is omitted from
    // list rows unless explicitly requested (skip_serializing_if on the field).
    let (_, body) = get(&app, format!("{}?extension=exe", base)).await;
    assert!(
        body["items"][0].get("metadata").is_none(),
        "list view must omit the full metadata document by default"
    );

    // include_metadata=true opts back into the full document.
    let (_, body) = get(
        &app,
        format!("{}?extension=exe&include_metadata=true", base),
    )
    .await;
    assert_eq!(body["items"][0]["metadata"]["name"], "notepad.exe");
}

// ============================================================
//  Disk map
// ============================================================

#[tokio::test]
async fn disk_map_regions_and_total_bytes() {
    let (app, case_id, db, _) = setup_test_app().await;

    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk.dd", "size": 1_000_000,
        }),
    )
    .await;
    let part_id = insert_artifact(
        &db,
        case_id,
        Some(source_id),
        ArtifactType::Partition,
        json!({
            "name": "Partition 1", "offset_bytes": 1048576, "size_bytes": 400000,
            "partition_scheme": "MBR",
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        Some(source_id),
        ArtifactType::UnallocatedSpace,
        json!({
            "name": "Unallocated", "offset_bytes": 0, "size_bytes": 1048576,
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        Some(part_id),
        ArtifactType::FileSystem,
        json!({
            "name": "NTFS", "offset_bytes": 1048576, "size_bytes": 400000,
            "filesystem_type": "NTFS",
        }),
    )
    .await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{}/sources/{}/disk_map", case_id, source_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_bytes"].as_i64().unwrap(), 1_000_000);

    let regions = body["regions"].as_array().unwrap();
    assert_eq!(regions.len(), 3);
    // Ordered by offset: unallocated (0) first
    assert_eq!(regions[0]["artifact_type"], "UnallocatedSpace");
    assert_eq!(regions[0]["offset_bytes"].as_i64().unwrap(), 0);
    let partition = regions
        .iter()
        .find(|r| r["artifact_type"] == "Partition")
        .unwrap();
    assert_eq!(partition["scheme"], "MBR");
    assert_eq!(partition["name"], "Partition 1");
    let fs = regions
        .iter()
        .find(|r| r["artifact_type"] == "FileSystem")
        .unwrap();
    assert_eq!(fs["fs_type"], "NTFS");
    assert_eq!(fs["parent_id"].as_str().unwrap(), part_id.to_string());

    // Unknown source -> 404
    let (status, _) = get(
        &app,
        format!(
            "/api/v1/cases/{}/sources/{}/disk_map",
            case_id,
            Uuid::new_v4()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn disk_map_total_bytes_falls_back_to_region_extent() {
    let (app, case_id, db, _) = setup_test_app().await;

    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk.dd",
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        Some(source_id),
        ArtifactType::Partition,
        json!({
            "name": "P1", "offset_bytes": 2048, "size_bytes": 8192,
        }),
    )
    .await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{}/sources/{}/disk_map", case_id, source_id),
    )
    .await;
    assert_eq!(body["total_bytes"].as_i64().unwrap(), 2048 + 8192);
}

// ============================================================
//  Timeline histogram
// ============================================================

async fn insert_timeline_event(db: &SqliteConnection, case_id: Uuid, timestamp: i64, module: &str) {
    insert_artifact(
        db,
        case_id,
        None,
        ArtifactType::TimelineEvent,
        json!({
            "timestamp": timestamp,
            "timestamp_desc": "Modified",
            "source_module": module,
            "short_desc": format!("event at {}", timestamp),
            "full_details": "{}",
        }),
    )
    .await;
}

#[tokio::test]
async fn timeline_histogram_buckets_and_extent() {
    let (app, case_id, db, _) = setup_test_app().await;

    // Events across ~1 hour
    insert_timeline_event(&db, case_id, 1_700_000_000, "mod_a").await;
    insert_timeline_event(&db, case_id, 1_700_000_100, "mod_a").await;
    insert_timeline_event(&db, case_id, 1_700_003_600, "mod_b").await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{}/timeline/histogram", case_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["min_ts"].as_i64().unwrap(), 1_700_000_000);
    assert_eq!(body["max_ts"].as_i64().unwrap(), 1_700_003_600);
    // span 3600 / 120 buckets = 30 -> rounded up to friendly 60
    assert_eq!(body["bucket_seconds"].as_i64().unwrap(), 60);
    let buckets = body["buckets"].as_array().unwrap();
    let total: i64 = buckets.iter().map(|b| b["count"].as_i64().unwrap()).sum();
    assert_eq!(total, 3);
    // Bucket starts are aligned to bucket_seconds
    for b in buckets {
        assert_eq!(b["start"].as_i64().unwrap() % 60, 0);
    }

    // Module filter narrows the histogram (same filters as the list endpoint)
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{}/timeline/histogram?modules=mod_b", case_id),
    )
    .await;
    let total: i64 = body["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["count"].as_i64().unwrap())
        .sum();
    assert_eq!(total, 1);
    assert_eq!(body["min_ts"].as_i64().unwrap(), 1_700_003_600);

    // buckets param is honored (clamped 10..=500)
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{}/timeline/histogram?buckets=10", case_id),
    )
    .await;
    // span 3600 / 10 = 360 -> friendly 900
    assert_eq!(body["bucket_seconds"].as_i64().unwrap(), 900);
}

#[tokio::test]
async fn timeline_histogram_empty_case() {
    let (app, case_id, _db, _) = setup_test_app().await;
    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{}/timeline/histogram", case_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["min_ts"].is_null());
    assert!(body["max_ts"].is_null());
    assert!(body["bucket_seconds"].is_null());
    assert_eq!(body["buckets"].as_array().unwrap().len(), 0);
}

// ============================================================
//  Allocation map
// ============================================================

#[tokio::test]
async fn allocation_map_returns_fields_verbatim() {
    let (app, case_id, db, _) = setup_test_app().await;

    let fs_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        json!({
            "name": "NTFS",
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        Some(fs_id),
        ArtifactType::ParsedRecord,
        json!({
            "type": "allocation_map",
            "allocation_bitmap_b64": "AP8=",
            "allocation_clusters_per_bucket": 64,
            "allocation_total_clusters": 1024,
            "allocation_cluster_size": 4096,
        }),
    )
    .await;

    let (status, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/artifacts/{}/allocation_map",
            case_id, fs_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allocation_bitmap_b64"], "AP8=");
    assert_eq!(body["allocation_clusters_per_bucket"].as_i64().unwrap(), 64);
    assert_eq!(body["allocation_total_clusters"].as_i64().unwrap(), 1024);
    assert_eq!(body["allocation_cluster_size"].as_i64().unwrap(), 4096);
}

#[tokio::test]
async fn allocation_map_404_when_absent() {
    let (app, case_id, db, _) = setup_test_app().await;
    let fs_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        json!({
            "name": "NTFS",
        }),
    )
    .await;
    let (status, _) = get(
        &app,
        format!(
            "/api/v1/cases/{}/artifacts/{}/allocation_map",
            case_id, fs_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================
//  Ancestors
// ============================================================

#[tokio::test]
async fn ancestors_root_first_with_name_fallback() {
    let (app, case_id, db, _) = setup_test_app().await;

    let root = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk.dd",
        }),
    )
    .await;
    // No name metadata -> falls back to artifact type
    let fs = insert_artifact(
        &db,
        case_id,
        Some(root),
        ArtifactType::FileSystem,
        json!({}),
    )
    .await;
    let file = insert_artifact(
        &db,
        case_id,
        Some(fs),
        ArtifactType::FileEntry,
        json!({
            "name": "hosts",
        }),
    )
    .await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{}/artifacts/{}/ancestors", case_id, file),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let chain = body.as_array().unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0]["id"].as_str().unwrap(), root.to_string());
    assert_eq!(chain[0]["name"], "disk.dd");
    assert_eq!(chain[0]["artifact_type"], "RawEvidence");
    assert_eq!(chain[1]["name"], "FileSystem");
    assert_eq!(chain[2]["id"].as_str().unwrap(), file.to_string());
    assert_eq!(chain[2]["name"], "hosts");

    // Unknown artifact -> 404
    let (status, _) = get(
        &app,
        format!(
            "/api/v1/cases/{}/artifacts/{}/ancestors",
            case_id,
            Uuid::new_v4()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================
//  Audit log filters
// ============================================================

#[tokio::test]
async fn audit_log_filtering() {
    let (app, case_id, db, _) = setup_test_app().await;

    db.record_audit_event(
        Some(case_id),
        "alice",
        "case_updated",
        Some("case"),
        Some(case_id),
        None,
    )
    .await
    .unwrap();
    db.record_audit_event(
        Some(case_id),
        "bob",
        "evidence_ingest_requested",
        Some("artifact"),
        None,
        None,
    )
    .await
    .unwrap();
    db.record_audit_event(
        Some(case_id),
        "alice",
        "evidence_ingest_requested",
        Some("artifact"),
        None,
        None,
    )
    .await
    .unwrap();

    // Unfiltered
    let (_, body) = get(&app, format!("/api/v1/cases/{}/audit_log", case_id)).await;
    assert_eq!(body["total"].as_i64().unwrap(), 3);

    // action filter: total reflects the filter
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?action=evidence_ingest_requested",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 2);
    assert!(body["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["action"] == "evidence_ingest_requested"));

    // user + action
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?action=evidence_ingest_requested&user=alice",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 1);
    assert_eq!(body["events"][0]["user_id"], "alice");

    // resource_type
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{}/audit_log?resource_type=case", case_id),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 1);

    // Time bounds: everything is in the past hour
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 3);
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?to=2000-01-01T00:00:00Z",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 0);

    // Invalid RFC3339 -> 400
    let (status, _) = get(
        &app,
        format!("/api/v1/cases/{}/audit_log?from=yesterday", case_id),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================
//  Stats
// ============================================================

#[tokio::test]
async fn stats_sources_counts_per_root() {
    let (app, case_id, db, _) = setup_test_app().await;

    let root_a = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk_a.dd",
        }),
    )
    .await;
    let child = insert_artifact(
        &db,
        case_id,
        Some(root_a),
        ArtifactType::FileSystem,
        json!({}),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        Some(child),
        ArtifactType::FileEntry,
        json!({"name": "f"}),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "disk_b.dd",
        }),
    )
    .await;

    let (status, body) = get(&app, format!("/api/v1/cases/{}/stats/sources", case_id)).await;
    assert_eq!(status, StatusCode::OK);
    let sources = body["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2);
    let a = sources.iter().find(|s| s["name"] == "disk_a.dd").unwrap();
    assert_eq!(
        a["source_artifact_id"].as_str().unwrap(),
        root_a.to_string()
    );
    assert_eq!(a["artifact_count"].as_i64().unwrap(), 2);
    let b = sources.iter().find(|s| s["name"] == "disk_b.dd").unwrap();
    assert_eq!(b["artifact_count"].as_i64().unwrap(), 0);

    // The names come from a walk of the root artifacts, which can fall short;
    // the counts come from their own complete aggregate. A row whose name was
    // not resolved falls back to the bare UUID, so `name_resolved` is the only
    // thing that separates "this source has no name" from "this response failed
    // to fetch its name".
    assert_eq!(a["name_resolved"], json!(true));
    assert_eq!(b["name_resolved"], json!(true));
    assert_eq!(
        body["truncated"],
        json!(false),
        "the name walk reached every root"
    );
    assert_eq!(body["has_more"], json!(false));
    assert_eq!(body["undecodable"], json!(0));
}

#[tokio::test]
async fn stats_file_sizes_pow2_buckets() {
    let (app, case_id, db, _) = setup_test_app().await;

    // 100 bytes -> bucket 6 (64..128); 5000 -> bucket 12 (4096..8192)
    insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileEntry,
        json!({
            "name": "small.bin", "size": 100,
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileEntry,
        json!({
            "name": "big.bin", "size": 5000,
        }),
    )
    .await;
    // Directories are excluded
    insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileEntry,
        json!({
            "name": "dir", "size": 100, "is_directory": true,
        }),
    )
    .await;

    let (status, body) = get(&app, format!("/api/v1/cases/{}/stats/file_sizes", case_id)).await;
    assert_eq!(status, StatusCode::OK);
    let buckets = body["buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0]["pow2"].as_i64().unwrap(), 6);
    assert_eq!(buckets[0]["count"].as_i64().unwrap(), 1);
    assert_eq!(buckets[1]["pow2"].as_i64().unwrap(), 12);
    assert_eq!(buckets[1]["count"].as_i64().unwrap(), 1);
}

// ============================================================
//  Hash hits
// ============================================================

#[tokio::test]
async fn hash_hits_lists_matches() {
    let (app, case_id, db, _) = setup_test_app().await;

    let artifact_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileEntry,
        json!({
            "name": "evil.exe", "path": "/evil.exe", "md5_hash": MD5_HELLO,
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileEntry,
        json!({
            "name": "clean.txt",
        }),
    )
    .await;

    let set_id = db
        .create_hash_set(case_id, "notable-set", None, "notable", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(set_id, &[(MD5_HELLO.to_string(), None)])
        .await
        .unwrap();

    let (status, body) = get(&app, format!("/api/v1/cases/{}/hash_hits", case_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"].as_i64().unwrap(), 1);
    assert_eq!(body["page"].as_u64().unwrap(), 1);
    let hit = &body["hits"][0];
    assert_eq!(
        hit["artifact_id"].as_str().unwrap(),
        artifact_id.to_string()
    );
    assert_eq!(hit["name"], "evil.exe");
    assert_eq!(hit["path"], "/evil.exe");
    assert_eq!(hit["hash_set_id"].as_str().unwrap(), set_id.to_string());
    assert_eq!(hit["hash_set_name"], "notable-set");
    assert_eq!(hit["matched_hash"], MD5_HELLO);
    assert_eq!(hit["algorithm"], "md5");

    // Filter by a different (empty) set
    let other_set = db
        .create_hash_set(case_id, "empty", None, "known", "md5")
        .await
        .unwrap();
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/hash_hits?hash_set_id={}",
            case_id, other_set
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 0);
    assert_eq!(body["hits"].as_array().unwrap().len(), 0);
}

// ============================================================
//  Processing cancel
// ============================================================

#[tokio::test]
async fn cancel_processing_sets_flag_and_audits() {
    let (app, case_id, db, cancellation) = setup_test_app().await;
    let other_case = Uuid::new_v4();
    assert!(!cancellation.is_cancelled(case_id));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/processing/cancel", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["cancelling"].as_bool().unwrap());
    assert!(cancellation.is_cancelled(case_id));
    // The cancel is scoped to this case only: another case must be unaffected,
    // and no global shutdown was triggered.
    assert!(
        !cancellation.is_cancelled(other_case),
        "cancelling one case must not cancel another"
    );
    assert!(!cancellation.is_shutting_down());

    // Best-effort audit event recorded
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?action=processing_cancelled",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 1);
    let _ = db;
}

// ============================================================
//  Verify-as-job
// ============================================================

async fn poll_job(app: &axum::Router, case_id: Uuid, job_id: &str) -> Value {
    for _ in 0..100 {
        let (status, body) = get(app, format!("/api/v1/cases/{}/jobs/{}", case_id, job_id)).await;
        assert_eq!(status, StatusCode::OK);
        if body["status"] != "running" && body["status"] != "pending" {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("verification job did not finish in time");
}

async fn post_verify(app: &axum::Router, case_id: Uuid, artifact_id: Uuid) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}/verify",
                    case_id, artifact_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

#[tokio::test]
async fn verify_runs_as_job_and_records_integrity_check() {
    let (app, case_id, db, _) = setup_test_app().await;

    // Evidence file with a matching acquisition baseline
    let path = std::env::temp_dir().join(format!("seance_verify_{}.bin", Uuid::new_v4()));
    std::fs::write(&path, b"hello").unwrap();

    let artifact_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "evidence.bin",
            "source_path": path.to_str().unwrap(),
            "acquisition_md5": MD5_HELLO,
            "acquisition_sha1": SHA1_HELLO,
            "acquisition_sha256": SHA256_HELLO,
        }),
    )
    .await;

    let (status, body) = post_verify(&app, case_id, artifact_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "running");
    let job_id = body["job_id"].as_str().unwrap().to_string();

    // The job appears in the jobs table and completes
    let job = poll_job(&app, case_id, &job_id).await;
    assert_eq!(job["status"], "complete");
    assert_eq!(job["module_id"], "verify.integrity");
    assert_eq!(
        job["target_artifact_id"].as_str().unwrap(),
        artifact_id.to_string()
    );

    // Integrity check recorded with status verified
    let (_, checks) = get(
        &app,
        format!(
            "/api/v1/cases/{}/artifacts/{}/integrity",
            case_id, artifact_id
        ),
    )
    .await;
    let checks = checks.as_array().unwrap().clone();
    assert!(
        checks.iter().any(|c| c["status"] == "verified"),
        "checks: {checks:?}"
    );

    // Audit event recorded
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?action=evidence_verified",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn verify_without_baseline_reports_no_baseline() {
    let (app, case_id, db, _) = setup_test_app().await;

    let path = std::env::temp_dir().join(format!("seance_verify_{}.bin", Uuid::new_v4()));
    std::fs::write(&path, b"hello").unwrap();

    let artifact_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "evidence.bin",
            "source_path": path.to_str().unwrap(),
        }),
    )
    .await;

    let (status, body) = post_verify(&app, case_id, artifact_id).await;
    assert_eq!(status, StatusCode::OK);
    let job_id = body["job_id"].as_str().unwrap().to_string();
    let job = poll_job(&app, case_id, &job_id).await;
    assert_eq!(job["status"], "complete");

    let (_, checks) = get(
        &app,
        format!(
            "/api/v1/cases/{}/artifacts/{}/integrity",
            case_id, artifact_id
        ),
    )
    .await;
    let checks = checks.as_array().unwrap().clone();
    assert!(
        checks.iter().any(|c| c["status"] == "no_baseline"),
        "checks: {checks:?}"
    );

    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn verify_unresolvable_artifact_fails_request_not_job() {
    let (app, case_id, db, _) = setup_test_app().await;

    // No source_path anywhere in the chain -> content cannot be resolved
    let artifact_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({
            "name": "no-source.bin",
        }),
    )
    .await;

    let (status, _) = post_verify(&app, case_id, artifact_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================
//  Async ingest
// ============================================================

#[tokio::test]
async fn ingest_returns_hashing_and_persists_in_background() {
    let (app, case_id, db, _) = setup_test_app().await;

    let path = std::env::temp_dir().join(format!("seance_ingest_{}.bin", Uuid::new_v4()));
    std::fs::write(&path, b"hello").unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": path.to_str().unwrap() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["status"], "hashing");
    let artifact_id = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    // Parse-while-hashing persists and queues the artifact first (integrity
    // still "verifying"), then records the acquisition baseline concurrently, so
    // poll until the baseline has landed rather than until the row merely exists.
    let mut persisted = None;
    for _ in 0..200 {
        if let Some(artifact) = db.get_artifact(artifact_id).await.unwrap() {
            if artifact.metadata.get("acquisition_md5").is_some() {
                persisted = Some(artifact);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let artifact = persisted.expect("background ingest did not record the baseline in time");
    assert_eq!(artifact.metadata["acquisition_md5"], MD5_HELLO);
    assert_eq!(artifact.metadata["acquisition_sha256"], SHA256_HELLO);
    assert_eq!(artifact.metadata["integrity_state"], "baseline_recorded");

    // The user-attributable ingest audit event is written at request time, and
    // says only that an ingest was REQUESTED: at the moment it is written the
    // hash has not run, so it cannot yet claim evidence was ingested. The
    // outcome is a separate event written when the background task ends.
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/audit_log?action=evidence_ingest_requested",
            case_id
        ),
    )
    .await;
    assert_eq!(body["total"].as_i64().unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

/// BUG-236: the persisted `source_path` must be the canonical path that was
/// actually opened and hashed, not the caller's (possibly non-canonical,
/// CWD-dependent) string. The original request is kept as `requested_path`.
#[tokio::test]
async fn ingest_persists_the_canonical_source_path() {
    let (app, case_id, db, _) = setup_test_app().await;

    let dir = std::env::temp_dir();
    let name = format!("seance_canon_{}.bin", Uuid::new_v4());
    let path = dir.join(&name);
    std::fs::write(&path, b"hello").unwrap();

    // Deliberately non-canonical: an extra "." component in the middle.
    let requested = dir.join(".").join(&name).to_str().unwrap().to_string();
    let canonical = std::fs::canonicalize(&path)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "path": requested }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let artifact_id = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    let mut persisted = None;
    for _ in 0..100 {
        if let Some(artifact) = db.get_artifact(artifact_id).await.unwrap() {
            persisted = Some(artifact);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let artifact = persisted.expect("background ingest did not persist the artifact in time");
    assert_eq!(artifact.metadata["source_path"], canonical);
    assert_eq!(artifact.metadata["path"], canonical);
    assert_eq!(artifact.metadata["requested_path"], requested);

    std::fs::remove_file(&path).ok();
}

/// LIVE-002 class. A directory is a source in its own right — an iOS backup
/// folder is the standard iOS acquisition — and the directory-aware modules
/// require a specific shape: `RawEvidence`, `path` at the directory, and
/// `is_directory: true`. `IosBackupParser` does nothing without it;
/// `AsepEnumerator`, `FileHasher`, `FileAnalyzer` and the iOS artifact readers
/// all branch on it. Only `seance scan` ever wrote that shape, so the whole
/// mobile-backup path was unreachable through the API and the UI, while every
/// unit test passed because they construct the artifact directly.
///
/// `FileDataSource::new` on a directory does not fail on Unix, so this had no
/// loud failure mode either: it opened the fd and every subsequent read failed.
#[tokio::test]
async fn a_directory_is_ingested_in_the_shape_the_directory_modules_require() {
    let (app, case_id, db, _) = setup_test_app().await;

    let dir = std::env::temp_dir().join(format!("seance_ios_backup_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Manifest.db"), b"SQLite format 3\0").unwrap();
    let canonical = std::fs::canonicalize(&dir)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": dir.to_str().unwrap() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a directory must be an ingestable source"
    );
    let body = body_json(response).await;
    // A directory has no bytes of its own, so claiming a hashing phase that
    // will never run would be a false statement about the chain of custody.
    assert_eq!(body["status"], "queued");
    let artifact_id = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    let mut persisted = None;
    for _ in 0..100 {
        if let Some(artifact) = db.get_artifact(artifact_id).await.unwrap() {
            persisted = Some(artifact);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let artifact = persisted.expect("background ingest did not persist the directory in time");
    assert_eq!(
        artifact.artifact_type,
        ArtifactType::RawEvidence,
        "the directory-aware modules subscribe to RawEvidence"
    );
    assert_eq!(
        artifact.metadata["is_directory"],
        json!(true),
        "without this key every directory-aware module skips the source"
    );
    assert_eq!(
        artifact.metadata["path"], canonical,
        "IosBackupParser opens `path` and requires it to be the directory"
    );
    assert!(
        artifact.metadata.get("source_path").is_none(),
        "a directory has no bytes to hash; setting source_path would fail the ingest"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A directory is not a memory capture, and a declaration on one would be
/// written onto an artifact with no data source behind it — recorded, read, and
/// matched against nothing.
#[tokio::test]
async fn a_memory_declaration_on_a_directory_is_refused() {
    let (app, case_id, _db, _) = setup_test_app().await;

    let dir = std::env::temp_dir().join(format!("seance_dir_mem_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": dir.to_str().unwrap(), "memory_image": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    std::fs::remove_dir_all(&dir).ok();
}

/// LIVE-002 class. A source whose type could not be determined used to be
/// classified `Container` — a positive claim that it wraps other files. Every
/// module subscribing to `Container` refuses a subtype it does not recognise,
/// and `SearchIndexer` does not subscribe to `Container` at all, so the ingest
/// reported success and produced an artifact nothing would open and no search
/// could find. `RawEvidence` is the honest non-claim, and it is what the memory
/// module, the filesystem detector and the search index all receive.
#[tokio::test]
async fn an_undetermined_source_is_ingested_as_raw_evidence_not_a_container() {
    let (app, case_id, db, _) = setup_test_app().await;

    // An Android backup: `AndroidBackupModule` subscribes to RawEvidence and
    // FileEntry, and `.ab` matches no magic and no extension entry.
    let path = std::env::temp_dir().join(format!("seance_undetermined_{}.ab", Uuid::new_v4()));
    std::fs::write(&path, b"ANDROID BACKUP\n5\n1\nnone\n").unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": path.to_str().unwrap() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let artifact_id = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    let mut persisted = None;
    for _ in 0..100 {
        if let Some(artifact) = db.get_artifact(artifact_id).await.unwrap() {
            persisted = Some(artifact);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let artifact = persisted.expect("background ingest did not persist the artifact in time");
    assert_eq!(
        artifact.artifact_type,
        ArtifactType::RawEvidence,
        "an undetermined source must not be claimed to be a container"
    );
    assert!(
        artifact.metadata.get("subtype").is_none(),
        "nothing was determined, so no subtype may be claimed"
    );

    std::fs::remove_file(&path).ok();
}

/// The same change makes `auto` plus a memory declaration work: a `.mem` matches
/// no magic and no extension entry, so it resolves to RawEvidence — the type the
/// memory analysis receives — and the declaration is honoured rather than
/// refused for landing on a type the module never sees.
#[tokio::test]
async fn a_declared_raw_capture_is_accepted_under_auto_detection() {
    let (app, case_id, db, _) = setup_test_app().await;

    let path = std::env::temp_dir().join(format!("seance_capture_{}.mem", Uuid::new_v4()));
    std::fs::write(&path, vec![0u8; 4096]).unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": path.to_str().unwrap(), "memory_image": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a declared headerless capture must be ingestable without overriding the type by hand"
    );
    let body = body_json(response).await;
    let artifact_id = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    let mut persisted = None;
    for _ in 0..100 {
        if let Some(artifact) = db.get_artifact(artifact_id).await.unwrap() {
            persisted = Some(artifact);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let artifact = persisted.expect("background ingest did not persist the artifact in time");
    assert_eq!(artifact.artifact_type, ArtifactType::RawEvidence);
    assert_eq!(
        artifact.metadata["memory_image"],
        json!(true),
        "the declaration must reach the metadata verbatim, at the top level"
    );

    std::fs::remove_file(&path).ok();
}

/// The other half of the same rule, and the half that must not be relaxed as a
/// side effect of accepting a declared capture under `auto`: a declaration on a
/// source whose own bytes identify it as something the memory analysis never
/// receives is REFUSED, not recorded.
///
/// `MemoryImageModule` subscribes to RawEvidence and FileEntry only. Attached
/// to a Container the keys are persisted, read by nothing, and the ingest
/// reports success with the whole memory tier absent — which on a report reads
/// exactly like a capture that held no evidence. The refusal is the only thing
/// that puts the mistaken declaration on the record, so it is asserted here
/// end-to-end rather than inferred from the type table.
#[tokio::test]
async fn a_memory_declaration_on_a_detected_container_is_refused() {
    let (app, case_id, _db, _) = setup_test_app().await;

    // A ZIP by magic, and a ZIP by extension: both routes resolve to Container.
    let path = std::env::temp_dir().join(format!("seance_declared_{}.zip", Uuid::new_v4()));
    std::fs::write(&path, b"PK\x03\x04\x14\x00\x00\x00\x00\x00").unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": path.to_str().unwrap(), "memory_image": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a declaration the analysis could never read must end the request"
    );
    let body = body_json(response).await;
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Container"),
        "the refusal must name what the source actually is: {message}"
    );
    assert!(
        message.contains("RawEvidence"),
        "and the type that would honour the declaration: {message}"
    );

    std::fs::remove_file(&path).ok();
}

/// B6-028: the audit log is ONE hash chain across the installation, so a
/// per-case route cannot report the result as a statement about this case. The
/// payload used to be `{valid, checked, broken_at}` with nothing saying what
/// was verified, and the UI rendered it under the case heading.
#[tokio::test]
async fn audit_chain_verify_declares_its_instance_wide_scope() {
    let (app, case_id, _db, _cancel) = setup_test_app().await;

    let (status, body) = get(&app, format!("/api/v1/cases/{}/audit_log/verify", case_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["valid"].is_boolean());
    assert_eq!(
        body["scope"].as_str(),
        Some("instance"),
        "the verify result must name what it covers"
    );
    assert!(
        body["scope_note"]
            .as_str()
            .unwrap_or_default()
            .contains("instance-wide hash chain"),
        "scope_note missing: {body}"
    );
    // DEPLOY-001: the payload carries the keyed/unkeyed split and the row from
    // which the chain is tamper-evident, so a partially keyed chain is never
    // reduced to one adjective. The test app is unkeyed; the fields must still
    // be present, not absent.
    assert!(body["keyed_rows"].is_i64(), "{body}");
    assert!(body["unkeyed_rows"].is_i64(), "{body}");
    assert!(
        body.get("tamper_evident_from").is_some() && body.get("break_reason").is_some(),
        "{body}"
    );
    // AUDIT-001: with no anchor supplied, completeness is reported as NOT
    // CHECKED — never as intact. A hash chain cannot show a deleted tail, so
    // silence here would read as "complete" for a question never asked.
    assert_eq!(body["completeness"]["anchored"], false, "{body}");
    assert_eq!(body["completeness"]["verdict"], "not_checked", "{body}");
    // And the head is published so it CAN be anchored out of band next time.
    assert!(
        body.get("head_id").is_some() && body.get("head_hash").is_some(),
        "{body}"
    );
}

/// AUDIT-001: an external anchor names a ROW, and the three verdicts it can
/// produce are the whole point of the feature.
///
/// Anchoring against the CURRENT head cannot work — an audit log grows on every
/// examiner action, so the head legitimately moves and every later verification
/// would cry tampering. These pin the row-anchored behaviour instead: a log that
/// has merely GROWN is intact, a rewritten anchor row is `diverged`, and an
/// anchor row that is gone is `truncated`.
#[tokio::test]
async fn an_anchored_verify_reports_intact_truncated_and_diverged() {
    let (app, case_id, db, _cancel) = setup_test_app().await;
    let verify_path = format!("/api/v1/cases/{}/audit_log/verify", case_id);

    // A chain needs entries before it has a head to anchor.
    for i in 0..3 {
        db.record_audit_event(
            Some(case_id),
            "examiner",
            "evidence_reviewed",
            None,
            None,
            Some(&format!("seed {i}")),
        )
        .await
        .expect("audit write");
    }

    // Anchor the current head.
    let (_, body) = get(&app, verify_path.clone()).await;
    let head_id = body["head_id"].as_i64().expect("a head id to anchor");
    let head_hash = body["head_hash"].as_str().expect("a head hash").to_string();

    // The log grows, as it does on every examiner action. That is NOT tampering
    // and must not be reported as such.
    for i in 0..3 {
        db.record_audit_event(
            Some(case_id),
            "examiner",
            "case_opened",
            None,
            None,
            Some(&format!("growth {i}")),
        )
        .await
        .expect("audit write");
    }
    let (status, body) = get(
        &app,
        format!("{verify_path}?expected_head_id={head_id}&expected_head={head_hash}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["completeness"]["verdict"], "intact",
        "a log that merely grew since the anchor must not read as tampered: {body}"
    );

    // A rewritten anchor row: present, different hash.
    let (status, body) = get(
        &app,
        format!(
            "{verify_path}?expected_head_id={head_id}&expected_head={}",
            "0".repeat(64)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["completeness"]["verdict"], "diverged", "{body}");

    // An anchor row that no longer exists at all: deleted tail.
    let (status, body) = get(
        &app,
        format!("{verify_path}?expected_head_id=999999&expected_head={head_hash}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["completeness"]["verdict"], "truncated", "{body}");

    // A half-supplied anchor is refused rather than silently degrading to
    // "not checked": the operator believes they checked something.
    let (status, _) = get(&app, format!("{verify_path}?expected_head_id={head_id}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(&app, format!("{verify_path}?expected_head={head_hash}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(
        &app,
        format!("{verify_path}?expected_head_id=notanumber&expected_head={head_hash}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// B4-020: a full page of conversation hits was returned as `{hits: [...]}`
/// with no limit, total or truncation flag, so matches beyond the cap simply
/// appeared not to exist.
#[tokio::test]
async fn conversation_search_declares_a_capped_hit_list() {
    let (app, case_id, db, _cancel) = setup_test_app().await;

    for (i, text) in ["coffee at nine", "more coffee", "coffee again"]
        .iter()
        .enumerate()
    {
        insert_artifact(
            &db,
            case_id,
            None,
            ArtifactType::ParsedRecord,
            json!({
                "type": "WhatsApp",
                "contact_jid": "alice",
                "text": text,
                "date": 1_000 + i as i64,
            }),
        )
        .await;
    }

    // Limit below the number of matches: the page is full, so the hit list is a
    // lower bound and must say so.
    let (status, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/conversations/search?type=WhatsApp&q=coffee&limit=2",
            case_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hits"].as_array().unwrap().len(), 2);
    assert_eq!(body["limit"].as_u64(), Some(2));
    assert_eq!(body["truncated"].as_bool(), Some(true));
    assert_eq!(body["count_is_lower_bound"].as_bool(), Some(true));

    // Room to spare: the hit list is the whole match set.
    let (_, body) = get(
        &app,
        format!(
            "/api/v1/cases/{}/conversations/search?type=WhatsApp&q=coffee&limit=50",
            case_id
        ),
    )
    .await;
    assert_eq!(body["hits"].as_array().unwrap().len(), 3);
    assert_eq!(body["truncated"].as_bool(), Some(false));
}

/// HUNT-081. A headerless raw memory capture is analysed only when the ingest
/// DECLARES it (`memory_image: true`), because a file name is not evidence.
/// `seance_memory::undeclared_memory_hint` exists to say so, and its own
/// documentation says it is returned "so the ingest surfaces can put it in
/// front of an operator at the moment of ingest, which is where it is actually
/// read". No ingest surface used it: the sentence went to the server log and
/// nowhere else, so an examiner who ingested a `.mem` got `status: hashing`,
/// no memory records, and no hint — output identical to a case with no capture
/// at all, which reads as "Séance cannot do memory".
#[tokio::test]
async fn an_undeclared_memory_shaped_ingest_returns_the_hint_that_names_the_flag() {
    let (app, case_id, _db, _) = setup_test_app().await;

    let path = std::env::temp_dir().join(format!("seance_physmem_{}.mem", Uuid::new_v4()));
    std::fs::write(&path, vec![0u8; 4096]).unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": path.to_str().unwrap() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["status"], "hashing");

    let note = body["notes"]
        .as_array()
        .and_then(|n| n.first())
        .and_then(|n| n.as_str())
        .unwrap_or_else(|| panic!("an undeclared .mem ingest must return the hint: {body}"));
    // It names the evidence, and the key that would make it analysable.
    assert!(note.contains(".mem"), "{note}");
    assert!(note.contains("memory_image"), "{note}");
    let _ = std::fs::remove_file(&path);
}

/// The other half: a declared capture is not lectured about declaring it, and
/// an ordinary disk image never sees the sentence at all.
#[tokio::test]
async fn a_declared_capture_and_an_ordinary_image_get_no_memory_hint() {
    let (app, case_id, _db, _) = setup_test_app().await;

    let declared = std::env::temp_dir().join(format!("seance_declared_{}.mem", Uuid::new_v4()));
    std::fs::write(&declared, vec![0u8; 4096]).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": declared.to_str().unwrap(), "memory_image": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(response).await;
    assert!(
        body.get("notes").is_none() || body["notes"].as_array().is_none_or(|n| n.is_empty()),
        "a declared capture needs no hint: {body}"
    );

    let disk = std::env::temp_dir().join(format!("seance_disk_{}.dd", Uuid::new_v4()));
    std::fs::write(&disk, vec![0u8; 4096]).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "path": disk.to_str().unwrap() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(response).await;
    assert!(
        body.get("notes").is_none() || body["notes"].as_array().is_none_or(|n| n.is_empty()),
        "a disk image is not memory-shaped and gets no hint: {body}"
    );
    let _ = std::fs::remove_file(&declared);
    let _ = std::fs::remove_file(&disk);
}
