//! Integration tests for the capabilities added in this change:
//! export-integrity headers, bulk file export + manifest, known-file status,
//! records-by-type, one-click deep carve, source size at ingest, and
//! gather_report_data assembly.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{gather_report_data, router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::Orchestrator,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const IMAGE_SIZE: usize = 64 * 1024;
const PART_OFFSET: u64 = 4096;
const PART_SIZE: u64 = 8192;

/// Build an app whose orchestrator is running (so ad-hoc sends succeed) and
/// return the router, db, the AppState (for direct calls), and a case id.
async fn setup() -> (axum::Router, Arc<SqliteConnection>, AppState, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Cap Test Case", "Test Examiner")
        .await
        .unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let orchestrator_sender = orchestrator.task_submitter();
    let event_sender = orchestrator.event_sender();
    let ad_hoc_sender = orchestrator.ad_hoc_submitter();
    let status_sender = orchestrator.status_sender();
    let active_tasks = orchestrator.active_tasks();
    let ingestion_service = orchestrator.ingestion_service();
    tokio::spawn(async move {
        orchestrator.run().await;
    });

    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender,
        event_sender,
        ad_hoc_sender,
        status_sender,
        active_tasks,
        search_service: None,
        ingestion_service,
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state.clone(), Some(auth_config));
    (app, db, app_state, case_id)
}

fn image_bytes() -> Vec<u8> {
    (0..IMAGE_SIZE).map(|i| (i % 251) as u8).collect()
}

fn write_image(dir: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
    let data = image_bytes();
    let path = dir.join("disk.raw");
    std::fs::write(&path, &data).unwrap();
    (path, data)
}

/// root(RawEvidence) -> Partition -> FileSystem. Returns (root, part, fs).
async fn record_disk_chain(
    db: &SqliteConnection,
    case_id: Uuid,
    image_path: &std::path::Path,
) -> (Uuid, Uuid, Uuid) {
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "disk.raw",
            "source_path": image_path.to_str().unwrap(),
            "path": image_path.to_str().unwrap(),
        }),
    );
    let part = Artifact::new(
        case_id,
        ArtifactType::Partition,
        None,
        json!({
            "name": "partition0", "offset_bytes": PART_OFFSET, "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(root.id);
    let fs = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        None,
        json!({
            "filesystem_type": "NTFS", "offset_bytes": PART_OFFSET, "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(part.id);
    db.record_artifact(&root).await.unwrap();
    db.record_artifact(&part).await.unwrap();
    db.record_artifact(&fs).await.unwrap();
    (root.id, part.id, fs.id)
}

async fn record_run_file(
    db: &SqliteConnection,
    case_id: Uuid,
    fs_id: Uuid,
    name: &str,
    extra: serde_json::Value,
) -> Uuid {
    let mut meta = json!({
        "name": name,
        "path": format!("/{}", name),
        "size": 32,
        "data_runs": [[512, 16], [null, 8], [1024, 8]],
    });
    if let (Some(obj), Some(ex)) = (meta.as_object_mut(), extra.as_object()) {
        for (k, v) in ex {
            obj.insert(k.clone(), v.clone());
        }
    }
    let file = Artifact::new(case_id, ArtifactType::FileEntry, None, meta).with_parent(fs_id);
    db.record_artifact(&file).await.unwrap();
    file.id
}

fn get(uri: String) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_json(uri: String, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(response).await).unwrap()
}

// ── Task 1: export-integrity headers ─────────────────────────────────────

#[tokio::test]
async fn test_content_integrity_headers_present_and_absent() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    let md5 = "0123456789abcdef0123456789abcdef";
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let hashed = record_run_file(
        &db,
        case_id,
        fs_id,
        "hashed.bin",
        json!({ "md5": md5, "sha256": sha256 }),
    )
    .await;
    let plain = record_run_file(&db, case_id, fs_id, "plain.bin", json!({})).await;

    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, hashed
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-content-sha256")
            .and_then(|v| v.to_str().ok()),
        Some(sha256)
    );
    assert_eq!(
        resp.headers()
            .get("x-content-md5")
            .and_then(|v| v.to_str().ok()),
        Some(md5)
    );

    let resp = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, plain
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-content-sha256").is_none());
    assert!(resp.headers().get("x-content-md5").is_none());
}

// ── Task 2: bulk export + manifest ───────────────────────────────────────

#[tokio::test]
async fn test_bulk_export_zip_with_manifest() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_a = record_run_file(&db, case_id, fs_id, "a.bin", json!({})).await;
    let file_b = record_run_file(&db, case_id, fs_id, "b.bin", json!({})).await;
    let missing = Uuid::new_v4();

    let resp = app
        .oneshot(post_json(
            format!("/api/v1/cases/{}/export/files", case_id),
            json!({ "artifact_ids": [file_a, file_b, missing] }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/zip")
    );
    assert_eq!(
        resp.headers()
            .get("x-export-file-count")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        resp.headers()
            .get("x-export-skipped-count")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );

    let bytes = body_bytes(resp).await;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let names: Vec<String> = zip.file_names().map(|s| s.unwrap().to_string()).collect();
    assert!(names.contains(&"a.bin".to_string()), "names: {:?}", names);
    assert!(names.contains(&"b.bin".to_string()));
    assert!(names.contains(&"MANIFEST.json".to_string()));
    assert!(names.contains(&"MANIFEST.csv".to_string()));

    let mut mf = String::new();
    zip.by_name("MANIFEST.json")
        .unwrap()
        .read_to_string(&mut mf)
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&mf).unwrap();
    assert_eq!(manifest["examiner"], "local"); // AuthenticatedUser (auth disabled → local)
    assert_eq!(manifest["case_name"], "Cap Test Case");
    assert!(manifest["tool_version"].as_str().is_some());
    assert_eq!(manifest["file_count"], 2);
    assert_eq!(manifest["skipped_count"], 1);
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    // Each file row carries all three hashes (recomputed) and a size.
    for f in files {
        assert_eq!(f["md5"].as_str().unwrap().len(), 32);
        assert_eq!(f["sha1"].as_str().unwrap().len(), 40);
        assert_eq!(f["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(f["size"].as_u64(), Some(32));
    }
    assert_eq!(manifest["skipped"].as_array().unwrap().len(), 1);

    let mut csv = String::new();
    zip.by_name("MANIFEST.csv")
        .unwrap()
        .read_to_string(&mut csv)
        .unwrap();
    assert!(csv.contains("# case_name,Cap Test Case"));
    assert!(csv.contains("artifact_id,name,path,size,md5,sha1,sha256"));
}

#[tokio::test]
async fn test_bulk_export_flags_short_content_as_incomplete() {
    // A file whose runs reach past the end of the filesystem window can only be
    // read in part. The archive still gets what exists, but the package must say
    // so: a chain-of-custody manifest that looks complete while bytes are
    // missing is the failure this guards (BUG-245).
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    // FS window is PART_SIZE (8192) bytes; this run starts 192 bytes before the
    // end and claims 1024, so only 192 bytes are readable.
    let short = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "truncated.bin",
            "path": "/truncated.bin",
            "size": 1024,
            "data_runs": [[PART_SIZE - 192, 1024]],
        }),
    )
    .with_parent(fs_id);
    db.record_artifact(&short).await.unwrap();
    let whole = record_run_file(&db, case_id, fs_id, "whole.bin", json!({})).await;

    let resp = app
        .oneshot(post_json(
            format!("/api/v1/cases/{}/export/files", case_id),
            json!({ "artifact_ids": [short.id, whole] }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-export-incomplete-count")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "the response must announce the incomplete file"
    );

    let bytes = body_bytes(resp).await;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut mf = String::new();
    zip.by_name("MANIFEST.json")
        .unwrap()
        .read_to_string(&mut mf)
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&mf).unwrap();

    assert_eq!(manifest["incomplete_count"], 1);
    let flagged = manifest["incomplete"].as_array().unwrap();
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0]["name"], "truncated.bin");
    assert_eq!(flagged[0]["bytes_exported"].as_u64(), Some(192));
    assert_eq!(flagged[0]["expected_size"].as_u64(), Some(1024));
    assert_eq!(flagged[0]["reason"], "short_read");

    let files = manifest["files"].as_array().unwrap();
    let short_row = files
        .iter()
        .find(|f| f["name"] == "truncated.bin")
        .expect("short file is still in the manifest");
    assert_eq!(short_row["content_incomplete"], true);
    assert_eq!(short_row["size"].as_u64(), Some(192));
    assert_eq!(short_row["expected_size"].as_u64(), Some(1024));
    assert_eq!(short_row["incomplete_reason"], "short_read");

    // The fully-readable file must NOT be flagged.
    let whole_row = files
        .iter()
        .find(|f| f["name"] == "whole.bin")
        .expect("complete file present");
    assert_eq!(whole_row["content_incomplete"], false);
    assert_eq!(whole_row["size"], whole_row["expected_size"]);

    let mut csv = String::new();
    zip.by_name("MANIFEST.csv")
        .unwrap()
        .read_to_string(&mut csv)
        .unwrap();
    assert!(csv.contains(",1024,short_read"), "csv: {csv}");
}

#[tokio::test]
async fn test_bulk_export_without_manifest() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_a = record_run_file(&db, case_id, fs_id, "a.bin", json!({})).await;

    let resp = app
        .oneshot(post_json(
            format!("/api/v1/cases/{}/export/files", case_id),
            json!({ "artifact_ids": [file_a], "include_manifest": false }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let names: Vec<String> = zip.file_names().map(|s| s.unwrap().to_string()).collect();
    assert!(names.contains(&"a.bin".to_string()));
    assert!(!names.iter().any(|n| n.starts_with("MANIFEST")));
}

#[tokio::test]
async fn test_bulk_export_empty_ids_rejected() {
    let (app, _db, _state, case_id) = setup().await;
    let resp = app
        .oneshot(post_json(
            format!("/api/v1/cases/{}/export/files", case_id),
            json!({ "artifact_ids": [] }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Task 3: known-file status ────────────────────────────────────────────

async fn plain_file(
    db: &SqliteConnection,
    case_id: Uuid,
    fs_id: Uuid,
    name: &str,
    md5: Option<&str>,
) -> Uuid {
    let mut meta = json!({ "name": name, "path": format!("/{}", name), "size": 10 });
    if let Some(h) = md5 {
        meta.as_object_mut().unwrap().insert("md5".into(), json!(h));
    }
    let file = Artifact::new(case_id, ArtifactType::FileEntry, None, meta).with_parent(fs_id);
    db.record_artifact(&file).await.unwrap();
    file.id
}

#[tokio::test]
async fn test_known_status_and_filter() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (root_id, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    let md5_notable = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let md5_known = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let _fa = plain_file(&db, case_id, fs_id, "notable.exe", Some(md5_notable)).await;
    let _fb = plain_file(&db, case_id, fs_id, "known.dll", Some(md5_known)).await;
    let _fc = plain_file(&db, case_id, fs_id, "unknown.txt", None).await;

    let notable_set = db
        .create_hash_set(case_id, "malware", None, "notable", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(notable_set, &[(md5_notable.to_string(), None)])
        .await
        .unwrap();
    let known_set = db
        .create_hash_set(case_id, "nsrl", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(known_set, &[(md5_known.to_string(), None)])
        .await
        .unwrap();

    // Full listing: every file carries a known_status key.
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/sources/{}/files",
            case_id, root_id
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    let status_of =
        |name: &str| items.iter().find(|i| i["name"] == name).unwrap()["known_status"].clone();
    assert_eq!(status_of("notable.exe"), json!("notable"));
    assert_eq!(status_of("known.dll"), json!("known"));
    assert_eq!(status_of("unknown.txt"), json!(null));

    // known=notable → just the notable file.
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/sources/{}/files?known=notable",
            case_id, root_id
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "notable.exe");

    // known=unknown → only the hashless file.
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/sources/{}/files?known=unknown",
            case_id, root_id
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "unknown.txt");

    // Invalid value → 400.
    let resp = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/sources/{}/files?known=bogus",
            case_id, root_id
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Precise CASE semantics of the known filter, including the `known=known`
/// filter and a file whose hash is in BOTH a notable and a known set (which must
/// classify as notable, and so appear under known=notable but NOT known=known).
#[tokio::test]
async fn test_known_status_filter_precise_classification() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (root_id, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    let md5_notable = "11111111111111111111111111111111";
    let md5_known = "22222222222222222222222222222222";
    let md5_both = "33333333333333333333333333333333";
    plain_file(&db, case_id, fs_id, "bad.exe", Some(md5_notable)).await;
    plain_file(&db, case_id, fs_id, "good.dll", Some(md5_known)).await;
    plain_file(&db, case_id, fs_id, "both.bin", Some(md5_both)).await;
    plain_file(&db, case_id, fs_id, "plain.txt", None).await;

    let notable_set = db
        .create_hash_set(case_id, "malware", None, "notable", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(
        notable_set,
        &[
            (md5_notable.to_string(), None),
            (md5_both.to_string(), None),
        ],
    )
    .await
    .unwrap();
    let known_set = db
        .create_hash_set(case_id, "nsrl", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(
        known_set,
        &[(md5_known.to_string(), None), (md5_both.to_string(), None)],
    )
    .await
    .unwrap();

    let list_names = |q: &str| {
        let app = app.clone();
        let q = q.to_string();
        async move {
            let uri = format!("/api/v1/cases/{}/sources/{}/files{}", case_id, root_id, q);
            let body = body_json(app.oneshot(get(uri)).await.unwrap()).await;
            let mut names: Vec<String> = body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["name"].as_str().unwrap().to_string())
                .collect();
            names.sort();
            names
        }
    };

    // A hash in both sets classifies as notable (higher priority).
    let all = body_json(
        app.clone()
            .oneshot(get(format!(
                "/api/v1/cases/{}/sources/{}/files",
                case_id, root_id
            )))
            .await
            .unwrap(),
    )
    .await;
    let status_of = |name: &str| {
        all["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == name)
            .unwrap()["known_status"]
            .clone()
    };
    assert_eq!(status_of("both.bin"), json!("notable"));

    // known=notable → the notable file and the both-sets file.
    assert_eq!(
        list_names("?known=notable").await,
        vec!["bad.exe", "both.bin"]
    );
    // known=known → only the purely-known file (both.bin is notable, excluded).
    assert_eq!(list_names("?known=known").await, vec!["good.dll"]);
    // known=unknown → only the hashless file.
    assert_eq!(list_names("?known=unknown").await, vec!["plain.txt"]);
}

// ── Task 4: records-by-type ──────────────────────────────────────────────

async fn record_parsed(db: &SqliteConnection, case_id: Uuid, parent: Uuid, rtype: &str, n: usize) {
    for i in 0..n {
        let a = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": rtype, "index": i, "detail": format!("{}-{}", rtype, i),
            }),
        )
        .with_parent(parent);
        db.record_artifact(&a).await.unwrap();
    }
}

#[tokio::test]
async fn test_records_by_type_and_counts() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (root_id, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    record_parsed(&db, case_id, fs_id, "browser_history", 3).await;
    record_parsed(&db, case_id, fs_id, "lnk", 2).await;

    // A second, independent acquisition with its own records, to prove the
    // source-scoped counts attribute records to the right source.
    let source_b = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "second.raw" }),
    );
    db.record_artifact(&source_b).await.unwrap();
    record_parsed(&db, case_id, source_b.id, "prefetch", 1).await;

    // record_types → case-wide counts (both sources).
    let counts_at = |suffix: String| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(get(format!(
                    "/api/v1/cases/{}/record_types{}",
                    case_id, suffix
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            let types = body["record_types"].as_array().unwrap().clone();
            move |t: &str| {
                types
                    .iter()
                    .find(|x| x["type"] == t)
                    .map(|x| x["count"].as_i64().unwrap())
            }
        }
    };

    let count_of = counts_at(String::new()).await;
    assert_eq!(count_of("browser_history"), Some(3));
    assert_eq!(count_of("lnk"), Some(2));
    assert_eq!(count_of("prefetch"), Some(1), "B's record shows case-wide");

    // record_types?source_id=<A> → only A's records; B's prefetch is absent.
    let count_a = counts_at(format!("?source_id={}", root_id)).await;
    assert_eq!(count_a("browser_history"), Some(3));
    assert_eq!(count_a("lnk"), Some(2));
    assert_eq!(count_a("prefetch"), None, "prefetch belongs to source B");

    // record_types?source_id=<B> → only B's one record; A's are absent.
    let count_b = counts_at(format!("?source_id={}", source_b.id)).await;
    assert_eq!(count_b("prefetch"), Some(1));
    assert_eq!(count_b("browser_history"), None, "source B has no history");
    assert_eq!(count_b("lnk"), None);

    // record_types?source_id=<unrelated> → nothing.
    let count_none = counts_at(format!("?source_id={}", Uuid::new_v4())).await;
    assert_eq!(count_none("browser_history"), None);

    // records?type=browser_history
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/records?type=browser_history",
            case_id
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["type"], "browser_history");
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["artifact_type"], "ParsedRecord");
    assert!(records[0]["metadata"]["type"] == "browser_history");
    assert!(records[0]["id"].as_str().is_some());

    // Pagination.
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/records?type=browser_history&page=1&page_size=2",
            case_id
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"], 3);

    // source_id scoping (records live under root_id's subtree).
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/records?type=lnk&source_id={}",
            case_id, root_id
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["total"], 2);

    // Unrelated source → 0.
    let other = Uuid::new_v4();
    let resp = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/records?type=lnk&source_id={}",
            case_id, other
        )))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["total"], 0);

    // Missing type → 400.
    let resp = app
        .oneshot(get(format!("/api/v1/cases/{}/records", case_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Task 7: one-click deep carve ─────────────────────────────────────────

#[tokio::test]
async fn test_deep_carve_enqueues_jobs() {
    let (app, db, _state, case_id) = setup().await;
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "disk.raw" }),
    );
    let part = Artifact::new(
        case_id,
        ArtifactType::Partition,
        None,
        json!({
            "name": "p0", "offset_bytes": PART_OFFSET, "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(root.id);
    let fs = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        None,
        json!({
            "filesystem_type": "NTFS", "offset_bytes": PART_OFFSET, "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(part.id);
    let unalloc = Artifact::new(
        case_id,
        ArtifactType::UnallocatedSpace,
        None,
        json!({
            "name": "unallocated", "offset_bytes": 0, "size_bytes": PART_OFFSET,
        }),
    )
    .with_parent(root.id);
    for a in [&root, &part, &fs, &unalloc] {
        db.record_artifact(a).await.unwrap();
    }

    let resp = app
        .clone()
        .oneshot(post_json(
            format!("/api/v1/cases/{}/sources/{}/carve", case_id, root.id),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["targets"], 2, "FileSystem + UnallocatedSpace");
    assert_eq!(body["job_ids"].as_array().unwrap().len(), 2);

    // Jobs were persisted.
    let resp = app
        .oneshot(get(format!("/api/v1/cases/{}/jobs", case_id)))
        .await
        .unwrap();
    let body = body_json(resp).await;
    // The job list is an envelope, not a bare array (B8-030): an examiner reads
    // it to answer "was this analysis ever run", and a list that stopped at its
    // ceiling without saying so invites the answer "no".
    let jobs = body["items"].as_array().expect("jobs travel under `items`");
    assert_eq!(jobs.len(), 2);
    assert!(jobs
        .iter()
        .all(|j| j["module_id"] == "plugin.recovery.file_carver"));
    assert_eq!(body["truncated"], json!(false));
    assert_eq!(body["has_more"], json!(false));
    assert_eq!(body["count_is_lower_bound"], json!(false));
    // A job row whose status string this build cannot read is counted here
    // instead of being reported as Failed, so a real zero is the claim that no
    // job was mislabelled -- `null` would be "not determined".
    assert_eq!(body["undecodable"], json!(0));
}

// ── Task 6: source size recorded at ingest ───────────────────────────────

#[tokio::test]
async fn test_ingest_records_source_size() {
    let (app, db, _state, case_id) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("evidence.bin");
    let payload = vec![7u8; 4096];
    std::fs::write(&file_path, &payload).unwrap();

    let resp = app
        .oneshot(post_json(
            format!("/api/v1/cases/{}/ingest", case_id),
            json!({ "path": file_path.to_str().unwrap(), "artifact_type": "RawEvidence" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let artifact_id: Uuid = Uuid::parse_str(body["artifact_id"].as_str().unwrap()).unwrap();

    // Background persistence: poll until the root artifact lands.
    let mut size = None;
    for _ in 0..80 {
        if let Ok(a) = db.get_artifact_details(case_id, artifact_id).await {
            if let Some(s) = a.metadata.get("size").and_then(|v| v.as_u64()) {
                size = Some(s);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        size,
        Some(4096),
        "root artifact metadata.size must equal the source byte length"
    );
}

// ── Task 8: gather_report_data ───────────────────────────────────────────

#[tokio::test]
async fn test_gather_report_data_assembles_case() {
    let (_app, db, state, case_id) = setup().await;

    // Evidence source with acquisition hashes + size.
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "disk.raw",
            "size": 123456,
            "acquisition_md5": "aa11",
            "acquisition_sha1": "bb22",
            "acquisition_sha256": "cc33",
            // Production shape: seance_core::ingestion writes this as a JSON
            // NUMBER (Unix seconds), not an RFC 3339 string. A fixture using a
            // string hid a report that always rendered "Acquired" blank.
            "acquisition_hashed_at": 1_783_987_200i64,
        }),
    );
    db.record_artifact(&root).await.unwrap();

    // A notable hash hit.
    let file_md5 = "deadbeefdeadbeefdeadbeefdeadbeef";
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "bad.exe", "path": "/bad.exe", "md5": file_md5,
            "offset_bytes": 512000,
        }),
    )
    .with_parent(root.id);
    db.record_artifact(&file).await.unwrap();
    let notable = db
        .create_hash_set(case_id, "malware", None, "notable", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(notable, &[(file_md5.to_string(), None)])
        .await
        .unwrap();

    // A bookmark.
    db.create_artifact_bookmark(
        case_id,
        file.id,
        None,
        Some("suspicious"),
        Some("Examiner Jo"),
    )
    .await
    .unwrap();

    // A tagged timeline event.
    let event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_000i64,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": "A tagged event",
            "type": "test",
        }),
    );
    db.record_artifact(&event).await.unwrap();
    db.create_timeline_tag(case_id, event.id, Some("Examiner Jo"), Some("look here"))
        .await
        .unwrap();

    // An audit event.
    db.record_audit_event(
        Some(case_id),
        "Examiner Jo",
        "case_created",
        Some("case"),
        Some(case_id),
        None,
    )
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();

    assert_eq!(data.case_name, "Cap Test Case");
    assert_eq!(data.examiner, "Test Examiner");
    assert_eq!(data.tool_name, "Seance");
    assert!(!data.tool_version.is_empty());

    assert_eq!(data.evidence_sources.len(), 1);
    let src = &data.evidence_sources[0];
    assert_eq!(src.name, "disk.raw");
    assert_eq!(src.source_type, "RawEvidence");
    assert_eq!(src.size_bytes, Some(123456));
    assert_eq!(src.md5.as_deref(), Some("aa11"));
    assert_eq!(src.sha256.as_deref(), Some("cc33"));
    assert_eq!(
        src.acquired_at.as_deref(),
        Some("2026-07-14T00:00:00+00:00"),
        "a numeric acquisition_hashed_at must render as an RFC 3339 instant, not blank"
    );

    assert!(data.total_artifacts >= 3);
    assert!(data
        .artifact_counts
        .iter()
        .any(|(t, c)| t == "FileEntry" && *c >= 1));

    assert_eq!(data.bookmarks.len(), 1);
    assert_eq!(data.bookmarks[0].artifact_name, "bad.exe");
    assert_eq!(data.bookmarks[0].note.as_deref(), Some("suspicious"));
    // D7: the finding carries source-location provenance for re-verification.
    assert_eq!(data.bookmarks[0].source_path.as_deref(), Some("/bad.exe"));
    assert_eq!(
        data.bookmarks[0].source_offset,
        Some(512000),
        "finding must carry its byte offset within the evidence"
    );

    assert_eq!(data.timeline_highlights.len(), 1);
    assert_eq!(data.timeline_highlights[0].description, "A tagged event");
    assert_eq!(data.timeline_highlights[0].source_module, "test.module");

    assert!(data
        .audit_entries
        .iter()
        .any(|e| e.action == "case_created" && e.user == "Examiner Jo"));
    assert!(data.audit_chain_valid);
    assert!(data.audit_chain_checked >= 1);

    assert_eq!(data.notable_hash_hits.len(), 1);
    let hit = &data.notable_hash_hits[0];
    assert_eq!(hit.artifact_name, "bad.exe");
    assert_eq!(hit.hash_set_name, "malware");
    assert_eq!(hit.algorithm, "md5");
    assert_eq!(hit.matched_hash.to_lowercase(), file_md5);

    // New comprehensive sections.
    let summary = data
        .executive_summary
        .as_ref()
        .expect("executive summary present");
    assert!(summary.contains("Cap Test Case"), "summary names the case");
    assert!(summary.contains("NOTABLE"), "summary flags the notable hit");
    // Full timeline includes the (only) timeline event; category sections derive
    // from it grouped by source module.
    assert!(!data.full_timeline.is_empty(), "full timeline populated");
    assert!(
        data.category_sections.iter().any(|s| s.total >= 1),
        "per-category detail section derived from the timeline"
    );
    // No known-good set was created, so that direction is empty (not populated
    // from the notable set).
    assert!(data.known_good_hash_hits.is_empty());
}

#[tokio::test]
async fn test_export_html_and_pdf_routes() {
    let (app, db, _state, case_id) = setup().await;
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "disk.raw", "size": 999, "acquisition_md5": "aa", "acquisition_hashed_at": 1_783_987_200i64,
        }),
    );
    db.record_artifact(&root).await.unwrap();

    let resp = app
        .clone()
        .oneshot(get(format!("/api/v1/cases/{}/export/html", case_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let html = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(html.contains("Cap Test Case"));

    let resp = app
        .oneshot(get(format!("/api/v1/cases/{}/export/pdf", case_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pdf")
    );
    let pdf = body_bytes(resp).await;
    assert!(pdf.starts_with(b"%PDF"), "response body must be a PDF");
}

// ── B3-061 / B3-002 / B3-003: report honesty ─────────────────────────────

/// Ingest records every acquisition hash with `status = "baseline"` and null
/// expected hashes: it is a hash recorded at acquisition, not a comparison.
/// The report used to count only "verified"/"match"/"ok"/"passed" as a pass, so
/// a completely normal case exported a court report headed
/// "HASH MISMATCH - Evidence may have been altered."
#[tokio::test]
async fn acquisition_baseline_is_not_reported_as_an_integrity_failure() {
    let (_app, db, state, case_id) = setup().await;

    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "disk.raw", "size": 4096 }),
    );
    db.record_artifact(&root).await.unwrap();
    // Exactly what IngestionService::persist_and_queue writes.
    db.record_integrity_check(
        case_id,
        root.id,
        Some("md5val"),
        Some("sha1val"),
        Some("sha256val"),
        None,
        None,
        None,
        "baseline",
        Some("Acquisition hash baseline recorded at ingest"),
    )
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert_eq!(data.integrity_checks.len(), 1);
    assert_eq!(
        data.integrity_checks[0].outcome,
        seance_reporting::IntegrityOutcome::Baseline,
        "an ingest baseline row must be classified as a baseline"
    );

    let html = seance_reporting::render_html(&data);
    assert!(
        !html.contains("HASH MISMATCH"),
        "a routine acquisition baseline must not allege evidence tampering"
    );
    assert!(
        html.contains("BASELINE"),
        "the report must name the row a baseline"
    );
    let summary = data.executive_summary.as_deref().unwrap_or_default();
    assert!(
        !summary.contains("HASH MISMATCH"),
        "executive summary must not allege a mismatch either"
    );
}

/// A real mismatch must still be reported as one.
#[tokio::test]
async fn recorded_hash_mismatch_is_still_reported_as_a_failure() {
    let (_app, db, state, case_id) = setup().await;

    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "disk.raw" }),
    );
    db.record_artifact(&root).await.unwrap();
    db.record_integrity_check(
        case_id,
        root.id,
        Some("computed"),
        None,
        None,
        Some("expected"),
        None,
        None,
        "mismatch",
        Some("recomputed md5 does not match acquisition"),
    )
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert_eq!(
        data.integrity_checks[0].outcome,
        seance_reporting::IntegrityOutcome::Failed
    );
    assert!(seance_reporting::render_html(&data).contains("HASH MISMATCH"));
}

/// The hash-hit listing is one page per set. The report must carry the true
/// case-wide total, not the page length, or a case with more matches than the
/// page holds is formally described as having only those.
#[tokio::test]
async fn report_hash_hit_total_is_case_wide_not_the_page_length() {
    let (_app, db, state, case_id) = setup().await;

    let set = db
        .create_hash_set(case_id, "malware", None, "notable", "md5")
        .await
        .unwrap();

    // More matching files than the single 500-row page the report loads, so a
    // total taken from the page length is provably wrong.
    const HITS: usize = 520;
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    for i in 0..HITS {
        let md5 = format!("{:032x}", i + 1);
        let f = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": format!("bad{i}.exe"), "path": format!("/bad{i}.exe"), "md5": md5.clone() }),
        );
        db.record_artifact(&f).await.unwrap();
        entries.push((md5, None));
    }
    db.import_hash_set_entries(set, &entries).await.unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert_eq!(
        data.notable_hash_total, HITS as i64,
        "report must carry the case-wide notable total"
    );
    assert_eq!(
        data.notable_hash_hits.len(),
        500,
        "the listing itself is still one 500-row page"
    );
    let summary = data.executive_summary.as_deref().unwrap_or_default();
    assert!(
        summary.contains(&format!("{} NOTABLE (known-bad) hash set match(es)", HITS)),
        "executive summary narrates the case-wide total: {summary}"
    );
    assert!(
        !summary.contains("No files matched a notable"),
        "a case with notable hits must never be summarised as having none"
    );
}

/// The timeline listing is capped; the report must state the case-wide count.
#[tokio::test]
async fn report_timeline_total_is_case_wide_not_the_listing_cap() {
    let (_app, db, state, case_id) = setup().await;

    for i in 0..5 {
        let ev = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000i64 + i,
                "timestamp_desc": "Created",
                "source_module": "test.module",
                "short_desc": format!("event {i}"),
                "type": "test",
            }),
        );
        db.record_artifact(&ev).await.unwrap();
    }

    let data = gather_report_data(&state, case_id).await.unwrap();
    assert_eq!(
        data.full_timeline_total, 5,
        "case-wide timeline count must be carried into the report"
    );
    assert!(data
        .executive_summary
        .as_deref()
        .unwrap_or_default()
        .contains("The timeline contains 5 event(s)"));
}

/// B3-063: the File Overview section is populated, and every figure in it is a
/// real count of the case.
///
/// `carved_files` and `encrypted_files` used to render as "not determined" on
/// every case, on the stated grounds that no query could answer them. Both are
/// now counted, so this test holds them to the answer rather than to the
/// excuse: a carved file is exactly the kind of recovery a court is told about,
/// and printing "not determined" for a case that carved 4,000 files is as wrong
/// as printing 0.
///
/// The encrypted count in particular has to reconcile two independent
/// conventions -- `encrypted` stamped on the file by a filesystem reader, and
/// `is_encrypted` on a separate encryption_detection record ABOUT a file -- so
/// the fixture below contains one file marked both ways (it must count once)
/// and one file established by content analysis alone (it must count at all).
#[tokio::test]
async fn report_file_overview_is_populated_and_counts_carved_and_encrypted() {
    let (_app, db, state, case_id) = setup().await;

    for (name, deleted, dir) in [
        ("a.txt", false, false),
        ("b.txt", true, false),
        ("docs", false, true),
    ] {
        let f = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": name,
                "path": format!("/{name}"),
                // Generated column 0018 reads $.deleted / $.is_directory.
                "deleted": deleted,
                "is_directory": dir,
            }),
        );
        db.record_artifact(&f).await.unwrap();
    }

    // A carved file, exactly as seance_plugin_carver writes one: a FileEntry
    // carrying the JSON boolean `carved: true`.
    let carved = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "carved_00001000.jpg", "path": "/carved_00001000.jpg", "carved": true }),
    );
    db.record_artifact(&carved).await.unwrap();

    // A file a filesystem reader stamped as encrypted...
    let vault = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "vault.dmg", "path": "/vault.dmg", "encrypted": true }),
    );
    db.record_artifact(&vault).await.unwrap();
    // ...and that file analysis then ALSO fingerprinted. One encrypted file,
    // not two: counting the detection record separately inflates the figure by
    // one per detection on an already-marked file.
    db.record_artifact(
        &Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "analysis_type": "encryption_detection", "is_encrypted": true }),
        )
        .with_parent(vault.id),
    )
    .await
    .unwrap();

    // A file with no filesystem flag anywhere, established as encrypted by
    // content analysis alone. Counting only `encrypted` would omit it -- and
    // with it the whole of a raw-image case, where no filesystem reader ever
    // sets the flag.
    let secret = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "secret.zip", "path": "/secret.zip" }),
    );
    db.record_artifact(&secret).await.unwrap();
    db.record_artifact(
        &Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "analysis_type": "encryption_detection", "is_encrypted": true }),
        )
        .with_parent(secret.id),
    )
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let ov = data.file_overview.as_ref().expect("file overview loaded");
    // The two encryption_detection records are ParsedRecords, not file entries.
    assert_eq!(ov.total_files, 6);
    assert_eq!(ov.directories, 1);
    assert_eq!(ov.deleted_files, 1);
    assert_eq!(
        ov.carved_files,
        Some(1),
        "carved files are counted, not reported as undetermined"
    );
    assert_eq!(
        ov.encrypted_files,
        Some(2),
        "vault.dmg counts once despite two markers; secret.zip counts on its \
         detection record alone"
    );
}

/// The companion to the count above: a case with no carved and no encrypted
/// files reports a determined ZERO, not "not determined". The two readings mean
/// different things to an examiner -- "we looked and there were none" versus
/// "nobody looked" -- so a query that stopped answering must not be able to
/// hide behind the empty case.
#[tokio::test]
async fn report_file_overview_reports_a_determined_zero_on_a_clean_case() {
    let (_app, db, state, case_id) = setup().await;

    db.record_artifact(&Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "plain.txt", "path": "/plain.txt" }),
    ))
    .await
    .unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();
    let ov = data.file_overview.as_ref().expect("file overview loaded");
    assert_eq!(ov.total_files, 1);
    assert_eq!(ov.carved_files, Some(0), "a real zero, not None");
    assert_eq!(ov.encrypted_files, Some(0), "a real zero, not None");
}

/// The per-category detail sections are grouped out of `full_timeline`, which is
/// itself only the earliest TIMELINE_REPORT_CAP events of the case. Counting the
/// group sizes inside that excerpt makes `CategorySection::total` — the figure
/// the renderer prints as "Showing N of M records." — a count of the excerpt
/// rather than of the case, and drops every module whose events all fall beyond
/// the cap out of the report with no trace.
///
/// What an examiner learns here: how many events each source module actually
/// produced. A wrong answer looks like "Program Execution: 5000 records" for a
/// module that produced 90,000, or a whole category that is simply not in the
/// report.
#[tokio::test]
async fn category_section_totals_are_case_wide_and_no_module_is_dropped() {
    let (_app, db, state, case_id) = setup().await;

    // 5100 "alpha" events, all earlier than every "omega" event, so the 5000-row
    // timeline slice the report lists is entirely alpha and omega never appears
    // in it.
    let mut events = Vec::new();
    for i in 0..5100i64 {
        events.push(Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000i64 + i,
                "timestamp_desc": "Created",
                "source_module": "alpha",
                "short_desc": format!("alpha {i}"),
                "type": "test",
            }),
        ));
    }
    for i in 0..10i64 {
        events.push(Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_900_000_000i64 + i,
                "timestamp_desc": "Created",
                "source_module": "omega",
                "short_desc": format!("omega {i}"),
                "type": "test",
            }),
        ));
    }
    db.record_artifacts_batch(&events).await.unwrap();

    let data = gather_report_data(&state, case_id).await.unwrap();

    let alpha = data
        .category_sections
        .iter()
        .find(|s| s.title == "Alpha")
        .expect("the alpha category must be present");
    assert_eq!(
        alpha.total, 5100,
        "the category total must be the case-wide count for that module, \
         not the number of its events that fell inside the listed slice"
    );
    assert_eq!(
        alpha.rows.len(),
        500,
        "the listing itself stays capped at CATEGORY_ROW_CAP"
    );

    let omega = data
        .category_sections
        .iter()
        .find(|s| s.title == "Omega")
        .expect("a module with no event inside the listed slice must still get a section");
    assert_eq!(omega.total, 10);
    assert!(
        omega.rows.is_empty(),
        "no omega event falls inside the listed slice, so it lists none - but says how many exist"
    );

    // The rendered report must state both figures rather than presenting the
    // excerpt count as the category size.
    let html = seance_reporting::render_html(&data);
    assert!(
        html.contains("Showing 500 of 5100 records."),
        "the HTML must disclose the true per-category total"
    );
    assert!(
        html.contains("Showing 0 of 10 records."),
        "a category listed with no rows must still state its case-wide total"
    );
}

// ── System Info: source scoping ──────────────────────────────────────────

#[tokio::test]
async fn test_system_info_scopes_to_source() {
    // A case can hold more than one machine's registry. System Info already
    // refuses to blend conflicting identities, but until now it could not be
    // read one machine at a time. `?source_id=` scopes it to a single
    // acquisition, reusing the same subtree scoping the record listing uses.
    let (app, db, _state, case_id) = setup().await;

    let mk_source = |name: &str| {
        Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({ "name": name }),
        )
    };
    let source_a = mk_source("machine-a.E01");
    let source_b = mk_source("machine-b.E01");
    db.record_artifact(&source_a).await.unwrap();
    db.record_artifact(&source_b).await.unwrap();

    let usb = |parent: Uuid, serial: &str| {
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "UsbDevice", "serial": serial }),
        )
        .with_parent(parent)
    };
    db.record_artifact(&usb(source_a.id, "AAA-0001"))
        .await
        .unwrap();
    db.record_artifact(&usb(source_b.id, "BBB-0002"))
        .await
        .unwrap();

    let serials = |suffix: String| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(get(format!(
                    "/api/v1/cases/{}/system_info{}",
                    case_id, suffix
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            body["usb_devices"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|d| d["serial"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        }
    };

    // Case-wide: both machines' USB history.
    let mut all = serials(String::new()).await;
    all.sort();
    assert_eq!(all, vec!["AAA-0001", "BBB-0002"]);

    // Scoped: only the chosen machine's, never the other's.
    assert_eq!(
        serials(format!("?source_id={}", source_a.id)).await,
        vec!["AAA-0001"]
    );
    assert_eq!(
        serials(format!("?source_id={}", source_b.id)).await,
        vec!["BBB-0002"]
    );

    // Unrelated source → nothing.
    assert!(serials(format!("?source_id={}", Uuid::new_v4()))
        .await
        .is_empty());
}
