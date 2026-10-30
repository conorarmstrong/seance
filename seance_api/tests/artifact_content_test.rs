//! Integration tests for derived-artifact content resolution:
//! hex view, content streaming (with Range support), and thumbnails.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::Orchestrator,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const IMAGE_SIZE: usize = 128 * 1024;
const PART_OFFSET: u64 = 4096;
const PART_SIZE: u64 = 8192;

async fn setup_test_app() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("content-test", "tester").await.unwrap();

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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

/// Deterministic disk image bytes.
fn image_bytes() -> Vec<u8> {
    (0..IMAGE_SIZE).map(|i| (i % 251) as u8).collect()
}

/// Write the disk image into `dir` and return its path plus the bytes.
fn write_image(dir: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
    let data = image_bytes();
    let path = dir.join("disk.raw");
    std::fs::write(&path, &data).unwrap();
    (path, data)
}

/// Record root (source_path) -> Partition -> FileSystem artifacts.
/// Returns (root_id, partition_id, filesystem_id).
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
            "name": "partition0",
            "offset_bytes": PART_OFFSET,
            "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(root.id);
    let fs = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        None,
        json!({
            "filesystem_type": "NTFS",
            "subtype": "ntfs",
            // Copied from the partition, same coordinate space (contract of
            // plugin.disk.filesystem_detector)
            "offset_bytes": PART_OFFSET,
            "size_bytes": PART_SIZE,
        }),
    )
    .with_parent(part.id);

    db.record_artifact(&root).await.unwrap();
    db.record_artifact(&part).await.unwrap();
    db.record_artifact(&fs).await.unwrap();
    (root.id, part.id, fs.id)
}

/// Expected content of the data_runs test file:
/// 16 bytes at fs-relative 512, an 8-byte sparse hole, 8 bytes at 1024.
fn expected_run_file(image: &[u8]) -> Vec<u8> {
    let base = PART_OFFSET as usize;
    let mut expected = Vec::new();
    expected.extend_from_slice(&image[base + 512..base + 512 + 16]);
    expected.extend_from_slice(&[0u8; 8]);
    expected.extend_from_slice(&image[base + 1024..base + 1024 + 8]);
    expected
}

async fn record_run_file(db: &SqliteConnection, case_id: Uuid, fs_id: Uuid) -> Uuid {
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "test.bin",
            "size": 32,
            "data_runs": [[512, 16], [null, 8], [1024, 8]],
            "data_runs_complete": true,
        }),
    )
    .with_parent(fs_id);
    db.record_artifact(&file).await.unwrap();
    file.id
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect()
}

fn get(uri: String) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn test_hex_for_file_entry_with_data_runs() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_id = record_run_file(&db, case_id, fs_id).await;

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex?offset=0&limit=64",
            case_id, file_id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["total_size"].as_u64(), Some(32));
    assert_eq!(body["offset"].as_u64(), Some(0));
    assert_eq!(body["limit"].as_u64(), Some(32));

    let bytes = hex_to_bytes(body["hex"].as_str().unwrap());
    let expected = expected_run_file(&image);
    assert_eq!(bytes, expected, "hex bytes must match runs + sparse zeros");
    // The middle 8 bytes are a sparse hole and must be zeros
    assert!(bytes[16..24].iter().all(|&b| b == 0));
}

#[tokio::test]
async fn test_content_for_file_entry_with_data_runs() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_id = record_run_file(&db, case_id, fs_id).await;

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, file_id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("32")
    );
    assert_eq!(
        response
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );

    let body = body_bytes(response).await;
    assert_eq!(body, expected_run_file(&image));
}

#[tokio::test]
async fn test_content_for_resident_file() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    let content = b"hello resident data";
    use base64::Engine;
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "resident.txt",
            "size": content.len(),
            "resident_data_b64": base64::engine::general_purpose::STANDARD.encode(content),
        }),
    )
    .with_parent(fs_id);
    db.record_artifact(&file).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, file.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, content);
}

#[tokio::test]
async fn test_hex_for_partition_artifact() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, part_id, _) = record_disk_chain(&db, case_id, &image_path).await;

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex?offset=0&limit=16",
            case_id, part_id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["total_size"].as_u64(), Some(PART_SIZE));
    let bytes = hex_to_bytes(body["hex"].as_str().unwrap());
    let base = PART_OFFSET as usize;
    assert_eq!(
        bytes,
        &image[base..base + 16],
        "partition hex must start at its window"
    );
}

#[tokio::test]
async fn test_content_for_carved_artifact() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, part_id, _) = record_disk_chain(&db, case_id, &image_path).await;

    let carved = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "carved_00000064.jpg",
            "carved": true,
            "carving_offset": 100,
            "carving_size": 32,
            "size": 32,
        }),
    )
    .with_parent(part_id);
    db.record_artifact(&carved).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, carved.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let base = PART_OFFSET as usize + 100;
    assert_eq!(body_bytes(response).await, &image[base..base + 32]);
}

/// A carve rebuilt without the ext2 pointer blocks in line with it (DFTT #12)
/// records `data_runs` in its `carving_offset` coordinates. The resolver
/// serves that run list, not the contiguous window, so what is downloaded is
/// what the carver hashed.
#[tokio::test]
async fn test_content_for_carved_artifact_rebuilt_as_runs() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, part_id, _) = record_disk_chain(&db, case_id, &image_path).await;

    let carved = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "carved_00000064.bmp",
            "carved": true,
            "carving_offset": 100,
            "carving_size": 32,
            "size": 32,
            "data_runs": [[100, 20], [200, 12]],
            "data_runs_complete": true,
            "carving_reconstruction": "ext2_indirect",
        }),
    )
    .with_parent(part_id);
    db.record_artifact(&carved).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, carved.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let base = PART_OFFSET as usize;
    let mut expected = image[base + 100..base + 120].to_vec();
    expected.extend_from_slice(&image[base + 200..base + 212]);
    assert_eq!(body_bytes(response).await, expected);
}

#[tokio::test]
async fn test_hex_limit_is_clamped() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (root_id, _, _) = record_disk_chain(&db, case_id, &image_path).await;

    // 128 KiB source; ask for far more than the 64 KiB cap
    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex?offset=0&limit=999999999",
            case_id, root_id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["total_size"].as_u64(), Some(IMAGE_SIZE as u64));
    assert_eq!(
        body["limit"].as_u64(),
        Some(64 * 1024),
        "limit must be clamped to 64 KiB"
    );
}

#[tokio::test]
async fn test_content_range_request() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, image) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_id = record_run_file(&db, case_id, fs_id).await;

    let request = Request::builder()
        .uri(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, file_id
        ))
        .header("range", "bytes=2-5")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes 2-5/32")
    );
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("4")
    );
    let expected = expected_run_file(&image);
    assert_eq!(body_bytes(response).await, &expected[2..6]);

    // Unsatisfiable range → 416
    let request = Request::builder()
        .uri(format!(
            "/api/v1/cases/{}/artifacts/{}/content",
            case_id, file_id
        ))
        .header("range", "bytes=500-600")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes */32")
    );
}

#[tokio::test]
async fn test_thumbnail_for_png_artifact() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();

    // Generate a 120x80 PNG on disk
    let png_path = dir.path().join("photo.png");
    let img = image::RgbImage::from_fn(120, 80, |x, _| image::Rgb([(x % 256) as u8, 64, 200]));
    image::DynamicImage::ImageRgb8(img).save(&png_path).unwrap();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "photo.png",
            "source_path": png_path.to_str().unwrap(),
        }),
    );
    db.record_artifact(&artifact).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/thumbnail?size=64",
            case_id, artifact.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("image/png")
    );

    let body = body_bytes(response).await;
    let thumb = image::load_from_memory(&body).unwrap();
    assert!(thumb.width() <= 64 && thumb.height() <= 64);
    // Aspect preserved: 120x80 scaled into 64 → 64x42 or 64x43
    assert_eq!(thumb.width(), 64);
    assert!(thumb.height() < 64);
}

#[tokio::test]
async fn test_thumbnail_for_non_image_is_404() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();

    let txt_path = dir.path().join("notes.txt");
    std::fs::write(&txt_path, b"just some text, definitely not an image").unwrap();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "notes.txt",
            "source_path": txt_path.to_str().unwrap(),
        }),
    );
    db.record_artifact(&artifact).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/thumbnail",
            case_id, artifact.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_derived_artifact_without_content_metadata_is_clear_error() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    // Old-style FileEntry with no data_runs / resident / carving metadata
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "legacy.bin", "size": 100 }),
    )
    .with_parent(fs_id);
    db.record_artifact(&file).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex",
            case_id, file.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("INVALID_REQUEST"));
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Re-ingest"),
        "error must tell the user how to fix it"
    );
}

#[tokio::test]
async fn test_unknown_api_route_returns_json_404() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(get("/api/v1/definitely/not/a/real/endpoint".to_string()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/json"),
        "unknown API paths must return JSON, not HTML"
    );
    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("RESOURCE_NOT_FOUND"));
}

/// B4-022: a hex page that could not read every byte it asked for looked
/// exactly like a page that ended at the end of the file — the response carried
/// the shortened length in `limit` while `total_size` still claimed the full
/// object. An examiner reading "the bytes stop here" was really being shown
/// "these bytes could not be read".
#[tokio::test]
async fn hex_page_short_of_the_declared_size_is_flagged_incomplete() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    // The FS window is PART_SIZE (8192) bytes. This run starts 192 bytes before
    // the end and claims 1024, so only 192 bytes are actually readable.
    let short = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "truncated.bin",
            "size": 1024,
            "data_runs": [[PART_SIZE - 192, 1024]],
        }),
    )
    .with_parent(fs_id);
    db.record_artifact(&short).await.unwrap();

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex?offset=0&limit=1024",
            case_id, short.id
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();

    assert_eq!(body["total_size"].as_u64(), Some(1024));
    assert_eq!(body["requested_bytes"].as_u64(), Some(1024));
    assert_eq!(body["limit"].as_u64(), Some(192), "only 192 bytes readable");
    assert_eq!(
        body["content_incomplete"].as_bool(),
        Some(true),
        "a short hex page must say it is short"
    );
    assert_eq!(
        body["content_incomplete_reason"].as_str(),
        Some("short_read")
    );
}

/// The flag must stay off for a page that was read in full, or it says nothing.
#[tokio::test]
async fn hex_page_read_in_full_is_not_flagged_incomplete() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let (image_path, _) = write_image(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;
    let file_id = record_run_file(&db, case_id, fs_id).await;

    let response = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/hex?offset=0&limit=64",
            case_id, file_id
        )))
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(body["limit"].as_u64(), Some(32));
    assert_eq!(body["requested_bytes"].as_u64(), Some(32));
    assert_eq!(body["content_incomplete"].as_bool(), Some(false));
    assert!(body["content_incomplete_reason"].is_null());
}

/// Write a disk image whose filesystem window opens with a small, valid PNG
/// followed by zero padding, and return its path.
#[cfg(feature = "video-thumbs")]
fn write_image_with_png(dir: &std::path::Path) -> std::path::PathBuf {
    let mut data = image_bytes();
    let img = image::RgbImage::from_fn(8, 8, |x, y| image::Rgb([(x * 8) as u8, (y * 8) as u8, 9]));
    let mut png = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    assert!(png.len() < PART_SIZE as usize);
    let base = PART_OFFSET as usize;
    // PNG first, then zeros to the end of the filesystem window.
    data[base..base + PART_SIZE as usize].fill(0);
    data[base..base + png.len()].copy_from_slice(&png);
    let path = dir.join("disk.raw");
    std::fs::write(&path, &data).unwrap();
    path
}

/// Record an oversized "video" plus the device-cached preview iOS keeps for it.
/// `thumb_declared` is the size recorded for the cached thumbnail; when it
/// exceeds what the filesystem window can supply, the preview is only partly
/// readable.
#[cfg(feature = "video-thumbs")]
async fn record_media_with_cached_thumb(
    db: &SqliteConnection,
    case_id: Uuid,
    fs_id: Uuid,
    stem: &str,
    thumb_declared: u64,
) -> Uuid {
    // Larger than THUMBNAIL_MAX_SOURCE_BYTES, so the request takes the
    // device-cache branch instead of decoding the file's own pixels.
    const OVERSIZE: u64 = 64 * 1024 * 1024 + 1;
    let media = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": format!("{stem}.MOV"),
            "relative_path": format!("Media/DCIM/{stem}.MOV"),
            "size": OVERSIZE,
            "data_runs": [[0, OVERSIZE]],
        }),
    )
    .with_parent(fs_id);
    let thumb = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "5005.JPG",
            "relative_path":
                format!("Media/PhotoData/Thumbnails/V2/DCIM/{stem}.MOV/5005.JPG"),
            "size": thumb_declared,
            "data_runs": [[0, thumb_declared]],
        }),
    )
    .with_parent(fs_id);
    db.record_artifact(&media).await.unwrap();
    db.record_artifact(&thumb).await.unwrap();
    media.id
}

/// B6-026: the device-cache preview path truncated a short read and rendered it
/// anyway, so a partially-readable JPEG was served as a clean preview. The
/// artifact's own-pixels path had refused exactly this since BUG-175.
///
/// Both halves of this test render byte-for-byte the same buffer; only the
/// declared size of the cached preview differs.
#[cfg(feature = "video-thumbs")]
#[tokio::test]
async fn cached_thumbnail_short_of_its_declared_size_is_refused() {
    let (app, db, case_id) = setup_test_app().await;
    let dir = tempfile::tempdir().unwrap();
    let image_path = write_image_with_png(dir.path());
    let (_, _, fs_id) = record_disk_chain(&db, case_id, &image_path).await;

    // Readable in full: PART_SIZE bytes are there, and PART_SIZE is claimed.
    let complete = record_media_with_cached_thumb(&db, case_id, fs_id, "IMG_0002", PART_SIZE).await;
    // Same bytes, but the record claims twice what the window can supply.
    let short =
        record_media_with_cached_thumb(&db, case_id, fs_id, "IMG_0001", PART_SIZE * 2).await;

    let ok = app
        .clone()
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/thumbnail?size=64",
            case_id, complete
        )))
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "a fully-readable cached preview must still be served"
    );
    assert_eq!(
        ok.headers()
            .get("x-thumbnail-source")
            .and_then(|v| v.to_str().ok()),
        Some("device-cache")
    );

    let refused = app
        .oneshot(get(format!(
            "/api/v1/cases/{}/artifacts/{}/thumbnail?size=64",
            case_id, short
        )))
        .await
        .unwrap();
    assert_ne!(
        refused.status(),
        StatusCode::OK,
        "a partially-readable cached preview must not be rendered as a clean image"
    );
}
