//! Shared harness for the volume unlock-to-read tests (HUNT-254).
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::db::DatabaseConnection;
use seance_core::module::ForensicsModule;
use seance_core::orchestrator::Orchestrator;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "volume-unlock-test-secret";
const CSRF: &str = "volume-unlock-csrf";
pub const RIGHT: &str = "bde-TEST";
pub const WRONG: &str = "wrong-bde-guess-7731";

// ── captured logs ────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct Captured(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn logs() -> &'static Captured {
    static LOGS: OnceLock<Captured> = OnceLock::new();
    LOGS.get_or_init(|| {
        let captured = Captured::default();
        let writer = captured.clone();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .try_init();
        captured
    })
}

// ── harness ──────────────────────────────────────────────────────────────

pub fn bdetogo() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("test_data/bdetogo.raw");
    p.exists().then_some(p)
}

pub struct Harness {
    pub app: axum::Router,
    pub db: Arc<SqliteConnection>,
    pub db_path: std::path::PathBuf,
    pub _dir: tempfile::TempDir,
    pub case_id: Uuid,
    pub token: String,
    pub runner: tokio::task::JoinHandle<()>,
}

pub async fn harness(grant: &str) -> Harness {
    logs();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("case.db");
    let db = Arc::new(
        SqliteConnection::new(&format!("sqlite:{}?mode=rwc", db_path.display()))
            .await
            .unwrap(),
    );
    db.initialize().await.unwrap();
    let case_id = db
        .create_case_with_metadata(Some("VolumeUnlock".into()), None, Some("Ex".into()))
        .await
        .unwrap();
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    db.grant_case_access(case_id, uid, grant, None)
        .await
        .unwrap();

    let mut orchestrator = Orchestrator::new(Some(db.clone() as Arc<dyn DatabaseConnection>), 64);
    orchestrator.register_module(Arc::new(seance_plugin_bitlocker::BitlockerDecryptor::new()));
    let ad_hoc_sender = orchestrator.ad_hoc_submitter();
    let task_submitter = orchestrator.task_submitter();
    let active_tasks = orchestrator.active_tasks();
    let cancellation = orchestrator.cancellation_handle();
    let runner = tokio::spawn(async move { orchestrator.run().await });

    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let state = AppState {
        db: db.clone(),
        orchestrator_sender: task_submitter,
        ad_hoc_sender,
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
        cancellation,
    };
    let cfg = AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled: true,
    };
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();
    let app = router_with_auth(state, Some(cfg));
    Harness {
        app,
        db,
        db_path,
        _dir: dir,
        case_id,
        token,
        runner,
    }
}

/// The volume, recorded as ingest records it, and the decryptor's own
/// "detected, not unlocked" record beneath it.
pub async fn seed_locked_volume(h: &Harness, image: &std::path::Path) -> (Uuid, Uuid) {
    let volume = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "bdetogo.raw", "source_path": image.to_string_lossy() }),
    );
    h.db.record_artifact(&volume).await.unwrap();
    let mut with_bytes = volume.clone();
    with_bytes.data =
        Some(Arc::new(FileDataSource::new(image.to_path_buf()).unwrap()) as Arc<dyn DataSource>);
    let locked = seance_plugin_bitlocker::BitlockerDecryptor::new()
        .process(&with_bytes)
        .unwrap()
        .remove(0);
    assert_eq!(locked.metadata["status"], "NotUnlocked");
    h.db.record_artifact(&locked).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    (volume.id, locked.id)
}

pub async fn call(
    h: &Harness,
    method: &str,
    uri: String,
    body: Option<Value>,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", h.token))
        .header("x-csrf-token", CSRF)
        .header("cookie", format!("seance_csrf={CSRF}"));
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = h.app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

pub async fn post_json(h: &Harness, uri: String, body: Value) -> (StatusCode, String) {
    call(h, "POST", uri, Some(body)).await
}

pub fn unlock_uri(h: &Harness, artifact: Uuid) -> String {
    format!("/api/v1/cases/{}/artifacts/{artifact}/unlock", h.case_id)
}

pub fn content_uri(h: &Harness, artifact: Uuid) -> String {
    format!("/api/v1/cases/{}/artifacts/{artifact}/content", h.case_id)
}

pub async fn wait_for_job(h: &Harness, job_id: &str) -> Value {
    for _ in 0..600 {
        let (status, body) = call(
            h,
            "GET",
            format!("/api/v1/cases/{}/jobs/{job_id}", h.case_id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        let s = v["status"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if s == "complete" || s == "failed" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job {job_id} never finished");
}

pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Decrypt the volume through the credential route (one run), then record a
/// 512-byte window at the start of the decrypted volume beneath it — the
/// shape a partition or file record under a decrypted volume has. Returns
/// `(locked volume, decrypted volume, window)`.
pub async fn decrypt_once(h: &Harness, image: &std::path::Path) -> (Uuid, Uuid, Uuid) {
    let (volume, _locked_record) = seed_locked_volume(h, image).await;
    let (status, body) = post_json(
        h,
        format!("/api/v1/cases/{}/artifacts/{volume}/credential", h.case_id),
        json!({ "kind": "bitlocker_password", "secret": RIGHT }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let job = wait_for_job(h, v["job_id"].as_str().unwrap()).await;
    assert_eq!(
        job["status"].as_str().unwrap().to_lowercase(),
        "complete",
        "{job}"
    );
    let decrypted =
        h.db.get_child_artifacts(h.case_id, Some(volume), Some(100), 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|c| c.metadata.get("bitlocker_decrypted") == Some(&json!(true)))
            .expect("the decrypted volume is recorded beneath the locked one");
    let window = Artifact::new(
        h.case_id,
        ArtifactType::Partition,
        None,
        json!({"name": "boot record", "offset_bytes": 0, "size_bytes": 512}),
    )
    .with_parent(decrypted.id);
    h.db.record_artifact(&window).await.unwrap();
    (volume, decrypted.id, window.id)
}
