//! The harness shared by the unlock-to-read tests (`BUG-026`): a case with
//! an examiner (`read_write`), a reader (`read_only`) and an owner, a router,
//! and a synthetic encrypted backup ingested with its password.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::module::ForensicsModule;
use seance_core::orchestrator::Orchestrator;
use seance_db::SqliteConnection;
use seance_plugin_ios_backup::test_support::{build_encrypted_backup, KeyShape};
use seance_plugin_ios_backup::IosBackupParser;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
use tower::util::ServiceExt;
use uuid::Uuid;

pub const JWT_SECRET: &str = "ios-reread-route-test-secret";
pub const CSRF: &str = "ios-reread-route-csrf";
pub const WRONG: &str = "wrong-reread-guess-40517";
pub const SMS_PLAINTEXT: &[u8] = b"the plaintext an examiner unlocks to read again";

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

pub struct Harness {
    pub app: axum::Router,
    pub db: Arc<SqliteConnection>,
    pub db_path: std::path::PathBuf,
    pub _dir: tempfile::TempDir,
    pub case_id: Uuid,
    pub token: String,
    pub reader_token: String,
    /// `owner` on the case: may delete it.
    pub owner_token: String,
    pub runner: tokio::task::JoinHandle<()>,
}

pub async fn harness() -> Harness {
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
        .create_case_with_metadata(Some("iOS re-read".into()), None, Some("Ex".into()))
        .await
        .unwrap();
    let erin = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    db.grant_case_access(case_id, erin, "read_write", None)
        .await
        .unwrap();
    let rory = db
        .create_user(
            "rory",
            &seance_api::hash_password("readerpw12").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    db.grant_case_access(case_id, rory, "read_only", None)
        .await
        .unwrap();
    let olive = db
        .create_user(
            "olive",
            &seance_api::hash_password("ownerpw1234").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    db.grant_case_access(case_id, olive, "owner", None)
        .await
        .unwrap();

    let mut orchestrator = Orchestrator::new(Some(db.clone() as Arc<dyn DatabaseConnection>), 64);
    orchestrator.register_module(Arc::new(IosBackupParser::new()));
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
    let (reader_token, _) = cfg.generate_token("rory", "examiner").unwrap();
    let (owner_token, _) = cfg.generate_token("olive", "examiner").unwrap();
    let app = router_with_auth(state, Some(cfg));
    Harness {
        app,
        db,
        db_path,
        _dir: dir,
        case_id,
        token,
        reader_token,
        owner_token,
        runner,
    }
}

/// An encrypted backup ingested with its password, as the credential route
/// leaves it: the folder, and the decrypted files recorded beneath it. The
/// password is then gone. Returns (backup dir, password, folder id, file id).
pub async fn ingested_backup(h: &Harness) -> (std::path::PathBuf, String, Uuid, Uuid) {
    let (backup, password) = build_encrypted_backup(&[(
        "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "Library/SMS/sms.db",
        1,
        SMS_PLAINTEXT,
        KeyShape::ClassFieldAndKey,
    )]);
    let folder = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "00008030-00AA11BB22CC33DD",
            "path": backup.to_string_lossy(),
            "is_directory": true,
        }),
    );
    h.db.record_artifact(&folder).await.unwrap();
    let mut sms = None;
    for a in IosBackupParser::with_password(password.clone())
        .process(&folder)
        .unwrap()
    {
        if a.metadata.get("relative_path") == Some(&json!("Library/SMS/sms.db")) {
            sms = Some(a.id);
        }
        h.db.record_artifact(&a).await.unwrap();
    }
    (backup, password, folder.id, sms.expect("the sms.db record"))
}

pub async fn call_as(
    h: &Harness,
    token: &str,
    method: &str,
    uri: String,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
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
    (status, bytes.to_vec())
}

pub async fn call(
    h: &Harness,
    method: &str,
    uri: String,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    call_as(h, &h.token, method, uri, body).await
}

pub fn unlock_uri(h: &Harness, artifact: Uuid) -> String {
    format!("/api/v1/cases/{}/artifacts/{artifact}/unlock", h.case_id)
}

pub fn content_uri(h: &Harness, artifact: Uuid) -> String {
    format!("/api/v1/cases/{}/artifacts/{artifact}/content", h.case_id)
}

pub fn body_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(bytes)))
}

pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}
