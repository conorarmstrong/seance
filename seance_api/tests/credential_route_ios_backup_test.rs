//! `POST …/credential` with kind `ios_backup_password` (`SEC-204`), end to end.
//!
//! The iOS backup password used to travel in `run_module`'s `secrets` map: a
//! plain `String`, merged into the artifact's metadata, never zeroed, and with
//! no outcome in the audit log. It now travels the credential route. An iOS
//! backup is a **directory** artifact — it has no bytes — so the route must
//! run the parser on a directory target the way `run_module` does (`HUNT-087`)
//! rather than refusing it as "content unresolved".
//!
//! A real orchestrator runs the real iOS backup parser, built with **no**
//! process-level password, behind the real router with authentication on. The
//! backup is **synthetic** (`seance_plugin_ios_backup::test_support`): it pins
//! the channel — how the password travels, what is audited, where it must not
//! land — and is not validation of decryption against a real device's backup.
//!
//! What is asserted:
//!
//! - a wrong password fails the job, records nothing new and leaves the
//!   `encrypted_no_password` record standing; the right one extracts the files
//!   beneath the backup and supersedes that record;
//! - `credential_supplied` and `credential_outcome` rows name the user, the
//!   kind and both outcomes;
//! - neither password is in the database file, its WAL or shm, an audit row, a
//!   job row, an HTTP response, or anything logged at TRACE while it ran.

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
use std::time::Duration;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "credential-ios-route-test-secret";
const CSRF: &str = "credential-ios-route-csrf";
const WRONG: &str = "wrong-ios-guess-66173";
const SMS_PLAINTEXT: &[u8] = b"the only message in this synthetic backup";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> &'static Captured {
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

struct Harness {
    app: axum::Router,
    db: Arc<SqliteConnection>,
    db_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    case_id: Uuid,
    token: String,
    runner: tokio::task::JoinHandle<()>,
}

async fn harness() -> Harness {
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
        .create_case_with_metadata(Some("iOS credential".into()), None, Some("Ex".into()))
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
    db.grant_case_access(case_id, uid, "read_write", None)
        .await
        .unwrap();

    let mut orchestrator = Orchestrator::new(Some(db.clone() as Arc<dyn DatabaseConnection>), 64);
    // No process-level password: the credential is the only way in.
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

/// The backup folder, recorded as ingest records a directory, and the
/// parser's own "encrypted, not extracted" record beneath it.
async fn seed_locked_backup(h: &Harness, backup: &std::path::Path) -> (Uuid, Uuid) {
    let folder = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "00008030-001259123E50802E",
            "path": backup.to_string_lossy(),
            "is_directory": true,
        }),
    );
    h.db.record_artifact(&folder).await.unwrap();
    let locked = IosBackupParser::new().process(&folder).unwrap().remove(0);
    assert_eq!(locked.metadata["status"], "encrypted_no_password");
    h.db.record_artifact(&locked).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    (folder.id, locked.id)
}

async fn call(h: &Harness, method: &str, uri: String, body: Option<Value>) -> (StatusCode, String) {
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

async fn supply(h: &Harness, artifact: Uuid, secret: &str) -> (StatusCode, String) {
    call(
        h,
        "POST",
        format!(
            "/api/v1/cases/{}/artifacts/{artifact}/credential",
            h.case_id
        ),
        Some(json!({ "kind": "ios_backup_password", "secret": secret })),
    )
    .await
}

async fn wait_for_job(h: &Harness, job_id: &str) -> (Value, String) {
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
            return (v, body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job {job_id} never finished");
}

async fn superseded(h: &Harness, id: Uuid) -> bool {
    let a = h.db.get_artifact(id).await.unwrap().unwrap();
    a.metadata.get("superseded").and_then(|v| v.as_bool()) == Some(true)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ios_backup_password_through_the_credential_route_with_the_secret_nowhere() {
    let (backup, right) = build_encrypted_backup(&[(
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "Library/SMS/sms.db",
        1,
        SMS_PLAINTEXT,
        KeyShape::ClassFieldAndKey,
    )]);
    let h = harness().await;
    let (folder, locked) = seed_locked_backup(&h, &backup).await;
    let mut responses = String::new();

    // Wrong: accepted for processing, then the job fails and nothing changes.
    let (status, body) = supply(&h, folder, WRONG).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    responses.push_str(&body);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["module_id"], "plugin.mobile.ios_backup");
    let (job, raw) = wait_for_job(&h, v["job_id"].as_str().unwrap()).await;
    responses.push_str(&raw);
    assert_eq!(
        job["status"].as_str().unwrap().to_lowercase(),
        "failed",
        "{job}"
    );
    let msg = job["error_message"].as_str().unwrap();
    assert!(msg.contains("did not open"), "{msg}");
    assert!(
        !superseded(&h, locked).await,
        "a wrong password must not supersede"
    );
    assert_eq!(h.db.count_child_artifacts(folder).await.unwrap(), 1);

    // Right: the files appear beneath the backup, the locked record is superseded.
    let (status, body) = supply(&h, folder, &right).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    responses.push_str(&body);
    let v: Value = serde_json::from_str(&body).unwrap();
    let (job, raw) = wait_for_job(&h, v["job_id"].as_str().unwrap()).await;
    responses.push_str(&raw);
    assert_eq!(
        job["status"].as_str().unwrap().to_lowercase(),
        "complete",
        "{job}"
    );
    assert!(
        superseded(&h, locked).await,
        "the encrypted_no_password record must be superseded"
    );
    let children =
        h.db.get_child_artifacts(h.case_id, Some(folder), Some(100), 0)
            .await
            .unwrap()
            .items;
    assert!(
        children.iter().any(|c| {
            c.metadata["relative_path"] == json!("Library/SMS/sms.db")
                && c.metadata["decrypted"] == json!(true)
        }),
        "the decrypted file must appear beneath the backup: {children:#?}"
    );

    // The audit log: two supplies and two outcomes, by kind, attributed.
    let audit = h.db.get_audit_log(h.case_id, 200, 0).await.unwrap();
    let rows = |action: &str| -> Vec<&Value> {
        audit
            .iter()
            .filter(|e| e["action"] == json!(action))
            .collect()
    };
    assert_eq!(rows("credential_supplied").len(), 2, "{audit:#?}");
    let outcomes = rows("credential_outcome");
    assert_eq!(outcomes.len(), 2, "{audit:#?}");
    for row in rows("credential_supplied").iter().chain(outcomes.iter()) {
        assert_eq!(row["user_id"], json!("erin"));
        assert!(row["details"]
            .as_str()
            .unwrap()
            .contains("kind=ios_backup_password"));
    }
    let details: String = outcomes
        .iter()
        .map(|r| r["details"].as_str().unwrap().to_string())
        .collect();
    assert!(details.contains("outcome=rejected"), "{details}");
    assert!(details.contains("outcome=accepted"), "{details}");

    // The secret is nowhere.
    let audit_text = serde_json::to_string(&audit).unwrap();
    let jobs = h.db.list_jobs(h.case_id).await.unwrap();
    let jobs_text = format!("{jobs:?}");
    h.runner.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log_bytes = logs().0.lock().unwrap().clone();
    assert!(
        contains(&log_bytes, "credential"),
        "the log capture is live (it saw the credential lines)"
    );
    for secret in [right.as_str(), WRONG] {
        assert!(
            !audit_text.contains(secret),
            "{secret} reached the audit log"
        );
        assert!(!jobs_text.contains(secret), "{secret} reached a job row");
        assert!(
            !responses.contains(secret),
            "{secret} reached an HTTP response"
        );
        assert!(
            !contains(&log_bytes, secret),
            "{secret} reached the process log"
        );
        for suffix in ["", "-wal", "-shm"] {
            let path = format!("{}{}", h.db_path.display(), suffix);
            if let Ok(bytes) = std::fs::read(&path) {
                assert!(!contains(&bytes, secret), "{secret} was written to {path}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&backup);
}
