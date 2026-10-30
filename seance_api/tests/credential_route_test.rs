//! `POST /api/v1/cases/{id}/artifacts/{id}/credential` (HUNT-120), end to end.
//!
//! A real orchestrator runs the real BitLocker decryptor — built with **no**
//! process-level credential, as the server now builds it — over the real
//! BitLocker To Go volume `test_data/bdetogo.raw` (password `bde-TEST`), behind
//! the real router with authentication on.
//!
//! What is asserted:
//!
//! - **auth and scoping** — a `read_only` grantee is refused before the
//!   handler runs; an artifact of another case is not found; an unknown kind
//!   is refused without echoing anything;
//! - **the lifecycle** — a wrong password fails the job, records nothing new
//!   and leaves the locked record standing; the right one puts the decrypted
//!   volume beneath it and supersedes the locked record;
//! - **the audit** — `credential_supplied` and `credential_outcome` rows name
//!   the user, the kind and the outcome;
//! - **the secret is nowhere** — not in the database file, its WAL or shm, not
//!   in any audit row, job row or HTTP response, and not in anything the
//!   process logged while it ran (a tracing subscriber captures every line at
//!   TRACE).

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

const JWT_SECRET: &str = "credential-route-test-secret";
const CSRF: &str = "credential-route-csrf";
const RIGHT: &str = "bde-TEST";
const WRONG: &str = "wrong-bde-guess-5521";

// ── captured logs ────────────────────────────────────────────────────────

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

// ── harness ──────────────────────────────────────────────────────────────

fn bdetogo() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("test_data/bdetogo.raw");
    p.exists().then_some(p)
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

async fn harness(grant: &str) -> Harness {
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
        .create_case_with_metadata(Some("Credential".into()), None, Some("Ex".into()))
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
    orchestrator.register_module(Arc::new(seance_plugin_whatsapp::WhatsAppParser));
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
async fn seed_locked_volume(h: &Harness, image: &std::path::Path) -> (Uuid, Uuid) {
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

async fn supply(h: &Harness, artifact: Uuid, kind: &str, secret: &str) -> (StatusCode, String) {
    call(
        h,
        "POST",
        format!(
            "/api/v1/cases/{}/artifacts/{artifact}/credential",
            h.case_id
        ),
        Some(json!({ "kind": kind, "secret": secret })),
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

// ── tests ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_then_a_right_password_through_the_route_with_the_secret_nowhere() {
    let Some(image) = bdetogo() else {
        eprintln!("skipping: test_data/bdetogo.raw is not present");
        return;
    };
    let h = harness("read_write").await;
    let (volume, locked) = seed_locked_volume(&h, &image).await;
    let mut responses = String::new();

    // Wrong: accepted for processing, then the job fails and nothing changes.
    let (status, body) = supply(&h, volume, "bitlocker_password", WRONG).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    responses.push_str(&body);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["module_id"], "plugin.crypto.bitlocker_decryptor");
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
    assert_eq!(h.db.count_child_artifacts(volume).await.unwrap(), 1);

    // Right: the decrypted volume appears beneath, the locked record is superseded.
    let (status, body) = supply(&h, volume, "bitlocker_password", RIGHT).await;
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
        "the locked record must be superseded"
    );
    let children =
        h.db.get_child_artifacts(h.case_id, Some(volume), Some(100), 0)
            .await
            .unwrap()
            .items;
    assert!(
        children
            .iter()
            .any(|c| c.metadata.get("bitlocker_decrypted") == Some(&json!(true))),
        "the decrypted volume must appear beneath the locked one"
    );
    assert!(children
        .iter()
        .any(|c| c.metadata["status"] == json!("Unlocked")));

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
            .contains("kind=bitlocker_password"));
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
    for secret in [RIGHT, WRONG] {
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
}

#[tokio::test]
async fn a_read_only_grantee_cannot_supply_a_credential() {
    let h = harness("read_only").await;
    let target = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "v"}),
    );
    h.db.record_artifact(&target).await.unwrap();
    let (status, body) = supply(&h, target.id, "luks_passphrase", "ro-secret-8812").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains("ro-secret-8812"));
    let audit = h.db.get_audit_log(h.case_id, 50, 0).await.unwrap();
    assert!(audit
        .iter()
        .all(|e| e["action"] != json!("credential_supplied")));
    assert!(h.db.list_jobs(h.case_id).await.unwrap().is_empty());
    h.runner.abort();
}

#[tokio::test]
async fn an_artifact_of_another_case_is_not_found() {
    let h = harness("read_write").await;
    let other_case =
        h.db.create_case_with_metadata(Some("Other".into()), None, Some("Ex".into()))
            .await
            .unwrap();
    let foreign = Artifact::new(
        other_case,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "v"}),
    );
    h.db.record_artifact(&foreign).await.unwrap();
    let (status, body) = supply(&h, foreign.id, "luks_passphrase", "x-secret-3391").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(!body.contains("x-secret-3391"));
    assert!(h.db.list_jobs(h.case_id).await.unwrap().is_empty());
    h.runner.abort();
}

#[tokio::test]
async fn an_unknown_kind_or_an_empty_secret_is_refused_without_echo() {
    let h = harness("read_write").await;
    let target = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "v"}),
    );
    h.db.record_artifact(&target).await.unwrap();
    let (status, body) = supply(&h, target.id, "password", "k-secret-7710").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("bitlocker_recovery_password"), "{body}");
    assert!(!body.contains("k-secret-7710"));
    let (status, _) = supply(&h, target.id, "luks_passphrase", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(h.db.list_jobs(h.case_id).await.unwrap().is_empty());
    h.runner.abort();
}

/// ROADMAP §5.7, owner decision (c) part b: a WhatsApp `crypt14` backup whose
/// key file is not in the case, opened through the route with kind
/// `whatsapp_key`. The backup and the keys are the synthetic fixtures made by
/// OpenSSL (`seance_plugin_whatsapp/tests/fixtures/make_synthetic_crypt14.py`);
/// the real-backup grade is `seance_plugin_whatsapp/tests/real_crypt14.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_whatsapp_backup_opens_with_its_key_through_the_route_with_the_key_nowhere() {
    let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../seance_plugin_whatsapp/tests/fixtures");
    let backup_path = fixtures.join("synthetic_msgstore.db.crypt14");
    let hex = |p: &str| -> String {
        std::fs::read(fixtures.join(p))
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let (right, wrong) = (hex("synthetic.key"), hex("synthetic_other_install.key"));

    let h = harness("read_write").await;
    let backup = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "msgstore.db.crypt14", "source_path": backup_path.to_string_lossy() }),
    );
    h.db.record_artifact(&backup).await.unwrap();
    // Ingest's statement: read with no key in the case, it awaits one.
    let mut with_bytes = backup.clone();
    with_bytes.data =
        Some(Arc::new(FileDataSource::new(backup_path.clone()).unwrap()) as Arc<dyn DataSource>);
    let awaiting = seance_plugin_whatsapp::WhatsAppParser
        .process(&with_bytes)
        .unwrap()
        .remove(0);
    assert_eq!(awaiting.metadata["status"], "AwaitingKey");
    h.db.record_artifact(&awaiting).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut responses = String::new();

    // Another install's key: the job fails, nothing is filed, the statement stands.
    let (status, body) = supply(&h, backup.id, "whatsapp_key", &wrong).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    responses.push_str(&body);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["module_id"], "plugin.messaging.whatsapp");
    let (job, raw) = wait_for_job(&h, v["job_id"].as_str().unwrap()).await;
    responses.push_str(&raw);
    assert_eq!(
        job["status"].as_str().unwrap().to_lowercase(),
        "failed",
        "{job}"
    );
    assert!(!superseded(&h, awaiting.id).await);
    assert_eq!(h.db.count_child_artifacts(backup.id).await.unwrap(), 1);

    // The right key: the messages are filed beneath, the statement superseded.
    let (status, body) = supply(&h, backup.id, "whatsapp_key", &right).await;
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
        superseded(&h, awaiting.id).await,
        "AwaitingKey is superseded"
    );
    let children =
        h.db.get_child_artifacts(h.case_id, Some(backup.id), Some(100), 0)
            .await
            .unwrap()
            .items;
    let messages: Vec<_> = children
        .iter()
        .filter(|c| c.metadata["type"] == json!("WhatsApp"))
        .collect();
    assert_eq!(messages.len(), 3, "the three messages the backup holds");
    for m in &messages {
        assert_eq!(
            m.metadata["decrypted_backup"]["key_source"],
            json!("credential")
        );
    }

    let audit = h.db.get_audit_log(h.case_id, 200, 0).await.unwrap();
    let details: String = audit
        .iter()
        .filter(|e| e["action"] == json!("credential_outcome"))
        .map(|r| r["details"].as_str().unwrap().to_string())
        .collect();
    assert!(details.contains("kind=whatsapp_key"), "{details}");
    assert!(details.contains("outcome=rejected"), "{details}");
    assert!(details.contains("outcome=accepted"), "{details}");

    // Neither key, nor the AES key inside the right one, is anywhere.
    let audit_text = serde_json::to_string(&audit).unwrap();
    let jobs_text = format!("{:?}", h.db.list_jobs(h.case_id).await.unwrap());
    h.runner.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log_bytes = logs().0.lock().unwrap().clone();
    let aes = right[right.len() - 64..].to_string();
    for secret in [right.as_str(), wrong.as_str(), aes.as_str()] {
        assert!(!audit_text.contains(secret), "a key reached the audit log");
        assert!(!jobs_text.contains(secret), "a key reached a job row");
        assert!(
            !responses.contains(secret),
            "a key reached an HTTP response"
        );
        assert!(
            !contains(&log_bytes, secret),
            "a key reached the process log"
        );
        for suffix in ["", "-wal", "-shm"] {
            let path = format!("{}{}", h.db_path.display(), suffix);
            if let Ok(bytes) = std::fs::read(&path) {
                assert!(!contains(&bytes, secret), "a key was written to {path}");
            }
        }
    }
}
