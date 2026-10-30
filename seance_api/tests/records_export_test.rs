//! The records export applies the same withholding every ordinary read does:
//! a recovered credential's value leaves the server only through the audited
//! reveal, and a CSV is not a reveal (SEC-010).

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{
    router_with_auth, AppState, AuthConfig, EvidenceRootPolicy, CREDENTIAL_VALUE_WITHHELD,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Export Case", "examiner").await.unwrap();
    let credential = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "MemoryCredential",
            "source": "SAM",
            "username": "Administrator",
            "value": HASH,
        }),
    );
    db.record_artifact(&credential).await.unwrap();
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: None,
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    (router_with_auth(app_state, Some(auth_config)), case_id)
}

async fn get_text(app: &axum::Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn the_records_export_withholds_a_recovered_credentials_value() {
    let (app, case) = setup().await;
    for uri in [
        format!("/api/v1/cases/{case}/records/export/csv?type=MemoryCredential"),
        format!(
            "/api/v1/cases/{case}/records/export/csv?type=MemoryCredential&columns=value,username"
        ),
    ] {
        let (status, body) = get_text(&app, &uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert!(
            !body.contains(HASH),
            "the decrypted value must not leave the server in an export: {uri}\n{body}"
        );
        assert!(
            body.contains(CREDENTIAL_VALUE_WITHHELD),
            "the row must say the value was withheld, not drop it: {uri}\n{body}"
        );
        assert!(
            body.contains("Administrator"),
            "the rest of the record is evidence: {body}"
        );
    }
}
