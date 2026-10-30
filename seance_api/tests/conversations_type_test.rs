//! CR-048: a mistyped conversation `type` is the client's error (400), not a
//! database failure (500). Synthetic empty case: the check precedes any query.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("T", "examiner").await.unwrap();
    let index_dir = tempfile::tempdir().unwrap();
    let search_service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(search_service),
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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

fn paths(t: &str) -> [String; 3] {
    [
        format!("conversations?type={t}"),
        format!("conversations/messages?type={t}&key=k"),
        format!("conversations/search?type={t}&q=x"),
    ]
}

#[tokio::test]
async fn a_non_messaging_type_is_refused_with_400_on_all_three_endpoints() {
    let (app, _db, case) = setup().await;
    for t in ["PrefetchEntry", "CallLog", "whatsapp"] {
        for path in paths(t) {
            let (s, body) = get(&app, &format!("/api/v1/cases/{case}/{path}")).await;
            assert_eq!(
                s,
                StatusCode::BAD_REQUEST,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }
}

#[tokio::test]
async fn a_messaging_type_is_still_accepted() {
    let (app, _db, case) = setup().await;
    for t in ["WhatsApp", "EmailMessage"] {
        for path in paths(t) {
            let (s, _) = get(&app, &format!("/api/v1/cases/{case}/{path}")).await;
            assert_eq!(s, StatusCode::OK, "{path}");
        }
    }
}
