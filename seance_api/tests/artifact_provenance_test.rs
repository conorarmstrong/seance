//! CR-048: an artifact's backup-container provenance is resolved by identity
//! first, and an ambiguous container name is disclosed rather than hidden.
//!
//! Synthetic: containers are hand-built metadata documents in an in-memory
//! database. They grade the handler's behaviour, not any real backup.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
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

fn container(name: &str, rel: &str) -> Artifact {
    Artifact::new(
        Uuid::nil(),
        ArtifactType::FileEntry,
        None,
        json!({"name": name, "domain": "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
               "relative_path": rel}),
    )
}

async fn put(db: &SqliteConnection, case: Uuid, mut a: Artifact) -> Uuid {
    a.case_id = case;
    db.record_artifact(&a).await.unwrap();
    a.id
}

async fn provenance(app: &axum::Router, case: Uuid, id: Uuid) -> serde_json::Value {
    let (s, b) = get(app, &format!("/api/v1/cases/{case}/artifacts/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["metadata"]["provenance"].clone()
}

fn child(parent: Option<Uuid>) -> Artifact {
    let a = Artifact::new(
        Uuid::nil(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "IMG-1.jpg", "container_path": "WhatsApp media.zip"}),
    );
    match parent {
        Some(p) => a.with_parent(p),
        None => a,
    }
}

#[tokio::test]
async fn a_child_resolves_its_origin_by_parent_identity_when_the_name_is_ambiguous() {
    let (app, db, case) = setup().await;
    let a = put(
        &db,
        case,
        container(
            "WhatsApp media.zip",
            "Message/Media/111@s.whatsapp.net/a.zip",
        ),
    )
    .await;
    let _b = put(
        &db,
        case,
        container(
            "WhatsApp media.zip",
            "Message/Media/222@s.whatsapp.net/b.zip",
        ),
    )
    .await;
    let c = put(&db, case, child(Some(a))).await;
    let p = provenance(&app, case, c).await;
    assert_eq!(p["in_app_path"], "Message/Media/111@s.whatsapp.net/a.zip");
    assert!(p.get("origin_ambiguous").is_none());
}

#[tokio::test]
async fn an_ambiguous_name_with_no_parent_says_the_origin_is_ambiguous() {
    let (app, db, case) = setup().await;
    put(
        &db,
        case,
        container(
            "WhatsApp media.zip",
            "Message/Media/111@s.whatsapp.net/a.zip",
        ),
    )
    .await;
    put(
        &db,
        case,
        container(
            "WhatsApp media.zip",
            "Message/Media/222@s.whatsapp.net/b.zip",
        ),
    )
    .await;
    let c = put(&db, case, child(None)).await;
    let p = provenance(&app, case, c).await;
    assert_eq!(p["origin_ambiguous"], true);
    assert_eq!(p["container"], "WhatsApp media.zip");
    assert!(p["note"].as_str().unwrap().contains("ambiguous"));
    assert!(
        p.get("source_app").is_none(),
        "no app may be attributed on a guess"
    );
    assert!(p.get("correspondent").is_none());
}

#[tokio::test]
async fn an_unambiguous_container_still_resolves_by_name() {
    let (app, db, case) = setup().await;
    put(
        &db,
        case,
        container(
            "WhatsApp media.zip",
            "Message/Media/111@s.whatsapp.net/a.zip",
        ),
    )
    .await;
    let c = put(&db, case, child(None)).await;
    let p = provenance(&app, case, c).await;
    assert_eq!(p["source_app"], "WhatsApp");
    assert!(p.get("origin_ambiguous").is_none());
}
