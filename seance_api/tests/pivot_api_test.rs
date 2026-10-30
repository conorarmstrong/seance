//! P1 pivot: `GET /cases/{id}/pivot?value=X` returns every artifact that
//! references a value, grouped by the kind of record each is — the move an
//! examiner makes constantly ("show me everything that touches this IP").

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::orchestrator::Orchestrator;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Pivot Case", "examiner").await.unwrap();

    // The C2 address appears across four kinds of record and is absent from a
    // fifth artifact, which must not show up in the pivot.
    let c2 = "203.78.103.109";
    let records = [
        (
            ArtifactType::ParsedRecord,
            json!({"type": "NetworkFlow", "name": format!("tcp 10.42.85.115 -> {c2}:443")}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"type": "NetworkFlow", "name": format!("tcp 10.42.85.10 -> {c2}:443")}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"type": "DnsResolution", "name": format!("evil.example resolved to {c2}")}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"type": "RegistryHive", "name": format!("Run key value {c2}")}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "c2-notes.txt", "path": format!("/notes about {c2}")}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "unrelated.txt", "path": "/nothing here"}),
        ),
    ];
    for (kind, meta) in records {
        let a = Artifact::new(case_id, kind, None, meta);
        db.record_artifact(&a).await.unwrap();
        service.add_artifact_to_index_sync(&a).unwrap();
    }
    service.commit_sync().unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(service),
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    (router_with_auth(app_state, Some(auth_config)), case_id, db)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

#[tokio::test]
async fn a_pivot_groups_every_artifact_touching_a_value_by_record_kind() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(
        &app,
        &format!("/api/v1/cases/{case_id}/pivot?value=203.78.103.109"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["value"], "203.78.103.109");
    // Five artifacts carry the value; the sixth (unrelated.txt) does not.
    assert_eq!(body["total_matches"], 5, "{body}");
    assert_eq!(body["truncated"], false);

    let groups = body["groups"].as_array().unwrap();
    let by_kind: std::collections::HashMap<&str, u64> = groups
        .iter()
        .map(|g| (g["kind"].as_str().unwrap(), g["count"].as_u64().unwrap()))
        .collect();
    // Two network flows, and one each of the others — grouped by record type,
    // not lumped as "5 records".
    assert_eq!(by_kind.get("NetworkFlow"), Some(&2));
    assert_eq!(by_kind.get("DnsResolution"), Some(&1));
    assert_eq!(by_kind.get("RegistryHive"), Some(&1));
    assert_eq!(by_kind.get("FileEntry"), Some(&1));

    // The largest group leads.
    assert_eq!(groups[0]["kind"], "NetworkFlow");
    assert_eq!(groups[0]["count"], 2);
    // Samples carry enough to open the artifact.
    let sample = &groups[0]["samples"][0];
    assert!(Uuid::parse_str(sample["artifact_id"].as_str().unwrap()).is_ok());
    assert!(sample["name"].as_str().unwrap().contains("203.78.103.109"));
}

#[tokio::test]
async fn a_value_nothing_references_pivots_to_an_empty_but_valid_answer() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(
        &app,
        &format!("/api/v1/cases/{case_id}/pivot?value=10.255.255.254"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_matches"], 0);
    assert_eq!(body["truncated"], false);
    assert!(body["groups"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_pivot_with_no_value_is_a_bad_request_not_a_scan_of_everything() {
    let (app, case_id, _db) = setup().await;
    let (status, _) = get(&app, &format!("/api/v1/cases/{case_id}/pivot")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(&app, &format!("/api/v1/cases/{case_id}/pivot?value=")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(&app, &format!("/api/v1/cases/{case_id}/pivot?value=%20%20")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// §1.0. The kind a pivot groups by comes off the search index with the hit,
/// so grouping costs nothing beyond the search that already ran. It used to
/// take every hit id back to the database — a chunked `id IN (...)` on the
/// interaction an examiner makes most often.
///
/// Proven by deleting the artifact rows out from under the pivot: with the
/// database emptied of them the grouping must still be exactly right, which it
/// can only be if the kinds came from the index.
#[tokio::test]
async fn the_pivot_groups_from_the_index_without_asking_the_database() {
    let (app, case_id, db) = setup().await;

    // The rows the old implementation depended on, gone. The index keeps its
    // documents: this is the state the old grouping could not survive.
    let rows = db
        .artifacts_page_after(case_id, None, 10_000)
        .await
        .expect("artifacts listed");
    assert!(!rows.is_empty(), "the fixture recorded artifacts");
    for a in &rows {
        db.delete_artifact_recursive(case_id, a.id)
            .await
            .expect("artifact deleted");
    }
    assert!(
        db.artifacts_page_after(case_id, None, 10)
            .await
            .expect("re-listed")
            .is_empty(),
        "every artifact row is gone"
    );

    let (status, body) = get(
        &app,
        &format!("/api/v1/cases/{case_id}/pivot?value=203.78.103.109"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total_matches"], 5, "{body}");

    let by_kind: std::collections::HashMap<&str, u64> = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["kind"].as_str().unwrap(), g["count"].as_u64().unwrap()))
        .collect();
    // The same grouping as with the rows present: the record `type`
    // discriminator, not the bare artifact type.
    assert_eq!(by_kind.get("NetworkFlow"), Some(&2), "{body}");
    assert_eq!(by_kind.get("DnsResolution"), Some(&1), "{body}");
    assert_eq!(by_kind.get("RegistryHive"), Some(&1), "{body}");
    assert_eq!(by_kind.get("FileEntry"), Some(&1), "{body}");
}
