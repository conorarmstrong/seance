//! "What is on this device": records grouped by the application they came from
//! (§2.12).
//!
//! The assertion that carries the weight here is
//! [`unattributed_records_are_counted_and_not_distributed_among_the_apps`].
//! The per-app figures are a triage metaphor an examiner reads as "this is
//! what was on the phone", and most of a case is not an application at all —
//! file entries, registry keys, network flows. If those were folded into the
//! apps, or silently dropped from the total, the screen would be a breakdown
//! of something other than the case it names.

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
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Apps", "examiner").await.unwrap();

    let rows = vec![
        // Attributed by record TYPE: the messengers name no `app` field.
        json!({"type": "WhatsApp", "body": "one"}),
        json!({"type": "WhatsApp", "body": "two"}),
        json!({"type": "iMessage", "body": "three"}),
        // An attachment groups under the app whose messages it came with,
        // rather than as an application of its own.
        json!({"type": "iMessageAttachment", "filename": "pic.jpg"}),
        // Attributed by the record NAMING the app, as SRUM does.
        json!({"type": "SrumAppResourceUse", "app": "chrome.exe", "bytes": 12}),
        json!({"type": "SrumAppResourceUse", "app": "chrome.exe", "bytes": 34}),
        json!({"type": "SrumAppResourceUse", "app": "outlook.exe", "bytes": 56}),
        // Belongs to no application: artefacts of the system. These must be
        // counted and NOT distributed among the apps.
        json!({"type": "NetworkFlow", "peer_address": "10.0.0.5"}),
        json!({"type": "RegistryHive", "key_path": "Run"}),
        json!({"type": "NtfsSecurityDescriptor", "owner": "S-1-5-18"}),
    ];
    for metadata in rows {
        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata);
        db.record_artifact(&artifact).await.unwrap();
    }

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

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn app_named<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["apps"]
        .as_array()
        .expect("apps array")
        .iter()
        .find(|a| a["app"] == name)
        .unwrap_or_else(|| panic!("no group for {name}: {body}"))
}

#[tokio::test]
async fn records_group_by_the_application_they_came_from() {
    let (app, case_id) = setup().await;
    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/stats/apps")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Attributed by type, and the attachment folded into its messenger.
    let whatsapp = app_named(&body, "WhatsApp");
    assert_eq!(whatsapp["records"], 2, "{body}");
    assert_eq!(whatsapp["attribution"], "record_type");

    let imessage = app_named(&body, "Messages (iMessage)");
    assert_eq!(
        imessage["records"], 2,
        "the message and its attachment belong to one app: {body}"
    );
    let types: Vec<&str> = imessage["record_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(types, ["iMessage", "iMessageAttachment"]);

    // Attributed by the record naming the app.
    let chrome = app_named(&body, "chrome.exe");
    assert_eq!(chrome["records"], 2, "{body}");
    assert_eq!(
        chrome["attribution"], "named_by_record",
        "the record said so; the type did not: {body}"
    );
    assert_eq!(app_named(&body, "outlook.exe")["records"], 1);

    // Largest group leads, so a quoted figure reads the same tomorrow.
    let first = &body["apps"].as_array().unwrap()[0];
    assert_eq!(first["records"], 2);
}

#[tokio::test]
async fn unattributed_records_are_counted_and_not_distributed_among_the_apps() {
    let (app, case_id) = setup().await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/stats/apps")).await;

    // The three system artefacts are unattributed, named, and counted.
    assert_eq!(body["unattributed"]["records"], 3, "{body}");
    let mut kinds: Vec<&str> = body["unattributed"]["record_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        ["NetworkFlow", "NtfsSecurityDescriptor", "RegistryHive"],
        "{body}"
    );
    assert!(body["unattributed"]["note"]
        .as_str()
        .unwrap()
        .contains("NOT distributed"));

    // No app group invented for them.
    for invented in ["NetworkFlow", "RegistryHive", "NtfsSecurityDescriptor"] {
        assert!(
            !body["apps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["app"] == invented),
            "a record kind that is not an application must not become one: {body}"
        );
    }

    // And the arithmetic closes: the per-app records plus the unattributed
    // equal the total, so the screen is a breakdown of the case it names.
    let per_app: i64 = body["apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["records"].as_i64().unwrap())
        .sum();
    assert_eq!(
        per_app + body["unattributed"]["records"].as_i64().unwrap(),
        body["total_records"].as_i64().unwrap(),
        "{body}"
    );
    assert_eq!(body["total_records"], 10, "{body}");
}

#[tokio::test]
async fn a_case_whose_records_are_all_applications_says_nothing_was_set_aside() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("OnlyApps", "examiner").await.unwrap();
    for _ in 0..2 {
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "Signal", "body": "x"}),
        ))
        .await
        .unwrap();
    }
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
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/stats/apps")).await;
    assert_eq!(body["unattributed"]["records"], 0, "{body}");
    assert!(body["unattributed"]["note"]
        .as_str()
        .unwrap()
        .contains("Every parsed record"));
    assert_eq!(app_named(&body, "Signal")["records"], 2);
}
