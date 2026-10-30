//! A search states what it searched (`SEARCH-002`).
//!
//! A search that returns nothing is read as "the term is absent from the
//! evidence". That reading is only as good as the scope searched, so every
//! search page carries the statement of that scope — the `universe` — even,
//! and especially, when it found nothing.

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

/// Matching documents seeded into the case under test.
const DOCS: usize = 25;

/// A term every seeded document contains.
const TERM: &str = "kestrel";

/// Build the router around a real Tantivy index seeded with [`DOCS`] matches.
///
/// The index directory is leaked deliberately, as `search_reindex_test` does,
/// because the service outlives the `TempDir` guard.
async fn setup() -> (axum::Router, Uuid) {
    setup_indexed_by(Build::This).await
}

/// Which build made the case's documents.
#[derive(PartialEq)]
enum Build {
    This,
    /// A build from before the text extractor version was recorded (every
    /// v1.0.x build). Simulated by removing the record after indexing: such a
    /// build never wrote it, so the directory is the same.
    Earlier,
}

async fn setup_indexed_by(build: Build) -> (axum::Router, Uuid) {
    let index_dir = tempfile::tempdir().unwrap();
    let index_path = index_dir.path().to_path_buf();
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Search Universe Case", "examiner")
        .await
        .unwrap();

    {
        let service = seance_search::SearchService::new(&index_path).expect("search index");
        for i in 0..DOCS {
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({
                    "name": format!("note_{i:03}.txt"),
                    "content": format!("{TERM} observation {i}"),
                }),
            );
            service
                .add_artifact_to_index_sync(&artifact)
                .expect("index");
        }
        service.commit_sync().expect("commit");
    }
    if build == Build::Earlier {
        let _ = std::fs::remove_file(index_path.join(seance_search::TEXT_EXTRACTOR_RECORD_FILE));
    }
    let service =
        Arc::new(seance_search::SearchService::new(&index_path).expect("reopen search index"));

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

async fn search(app: &axum::Router, case_id: Uuid, query: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/search?{}", case_id, query))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_case_search_response_states_its_universe() {
    let (app, case_id) = setup().await;

    // A term nothing contains: the zero-hit page is the one that most needs it.
    let (status, body) = search(&app, case_id, "q=absentterm").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_count"], 0);
    let universe = &body["universe"];
    let statement = universe["statement"].as_str().unwrap_or_default();
    assert!(
        statement.contains("MiB") && statement.contains("slack"),
        "a zero-hit page must say what was searched: {body}"
    );
    assert_eq!(
        universe["content_bytes_per_artifact"],
        16 * 1024 * 1024,
        "{universe}"
    );
    assert_eq!(
        universe["byte_sweep_route"],
        "POST /api/v1/cases/:id/search/sweep"
    );

    // And a page with hits carries the same statement.
    let (_, hits) = search(&app, case_id, &format!("q={TERM}")).await;
    assert_eq!(hits["universe"], body["universe"]);
}

/// An export is an exhibit separated from the screen that made it, so it must
/// carry the same statement of scope: a reader of the file has no search page
/// beside it.
#[tokio::test]
async fn a_search_export_states_its_universe_in_both_formats() {
    let (app, case_id) = setup().await;
    for format in ["json", "csv"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/cases/{case_id}/search/export/{format}?q=absentterm"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{format}");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        // The statement for THIS case, whose documents this build indexed.
        let expected = seance_search::search_universe_for(
            &seance_search::IndexTextProvenance {
                status: seance_search::IndexTextExtractor::Current,
                recorded_versions: vec![seance_search::TEXT_EXTRACTOR_VERSION],
            },
            seance_search::MatchMode::Exact,
        )
        .statement;
        if format == "json" {
            let v: Value = serde_json::from_str(&text).expect("a whole JSON export");
            assert_eq!(
                v["universe"]["statement"].as_str(),
                Some(expected.as_str()),
                "{text}"
            );
        } else {
            assert!(
                text.contains("search_universe") && text.contains("slack"),
                "the CSV preamble must state the scope: {text}"
            );
        }
    }
}

/// The statement is about the index that answered, not the running build: a
/// case an earlier build indexed read UTF-16 as ASCII only, and its search
/// page must not claim this build's coverage (review of 2026-09-27).
#[tokio::test]
async fn a_case_an_earlier_build_indexed_is_told_so_on_the_page() {
    let (app, case_id) = setup_indexed_by(Build::This).await;
    let (_, body) = search(&app, case_id, "q=absentterm").await;
    assert_eq!(
        body["universe"]["index_text_extractor"], "current",
        "{body}"
    );

    let (app, case_id) = setup_indexed_by(Build::Earlier).await;
    let (status, body) = search(&app, case_id, "q=absentterm").await;
    assert_eq!(status, StatusCode::OK);
    let universe = &body["universe"];
    assert_eq!(universe["index_text_extractor"], "earlier", "{universe}");
    let statement = universe["statement"].as_str().unwrap_or_default();
    assert!(
        statement.contains("earlier build") && statement.contains("re-ingest"),
        "{statement}"
    );
}

/// A fuzzy search is approximate, and the page says so rather than calling it
/// exact-form.
#[tokio::test]
async fn a_fuzzy_search_page_does_not_call_its_matching_exact() {
    let (app, case_id) = setup().await;
    let (status, body) = search(&app, case_id, &format!("q={TERM}&fuzzy=2")).await;
    assert_eq!(status, StatusCode::OK);
    let matching = body["universe"]["matching"].as_str().unwrap_or_default();
    assert!(!matching.contains("exact-form"), "{matching}");
    assert!(matching.contains("edit distance 2"), "{matching}");
}

/// Both export formats carry the per-case statement.
#[tokio::test]
async fn an_export_of_a_case_an_earlier_build_indexed_says_so() {
    let (app, case_id) = setup_indexed_by(Build::Earlier).await;
    for format in ["json", "csv"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/cases/{case_id}/search/export/{format}?q=absentterm"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{format}");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        // The case-specific sentence, not the build-level caveat (which also
        // mentions earlier builds, and is true of every case).
        assert!(
            text.contains("of this case's file documents were indexed by an earlier build"),
            "{format}: {text}"
        );
        if format == "json" {
            let v: Value = serde_json::from_str(&text).expect("a whole JSON export");
            assert_eq!(v["universe"]["index_text_extractor"], "earlier", "{text}");
        }
    }
}
