//! Examiner assignment and personal bookmarks over the wire (ROADMAP §3.15).
//!
//! Auth is ENABLED throughout: who may assign, who may be assigned, and whose
//! personal marks a request can see are all questions about the caller.
//! Synthetic users and artifacts; this is case-workflow state and there is no
//! on-disk format to validate against.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "assignment-test-secret";
const CSRF_TOKEN: &str = "assignment-csrf";

async fn fresh_db() -> Arc<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    Arc::new(db)
}

fn make_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled: true,
    }
}

fn build_state(db: Arc<SqliteConnection>) -> AppState {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    AppState {
        db: db.clone(),
        // A counted submitter over the test channel; the counter is the test's own
        // because nothing here submits through it.
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ),
        ad_hoc_sender: ad_hoc_tx,
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
        evidence_roots: seance_api::EvidenceRootPolicy::from_env(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    }
}

fn build_app(db: Arc<SqliteConnection>) -> (axum::Router, AuthConfig) {
    let cfg = make_config();
    let app = router_with_auth(build_state(db), Some(cfg.clone()));
    (app, cfg)
}

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

/// Authenticated request carrying an optional JSON body plus the CSRF
/// double-submit pair (required for unsafe methods).
fn authed(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .header("x-csrf-token", CSRF_TOKEN)
        .header("cookie", format!("seance_csrf={}", CSRF_TOKEN));
    match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Create a case directly in the DB and return its id (no owner grant), so we
/// can test the "examiner has no grant" path deterministically.
async fn seed_case(db: &SqliteConnection) -> Uuid {
    db.create_case_with_metadata(Some("Seed".to_string()), None, Some("Ex".to_string()))
        .await
        .unwrap()
}

/// Seed a plain artifact directly into a case; returns its id.
async fn seed_artifact(db: &SqliteConnection, case_id: Uuid, name: &str) -> Uuid {
    let art = Artifact::new(
        case_id,
        ArtifactType::Container,
        None,
        json!({ "name": name }),
    );
    let id = art.id;
    db.record_artifact(&art).await.unwrap();
    id
}

async fn examiner(db: &SqliteConnection, name: &str) -> Uuid {
    db.create_user(
        name,
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap()
}

struct World {
    db: Arc<SqliteConnection>,
    app: axum::Router,
    cfg: AuthConfig,
    case: Uuid,
    ids: Vec<Uuid>,
    alice: Uuid,
}

/// olive owns the case, alice and bob are read_write, rita is read_only.
async fn world() -> World {
    let db = fresh_db().await;
    let case = seed_case(&db).await;
    let mut ids = Vec::new();
    for i in 0..4 {
        ids.push(seed_artifact(&db, case, &format!("f{i}")).await);
    }
    let olive = examiner(&db, "olive").await;
    let alice = examiner(&db, "alice").await;
    let bob = examiner(&db, "bob").await;
    let rita = examiner(&db, "rita").await;
    db.grant_case_access(case, olive, "owner", None)
        .await
        .unwrap();
    db.grant_case_access(case, alice, "read_write", None)
        .await
        .unwrap();
    db.grant_case_access(case, bob, "read_write", None)
        .await
        .unwrap();
    db.grant_case_access(case, rita, "read_only", None)
        .await
        .unwrap();
    let (app, cfg) = build_app(db.clone());
    World {
        db,
        app,
        cfg,
        case,
        ids,
        alice,
    }
}

impl World {
    fn token(&self, who: &str) -> String {
        self.cfg.generate_token(who, "examiner").unwrap().0
    }
    async fn send(
        &self,
        who: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let token = self.token(who);
        let req = if method == "GET" {
            authed_get(uri, &token)
        } else {
            authed(method, uri, &token, body)
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn assign(&self, who: &str, assignee: Uuid, ids: &[Uuid]) -> (StatusCode, Value) {
        self.send(
            who,
            "POST",
            &format!("/api/v1/cases/{}/assignments", self.case),
            Some(json!({"assignee_user_id": assignee, "artifact_ids": ids, "note": "triage"})),
        )
        .await
    }
    async fn count_assignments(&self) -> i64 {
        self.db.list_assignments(self.case).await.unwrap().len() as i64
    }
}

#[tokio::test]
async fn assigning_to_a_read_only_examiner_is_refused_with_400_and_nothing_recorded() {
    let w = world().await;
    let rita = w.db.get_user_by_username("rita").await.unwrap().unwrap().id;
    let (status, body) = w.assign("olive", rita, &w.ids).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("read_only"),
        "the refusal names the reason: {body}"
    );
    assert_eq!(w.count_assignments().await, 0);
}

#[tokio::test]
async fn a_read_write_examiner_cannot_assign_but_an_owner_can() {
    let w = world().await;
    let (status, _) = w.assign("bob", w.alice, &w.ids).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(w.count_assignments().await, 0);

    let (status, body) = w.assign("olive", w.alice, &w.ids).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["assignee_username"], "alice");
    assert_eq!(body["progress"]["total"], 4);
    assert_eq!(w.count_assignments().await, 1);
}

#[tokio::test]
async fn the_queue_lists_only_items_the_assignee_has_not_reviewed() {
    let w = world().await;
    let (_, created) = w.assign("olive", w.alice, &w.ids).await;
    let aid = created["id"].as_str().unwrap().to_string();

    // bob (a colleague) reviews ids[0]; alice reviews ids[1].
    for (who, id) in [("bob", w.ids[0]), ("alice", w.ids[1])] {
        let (s, b) = w
            .send(
                who,
                "POST",
                &format!("/api/v1/cases/{}/artifact_reviews", w.case),
                Some(json!({"marks": [{"artifact_id": id, "state": "reviewed"}]})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
    }

    let (status, q) = w
        .send(
            "alice",
            "GET",
            &format!("/api/v1/cases/{}/assignments/{}/queue", w.case, aid),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{q}");
    let left: Vec<String> = q["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["artifact_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(left.len(), 3, "{q}");
    assert!(
        left.contains(&w.ids[0].to_string()),
        "a colleague's review does not clear alice's item"
    );
    assert!(!left.contains(&w.ids[1].to_string()));
    assert_eq!(q["progress"]["reviewed_by_assignee"], 1);
    assert_eq!(q["progress"]["total"], 4);
    assert_eq!(q["has_more"], false);
}

#[tokio::test]
async fn an_over_cap_assignment_is_refused_in_full() {
    let w = world().await;
    let over = vec![w.ids[0]; seance_db::ASSIGNMENT_ITEMS_MAX + 1];
    let (status, body) = w.assign("olive", w.alice, &over).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("nothing was recorded"), "{body}");
    assert_eq!(w.count_assignments().await, 0);

    // An artifact of another case refuses the whole request too.
    let other = seed_case(&w.db).await;
    let foreign = seed_artifact(&w.db, other, "x").await;
    let (status, _) = w.assign("olive", w.alice, &[w.ids[0], foreign]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(w.count_assignments().await, 0);
}

#[tokio::test]
async fn creating_and_withdrawing_an_assignment_each_write_one_audit_entry() {
    let w = world().await;
    let (_, created) = w.assign("olive", w.alice, &w.ids).await;
    let aid: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        w.db.count_audit_actions_for_resource("assignment_created", aid)
            .await
            .unwrap(),
        1
    );
    let (s, _) = w
        .send(
            "olive",
            "POST",
            &format!("/api/v1/cases/{}/assignments/{}/withdraw", w.case, aid),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        w.db.count_audit_actions_for_resource("assignment_withdrawn", aid)
            .await
            .unwrap(),
        1
    );
    // Still listed, marked withdrawn.
    let (_, list) = w
        .send(
            "alice",
            "GET",
            &format!("/api/v1/cases/{}/assignments", w.case),
            None,
        )
        .await;
    let a = &list["assignments"][0];
    assert!(a["withdrawn_at"].is_number(), "{list}");
    // A second withdrawal is a 409, not a silent success.
    let (s, _) = w
        .send(
            "olive",
            "POST",
            &format!("/api/v1/cases/{}/assignments/{}/withdraw", w.case, aid),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_user_without_case_access_gets_403_on_the_queue() {
    let w = world().await;
    let (_, created) = w.assign("olive", w.alice, &w.ids).await;
    let aid = created["id"].as_str().unwrap().to_string();
    examiner(&w.db, "mallory").await;
    let (status, _) = w
        .send(
            "mallory",
            "GET",
            &format!("/api/v1/cases/{}/assignments/{}/queue", w.case, aid),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn my_assignments_lists_only_the_callers_own() {
    let w = world().await;
    w.assign("olive", w.alice, &w.ids[..2]).await;
    let bob = w.db.get_user_by_username("bob").await.unwrap().unwrap().id;
    w.assign("olive", bob, &w.ids[2..]).await;
    let (_, mine) = w
        .send(
            "alice",
            "GET",
            &format!("/api/v1/cases/{}/assignments?mine=true", w.case),
            None,
        )
        .await;
    let list = mine["assignments"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{mine}");
    assert_eq!(list[0]["assignee_username"], "alice");
    assert_eq!(list[0]["progress"]["total"], 2);
}

#[tokio::test]
async fn personal_bookmarks_are_private_and_promotion_is_audited() {
    let w = world().await;
    let (s, created) = w
        .send(
            "alice",
            "POST",
            &format!("/api/v1/cases/{}/personal_bookmarks", w.case),
            Some(json!({"artifact_id": w.ids[0], "note": "check later"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let pid = created["id"].as_str().unwrap().to_string();

    let (_, bobs) = w
        .send(
            "bob",
            "GET",
            &format!("/api/v1/cases/{}/personal_bookmarks", w.case),
            None,
        )
        .await;
    assert!(
        bobs["items"].as_array().unwrap().is_empty(),
        "bob never sees alice's marks"
    );
    let (_, alices) = w
        .send(
            "alice",
            "GET",
            &format!("/api/v1/cases/{}/personal_bookmarks", w.case),
            None,
        )
        .await;
    assert_eq!(alices["items"].as_array().unwrap().len(), 1);

    // Not in the shared set until promoted.
    let (_, shared) = w
        .send(
            "alice",
            "GET",
            &format!("/api/v1/cases/{}/bookmarks", w.case),
            None,
        )
        .await;
    assert!(
        !shared.to_string().contains(&w.ids[0].to_string()),
        "{shared}"
    );

    // bob cannot promote alice's mark.
    let (s, _) = w
        .send(
            "bob",
            "POST",
            &format!(
                "/api/v1/cases/{}/personal_bookmarks/{}/promote",
                w.case, pid
            ),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, promoted) = w
        .send(
            "alice",
            "POST",
            &format!(
                "/api/v1/cases/{}/personal_bookmarks/{}/promote",
                w.case, pid
            ),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{promoted}");
    let pid_uuid: Uuid = pid.parse().unwrap();
    assert_eq!(
        w.db.count_audit_actions_for_resource("personal_bookmark_promoted", pid_uuid)
            .await
            .unwrap(),
        1
    );
    let shared =
        w.db.get_artifact_bookmark(w.case, w.ids[0])
            .await
            .unwrap()
            .unwrap();
    assert_eq!(shared.note.as_deref(), Some("check later"));
    assert_eq!(shared.examiner.as_deref(), Some("alice"));

    // The listing says whether the mark is in the shared set now, not merely
    // whether it was once promoted: the screen's "in shared bookmarks" claim
    // must track what the report will carry.
    let personal_url = format!("/api/v1/cases/{}/personal_bookmarks", w.case);
    let (_, listed) = w.send("alice", "GET", &personal_url, None).await;
    assert_eq!(listed["items"][0]["in_shared_set"], true, "{listed}");
    w.db.delete_artifact_bookmark(w.case, w.ids[0])
        .await
        .unwrap();
    let (_, listed) = w.send("alice", "GET", &personal_url, None).await;
    assert!(listed["items"][0]["promoted_at"].is_i64(), "{listed}");
    assert_eq!(
        listed["items"][0]["in_shared_set"], false,
        "its shared bookmark was deleted, so it is no longer reported: {listed}"
    );
}

#[tokio::test]
async fn assigning_to_an_examiner_with_no_grant_is_refused_with_400_and_nothing_recorded() {
    let w = world().await;
    let nobody = examiner(&w.db, "nora").await;
    let (status, body) = w.assign("olive", nobody, &w.ids).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("no access to this case"),
        "the refusal names the reason: {body}"
    );
    assert_eq!(w.count_assignments().await, 0);
}

#[tokio::test]
async fn assigning_to_a_deactivated_examiner_is_refused_with_400_and_nothing_recorded() {
    let w = world().await;
    assert!(w.db.set_user_active(w.alice, false).await.unwrap());
    let (status, body) = w.assign("olive", w.alice, &w.ids).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("deactivated"), "{body}");
    assert_eq!(w.count_assignments().await, 0);
}

#[tokio::test]
async fn a_read_only_examiner_cannot_create_a_personal_bookmark() {
    let w = world().await;
    let (status, body) = w
        .send(
            "rita",
            "POST",
            &format!("/api/v1/cases/{}/personal_bookmarks", w.case),
            Some(json!({"artifact_id": w.ids[0], "note": "mine"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let rita = w.db.get_user_by_username("rita").await.unwrap().unwrap().id;
    let listed =
        w.db.list_personal_bookmarks(w.case, rita, None, 0)
            .await
            .unwrap();
    assert!(listed.items.is_empty(), "nothing was recorded");
}

#[tokio::test]
async fn the_bootstrap_admin_with_no_user_row_gets_403_on_personal_bookmarks() {
    // The env-bootstrap admin authenticates only while the users table is
    // empty (auth.rs, BUG-044), and has no user row to scope a private mark
    // to. So this world has a case and an artifact but no users at all.
    let db = fresh_db().await;
    let case = seed_case(&db).await;
    let artifact = seed_artifact(&db, case, "f0").await;
    let (app, cfg) = build_app(db.clone());
    let token = cfg.generate_token("admin", "admin").unwrap().0;
    let url = format!("/api/v1/cases/{}/personal_bookmarks", case);
    for req in [
        authed_get(&url, &token),
        authed(
            "POST",
            &url,
            &token,
            Some(json!({"artifact_id": artifact, "note": "x"})),
        ),
    ] {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(
            text.contains("user account"),
            "the reason is stated: {text}"
        );
    }
}

#[tokio::test]
async fn the_report_carries_only_shared_bookmarks_and_counts_the_personal_ones_excluded() {
    let w = world().await;
    let mut marks = Vec::new();
    for id in &w.ids[..2] {
        let (_, created) = w
            .send(
                "alice",
                "POST",
                &format!("/api/v1/cases/{}/personal_bookmarks", w.case),
                Some(json!({"artifact_id": id, "note": "private thought"})),
            )
            .await;
        marks.push(created["id"].as_str().unwrap().to_string());
    }
    w.send(
        "alice",
        "POST",
        &format!(
            "/api/v1/cases/{}/personal_bookmarks/{}/promote",
            w.case, marks[0]
        ),
        None,
    )
    .await;

    let data = seance_api::gather_report_data(&build_state(w.db.clone()), w.case)
        .await
        .unwrap();
    assert_eq!(
        data.bookmarks.len(),
        1,
        "only the promoted mark is reported"
    );
    assert_eq!(
        data.personal_bookmarks_excluded, 1,
        "the unpromoted personal mark is counted, not silently dropped"
    );
}

#[tokio::test]
async fn the_auth_disabled_local_identity_gets_403_on_personal_bookmarks() {
    // With authentication disabled every request is the `local` identity,
    // which has no user row; personal marks would otherwise be one anonymous
    // scratch space shared by everyone on the machine.
    let db = fresh_db().await;
    let case = seed_case(&db).await;
    let artifact = seed_artifact(&db, case, "f0").await;
    let cfg = AuthConfig {
        enabled: false,
        ..make_config()
    };
    let app = router_with_auth(build_state(db.clone()), Some(cfg));
    let url = format!("/api/v1/cases/{}/personal_bookmarks", case);
    for req in [
        authed_get(&url, "unused"),
        authed(
            "POST",
            &url,
            "unused",
            Some(json!({"artifact_id": artifact, "note": "x"})),
        ),
    ] {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(
            text.contains("user account"),
            "the reason is stated: {text}"
        );
    }
}

// --- due dates and reassignment (ROADMAP §3.15) ---

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test]
async fn a_due_date_is_recorded_and_a_past_one_is_refused_in_full() {
    let w = world().await;
    let due = now() + 3600;
    let (status, body) = w
        .send(
            "olive",
            "POST",
            &format!("/api/v1/cases/{}/assignments", w.case),
            Some(json!({
                "assignee_user_id": w.alice,
                "artifact_ids": w.ids,
                "due_at": due,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["due_at"], due);
    assert_eq!(body["overdue"], false, "not due yet: {body}");

    let (status, body) = w
        .send(
            "olive",
            "POST",
            &format!("/api/v1/cases/{}/assignments", w.case),
            Some(json!({
                "assignee_user_id": w.alice,
                "artifact_ids": w.ids,
                "due_at": now() - 10,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("due"), "{body}");
    assert_eq!(w.count_assignments().await, 1, "the refusal wrote nothing");
}

#[tokio::test]
async fn reassigning_withdraws_the_old_assignment_and_gives_the_same_items_to_another_examiner() {
    let w = world().await;
    let bob = w.db.get_user_by_username("bob").await.unwrap().unwrap().id;
    let (_, created) = w.assign("olive", w.alice, &w.ids).await;
    let old: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let uri = format!("/api/v1/cases/{}/assignments/{}/reassign", w.case, old);

    // Only the owner may reassign.
    let (status, _) = w
        .send(
            "alice",
            "POST",
            &uri,
            Some(json!({"assignee_user_id": bob})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, new) = w
        .send(
            "olive",
            "POST",
            &uri,
            Some(json!({"assignee_user_id": bob, "note": "alice is out"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{new}");
    assert_eq!(new["assignee_username"], "bob");
    assert_eq!(new["progress"]["total"], 4, "the same four items");
    assert_eq!(new["reassigned_from"], old.to_string());
    assert_eq!(new["note"], "alice is out");
    let new_id: Uuid = new["id"].as_str().unwrap().parse().unwrap();

    // The old one is kept, marked withdrawn; the new one is active.
    let all = w.db.list_assignments(w.case).await.unwrap();
    assert_eq!(all.len(), 2);
    let old_row = all.iter().find(|a| a.id == old).unwrap();
    assert!(old_row.withdrawn_at.is_some());
    assert!(all
        .iter()
        .find(|a| a.id == new_id)
        .unwrap()
        .withdrawn_at
        .is_none());

    // One audit entry on the new assignment, naming where it came from.
    assert_eq!(
        w.db.count_audit_actions_for_resource("assignment_reassigned", new_id)
            .await
            .unwrap(),
        1
    );

    // Reassigning a withdrawn assignment is a 409, and writes nothing.
    let (status, _) = w
        .send(
            "olive",
            "POST",
            &uri,
            Some(json!({"assignee_user_id": bob})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(w.count_assignments().await, 2);

    // The assignee rules of a fresh assignment apply: a read_only examiner is refused.
    let rita = w.db.get_user_by_username("rita").await.unwrap().unwrap().id;
    let uri2 = format!("/api/v1/cases/{}/assignments/{}/reassign", w.case, new_id);
    let (status, body) = w
        .send(
            "olive",
            "POST",
            &uri2,
            Some(json!({"assignee_user_id": rita})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        w.db.get_assignment(w.case, new_id)
            .await
            .unwrap()
            .unwrap()
            .withdrawn_at
            .is_none(),
        "a refused reassignment leaves the source untouched"
    );
}
