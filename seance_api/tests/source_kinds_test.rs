//! `GET /cases/:id/source_kinds` — the mobile source-type triage label per
//! evidence source (ROADMAP §1.4).
//!
//! The record shapes are the ones the plugins write (quoted from their emission
//! sites); the root shapes are the Magnet 2019 Android case's two roots, a
//! `Container` for `adb-data.tar` and a `RawEvidence` for the `sdcard`
//! directory. Synthetic records pin the mechanism; they do not stand for a
//! grade on real evidence.

use axum::{body::Body, http::Request};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    profile::IngestRun,
};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// The receivers the server would hold; dropping them closes the channels.
type RuntimeEnds = (
    tokio::sync::mpsc::UnboundedReceiver<Artifact>,
    tokio::sync::mpsc::UnboundedReceiver<Artifact>,
    tokio::sync::mpsc::Receiver<seance_core::profile::AdHocRequest>,
    tokio::sync::broadcast::Receiver<Artifact>,
    tokio::sync::broadcast::Receiver<seance_core::orchestrator::OrchestratorEvent>,
);

struct Harness {
    app: axum::Router,
    db: Arc<SqliteConnection>,
    case_id: Uuid,
    _ends: RuntimeEnds,
}

async fn harness() -> Harness {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Source kinds", "Examiner").await.unwrap();
    let (tx, orchestrator_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, status_rx) = tokio::sync::broadcast::channel(256);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = AppState {
        db: db.clone(),
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let auth = AuthConfig {
        jwt_secret: "test-secret".into(),
        admin_username: "admin".into(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    Harness {
        app: router_with_auth(state, Some(auth)),
        db,
        case_id,
        _ends: (orchestrator_rx, task_rx, ad_hoc_rx, event_rx, status_rx),
    }
}

impl Harness {
    async fn record(&self, ty: ArtifactType, parent: Option<Uuid>, metadata: Value) -> Uuid {
        self.record_in(self.case_id, ty, parent, metadata).await
    }

    async fn record_in(
        &self,
        case_id: Uuid,
        ty: ArtifactType,
        parent: Option<Uuid>,
        metadata: Value,
    ) -> Uuid {
        let mut a = Artifact::new(case_id, ty, None, metadata);
        if let Some(p) = parent {
            a = a.with_parent(p);
        }
        let id = a.id;
        self.db.record_artifact(&a).await.unwrap();
        id
    }

    async fn run(&self, root: Uuid, started_at: i64) {
        self.db
            .start_ingest_run(&IngestRun {
                id: Uuid::new_v4(),
                case_id: self.case_id,
                source_artifact_id: root,
                source_label: "x".into(),
                started_at,
                finished_at: None,
                status: IngestRun::RUNNING.into(),
                artifacts_recorded: None,
                detail: None,
            })
            .await
            .unwrap();
    }

    async fn get(&self, uri: &str) -> Value {
        let resp = self
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{uri}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn kinds(&self) -> Value {
        self.get(&format!("/api/v1/cases/{}/source_kinds", self.case_id))
            .await
    }
}

fn row(out: &Value, id: Uuid) -> Value {
    out["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("no sources: {out}"))
        .iter()
        .find(|r| r["source_artifact_id"] == json!(id))
        .cloned()
        .unwrap_or_else(|| panic!("no row for {id}: {out}"))
}

/// The Magnet 2019 two-root shape: a tar with a calendar store at depth 2, and
/// an sdcard directory with ordinary files.
async fn two_roots(h: &Harness) -> (Uuid, Uuid) {
    let tar = h
        .record(
            ArtifactType::Container,
            None,
            json!({"name": "adb-data.tar"}),
        )
        .await;
    let sdcard = h
        .record(ArtifactType::RawEvidence, None, json!({"name": "sdcard"}))
        .await;
    let db_file = h
        .record(
            ArtifactType::FileEntry,
            Some(tar),
            json!({"name": "calendar.db", "path": "apps/com.android.providers.calendar/db/calendar.db"}),
        )
        .await;
    h.record(
        ArtifactType::ParsedRecord,
        Some(db_file),
        json!({"type": "AndroidCalendarSummary", "subtype": "android_calendar_summary",
               "event_count": 3, "source": "android_calendar"}),
    )
    .await;
    h.record(
        ArtifactType::FileEntry,
        Some(sdcard),
        json!({"name": "IMG_0001.jpg", "path": "/sdcard/DCIM/IMG_0001.jpg"}),
    )
    .await;
    (tar, sdcard)
}

#[tokio::test]
async fn a_marker_record_is_attributed_to_the_root_it_descends_from_not_to_the_first_source_in_the_case(
) {
    let h = harness().await;
    let (tar, sdcard) = two_roots(&h).await;
    h.run(tar, 1_000).await;
    h.run(sdcard, 1_000).await;
    h.db.finish_ingest_runs_for_case(h.case_id, IngestRun::COMPLETED, 2_000)
        .await
        .unwrap();

    let out = h.kinds().await;
    let t = row(&out, tar);
    assert_eq!(t["label"], "android_device");
    assert_eq!(
        t["basis"][0]["records"][0]["record_type"],
        "AndroidCalendarSummary"
    );
    let s = row(&out, sdcard);
    assert_eq!(s["label"], "none_recognised");
    assert_eq!(s["kinds"], json!([]));
}

#[tokio::test]
async fn a_root_with_a_completed_ingest_run_and_no_markers_is_none_recognised() {
    let h = harness().await;
    let (_, sdcard) = two_roots(&h).await;
    h.run(sdcard, 1_000).await;
    h.db.finish_ingest_runs_for_case(h.case_id, IngestRun::COMPLETED, 2_000)
        .await
        .unwrap();
    let out = h.kinds().await;
    let s = row(&out, sdcard);
    assert_eq!(s["label"], "none_recognised");
    assert_eq!(s["assessed"], true);
    assert_eq!(s["walk_state"], "completed");
    assert!(!out["looked_for"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_root_with_no_ingest_run_is_not_assessed() {
    let h = harness().await;
    let (tar, sdcard) = two_roots(&h).await;
    let out = h.kinds().await;
    let s = row(&out, sdcard);
    assert_eq!(s["label"], "not_assessed");
    assert_eq!(s["walk_state"], "no_run_recorded");
    // A marker is still evidence without a recorded run.
    assert_eq!(row(&out, tar)["label"], "android_device");
    assert_eq!(row(&out, tar)["assessed"], false);
}

#[tokio::test]
async fn an_interrupted_run_is_not_assessed_with_its_reason() {
    let h = harness().await;
    let (_, sdcard) = two_roots(&h).await;
    h.run(sdcard, 1_000).await;
    h.db.mark_interrupted_ingest_runs(5_000, "the process stopped before the walk ended")
        .await
        .unwrap();
    let out = h.kinds().await;
    let s = row(&out, sdcard);
    assert_eq!(s["label"], "not_assessed");
    assert_eq!(s["walk_state"], "interrupted");
    assert!(s["not_assessed_reason"]
        .as_str()
        .unwrap()
        .contains("the process stopped before the walk ended"));
}

#[tokio::test]
async fn source_id_scopes_the_response() {
    let h = harness().await;
    let (tar, sdcard) = two_roots(&h).await;
    let out = h
        .get(&format!(
            "/api/v1/cases/{}/source_kinds?source_id={tar}",
            h.case_id
        ))
        .await;
    let rows = out["sources"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{out}");
    assert_eq!(rows[0]["source_artifact_id"], json!(tar));
    assert!(!out.to_string().contains(&sdcard.to_string()));
}

#[tokio::test]
async fn a_cross_case_parent_stops_the_walk() {
    let h = harness().await;
    let other_case = h.db.create_case("Other", "Examiner").await.unwrap();
    let foreign_root = h
        .record_in(
            other_case,
            ArtifactType::Container,
            None,
            json!({"name": "foreign.tar"}),
        )
        .await;
    let root = h
        .record(ArtifactType::Container, None, json!({"name": "mine.tar"}))
        .await;
    // A marker in this case whose parent is the other case's root.
    h.record(
        ArtifactType::ParsedRecord,
        Some(foreign_root),
        json!({"type": "MobileDeviceInfo", "platform": "android",
               "source_file": "/data/system/users/0/settings_system.xml"}),
    )
    .await;
    let out = h.kinds().await;
    assert_eq!(out["unattributed"], 1, "{out}");
    assert!(!out.to_string().contains(&foreign_root.to_string()));
    assert_eq!(row(&out, root)["kinds"], json!([]));
}

/// A marker whose root could not be reached may be the scoped source's, so a
/// scoped request keeps it: it neither vanishes nor lets the source read as
/// free of markers.
#[tokio::test]
async fn a_scoped_request_keeps_a_marker_whose_root_could_not_be_reached() {
    let h = harness().await;
    let other_case = h.db.create_case("Other", "Examiner").await.unwrap();
    let foreign_root = h
        .record_in(
            other_case,
            ArtifactType::Container,
            None,
            json!({"name": "foreign.tar"}),
        )
        .await;
    let (_, sdcard) = two_roots(&h).await;
    h.run(sdcard, 1_000).await;
    h.db.finish_ingest_runs_for_case(h.case_id, IngestRun::COMPLETED, 2_000)
        .await
        .unwrap();
    h.record(
        ArtifactType::ParsedRecord,
        Some(foreign_root),
        json!({"type": "AndroidSmsSummary", "file_name": "mmssms.db"}),
    )
    .await;
    let out = h
        .get(&format!(
            "/api/v1/cases/{}/source_kinds?source_id={sdcard}",
            h.case_id
        ))
        .await;
    assert_eq!(out["unattributed"], 1, "{out}");
    let s = row(&out, sdcard);
    assert_eq!(s["label"], "not_assessed", "{out}");
    assert!(s["not_assessed_reason"]
        .as_str()
        .unwrap()
        .contains("could not be traced"));
}

#[tokio::test]
async fn a_marker_listing_that_reaches_its_cap_is_named_and_no_source_is_called_free_of_markers() {
    let h = harness().await;
    let (tar, sdcard) = two_roots(&h).await;
    for _ in 0..3 {
        h.record(
            ArtifactType::ParsedRecord,
            Some(tar),
            json!({"type": "BluetoothPairing", "platform": "android",
                   "source_file": "/data/misc/bluedroid/bt_config.conf"}),
        )
        .await;
    }
    h.run(sdcard, 1_000).await;
    h.db.finish_ingest_runs_for_case(h.case_id, IngestRun::COMPLETED, 2_000)
        .await
        .unwrap();
    // The cap is lowered here: no held evidence has more marker records of one
    // type than the shipped cap.
    let out = seance_api::source_kind::assess(
        &h.db,
        h.case_id,
        vec![(tar, "adb-data.tar".into()), (sdcard, "sdcard".into())],
        None,
        2,
    )
    .await
    .unwrap();
    assert_eq!(out["capped_types"], json!(["BluetoothPairing"]));
    assert_eq!(row(&out, sdcard)["label"], "not_assessed");
    assert_eq!(row(&out, tar)["label"], "android_device");
}

/// Two records parsed from one store: the second reaches the file through the
/// memo, and must still see the store's path, or a path-corroborated marker
/// would count once and then silently stop counting.
#[tokio::test]
async fn records_from_one_store_all_carry_the_stores_path_through_the_walk_memo() {
    let h = harness().await;
    let root = h
        .record(ArtifactType::Container, None, json!({"name": "iphone.zip"}))
        .await;
    let file = h
        .record(
            ArtifactType::FileEntry,
            Some(root),
            json!({"name": "CurrentPowerlog.PLSQL",
                   "path": "/private/var/containers/Shared/SystemGroup/F3EF9636-FF64-40BB-9B94-D34F2694F64E/Library/BatteryLife/CurrentPowerlog.PLSQL"}),
        )
        .await;
    for _ in 0..2 {
        h.record(
            ArtifactType::ParsedRecord,
            Some(file),
            json!({"type": "PowerLogSummary", "subtype": "powerlog_summary", "platform": "iOS"}),
        )
        .await;
    }
    let out = h.kinds().await;
    let r = row(&out, root);
    assert_eq!(r["label"], "ios_device", "{out}");
    assert_eq!(r["basis"][0]["marker_records"], 2, "{out}");
}

/// The end-to-end check on a real case database, by hand: set
/// `SEANCE_SOURCE_KINDS_DB` to a COPY of a kept sweep database (it is migrated
/// on open) and run with `--ignored --nocapture`. The result is recorded in
/// `VALIDATION.md` (SRCKIND-1); this test prints it and asserts nothing about a
/// case it cannot see.
#[tokio::test]
#[ignore]
async fn print_the_label_for_every_case_in_a_real_database() {
    let Ok(path) = std::env::var("SEANCE_SOURCE_KINDS_DB") else {
        eprintln!("SKIP: SEANCE_SOURCE_KINDS_DB is not set");
        return;
    };
    let db = SqliteConnection::new(&format!("sqlite:{path}"))
        .await
        .unwrap();
    db.initialize().await.unwrap();
    for case in db.list_cases().await.unwrap() {
        let mut roots = Vec::new();
        let mut offset = 0;
        loop {
            let page = db
                .get_child_artifacts(case.id, None, None, offset)
                .await
                .unwrap();
            offset += page.items.len() + page.undecodable;
            let more = page.has_more;
            for a in page.items {
                let name = a.metadata["name"].as_str().unwrap_or("?").to_string();
                roots.push((a.id, name));
            }
            if !more {
                break;
            }
        }
        let started = std::time::Instant::now();
        let out = seance_api::source_kind::assess(
            &db,
            case.id,
            roots,
            None,
            seance_api::source_kind::MARKER_LISTING_CAP,
        )
        .await
        .unwrap();
        let mut brief = out.clone();
        brief.as_object_mut().unwrap().remove("looked_for");
        println!(
            "case {} ({}) in {:?}:\n{}",
            case.name,
            case.id,
            started.elapsed(),
            serde_json::to_string_pretty(&brief).unwrap()
        );
    }
}

/// The cheap path: the orchestrator's `processing_state` stamp on the root is
/// read first, and the ingest-run table only for a root without one.
#[tokio::test]
async fn the_state_stamped_on_the_root_is_read_without_the_run_table() {
    let h = harness().await;
    let done = h
        .record(
            ArtifactType::RawEvidence,
            None,
            json!({"name": "done.E01", "processing_state": "completed"}),
        )
        .await;
    h.record(
        ArtifactType::FileEntry,
        Some(done),
        json!({"name": "a", "path": "/a"}),
    )
    .await;
    let stopped = h
        .record(
            ArtifactType::RawEvidence,
            None,
            json!({"name": "stopped.E01", "processing_state": "cancelled",
                   "incomplete_detail": "processing of this source was cancelled by the examiner"}),
        )
        .await;
    h.record(
        ArtifactType::FileEntry,
        Some(stopped),
        json!({"name": "b", "path": "/b"}),
    )
    .await;
    let out = h.kinds().await;
    assert_eq!(row(&out, done)["label"], "none_recognised", "{out}");
    let s = row(&out, stopped);
    assert_eq!(s["label"], "not_assessed");
    assert_eq!(s["walk_state"], "cancelled");
    assert!(s["not_assessed_reason"]
        .as_str()
        .unwrap()
        .contains("cancelled by the examiner"));
}
