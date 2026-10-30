//! An email thread read as a thread (`ROADMAP.md` §5.14).
//!
//! Email parses with headers, bodies and attachments, and the Comms table told
//! an examiner per row that "calls and email have no conversation view; the
//! record itself is the whole of what was recovered". So the one channel most
//! likely to carry a long exchange was the one that could not be read as an
//! exchange.
//!
//! What made it not a viewer registration is that email has no thread *field*.
//! Every other channel has one — a chat identifier, a JID, a thread id — and
//! the conversation queries group on a `COALESCE` over JSON paths. Email has a
//! *chain*: each message names its parent and, by convention, carries its whole
//! ancestry. So the root is derived in the parser that holds the headers and
//! published as one string the existing machinery can group on.
//!
//! Two assertions here carry the weight.
//! [`a_message_with_no_threading_headers_is_not_invented_into_a_thread`]:
//! grouping every header-less message under one catch-all key would present a
//! conversation that never existed, which is worse than no thread view.
//! [`an_email_thread_pages_by_when_the_messages_were_sent`]: the conversation
//! queries order on one integer expression across every channel, and casting
//! an RFC 3339 string to an integer yields its *year*.

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

/// One email record as the readers write one, threaded by
/// `seance_plugin_email::thread`.
fn email(
    subject: &str,
    message_id: &str,
    in_reply_to: &str,
    references: &[&str],
    epoch: i64,
) -> Artifact {
    let refs: Vec<String> = references.iter().map(|r| r.to_string()).collect();
    let mut m = json!({
        "type": "EmailMessage",
        "analysis_type": "email",
        "subtype": "email_message",
        "from": "alice@example.com",
        "to": ["bob@example.com"],
        "subject": subject,
        "date": chrono::DateTime::from_timestamp(epoch, 0).unwrap().to_rfc3339(),
        "date_epoch": epoch,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": refs.clone(),
        "body_text": format!("the body of {subject}"),
    });
    seance_plugin_email::thread::stamp(m.as_object_mut().unwrap(), message_id, in_reply_to, &refs);
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, m)
}

async fn setup(records: Vec<Artifact>) -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Mailbox", "examiner").await.unwrap();
    for a in records {
        let mut a = a;
        a.case_id = case_id;
        db.record_artifact(&a).await.unwrap();
    }
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app = router_with_auth(
        AppState {
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
        },
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    (app, case_id)
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

/// A three-message exchange reaches the conversation list as one thread,
/// labelled by the newest message's subject.
#[tokio::test]
async fn an_exchange_is_one_thread_named_by_its_newest_subject() {
    let (app, case_id) = setup(vec![
        email("Invoice 4471", "<root@ex>", "", &[], 1_700_000_000),
        email(
            "Re: Invoice 4471",
            "<r1@ex>",
            "<root@ex>",
            &["<root@ex>"],
            1_700_000_100,
        ),
        email(
            "Re: Invoice 4471 (paid)",
            "<r2@ex>",
            "<r1@ex>",
            &["<root@ex>", "<r1@ex>"],
            1_700_000_200,
        ),
        // A separate exchange, so the grouping is doing work.
        email("Lunch", "<other@ex>", "", &[], 1_700_000_050),
    ])
    .await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/conversations?type=EmailMessage"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let threads = body["conversations"].as_array().unwrap();
    assert_eq!(threads.len(), 2, "{body}");
    // Newest exchange first.
    assert_eq!(threads[0]["key"], json!("root@ex"));
    assert_eq!(threads[0]["count"], json!(3));
    // The thread is named by the newest message's subject — the line a reader
    // recognises the exchange by — not by the lexicographic maximum of every
    // subject in it.
    assert_eq!(threads[0]["label"], json!("Re: Invoice 4471 (paid)"));
    assert_eq!(threads[1]["key"], json!("other@ex"));
    assert_eq!(threads[1]["count"], json!(1));
    // Nothing was left out of a thread, and the response says so rather than
    // staying silent.
    assert_eq!(body["unthreadable"], json!(0));
    assert!(body["unthreadable_note"].is_null());
}

/// The reason this is not a `COALESCE` over JSON paths: the conversation
/// queries order on one integer expression across every channel, and chat
/// records keep `$.date` as unix seconds. `CAST('2026-03-02T…' AS INTEGER)` is
/// `2026` — a valid integer COALESCE would accept — so an email thread would
/// page in an order with nothing to do with when the messages were sent.
#[tokio::test]
async fn an_email_thread_pages_by_when_the_messages_were_sent() {
    let (app, case_id) = setup(vec![
        email("First", "<root@ex>", "", &[], 1_700_000_000),
        email(
            "Second",
            "<r1@ex>",
            "<root@ex>",
            &["<root@ex>"],
            1_700_086_400,
        ),
        email(
            "Third",
            "<r2@ex>",
            "<r1@ex>",
            &["<root@ex>", "<r1@ex>"],
            1_700_172_800,
        ),
    ])
    .await;

    let (status, body) = get(
        &app,
        format!(
            "/api/v1/cases/{case_id}/conversations/messages?type=EmailMessage&key=root@ex&limit=10"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let msgs = body["records"].as_array().unwrap();
    assert_eq!(msgs.len(), 3, "{body}");
    // Newest first, which is the order the viewer loads a thread in.
    let subjects: Vec<&str> = msgs
        .iter()
        .map(|m| m["metadata"]["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, vec!["Third", "Second", "First"]);
}

/// Grouping every header-less message under one catch-all key would present a
/// conversation that never existed. They get no key, are absent from the
/// thread list, and the list says how many it could not place.
#[tokio::test]
async fn a_message_with_no_threading_headers_is_not_invented_into_a_thread() {
    let (app, case_id) = setup(vec![
        email("Invoice", "<root@ex>", "", &[], 1_700_000_000),
        email("Orphan one", "", "", &[], 1_700_000_100),
        email("Orphan two", "", "", &[], 1_700_000_200),
    ])
    .await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/conversations?type=EmailMessage"),
    )
    .await;
    let threads = body["conversations"].as_array().unwrap();
    assert_eq!(threads.len(), 1, "no catch-all thread: {body}");
    assert_eq!(threads[0]["key"], json!("root@ex"));

    // And the two are accounted for rather than silently dropped.
    assert_eq!(body["unthreadable"], json!(2));
    let note = body["unthreadable_note"].as_str().unwrap();
    assert!(note.contains("NOT counted in the threads above"), "{note}");
    assert!(note.contains("subset"), "{note}");
}

/// A chat channel's key expression ends in a literal, so every record groups
/// somewhere and the disclosure is zero rather than absent: "nothing was set
/// aside" is a positive statement.
#[tokio::test]
async fn a_chat_channel_reports_nothing_left_out_rather_than_nothing_at_all() {
    let (app, case_id) = setup(vec![Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "WhatsApp",
            "contact_jid": "4470000@s.whatsapp.net",
            "text": "hello",
            "date": 1_700_000_000i64,
        }),
    )])
    .await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/conversations?type=WhatsApp"),
    )
    .await;
    assert_eq!(body["conversations"].as_array().unwrap().len(), 1);
    assert_eq!(body["unthreadable"], json!(0));
    assert!(body["unthreadable_note"].is_null());
}

/// A reply carrying only `In-Reply-To` threads with its parent, and the basis
/// on the record says the thread may be part of a longer exchange. The basis is
/// what stops a split thread reading as a whole one.
#[tokio::test]
async fn a_reply_with_no_references_header_threads_and_declares_the_limit() {
    let (app, case_id) = setup(vec![
        email("Invoice", "<root@ex>", "", &[], 1_700_000_000),
        email("Re: Invoice", "<r1@ex>", "<root@ex>", &[], 1_700_000_100),
        // A reply to the reply, still with no References: it keys on its own
        // parent and is therefore a second thread. That is the limit, and it is
        // declared rather than hidden.
        email("Re: Re: Invoice", "<r2@ex>", "<r1@ex>", &[], 1_700_000_200),
    ])
    .await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/conversations?type=EmailMessage"),
    )
    .await;
    let threads = body["conversations"].as_array().unwrap();
    assert_eq!(threads.len(), 2, "the limit is real: {body}");

    // The record itself carries the basis and the sentence for it.
    let (_, msgs) = get(
        &app,
        format!(
            "/api/v1/cases/{case_id}/conversations/messages?type=EmailMessage&key=root@ex&limit=10"
        ),
    )
    .await;
    let reply = msgs["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["metadata"]["subject"] == "Re: Invoice")
        .expect("the reply threads with its parent");
    assert_eq!(
        reply["metadata"]["email_thread_basis"],
        json!("in_reply_to")
    );
    assert!(reply["metadata"]["email_thread_basis_note"]
        .as_str()
        .unwrap()
        .contains("more than one thread"));
}
