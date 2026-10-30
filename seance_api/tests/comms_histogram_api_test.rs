//! The server-side communications volume histogram.
//!
//! A histogram is a claim about WHEN things happened, and this one is quoted
//! into statements handed to courts. So these tests do not merely check that
//! bars come back: they pin the census the bars sit on, the arithmetic that
//! relates the two, and the four empty states that a bare `{buckets: []}`
//! cannot tell apart.
//!
//! Every number asserted here is hand-derived from `setup()` below, so a reader
//! can re-count the fixture rather than trust what the code produced.

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

/// Every count in the contract, by name.
///
/// Listed once and asserted on EVERY path, because the client type reads an
/// absent field as "not stated" rather than as zero — and a count the server
/// did not send is not a count of zero.
const CENSUS_FIELDS: [&str; 8] = [
    "total_records",
    "matched_records",
    "unreadable_metadata",
    "not_a_message",
    "unplaceable_absent",
    "unplaceable_value",
    "placed_by_rescue",
    "placed_as_written",
];

/// 2024-03-03T00:00:00Z, whole Unix seconds — a `date` written to contract.
const MARCH_3: i64 = 1_709_424_000;
/// 2024-03-04T00:00:00Z. Written into the fixture in MILLISECONDS, so it can
/// only be placed by assuming which unit the parser used.
const MARCH_4: i64 = 1_709_510_400;

/// A case whose eleven communications records exercise every census class the
/// contract names, plus one record of a type the comms view does not correlate.
///
/// ```text
/// iMessage (8):
///   alice x2, `date` in whole seconds          -> placed_as_written
///   bob    x1, `date` in milliseconds          -> placed_by_rescue
///   a parser tally row (`subtype` = "summary") -> not_a_message
///   a parser STATUS STUB (`status`, no subtype)-> not_a_message
///   no time key at all                         -> unplaceable_absent
///   `date` written as JSON null                -> unplaceable_absent
///   `date` = 0, a claim no reading admits      -> unplaceable_value
/// EmailMessage (1):
///   `date` = "not a date"                      -> unplaceable_value
/// CallLog (2):
///   two calls the device recorded with no time -> unplaceable_absent
/// ```
///
/// `unreadable_metadata` is deliberately absent from the fixture: it is only
/// reachable by corrupting `metadata_json` AFTER the write, which this API-level
/// test has no honest way to do. It is asserted present and zero instead.
async fn setup() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Comms Histogram", "examiner").await.unwrap();

    let rec =
        |meta: serde_json::Value| Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta);

    for _ in 0..2 {
        db.record_artifact(&rec(
            json!({"type": "iMessage", "contact": "alice", "date": MARCH_3}),
        ))
        .await
        .unwrap();
    }
    db.record_artifact(&rec(
        json!({"type": "iMessage", "contact": "bob", "date": MARCH_4 * 1000}),
    ))
    .await
    .unwrap();
    db.record_artifact(&rec(
        json!({"type": "iMessage", "contact": "alice", "subtype": "summary", "count": 99}),
    ))
    .await
    .unwrap();
    // A status stub stands for an entire unread database. Counting it as one
    // unplaced message would understate the shortfall by an unbounded amount.
    db.record_artifact(&rec(
        json!({"type": "iMessage", "contact": "alice", "status": "ParseFailed"}),
    ))
    .await
    .unwrap();
    db.record_artifact(&rec(json!({"type": "iMessage", "contact": "alice"})))
        .await
        .unwrap();
    db.record_artifact(&rec(
        json!({"type": "iMessage", "contact": "alice", "date": Value::Null}),
    ))
    .await
    .unwrap();
    db.record_artifact(&rec(
        json!({"type": "iMessage", "contact": "alice", "date": 0}),
    ))
    .await
    .unwrap();
    db.record_artifact(&rec(
        json!({"type": "EmailMessage", "contact": "carol", "date": "not a date"}),
    ))
    .await
    .unwrap();
    for _ in 0..2 {
        db.record_artifact(&rec(json!({"type": "CallLog", "contact": "Unknown"})))
            .await
            .unwrap();
    }
    // Parsed, timed, and none of the sixteen comms types: it must appear in no
    // total on this endpoint.
    db.record_artifact(&rec(json!({"type": "exif", "date": MARCH_3})))
        .await
        .unwrap();

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
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db)
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn histogram_uri(case_id: Uuid, query: &str) -> String {
    if query.is_empty() {
        format!("/api/v1/cases/{case_id}/comms/histogram")
    } else {
        format!("/api/v1/cases/{case_id}/comms/histogram?{query}")
    }
}

fn n(body: &Value, field: &str) -> i64 {
    body[field]
        .as_i64()
        .unwrap_or_else(|| panic!("'{field}' is not a stated number: {body}"))
}

/// `by_type_unplaceable` as pairs, refusing anything that is not the wire shape
/// the client parses (`statedByType`, frontend/src/pages/analysis/api.ts). A
/// breakdown the page cannot read is a breakdown the page drops whole, so a
/// malformed pair here is a failure, not a missing entry.
fn unplaceable_types(body: &Value) -> Vec<(String, i64)> {
    body["by_type_unplaceable"]
        .as_array()
        .unwrap_or_else(|| panic!("'by_type_unplaceable' is not an array: {body}"))
        .iter()
        .map(|pair| {
            let p = pair
                .as_array()
                .unwrap_or_else(|| panic!("each entry must be a [type, count] pair: {body}"));
            assert_eq!(
                p.len(),
                2,
                "each entry must be a [type, count] pair: {body}"
            );
            (
                p[0].as_str()
                    .unwrap_or_else(|| panic!("the type must be a string: {body}"))
                    .to_string(),
                p[1].as_i64()
                    .unwrap_or_else(|| panic!("the count must be a number: {body}")),
            )
        })
        .collect()
}

fn bars(body: &Value) -> Vec<(i64, i64, i64)> {
    body["buckets"]
        .as_array()
        .unwrap_or_else(|| panic!("'buckets' is not an array: {body}"))
        .iter()
        .map(|b| {
            (
                b["bucket_start_secs"].as_i64().unwrap(),
                b["count"].as_i64().unwrap(),
                b["rescued_count"].as_i64().unwrap(),
            )
        })
        .collect()
}

/// The contract's invariants, asserted against one response.
///
/// Called by every test that fetches a histogram, because an identity that
/// holds on the happy path and quietly fails under a filter is worse than no
/// identity at all: the numbers still look like numbers.
fn assert_invariants(body: &Value) {
    for field in CENSUS_FIELDS {
        assert!(
            body.get(field).map(|v| v.is_i64()).unwrap_or(false),
            "'{field}' must be stated on every path; absent is not zero: {body}"
        );
    }
    assert!(
        body.get("bucket_seconds").is_some()
            && body.get("min_ts_secs").is_some()
            && body.get("max_ts_secs").is_some()
            && body.get("by_type_unplaceable").is_some(),
        "every contract field must be present, null where it has no value: {body}"
    );

    let matched = n(body, "matched_records");
    let classes: i64 = CENSUS_FIELDS[2..].iter().map(|f| n(body, f)).sum();
    assert_eq!(
        matched, classes,
        "the classes must sum to the matched population: {body}"
    );

    let placed = n(body, "placed_by_rescue") + n(body, "placed_as_written");
    let drawn: i64 = bars(body).iter().map(|(_, c, _)| c).sum();
    let rescued: i64 = bars(body).iter().map(|(_, _, r)| r).sum();
    assert_eq!(
        drawn, placed,
        "the bars must sum to the placed records: {body}"
    );
    assert_eq!(
        rescued,
        n(body, "placed_by_rescue"),
        "the rescued part of the bars must sum to the rescued class: {body}"
    );

    assert!(
        n(body, "total_records") >= matched,
        "the case total can never be smaller than the matched part of it: {body}"
    );

    // The breakdown decomposes ONE class, `unplaceable_value`, and must sum to
    // it exactly. That is the whole reason it is served: a list of parts that
    // does not add up to its own total is worse than no list, because it
    // invites the reader to trust the parts. It holds by construction — the
    // parts and the total come from one pass of one statement — so a failure
    // here means the two stopped describing the same population.
    let by_type = unplaceable_types(body);
    assert_eq!(
        by_type.iter().map(|(_, n)| n).sum::<i64>(),
        n(body, "unplaceable_value"),
        "the per-type breakdown must sum to the class it decomposes: {body}"
    );
    // Count descending, then type name ascending — the order the ranking beside
    // it uses. A sentence quoted into a statement must read the same tomorrow.
    let mut ordered = by_type.clone();
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    assert_eq!(
        by_type, ordered,
        "the breakdown must arrive in a fixed order: {body}"
    );

    assert_eq!(
        body["min_ts_secs"].is_null(),
        drawn == 0,
        "an extent exists exactly when something was placed: {body}"
    );
    assert_eq!(
        body["max_ts_secs"].is_null(),
        drawn == 0,
        "an extent exists exactly when something was placed: {body}"
    );
    assert_eq!(
        body["bucket_seconds"].is_null(),
        drawn == 0,
        "a bucket width is stated exactly when there are bars to width: {body}"
    );
}

#[tokio::test]
async fn every_class_is_counted_where_the_reader_would_count_it() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_invariants(&body);

    // Eleven comms records; the exif row is not one of them.
    assert_eq!(n(&body, "total_records"), 11);
    assert_eq!(n(&body, "matched_records"), 11);
    // Only reachable by corrupting metadata_json after the write.
    assert_eq!(n(&body, "unreadable_metadata"), 0);
    // The parser tally row and the status stub.
    assert_eq!(n(&body, "not_a_message"), 2);
    // Two iMessages that never claimed a time (one absent key, one JSON null)
    // and the two calls the device recorded with no time.
    assert_eq!(n(&body, "unplaceable_absent"), 4);
    // `date: 0` and `date: "not a date"` — both CLAIMED a time.
    assert_eq!(n(&body, "unplaceable_value"), 2);
    assert_eq!(n(&body, "placed_by_rescue"), 1);
    assert_eq!(n(&body, "placed_as_written"), 2);

    assert_eq!(n(&body, "min_ts_secs"), MARCH_3);
    assert_eq!(n(&body, "max_ts_secs"), MARCH_4);
}

#[tokio::test]
async fn a_rescued_placement_is_drawn_and_disclosed() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Span 86,400s over the default 120 buckets rounds UP to the friendly
    // quarter-hour, and both instants are exact multiples of it.
    assert_eq!(n(&body, "bucket_seconds"), 900);
    assert_eq!(bars(&body), vec![(MARCH_3, 2, 0), (MARCH_4, 1, 1)]);
}

#[tokio::test]
async fn a_search_term_narrows_the_bars_and_never_the_case_total() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "q=ALI")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_invariants(&body);

    // LIVE-024: a total that shrank while an examiner typed would read as
    // evidence disappearing.
    assert_eq!(n(&body, "total_records"), 11);
    // Seven alice records: two placed, two not-a-message, two silent, one
    // unreadable value. Case-folded for A-Z, so "ALI" finds "alice".
    assert_eq!(n(&body, "matched_records"), 7);
    assert_eq!(n(&body, "placed_as_written"), 2);
    assert_eq!(n(&body, "placed_by_rescue"), 0);
    assert_eq!(n(&body, "not_a_message"), 2);
    assert_eq!(n(&body, "unplaceable_absent"), 2);
    assert_eq!(n(&body, "unplaceable_value"), 1);

    // A single instant is a zero-width span; the width falls to the smallest
    // friendly unit rather than to zero.
    assert_eq!(n(&body, "bucket_seconds"), 60);
    assert_eq!(bars(&body), vec![(MARCH_3, 2, 0)]);
}

#[tokio::test]
async fn an_exact_contact_narrows_the_bars_too() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "contact=bob")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_invariants(&body);

    assert_eq!(n(&body, "total_records"), 11);
    assert_eq!(n(&body, "matched_records"), 1);
    assert_eq!(n(&body, "placed_by_rescue"), 1);
    assert_eq!(bars(&body), vec![(MARCH_4, 1, 1)]);

    // An emptied selection is a deselection, not a search for the empty string.
    let (status, cleared) = get(&app, histogram_uri(case_id, "contact=&q=")).await;
    assert_eq!(status, StatusCode::OK, "body: {cleared}");
    assert_eq!(n(&cleared, "matched_records"), 11);
}

#[tokio::test]
async fn the_two_totals_are_equal_only_when_nothing_narrows_them() {
    let (app, case_id, _db) = setup().await;
    for query in ["", "channel=iMessage"] {
        let (_s, body) = get(&app, histogram_uri(case_id, query)).await;
        assert_eq!(
            n(&body, "total_records"),
            n(&body, "matched_records"),
            "'{query}' narrows by channel alone, so both totals describe it: {body}"
        );
    }
    for query in ["q=ali", "contact=bob", "channel=iMessage&q=bob"] {
        let (_s, body) = get(&app, histogram_uri(case_id, query)).await;
        assert!(
            n(&body, "total_records") > n(&body, "matched_records"),
            "'{query}' narrows the matched population only: {body}"
        );
    }
}

#[tokio::test]
async fn records_exist_but_none_placeable_is_not_no_communications_at_all() {
    let (app, case_id, _db) = setup().await;

    // Two calls, both real evidence, neither carrying a time.
    let (status, unplaceable) = get(&app, histogram_uri(case_id, "channel=CallLog")).await;
    assert_eq!(status, StatusCode::OK, "body: {unplaceable}");
    assert_invariants(&unplaceable);
    assert_eq!(n(&unplaceable, "total_records"), 2);
    assert_eq!(n(&unplaceable, "matched_records"), 2);
    assert_eq!(n(&unplaceable, "unplaceable_absent"), 2);
    assert_eq!(unplaceable["buckets"], json!([]));
    assert!(unplaceable["bucket_seconds"].is_null());

    // A channel this case holds nothing of at all.
    let (status, absent) = get(&app, histogram_uri(case_id, "channel=Snapchat")).await;
    assert_eq!(status, StatusCode::OK, "body: {absent}");
    assert_invariants(&absent);
    assert_eq!(n(&absent, "total_records"), 0);
    for field in CENSUS_FIELDS {
        assert_eq!(n(&absent, field), 0, "{field}: {absent}");
    }
    assert_eq!(absent["buckets"], json!([]));

    // A filter nobody matched, over a case that is full of records.
    let (status, unmatched) = get(&app, histogram_uri(case_id, "q=zzz")).await;
    assert_eq!(status, StatusCode::OK, "body: {unmatched}");
    assert_invariants(&unmatched);
    assert_eq!(n(&unmatched, "total_records"), 11);
    assert_eq!(n(&unmatched, "matched_records"), 0);
    assert_eq!(unmatched["buckets"], json!([]));

    // The three states must be separable by the payload alone — which is
    // exactly what `{buckets: []}` on its own cannot do.
    assert_ne!(unplaceable, absent);
    assert_ne!(unplaceable, unmatched);
    assert_ne!(absent, unmatched);
}

#[tokio::test]
async fn the_empty_extent_path_still_carries_the_full_census() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "channel=CallLog")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The timeline handler early-returns before it computes anything; this one
    // must not, or "records exist, none placeable" arrives indistinguishable
    // from "no communications at all".
    //
    // The counts are asserted by VALUE and not merely by presence: a census
    // zeroed on this path is as present, as well-formed and as wrong as no
    // census at all, and it is the reading that erases two calls from the
    // record.
    assert_eq!(n(&body, "total_records"), 2, "{body}");
    assert_eq!(n(&body, "matched_records"), 2, "{body}");
    assert_eq!(n(&body, "unplaceable_absent"), 2, "{body}");
    for field in CENSUS_FIELDS {
        assert!(
            body[field].is_i64(),
            "'{field}' must survive the empty-extent path: {body}"
        );
    }
    assert!(body["min_ts_secs"].is_null() && body["max_ts_secs"].is_null());
}

#[tokio::test]
async fn the_bucket_width_is_a_friendly_unit_chosen_from_the_extent() {
    let (app, case_id, _db) = setup().await;
    // Span 86,400s. Fewer bars means wider ones, and every width is one of the
    // nine friendly units — never the raw quotient.
    for (query, expected) in [
        ("", 900),
        ("buckets=120", 900),
        ("buckets=10", 21600),
        ("buckets=500", 300),
        // Clamped: below the floor and above the ceiling.
        ("buckets=1", 21600),
        ("buckets=100000", 300),
        // Unreadable, so the default stands rather than the request failing.
        ("buckets=lots", 900),
    ] {
        let (status, body) = get(&app, histogram_uri(case_id, query)).await;
        assert_eq!(status, StatusCode::OK, "'{query}': {body}");
        assert_eq!(n(&body, "bucket_seconds"), expected, "'{query}': {body}");
        assert_invariants(&body);
    }
}

#[tokio::test]
async fn the_unit_is_in_every_name_that_carries_one() {
    let (app, case_id, _db) = setup().await;
    let (_s, body) = get(&app, histogram_uri(case_id, "")).await;

    // The chart works in milliseconds; the server answers in seconds. A 1000x
    // mix renders 2024 as 1970-01-20, and the only defence that survives a
    // refactor is the unit being unskippable in the name.
    for absent in ["min_ts", "max_ts", "start", "bucket_start", "buckets_ms"] {
        assert!(
            body.get(absent).is_none(),
            "'{absent}' names no unit and must not be served: {body}"
        );
    }
    let bar = &body["buckets"][0];
    assert!(bar["bucket_start_secs"].is_i64(), "{bar}");
    assert!(bar.get("start").is_none(), "{bar}");
}

#[tokio::test]
async fn an_unparsed_channel_is_refused_by_name_not_answered_with_an_empty_chart() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, histogram_uri(case_id, "channel=Mastodon")).await;

    // An empty chart would read as "this case holds no messages of that kind",
    // which is a claim about the evidence that nobody checked.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let text = body.to_string();
    assert!(
        text.contains("Mastodon"),
        "must name what was rejected: {text}"
    );
    for accepted in ["iMessage", "WhatsApp", "TwitterDM"] {
        assert!(
            text.contains(accepted),
            "must name the accepted values, missing {accepted}: {text}"
        );
    }
}

/// `by_type_unplaceable` is the deliverable sentence's data — "2 records
/// carried a value no reading of which is admissible (EmailMessage 1,
/// iMessage 1)". It breaks down `unplaceable_value` AND ONLY THAT CLASS, which
/// is where the page prints it (`describeUnplaceableTypes`, CommsPage.tsx), and
/// it comes from the same pass as the total it decomposes.
///
/// The numbers below are counted off the fixture by hand, not derived the way
/// the code derives them: the fixture holds exactly two records that claimed a
/// time nobody can read — one iMessage writing `date: 0` and one EmailMessage
/// writing `date: "not a date"`.
#[tokio::test]
async fn the_per_type_breakdown_decomposes_the_unreadable_value_class() {
    let (app, case_id, _db) = setup().await;

    let (status, body) = get(&app, histogram_uri(case_id, "")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_invariants(&body);
    assert_eq!(n(&body, "unplaceable_value"), 2);
    // Both counts are 1, so the tiebreak decides the order: type name
    // ascending, in byte order.
    assert_eq!(
        body["by_type_unplaceable"],
        json!([["EmailMessage", 1], ["iMessage", 1]]),
        "{body}"
    );

    // It follows the MATCHED population, exactly as the class it decomposes
    // does. "ali" reaches the iMessage that wrote `date: 0` and not carol's
    // email; "carol" reaches the email and nothing else.
    let (_s, alice) = get(&app, histogram_uri(case_id, "q=ali")).await;
    assert_invariants(&alice);
    assert_eq!(n(&alice, "unplaceable_value"), 1);
    assert_eq!(alice["by_type_unplaceable"], json!([["iMessage", 1]]));

    let (_s, carol) = get(&app, histogram_uri(case_id, "contact=carol")).await;
    assert_invariants(&carol);
    assert_eq!(n(&carol, "unplaceable_value"), 1);
    assert_eq!(carol["by_type_unplaceable"], json!([["EmailMessage", 1]]));
}

/// An empty breakdown is a claim too: "nothing in this population carried an
/// unreadable time". It must be an empty ARRAY on every such path, never a
/// missing field and never a list of types with a zero beside them — the two
/// calls the device recorded with no time at all are a DIFFERENT finding, and
/// naming CallLog in this list would file them under the wrong one.
#[tokio::test]
async fn a_class_with_nothing_in_it_is_broken_down_into_nothing() {
    let (app, case_id, _db) = setup().await;
    for query in [
        // Two calls, both unplaceable, both because no time was ever written.
        "channel=CallLog",
        // A channel the case holds nothing of.
        "channel=Snapchat",
        // A search nobody matched.
        "q=zzz",
    ] {
        let (_s, body) = get(&app, histogram_uri(case_id, query)).await;
        assert_invariants(&body);
        assert_eq!(n(&body, "unplaceable_value"), 0, "'{query}': {body}");
        assert_eq!(
            body["by_type_unplaceable"],
            json!([]),
            "'{query}' has nothing to break down: {body}"
        );
    }

    // The calls ARE reported — under the class that describes them.
    let (_s, calls) = get(&app, histogram_uri(case_id, "channel=CallLog")).await;
    assert_eq!(n(&calls, "unplaceable_absent"), 2, "{calls}");
}

#[tokio::test]
async fn reading_the_histogram_is_audited() {
    let (app, case_id, db) = setup().await;
    let (status, _body) = get(
        &app,
        histogram_uri(case_id, "channel=iMessage&q=ali&contact=alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let rows = db
        .get_audit_log_filtered(
            case_id,
            None,
            Some("comms_histogram_executed"),
            None,
            None,
            None,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one read, one audit row: {rows:?}");
    let details = rows[0]["details"].as_str().unwrap_or_default().to_string();
    for asked in ["iMessage", "ali", "alice"] {
        assert!(
            details.contains(asked),
            "the audit row must record what was asked for, missing '{asked}': {details}"
        );
    }
}

/// The route carries no access check of its own; it inherits the router-level
/// per-case gate every `/api/v1/cases/:id/...` route sits behind. Pinned here
/// because when a device's traffic peaked is disclosive on its own, and
/// inheriting a guard is only safe while the route is actually inside it.
#[tokio::test]
async fn an_examiner_with_no_grant_on_the_case_is_refused() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let case_id = db.create_case("Comms Histogram", "examiner").await.unwrap();

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
        jwt_secret: "comms-histogram-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled: true,
    };
    let app = router_with_auth(app_state, Some(auth_config.clone()));
    let (token, _) = auth_config.generate_token("erin", "examiner").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(histogram_uri(case_id, ""))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
