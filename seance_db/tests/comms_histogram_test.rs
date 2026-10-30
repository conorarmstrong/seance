//! The comms volume histogram: the bars, the ordered census behind them, and
//! the extent the API sizes buckets from.
//!
//! Every assertion here is about a sentence someone could end up writing down.
//! A bar is a claim that N communications happened in a named span; a census
//! line is a claim about how many records the chart could NOT place, and why.
//! The two failure modes this file exists to prevent are a record counted twice
//! (a census that sums to more than the case holds) and a record dropped
//! silently (a shortfall the chart does not disclose).

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{SqliteConnection, COMMS_TIME_KEYS};
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Histogram", "Examiner").await?;
    Ok((db, case_id))
}

fn artifact(case_id: Uuid, metadata: serde_json::Value) -> Artifact {
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata,
        data: None,
    }
}

async fn record(db: &SqliteConnection, case_id: Uuid, metadata: serde_json::Value) -> Result<()> {
    db.record_artifact(&artifact(case_id, metadata)).await
}

/// 2024-03-05T12:00:00Z, the corpus's reference instant.
const T: i64 = 1_709_640_000;
const DAY: i64 = 86_400;

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Buckets are floor-aligned on the epoch and empty interiors are omitted — the
/// same contract `get_timeline_histogram` already keeps, because the client
/// gap-fills interiors and would draw a phantom zero-width span otherwise.
#[tokio::test]
async fn buckets_are_epoch_floor_aligned_and_empty_interiors_are_omitted() -> Result<()> {
    let (db, case_id) = setup().await?;
    // Two instants on one day, one three days later. Day two and day three hold
    // nothing at all.
    for secs in [T, T + 3600, T + 3 * DAY] {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": secs}),
        )
        .await?;
    }

    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;

    let floor = |t: i64| t - t.rem_euclid(DAY);
    assert_eq!(
        bars.iter()
            .map(|b| (b.bucket_start_secs, b.count))
            .collect::<Vec<_>>(),
        vec![(floor(T), 2), (floor(T + 3 * DAY), 1)],
        "the two empty interior days must be absent, not zero-count rows"
    );
    assert_eq!(bars[0].bucket_start_secs % DAY, 0);
    Ok(())
}

/// Floor division, not truncation toward zero. SQLite's `/` and `%` truncate
/// toward zero, so a pre-1970 instant would be filed in the bucket AFTER the one
/// containing it — the record would move forward in time by up to a bucket.
#[tokio::test]
async fn a_pre_epoch_instant_floors_backwards_not_towards_zero() -> Result<()> {
    let (db, case_id) = setup().await?;
    // 0100-01-01T00:00:00Z, a corpus shape: the reader has no floor, and this
    // chart must not invent one.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a",
               "date": "0100-01-01T00:00:00Z"}),
    )
    .await?;
    // One second before the epoch, reached through a written date-time because
    // a bare negative number is below the reader's band.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a",
               "date": "1969-12-31T23:59:59Z"}),
    )
    .await?;

    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;

    let starts: Vec<i64> = bars.iter().map(|b| b.bucket_start_secs).collect();
    assert!(
        starts.iter().all(|s| s % DAY == 0),
        "every bucket start must be a multiple of the bucket width, got {starts:?}"
    );
    assert!(
        starts.contains(&(-DAY)),
        "-1 s must floor to the day that STARTS at -86400, not to 0; got {starts:?}"
    );
    assert!(
        starts.iter().all(|s| *s <= 0),
        "a chart that silently dropped pre-1970 records would report a case as \
         empty in the years it actually covers; got {starts:?}"
    );
    Ok(())
}

/// `get_timeline_activity` carries an undisclosed `timestamp > 0` filter. Copying
/// it here would silently delete every genuine pre-1970 record from the chart.
#[tokio::test]
async fn there_is_no_undisclosed_positive_timestamp_filter() -> Result<()> {
    let (db, case_id) = setup().await?;
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a",
               "date": "1970-01-01T00:00:00Z"}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(census.placed_as_written, 1);
    assert_eq!(
        census.min_ts_secs,
        Some(0),
        "the epoch itself is an instant"
    );

    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;
    assert_eq!(bars.len(), 1);
    assert_eq!(bars[0].count, 1);
    Ok(())
}

#[tokio::test]
async fn a_non_positive_bucket_width_is_refused_rather_than_answered() -> Result<()> {
    let (db, case_id) = setup().await?;
    assert!(db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, 0)
        .await
        .is_err());
    assert!(db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, -60)
        .await
        .is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// The ordered census
// ---------------------------------------------------------------------------

/// v1's census was arithmetically FALSE: a CallLog summary row has no `date`
/// key, so it satisfied both "summary" and "no time key" and was counted twice —
/// 8 rows in, 11 out. The chain is ordered, so every record lands in exactly one
/// class and the classes sum to the population.
#[tokio::test]
async fn a_summary_row_with_no_time_key_is_counted_once_not_twice() -> Result<()> {
    let (db, case_id) = setup().await?;
    // The exact shape seance_plugin_call_history writes: a tally OF calls, with
    // no date of its own.
    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "summary", "contact": "Unknown",
               "total_calls": 7}),
    )
    .await?;
    for i in 0..7 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": "+353860000000",
                   "timestamp": T + i}),
        )
        .await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, Some("CallLog"), None, None)
        .await?;

    assert_eq!(census.total_records, 8);
    assert_eq!(census.matched_records, 8);
    assert_eq!(census.not_a_message, 1);
    assert_eq!(
        census.unplaceable_absent, 0,
        "the summary row carries no `date` key, but it is NOT a communication \
         that failed to place — counting it in both classes is what made v1's \
         census sum to 11 on an 8-record case"
    );
    assert_eq!(census.placed_as_written, 7);
    assert_eq!(census.class_sum(), 8);
    Ok(())
}

/// Four plugins emit records whose `$.type` IS a comms type but which are
/// database status markers: `Identified` (no data source) and `ParseFailed` (a
/// store this tool could not read). They carry `$.status` and no `$.subtype`.
///
/// A `ParseFailed` stub stands for an ENTIRE UNREAD DATABASE. Reporting it as
/// one unplaced communication understates the shortfall by an unbounded amount,
/// which is precisely the wrong sentence to put in front of a court.
#[tokio::test]
async fn parser_status_stubs_are_not_messages() -> Result<()> {
    let (db, case_id) = setup().await?;
    for (ty, status) in [
        ("CallLog", "Identified"),
        ("CallLog", "ParseFailed"),
        ("AndroidSms", "Identified"),
        ("AndroidSms", "ParseFailed"),
        ("WhatsApp", "Identified"),
        ("WhatsApp", "ParseFailed"),
        ("iMessage", "Identified"),
        ("iMessage", "ParseFailed"),
    ] {
        record(
            &db,
            case_id,
            json!({"type": ty, "status": status, "file_name": "store.db",
                   "name": format!("{ty} Database ({status})")}),
        )
        .await?;
    }
    // A real message that also carries a `status` column value — android_sms and
    // whatsapp both write one on genuine messages. The discriminator is the
    // ABSENT subtype, not the presence of a status.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a",
               "status": 13, "date": T}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;

    assert_eq!(census.not_a_message, 8);
    assert_eq!(
        census.unplaceable_absent, 0,
        "eight status stubs reported as unplaced communications would read as \
         eight missing messages, when each one stands for a whole database"
    );
    assert_eq!(census.placed_as_written, 1);
    assert_eq!(census.class_sum(), census.matched_records);
    assert_eq!(census.matched_records, 9);
    Ok(())
}

/// The three-valued answer, kept apart: a key that was there and could not be
/// read is a different finding from a record that never claimed a time.
#[tokio::test]
async fn a_value_that_cannot_be_read_is_not_the_same_finding_as_no_key_at_all() -> Result<()> {
    let (db, case_id) = setup().await?;
    for meta in [
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": "nope"}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": 0}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": null}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a"}),
    ] {
        record(&db, case_id, meta).await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;

    assert_eq!(census.unplaceable_value, 2, "`nope` and `0`");
    assert_eq!(
        census.unplaceable_absent, 2,
        "JSON null means the parser recorded no time; it must never read as \
         1970-01-01, and it must not read as an unreadable value either"
    );
    assert_eq!(census.class_sum(), 4);
    Ok(())
}

/// A rescued instant is a weaker fact than one read to contract, and it is drawn
/// on the chart WITH its own count so a reader can size the assumption.
#[tokio::test]
async fn rescued_instants_are_drawn_and_counted_separately() -> Result<()> {
    let (db, case_id) = setup().await?;
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": T}),
    )
    .await?;
    // Milliseconds: the same instant, reachable only by assuming the unit.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a",
               "date": T * 1000}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(census.placed_as_written, 1);
    assert_eq!(census.placed_by_rescue, 1);

    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;
    assert_eq!(bars.len(), 1, "both land in the same day");
    assert_eq!(bars[0].count, 2);
    assert_eq!(
        bars[0].rescued_count, 1,
        "a bar of 2 whose evidence is one contract reading and one guess must \
         be able to say so"
    );
    Ok(())
}

/// The browser's rule is "first key that YIELDS AN INSTANT wins", not "first
/// non-null wins". The window has to be applied INSIDE each branch, before the
/// COALESCE, or this record lands fifty years from where the viewer shows it.
#[tokio::test]
async fn key_precedence_applies_the_window_inside_each_branch() -> Result<()> {
    let (db, case_id) = setup().await?;
    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "call", "contact": "a",
               "date": 0, "timestamp": 1_600_000_000}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(
        census.min_ts_secs,
        Some(1_600_000_000),
        "a naive COALESCE takes `date: 0` as the first non-null value and files \
         this call in 1970; the browser files it in 2020"
    );
    assert_eq!(census.placed_as_written, 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// The per-type breakdown of the two unplaceable findings
// ---------------------------------------------------------------------------

/// The counts in a breakdown, summed — the only number that makes a breakdown
/// quotable. A list of parts that does not add up to the total it decomposes is
/// worse than no list at all, because it invites the reader to trust the parts.
fn breakdown_sum(by_type: &[(String, i64)]) -> i64 {
    by_type.iter().map(|(_, n)| *n).sum()
}

/// The sentence this exists to support — "2 records carried a value no reading
/// of which is admissible (EmailMessage 3, iMessage 1)" — and the arithmetic
/// that makes it quotable: the parts sum to the class they decompose.
///
/// The breakdown comes from the SAME PASS as the class total, which is why the
/// sum is an identity rather than a coincidence. A per-type set fetched by a
/// second query could disagree with the census it is meant to explain, and two
/// contradicting exact figures on one screen is the failure this whole feature
/// exists to avoid.
#[tokio::test]
async fn each_unplaceable_class_is_broken_down_by_type_and_the_parts_sum_to_it() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..3 {
        record(
            &db,
            case_id,
            json!({"type": "EmailMessage", "subtype": "message", "contact": format!("c{i}"),
                   "date": "not a date"}),
        )
        .await?;
    }
    record(
        &db,
        case_id,
        json!({"type": "iMessage", "subtype": "message", "contact": "alice", "date": 0}),
    )
    .await?;
    for i in 0..2 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": format!("+3538600000{i}0")}),
        )
        .await?;
    }
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "bob", "date": null}),
    )
    .await?;
    // A placed record and a tally row: neither belongs in either breakdown.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "bob", "date": T}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "iMessage", "subtype": "summary", "contact": "alice", "total": 4}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;

    assert_eq!(census.unplaceable_value, 4);
    assert_eq!(
        census.by_type_unplaceable_value,
        vec![("EmailMessage".to_string(), 3), ("iMessage".to_string(), 1)],
        "the value breakdown must name the parsers whose written times could \
         not be read"
    );
    assert_eq!(census.unplaceable_absent, 3);
    assert_eq!(
        census.by_type_unplaceable_absent,
        vec![("CallLog".to_string(), 2), ("WhatsApp".to_string(), 1)],
    );
    // The identity, stated as an equation over both classes.
    assert_eq!(
        breakdown_sum(&census.by_type_unplaceable_value),
        census.unplaceable_value,
        "a breakdown that does not add up to its own total is worse than none"
    );
    assert_eq!(
        breakdown_sum(&census.by_type_unplaceable_absent),
        census.unplaceable_absent,
    );
    // Nothing else leaked in: the placed record and the tally row are in
    // neither list, and the classes still sum to the population.
    assert_eq!(census.placed_as_written, 1);
    assert_eq!(census.not_a_message, 1);
    assert_eq!(census.class_sum(), census.matched_records);
    Ok(())
}

/// "Claimed a time this tool could not read" and "never claimed a time at all"
/// are different findings, kept apart everywhere else in this feature, and one
/// record type is routinely BOTH. Two lists, each summing to its own class —
/// collapsing them into one would report a parser as having lost times it never
/// wrote.
#[tokio::test]
async fn the_two_unplaceable_findings_keep_their_own_breakdowns() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..2 {
        record(
            &db,
            case_id,
            json!({"type": "iMessage", "subtype": "message", "contact": format!("c{i}"),
                   "date": "not a date"}),
        )
        .await?;
    }
    for i in 0..5 {
        record(
            &db,
            case_id,
            json!({"type": "iMessage", "subtype": "message", "contact": format!("d{i}")}),
        )
        .await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;

    assert_eq!(
        census.by_type_unplaceable_value,
        vec![("iMessage".to_string(), 2)],
    );
    assert_eq!(
        census.by_type_unplaceable_absent,
        vec![("iMessage".to_string(), 5)],
        "the same parser wrote five records with no time key and two with a \
         time nobody can read; one list of seven would describe neither"
    );
    Ok(())
}

/// The order is fixed — count descending, then type name ascending — so the
/// sentence a reader quotes today reads the same tomorrow. The tiebreak is
/// BYTE order, the comparator `comms_contact_ranking` already uses for its own
/// `by_type`, which is why "iMessage" sorts after "WhatsApp".
#[tokio::test]
async fn the_breakdown_order_is_fixed_so_the_sentence_does_not_reshuffle() -> Result<()> {
    let (db, case_id) = setup().await?;
    for ty in ["iMessage", "WhatsApp", "CallLog"] {
        record(
            &db,
            case_id,
            json!({"type": ty, "subtype": "message", "contact": "a", "date": "not a date"}),
        )
        .await?;
    }
    // One type with more of them, to pin that count beats name.
    for i in 0..3 {
        record(
            &db,
            case_id,
            json!({"type": "TwitterDM", "subtype": "message", "contact": format!("c{i}"),
                   "date": "not a date"}),
        )
        .await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    let expected: Vec<(String, i64)> = [
        ("TwitterDM", 3),
        ("CallLog", 1),
        ("WhatsApp", 1),
        ("iMessage", 1),
    ]
    .into_iter()
    .map(|(t, n)| (t.to_string(), n))
    .collect();
    assert_eq!(census.by_type_unplaceable_value, expected);

    // Read again: SQLite is free to return groups in any order it likes, so
    // the order has to be imposed rather than observed once and trusted.
    let again = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(again.by_type_unplaceable_value, expected);
    Ok(())
}

/// The breakdown describes the MATCHED population, exactly as the class it
/// decomposes does. A type that matched nothing is absent from the list rather
/// than present with a zero: "EmailMessage 0" in a shortfall sentence reads as
/// a finding about EmailMessage, when the truth is that the search excluded it.
#[tokio::test]
async fn a_type_the_search_excluded_is_absent_from_the_breakdown_not_listed_as_zero() -> Result<()>
{
    let (db, case_id) = setup().await?;
    record(
        &db,
        case_id,
        json!({"type": "EmailMessage", "subtype": "message", "contact": "carol",
               "date": "not a date"}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "iMessage", "subtype": "message", "contact": "alice", "date": 0}),
    )
    .await?;

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("ali"), None)
        .await?;

    assert_eq!(census.unplaceable_value, 1);
    assert_eq!(
        census.by_type_unplaceable_value,
        vec![("iMessage".to_string(), 1)],
    );
    assert_eq!(
        breakdown_sum(&census.by_type_unplaceable_value),
        census.unplaceable_value,
    );

    // A search nobody matched leaves nothing to break down at all.
    let none = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("zzz"), None)
        .await?;
    assert_eq!(none.matched_records, 0);
    assert!(none.by_type_unplaceable_value.is_empty());
    assert!(none.by_type_unplaceable_absent.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Two populations, both named
// ---------------------------------------------------------------------------

/// `total_records` describes the case narrowed by channel alone. LIVE-024: a
/// tile that shrank while an examiner typed would read as evidence
/// disappearing. `matched_records` is what the bars sum to, and only that.
#[tokio::test]
async fn the_case_total_never_narrows_with_the_search_but_the_bars_do() -> Result<()> {
    let (db, case_id) = setup().await?;
    for (contact, n) in [("alice", 5), ("bob", 3)] {
        for i in 0..n {
            record(
                &db,
                case_id,
                json!({"type": "WhatsApp", "subtype": "chat_message",
                       "contact": contact, "date": T + i}),
            )
            .await?;
        }
    }
    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "call", "contact": "alice", "timestamp": T}),
    )
    .await?;

    let all = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(all.total_records, 9);
    assert_eq!(all.matched_records, 9);

    let searched = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("ali"), None)
        .await?;
    assert_eq!(
        searched.total_records, 9,
        "the case total is narrowed by channel ALONE"
    );
    assert_eq!(searched.matched_records, 6, "5 WhatsApp + 1 call");
    assert_eq!(searched.class_sum(), 6);

    let channelled = db
        .comms_volume_census(
            case_id,
            COMMS_TIME_KEYS,
            Some("WhatsApp"),
            Some("ali"),
            None,
        )
        .await?;
    assert_eq!(
        channelled.total_records, 8,
        "channel DOES narrow the case total"
    );
    assert_eq!(channelled.matched_records, 5);

    let picked = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, Some("bob"))
        .await?;
    assert_eq!(picked.total_records, 9);
    assert_eq!(picked.matched_records, 3);

    // The bars sum to matched_records' placed classes, over every narrowing.
    for (needle, contact, want) in [
        (None, None, 9i64),
        (Some("ali"), None, 6),
        (None, Some("bob"), 3),
    ] {
        let bars = db
            .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, needle, contact, DAY)
            .await?;
        let sum: i64 = bars.iter().map(|b| b.count).sum();
        assert_eq!(sum, want, "bars must sum to the matched placed population");
    }
    Ok(())
}

/// The search folds ASCII letters only, on both sides — the same rule and the
/// same residual limit the ranking beside it documents. A caller must not
/// present an empty answer as "no correspondent by that name".
#[tokio::test]
async fn the_search_folds_ascii_on_both_sides_and_no_further() -> Result<()> {
    let (db, case_id) = setup().await?;
    for contact in ["Sahin", "Ünal"] {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message",
                   "contact": contact, "date": T}),
        )
        .await?;
    }

    let hit = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("SAHIN"), None)
        .await?;
    assert_eq!(hit.matched_records, 1);

    let exact = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("Ünal"), None)
        .await?;
    assert_eq!(
        exact.matched_records, 1,
        "a correspondent must always be found by their own spelling"
    );

    let folded = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, Some("ünal"), None)
        .await?;
    assert_eq!(
        folded.matched_records, 0,
        "SQLite folds A-Z and nothing else; this limit is stated on the API, \
         not papered over here"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Extent
// ---------------------------------------------------------------------------

/// The extent is MIN/MAX over the PLACED population, which is what the API sizes
/// buckets from. Unplaceable records must not drag it to zero.
#[tokio::test]
async fn the_extent_spans_the_placed_records_only() -> Result<()> {
    let (db, case_id) = setup().await?;
    for meta in [
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": T}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": T + 10 * DAY}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": 0}),
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a"}),
        json!({"type": "WhatsApp", "status": "ParseFailed", "file_name": "x", "date": T - DAY}),
    ] {
        record(&db, case_id, meta).await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(census.min_ts_secs, Some(T));
    assert_eq!(
        census.max_ts_secs,
        Some(T + 10 * DAY),
        "a status stub that happens to carry a date must not widen the axis of \
         a chart it is not drawn on"
    );
    assert_eq!(census.placed_records(), 2);
    Ok(())
}

/// A case with records but nothing placeable has an empty extent AND a census
/// that says why — the four empty states must stay apart, and `{buckets: []}`
/// cannot tell them apart on its own.
#[tokio::test]
async fn an_empty_extent_still_carries_the_census_that_explains_it() -> Result<()> {
    let (db, case_id) = setup().await?;
    for _ in 0..3 {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "a", "date": "now"}),
        )
        .await?;
    }

    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(census.min_ts_secs, None);
    assert_eq!(census.max_ts_secs, None);
    assert_eq!(census.placed_records(), 0);
    assert_eq!(
        census.unplaceable_value, 3,
        "`now` is SQLite magic that would otherwise return the time of the \
         QUERY — three messages dated the moment the examiner opened the page"
    );
    assert_eq!(census.total_records, 3);

    let empty = db
        .comms_volume_census(Uuid::new_v4(), COMMS_TIME_KEYS, None, None, None)
        .await?;
    assert_eq!(empty.total_records, 0);
    assert_eq!(empty.class_sum(), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// An unrecognised channel is an error, never an empty answer: a well-formed
/// empty histogram reads on screen as "this case holds no messages of that
/// kind". The same rule the ranking keeps.
#[tokio::test]
async fn an_unknown_channel_is_refused_rather_than_answered_empty() -> Result<()> {
    let (db, case_id) = setup().await?;
    assert!(db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, Some("Telepathy"), None, None)
        .await
        .is_err());
    assert!(db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, Some("Telepathy"), None, None, DAY)
        .await
        .is_err());
    Ok(())
}

/// The key list is interpolated into a JSON path, so it is shape-checked. In
/// production it is the crate's own constant; the check is what keeps it that
/// way if a caller ever tries to pass one through from a request.
#[tokio::test]
async fn a_key_that_is_not_a_bare_identifier_is_refused() -> Result<()> {
    let (db, case_id) = setup().await?;
    for keys in [
        vec!["date'"],
        vec!["$.date"],
        vec![""],
        vec!["date\").x"],
        vec![],
    ] {
        assert!(
            db.comms_volume_census(case_id, &keys, None, None, None)
                .await
                .is_err(),
            "{keys:?} must be refused"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reconciliation with the ranking beside it
// ---------------------------------------------------------------------------

/// Two "exact" totals differing by thousands with nothing explaining the gap is
/// the failure mode this pins.
///
/// The ranking files `(CallLog, contact = "Unknown")` — the literal the
/// call-history parser writes when the device recorded no number at all — into
/// `records_without_counterparty` and EXCLUDES it from `by_type`. Those calls
/// have real timestamps and are real evidence, so they belong on the chart. The
/// two numbers therefore differ, they differ by exactly that population, and a
/// caller that shows both must be able to say so.
#[tokio::test]
async fn the_chart_draws_the_calls_the_ranking_files_as_having_no_counterparty() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..5 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": "Unknown",
                   "timestamp": T + i}),
        )
        .await?;
    }
    for i in 0..3 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": "+353860000000",
                   "timestamp": T + i}),
        )
        .await?;
    }

    let ranking = db.comms_contact_ranking(case_id, None, None, 8).await?;
    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;

    assert_eq!(ranking.records_without_counterparty, 5);
    let ranked: i64 = ranking.by_type.iter().map(|(_, n)| *n).sum();
    assert_eq!(
        ranked, 3,
        "the ranking's tiles show three of the eight calls"
    );

    let drawn: i64 = bars.iter().map(|b| b.count).sum();
    assert_eq!(
        drawn, 8,
        "all eight calls happened and all eight belong on the chart"
    );
    assert_eq!(census.placed_records(), 8);
    // The relationship, stated as the equation a caller can show:
    assert_eq!(drawn, ranked + ranking.records_without_counterparty);
    // Both read the same population, so the case totals agree exactly.
    assert_eq!(census.total_records, ranking.total_records);
    Ok(())
}

/// `json_extract` on malformed `metadata_json` ABORTS THE WHOLE QUERY, where the
/// browser would lose only that row. One corrupt record would zero the
/// histogram; guarded, it costs one record and says so.
///
/// The corruption has to be introduced behind the crate's back, because nothing
/// in it can write invalid JSON: `metadata_json` is serialised from a
/// `serde_json::Value`. That is the point — this is the shape corruption AFTER
/// write leaves behind, and the row is still reachable through the expression
/// index whose stored key was computed while the JSON still parsed.
#[tokio::test]
async fn one_unreadable_record_costs_one_record_not_the_whole_chart() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Corrupt", "Examiner").await?;
    for i in 0..4 {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message",
                   "contact": format!("c{i}"), "date": T + i}),
        )
        .await?;
    }
    drop(db);

    // Corrupted IN PLACE, byte for byte, because that is the only way this
    // state can arise: every write path through the crate serialises
    // `metadata_json` from a `serde_json::Value`, and an UPDATE that wrote
    // malformed JSON would be refused by the record-type EXPRESSION INDEX
    // before it landed — the index recomputes its key and json_extract fails.
    // Overwriting one quote with a space leaves the row length, the page
    // layout and the index's stored key untouched, which is exactly what a
    // half-written page or a truncated file leaves behind.
    {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await?;
        drop(pool);
    }
    let mut bytes = std::fs::read(path.path())?;
    let needle = br#""contact":"c0""#;
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the record's metadata_json is stored verbatim in the file");
    bytes[at] = b' '; // `"contact":"c0"` -> ` contact":"c0"`
    std::fs::write(path.path(), &bytes)?;

    let db = SqliteConnection::new(&format!("sqlite:{}", path)).await?;
    let census = db
        .comms_volume_census(case_id, COMMS_TIME_KEYS, None, None, None)
        .await?;
    let bars = db
        .comms_volume_histogram(case_id, COMMS_TIME_KEYS, None, None, None, DAY)
        .await?;

    assert_eq!(census.total_records, 4, "the corrupt row is still a record");
    assert_eq!(census.unreadable_metadata, 1);
    assert_eq!(census.placed_as_written, 3);
    assert_eq!(census.class_sum(), 4);
    assert_eq!(
        bars.iter().map(|b| b.count).sum::<i64>(),
        3,
        "three placed records must still be drawn; an unguarded json_extract \
         would have aborted the statement and drawn nothing at all"
    );

    drop(db);
    Ok(())
}
