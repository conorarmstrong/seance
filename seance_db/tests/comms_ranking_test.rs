//! The most-contacted league table must be computed over every comms record in
//! the case, not over whatever prefix a browser managed to download.
//!
//! LIVE-024: the correlation page built its ranking client-side from a
//! 2,000-record-per-type slice of up to 78,237 records. A ranking derived from a
//! sample is not a ranking — the ORDER ITSELF is wrong whenever the sample is
//! not representative, and an ingest-ordered prefix never is. These tests pin
//! `comms_contact_ranking` to the whole match set, to the exact counterparty
//! chain the viewer applies (frontend/src/pages/comms/normalize.ts), and to a
//! census that adds up, so no row can be dropped without being reported.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Ranking", "Examiner").await?;
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

/// Count for one contact in the returned ranking, or None when it is absent.
fn count_of(r: &seance_db::CommsContactRanking, contact: &str) -> Option<i64> {
    r.contacts
        .iter()
        .find(|c| c.contact == contact)
        .map(|c| c.count)
}

/// Count the census attributed to one record type.
fn by_type(r: &seance_db::CommsContactRanking, ty: &str) -> i64 {
    r.by_type
        .iter()
        .find(|(t, _)| t == ty)
        .map(|(_, n)| *n)
        .unwrap_or(0)
}

/// The exact inversion LIVE-024 describes: the client's 2,000-record
/// ingest-ordered prefix sees only Alice, so it ranks Alice first, while the
/// case as a whole is dominated by Bob.
#[tokio::test]
async fn ranks_over_every_record_not_a_page() -> Result<()> {
    let (db, case_id) = setup().await?;

    // Alice's messages are ingested FIRST, Bob's after. Two batches, because
    // `record_artifacts_batch` stamps one `created_at` per batch and the whole
    // point of this test is that Alice's rows sort ahead of Bob's.
    let alice: Vec<Artifact> = (0..2000)
        .map(|i| {
            artifact(
                case_id,
                json!({"type": "WhatsApp", "subtype": "chat_message",
                       "contact": "alice", "text": format!("a{i}")}),
            )
        })
        .collect();
    db.record_artifacts_batch(&alice).await?;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let bob: Vec<Artifact> = (0..3000)
        .map(|i| {
            artifact(
                case_id,
                json!({"type": "WhatsApp", "subtype": "chat_message",
                       "contact": "bob", "text": format!("b{i}")}),
            )
        })
        .collect();
    db.record_artifacts_batch(&bob).await?;

    // What the browser actually had to rank from: the first 2,000 records in
    // ingest order. Every one of them is Alice's, so a client-side tally of
    // that slice puts Alice on top with Bob nowhere.
    let (slice, total) = db
        .list_records_by_type(case_id, "WhatsApp", None, 1, 2000)
        .await?;
    assert_eq!(total, 5000);
    assert_eq!(slice.len(), 2000);
    assert!(
        slice
            .iter()
            .all(|r| r.metadata["contact"] == json!("alice")),
        "the ingest-ordered prefix the client ranks from contains only Alice, \
         which is what makes the client-side ranking wrong"
    );

    let ranking = db.comms_contact_ranking(case_id, None, None, 8).await?;

    assert_eq!(
        ranking.contacts.first().map(|c| c.contact.as_str()),
        Some("bob"),
        "the ranking must be computed over all 5,000 records, not the first 2,000"
    );
    assert_eq!(count_of(&ranking, "bob"), Some(3000));
    assert_eq!(count_of(&ranking, "alice"), Some(2000));
    assert_eq!(ranking.distinct_contacts, 2);
    assert_eq!(ranking.total_records, 5000);
    assert!(!ranking.has_more);

    Ok(())
}

/// Guards the SQL COALESCE against drifting from the chain in
/// frontend/src/pages/comms/normalize.ts:87-97. Each key gets a record of its
/// own, and the precedence pairs pin the ORDER of the chain, not just its
/// membership.
#[tokio::test]
async fn the_counterparty_chain_matches_the_viewer() -> Result<()> {
    let (db, case_id) = setup().await?;

    // One record per key, each carrying only that key, in chain order.
    for (key, value) in [
        ("contact", "k-contact"),
        ("chat_display_name", "k-chat_display_name"),
        ("contact_name", "k-contact_name"),
        ("chat_identifier", "k-chat_identifier"),
        ("sender", "k-sender"),
        ("sender_screen_name", "k-sender_screen_name"),
        ("contact_jid", "k-contact_jid"),
        ("remote_jid", "k-remote_jid"),
        ("from", "k-from"),
        ("from_name", "k-from_name"),
    ] {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message", key: value}),
        )
        .await?;
    }

    // Precedence: an earlier key always wins over a later one.
    record(
        &db,
        case_id,
        json!({"type": "iMessage", "subtype": "chat_message",
               "contact": "wins", "chat_display_name": "loses"}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "EmailMessage", "from": "from-wins", "from_name": "from_name-loses"}),
    )
    .await?;

    // A modern WhatsApp Android row carries no `contact`/`contact_name`/
    // `contact_jid` at all (seance_plugin_whatsapp/src/lib.rs:1137-1158), so the
    // viewer falls all the way through to `remote_jid` — and `chat_subject` is
    // NOT in the chain, so a named group chat ranks under its raw JID.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message",
               "remote_jid": "4477009@g.us", "chat_subject": "Site Crew",
               "sender_jid": "4477001@s.whatsapp.net"}),
    )
    .await?;

    // A record whose only label is off-chain is unrankable, not silently
    // relabelled to something the viewer would never show.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "chat_subject": "Orphan Crew"}),
    )
    .await?;

    // An empty string is absent, the way metaStr treats it
    // (frontend/src/pages/analysis/lib.ts:126-140), and a numeric value coerces
    // to its digits rather than being dropped.
    record(
        &db,
        case_id,
        json!({"type": "AndroidSms", "contact": "", "chat_display_name": "empty-falls-through"}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "AndroidSms", "contact": 447700900123i64}),
    )
    .await?;

    let r = db.comms_contact_ranking(case_id, None, None, 100).await?;

    for key in [
        "contact",
        "chat_display_name",
        "contact_name",
        "chat_identifier",
        "sender",
        "sender_screen_name",
        "contact_jid",
        "remote_jid",
        "from",
        "from_name",
    ] {
        assert_eq!(
            count_of(&r, &format!("k-{key}")),
            Some(1),
            "`{key}` must be part of the counterparty chain"
        );
    }

    assert_eq!(count_of(&r, "wins"), Some(1));
    assert_eq!(
        count_of(&r, "loses"),
        None,
        "`contact` outranks a later key"
    );
    assert_eq!(count_of(&r, "from-wins"), Some(1));
    assert_eq!(count_of(&r, "from_name-loses"), None);

    assert_eq!(count_of(&r, "4477009@g.us"), Some(1));
    assert_eq!(
        count_of(&r, "Site Crew"),
        None,
        "`chat_subject` is not in the viewer's chain and must not be ranked"
    );
    assert_eq!(count_of(&r, "Orphan Crew"), None);
    assert_eq!(count_of(&r, "empty-falls-through"), Some(1));
    assert_eq!(count_of(&r, "447700900123"), Some(1));

    // Exactly one record — the chat_subject-only one — carried nothing the
    // viewer could read as a counterparty.
    assert_eq!(r.unrankable_records, 1);

    Ok(())
}

/// The summary row a chat parser appends is a tally OF the messages, not a
/// message. The viewer skips it (normalize.ts:81) and so must the ranking.
#[tokio::test]
async fn a_summary_row_is_not_a_counterparty() -> Result<()> {
    let (db, case_id) = setup().await?;

    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "call", "contact": "+15550100",
               "number": "+15550100", "timestamp": 1_700_000_000}),
    )
    .await?;
    // Exactly the shape seance_plugin_call_history/src/lib.rs:528-529 emits.
    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "summary", "platform": "Android",
               "call_count": 1, "contact": "+15550100"}),
    )
    .await?;

    let r = db.comms_contact_ranking(case_id, None, None, 10).await?;

    assert_eq!(
        count_of(&r, "+15550100"),
        Some(1),
        "the summary row must not inflate the call count"
    );
    assert_eq!(r.summary_records, 1);
    assert_eq!(r.total_records, 2);
    assert_eq!(by_type(&r, "CallLog"), 1);

    Ok(())
}

/// Nothing is dropped in silence: every record the query touched lands in
/// exactly one bucket, and the buckets add up to the total.
#[tokio::test]
async fn records_with_no_counterparty_are_counted_not_dropped() -> Result<()> {
    let (db, case_id) = setup().await?;

    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "alice"}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "text": "no counterparty keys"}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "summary", "message_count": 2}),
    )
    .await?;
    record(
        &db,
        case_id,
        json!({"type": "CallLog", "subtype": "call", "contact": "Unknown", "number": null}),
    )
    .await?;

    let r = db.comms_contact_ranking(case_id, None, None, 10).await?;

    assert_eq!(r.unrankable_records, 1);
    assert_eq!(r.summary_records, 1);
    assert_eq!(r.records_without_counterparty, 1);
    assert_eq!(r.total_records, 4);

    let ranked: i64 = r.by_type.iter().map(|(_, n)| *n).sum();
    assert_eq!(ranked, 1);
    assert_eq!(
        r.total_records,
        ranked + r.summary_records + r.unrankable_records + r.records_without_counterparty,
        "the census must account for every record it read"
    );

    Ok(())
}

/// The call-history parser writes the LITERAL string "Unknown" as `contact`
/// when the device recorded no number (seance_plugin_call_history/src/lib.rs:194).
/// A ranking presented as exact must not seat a phantom party called "Unknown"
/// at the top of the table — but the calls are real and their count must stay
/// on the record.
#[tokio::test]
async fn the_calllog_unknown_placeholder_is_not_seated_as_a_party() -> Result<()> {
    let (db, case_id) = setup().await?;

    for _ in 0..50 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": "Unknown",
                   "number": null, "timestamp": 1_700_000_000}),
        )
        .await?;
    }
    for _ in 0..3 {
        record(
            &db,
            case_id,
            json!({"type": "CallLog", "subtype": "call", "contact": "+15550100",
                   "number": "+15550100", "timestamp": 1_700_000_001}),
        )
        .await?;
    }
    // A genuine contact named "Unknown" on another platform is a real party and
    // must survive: the placeholder rule is CallLog's, not a global blocklist.
    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "Unknown"}),
    )
    .await?;

    let r = db.comms_contact_ranking(case_id, None, None, 10).await?;

    assert_eq!(
        r.contacts.first().map(|c| c.contact.as_str()),
        Some("+15550100"),
        "the 50 numberless calls must not outrank the 3 real ones"
    );
    assert_eq!(
        count_of(&r, "Unknown"),
        Some(1),
        "the WhatsApp contact genuinely named \"Unknown\" is still a party"
    );
    assert_eq!(
        r.records_without_counterparty, 50,
        "the numberless calls are reported, not discarded"
    );
    assert_eq!(r.distinct_contacts, 2);
    assert_eq!(r.total_records, 54);
    assert_eq!(
        by_type(&r, "CallLog"),
        3,
        "only the calls with a counterparty are tiled under CallLog"
    );

    Ok(())
}

/// A top-8 must never be readable as the whole correspondent list.
#[tokio::test]
async fn a_capped_ranking_says_it_is_capped() -> Result<()> {
    let (db, case_id) = setup().await?;

    for i in 0..12 {
        for _ in 0..=i {
            record(
                &db,
                case_id,
                json!({"type": "Signal", "subtype": "chat_message",
                       "contact": format!("c{i:02}")}),
            )
            .await?;
        }
    }

    let r = db.comms_contact_ranking(case_id, None, None, 8).await?;
    assert_eq!(r.contacts.len(), 8);
    assert_eq!(r.limit, 8);
    assert!(r.has_more, "12 correspondents do not fit in a top-8");
    assert_eq!(
        r.distinct_contacts, 12,
        "the distinct count stays exact even when the list is capped"
    );
    assert_eq!(r.contacts[0].contact, "c11");
    assert_eq!(r.contacts[0].count, 12);

    let full = db.comms_contact_ranking(case_id, None, None, 12).await?;
    assert_eq!(full.contacts.len(), 12);
    assert!(
        !full.has_more,
        "a limit that fits every correspondent is complete"
    );

    Ok(())
}

/// Fail-closed rather than fail-loudly on a case with nothing to rank.
#[tokio::test]
async fn an_empty_case_reports_zero_rather_than_failing() -> Result<()> {
    let (db, case_id) = setup().await?;

    let r = db.comms_contact_ranking(case_id, None, None, 8).await?;

    assert!(r.contacts.is_empty());
    assert!(!r.has_more);
    assert_eq!(r.distinct_contacts, 0);
    assert_eq!(r.total_records, 0);
    assert_eq!(r.summary_records, 0);
    assert_eq!(r.unrankable_records, 0);
    assert_eq!(r.records_without_counterparty, 0);
    assert!(r.by_type.is_empty());

    Ok(())
}

/// A channel filter narrows the whole question — ranking and census alike — and
/// a channel the ranking does not cover is refused rather than interpolated.
#[tokio::test]
async fn a_channel_restricts_the_whole_census_and_an_unknown_one_is_refused() -> Result<()> {
    let (db, case_id) = setup().await?;

    for _ in 0..4 {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "alice"}),
        )
        .await?;
    }
    for _ in 0..7 {
        record(
            &db,
            case_id,
            json!({"type": "iMessage", "subtype": "chat_message", "contact": "bob"}),
        )
        .await?;
    }
    // A non-comms record type must never be counted by the comms census.
    record(
        &db,
        case_id,
        json!({"type": "BrowserHistory", "url": "https://example.com", "contact": "alice"}),
    )
    .await?;

    let all = db.comms_contact_ranking(case_id, None, None, 10).await?;
    assert_eq!(all.total_records, 11, "BrowserHistory is not a comms type");

    let wa = db
        .comms_contact_ranking(case_id, Some("WhatsApp"), None, 10)
        .await?;
    assert_eq!(wa.total_records, 4);
    assert_eq!(wa.contacts.len(), 1);
    assert_eq!(count_of(&wa, "alice"), Some(4));
    assert_eq!(by_type(&wa, "iMessage"), 0);

    assert!(
        db.comms_contact_ranking(case_id, Some("BrowserHistory"), None, 10)
            .await
            .is_err(),
        "a record type outside the comms set must be refused, never interpolated"
    );
    assert!(db
        .comms_contact_ranking(case_id, Some("'; DROP TABLE artifacts; --"), None, 10)
        .await
        .is_err());

    Ok(())
}

/// The needle narrows the ranked list without rewriting the census, so a search
/// can never make the case look smaller than it is.
#[tokio::test]
async fn a_needle_filters_the_ranking_but_not_the_census() -> Result<()> {
    let (db, case_id) = setup().await?;

    for name in ["Alice Smith", "Alicia Jones", "Bob Stone"] {
        record(
            &db,
            case_id,
            json!({"type": "Skype", "subtype": "chat_message", "contact": name}),
        )
        .await?;
    }
    record(
        &db,
        case_id,
        json!({"type": "Skype", "subtype": "chat_message", "text": "orphan"}),
    )
    .await?;
    // A literal `%` must match literally, not as a wildcard.
    record(
        &db,
        case_id,
        json!({"type": "Skype", "subtype": "chat_message", "contact": "100%Bob"}),
    )
    .await?;

    let r = db
        .comms_contact_ranking(case_id, None, Some("alic"), 10)
        .await?;
    assert_eq!(
        r.contacts.len(),
        2,
        "substring match, case-insensitive for ASCII letters"
    );
    assert_eq!(count_of(&r, "Alice Smith"), Some(1));
    assert_eq!(count_of(&r, "Alicia Jones"), Some(1));
    assert_eq!(r.distinct_contacts, 2);
    assert_eq!(
        r.total_records, 5,
        "the census describes the case, not the search"
    );
    assert_eq!(r.unrankable_records, 1);

    let pct = db
        .comms_contact_ranking(case_id, None, Some("100%"), 10)
        .await?;
    assert_eq!(pct.contacts.len(), 1);
    assert_eq!(count_of(&pct, "100%Bob"), Some(1));

    Ok(())
}

/// A counterparty whose name is not ASCII must be found by its own spelling.
///
/// The needle used to be folded with Rust's Unicode-aware `to_lowercase()` and
/// then compared against SQLite's `lower()`, which folds ASCII only. The two
/// sides therefore disagreed on every non-ASCII letter, so searching for
/// "Ünal" produced the pattern `%ünal%` against an unfolded `Ünal` and matched
/// NOTHING — not even the name typed exactly as the evidence stores it. The
/// answer was then presented to the examiner as an exact, server-side count of
/// zero correspondents, beside a record table that listed that correspondent's
/// messages.
#[tokio::test]
async fn a_non_ascii_counterparty_is_found_by_its_own_spelling() -> Result<()> {
    let (db, case_id) = setup().await?;

    for name in ["Ünal Sahin", "Ярослав", "JOSÉ Ramos", "Alice Smith"] {
        record(
            &db,
            case_id,
            json!({"type": "WhatsApp", "subtype": "chat_message", "contact": name}),
        )
        .await?;
    }

    for (needle, expected) in [
        // The stored spelling, character for character.
        ("Ünal Sahin", "Ünal Sahin"),
        // A substring of it, still in the stored case.
        ("Ünal", "Ünal Sahin"),
        // Cyrillic, no ASCII letter in it at all.
        ("Ярослав", "Ярослав"),
        // The ASCII letters may be typed in any case; the accented one is
        // typed as stored.
        ("josÉ ramos", "JOSÉ Ramos"),
    ] {
        let r = db
            .comms_contact_ranking(case_id, None, Some(needle), 10)
            .await?;
        assert_eq!(
            count_of(&r, expected),
            Some(1),
            "searching for {needle:?} must find {expected:?}"
        );
        assert_eq!(
            r.distinct_contacts, 1,
            "searching for {needle:?} must count exactly the one correspondent it matched"
        );
    }

    Ok(())
}

/// The DISCLOSED limit of that search, pinned so it cannot widen or narrow by
/// accident: case folding is ASCII-only on both sides, so a non-ASCII letter
/// matches only in the case it is stored in.
///
/// This is asserted rather than merely documented because the examiner is shown
/// the result as an exact server-side count. If the search is ever made
/// Unicode-aware, this test must be rewritten deliberately — and the wording of
/// the comms page's "correspondents whose identifier contains …" note revisited
/// with it, since the page's own fallback filter uses JavaScript's
/// Unicode-aware `toLowerCase()` and is therefore more permissive here.
#[tokio::test]
async fn a_non_ascii_letter_matches_only_in_the_case_it_is_stored_in() -> Result<()> {
    let (db, case_id) = setup().await?;

    record(
        &db,
        case_id,
        json!({"type": "WhatsApp", "subtype": "chat_message", "contact": "Ünal Sahin"}),
    )
    .await?;

    // "ünal" is the same name with the same letters; SQLite's built-in lower()
    // cannot fold 'Ü', so the server cannot match it and says so with a zero,
    // rather than by matching approximately.
    let r = db
        .comms_contact_ranking(case_id, None, Some("ünal sahin"), 10)
        .await?;
    assert!(
        r.contacts.is_empty() && r.distinct_contacts == 0,
        "a lower-case 'ü' is outside SQLite's ASCII-only folding; the documented \
         limit is that it does not match, not that it half-matches"
    );

    // The ASCII half of the same name still folds in both directions.
    let ascii = db
        .comms_contact_ranking(case_id, None, Some("SAHIN"), 10)
        .await?;
    assert_eq!(count_of(&ascii, "Ünal Sahin"), Some(1));

    Ok(())
}
