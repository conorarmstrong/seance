use super::*;
use seance_core::test_support::{DribbleSource, TruncatedSource};
use seance_sqlite_util::{SupportedRange, TempDb};

/// A source declaring twice the bytes it can deliver, over the shared double.
///
/// The local copy this replaces bounds-checked in `usize` after casting the
/// `u64` offset, which is lossless here and wrong on a 32-bit target; the
/// shared one compares in `u64` space. `declared = 2 x len` keeps the exact
/// shape every assertion below was written against.
fn truncated(bytes: Vec<u8>) -> TruncatedSource {
    let declared = (bytes.len() as u64) * 2;
    TruncatedSource::new(bytes, declared)
}

use rusqlite::Connection;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// Build a Viber `messages` DB from a CREATE + INSERT batch, returning its bytes.
fn viber_db(batch: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_viber_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(batch).unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    ViberParser.process(&art).unwrap()
}

fn by_rowid(arts: &[Artifact], rowid: i64) -> &Artifact {
    arts.iter()
        .find(|a| a.metadata.get("rowid").and_then(|v| v.as_i64()) == Some(rowid))
        .expect("record present")
}

#[test]
fn parses_send_type_schema() {
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'Hi from Viber', 1672848000000, 0);
         INSERT INTO messages VALUES (2, 10, 'Reply sent', 1672848060000, 1);
         INSERT INTO messages VALUES (3, 20, NULL, 1672848120000, 0);",
    );
    let arts = run("viber_messages", db);
    assert_eq!(messages(&arts).len(), 3);

    let recv = by_rowid(&arts, 1);
    assert_eq!(recv.metadata["direction"], "received");
    assert_eq!(recv.metadata["is_from_me"], false);
    assert_eq!(recv.metadata["text"], "Hi from Viber");
    assert_eq!(recv.metadata["service"], "Viber");
    assert_eq!(recv.metadata["conversation_id"], 10);
    // date is Unix milliseconds -> seconds.
    assert_eq!(recv.metadata["date"].as_i64(), Some(1_672_848_000));

    let sent = by_rowid(&arts, 2);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    // Media/no-body row: no text key, name notes it.
    let media = by_rowid(&arts, 3);
    assert!(media.metadata.get("text").is_none());
    assert!(media.metadata["name"]
        .as_str()
        .unwrap()
        .contains("(no text)"));

    // Every message record is a chat_message; the only other record is the
    // schema-support disclosure this parser owes for every store.
    for a in &arts {
        assert!(
            a.metadata["subtype"] == "chat_message"
                || a.metadata["warning_class"] == "ParserStaleWarning",
            "{a:?}"
        );
    }
}

#[test]
fn parses_legacy_type_column() {
    // Older builds name the direction column `type` and omit conversation_id.
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER, type INTEGER);
         INSERT INTO messages VALUES (1, 'legacy schema', 1672848000000, 1);",
    );
    let arts = run("viber_data", db);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["direction"], "sent");
    assert_eq!(arts[0].metadata["text"], "legacy schema");
    assert!(arts[0].metadata.get("conversation_id").is_none());
}

/// BUG-253: a build with no direction column, or a NULL in it, never recorded
/// the direction. It must stay unknown rather than be asserted as received.
#[test]
fn direction_is_unknown_without_a_direction_column() {
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER);
         INSERT INTO messages VALUES (1, 'no direction column', 1672848000000);",
    );
    let arts = run("viber_messages", db);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
    assert!(arts[0].metadata.get("is_from_me").is_none());
    assert_eq!(arts[0].metadata["text"], "no direction column");

    let null_dir = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 'null send_type', 1672848000000, NULL);",
    );
    let arts = run("viber_messages", null_dir);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
}

#[test]
fn skips_non_viber_name() {
    // A valid Viber DB under a different filename is not ours to parse.
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 'x', 1672848000000, 1);",
    );
    assert!(run("random.db", db).is_empty());
}

#[test]
fn ignores_non_sqlite_and_wrong_schema() {
    // Right name, not a SQLite database.
    assert!(run("viber_messages", b"not a database".to_vec()).is_empty());
    // Right name and SQLite, but no messages table.
    let other = viber_db("CREATE TABLE contacts (_id INTEGER, name TEXT);");
    assert!(run("viber_messages", other).is_empty());
}

#[test]
fn module_metadata() {
    let p = ViberParser;
    assert_eq!(p.id(), "plugin.messaging.viber");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}
fn run_source(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    ViberParser.process(&art).unwrap()
}

fn one_message_db() -> Vec<u8> {
    viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'Hi from Viber', 1672848000000, 0);",
    )
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source("viber_messages", Arc::new(truncated(one_message_db())));
    let msg = out
        .iter()
        .find(|a| a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("chat_message"))
        .expect("the readable prefix still parses");
    assert_eq!(msg.metadata["content_incomplete"], true);
    assert_eq!(msg.metadata["content_incomplete_reason"], "short_read");
    assert!(
        out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                == Some("DatabaseNotStagedInFull")),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: a database read whole must stay unmarked, or the marker
/// means nothing.
#[test]
fn a_complete_database_carries_no_incompleteness_marks() {
    let out = run("viber_messages", one_message_db());
    assert_eq!(messages(&out).len(), 1);
    // The schema-support disclosure is the only other record, and it must not
    // stamp incompleteness on a store whose every field resolved.
    assert!(
        out.iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "{out:?}"
    );
}

/// The magic probe loops over short reads. A source that answers four bytes per
/// call holds a perfectly good database; refusing it would drop the whole store
/// on nothing more than the shape of the read.
#[test]
fn a_source_that_answers_in_small_chunks_is_still_parsed() {
    let out = run_source(
        "viber_messages",
        Arc::new(DribbleSource::new(one_message_db(), 4)),
    );
    assert_eq!(
        messages(&out).len(),
        1,
        "a chunked source is not a non-SQLite file"
    );
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// B3-023: undecodable rows were swallowed by `flatten()`, so the message count
/// read as exact for a store that held more. The marker is what turns that
/// count back into a floor, and it must carry the reason as well as the number.
#[test]
fn undecodable_message_rows_are_counted_marked_and_explained() {
    let db = viber_db(
        "CREATE TABLE messages (_id, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'decodes fine', 1672848000000, 0);
         -- `_id` is read as a non-null i64; TEXT here will not decode.
         INSERT INTO messages VALUES ('not-an-integer', 10, 'lost row', 1672848060000, 0);",
    );
    let out = run("viber_messages", db);

    let messages: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 1, "only the decodable row yields a message");

    let marker = out
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a dropped row must produce an incompleteness marker");
    // Never "Viber": `seance_db` groups conversations by `metadata.$.type`, so
    // a marker carrying the walk's own type becomes a one-message conversation.
    assert_eq!(marker.metadata["type"], "ViberIncomplete");
    assert_eq!(marker.metadata["status"], "RowsUndecodable");
    assert_eq!(marker.metadata["source_table"], "messages");
    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(marker.metadata["records_recovered"], json!(1));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert!(
        marker.metadata["first_error"].is_string(),
        "the decoder's reason must reach the artifact, not just the log"
    );
}

/// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6`, so the schema catalogue will not
/// read while the file still opens.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

/// B8-039. `table_columns` ends in an empty set when the PRAGMA fails, and an
/// empty set fails the `body`/`date` check, so `parse_viber` returned nothing
/// for a store it could not read. Nothing is exactly what a phone that never
/// had Viber produces, so a damaged database was reported as an app that was
/// never installed — an exculpatory finding nobody established.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn a_corrupt_viber_store_is_not_reported_as_a_phone_without_viber() {
    let out = run("viber_messages", corrupt_the_catalogue(one_message_db()));

    assert!(
        !out.is_empty(),
        "an unreadable Viber store must not render as a phone that never had Viber"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("ViberIncomplete"));
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    // No messages were invented to go with it.
    assert!(
        !out.iter()
            .any(|a| a.metadata["type"] == json!("ViberMessage")),
        "no message record may accompany a store that could not be read"
    );
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

/// Records the schema-support mechanism emitted for a store: one per parsed
/// database, typed apart from the messages.
fn schema_records(arts: &[Artifact]) -> Vec<&Artifact> {
    arts.iter()
        .filter(|a| a.metadata["warning_class"] == json!("ParserStaleWarning"))
        .collect()
}

fn messages(arts: &[Artifact]) -> Vec<&Artifact> {
    arts.iter()
        .filter(|a| a.metadata["subtype"] == json!("chat_message"))
        .collect()
}

/// Run the parser on `bytes` under an injected declaration, the way `process`
/// would run it under the crate's own.
fn run_with_support(bytes: Vec<u8>, support: &SchemaSupport) -> Vec<Artifact> {
    let temp = TempDb::write(&bytes, "viber_schema_test").unwrap();
    parse_viber_with(temp.path(), Uuid::new_v4(), Uuid::new_v4(), support)
}

/// A store whose `PRAGMA user_version` is beyond the range a parser was
/// validated against must say so — and must still parse what it can. The
/// crate's own declaration is Unranged (no real Viber store is held), so the
/// Validated bound here is injected; the range is a test value and asserts
/// nothing about any Viber build.
#[test]
fn a_schema_version_beyond_the_validated_range_is_declared_and_the_store_is_still_parsed() {
    let db = viber_db(
        "PRAGMA user_version = 99;
         CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'still read', 1672848000000, 0);",
    );
    let support = SchemaSupport {
        app: "viber-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Viber build",
        },
    };
    let out = run_with_support(db, &support);

    assert_eq!(messages(&out).len(), 1, "the message is still recovered");
    let stale = schema_records(&out);
    assert_eq!(stale.len(), 1, "{out:?}");
    let m = &stale[0].metadata;
    assert_eq!(m["type"], json!("ViberIncomplete"));
    assert_eq!(m["subtype"], json!("parser_stale"));
    assert_eq!(m["status"], json!("SchemaOutsideValidated"));
    assert_eq!(m["schema_version_seen"], json!(99));
    assert_eq!(m["schema_version_supported"], json!("1..=3"));
    assert!(m["message"].as_str().unwrap().contains("NEWER"));
    // Every column the parser needs still resolved, so the parse is not
    // claimed incomplete: the version is disclosed, not spent as a finding.
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// Below the range is the other direction of the same disclosure.
#[test]
fn a_schema_version_below_the_validated_range_is_declared_as_older() {
    let db = viber_db(
        "PRAGMA user_version = 2;
         CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER);
         INSERT INTO messages VALUES (1, 'x', 1672848000000);",
    );
    let support = SchemaSupport {
        app: "viber-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(5, Some(9)),
            evidence: "test value, not a Viber build",
        },
    };
    let out = run_with_support(db, &support);
    let stale = schema_records(&out);
    assert_eq!(stale[0].metadata["status"], json!("SchemaOutsideValidated"));
    assert_eq!(messages(&out).len(), 1);
}

/// A renamed message-body column used to make this parser return nothing at
/// all — indistinguishable from a phone with no Viber messages. The FieldMap
/// turns that into a marker naming the LOGICAL field the examiner is missing,
/// and the rows the parser can still read are still read.
#[test]
fn a_renamed_body_column_yields_a_marker_naming_the_unresolved_field() {
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, message_text TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'unreachable body', 1672848000000, 1);",
    );
    let out = run("viber_messages", db);

    let marker = schema_records(&out);
    assert_eq!(marker.len(), 1, "{out:?}");
    let m = &marker[0].metadata;
    assert_eq!(m["type"], json!("ViberIncomplete"));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("text"));
    // The timeline half of the row survives: date and direction were read.
    let msgs = messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["date"], json!(1672848000));
    assert_eq!(msgs[0].metadata["direction"], json!("sent"));
    assert!(msgs[0].metadata.get("text").is_none());
    assert_eq!(m["records_recovered"], json!(1));
}

/// When NEITHER field an evidentiary message needs resolves, no record is
/// invented — but the store is not reported as empty either.
#[test]
fn a_messages_table_with_no_recognised_column_yields_the_marker_and_no_records() {
    let db = viber_db(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, payload TEXT, when_ms INTEGER);
         INSERT INTO messages VALUES (1, 'x', 1672848000000);",
    );
    let out = run("viber_messages", db);
    assert!(messages(&out).is_empty());
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text", "sent_at"]));
    assert_eq!(m["records_recovered"], json!(0));
}

/// No real Viber store is held by this project, so the crate declares
/// Unranged: the record says so, reports the version the store carries, and
/// carries NO range — a `1..=N` here would be a claim about databases this
/// project has never opened.
#[test]
fn a_parser_with_no_reference_database_declares_that_rather_than_a_range() {
    let db = viber_db(
        "PRAGMA user_version = 7;
         CREATE TABLE messages (_id INTEGER PRIMARY KEY, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 'x', 1672848000000, 1);",
    );
    let out = run("viber_messages", db);
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["type"], json!("ViberIncomplete"));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_seen"], json!(7));
    assert_eq!(m["schema_version_locator"], json!("user_version"));
    assert!(m.get("schema_version_supported").is_none(), "{m}");
    assert!(m.get("supported_range").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("no reference database"));
    // Disclosure, not a finding of incompleteness.
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert_eq!(messages(&out).len(), 1);
}

/// `PRAGMA user_version` reads 0 on a store that never set it — SQLite's
/// default. That is the absence of a version, never "version 0", and the
/// record must say which.
#[test]
fn a_user_version_of_zero_is_the_absence_of_a_version_not_a_version_of_zero() {
    let out = run("viber_messages", one_message_db());
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_recorded"], json!(false));
    assert!(m.get("schema_version_seen").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("records no schema version"));

    // The same store under a Validated declaration: the range cannot be
    // applied, and the record says that rather than "older than 1..=3".
    let support = SchemaSupport {
        app: "viber-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Viber build",
        },
    };
    let out = run_with_support(one_message_db(), &support);
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaVersionNotRecorded"));
    assert!(m.get("schema_version_seen").is_none(), "{m}");
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A version the store would not answer is never spent as "in range".
#[test]
fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
    let support = SchemaSupport {
        app: "viber-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Viber build",
        },
    };
    let fields = FieldMap::resolve(
        &["body".to_string(), "date".to_string()]
            .into_iter()
            .collect(),
        MESSAGE_FIELDS,
    );
    let rec = SchemaCheck {
        support: &support,
        version: SchemaVersion::Undetermined("PRAGMA user_version would not read".into()),
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "ViberIncomplete",
        store: "messages",
    }
    .marker(Uuid::new_v4(), Uuid::new_v4(), 3)
    .expect("an unanswered version is a record, not silence");
    assert_eq!(rec.metadata["status"], json!("SchemaVersionUndetermined"));
    assert!(rec.metadata["schema_version_detail"]
        .as_str()
        .unwrap()
        .contains("would not read"));
    assert!(rec.metadata.get("schema_version_seen").is_none());
}

/// The crate's own declaration: Unranged, with the reason, and every logical
/// field the parser reads on the map.
#[test]
fn the_declared_schema_support_is_unranged_for_want_of_a_real_store() {
    assert!(matches!(SCHEMA_SUPPORT.bound, SchemaBound::Unranged { .. }));
    assert!(REQUIRED_FIELDS
        .iter()
        .all(|r| MESSAGE_FIELDS.iter().any(|(l, _)| l == r)));
}

/// The one `DatabaseUnreadable` record a walk whose query did not run owes.
fn query_unreadable(arts: &[Artifact]) -> &Artifact {
    let v: Vec<&Artifact> = arts
        .iter()
        .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
        .collect();
    assert_eq!(
        v.len(),
        1,
        "a query that did not run must leave exactly one DatabaseUnreadable record; got {} \
         artifact(s): {:?}",
        arts.len(),
        arts.iter()
            .map(|a| a.metadata["type"].clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(v[0].metadata["type"], json!("ViberIncomplete"));
    v[0]
}

/// HUNT-189: after `messages` and its columns were established, a statement
/// that would not prepare returned an empty list — a phone with no Viber
/// messages, as far as the case file could tell.
#[test]
fn a_messages_table_whose_query_will_not_run_is_reported_unreadable_not_empty() {
    let db = viber_db(concat!(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
         INSERT INTO messages VALUES (1, 10, 'Hi from Viber', 1672848000000, 0);",
        // `date` declared with Android's framework-only `LOCALIZED`
        // collation, which stock SQLite does not have: the store opens and
        // lists its columns, and the `ORDER BY date` will not prepare. The
        // catalogue is edited because SQLite refuses to CREATE a table with a
        // collation it does not know.
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master SET sql = replace(sql, 'date INTEGER', 'date INTEGER COLLATE LOCALIZED')
           WHERE name = 'messages';
         PRAGMA writable_schema = OFF;"
    ));
    let arts = run("viber_messages", db);
    assert!(messages(&arts).is_empty());
    let m = query_unreadable(&arts);
    assert_eq!(m.metadata["source_table"], json!("messages"));
    assert_eq!(m.metadata["content_incomplete"], json!(true));
    assert!(m.metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
}
