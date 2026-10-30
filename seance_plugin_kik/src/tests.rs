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

fn kik_db(batch: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_kik_{}.db", Uuid::new_v4()));
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
    KikParser.process(&art).unwrap()
}

fn by_rowid(arts: &[Artifact], rowid: i64) -> &Artifact {
    arts.iter()
        .find(|a| a.metadata.get("rowid").and_then(|v| v.as_i64()) == Some(rowid))
        .expect("record present")
}

const SCHEMA: &str = "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, body TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
    CREATE TABLE KIKcontactsTable (jid TEXT, display_name TEXT);
    INSERT INTO KIKcontactsTable VALUES ('alice_x1@talk.kik.com', 'Alice');
    INSERT INTO messagesTable VALUES (1, 'Hi there', 'alice_x1@talk.kik.com', 0, 1672848000000);
    INSERT INTO messagesTable VALUES (2, 'Sent back', 'alice_x1@talk.kik.com', 1, 1672848060000);
    INSERT INTO messagesTable VALUES (3, 'from a stranger', 'bob_y2@talk.kik.com', 0, 1672848120000);";

#[test]
fn parses_messages_and_resolves_contact_names() {
    let arts = run("kikDatabase.db", kik_db(SCHEMA));
    assert_eq!(messages(&arts).len(), 3);

    let recv = by_rowid(&arts, 1);
    assert_eq!(recv.metadata["direction"], "received");
    assert_eq!(recv.metadata["is_from_me"], false);
    assert_eq!(recv.metadata["text"], "Hi there");
    assert_eq!(recv.metadata["service"], "Kik");
    // Contact name resolved from KIKcontactsTable.
    assert_eq!(recv.metadata["contact"], "Alice");
    assert_eq!(recv.metadata["chat_identifier"], "alice_x1@talk.kik.com");
    assert_eq!(recv.metadata["date"].as_i64(), Some(1_672_848_000));

    let sent = by_rowid(&arts, 2);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    // Unknown JID falls back to the raw JID as the contact.
    let stranger = by_rowid(&arts, 3);
    assert_eq!(stranger.metadata["contact"], "bob_y2@talk.kik.com");
}

#[test]
fn works_without_a_contacts_table() {
    let db = kik_db(
        "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, body TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
         INSERT INTO messagesTable VALUES (1, 'no contacts table', 'z@talk.kik.com', 1, 1672848000000);",
    );
    let arts = run("kikDatabase.db", db);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["contact"], "z@talk.kik.com");
    assert_eq!(arts[0].metadata["direction"], "sent");
}

/// BUG-253: a schema with no `was_me` column, or a NULL in it, never recorded
/// the direction. It must stay unknown rather than be asserted as received.
#[test]
fn direction_is_unknown_without_was_me() {
    let db = kik_db(
        "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, body TEXT, partner_jid TEXT, timestamp INTEGER);
         INSERT INTO messagesTable VALUES (1, 'no was_me column', 'z@talk.kik.com', 1672848000000);",
    );
    let arts = run("kikDatabase.db", db);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
    assert!(arts[0].metadata.get("is_from_me").is_none());
    assert_eq!(arts[0].metadata["text"], "no was_me column");

    let null_flag = kik_db(
        "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, body TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
         INSERT INTO messagesTable VALUES (1, 'null was_me', 'z@talk.kik.com', NULL, 1672848000000);",
    );
    let arts = run("kikDatabase.db", null_flag);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
}

#[test]
fn skips_non_kik_name() {
    assert!(run("other.db", kik_db(SCHEMA)).is_empty());
}

#[test]
fn ignores_non_sqlite_and_wrong_schema() {
    assert!(run("kikDatabase.db", b"not a database".to_vec()).is_empty());
    let other = kik_db("CREATE TABLE unrelated (a INTEGER);");
    assert!(run("kikDatabase.db", other).is_empty());
}

#[test]
fn module_metadata() {
    let p = KikParser;
    assert_eq!(p.id(), "plugin.messaging.kik");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}
fn run_source(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    KikParser.process(&art).unwrap()
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source("kikDatabase.db", Arc::new(truncated(kik_db(SCHEMA))));
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
    let out = run("kikDatabase.db", kik_db(SCHEMA));
    assert!(!out.is_empty());
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// The magic probe loops over short reads. A source that answers four bytes per
/// call holds a perfectly good database; refusing it would drop the whole store
/// on nothing more than the shape of the read.
#[test]
fn a_source_that_answers_in_small_chunks_is_still_parsed() {
    let out = run_source(
        "kikDatabase.db",
        Arc::new(DribbleSource::new(kik_db(SCHEMA), 4)),
    );
    assert!(!out.is_empty(), "a chunked source is not a non-SQLite file");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// B3-023: undecodable rows were swallowed by `flatten()`, so the message count
/// read as exact for a store that held more. Kik walks two tables, and BOTH
/// need their own marker: a lost contact row is a lost identity, and the
/// messages that JID sent are then attributed to a bare handle with nothing
/// saying the name was there and unreadable.
#[test]
fn undecodable_rows_in_either_table_are_counted_marked_and_explained() {
    let db = kik_db(
        "CREATE TABLE messagesTable (_id, body TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
         CREATE TABLE KIKcontactsTable (jid, display_name TEXT);
         INSERT INTO messagesTable VALUES (1, 'decodes fine', 'friend@kik', 0, 1672848000000);
         -- `_id` is read as a non-null i64; TEXT here will not decode.
         INSERT INTO messagesTable VALUES ('not-an-integer', 'lost row', 'friend@kik', 0, 1672848060000);
         INSERT INTO KIKcontactsTable VALUES ('friend@kik', 'Friend');
         -- `jid` is read as a non-null String; an integer here will not decode.
         INSERT INTO KIKcontactsTable VALUES (42, 'Lost Identity');",
    );
    let out = run("kikDatabase.db", db);

    let messages: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 1, "only the decodable row yields a message");

    let msg_marker = out
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a dropped message row must produce a marker");
    assert_eq!(msg_marker.metadata["type"], "KikIncomplete");
    assert_eq!(msg_marker.metadata["subtype"], "parse_incomplete");
    assert_eq!(msg_marker.metadata["status"], "RowsUndecodable");
    assert_eq!(msg_marker.metadata["source_table"], "messagesTable");
    assert_eq!(msg_marker.metadata["rows_dropped"], json!(1));
    assert_eq!(msg_marker.metadata["records_recovered"], json!(1));
    assert_eq!(msg_marker.metadata["content_incomplete"], json!(true));
    assert_eq!(msg_marker.metadata["inventory_incomplete"], json!(true));
    assert!(msg_marker.metadata["first_error"].is_string());

    let contact_marker = out
        .iter()
        .find(|a| a.metadata["type"] == "KikContactIncomplete")
        .expect("a dropped contact row must produce its own marker");
    assert_eq!(contact_marker.metadata["source_table"], "KIKcontactsTable");
    assert_eq!(contact_marker.metadata["rows_dropped"], json!(1));
    assert_eq!(contact_marker.metadata["records_recovered"], json!(1));
    assert_eq!(contact_marker.metadata["content_incomplete"], json!(true));

    // Neither marker may reuse the walk's own record type: `seance_db` groups
    // conversations by `metadata.$.type`, and a marker filed as "Kik" would
    // appear in the Conversations view as a one-message thread.
    assert!(out
        .iter()
        .all(|a| a.metadata["type"] != json!("Kik")
            || a.metadata["subtype"] == json!("chat_message")));
}

/// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6`, so the schema catalogue will not
/// read while the file still opens.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

/// B8-039. `table_columns` ends in an empty set when the PRAGMA fails, and an empty set
/// fails the `body`/`timestamp` check, so the parser returned nothing
/// for a store it could not read. Nothing is exactly what a device that never
/// had Kik produces, so a damaged database was reported as an app that was
/// never installed — an exculpatory finding nobody established.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn a_corrupt_store_is_not_reported_as_a_device_without_the_app() {
    let out = run("kikDatabase.db", corrupt_the_catalogue(kik_db(SCHEMA)));

    assert!(
        !out.is_empty(),
        "an unreadable Kik store must not render as a device that never had Kik"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("KikIncomplete"));
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

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
    let temp = TempDb::write(&bytes, "kik_schema_test").unwrap();
    parse_kik_with(temp.path(), Uuid::new_v4(), Uuid::new_v4(), support)
}

/// A store whose `PRAGMA user_version` is beyond the range a parser was
/// validated against must say so — and must still parse what it can. The
/// crate's own declaration is Unranged (no real Kik Android store is held), so
/// the Validated bound here is injected; the range is a test value and asserts
/// nothing about any Kik build.
#[test]
fn a_schema_version_beyond_the_validated_range_is_declared_and_the_store_is_still_parsed() {
    let db = kik_db(&format!("PRAGMA user_version = 99; {SCHEMA}"));
    let support = SchemaSupport {
        app: "kik-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Kik build",
        },
    };
    let out = run_with_support(db, &support);

    assert_eq!(messages(&out).len(), 3, "the messages are still recovered");
    let stale = schema_records(&out);
    assert_eq!(stale.len(), 1, "{out:?}");
    let m = &stale[0].metadata;
    assert_eq!(m["type"], json!("KikIncomplete"));
    assert_eq!(m["subtype"], json!("parser_stale"));
    assert_eq!(m["status"], json!("SchemaOutsideValidated"));
    assert_eq!(m["schema_version_seen"], json!(99));
    assert_eq!(m["schema_version_supported"], json!("1..=3"));
    assert!(m["message"].as_str().unwrap().contains("NEWER"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A renamed message-body column used to make this parser return nothing at
/// all — indistinguishable from a device with no Kik messages. The FieldMap
/// turns that into a marker naming the LOGICAL field, and the rows the parser
/// can still read are still read.
#[test]
fn a_renamed_body_column_yields_a_marker_naming_the_unresolved_field() {
    let db = kik_db(
        "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, message_text TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
         INSERT INTO messagesTable VALUES (1, 'unreachable body', 'z@talk.kik.com', 1, 1672848000000);",
    );
    let out = run("kikDatabase.db", db);

    let marker = schema_records(&out);
    assert_eq!(marker.len(), 1, "{out:?}");
    let m = &marker[0].metadata;
    assert_eq!(m["type"], json!("KikIncomplete"));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("text"));
    let msgs = messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["date"], json!(1672848000));
    assert_eq!(msgs[0].metadata["direction"], json!("sent"));
    assert_eq!(msgs[0].metadata["chat_identifier"], json!("z@talk.kik.com"));
    assert!(msgs[0].metadata.get("text").is_none());
    assert_eq!(m["records_recovered"], json!(1));
}

/// When NEITHER field an evidentiary message needs resolves, no record is
/// invented — but the store is not reported as empty either.
#[test]
fn a_messages_table_with_no_recognised_column_yields_the_marker_and_no_records() {
    let db = kik_db(
        "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, payload TEXT, when_ms INTEGER);
         INSERT INTO messagesTable VALUES (1, 'x', 1672848000000);",
    );
    let out = run("kikDatabase.db", db);
    assert!(messages(&out).is_empty());
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text", "sent_at"]));
    assert_eq!(m["records_recovered"], json!(0));
}

/// No real Kik Android store is held by this project (the one real Kik
/// database here, `reference/plaso/test_data/kik_ios.sqlite`, is the iOS Core
/// Data store this parser does not read), so the crate declares Unranged: the
/// record says so, reports the version the store carries, and carries NO range.
#[test]
fn a_parser_with_no_reference_database_declares_that_rather_than_a_range() {
    let db = kik_db(&format!("PRAGMA user_version = 7; {SCHEMA}"));
    let out = run("kikDatabase.db", db);
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["type"], json!("KikIncomplete"));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_seen"], json!(7));
    assert!(m.get("schema_version_supported").is_none(), "{m}");
    assert!(m.get("supported_range").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("no reference database"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert_eq!(messages(&out).len(), 3);
}

/// `PRAGMA user_version` reads 0 on a store that never set it — SQLite's
/// default. That is the absence of a version, never "version 0".
#[test]
fn a_user_version_of_zero_is_the_absence_of_a_version_not_a_version_of_zero() {
    let out = run("kikDatabase.db", kik_db(SCHEMA));
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_recorded"], json!(false));
    assert!(m.get("schema_version_seen").is_none(), "{m}");

    let support = SchemaSupport {
        app: "kik-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Kik build",
        },
    };
    let out = run_with_support(kik_db(SCHEMA), &support);
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaVersionNotRecorded"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A version the store would not answer is never spent as "in range".
#[test]
fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
    let support = SchemaSupport {
        app: "kik-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Kik build",
        },
    };
    let fields = FieldMap::resolve(
        &["body".to_string(), "timestamp".to_string()]
            .into_iter()
            .collect(),
        MESSAGE_FIELDS,
    );
    let rec = SchemaCheck {
        support: &support,
        version: SchemaVersion::Undetermined("PRAGMA user_version would not read".into()),
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "KikIncomplete",
        store: "messagesTable",
    }
    .marker(Uuid::new_v4(), Uuid::new_v4(), 3)
    .expect("an unanswered version is a record, not silence");
    assert_eq!(rec.metadata["status"], json!("SchemaVersionUndetermined"));
    assert!(rec.metadata.get("schema_version_seen").is_none());
}

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
    assert_eq!(v[0].metadata["type"], json!("KikIncomplete"));
    v[0]
}

/// Android declares its own collations (`LOCALIZED`, `PHONEBOOK`) through the
/// framework, not through stock SQLite; a store whose sort column carries one
/// opens, lists its tables and columns, and then refuses any statement that
/// sorts on that column with "no such collation sequence". This rewrites the
/// declared column in the catalogue — the one way to put an unregistered
/// collation on a table outside Android — so the fixture is the real table
/// with the real rows and one column declared as the framework declares it.
const LOCALIZED_TIMESTAMP: &str = "PRAGMA writable_schema = ON;
    UPDATE sqlite_master SET sql = replace(sql, 'timestamp INTEGER', 'timestamp INTEGER COLLATE LOCALIZED')
      WHERE name = 'messagesTable';
    PRAGMA writable_schema = OFF;";

/// HUNT-189: after `messagesTable` and its columns were established, a
/// statement that would not prepare returned an empty list.
#[test]
fn a_messages_table_whose_query_will_not_run_is_reported_unreadable_not_empty() {
    let db = kik_db(&format!("{SCHEMA}\n{LOCALIZED_TIMESTAMP}"));
    let arts = run("kikDatabase.db", db);
    assert!(messages(&arts).is_empty());
    let m = query_unreadable(&arts);
    assert_eq!(m.metadata["source_table"], json!("messagesTable"));
    assert!(m.metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
}

/// The `KikContactIncomplete` records in `arts` whose status is `status`.
fn contact_markers<'a>(arts: &'a [Artifact], status: &str) -> Vec<&'a Artifact> {
    arts.iter()
        .filter(|a| a.metadata["type"] == json!("KikContactIncomplete"))
        .filter(|a| a.metadata["status"] == json!(status))
        .collect()
}

const MESSAGES_ONLY: &str = "CREATE TABLE messagesTable (_id INTEGER PRIMARY KEY, body TEXT, partner_jid TEXT, was_me INTEGER, timestamp INTEGER);
    INSERT INTO messagesTable VALUES (1, 'Hi there', 'alice_x1@talk.kik.com', 0, 1672848000000);";

/// HUNT-226: `KIKcontactsTable` present, whose query will not run (here a view
/// that sorts under Android's framework-only `LOCALIZED` collation), left every
/// sender a bare JID and said nothing.
#[test]
fn a_contacts_query_that_will_not_run_is_reported_not_silently_unresolved() {
    let db = kik_db(&format!(
        "{MESSAGES_ONLY}
         CREATE TABLE contacts_store (jid TEXT, display_name TEXT);
         INSERT INTO contacts_store VALUES ('alice_x1@talk.kik.com', 'Alice');
         CREATE VIEW KIKcontactsTable AS SELECT jid, display_name FROM contacts_store
           ORDER BY display_name COLLATE LOCALIZED;"
    ));
    let arts = run("kikDatabase.db", db);
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 1, "the messages still walk: {arts:?}");
    assert_eq!(msgs[0].metadata["contact"], "alice_x1@talk.kik.com");
    let v = contact_markers(&arts, "DatabaseUnreadable");
    assert_eq!(
        v.len(),
        1,
        "no DatabaseUnreadable record for the contacts: {arts:?}"
    );
    assert_eq!(v[0].metadata["source_table"], json!("KIKcontactsTable"));
    assert!(v[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
}

/// HUNT-226: a `KIKcontactsTable` whose name column is not the one the query
/// names fails to prepare; the names were on the device and unread.
#[test]
fn a_contacts_table_without_the_expected_columns_is_reported() {
    let db = kik_db(&format!(
        "{MESSAGES_ONLY}
         CREATE TABLE KIKcontactsTable (jid TEXT, nickname TEXT);
         INSERT INTO KIKcontactsTable VALUES ('alice_x1@talk.kik.com', 'Alice');"
    ));
    let arts = run("kikDatabase.db", db);
    assert_eq!(messages(&arts).len(), 1);
    let v = contact_markers(&arts, "DatabaseUnreadable");
    assert_eq!(v.len(), 1, "{arts:?}");
    assert!(v[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("display_name"));
}

/// The control: no `KIKcontactsTable` at all is a store shape, not a failure.
#[test]
fn a_store_without_a_contacts_table_carries_no_contact_marker() {
    let arts = run("kikDatabase.db", kik_db(MESSAGES_ONLY));
    assert!(
        !arts
            .iter()
            .any(|a| a.metadata["type"] == json!("KikContactIncomplete")),
        "{arts:?}"
    );
}
