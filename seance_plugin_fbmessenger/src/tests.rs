use super::*;
use seance_core::test_support::{DribbleSource, TruncatedSource};

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

fn fb_db() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_fbm_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE messages (msg_id TEXT, thread_key TEXT, sender TEXT, text TEXT, timestamp_ms INTEGER, msg_type INTEGER);
               INSERT INTO messages VALUES ('m1', 't_100', '{"user_key":"FACEBOOK:100001","name":"Alice Smith"}', 'Hi on Messenger', 1673000000000, 0);
               INSERT INTO messages VALUES ('m2', 't_100', '{"user_key":"FACEBOOK:200002","name":"Bob"}', 'reply back', 1673000060000, 0);"#,
        )
        .unwrap();
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
    FbMessengerParser.process(&art).unwrap()
}

#[test]
fn parses_messages_and_sender_json() {
    let arts = run("threads_db2", fb_db());
    assert_eq!(arts.len(), 2);
    let first = &arts[0];
    assert_eq!(first.metadata["type"], "FacebookMessenger");
    assert_eq!(first.metadata["text"], "Hi on Messenger");
    assert_eq!(first.metadata["contact"], "Alice Smith");
    assert_eq!(first.metadata["sender_key"], "FACEBOOK:100001");
    assert_eq!(first.metadata["chat_identifier"], "t_100");
    assert_eq!(first.metadata["date"].as_i64(), Some(1_673_000_000));
}

#[test]
fn skips_non_fb_name() {
    assert!(run("other.db", fb_db()).is_empty());
}

#[test]
fn empty_on_unexpected_schema() {
    let path = std::env::temp_dir().join(format!("test_fbm_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE something_else (a INTEGER);")
            .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(run("threads_db2", data).is_empty());
}

#[test]
fn module_metadata() {
    let p = FbMessengerParser;
    assert_eq!(p.id(), "plugin.messaging.fb_messenger");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

// --- msys / lightspeed (newer store) -----------------------------------------

/// A decrypted `msys`/lightspeed store: numeric `sender_id` + integer
/// `thread_key`, names resolved from a `contacts` table.
fn msys_db() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_msys_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE contacts (id INTEGER, name TEXT);
               INSERT INTO contacts VALUES (100001, 'Alice Smith');
               INSERT INTO contacts VALUES (200002, 'Bob Jones');
               CREATE TABLE messages (thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
               INSERT INTO messages VALUES (555, 100001, 'Hi via msys', 1673000000000);
               INSERT INTO messages VALUES (555, 200002, 'reply via msys', 1673000060000);"#,
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

#[test]
fn parses_msys_lightspeed_with_contacts() {
    let arts = run("lightspeed-1614984829.db", msys_db());
    assert_eq!(arts.len(), 2);
    let first = &arts[0];
    assert_eq!(first.metadata["type"], "FacebookMessenger");
    assert_eq!(first.metadata["subtype"], "chat_message");
    assert_eq!(first.metadata["text"], "Hi via msys");
    // Numeric sender_id resolved to a name via the contacts table.
    assert_eq!(first.metadata["contact"], "Alice Smith");
    assert_eq!(first.metadata["sender_key"], "100001");
    // Integer thread_key coerced to a string identifier.
    assert_eq!(first.metadata["chat_identifier"], "555");
    assert_eq!(first.metadata["date"].as_i64(), Some(1_673_000_000));
    assert_eq!(first.metadata["platform"], "msys/lightspeed");
}

/// An encrypted iOS store (`.db.enc`, not a SQLite file) must be FLAGGED, not
/// silently dropped — the examiner needs to know a message store exists.
#[test]
fn flags_encrypted_lightspeed_store() {
    let arts = run(
        "lightspeed-1614984829.db.enc",
        vec![0x00, 0xD6, 0x93, 0x85, 0xF6],
    );
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["type"], "EncryptedMessengerDatabase");
    assert_eq!(arts[0].metadata["app"], "Facebook Messenger");
    assert_eq!(arts[0].metadata["status"], "Encrypted");
}

/// The unencrypted `lightspeed-sessionless.db` carries only schema facets, no
/// messages — it must parse to nothing, not error.
#[test]
fn sessionless_lightspeed_yields_nothing() {
    let path = std::env::temp_dir().join(format!("test_sessionless_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE msyssessionless_upgrade_cql_schema_facets (facet TEXT, version INTEGER);",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(run("lightspeed-sessionless.db", data).is_empty());
}

#[test]
fn store_kind_classification() {
    assert_eq!(
        messenger_db_kind("threads_db2"),
        Some(StoreKind::ThreadsDb2)
    );
    assert_eq!(
        messenger_db_kind("/path/lightspeed-123.db"),
        Some(StoreKind::Msys)
    );
    assert_eq!(
        messenger_db_kind("msys_database_9.db"),
        Some(StoreKind::Msys)
    );
    assert_eq!(
        messenger_db_kind("lightspeed-123.db.enc"),
        Some(StoreKind::EncryptedLightspeed)
    );
    assert_eq!(messenger_db_kind("photos.db"), None);
}
fn run_source(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    FbMessengerParser.process(&art).unwrap()
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source("threads_db2", Arc::new(truncated(fb_db())));
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
    let out = run("threads_db2", fb_db());
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
    let out = run_source("threads_db2", Arc::new(DribbleSource::new(fb_db(), 4)));
    assert!(!out.is_empty(), "a chunked source is not a non-SQLite file");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// A msys/lightspeed store whose first sixteen bytes are NOT the SQLite magic
/// is encrypted, and must be recorded. A file with fewer than sixteen bytes has
/// shown no header at all, and recording that as an encrypted Messenger store
/// asserts something the evidence does not support.
///
/// Against the unfixed code the four-byte case produced an
/// `EncryptedMessengerDatabase` record: the header probe was tested with
/// `is_sqlite_header(&head[..n])`, which is false both when the header is wrong
/// and when there was no header to read, and the two were treated alike.
#[test]
fn a_msys_file_too_short_to_show_a_header_is_not_called_encrypted() {
    let out = run("msys_database.db", vec![0x00, 0xD6, 0x93, 0x85]);
    assert!(
        out.is_empty(),
        "four bytes are not evidence of an encrypted Messenger store: {out:?}"
    );

    // The contrast: a full sixteen bytes that are not the SQLite magic IS the
    // encrypted store, and must still be flagged.
    let out = run("msys_database.db", vec![0xD6u8; 64]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "EncryptedMessengerDatabase");
    assert_eq!(out[0].metadata["status"], "Encrypted");
}

/// B3-023 control: a store whose rows all decode must carry no dropped-row
/// marker, or the marker means nothing when it does appear.
///
/// Messenger reads its columns through `col_str` / `col_i64`, which coerce
/// rather than fail, so its drop counter fires only on a storage-level error
/// (a damaged page mid-walk) — not on the column-type drift that trips the
/// plugins reading typed columns directly. The shape of the marker itself is
/// covered once, in `seance_sqlite_util`.
#[test]
fn a_fully_decodable_msys_store_carries_no_dropped_row_marker() {
    let path = std::env::temp_dir().join(format!("test_fbm_drop_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (thread_key TEXT, sender_id TEXT, text TEXT, timestamp_ms INTEGER);
             INSERT INTO messages VALUES ('t1', '100001', 'hello', 1673000000000);
             CREATE TABLE contacts (id TEXT, name TEXT);
             INSERT INTO contacts VALUES ('100001', 'Alice');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    // Control: everything decodes, so nothing is marked. The marker only means
    // something if a clean parse never carries one.
    let out = run("msys_database.db", data);
    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == "RowsUndecodable"),
        "a fully decodable store must carry no dropped-row marker"
    );
    assert!(out.iter().any(|a| a.metadata["subtype"] == "chat_message"));
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
/// fails the `text` check, so the parser returned nothing
/// for a store it could not read. Nothing is exactly what a device that never
/// had Messenger produces, so a damaged database was reported as an app that was
/// never installed — an exculpatory finding nobody established.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn a_corrupt_store_is_not_reported_as_a_device_without_the_app() {
    let out = run("threads_db2", corrupt_the_catalogue(fb_db()));

    assert!(
        !out.is_empty(),
        "an unreadable Messenger store must not render as a device that never had Messenger"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(
        marker.metadata["type"],
        json!("FacebookMessengerIncomplete")
    );
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

/// The marker records this parse emitted about the schema itself.
fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

fn db_from_sql(sql: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_fbm_sql_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

/// A renamed `messages` column is named by the logical field it carried, and
/// the rows still walk with that field absent. The old code returned an empty
/// list when `text` was missing — silence indistinguishable from an account
/// with no messages.
#[test]
fn a_renamed_messages_column_is_declared_by_logical_field_and_the_rows_still_walk() {
    let db = db_from_sql(
        r#"CREATE TABLE messages (msg_id TEXT, thread_key TEXT, sender TEXT, body TEXT, timestamp_ms INTEGER);
           INSERT INTO messages VALUES ('m1', 't_100', '{"user_key":"FACEBOOK:100001","name":"Alice Smith"}', 'renamed', 1673000000000);"#,
    );
    let result = run("threads_db2", db);
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(m.metadata["app"], SCHEMA_APP);
    assert_eq!(m.metadata["source_table"], "messages");
    assert_eq!(m.metadata["unresolved_fields"], json!(["text"]));
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_ne!(
        m.metadata["type"], "FacebookMessenger",
        "never the walk's own type"
    );
    let msgs: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(msgs.len(), 1, "the row is still walked");
    assert_eq!(msgs[0].metadata["contact"], "Alice Smith");
    assert!(
        msgs[0].metadata.get("text").is_none_or(|t| t.is_null()),
        "no body column resolved, so no text is written"
    );
}

/// Two renames are both named, in declaration order.
#[test]
fn every_unresolved_messages_field_is_named() {
    let db = db_from_sql(
        "CREATE TABLE messages (msg_id TEXT, thread_key TEXT, sender_id INTEGER, text TEXT, sent_at INTEGER);
         INSERT INTO messages VALUES ('m1', 't_100', 100001, 'undated', 1673000000000);",
    );
    let result = run("msys_database_9.db", db);
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(
        markers[0].metadata["unresolved_fields"],
        json!(["timestamp"])
    );
    let msgs: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].metadata.get("date").is_none_or(|d| d.is_null()));
}

/// The `contacts` lookup has its own column set and its own marker: a renamed
/// name column leaves the messages attributed by numeric id, and says so.
#[test]
fn a_renamed_contacts_column_is_declared_under_the_contacts_table() {
    let db = db_from_sql(
        "CREATE TABLE contacts (id INTEGER, label TEXT);
         INSERT INTO contacts VALUES (100001, 'Alice Smith');
         CREATE TABLE messages (thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
         INSERT INTO messages VALUES (555, 100001, 'Hi via msys', 1673000000000);",
    );
    let result = run("lightspeed-1614984829.db", db);
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(markers[0].metadata["source_table"], "contacts");
    assert_eq!(markers[0].metadata["unresolved_fields"], json!(["name"]));
    let msgs: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["contact"], "100001");
}

/// No real Messenger store — `threads_db2`, `msys_database_*.db` or
/// `lightspeed-*.db` — has been observed on any corpus this parser was run
/// against, so no schema-version window is declared and none is enforced: a
/// window nobody observed would be a fabrication. This pins that state; the
/// day a real store is added, this test is replaced by one that declares the
/// observed version.
#[test]
fn no_version_window_is_claimed_because_no_real_store_has_been_observed() {
    for v in [0, 999] {
        let db = db_from_sql(&format!(
            r#"PRAGMA user_version = {v};
               CREATE TABLE messages (msg_id TEXT, thread_key TEXT, sender TEXT, text TEXT, timestamp_ms INTEGER);
               INSERT INTO messages VALUES ('m1', 't_100', '{{"user_key":"FACEBOOK:1","name":"A"}}', 'hi', 1673000000000);"#
        ));
        let result = run("threads_db2", db);
        assert!(
            stale_markers(&result).is_empty(),
            "user_version {v}: no window is declared, so no version marker: {result:?}"
        );
        assert!(result
            .iter()
            .any(|a| a.metadata["subtype"] == "chat_message"));
    }
}

/// HUNT-189: `messages` found and its columns resolved, and a statement that
/// would not prepare (`timestamp_ms` declared with Android's framework-only
/// `LOCALIZED` collation, which the `ORDER BY` needs) returned an empty list.
#[test]
fn a_messages_table_whose_query_will_not_run_is_reported_unreadable_not_empty() {
    let path = std::env::temp_dir().join(format!("test_fbm_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE messages (msg_id TEXT, thread_key TEXT, sender TEXT, text TEXT, timestamp_ms INTEGER, msg_type INTEGER);
               INSERT INTO messages VALUES ('m1', 't_100', '{"user_key":"FACEBOOK:100001","name":"Alice Smith"}', 'Hi on Messenger', 1673000000000, 0);
               PRAGMA writable_schema = ON;
               UPDATE sqlite_master SET sql = replace(sql, 'timestamp_ms INTEGER', 'timestamp_ms INTEGER COLLATE LOCALIZED')
                 WHERE name = 'messages';
               PRAGMA writable_schema = OFF;"#,
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let out = run("threads_db2", bytes);
    let v: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
        .collect();
    assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
    assert_eq!(v[0].metadata["type"], json!("FacebookMessengerIncomplete"));
    assert!(v[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
}

/// The `contacts` records of `ty` in `out` whose status is `status`.
fn contact_markers<'a>(out: &'a [Artifact], status: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == json!("FacebookMessengerContactIncomplete"))
        .filter(|a| a.metadata["status"] == json!(status))
        .collect()
}

/// HUNT-225: a msys `contacts` lookup present with both its columns, whose
/// query will not run (here a view that sorts under Android's framework-only
/// `LOCALIZED` collation), left every sender a bare numeric id and said
/// nothing — indistinguishable from a store that never held the names.
#[test]
fn a_contacts_query_that_will_not_run_is_reported_not_silently_unresolved() {
    let db = db_from_sql(
        "CREATE TABLE contacts_store (id INTEGER, name TEXT);
         INSERT INTO contacts_store VALUES (100001, 'Alice Smith');
         CREATE VIEW contacts AS SELECT id, name FROM contacts_store
           ORDER BY name COLLATE LOCALIZED;
         CREATE TABLE messages (thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
         INSERT INTO messages VALUES (555, 100001, 'Hi via msys', 1673000000000);",
    );
    let out = run("lightspeed-1614984829.db", db);
    let msgs: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(msgs.len(), 1, "the messages still walk: {out:?}");
    assert_eq!(msgs[0].metadata["contact"], "100001");
    let v = contact_markers(&out, "DatabaseUnreadable");
    assert_eq!(
        v.len(),
        1,
        "no DatabaseUnreadable record for `contacts`: {out:?}"
    );
    assert_eq!(v[0].metadata["source_table"], json!("contacts"));
    assert!(v[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
    assert_eq!(v[0].metadata["content_incomplete"], json!(true));
}

/// HUNT-225, the column list: a `contacts` view whose base table is gone lists
/// in the catalogue and will not answer `PRAGMA table_info`, so whether its
/// columns are there is undetermined — never "no names on the device".
#[test]
fn a_contacts_column_list_that_will_not_read_is_reported() {
    let db = db_from_sql(
        "CREATE TABLE contacts_store (id INTEGER, name TEXT);
         CREATE VIEW contacts AS SELECT id, name FROM contacts_store;
         DROP TABLE contacts_store;
         CREATE TABLE messages (thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
         INSERT INTO messages VALUES (555, 100001, 'Hi via msys', 1673000000000);",
    );
    let out = run("lightspeed-1614984829.db", db);
    assert_eq!(
        out.iter()
            .filter(|a| a.metadata["subtype"] == "chat_message")
            .count(),
        1
    );
    let v = contact_markers(&out, "StoreUnreadable");
    assert_eq!(v.len(), 1, "no marker for the unread column list: {out:?}");
    assert!(v[0].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("contacts"));
}

/// The control: a msys store with no `contacts` table at all is a store shape,
/// not a failure, and carries no contact marker.
#[test]
fn a_msys_store_without_a_contacts_table_carries_no_contact_marker() {
    let db = db_from_sql(
        "CREATE TABLE messages (thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
         INSERT INTO messages VALUES (555, 100001, 'Hi via msys', 1673000000000);",
    );
    let out = run("lightspeed-1614984829.db", db);
    assert!(
        !out.iter()
            .any(|a| a.metadata["type"] == json!("FacebookMessengerContactIncomplete")),
        "{out:?}"
    );
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// ROADMAP §5.11, owner decision (b) of 2026-09-26: the schema record speaks
/// the vocabulary every schema record shares.
#[test]
fn schema_records_speak_the_shared_vocabulary() {
    let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
    let present: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
    let map = seance_sqlite_util::FieldMap::resolve(&present, &[("a", &["a"]), ("b", &["b"])]);
    let m = field_drift_marker(c, p, "x", "t", &map, 1).unwrap();
    assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(m.subtype(), Some("parser_stale"));
    assert_eq!(m.metadata["subtype"], "parser_stale");
    assert_eq!(m.metadata["warning_class"], "ParserStaleWarning");
}
