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

fn line_db() -> Vec<u8> {
    line_db_with(0, "content")
}

/// Two-message `naver_line` at `user_version`, with the body column under
/// `text_col`. No real LINE store is held, so 0 (SQLite's default) is the
/// only version this fixture can honestly carry by default.
fn line_db_with(user_version: i64, text_col: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_line_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA user_version = {user_version};
             CREATE TABLE chat_history (id INTEGER PRIMARY KEY, chat_id TEXT, from_mid TEXT, {text_col} TEXT, created_time INTEGER, type INTEGER);
             INSERT INTO chat_history VALUES (1, 'c1', 'u_alice', 'Hello on LINE', 1673000000000, 1);
             INSERT INTO chat_history VALUES (2, 'c1', 'u_me', 'reply', 1673000060000, 1);"
        ))
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

fn schema_notes(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["warning_class"] == "ParserStaleWarning")
        .collect()
}

fn messages(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect()
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    LineParser.process(&art).unwrap()
}

#[test]
fn parses_chat_history() {
    let arts = run("naver_line", line_db());
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 2);
    let first = msgs
        .iter()
        .find(|a| a.metadata.get("rowid").and_then(|v| v.as_i64()) == Some(1))
        .unwrap();
    assert_eq!(first.metadata["type"], "LINE");
    assert_eq!(first.metadata["text"], "Hello on LINE");
    assert_eq!(first.metadata["contact"], "u_alice");
    assert_eq!(first.metadata["chat_identifier"], "c1");
    assert_eq!(first.metadata["date"].as_i64(), Some(1_673_000_000));
}

/// BUG-276: `chat_id` is an integer conversation id on several LINE
/// generations. Binding it as a String errored on every row, so a valid
/// database emitted zero messages with no marker at all.
#[test]
fn parses_integer_chat_id_and_from_mid() {
    let path = std::env::temp_dir().join(format!("test_line_int_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chat_history (id INTEGER PRIMARY KEY, chat_id INTEGER, from_mid INTEGER, content TEXT, created_time INTEGER, type INTEGER);
             INSERT INTO chat_history VALUES (1, 4242, 909, 'integer keys', 1673000000000, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("naver_line", data);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1, "integer chat_id must not drop the row");
    assert_eq!(arts[0].metadata["chat_identifier"], "4242");
    assert_eq!(arts[0].metadata["contact"], "909");
    assert_eq!(arts[0].metadata["text"], "integer keys");
    assert_eq!(arts[0].metadata["date"].as_i64(), Some(1_673_000_000));
}

/// A generation without `chat_id` / `from_mid` still yields its messages: the
/// columns are probed, so naming one the schema lacks cannot fail the query.
/// The missing fields are disclosed, not passed over: every record omits its
/// conversation and sender, and the note names both logical fields.
#[test]
fn parses_schema_without_chat_id_or_from_mid() {
    let path = std::env::temp_dir().join(format!("test_line_nocols_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chat_history (id INTEGER PRIMARY KEY, content TEXT, created_time INTEGER);
             INSERT INTO chat_history VALUES (1, 'no thread columns', 1673000000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("naver_line", data);
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["text"], "no thread columns");
    assert!(msgs[0].metadata.get("chat_identifier").is_none());
    assert!(msgs[0].metadata.get("contact").is_none());
    let note = schema_notes(&arts)
        .into_iter()
        .find(|a| a.metadata["status"] == "SchemaOptionalFieldsUnresolved")
        .expect("the absent conversation and sender columns are disclosed");
    assert_eq!(
        note.metadata["schema_unresolved_fields"],
        json!(["conversation", "sender"])
    );
    assert!(note.metadata.get("content_incomplete").is_none());
}

#[test]
fn flags_encrypted_db() {
    let mut enc = vec![0x00, 0x11, 0x22, 0x33];
    enc.extend_from_slice(&[0x55u8; 2048]);
    let arts = run("naver_line", enc);
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["type"], "EncryptedMessengerDatabase");
    assert_eq!(arts[0].metadata["app"], "LINE");
}

#[test]
fn skips_non_line_name() {
    assert!(run("other.db", line_db()).is_empty());
}

/// `naver_line` names LINE and nothing else. A readable catalogue with no
/// `chat_history` table is either a schema this parser predates or not the
/// message store — and silence would render exactly like a device with no
/// LINE messages. No garbage row is manufactured from it either.
#[test]
fn a_line_store_without_the_message_table_is_not_silently_empty() {
    let path = std::env::temp_dir().join(format!("test_line_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (a INTEGER);")
            .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let out = run("naver_line", data);
    assert!(messages(&out).is_empty());
    let notes = schema_notes(&out);
    assert_eq!(notes.len(), 1, "{out:?}");
    assert_eq!(notes[0].metadata["status"], "SchemaTableAbsent");
    assert_eq!(notes[0].metadata["table"], "chat_history");
    assert_eq!(notes[0].metadata["content_incomplete"], true);
    assert_eq!(
        notes[0].metadata["content_incomplete_reason"],
        "unvalidated"
    );
}

#[test]
fn module_metadata() {
    let p = LineParser;
    assert_eq!(p.id(), "plugin.messaging.line");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

/// A phone seized while LINE was running leaves the newest messages in the
/// `-wal`, not the main database. The spill must carry that sidecar across.
#[test]
fn uncheckpointed_wal_messages_are_parsed() {
    use seance_core::data_source::FileDataSource;

    let dir = std::env::temp_dir().join(format!("test_line_wal_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("naver_line");

    // Keep the seed connection open: closing it checkpoints the WAL away.
    let seed = Connection::open(&db).unwrap();
    seed.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    seed.execute_batch(
        "CREATE TABLE chat_history (id INTEGER PRIMARY KEY, chat_id TEXT, from_mid TEXT, content TEXT, created_time INTEGER, type INTEGER);
         INSERT INTO chat_history VALUES (1, 'c1', 'u_alice', 'checkpointed', 1673000000000, 1);",
    )
    .unwrap();
    seed.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    seed.execute_batch(
        "INSERT INTO chat_history VALUES (2, 'c1', 'u_alice', 'only in wal', 1673000060000, 1);",
    )
    .unwrap();

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(db).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "naver_line" }),
    );
    let arts = LineParser.process(&art).unwrap();
    let texts: Vec<&str> = messages(&arts)
        .iter()
        .map(|a| a.metadata["text"].as_str().unwrap())
        .collect();
    assert!(
        texts.contains(&"only in wal"),
        "uncheckpointed message must come across with the -wal sidecar, got {texts:?}"
    );

    drop(seed);
    let _ = std::fs::remove_dir_all(&dir);
}
fn run_source(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    LineParser.process(&art).unwrap()
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source("naver_line", Arc::new(truncated(line_db())));
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
    let out = run("naver_line", line_db());
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
    let out = run_source("naver_line", Arc::new(DribbleSource::new(line_db(), 4)));
    assert!(!out.is_empty(), "a chunked source is not a non-SQLite file");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// "The header is something else" and "there were not enough bytes to read a
/// header" are different facts. The first is LINE's encrypted store and must be
/// recorded; the second is a file this tool could not judge, and claiming it was
/// encrypted would put an assertion in the case file that the evidence does not
/// support. The gate reports how far the probe got so this stays decidable.
#[test]
fn a_file_too_short_to_show_a_header_is_not_called_encrypted() {
    let out = run("naver_line", vec![0x00, 0x11, 0x22, 0x33]);
    assert!(
        out.is_empty(),
        "four bytes are not evidence of an encrypted LINE store: {out:?}"
    );

    // The contrast: a full 16 bytes that are not the SQLite magic IS the
    // encrypted store, and must still be recorded.
    let mut enc = vec![0xAAu8; 64];
    enc[0] = 0x00;
    let out = run("naver_line", enc);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "EncryptedMessengerDatabase");
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
/// fails the `content`/`created_time` check, so the parser returned nothing
/// for a store it could not read. Nothing is exactly what a device that never
/// had LINE produces, so a damaged database was reported as an app that was
/// never installed — an exculpatory finding nobody established.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn a_corrupt_store_is_not_reported_as_a_device_without_the_app() {
    let out = run("naver_line", corrupt_the_catalogue(line_db()));

    assert!(
        !out.is_empty(),
        "an unreadable LINE store must not render as a device that never had LINE"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("LineIncomplete"));
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
}

/// ROADMAP §1.4a. No real LINE database is held by this project, so this
/// parser declares NO validated range — a range endpoint not read out of a
/// real file would be a number copied from somewhere. What it does instead:
/// record the version it saw and say plainly that it was compared against
/// nothing. There is therefore no "out of range" test here; there cannot be.
#[test]
fn a_line_store_declares_no_validated_range_and_records_the_version_it_saw() {
    let arts = run("naver_line", line_db_with(7, "content"));
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 2);
    seance_core::test_support::assert_no_incompleteness_stamps(msgs.iter().copied());

    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    let note = notes[0];
    assert_eq!(note.metadata["type"], "LineIncomplete");
    assert_eq!(note.metadata["status"], "SchemaNotRanged");
    assert_eq!(note.metadata["schema_version_seen"], 7);
    assert!(
        note.metadata.get("schema_version_supported").is_none(),
        "no range may be stated where none was validated: {note:?}"
    );
    assert!(note.metadata["schema_unranged_reason"]
        .as_str()
        .unwrap()
        .contains("no real"));
    assert!(note.metadata.get("content_incomplete").is_none());
    assert_eq!(note.metadata["subtype"], "parser_stale");
}

/// `PRAGMA user_version` 0 is SQLite's default, so it is the ABSENCE of a
/// version — never a version older than anything.
#[test]
fn a_line_store_that_never_recorded_a_version_is_disclosed_as_unrecorded_not_older() {
    let arts = run("naver_line", line_db());
    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    assert_eq!(notes[0].metadata["status"], "SchemaNotRanged");
    assert_eq!(notes[0].metadata["schema_version_not_recorded"], true);
    assert!(notes[0].metadata.get("schema_version_seen").is_none());
    assert!(!notes[0].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("OLDER"));
}

/// A column rename is the edit that turns a working parser into a silent one.
/// Before this, `content` going missing made the parser return nothing for a
/// store full of messages. Now what can be parsed is, and the note names the
/// LOGICAL field that went — the examiner needs to know the text is missing.
#[test]
fn a_line_store_that_renamed_the_body_column_claims_incompleteness_and_names_the_field() {
    let arts = run("naver_line", line_db_with(0, "body"));
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 2, "what can be parsed still is: {arts:?}");
    assert!(msgs.iter().all(|m| m.metadata.get("text").is_none()));
    assert_eq!(msgs[0].metadata["date"].as_i64(), Some(1_673_000_000));

    let note = schema_notes(&arts)
        .into_iter()
        .find(|a| a.metadata["status"] == "SchemaFieldsUnresolved")
        .expect("the missing body column must be reported");
    assert_eq!(note.metadata["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(note.metadata["content_incomplete"], true);
    assert_eq!(note.metadata["content_incomplete_reason"], "unvalidated");
    assert_eq!(note.metadata["inventory_incomplete"], true);
    assert_eq!(note.metadata["records_recovered"], 2);
    assert_eq!(note.metadata["subtype"], "parser_stale");
}

/// HUNT-189: `chat_history` found and its columns read, and a statement that
/// would not prepare (here: `created_time` declared with Android's
/// framework-only `LOCALIZED` collation, which the `ORDER BY` needs) returned
/// an empty list.
#[test]
fn a_chat_history_whose_query_will_not_run_is_reported_unreadable_not_empty() {
    let path = std::env::temp_dir().join(format!("test_line_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chat_history (id INTEGER PRIMARY KEY, chat_id TEXT, from_mid TEXT, content TEXT, created_time INTEGER, type INTEGER);
             INSERT INTO chat_history VALUES (1, 'c1', 'u_alice', 'Hello on LINE', 1673000000000, 1);
             PRAGMA writable_schema = ON;
             UPDATE sqlite_master SET sql = replace(sql, 'created_time INTEGER', 'created_time INTEGER COLLATE LOCALIZED')
               WHERE name = 'chat_history';
             PRAGMA writable_schema = OFF;",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let out = run("naver_line", bytes);
    assert!(messages(&out).is_empty());
    let v: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
        .collect();
    assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
    assert_eq!(v[0].metadata["type"], json!("LineIncomplete"));
    assert!(v[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("LOCALIZED"));
}
