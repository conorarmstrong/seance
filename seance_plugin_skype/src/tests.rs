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

fn skype_db(batch: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_skype_{}.db", Uuid::new_v4()));
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
    SkypeParser.process(&art).unwrap()
}

fn by_rowid(arts: &[Artifact], rowid: i64) -> &Artifact {
    arts.iter()
        .find(|a| a.metadata.get("rowid").and_then(|v| v.as_i64()) == Some(rowid))
        .expect("record present")
}

/// Skype's own version table, transcribed from the real `main.db` on file
/// (plaso's `skype_main.db`: ClientVersion `0/6.6.0.106//_checksum_3768521794`,
/// SQLiteSchemaVersion 66, SchemaUpdateType 3; `PRAGMA user_version` is 0
/// there, which is why the parser does not read it).
const APP_SCHEMA_VERSION_66: &str = "CREATE TABLE AppSchemaVersion (ClientVersion TEXT NOT NULL, SQLiteSchemaVersion INTEGER NOT NULL, SchemaUpdateType INTEGER NOT NULL);
    INSERT INTO AppSchemaVersion VALUES ('0/6.6.0.106//_checksum_3768521794', 66, 3);";

const SKYPE_MESSAGES: &str = "CREATE TABLE Accounts (skypename TEXT);
    INSERT INTO Accounts VALUES ('alice.owner');
    CREATE TABLE Messages (id INTEGER PRIMARY KEY, author TEXT, from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, body_xml TEXT, chatname TEXT);
    INSERT INTO Messages VALUES (1, 'bob.friend', 'Bob Friend', 'bob.friend', 1673000000, 'Hi &amp; welcome <ss type=\"smile\">:)</ss>', 'chat1');
    INSERT INTO Messages VALUES (2, 'alice.owner', 'Alice Owner', 'bob.friend', 1673000060, 'Reply from me', 'chat1');";

fn with_version(batch: &str, version: i64) -> String {
    format!(
        "CREATE TABLE AppSchemaVersion (ClientVersion TEXT NOT NULL, SQLiteSchemaVersion INTEGER NOT NULL, SchemaUpdateType INTEGER NOT NULL);
         INSERT INTO AppSchemaVersion VALUES ('0/6.6.0.106//_checksum_3768521794', {version}, 3);
         {batch}"
    )
}

fn skype_fixture() -> Vec<u8> {
    skype_db(&format!("{APP_SCHEMA_VERSION_66}\n{SKYPE_MESSAGES}"))
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

#[test]
fn parses_messages_owner_direction_and_strips_body_xml() {
    let arts = run("main.db", skype_fixture());
    assert_eq!(arts.len(), 2);

    let recv = by_rowid(&arts, 1);
    assert_eq!(recv.metadata["direction"], "received");
    assert_eq!(recv.metadata["is_from_me"], false);
    assert_eq!(recv.metadata["service"], "Skype");
    // Tags stripped, &amp; decoded.
    assert_eq!(recv.metadata["text"], "Hi & welcome :)");
    assert_eq!(recv.metadata["contact"], "Bob Friend");
    // timestamp is Unix seconds (not milliseconds).
    assert_eq!(recv.metadata["date"].as_i64(), Some(1_673_000_000));

    let sent = by_rowid(&arts, 2);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);
    assert_eq!(sent.metadata["author"], "alice.owner");
}

/// BUG-225: without a conversation key every Skype message collapses into one
/// thread. `chatname` is Skype's own key and must be carried through.
#[test]
fn messages_carry_the_conversation_key() {
    let arts = run("main.db", skype_fixture());
    assert_eq!(arts.len(), 2);
    for a in &arts {
        assert_eq!(a.metadata["chat_identifier"], "chat1");
    }
}

/// A legacy schema without `chatname` still groups direct chats by the dialog
/// partner rather than dropping the key entirely.
#[test]
fn falls_back_to_dialog_partner_without_chatname() {
    const NO_CHATNAME: &str = "CREATE TABLE Accounts (skypename TEXT);
        INSERT INTO Accounts VALUES ('alice.owner');
        CREATE TABLE Messages (id INTEGER PRIMARY KEY, author TEXT, from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, body_xml TEXT);
        INSERT INTO Messages VALUES (1, 'bob.friend', 'Bob Friend', 'bob.friend', 1673000000, 'Hi');";
    let arts = run("main.db", skype_db(&with_version(NO_CHATNAME, 66)));
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["chat_identifier"], "bob.friend");
    // The missing conversation key is disclosed rather than passed over: the
    // records omit it, and the note names the logical field that went.
    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    assert_eq!(
        notes[0].metadata["status"],
        "SchemaOptionalFieldsUnresolved"
    );
    assert_eq!(
        notes[0].metadata["schema_unresolved_fields"],
        json!(["chat"])
    );
    assert!(notes[0].metadata.get("content_incomplete").is_none());
}

/// BUG-253: with no `Accounts` row there is no owner to compare the author
/// against, so the direction was never established. It must stay unknown rather
/// than being reported as received, which would invert every outgoing message.
#[test]
fn direction_is_unknown_without_an_owner_account() {
    // The Accounts table exists (Skype's schema marker) but carries no
    // skypename — a common state on a partially populated or wiped profile.
    const NO_ACCOUNT: &str = "CREATE TABLE Accounts (skypename TEXT);
        CREATE TABLE Messages (id INTEGER PRIMARY KEY, author TEXT, from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, body_xml TEXT, chatname TEXT);
        INSERT INTO Messages VALUES (1, 'bob.friend', 'Bob Friend', 'bob.friend', 1673000000, 'Hi', 'chat1');";
    let arts = run("main.db", skype_db(&with_version(NO_ACCOUNT, 66)));
    assert_eq!(arts.len(), 1);
    assert!(
        arts[0].metadata.get("direction").is_none(),
        "an unestablished direction must not be asserted"
    );
    assert!(arts[0].metadata.get("is_from_me").is_none());
    assert_eq!(arts[0].metadata["text"], "Hi");
}

#[test]
fn non_skype_main_db_is_ignored() {
    // A main.db without Skype's schema is not ours.
    let other =
        skype_db("CREATE TABLE settings (k TEXT, v TEXT); INSERT INTO settings VALUES ('a','b');");
    assert!(run("main.db", other).is_empty());
}

#[test]
fn skype_schema_under_other_name_is_ignored() {
    assert!(run("notes.db", skype_fixture()).is_empty());
}

#[test]
fn non_sqlite_is_ignored() {
    assert!(run("main.db", b"not a database".to_vec()).is_empty());
}

#[test]
fn module_metadata() {
    let p = SkypeParser;
    assert_eq!(p.id(), "plugin.messaging.skype");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}
fn run_source(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    SkypeParser.process(&art).unwrap()
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source("main.db", Arc::new(truncated(skype_fixture())));
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
    let out = run("main.db", skype_fixture());
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
    let out = run_source("main.db", Arc::new(DribbleSource::new(skype_fixture(), 4)));
    assert!(!out.is_empty(), "a chunked source is not a non-SQLite file");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// B3-023: `rows.flatten()` swallowed rows that would not decode, so a store
/// with corrupt rows reported an exact-looking message count. What an examiner
/// learns from the marker: the count is a floor. A wrong answer looks like "1
/// Skype message" for a database that holds two.
#[test]
fn undecodable_message_rows_are_tallied_not_silently_dropped() {
    // `id` declared INTEGER: INTEGER affinity keeps `1` an integer and stores
    // the non-numeric `'corrupt'` as TEXT, so exactly one of the two rows makes
    // `row.get::<i64>` fail, as a corrupt page would. A TEXT-affinity column
    // would convert BOTH values to text and drop the whole table, which would
    // not test the tally at all.
    let arts = run(
        "main.db",
        skype_db(&with_version(
            "CREATE TABLE Accounts (skypename TEXT);
             INSERT INTO Accounts VALUES ('alice.owner');
             CREATE TABLE Messages (id INTEGER, author TEXT, from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, body_xml TEXT, chatname TEXT);
             INSERT INTO Messages VALUES (1, 'bob.friend', 'Bob', 'bob.friend', 1673000000, 'readable', 'chat1');
             INSERT INTO Messages VALUES ('corrupt', 'bob.friend', 'Bob', 'bob.friend', 1673000060, 'unreachable', 'chat1');",
            66,
        )),
    );

    let messages = arts
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .count();
    assert_eq!(messages, 1, "only the decodable row yields a message");

    let marker = arts
        .iter()
        .find(|a| a.metadata["type"] == "SkypeIncomplete")
        .expect("a dropped row must produce an incompleteness marker");
    assert_eq!(marker.metadata["status"], "RowsUndecodable");
    assert_eq!(marker.metadata["rows_dropped"], 1);
    assert_eq!(marker.metadata["records_recovered"], 1);
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["inventory_incomplete"], true);
}

/// B3-023 control: a store whose rows all decode carries no dropped-row marker.
#[test]
fn a_fully_decodable_skype_database_has_no_dropped_row_marker() {
    let arts = run("main.db", skype_fixture());
    assert!(!arts
        .iter()
        .any(|a| a.metadata["status"] == "RowsUndecodable"));
}

/// ROADMAP §1.4a. Skype records its schema version in its own
/// `AppSchemaVersion.SQLiteSchemaVersion`, not in `PRAGMA user_version` (which
/// is 0 on the real file). The validated range is 66..=66 because one real
/// store was read. A store past it is disclosed with the version seen and the
/// range, and still parsed: every column resolved, so nothing is claimed
/// incomplete.
#[test]
fn a_skype_store_past_the_validated_schema_version_is_disclosed_and_still_parsed() {
    let arts = run("main.db", skype_db(&with_version(SKYPE_MESSAGES, 99)));

    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 2, "{arts:?}");
    seance_core::test_support::assert_no_incompleteness_stamps(msgs.iter().copied());

    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    let note = notes[0];
    assert_eq!(note.metadata["type"], "SkypeIncomplete");
    assert_eq!(note.metadata["status"], "SchemaOutsideValidated");
    assert_eq!(note.metadata["schema_version_seen"], 99);
    assert_eq!(note.metadata["schema_version_supported"], "66..=66");
    assert_eq!(
        note.metadata["schema_version_locator"],
        "AppSchemaVersion.SQLiteSchemaVersion"
    );
    assert!(note.metadata["schema_version_evidence"]
        .as_str()
        .unwrap()
        .contains("skype_main.db"));
    assert!(note.metadata.get("content_incomplete").is_none());
}

/// The positive anchor: at 66 with every field resolving there is no note,
/// and in particular `PRAGMA user_version` being 0 (as on the real file) is
/// not read as "older than the range".
#[test]
fn a_skype_store_at_the_validated_schema_version_carries_no_schema_note() {
    let arts = run("main.db", skype_fixture());
    assert_eq!(messages(&arts).len(), 2);
    assert!(schema_notes(&arts).is_empty(), "{arts:?}");
}

/// No `AppSchemaVersion` table at all: the version is not recorded where this
/// parser looks, and the store is compared against nothing — not called older,
/// not called in range.
#[test]
fn a_skype_store_without_the_version_table_is_disclosed_as_unrecorded() {
    let arts = run("main.db", skype_db(SKYPE_MESSAGES));
    assert_eq!(messages(&arts).len(), 2);
    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    assert_eq!(notes[0].metadata["status"], "SchemaVersionNotRecorded");
    assert_eq!(notes[0].metadata["schema_version_not_recorded"], true);
    assert!(notes[0].metadata.get("schema_version_seen").is_none());
    assert!(notes[0].metadata.get("content_incomplete").is_none());
}

/// A renamed body column used to make this store "not Skype" and yield
/// nothing. `Accounts.skypename` plus a `Messages` table is Skype's signature
/// on its own, so the store is still recognised, what can be parsed is, and
/// the note names the LOGICAL field that went — the examiner needs to know
/// the message text is missing, not which column list was tried.
#[test]
fn a_skype_store_that_renamed_the_body_column_claims_incompleteness_and_names_the_field() {
    const RENAMED: &str = "CREATE TABLE Accounts (skypename TEXT);
        INSERT INTO Accounts VALUES ('alice.owner');
        CREATE TABLE Messages (id INTEGER PRIMARY KEY, author TEXT, from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, body_text TEXT, chatname TEXT);
        INSERT INTO Messages VALUES (1, 'bob.friend', 'Bob Friend', 'bob.friend', 1673000000, 'Hi', 'chat1');";
    let arts = run("main.db", skype_db(&with_version(RENAMED, 66)));

    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 1, "what can be parsed still is: {arts:?}");
    assert!(msgs[0].metadata.get("text").is_none());
    assert_eq!(msgs[0].metadata["date"].as_i64(), Some(1_673_000_000));

    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    let note = notes[0];
    assert_eq!(note.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(note.metadata["schema_unresolved_fields"], json!(["body"]));
    assert_eq!(note.metadata["content_incomplete"], true);
    assert_eq!(note.metadata["content_incomplete_reason"], "unvalidated");
    assert_eq!(note.metadata["inventory_incomplete"], true);
    assert_eq!(note.metadata["records_recovered"], 1);
    assert_eq!(note.metadata["subtype"], "parser_stale");
}

/// The corpus-diff anchor, gated on `SEANCE_SKYPE_SAMPLES` (a directory
/// holding plaso's `skype_main.db`). The real store reads
/// SQLiteSchemaVersion 66, every column the parser reads resolves, and it
/// holds exactly 15 `Messages` rows, so a duplicated or dropped row fails.
#[test]
fn the_real_skype_store_reads_schema_version_66_and_every_field_resolves() {
    use seance_core::data_source::FileDataSource;
    use seance_core::test_support::corpus;

    let Some(path) = corpus::file("SEANCE_SKYPE_SAMPLES", "skype_main.db") else {
        return;
    };
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let out = run_source("main.db", ds);
    assert_eq!(messages(&out).len(), 15, "{out:?}");
    assert!(schema_notes(&out).is_empty(), "{out:?}");
    seance_core::test_support::assert_no_incompleteness_stamps(out.iter());
}
