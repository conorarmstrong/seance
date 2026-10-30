use super::*;
use seance_core::test_support::TruncatedSource;
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

use rusqlite::{params, Connection};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// TL's wire encoding of a `string`: a one-byte length — or `0xFE` plus a
/// three-byte little-endian length for 254 bytes and over — then the bytes,
/// then zero padding to the next 4-byte boundary.
fn tl_string(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    if s.len() < 254 {
        v.push(s.len() as u8);
    } else {
        v.push(0xFE);
        v.extend_from_slice(&(s.len() as u32).to_le_bytes()[..3]);
    }
    v.extend_from_slice(s);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// A serialized `TLRPC.Message` in the shape Telegram writes one: a constructor
/// id, the flag/id/peer words ahead of the body, `date`, the body, then a
/// trailing field.
///
/// The word values other than `date` and the body are arbitrary — the decoder
/// is told none of this layout and never reads them. That is the point: it must
/// find the body from the `date` anchor and TL's string framing alone, so a
/// build that adds or re-types a field ahead of `date` cannot move the answer.
fn tl_message(date: i32, body: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x3811_6ee0u32.to_le_bytes()); // constructor id
    v.extend_from_slice(&0x0000_0300u32.to_le_bytes()); // flags
    v.extend_from_slice(&7i32.to_le_bytes()); // message id
    v.extend_from_slice(&0x9db1_bc6du32.to_le_bytes()); // peer constructor
    v.extend_from_slice(&12_345i64.to_le_bytes()); // peer user id
    v.extend_from_slice(&date.to_le_bytes());
    v.extend_from_slice(&tl_string(body.as_bytes()));
    v.extend_from_slice(&0x3ded_6320u32.to_le_bytes()); // a field after the body
    v
}

/// A cache4.db whose single row carries `blob` in its `data` column.
fn db_with_blob(mid: i64, date: i64, blob: Vec<u8>) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_tg_blob_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages_v2 VALUES (?1, 12345, ?2, 0, ?3)",
            params![mid, date, blob],
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

fn telegram_db() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_tg_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
             INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 0, x'0102');
             INSERT INTO messages_v2 VALUES (2, 12345, 1673000060, 1, x'0304');
             INSERT INTO messages_v2 VALUES (3, -900123, 1673000120, 0, x'05');",
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
    TelegramParser.process(&art).unwrap()
}

#[test]
fn builds_timeline_metadata() {
    let arts = run("cache4.db", telegram_db());
    assert_eq!(messages(&arts).len(), 3);
    let first = arts
        .iter()
        .find(|a| a.metadata.get("mid").and_then(|v| v.as_i64()) == Some(1))
        .unwrap();
    assert_eq!(first.metadata["type"], "TelegramMessage");
    assert_eq!(first.metadata["direction"], "received");
    assert_eq!(first.metadata["chat_identifier"], "12345");
    assert_eq!(first.metadata["date"].as_i64(), Some(1_673_000_000));
    // Text is honestly flagged as not decoded.
    assert_eq!(
        first.metadata["content_encoding"],
        "TL-serialized (not decoded)"
    );
    assert!(first.metadata.get("text").is_none());

    let sent = arts
        .iter()
        .find(|a| a.metadata.get("mid").and_then(|v| v.as_i64()) == Some(2))
        .unwrap();
    assert_eq!(sent.metadata["direction"], "sent");

    // Groups/channels use a negative dialog id.
    let group = arts
        .iter()
        .find(|a| a.metadata.get("mid").and_then(|v| v.as_i64()) == Some(3))
        .unwrap();
    assert_eq!(group.metadata["chat_identifier"], "-900123");
}

#[test]
fn skips_non_telegram_name() {
    assert!(run("other.db", telegram_db()).is_empty());
}

#[test]
fn module_metadata() {
    let p = TelegramParser;
    assert_eq!(p.id(), "plugin.messaging.telegram");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

/// A NULL `out` column never recorded the direction. Reporting it as "received"
/// would put a message the owner sent into the inbound column of a report.
#[test]
fn a_null_out_column_leaves_the_direction_unknown() {
    let path = std::env::temp_dir().join(format!("test_tg_null_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
             INSERT INTO messages_v2 VALUES (7, 555, 1673000000, NULL, x'01');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("cache4.db", data);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    let md = &arts[0].metadata;
    assert!(
        md.get("direction").is_none(),
        "unknown direction must be absent, got {:?}",
        md.get("direction")
    );
    assert!(md.get("is_from_me").is_none());
    assert_eq!(md["chat_identifier"], "555");
}

/// A schema with no `out` column at all is the same case: unknown, not received.
#[test]
fn a_schema_without_an_out_column_leaves_the_direction_unknown() {
    let path = std::env::temp_dir().join(format!("test_tg_noout_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (mid INTEGER, uid INTEGER, date INTEGER, data BLOB);
             INSERT INTO messages VALUES (1, 99, 1673000000, x'01');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("cache4.db", data);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
    assert!(arts[0].metadata.get("is_from_me").is_none());
}

/// A recorded 0 is still a real answer: incoming, not unknown.
#[test]
fn a_zero_out_column_is_recorded_as_received() {
    let arts = run("cache4.db", telegram_db());
    let received = arts
        .iter()
        .find(|a| a.metadata.get("mid").and_then(|v| v.as_i64()) == Some(1))
        .unwrap();
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["is_from_me"], json!(false));
}
/// B2-124: the database was read with `read_capped` and staged without ever
/// comparing what came back against what the source declared, so a cache4.db
/// that could not be read whole parsed as a complete recovery.
#[test]
fn a_short_read_cache4_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(telegram_db()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "cache4.db" }),
    );
    let arts = TelegramParser.process(&art).unwrap();

    let msg = arts
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("the readable prefix still parses");
    assert_eq!(
        msg.metadata["content_incomplete"], true,
        "a message pulled out of a partial database must carry that fact"
    );
    assert_eq!(msg.metadata["content_incomplete_reason"], "short_read");
    assert!(
        arts.iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: a cache4.db read whole stays unmarked.
#[test]
fn a_complete_cache4_carries_no_incompleteness_marks() {
    let arts = run("cache4.db", telegram_db());
    assert!(
        arts.iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

/// B4-011: rows were iterated with `rows.flatten()`, so a message row that would
/// not decode vanished with no counter and no marker — the survivors then read
/// as the whole Telegram history.
#[test]
fn undecodable_message_rows_are_counted_and_marked() {
    let path = std::env::temp_dir().join(format!("test_tg_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
             INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 0, x'01');
             -- `mid` is read as a non-null i64; TEXT here will not decode.
             INSERT INTO messages_v2 VALUES ('not-an-integer', 12345, 1673000060, 0, x'02');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("cache4.db", data);
    let msgs: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(msgs.len(), 1, "only the decodable row yields a message");

    let marker = arts
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a dropped row must produce an incompleteness marker");
    assert_eq!(marker.metadata["type"], "TelegramMessageIncomplete");
    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(marker.metadata["records_recovered"], json!(1));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
}

/// A cache4.db that carries the SQLite header and will not answer a query is a
/// store this tool could not read, not an account with no messages.
#[test]
fn an_unreadable_cache4_is_reported_rather_than_returning_nothing() {
    let mut data = telegram_db();
    // Keep the header so the pre-spill probe still admits it, then destroy the
    // pages behind it.
    for b in data.iter_mut().skip(16) {
        *b = 0xFF;
    }
    let arts = run("cache4.db", data);
    assert!(
        !arts.is_empty(),
        "an unreadable Telegram store must not render as an empty history"
    );
    assert!(arts.iter().any(|a| {
        a.metadata["type"] == "TelegramMessageIncomplete"
            && a.metadata["content_incomplete"] == json!(true)
    }));
}

/// The counterpart to the unreadable-store report: a perfectly readable SQLite
/// file that simply is not a Telegram schema must still produce nothing. A
/// module that files an incompleteness finding against every database it does
/// not recognise teaches the examiner to skip the findings that matter.
#[test]
fn a_readable_non_telegram_database_reports_nothing() {
    let path = std::env::temp_dir().join(format!("test_tg_other_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE unrelated (id INTEGER PRIMARY KEY, v TEXT); \
             INSERT INTO unrelated VALUES (1, 'x');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        run("cache4.db", data).is_empty(),
        "an unrecognised schema is not an incompleteness finding"
    );
}

fn message_record(arts: &[Artifact]) -> &Artifact {
    let msg = arts.iter().find(|a| a.subtype() == Some("chat_message"));
    msg.expect("the row produces a chat message")
}

/// HUNT-020: every Telegram record was emitted with no body at all, so a
/// messaging case read as who/when/direction and nothing said. The text is in
/// the row's TL `data` blob and is recoverable without assuming a layout.
#[test]
fn a_message_body_is_recovered_from_the_tl_data_blob() {
    let date = 1_673_000_000i64;
    let db = db_with_blob(11, date, tl_message(date as i32, "meet me at nine"));
    let arts = run("cache4.db", db);
    let msg = message_record(&arts);

    assert_eq!(msg.metadata["text"], "meet me at nine");
    assert_eq!(msg.metadata["text_recovered"], json!(true));
    assert_eq!(
        msg.metadata["content_encoding"],
        "TL-serialized (message text recovered)"
    );
    // The label could only name the dialog while no row had a body.
    assert_eq!(
        msg.metadata["name"],
        "Telegram received in dialog 12345: meet me at nine"
    );
    // The exact columns are untouched by the decode.
    assert_eq!(msg.metadata["date"].as_i64(), Some(date));
    assert_eq!(msg.metadata["chat_identifier"], "12345");
    assert_eq!(msg.metadata["direction"], "received");
}

/// A body of 254 bytes or more is written with TL's long string form.
#[test]
fn a_body_over_the_short_string_limit_is_recovered_from_the_long_form() {
    let date = 1_673_000_000i32;
    let body = "b".repeat(300);
    let blob = tl_message(date, &body);
    assert_eq!(
        tl::message_text(&blob, date as i64).as_deref(),
        Some(body.as_str())
    );
}

/// The row's date can appear more than once in one object — an attached photo
/// carries its own — and there is then no way to say which read is the body.
/// Absent is the only honest answer; the wrong text is the worst one.
#[test]
fn two_date_anchors_that_disagree_leave_the_body_absent() {
    let date = 1_673_000_000i64;
    let mut blob = tl_message(date as i32, "the real body");
    blob.extend_from_slice(&(date as i32).to_le_bytes());
    blob.extend_from_slice(&tl_string(b"a caption"));

    let arts = run("cache4.db", db_with_blob(12, date, blob));
    let msg = message_record(&arts);
    assert!(
        msg.metadata.get("text").is_none(),
        "an ambiguous read must not be published as the body, got {:?}",
        msg.metadata.get("text")
    );
    assert_eq!(msg.metadata["text_recovered"], json!(false));
    assert_eq!(
        msg.metadata["content_encoding"],
        "TL-serialized (not decoded)"
    );
}

/// An encrypted, truncated or simply unrecognised blob leaves the body absent
/// and says so, rather than surfacing whatever bytes read as text.
#[test]
fn a_data_blob_that_carries_no_tl_body_leaves_the_message_text_absent() {
    let date = 1_673_000_000i64;
    let blob = vec![
        0x9f, 0x03, 0xdb, 0xdc, 0x7b, 0xe3, 0x46, 0x52, 0x00, 0x11, 0x88, 0x21,
    ];
    let arts = run("cache4.db", db_with_blob(13, date, blob));
    let msg = message_record(&arts);
    assert!(msg.metadata.get("text").is_none());
    assert_eq!(msg.metadata["text_recovered"], json!(false));
    assert_eq!(
        msg.metadata["content_encoding"],
        "TL-serialized (not decoded)"
    );
}

/// The blob is read as a BLOB or not at all. A `data` column holding something
/// else is a body this parser cannot recover, not a row it failed to decode:
/// counting it as a lost row would overstate what the store lost.
#[test]
fn a_data_column_that_is_not_a_blob_is_not_counted_as_a_lost_row() {
    let path = std::env::temp_dir().join(format!("test_tg_textdata_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
             INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 0, 'not a blob');",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("cache4.db", data);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1, "the row's exact metadata is still a record");
    assert_eq!(arts[0].metadata["type"], "TelegramMessage");
    assert_eq!(arts[0].metadata["text_recovered"], json!(false));
}

/// TL pads a string with zeros to the next 4-byte boundary. That padding is
/// what separates a real string from a byte that merely looks like a length.
#[test]
fn a_tl_string_whose_padding_is_not_zero_is_not_read_as_a_body() {
    let date = 1_700_000_000i32;
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x3811_6ee0u32.to_le_bytes());
    blob.extend_from_slice(&date.to_le_bytes());
    blob.extend_from_slice(&tl_string(b"hello"));
    assert_eq!(
        tl::message_text(&blob, date as i64).as_deref(),
        Some("hello"),
        "the well-formed form must read, or the check below proves nothing"
    );

    let last = blob.len() - 1;
    blob[last] = 0xAA;
    assert_eq!(tl::message_text(&blob, date as i64), None);
}

/// Valid UTF-8 with control bytes in it is a neighbouring binary field spliced
/// onto the anchor, not a message body.
#[test]
fn binary_following_the_date_anchor_is_not_read_as_text() {
    let date = 1_700_000_000i32;
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x3811_6ee0u32.to_le_bytes());
    blob.extend_from_slice(&date.to_le_bytes());
    blob.extend_from_slice(&tl_string(&[0x41, 0x01, 0x42, 0x02, 0x43]));
    assert_eq!(tl::message_text(&blob, date as i64), None);
}

/// A length prefix that runs past the end of the blob is not a string.
#[test]
fn a_declared_length_that_runs_past_the_blob_is_refused() {
    let date = 1_700_000_000i32;
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x3811_6ee0u32.to_le_bytes());
    blob.extend_from_slice(&date.to_le_bytes());
    blob.extend_from_slice(b"\x64hi truncated"); // declares 100 bytes, carries 12
    assert_eq!(tl::message_text(&blob, date as i64), None);
}

/// An empty TL string is four zero bytes — the commonest word in a serialized
/// object. Reading it as "this message had no text" would turn a coincidence
/// into a finding.
#[test]
fn an_empty_tl_string_is_not_reported_as_a_recovered_body() {
    let date = 1_700_000_000i32;
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x3811_6ee0u32.to_le_bytes());
    blob.extend_from_slice(&date.to_le_bytes());
    blob.extend_from_slice(&tl_string(b""));
    assert_eq!(tl::message_text(&blob, date as i64), None);
}

/// Every TL value is 4-byte aligned, so the date bytes appearing off the grid
/// are a coincidence inside some other field, not the `date` this parser is
/// anchoring on. Following them is how a scan starts inventing bodies.
#[test]
fn a_date_match_at_an_unaligned_offset_is_not_an_anchor() {
    let date = 1_700_000_000i32;
    let mut blob = vec![0xAA; 6];
    blob.extend_from_slice(&date.to_le_bytes());
    blob.extend_from_slice(&tl_string(b"nope"));
    assert_eq!(tl::message_text(&blob, date as i64), None);
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

fn cache4_with(batch: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_tg_schema_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(batch).unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

/// Run the parser on `bytes` under an injected declaration, the way `process`
/// would run it under the crate's own.
fn run_with_support(bytes: Vec<u8>, support: &SchemaSupport) -> Vec<Artifact> {
    let temp = TempDb::write(&bytes, "telegram_schema_test").unwrap();
    parse_messages_with(temp.path(), Uuid::new_v4(), Uuid::new_v4(), support)
}

/// A store whose `PRAGMA user_version` is beyond the range a parser was
/// validated against must say so — and must still parse what it can. The
/// crate's own declaration is Unranged (no real cache4.db is held), so the
/// Validated bound here is injected; the range is a test value and asserts
/// nothing about any Telegram build.
#[test]
fn a_schema_version_beyond_the_validated_range_is_declared_and_the_store_is_still_parsed() {
    let db = cache4_with(
        "PRAGMA user_version = 99;
         CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
         INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 0, x'0102');",
    );
    let support = SchemaSupport {
        app: "telegram-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Telegram build",
        },
    };
    let out = run_with_support(db, &support);

    assert_eq!(messages(&out).len(), 1, "the message is still recovered");
    let stale = schema_records(&out);
    assert_eq!(stale.len(), 1, "{out:?}");
    let m = &stale[0].metadata;
    assert_eq!(m["type"], json!("TelegramMessageIncomplete"));
    assert_eq!(m["subtype"], json!("parser_stale"));
    assert_eq!(m["status"], json!("SchemaOutsideValidated"));
    assert_eq!(m["schema_version_seen"], json!(99));
    assert_eq!(m["schema_version_supported"], json!("1..=3"));
    assert_eq!(m["source_table"], json!("messages_v2"));
    assert!(m["message"].as_str().unwrap().contains("NEWER"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A renamed dialog column used to make this parser return nothing at all —
/// indistinguishable from an account with no Telegram history. The FieldMap
/// turns that into a marker naming the LOGICAL field, and the rows the parser
/// can still read are still read.
#[test]
fn a_renamed_dialog_column_yields_a_marker_naming_the_unresolved_field() {
    let db = cache4_with(
        "CREATE TABLE messages_v2 (mid INTEGER, dialog_id INTEGER, date INTEGER, out INTEGER, data BLOB);
         INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 1, x'0102');",
    );
    let out = run("cache4.db", db);

    let marker = schema_records(&out);
    assert_eq!(marker.len(), 1, "{out:?}");
    let m = &marker[0].metadata;
    assert_eq!(m["type"], json!("TelegramMessageIncomplete"));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["dialog"]));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("dialog"));
    let msgs = messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["date"], json!(1673000000));
    assert_eq!(msgs[0].metadata["direction"], json!("sent"));
    assert!(msgs[0].metadata.get("chat_identifier").is_none());
    assert_eq!(m["records_recovered"], json!(1));
}

/// When NEITHER required field resolves, no record is invented — but the store
/// is not reported as empty either.
#[test]
fn a_message_table_with_no_recognised_column_yields_the_marker_and_no_records() {
    let db = cache4_with(
        "CREATE TABLE messages_v2 (mid INTEGER, peer INTEGER, when_s INTEGER, data BLOB);
         INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, x'01');",
    );
    let out = run("cache4.db", db);
    assert!(messages(&out).is_empty());
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["dialog", "sent_at"]));
    assert_eq!(m["records_recovered"], json!(0));
}

/// No real cache4.db is held by this project, so the crate declares Unranged:
/// the record says so, reports the version the store carries, and carries NO
/// range — a `1..=N` here would be a claim about databases this project has
/// never opened.
#[test]
fn a_parser_with_no_reference_database_declares_that_rather_than_a_range() {
    let db = cache4_with(
        "PRAGMA user_version = 7;
         CREATE TABLE messages_v2 (mid INTEGER, uid INTEGER, date INTEGER, out INTEGER, data BLOB);
         INSERT INTO messages_v2 VALUES (1, 12345, 1673000000, 0, x'0102');",
    );
    let out = run("cache4.db", db);
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["type"], json!("TelegramMessageIncomplete"));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_seen"], json!(7));
    assert!(m.get("schema_version_supported").is_none(), "{m}");
    assert!(m.get("supported_range").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("no reference database"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert_eq!(messages(&out).len(), 1);
}

/// `PRAGMA user_version` reads 0 on a store that never set it — SQLite's
/// default. That is the absence of a version, never "version 0".
#[test]
fn a_user_version_of_zero_is_the_absence_of_a_version_not_a_version_of_zero() {
    let out = run("cache4.db", telegram_db());
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_recorded"], json!(false));
    assert!(m.get("schema_version_seen").is_none(), "{m}");

    let support = SchemaSupport {
        app: "telegram-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Telegram build",
        },
    };
    let out = run_with_support(telegram_db(), &support);
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaVersionNotRecorded"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A version the store would not answer is never spent as "in range".
#[test]
fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
    let support = SchemaSupport {
        app: "telegram-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Telegram build",
        },
    };
    let fields = FieldMap::resolve(
        &["uid".to_string(), "date".to_string()]
            .into_iter()
            .collect(),
        MESSAGE_FIELDS,
    );
    let rec = SchemaCheck {
        support: &support,
        version: SchemaVersion::Undetermined("PRAGMA user_version would not read".into()),
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "TelegramMessageIncomplete",
        store: "messages_v2",
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
