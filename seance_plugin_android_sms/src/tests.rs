use super::*;
use seance_core::test_support::TruncatedSource;
use seance_sqlite_util::TempDb;

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

use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

/// Build a synthetic Android `mmssms.db` exercising SMS types, a null-address
/// row resolved via threads/canonical_addresses, and one MMS.
fn create_android_sms_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_android_sms_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 67;
            CREATE TABLE sms (
                _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER,
                date INTEGER, date_sent INTEGER, read INTEGER, status INTEGER, type INTEGER,
                subject TEXT, body TEXT, service_center TEXT
            );
            CREATE TABLE threads (
                _id INTEGER PRIMARY KEY, recipient_ids TEXT, snippet TEXT, message_count INTEGER
            );
            CREATE TABLE canonical_addresses (_id INTEGER PRIMARY KEY, address TEXT);
            CREATE TABLE pdu (
                _id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER,
                msg_box INTEGER, read INTEGER, sub TEXT, m_type INTEGER, st INTEGER
            );
            CREATE TABLE part (
                _id INTEGER PRIMARY KEY, mid INTEGER, seq INTEGER, ct TEXT, name TEXT,
                cl TEXT, fn TEXT, _data TEXT, text TEXT
            );
            CREATE TABLE addr (
                _id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER, charset INTEGER
            );

            INSERT INTO canonical_addresses VALUES (2, '+15551234567');
            INSERT INTO threads VALUES (5, '2', 'hi', 3);

            -- date in millis. type 1=received, 2=sent, 4=outbox(outgoing)
            INSERT INTO sms VALUES (1, 5, '+15551234567', NULL, 1600000000000, 0, 1, -1, 1, NULL, 'Incoming hello', NULL);
            INSERT INTO sms VALUES (2, 5, '+15551234567', NULL, 1600000100000, 1600000100000, 1, -1, 2, NULL, 'Sent reply', NULL);
            INSERT INTO sms VALUES (3, 5, NULL, NULL, 1600000200000, 0, 0, -1, 4, NULL, 'Outbox no-address', NULL);

            -- one received MMS (msg_box=1) with a text part and an image attachment
            INSERT INTO pdu VALUES (100, 5, 1600000300, 0, 1, 0, 'Photo subject', 132, 0);
            INSERT INTO addr VALUES (1, 100, '+15559998888', 137, 106);
            INSERT INTO part VALUES (1, 100, 0, 'text/plain', NULL, NULL, NULL, NULL, 'Check this out');
            INSERT INTO part VALUES (2, 100, 1, 'image/jpeg', 'photo.jpg', 'photo.jpg', NULL, '/data/photo.jpg', NULL);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Build a SQLite db that is NOT an Android SMS store (only a `foo` table).
fn create_non_sms_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_non_sms_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE foo (id INTEGER PRIMARY KEY, bar TEXT); INSERT INTO foo VALUES (1, 'x');",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn messages(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "AndroidSms")
        .collect()
}

fn summary(result: &[Artifact]) -> &Artifact {
    result
        .iter()
        .find(|a| a.metadata["type"] == "AndroidSmsSummary")
        .expect("summary record present")
}

#[test]
fn test_module_metadata() {
    let parser = AndroidSmsParser;
    assert_eq!(parser.id(), "plugin.messaging.android_sms");
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_filename_prefilter() {
    assert!(identify_android_sms_db("mmssms.db"));
    assert!(identify_android_sms_db(
        "/data/data/com.android.providers.telephony/databases/mmssms.db"
    ));
    assert!(identify_android_sms_db("backup_mmssms.db"));
    assert!(identify_android_sms_db("mmssms.db-wal"));
    assert!(!identify_android_sms_db("chat.db"));
    assert!(!identify_android_sms_db("msgstore.db"));
    assert!(!identify_android_sms_db("random.txt"));
}

#[test]
fn test_epoch_normalization() {
    // millis -> seconds
    assert_eq!(normalize_epoch_secs(1_383_065_788_038), Some(1_383_065_788));
    // already seconds -> unchanged
    assert_eq!(normalize_epoch_secs(1_600_000_300), Some(1_600_000_300));
    // micros -> seconds. This is the case the old two-branch rule got wrong:
    // it divided a 16-digit value by a thousand and dated the message to the
    // year 52671.
    assert_eq!(
        normalize_epoch_secs(1_600_000_300_123_456),
        Some(1_600_000_300)
    );
    // An unset column is absent, not midnight on 1970-01-01.
    assert_eq!(normalize_epoch_secs(0), None);
    assert_eq!(normalize_epoch_secs(-1_600_000_300_000), None);
    assert!(to_rfc3339(1_600_000_300).unwrap().starts_with("2020-"));
}

#[test]
fn test_skips_non_matching_file() {
    let parser = AndroidSmsParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "random_file.txt"}),
    );
    assert_eq!(parser.process(&artifact).unwrap().len(), 0);
}

#[test]
fn test_identification_only_no_data() {
    let parser = AndroidSmsParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "mmssms.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "AndroidSms");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_synthetic_parsing_and_direction() {
    let parser = AndroidSmsParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_android_sms_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let msgs = messages(&result);
    // 3 SMS + 1 MMS
    assert_eq!(msgs.len(), 4, "expected 4 messages, got {}", msgs.len());

    let received = msgs.iter().find(|a| a.metadata["rowid"] == 1).unwrap();
    assert_eq!(received.metadata["is_from_me"], false);
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["text"], "Incoming hello");
    assert_eq!(received.metadata["service"], "SMS");
    assert_eq!(received.metadata["contact"], "+15551234567");
    assert_eq!(received.metadata["chat_identifier"], "+15551234567");

    let sent = msgs.iter().find(|a| a.metadata["rowid"] == 2).unwrap();
    assert_eq!(sent.metadata["is_from_me"], true);
    assert_eq!(sent.metadata["direction"], "sent");

    // Outbox (type 4) is outgoing; null address resolves via threads/canonical.
    let outbox = msgs.iter().find(|a| a.metadata["rowid"] == 3).unwrap();
    assert_eq!(outbox.metadata["is_from_me"], true);
    assert_eq!(outbox.metadata["sms_type"], 4);
    assert_eq!(outbox.metadata["contact"], "+15551234567");

    // MMS: received, text part + image attachment.
    let mms = msgs
        .iter()
        .find(|a| a.metadata["service"] == "MMS")
        .unwrap();
    assert_eq!(mms.metadata["is_from_me"], false);
    assert_eq!(mms.metadata["direction"], "received");
    assert_eq!(mms.metadata["text"], "Check this out");
    assert_eq!(mms.metadata["has_attachments"], true);
    assert_eq!(mms.metadata["contact"], "+15559998888");
    let atts = mms.metadata["attachment_names"].as_array().unwrap();
    assert!(atts.iter().any(|v| v == "photo.jpg"));
    // MMS pdu.date is seconds; must not be divided again.
    assert_eq!(mms.metadata["date"].as_i64().unwrap(), 1_600_000_300);

    // Summary counts.
    let s = summary(&result);
    assert_eq!(s.metadata["message_count"], 4);
    assert_eq!(s.metadata["sms_count"], 3);
    assert_eq!(s.metadata["mms_count"], 1);
    assert_eq!(s.metadata["thread_count"], 1);
    assert_eq!(s.metadata["file_name"], "mmssms.db");
}

/// Build a minimal `mmssms.db` with one SMS of each direction-relevant type.
fn create_sms_types_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_sms_types_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 67;
            CREATE TABLE sms (
                _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER,
                date INTEGER, date_sent INTEGER, read INTEGER, status INTEGER, type INTEGER,
                subject TEXT, body TEXT, service_center TEXT
            );
            INSERT INTO sms VALUES (1, 1, '+100', NULL, 1600000000000, 0, 1, -1, 1, NULL, 'in',  NULL);
            INSERT INTO sms VALUES (2, 1, '+100', NULL, 1600000001000, 0, 1, -1, 2, NULL, 'out', NULL);
            INSERT INTO sms VALUES (3, 1, '+100', NULL, 1600000002000, 0, 0, -1, 3, NULL, 'drf', NULL);
            INSERT INTO sms VALUES (4, 1, '+100', NULL, 1600000003000, 0, 0, -1, 5, NULL, 'bad', NULL);
            INSERT INTO sms VALUES (5, 1, '+100', NULL, 1600000004000, 0, 0, -1, 6, NULL, 'que', NULL);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn test_non_sent_types_get_correct_direction() {
    // Drafts/failed/queued must NOT be labeled "sent" (they were never sent),
    // though they are still outgoing (is_from_me == true).
    let parser = AndroidSmsParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_sms_types_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    let by_id = |rowid: i64| {
        messages(&result)
            .into_iter()
            .find(|a| a.metadata["rowid"] == rowid)
            .unwrap()
            .clone()
    };

    let inbox = by_id(1);
    assert_eq!(inbox.metadata["direction"], "received");
    assert_eq!(inbox.metadata["is_from_me"], false);

    let sent = by_id(2);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    let draft = by_id(3);
    assert_eq!(draft.metadata["direction"], "draft");
    assert_eq!(draft.metadata["is_from_me"], true);

    let failed = by_id(4);
    assert_eq!(failed.metadata["direction"], "failed");
    assert_eq!(failed.metadata["is_from_me"], true);

    let queued = by_id(5);
    assert_eq!(queued.metadata["direction"], "queued");
    assert_eq!(queued.metadata["is_from_me"], true);
}

/// BUG-254: on an outgoing MMS the `from` address row (type 137) is the device
/// owner. Falling back to it made sent/draft/outbox messages show the owner as
/// the peer. The recipient (type 151) is the peer; with no recipient row the
/// thread's own address resolves it — never `from`.
#[test]
fn test_outgoing_mms_never_takes_the_owner_as_contact() {
    let temp_path = std::env::temp_dir().join(format!("test_mms_sent_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 67;
            CREATE TABLE sms (
                _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER,
                date INTEGER, date_sent INTEGER, read INTEGER, status INTEGER, type INTEGER,
                subject TEXT, body TEXT, service_center TEXT
            );
            CREATE TABLE threads (
                _id INTEGER PRIMARY KEY, recipient_ids TEXT, snippet TEXT, message_count INTEGER
            );
            CREATE TABLE canonical_addresses (_id INTEGER PRIMARY KEY, address TEXT);
            CREATE TABLE pdu (
                _id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER,
                msg_box INTEGER, read INTEGER, sub TEXT, m_type INTEGER, st INTEGER
            );
            CREATE TABLE part (
                _id INTEGER PRIMARY KEY, mid INTEGER, seq INTEGER, ct TEXT, name TEXT,
                cl TEXT, fn TEXT, _data TEXT, text TEXT
            );
            CREATE TABLE addr (
                _id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER, charset INTEGER
            );

            INSERT INTO canonical_addresses VALUES (2, '+15551234567');
            INSERT INTO threads VALUES (5, '2', 'hi', 2);

            -- Sent MMS with both address rows: peer is the `to` (151) row.
            INSERT INTO pdu VALUES (100, 5, 1600000300, 0, 2, 1, NULL, 128, 0);
            INSERT INTO addr VALUES (1, 100, '+15550000001', 137, 106);
            INSERT INTO addr VALUES (2, 100, '+15551234567', 151, 106);
            INSERT INTO part VALUES (1, 100, 0, 'text/plain', NULL, NULL, NULL, NULL, 'sent mms');

            -- Outbox MMS with only the owner's `from` row: the peer must come
            -- from the thread, not from the owner.
            INSERT INTO pdu VALUES (101, 5, 1600000400, 0, 4, 1, NULL, 128, 0);
            INSERT INTO addr VALUES (3, 101, '+15550000001', 137, 106);
            INSERT INTO part VALUES (2, 101, 0, 'text/plain', NULL, NULL, NULL, NULL, 'outbox mms');",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = AndroidSmsParser.process(&artifact).unwrap();
    let msgs = messages(&result);

    let sent = msgs.iter().find(|a| a.metadata["rowid"] == 100).unwrap();
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["contact"], "+15551234567");
    assert_eq!(sent.metadata["chat_identifier"], "+15551234567");

    let outbox = msgs.iter().find(|a| a.metadata["rowid"] == 101).unwrap();
    assert_eq!(outbox.metadata["direction"], "outbox");
    assert_ne!(
        outbox.metadata["contact"], "+15550000001",
        "the device owner must never be reported as the peer"
    );
    assert_eq!(outbox.metadata["contact"], "+15551234567");
}

#[test]
fn test_parent_and_case_chain() {
    let parser = AndroidSmsParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_android_sms_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let parent_id = artifact.id;
    let result = parser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    for rec in &result {
        assert_eq!(rec.parent_id, Some(parent_id));
        assert_eq!(rec.case_id, case_id);
        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
    }
}

#[test]
fn test_negative_non_sms_schema_rejected() {
    let parser = AndroidSmsParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_non_sms_db()));
    // Name passes the pre-filter, so only the schema check can reject it.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0, "non-SMS schema must yield zero artifacts");
}

#[test]
fn test_garbage_no_panic() {
    let parser = AndroidSmsParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 2048]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        0,
        "garbage must yield zero artifacts, no panic"
    );
}

#[test]
fn test_real_mmssms_fixture() {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let db_path = crate_dir
        .parent()
        .unwrap()
        .join("test_data")
        .join("mmssms.db");

    if !db_path.exists() {
        eprintln!("Skipping test_real_mmssms_fixture: {:?} not found", db_path);
        return;
    }

    let data = std::fs::read(&db_path).unwrap();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let parser = AndroidSmsParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let msgs = messages(&result);
    assert!(!msgs.is_empty(), "fixture should yield messages");

    // Both directions present with correct is_from_me.
    let sent: Vec<_> = msgs
        .iter()
        .filter(|a| a.metadata["is_from_me"] == true)
        .collect();
    let received: Vec<_> = msgs
        .iter()
        .filter(|a| a.metadata["is_from_me"] == false)
        .collect();
    assert!(!sent.is_empty(), "expected some sent messages");
    assert!(!received.is_empty(), "expected some received messages");
    for a in &sent {
        assert_eq!(a.metadata["direction"], "sent");
    }
    for a in &received {
        assert_eq!(a.metadata["direction"], "received");
    }

    // Every message has a plausible Unix-seconds date and a contact/chat id.
    for a in &msgs {
        let date = a.metadata["date"].as_i64().expect("date present");
        assert!(
            (1_000_000_000..2_000_000_000).contains(&date),
            "date {} not a plausible unix-seconds value",
            date
        );
        assert!(a.metadata["date_rfc3339"].is_string());
        assert!(a.metadata["contact"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
        assert!(a.metadata["chat_identifier"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    // Summary sanity.
    let s = summary(&result);
    let sms_count = s.metadata["sms_count"].as_u64().unwrap();
    let mms_count = s.metadata["mms_count"].as_u64().unwrap();
    let message_count = s.metadata["message_count"].as_u64().unwrap();
    assert_eq!(message_count, sms_count + mms_count);
    assert_eq!(message_count as usize, msgs.len());
    assert!(s.metadata["thread_count"].as_u64().unwrap() >= 1);

    eprintln!(
        "Parsed {} messages ({} sms, {} mms) from real fixture",
        message_count, sms_count, mms_count
    );
}

/// Open a database built from `bytes` read-only, the way `process` does.
fn open_bytes(bytes: &[u8]) -> (TempDb, Connection) {
    let temp = TempDb::write(bytes, "android_sms_test").unwrap();
    let conn = temp.open().unwrap();
    (temp, conn)
}

/// B2-130: the cap set `truncated` and nothing else. Every other parser in this
/// tree marks a cap with `content_incomplete` + a reason, and that is the pair
/// consumers check — a lone `truncated` is easy to miss, and a missed cap turns
/// a newest-first slice into "the whole message store".
#[test]
fn a_capped_walk_marks_the_summary_content_incomplete() {
    let (_temp, conn) = open_bytes(&create_android_sms_db());

    let capped =
        parse_android_sms_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "mmssms.db", 2).unwrap();
    let s = summary(&capped);
    assert_eq!(s.metadata["truncated"], true);
    assert_eq!(
        s.metadata["content_incomplete"], true,
        "a cap must set the flag consumers actually read"
    );
    assert_eq!(s.metadata["content_incomplete_reason"], "cap_reached");
    assert!(s.metadata["message"].as_str().is_some());

    // The store holds 3 SMS + 1 MMS; a budget that covers them all must not
    // claim truncation.
    let whole =
        parse_android_sms_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "mmssms.db", 4).unwrap();
    let s = summary(&whole);
    assert!(
        s.metadata.get("content_incomplete").is_none(),
        "a complete walk must not be marked incomplete"
    );
}

/// B2-123: a telephony store the spill could not stage in full still opens.
#[test]
fn a_short_read_store_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(create_android_sms_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = AndroidSmsParser.process(&artifact).unwrap();

    let msgs = messages(&result);
    assert!(!msgs.is_empty(), "the readable prefix still parses");
    assert_eq!(
        msgs[0].metadata["content_incomplete"], true,
        "a message pulled out of a partial database must carry that fact"
    );
    assert_eq!(msgs[0].metadata["content_incomplete_reason"], "short_read");
    assert!(
        result
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: a store read whole must stay unmarked.
#[test]
fn a_complete_store_carries_no_incompleteness_marks() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_android_sms_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "mmssms.db"}),
    );
    let result = AndroidSmsParser.process(&artifact).unwrap();
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

// --- Direction honesty (B4-007) ----------------------------------------------

/// Build a telephony store from a literal schema+rows script.
fn db_from_sql(sql: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_sms_sql_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn process_db(db: Vec<u8>, name: &str) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    AndroidSmsParser.process(&artifact).unwrap()
}

const SMS_SCHEMA: &str = "CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, \
     address TEXT, date INTEGER, read INTEGER, status INTEGER, type INTEGER, body TEXT, \
     subject TEXT);";

/// A row whose `type` was never recorded must not be asserted inbound. Before
/// the fix `sms_type.unwrap_or(1)` made every such row `direction: "received"`
/// with `is_from_me: false` — an affirmative claim that the correspondent, not
/// the phone's owner, wrote the message.
#[test]
fn sms_null_type_is_unknown_not_received() {
    let db = db_from_sql(&format!(
        "{SMS_SCHEMA} INSERT INTO sms VALUES \
         (1, 5, '+15551234567', 1600000000000, 1, -1, NULL, 'who wrote this', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    let msgs = messages(&result);
    assert_eq!(msgs.len(), 1);
    // Omitted, not the literal "unknown": the messaging viewer only prints
    // "Direction (Sent/Received) Not Determinable" when the key is absent, and
    // renders the string "unknown" on the received side with no note.
    assert!(
        msgs[0].metadata.get("direction").is_none(),
        "an unrecorded direction must be omitted, not asserted: {:?}",
        msgs[0].metadata.get("direction")
    );
    assert!(
        msgs[0].metadata.get("is_from_me").is_none(),
        "a NULL type must not attribute the message to the correspondent"
    );
    assert!(
        msgs[0].metadata["sms_type"].is_null(),
        "a NULL type column must not be recorded as 1"
    );
    assert!(
        msgs[0].metadata["name"]
            .as_str()
            .unwrap()
            .starts_with("message:"),
        "the display name must not claim a direction either: {}",
        msgs[0].metadata["name"]
    );
}

/// An out-of-vocabulary type code is equally undetermined: `is_from_me` stays
/// null rather than defaulting to "not from me".
#[test]
fn sms_unknown_type_code_leaves_the_author_undetermined() {
    let db = db_from_sql(&format!(
        "{SMS_SCHEMA} INSERT INTO sms VALUES \
         (1, 5, '+15551234567', 1600000000000, 1, -1, 99, 'odd type', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    let msgs = messages(&result);
    assert!(msgs[0].metadata.get("direction").is_none());
    assert!(msgs[0].metadata.get("is_from_me").is_none());
    // The code itself is still reported, so the examiner can see what the row
    // held that this build does not map.
    assert_eq!(msgs[0].metadata["sms_type"], 99);
}

const MMS_SCHEMA: &str = "CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, \
     address TEXT, date INTEGER, read INTEGER, status INTEGER, type INTEGER, body TEXT, \
     subject TEXT); \
     CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, \
     msg_box INTEGER, read INTEGER, sub TEXT, st INTEGER); \
     CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER);";

/// On MMS the invented direction also picked the correspondent: `msg_box`
/// defaulted to inbox, so the type-137 `from` row (the device owner on an
/// outgoing PDU) became the peer. With the direction undetermined no addr row
/// may be chosen at all.
#[test]
fn mms_null_msg_box_selects_no_peer_from_the_addr_rows() {
    let db = db_from_sql(&format!(
        "{MMS_SCHEMA} \
         INSERT INTO pdu VALUES (100, 5, 1600000300, NULL, 0, 'subject', 0); \
         INSERT INTO addr VALUES (1, 100, '+15550000001', 137); \
         INSERT INTO addr VALUES (2, 100, '+15550000002', 151);"
    ));
    let result = process_db(db, "mmssms.db");
    let msgs = messages(&result);
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].metadata.get("direction").is_none());
    assert!(msgs[0].metadata.get("is_from_me").is_none());
    assert!(msgs[0].metadata["msg_box"].is_null());
    assert_eq!(msgs[0].metadata["peer_undetermined"], true);
    assert_ne!(
        msgs[0].metadata["contact"], "+15550000001",
        "the `from` row must not become the peer on an undetermined direction"
    );
    assert_ne!(msgs[0].metadata["contact"], "+15550000002");
}

// --- Dropped-row honesty (B4-010) --------------------------------------------

/// A message row that will not decode is a message that existed and was not
/// recovered. The summary counts it instead of letting the survivors present as
/// the whole conversation.
#[test]
fn undecodable_sms_rows_are_counted_on_the_summary() {
    let db = db_from_sql(&format!(
        "{SMS_SCHEMA} \
         INSERT INTO sms VALUES (1, 5, '+1555', 1600000000000, 1, -1, 1, 'ok', NULL); \
         INSERT INTO sms VALUES (2, 5, '+1555', 1600000100000, 1, -1, 'not-an-integer', 'x', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    assert_eq!(messages(&result).len(), 1);
    let s = summary(&result);
    assert_eq!(s.metadata["sms_count"], 1);
    assert_eq!(s.metadata["rows_dropped"], 1);
    assert_eq!(s.metadata["inventory_incomplete"], true);
    assert_eq!(
        s.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(s.metadata["content_incomplete"], true);
    assert_eq!(
        s.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

/// The MMS side tables count too: a lost `addr` row changes which number is
/// reported as the correspondent.
#[test]
fn undecodable_addr_rows_are_counted_on_the_summary() {
    let db = db_from_sql(&format!(
        "{MMS_SCHEMA} \
         INSERT INTO pdu VALUES (100, 5, 1600000300, 1, 0, 'subject', 0); \
         INSERT INTO addr VALUES (1, 100, '+15550000001', 137); \
         INSERT INTO addr VALUES (2, 100, '+15550000002', 'not-an-integer');"
    ));
    let result = process_db(db, "mmssms.db");
    let s = summary(&result);
    assert_eq!(s.metadata["rows_dropped"], 1);
    assert_eq!(s.metadata["content_incomplete"], true);
}

// --- Unreadable databases (B7-023 class) -------------------------------------

/// A corrupt telephony store is a store this tool could not read, not a phone
/// that exchanged no messages. Before the fix the schema probe swallowed the
/// error (`unwrap_or(false)`) and the parser returned zero artifacts.
#[test]
fn a_corrupt_store_reports_a_parse_failure_not_an_empty_store() {
    let mut db = create_android_sms_db();
    for b in db.iter_mut().skip(16) {
        *b = 0xFF;
    }
    let result = process_db(db, "mmssms.db");
    assert_eq!(result.len(), 1, "the failure must be reported as a record");
    let m = &result[0].metadata;
    assert_eq!(m["status"], "ParseFailed");
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(m["inventory_incomplete"], true);
}

/// The counterpart: a file that is not a database at all stays silent.
#[test]
fn a_non_sqlite_file_still_yields_nothing() {
    assert!(process_db(vec![0xABu8; 2048], "mmssms.db").is_empty());
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

/// The marker records this parse emitted about the schema itself.
fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// A telephony store whose `PRAGMA user_version` is newer than any this parser
/// was validated against must say so — and still parse the rows it can. An
/// examiner reads "schema newer than supported" beside the messages, never an
/// unexplained shortfall.
#[test]
fn a_schema_version_outside_the_validated_range_is_declared_and_the_messages_still_parse() {
    let db = db_from_sql(&format!(
        "PRAGMA user_version = 99; {SMS_SCHEMA} INSERT INTO sms VALUES \
         (1, 5, '+15550001', 1600000000000, 1, -1, 1, 'still parsed', NULL);"
    ));
    let result = process_db(db, "mmssms.db");

    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "one stale-schema marker: {result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["app"], SCHEMA_APP);
    assert_eq!(m.metadata["seen_schema_version"], 99);
    assert_eq!(
        m.metadata["supported_range"],
        SUPPORTED_SCHEMA.describe(),
        "the range on the marker is the declared one"
    );
    // §1.4a (decided 2026-09-26): a version outside the validated range is a
    // disclosure, not an incompleteness claim; a missing column is what claims.
    assert!(
        m.metadata.get("content_incomplete").is_none(),
        "{}",
        m.metadata
    );
    assert!(m.metadata.get("content_incomplete_reason").is_none());
    assert!(m.metadata.get("content_incomplete_detail").is_none());
    assert_eq!(m.metadata["detail"], m.metadata["message"]);
    assert!(m.metadata["message"].as_str().unwrap().contains("NEWER"));
    // HUNT-204: the warning names the real stores the range was read from,
    // so a reader can go from it to the file that set each endpoint.
    let evidence = m.metadata["validated_against"].as_str().unwrap_or_default();
    assert!(
        evidence.contains("mmssms.db") && evidence.contains("57") && evidence.contains("67"),
        "the range carries no evidence-file name: {}",
        m.metadata
    );
    // Never the walk's own type: the conversation grouping keys on it.
    assert_ne!(m.metadata["type"], "AndroidSms");

    let msgs = messages(&result);
    assert_eq!(msgs.len(), 1, "the parse still recovers what it can");
    assert_eq!(msgs[0].metadata["text"], "still parsed");
}

/// The other side of the window: a store older than the validated range.
#[test]
fn a_schema_version_older_than_the_validated_range_is_declared_too() {
    let db = db_from_sql(&format!(
        "PRAGMA user_version = 3; {SMS_SCHEMA} INSERT INTO sms VALUES \
         (1, 5, '+15550001', 1600000000000, 1, -1, 1, 'old store', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].metadata["seen_schema_version"], 3);
    assert!(markers[0].metadata["message"]
        .as_str()
        .unwrap()
        .contains("OLDER"));
    assert_eq!(messages(&result).len(), 1);
}

/// `PRAGMA user_version` of 0 is SQLite's default for a store that never set
/// one — the absence of a version, not "version 0". Comparing it to the window
/// would manufacture an "older than supported" finding out of an unset field,
/// so the parse is declared unranked instead, with nothing called incomplete.
#[test]
fn a_store_with_no_recorded_version_is_declared_unranked_not_older() {
    let db = db_from_sql(&format!(
        "{SMS_SCHEMA} INSERT INTO sms VALUES \
         (1, 5, '+15550001', 1600000000000, 1, -1, 1, 'unranked', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaVersionNotRecorded");
    assert_eq!(m.metadata["supported_range"], SUPPORTED_SCHEMA.describe());
    assert!(
        m.metadata.get("content_incomplete").is_none(),
        "an unranked parse is not thereby an incomplete one"
    );
    assert!(m.metadata["message"].as_str().unwrap().contains("unranked"));
    assert_eq!(messages(&result).len(), 1);
}

/// A store inside the validated range carries no stale marker, or the marker
/// means nothing when it appears.
#[test]
fn a_schema_version_inside_the_validated_range_carries_no_stale_marker() {
    for v in [SUPPORTED_SCHEMA.min, SUPPORTED_SCHEMA.max.unwrap()] {
        let db = db_from_sql(&format!(
            "PRAGMA user_version = {v}; {SMS_SCHEMA} INSERT INTO sms VALUES \
             (1, 5, '+15550001', 1600000000000, 1, -1, 1, 'in range', NULL);"
        ));
        let result = process_db(db, "mmssms.db");
        assert!(
            stale_markers(&result).is_empty(),
            "user_version {v} is inside {} and must not warn",
            SUPPORTED_SCHEMA.describe()
        );
    }
}

/// A column the parser was validated against has been renamed. The old code
/// failed to prepare its hard-coded SELECT and filed the whole store as
/// `ParseFailed`; a subtler rename would have substituted nothing and reported
/// a complete parse. Now the logical field that no longer resolves is named,
/// and the rows are still walked with that field absent.
#[test]
fn a_renamed_sms_column_is_declared_by_logical_field_and_the_rows_still_walk() {
    let db = db_from_sql(
        "PRAGMA user_version = 67;
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, \
         date INTEGER, read INTEGER, status INTEGER, type INTEGER, message_text TEXT, \
         subject TEXT);
         INSERT INTO sms VALUES (1, 5, '+15550001', 1600000000000, 1, -1, 2, 'renamed body', NULL);",
    );
    let result = process_db(db, "mmssms.db");

    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "one field-drift marker: {result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(m.metadata["source_table"], "sms");
    assert_eq!(m.metadata["unresolved_fields"], json!(["body"]));
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(m.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("body"));

    let msgs = messages(&result);
    assert_eq!(msgs.len(), 1, "the row is still walked");
    assert_eq!(msgs[0].metadata["direction"], "sent");
    assert!(
        msgs[0].metadata.get("text").is_none(),
        "no body column resolved, so no text is written — never a guess"
    );
}

/// The MMS walk has its own column set and its own marker.
#[test]
fn a_renamed_pdu_column_is_declared_under_the_pdu_table() {
    let db = db_from_sql(&format!(
        "PRAGMA user_version = 67; {SMS_SCHEMA}
         CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, \
         box_kind INTEGER, read INTEGER, sub TEXT, st INTEGER);
         INSERT INTO pdu VALUES (1, 5, 1600000300, 1, 1, 'subj', NULL);"
    ));
    let result = process_db(db, "mmssms.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(markers[0].metadata["source_table"], "pdu");
    assert_eq!(markers[0].metadata["unresolved_fields"], json!(["msg_box"]));
    let mms: Vec<_> = messages(&result)
        .into_iter()
        .filter(|a| a.metadata["service"] == "MMS")
        .collect();
    assert_eq!(mms.len(), 1, "the MMS row is still walked");
    assert!(mms[0].metadata.get("direction").is_none());
}

/// A real store the parser was validated against: in range, every field
/// resolved, no stale marker, and at least the record count observed when the
/// range was declared. This is the corpus-diff harness for this parser; a
/// change that breaks it against a real schema fails here.
///
/// The files are not in the tree (`reference/` and `test_data/` are ignored),
/// so each is skipped when absent. `SEANCE_APP_SCHEMA_CORPUS` points at a
/// directory holding the CTF-derived copies; the plaso file is read from the
/// checked-out reference tree.
#[test]
fn real_telephony_stores_in_the_validated_range_carry_no_stale_marker() {
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let corpus = std::env::var_os("SEANCE_APP_SCHEMA_CORPUS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| workspace.join("test_data").join("app_schema_corpus"));
    let expectations = [
        (
            workspace.join("reference/plaso/test_data/mmssms.db"),
            57,
            seance_sqlite_util::CorpusExpectation {
                label: "plaso test_data/mmssms.db (user_version 57)".into(),
                min_records: 9,
            },
        ),
        (
            corpus.join("android2022_mmssms.db"),
            67,
            seance_sqlite_util::CorpusExpectation {
                label: "Magnet 2022 CTF Pixel 3 mmssms.db (user_version 67)".into(),
                min_records: 11,
            },
        ),
    ];
    let mut checked = 0;
    for (path, version, expect) in expectations {
        if !path.exists() {
            // A skipped corpus passes silently; CI sets the REQUIRED switch so an
            // absent file fails the job instead of counting as checked.
            assert!(
                std::env::var_os("SEANCE_APP_SCHEMA_CORPUS_REQUIRED").is_none(),
                "{}: {} not found and SEANCE_APP_SCHEMA_CORPUS_REQUIRED is set",
                expect.label,
                path.display()
            );
            eprintln!("skipping {}: {} not found", expect.label, path.display());
            continue;
        }
        let result = process_db(std::fs::read(&path).unwrap(), "mmssms.db");
        assert!(
            SUPPORTED_SCHEMA.contains(version),
            "the declared range must include the observed version {version}"
        );
        assert!(
            stale_markers(&result).is_empty(),
            "{}: a real store in range must not warn: {:?}",
            expect.label,
            stale_markers(&result)
        );
        seance_sqlite_util::check_corpus(&expect, messages(&result).len()).unwrap();
        checked += 1;
    }
    eprintln!("checked {checked} real telephony store(s)");
}

/// ROADMAP §5.11, owner decision (b) of 2026-09-26: this parser's schema
/// records speak the vocabulary every schema record shares — the same status
/// names, subtype `parser_stale` and `warning_class: "ParserStaleWarning"`.
#[test]
fn schema_records_speak_the_shared_vocabulary() {
    use seance_sqlite_util::adopt::inline_marker::{
        field_drift_marker, stale_marker, version_not_recorded_marker, version_undetermined_marker,
    };
    let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
    let range = seance_sqlite_util::SupportedRange::new(3, Some(3));
    let present: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
    let map = seance_sqlite_util::FieldMap::resolve(&present, &[("a", &["a"]), ("b", &["b"])]);
    let warning = seance_sqlite_util::StaleWarning {
        app: "x".into(),
        seen_version: 9,
        supported: range.clone(),
    };
    let records = [
        (stale_marker(&warning, c, p), "SchemaOutsideValidated"),
        (
            version_undetermined_marker(c, p, "x", &range, "io"),
            "SchemaVersionUndetermined",
        ),
        (
            version_not_recorded_marker(c, p, "x", &range, "nowhere"),
            "SchemaVersionNotRecorded",
        ),
        (
            field_drift_marker(c, p, "x", "t", &map, 1).unwrap(),
            "SchemaFieldsUnresolved",
        ),
    ];
    for (m, status) in records {
        assert_eq!(m.metadata["status"], status, "{}", m.metadata);
        assert_eq!(m.subtype(), Some("parser_stale"), "{}", m.metadata);
        assert_eq!(m.metadata["subtype"], "parser_stale", "{}", m.metadata);
        assert_eq!(
            m.metadata["warning_class"], "ParserStaleWarning",
            "{}",
            m.metadata
        );
    }
}

/// ROADMAP §5.11 (messaging residue): this entry now shares the gate every
/// other messenger stages through (`seance_sqlite_util::stage_sqlite_db`). A
/// directory entry that merely carries a store's name is not a database, and
/// no identification record is filed for it.
#[test]
fn a_directory_entry_named_as_the_store_yields_nothing() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "mmssms.db", "is_directory": true }),
    );
    let out = AndroidSmsParser.process(&artifact).unwrap();
    assert!(out.is_empty(), "a directory is not a mmssms.db: {out:?}");
}

/// ROADMAP §5.11: a store whose first 100 bytes did not all arrive is a fact
/// about this tool's read, not about the evidence. It must never be spent as
/// "not a SQLite database" — a record saying so would assert a finding the
/// bytes do not support (the Messenger defect `SqliteEntry::HeaderUnreadable`
/// exists to prevent) — and it must not be silence either, for a file whose
/// name identifies the store. Synthetic: a real store cut to 4 readable bytes
/// of the size it declares.
#[test]
fn a_store_whose_header_is_a_short_read_is_not_claimed_as_a_store() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::cut_to(create_android_sms_db(), 4));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "mmssms.db" }),
    );
    let out = AndroidSmsParser.process(&artifact).unwrap();
    // What may be said is that the read was short — the stager's own record —
    // and nothing about what the file is.
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].metadata["type"], "SqliteSpillIncomplete", "{out:?}");
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["records_recovered"], 0);
}
