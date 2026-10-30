use super::*;
use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

/// Create a synthetic iMessage database with known data.
fn create_imessage_test_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                text TEXT,
                handle_id INTEGER DEFAULT 0,
                service TEXT DEFAULT 'iMessage',
                date INTEGER DEFAULT 0,
                date_read INTEGER DEFAULT 0,
                date_delivered INTEGER DEFAULT 0,
                is_from_me INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                is_delivered INTEGER DEFAULT 0,
                cache_has_attachments INTEGER DEFAULT 0,
                associated_message_guid TEXT,
                reply_to_guid TEXT
            );
            CREATE TABLE handle (
                ROWID INTEGER PRIMARY KEY,
                id TEXT NOT NULL,
                service TEXT DEFAULT 'iMessage',
                country TEXT
            );
            CREATE TABLE chat (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                chat_identifier TEXT,
                service_name TEXT DEFAULT 'iMessage',
                display_name TEXT
            );
            CREATE TABLE chat_message_join (
                chat_id INTEGER,
                message_id INTEGER
            );
            CREATE TABLE chat_handle_join (
                chat_id INTEGER,
                handle_id INTEGER
            );
            CREATE TABLE attachment (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                filename TEXT,
                mime_type TEXT,
                total_bytes INTEGER DEFAULT 0,
                created_date INTEGER DEFAULT 0,
                transfer_name TEXT,
                uti TEXT,
                is_outgoing INTEGER DEFAULT 0
            );
            CREATE TABLE message_attachment_join (
                message_id INTEGER,
                attachment_id INTEGER
            );

            -- Handles (contacts)
            INSERT INTO handle VALUES (1, '+15551234567', 'iMessage', 'US');
            INSERT INTO handle VALUES (2, 'alice@example.com', 'iMessage', NULL);

            -- Chat
            INSERT INTO chat VALUES (1, 'iMessage;-;+15551234567', '+15551234567', 'iMessage', NULL);

            -- Messages (using seconds-based Cocoa timestamps: ~2023)
            INSERT INTO message VALUES (1, 'msg-001', 'Hello, how are you?', 1, 'iMessage', 694540800, 694540810, 0, 0, 1, 0, 0, NULL, NULL);
            INSERT INTO message VALUES (2, 'msg-002', 'I am good, thanks!', 1, 'iMessage', 694540860, 0, 694540865, 1, 0, 1, 0, NULL, NULL);
            INSERT INTO message VALUES (3, 'msg-003', 'Check out this photo', 2, 'iMessage', 694541000, 0, 0, 0, 0, 0, 1, NULL, NULL);

            -- Chat-message joins
            INSERT INTO chat_message_join VALUES (1, 1);
            INSERT INTO chat_message_join VALUES (1, 2);

            -- Attachment
            INSERT INTO attachment VALUES (1, 'att-001', '~/Library/Messages/Attachments/photo.jpg', 'image/jpeg', 245000, 694541000, 'photo.jpg', 'public.jpeg', 0);

            -- Message-attachment join
            INSERT INTO message_attachment_join VALUES (3, 1);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Create a minimal iMessage DB with nanosecond timestamps (iOS 14+).
fn create_imessage_nano_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_nano_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                text TEXT,
                handle_id INTEGER DEFAULT 0,
                service TEXT DEFAULT 'iMessage',
                date INTEGER DEFAULT 0,
                date_read INTEGER DEFAULT 0,
                date_delivered INTEGER DEFAULT 0,
                is_from_me INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                is_delivered INTEGER DEFAULT 0,
                cache_has_attachments INTEGER DEFAULT 0,
                associated_message_guid TEXT,
                reply_to_guid TEXT
            );
            CREATE TABLE handle (
                ROWID INTEGER PRIMARY KEY,
                id TEXT NOT NULL,
                service TEXT DEFAULT 'iMessage',
                country TEXT
            );

            INSERT INTO handle VALUES (1, '+447775001234', 'iMessage', 'GB');
            -- Nanosecond timestamp: 694540800 * 1e9 + 123456789 ns
            INSERT INTO message VALUES (1, 'nano-001', 'Nano timestamp test', 1, 'iMessage', 694540800123456789, 0, 0, 0, 1, 0, 0, NULL, NULL);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Minimal chat.db (message/handle/chat/chat_message_join) seeded with `rows`.
/// Used by the join-fan-out and NULL-flag cases, which need a schema small
/// enough that the assertion is about one behaviour only.
fn create_minimal_chat_db(rows: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_min_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                text TEXT,
                handle_id INTEGER DEFAULT 0,
                service TEXT DEFAULT 'iMessage',
                date INTEGER DEFAULT 0,
                date_read INTEGER DEFAULT 0,
                date_delivered INTEGER DEFAULT 0,
                is_from_me INTEGER,
                is_read INTEGER,
                cache_has_attachments INTEGER DEFAULT 0
            );
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL);
            CREATE TABLE chat (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT UNIQUE NOT NULL,
                chat_identifier TEXT,
                display_name TEXT
            );
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
            {rows}"
        ))
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn parse_bytes(data: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "chat.db"}),
    );
    IMessageParser.process(&artifact).unwrap()
}

#[test]
fn test_message_in_two_chats_is_not_duplicated() {
    // BUG-227: chat_message_join is many-to-many. A message filed under both an
    // iMessage and an SMS chat must still produce exactly one artifact, not one
    // per chat membership.
    let data = create_minimal_chat_db(
        "INSERT INTO handle VALUES (1, '+15550000001');
         INSERT INTO chat VALUES (1, 'iMessage;-;+15550000001', '+15550000001', NULL);
         INSERT INTO chat VALUES (2, 'SMS;-;+15550000001', '+15550000001', NULL);
         INSERT INTO message VALUES (1, 'dup-001', 'only once please', 1, 'iMessage', 694540800, 0, 0, 0, 1, 0);
         INSERT INTO chat_message_join VALUES (1, 1);
         INSERT INTO chat_message_join VALUES (2, 1);",
    );
    let result = parse_bytes(data);
    let messages: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(
        messages.len(),
        1,
        "a message in two chats must not be emitted twice"
    );
    assert_eq!(messages[0].metadata["chat_identifier"], "+15550000001");
}

#[test]
fn test_null_direction_flags_do_not_drop_the_message() {
    // BUG-229: is_from_me / is_read can be NULL on a damaged row. The message
    // must survive with an unknown direction rather than being skipped.
    let data = create_minimal_chat_db(
        "INSERT INTO handle VALUES (1, '+15550000002');
         INSERT INTO chat VALUES (1, 'iMessage;-;+15550000002', '+15550000002', NULL);
         INSERT INTO message VALUES (1, 'null-001', 'direction unknown', 1, 'iMessage', 694540800, 0, 0, NULL, NULL, 0);
         INSERT INTO chat_message_join VALUES (1, 1);",
    );
    let result = parse_bytes(data);
    let messages: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 1, "NULL flags must not drop the row");
    let m = &messages[0].metadata;
    assert_eq!(m["text"], "direction unknown");
    assert!(m["is_from_me"].is_null(), "unknown direction must be null");
    assert!(m["is_read"].is_null());
    assert!(m["direction"].is_null(), "must not be guessed as received");
    assert!(m["name"].as_str().unwrap().starts_with("message:"));
}

/// BUG-255: when the attachment tables exist but cannot be read, the failure
/// must surface. Messages that claim `has_attachments` are marked incomplete and
/// a record of the failure is emitted, rather than the conversation silently
/// showing no media at all.
#[test]
fn test_attachment_inventory_failure_is_reported() {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_att_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        // `attachment` exists (so the inventory is attempted) but lacks the
        // columns the query names, so preparing it fails.
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY, guid TEXT UNIQUE NOT NULL, text TEXT,
                handle_id INTEGER DEFAULT 0, service TEXT DEFAULT 'iMessage',
                date INTEGER DEFAULT 0, date_read INTEGER DEFAULT 0,
                date_delivered INTEGER DEFAULT 0, is_from_me INTEGER,
                is_read INTEGER, cache_has_attachments INTEGER DEFAULT 0
            );
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL);
            CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT UNIQUE NOT NULL, chat_identifier TEXT, display_name TEXT);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
            CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY);
            CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
            INSERT INTO handle VALUES (1, '+15550000003');
            INSERT INTO chat VALUES (1, 'iMessage;-;+15550000003', '+15550000003', NULL);
            INSERT INTO message VALUES (1, 'att-001', 'photo attached', 1, 'iMessage', 694540800, 0, 0, 0, 1, 1);
            INSERT INTO chat_message_join VALUES (1, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let result = parse_bytes(data);

    let message = result
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("message parsed");
    assert_eq!(message.metadata["has_attachments"], true);
    assert_eq!(
        message.metadata["attachment_inventory_incomplete"], true,
        "a message claiming media must say the inventory failed"
    );
    assert_eq!(
        message.metadata["incomplete_reason"],
        "unresolved_structure"
    );

    let failure = result
        .iter()
        .find(|a| a.metadata["status"] == "AttachmentInventoryFailed")
        .expect("attachment inventory failure reported");
    assert_eq!(failure.metadata["source_table"], "attachment");
    assert!(failure.metadata["error"].as_str().is_some());

    // B3-022: the plugin-local keys above are invisible to the API and export
    // honesty paths, which read `content_incomplete`. Without the standard pair
    // a message whose media could not be inventoried exported as a complete
    // message that simply carried no attachment.
    assert_eq!(
        message.metadata["content_incomplete"], true,
        "the standard flag must carry the failed attachment inventory"
    );
    assert_eq!(
        message.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(failure.metadata["content_incomplete"], true);
    assert_eq!(
        failure.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(failure.metadata["inventory_incomplete"], true);
}

#[test]
fn test_module_metadata() {
    let parser = IMessageParser;
    assert_eq!(parser.id(), "plugin.apple.imessage");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_skips_non_imessage_file() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "random_file.txt"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_skips_no_name() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({}));
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_identification_only_without_data_source() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "sms.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "iMessage");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_imessage_parsing() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let data = create_imessage_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let result = parser.process(&artifact).unwrap();

    // Should have 3 messages + 1 attachment = 4 records
    assert_eq!(
        result.len(),
        4,
        "Expected 4 records (3 messages + 1 attachment), got {}",
        result.len()
    );

    // Find messages by subtype
    let messages: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    let attachments: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_attachment")
        .collect();

    assert_eq!(messages.len(), 3);
    assert_eq!(attachments.len(), 1);

    // Check first received message
    let received = messages
        .iter()
        .find(|a| a.metadata["guid"] == "msg-001")
        .expect("Should find msg-001");
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["is_from_me"], false);
    assert_eq!(received.metadata["contact"], "+15551234567");
    assert_eq!(received.metadata["text"], "Hello, how are you?");
    assert_eq!(received.metadata["service"], "iMessage");

    // Check sent message
    let sent = messages
        .iter()
        .find(|a| a.metadata["guid"] == "msg-002")
        .expect("Should find msg-002");
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    // Check attachment
    let att = &attachments[0];
    assert_eq!(att.metadata["mime_type"], "image/jpeg");
    assert_eq!(att.metadata["total_bytes"], 245000);
    assert_eq!(att.metadata["transfer_name"], "photo.jpg");
}

#[test]
fn test_cocoa_timestamp_conversion() {
    // 0 means "unset": it must be None, not 1970 or 2001
    assert_eq!(cocoa_to_unix_nanos(0), None);
    assert_eq!(cocoa_to_unix_nanos(1), Some((978_307_201, 0))); // 1 second after epoch

    // Known conversion: 694540800 seconds after 2001-01-01 = Unix 1672848000
    // That's approximately 2023-01-04
    assert_eq!(
        cocoa_to_unix_nanos(694540800),
        Some((694540800 + 978_307_200, 0))
    );
}

#[test]
fn test_nanosecond_timestamp_detection() {
    // Values above the 1e9 boundary are nanoseconds since 2001
    let nano_ts: i64 = 694_540_800_000_000_000;
    assert_eq!(
        cocoa_to_unix_nanos(nano_ts),
        Some((694540800 + 978_307_200, 0))
    );

    // Sub-second precision must be preserved, not truncated away
    let nano_ts_frac: i64 = 694_540_800_123_456_789;
    assert_eq!(
        cocoa_to_unix_nanos(nano_ts_frac),
        Some((694540800 + 978_307_200, 123_456_789))
    );
}

#[test]
fn test_zero_dates_absent_from_metadata() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let data = create_imessage_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let result = parser.process(&artifact).unwrap();

    // msg-002 has date_read = 0 (unread): must be null, not 2001-01-01
    let sent = result
        .iter()
        .find(|a| a.metadata["guid"] == "msg-002")
        .expect("Should find msg-002");
    assert!(
        sent.metadata["date_read"].is_null(),
        "date_read 0 must not become an epoch date, got {:?}",
        sent.metadata["date_read"]
    );
    // its date_delivered is set and must convert
    assert_eq!(
        sent.metadata["date_delivered"].as_i64(),
        Some(694540865 + 978_307_200)
    );
}

#[test]
fn test_nanosecond_db_parsing() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let data = create_imessage_nano_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);

    let msg = &result[0];
    let expected_unix = 694540800i64 + 978_307_200;
    assert_eq!(msg.metadata["date"].as_i64().unwrap(), expected_unix);
    // Nanosecond sources keep full precision in date_ns (unix epoch ns)
    assert_eq!(
        msg.metadata["date_ns"].as_i64().unwrap(),
        expected_unix * 1_000_000_000 + 123_456_789
    );
}

#[test]
fn test_parent_id_chain() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let data = create_imessage_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let parent_id = artifact.id;
    let result = parser.process(&artifact).unwrap();
    for record in &result {
        assert_eq!(record.parent_id, Some(parent_id));
        assert_eq!(record.case_id, case_id);
        assert_eq!(record.artifact_type, ArtifactType::ParsedRecord);
    }
}

#[test]
fn test_invalid_sqlite_graceful_handling() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let data = vec![0u8; 1024];
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    // Should produce a ParseFailed identification artifact
    assert!(result.len() <= 1);
}

#[test]
fn test_chat_db_also_detected() {
    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "chat.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_real_imessage_db() {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let db_path = crate_dir
        .parent()
        .unwrap()
        .join("test_data")
        .join("imessage_chat.db");

    if !db_path.exists() {
        eprintln!("Skipping test_real_imessage_db: {:?} not found", db_path);
        return;
    }

    let data = std::fs::read(&db_path).unwrap();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let parser = IMessageParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "sms.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    assert!(
        !result.is_empty(),
        "Expected at least some records from real iMessage DB"
    );

    // Check that messages have expected structure
    let messages: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();

    assert!(!messages.is_empty(), "Expected at least some messages");

    // Every message should have a date and direction
    for msg in &messages {
        assert!(msg.metadata.get("date").is_some(), "Message missing date");
        assert!(
            msg.metadata.get("direction").is_some(),
            "Message missing direction"
        );
        assert!(
            msg.metadata.get("service").is_some(),
            "Message missing service"
        );
    }

    eprintln!(
        "Parsed {} records from real iMessage DB ({} messages)",
        result.len(),
        messages.len()
    );
}

/// Open a database built from `bytes` read-only, the way `process` does.
fn open_bytes(bytes: &[u8]) -> (seance_sqlite_util::TempDb, Connection) {
    let temp = seance_sqlite_util::TempDb::write(bytes, "imessage_test").unwrap();
    let conn = temp.open().unwrap();
    (temp, conn)
}

/// B2-126: the message walk is `ORDER BY date DESC LIMIT n`, so hitting the cap
/// drops the OLDEST messages — the beginning of a conversation. Nothing said so,
/// which made "this is the conversation" the only reading available.
#[test]
fn a_capped_message_walk_says_it_stopped_early() {
    let data = create_minimal_chat_db(
        "INSERT INTO handle VALUES (1, '+15550000001');
         INSERT INTO chat VALUES (1, 'iMessage;-;+15550000001', '+15550000001', NULL);
         INSERT INTO message VALUES (1, 'm-1', 'oldest', 1, 'iMessage', 694540800, 0, 0, 0, 1, 0);
         INSERT INTO message VALUES (2, 'm-2', 'middle', 1, 'iMessage', 694540900, 0, 0, 0, 1, 0);
         INSERT INTO message VALUES (3, 'm-3', 'newest', 1, 'iMessage', 694541000, 0, 0, 0, 1, 0);
         INSERT INTO chat_message_join VALUES (1, 1);
         INSERT INTO chat_message_join VALUES (1, 2);
         INSERT INTO chat_message_join VALUES (1, 3);",
    );
    let (_temp, conn) = open_bytes(&data);

    let capped = parse_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    let messages: Vec<&Artifact> = capped
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 2, "the cap must still be enforced");
    // Newest-first: the message that fell off the end is the oldest one.
    assert!(messages.iter().all(|m| m.metadata["text"] != "oldest"));

    let marker = capped
        .iter()
        .find(|a| a.metadata["status"] == "CapReached" && a.metadata["source_table"] == "message")
        .expect("a capped walk must emit an incompleteness marker");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(marker.metadata["max_entries"], 2);

    // Exactly at the cap is NOT truncation: the marker must not cry wolf.
    let exact = parse_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 3).unwrap();
    assert!(
        !exact.iter().any(|a| a.metadata["status"] == "CapReached"),
        "a walk that read every row must not claim it stopped early"
    );
}

/// B2-127: the same for the attachment inventory. Full inventory *failure* was
/// already reported; stopping at the cap was not, so "no attachment record" read
/// as "no attachment".
#[test]
fn a_capped_attachment_inventory_says_it_stopped_early() {
    let temp_path =
        std::env::temp_dir().join(format!("test_imessage_attcap_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY, guid TEXT UNIQUE NOT NULL, text TEXT,
                handle_id INTEGER DEFAULT 0, service TEXT DEFAULT 'iMessage',
                date INTEGER DEFAULT 0, date_read INTEGER DEFAULT 0,
                date_delivered INTEGER DEFAULT 0, is_from_me INTEGER,
                is_read INTEGER, cache_has_attachments INTEGER DEFAULT 0
            );
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL);
            CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT UNIQUE NOT NULL, chat_identifier TEXT, display_name TEXT);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
            CREATE TABLE attachment (
                ROWID INTEGER PRIMARY KEY, guid TEXT, filename TEXT, mime_type TEXT,
                total_bytes INTEGER, created_date INTEGER, transfer_name TEXT,
                uti TEXT, is_outgoing INTEGER
            );
            CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
            INSERT INTO handle VALUES (1, '+15550000003');
            INSERT INTO message VALUES (1, 'att-001', 'photo', 1, 'iMessage', 694540800, 0, 0, 0, 1, 1);
            INSERT INTO attachment VALUES (1, 'a-1', 'IMG_1.jpg', 'image/jpeg', 10, 694540800, 'IMG_1.jpg', 'public.jpeg', 0);
            INSERT INTO attachment VALUES (2, 'a-2', 'IMG_2.jpg', 'image/jpeg', 10, 694540900, 'IMG_2.jpg', 'public.jpeg', 0);
            INSERT INTO message_attachment_join VALUES (1, 1);
            INSERT INTO message_attachment_join VALUES (1, 2);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    let (_temp, conn) = open_bytes(&data);

    let out = parse_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    let attachments: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_attachment")
        .collect();
    assert_eq!(attachments.len(), 1);

    let marker = out
        .iter()
        .find(|a| {
            a.metadata["status"] == "CapReached" && a.metadata["source_table"] == "attachment"
        })
        .expect("a capped attachment inventory must be marked incomplete");
    // The marker must NOT reuse the type its records carry: `seance_db` groups
    // ParsedRecords by `metadata.$.type`, so a marker typed `iMessageAttachment`
    // would be filed among the attachments it qualifies. It is named after them
    // instead (see `seance_sqlite_util::cap_marker`).
    assert_eq!(marker.metadata["type"], "iMessageAttachmentIncomplete");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["content_incomplete_reason"], "cap_reached");
}

/// B2-123: SQLite answers queries from a truncated file without complaining, so
/// a database the spill could not stage in full yields a partial conversation
/// that is indistinguishable from a complete one. Every record must carry the
/// fact, and a marker must exist even when nothing was recovered.
#[test]
fn a_short_read_database_marks_every_record_it_produced() {
    let data = create_minimal_chat_db(
        "INSERT INTO handle VALUES (1, '+15550000001');
         INSERT INTO chat VALUES (1, 'iMessage;-;+15550000001', '+15550000001', NULL);
         INSERT INTO message VALUES (1, 'm-1', 'hello', 1, 'iMessage', 694540800, 0, 0, 0, 1, 0);
         INSERT INTO chat_message_join VALUES (1, 1);",
    );
    let ds: Arc<dyn DataSource> =
        Arc::new(seance_core::test_support::TruncatedSource::halved(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "chat.db"}),
    );
    let result = IMessageParser.process(&artifact).unwrap();

    let message = result
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("the readable prefix still parses");
    assert_eq!(
        message.metadata["content_incomplete"], true,
        "a record pulled out of a partial database must carry that fact"
    );
    assert_eq!(message.metadata["content_incomplete_reason"], "short_read");

    let marker = result
        .iter()
        .find(|a| a.metadata["status"] == "DatabaseNotStagedInFull")
        .expect("a partial spill must be reported in its own right");
    assert_eq!(marker.metadata["file_name"], "chat.db");
}

/// The counterpart: a database read whole must stay unmarked, or the marker
/// carries no information.
#[test]
fn a_complete_database_carries_no_incompleteness_marks() {
    let result = parse_bytes(create_imessage_test_db());
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
    assert!(
        !result
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a complete parse must not emit a partial-database marker"
    );
}

/// B3-023: a row the walk fetched but could not decode used to disappear into a
/// `debug!` line. What an examiner learns from the marker: the message count is
/// a floor, not a total. A wrong answer looks like "1 message" for a database
/// that holds two, one of them recoverable-but-corrupt, with nothing to say so.
#[test]
fn undecodable_message_rows_are_tallied_not_silently_dropped() {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        // `ROWID` declared INTEGER (not INTEGER PRIMARY KEY, so it is a plain
        // column, not the rowid alias). INTEGER affinity keeps `1` an integer
        // and stores the non-numeric `'corrupt'` as TEXT, so exactly one of the
        // two rows makes `row.get::<i64>` fail, as a corrupt page would.
        // A TEXT-affinity column would convert BOTH values to text and drop the
        // whole table, which would not test the tally at all.
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER,
                guid TEXT,
                text TEXT,
                handle_id INTEGER,
                service TEXT,
                date INTEGER,
                date_read INTEGER,
                date_delivered INTEGER,
                is_from_me INTEGER,
                is_read INTEGER,
                cache_has_attachments INTEGER
            );
            INSERT INTO message VALUES (1, 'ok-1', 'readable', 0, 'iMessage', 694540800, 0, 0, 0, 0, 0);
            INSERT INTO message VALUES ('corrupt', 'bad-1', 'unreachable', 0, 'iMessage', 694540900, 0, 0, 0, 0, 0);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let result = parse_bytes(data);

    let messages = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .count();
    assert_eq!(messages, 1, "only the decodable row yields a message");

    let marker = result
        .iter()
        .find(|a| a.metadata["type"] == "iMessageIncomplete")
        .expect("a dropped row must produce an incompleteness marker");
    assert_eq!(marker.metadata["status"], "RowsUndecodable");
    assert_eq!(marker.metadata["rows_dropped"], 1);
    assert_eq!(marker.metadata["records_recovered"], 1);
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["inventory_incomplete"], true);
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

/// B3-023 control: a database whose rows all decode must carry no dropped-row
/// marker, or the marker means nothing.
#[test]
fn a_fully_decodable_database_has_no_dropped_row_marker() {
    let result = parse_bytes(create_imessage_test_db());
    assert!(
        !result
            .iter()
            .any(|a| a.metadata["status"] == "RowsUndecodable"),
        "no rows were dropped, so nothing may claim they were"
    );
}

/// B7-019: a NULL `cache_has_attachments` never recorded whether the message
/// carried media. Before the fix `unwrap_or(0) != 0` published it as
/// `has_attachments: false` — "this message had no media" — while the direction
/// on the same row was correctly left as an Option.
#[test]
fn a_null_attachment_flag_is_unknown_not_false() {
    let temp_path = std::env::temp_dir().join(format!("test_imsg_nullatt_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
            INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '15009');
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER,
                service TEXT, date INTEGER, date_read INTEGER, date_delivered INTEGER,
                is_from_me INTEGER, is_read INTEGER, cache_has_attachments INTEGER
            );
            INSERT INTO message VALUES (1, 'g-1', 'unknown media', 0, 'iMessage', 694540800, 0, 0, 1, 0, NULL);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let result = parse_bytes(data);
    let msg = result
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("the row parses");
    assert!(
        msg.metadata["has_attachments"].is_null(),
        "an unrecorded attachment flag must not read as 'no media': {}",
        msg.metadata["has_attachments"]
    );
}

// --- B8-012: the optional-column probe must not fail closed as "absent" ---

/// Damage page 1's b-tree without touching the file header, so the database
/// OPENS and then answers every catalogue query with `SQLITE_CORRUPT` — the
/// state a carved or partially recovered `chat.db` arrives in.
///
/// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6`.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

/// B8-012. The optional-column probe ended in `.unwrap_or(false)`, so a
/// catalogue read that failed substituted `NULL AS attributedBody` — and modern
/// iOS stores most message bodies ONLY there. The conversation then came out
/// empty or attachment-only, with nothing to distinguish "these messages had no
/// text" from "the store was unreadable for columns". The table probes beside it
/// already made that distinction; the column probe did not.
///
/// The conservative `NULL` substitution is unchanged. What is new is that the
/// reason is retained — the unfixed closure returned only a `bool` and kept
/// nothing, so this assertion had nothing to read.
#[test]
fn an_unanswerable_column_probe_is_declared_not_read_as_an_absent_column() {
    let (_temp, conn) = open_bytes(&corrupt_the_catalogue(create_imessage_test_db()));

    let (assoc, reply, body, probe) = optional_message_columns(&conn);
    assert_eq!(assoc, "NULL AS associated_message_guid");
    assert_eq!(reply, "NULL AS reply_to_guid");
    assert_eq!(body, "NULL AS attributedBody");
    assert!(
        probe.undetermined(),
        "a column list that would not read must not pass as an absent column"
    );

    let marker = probe
        .marker(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "iMessageIncomplete",
            "message",
            4,
        )
        .expect("an undetermined probe owes the examiner a marker");
    assert_eq!(marker.metadata["type"], json!("iMessageIncomplete"));
    assert_ne!(
        marker.metadata["type"],
        json!("iMessage"),
        "a marker filed under the message type becomes a phantom conversation"
    );
    assert_eq!(marker.metadata["status"], json!("SchemaUndetermined"));
    assert_eq!(marker.metadata["records_recovered"], json!(4));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_detail"],
        marker.metadata["detail"]
    );
}

/// A `chat.db` that opens and then will not answer for its own catalogue takes
/// the parse-failure path, and that record is a statement ABOUT the database —
/// never one of its messages.
///
/// `SqliteConnection::conversation_summaries` selects ParsedRecords on
/// `metadata.$.type` alone, with no subtype filter, and the iMessage thread-key
/// expression COALESCEs down to the literal `'unknown'`. A failure record typed
/// `"iMessage"` is therefore counted as a message in an `unknown` conversation
/// the custodian never had — a fabricated thread in an exhibit. Same rule the
/// `cap_marker` docs state for the helper-built markers; this hand-rolled one
/// sat outside that sweep.
#[test]
fn a_database_that_would_not_parse_is_not_filed_as_one_of_its_messages() {
    let out = parse_bytes(corrupt_the_catalogue(create_imessage_test_db()));
    let failed = out
        .iter()
        .find(|a| a.metadata["status"] == json!("ParseFailed"))
        .expect("a chat.db whose catalogue will not read must say so");
    assert_eq!(failed.metadata["type"], json!("iMessageIncomplete"));
    assert_ne!(
        failed.metadata["type"],
        json!("iMessage"),
        "a parse failure filed under the message type invents a conversation"
    );
    // And it stays visible to the completeness census and the court report,
    // which key on the standard pair rather than on `status`.
    assert_eq!(failed.metadata["content_incomplete"], json!(true));
    assert_eq!(
        failed.metadata["content_incomplete_reason"],
        json!("unresolved_structure")
    );
    assert_eq!(failed.metadata["inventory_incomplete"], json!(true));
    // The sentence lands on the key the examiner-facing reader shows.
    assert!(failed.metadata["content_incomplete_detail"]
        .as_str()
        .is_some_and(|s| s.contains("chat.db")));
}

/// The control that gives the stamp its meaning: on a readable `chat.db` every
/// optional-column probe is ANSWERED, so no message may carry a schema-probe
/// stamp and no marker may be emitted.
#[test]
fn a_readable_chat_db_carries_no_schema_probe_stamp() {
    let (_temp, conn) = open_bytes(&create_imessage_test_db());
    let (_, _, body, probe) = optional_message_columns(&conn);
    assert!(!probe.undetermined(), "{:?}", probe.failures());
    assert_eq!(probe.detail(), None);
    // The healthy fixture has no attributedBody column, and an ANSWERED absence
    // is a finding: the NULL substitution is correct and must stay silent.
    assert_eq!(body, "NULL AS attributedBody");

    let out = parse_bytes(create_imessage_test_db());
    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == json!("SchemaUndetermined")),
        "a schema marker on a readable database would make the marker meaningless"
    );
    assert!(!out
        .iter()
        .any(|a| a.metadata.get("schema_probe_incomplete").is_some()));
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

/// The marker records this parse emitted about the schema itself.
fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// Apple's own version row. The three real stores this parser was validated
/// against record `_ClientVersion` 9005, 14005 and 15009 and leave
/// `PRAGMA user_version` at 0, so the version row is the signal.
const CLIENT_VERSION_ROW: &str = "CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);
     INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '{v}');";

fn minimal_chat_db_with_version(v: &str, rows: &str) -> Vec<u8> {
    create_minimal_chat_db(&format!("{} {rows}", CLIENT_VERSION_ROW.replace("{v}", v)))
}

const ONE_MESSAGE: &str = "INSERT INTO message VALUES (1, 'g1', 'still parsed', 1, 'iMessage', \
     694540800, 0, 0, 1, 1, 0); INSERT INTO handle VALUES (1, '+15551234567');";

/// A `chat.db` whose `_ClientVersion` is newer than any this parser was
/// validated against says so beside the messages it still recovers.
#[test]
fn a_client_version_outside_the_validated_range_is_declared_and_the_messages_still_parse() {
    let result = parse_bytes(minimal_chat_db_with_version("99001", ONE_MESSAGE));
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["app"], SCHEMA_APP);
    assert_eq!(m.metadata["seen_schema_version"], 99001);
    assert_eq!(
        m.metadata["supported_range"],
        SUPPORTED_CLIENT_VERSION.describe()
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
    // HUNT-204: the range names the real stores its endpoints came from.
    let evidence = m.metadata["validated_against"].as_str().unwrap_or_default();
    assert!(
        evidence.contains("imessage_chat.db") && evidence.contains("sms.db"),
        "the range carries no evidence-file name: {}",
        m.metadata
    );
    assert_ne!(m.metadata["type"], "iMessage", "never the walk's own type");
    let messages: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].metadata["text"], "still parsed");
}

/// Inside the window, at both ends, no marker: the control that gives the
/// marker its meaning.
#[test]
fn a_client_version_inside_the_validated_range_carries_no_stale_marker() {
    for v in [
        SUPPORTED_CLIENT_VERSION.min,
        SUPPORTED_CLIENT_VERSION.max.unwrap(),
    ] {
        let result = parse_bytes(minimal_chat_db_with_version(&v.to_string(), ONE_MESSAGE));
        assert!(
            stale_markers(&result).is_empty(),
            "_ClientVersion {v} is inside the window: {result:?}"
        );
    }
}

/// A store with no `_ClientVersion` row is not "in range": it records no
/// version, and the parse is declared unranked — with nothing called
/// incomplete, since nothing was established either way.
#[test]
fn a_store_without_a_client_version_row_is_declared_unranked_not_in_range() {
    let result = parse_bytes(create_minimal_chat_db(ONE_MESSAGE));
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(markers[0].metadata["status"], "SchemaVersionNotRecorded");
    assert_eq!(markers[0].metadata["app"], SCHEMA_APP);
    assert!(markers[0].metadata.get("content_incomplete").is_none());
    assert!(markers[0].metadata["message"]
        .as_str()
        .unwrap()
        .contains("_ClientVersion"));
    assert!(result
        .iter()
        .any(|a| a.metadata["subtype"] == "chat_message"));
}

/// A renamed `message` column is named by the logical field it carried, and
/// the rows still walk with that field absent — never with a substituted value.
#[test]
fn a_renamed_message_column_is_declared_by_logical_field_and_the_rows_still_walk() {
    let temp_path = std::env::temp_dir().join(format!("test_imessage_drift_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(&format!(
            "{}
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER,
                service TEXT, date INTEGER, date_read INTEGER, date_delivered INTEGER,
                from_me INTEGER, is_read INTEGER, cache_has_attachments INTEGER
            );
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL);
            INSERT INTO handle VALUES (1, '+15551234567');
            INSERT INTO message VALUES (1, 'g1', 'direction lost', 1, 'iMessage', 694540800, 0, 0, 1, 1, 0);",
            CLIENT_VERSION_ROW.replace("{v}", "15009")
        ))
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let result = parse_bytes(data);
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(m.metadata["source_table"], "message");
    assert_eq!(m.metadata["unresolved_fields"], json!(["is_from_me"]));
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    let messages: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 1, "the row is still walked");
    assert_eq!(messages[0].metadata["text"], "direction lost");
    assert!(
        messages[0].metadata["is_from_me"].is_null(),
        "no direction column resolved, so none is written"
    );
    assert_eq!(messages[0].metadata["contact"], "+15551234567");
}

/// The attachment inventory has its own column set and its own marker.
#[test]
fn a_renamed_attachment_column_is_declared_under_the_attachment_table() {
    let temp_path =
        std::env::temp_dir().join(format!("test_imessage_adrift_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(&format!(
            "{}
            CREATE TABLE message (
                ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER,
                service TEXT, date INTEGER, date_read INTEGER, date_delivered INTEGER,
                is_from_me INTEGER, is_read INTEGER, cache_has_attachments INTEGER
            );
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL);
            CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT, chat_identifier TEXT, display_name TEXT);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
            CREATE TABLE attachment (
                ROWID INTEGER PRIMARY KEY, guid TEXT, path TEXT, mime_type TEXT,
                total_bytes INTEGER, created_date INTEGER, transfer_name TEXT, uti TEXT,
                is_outgoing INTEGER
            );
            CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
            INSERT INTO message VALUES (1, 'g1', NULL, 0, 'iMessage', 694540800, 0, 0, 1, 1, 1);
            INSERT INTO attachment VALUES (1, 'a1', '/x/photo.jpg', 'image/jpeg', 10, 694540800, 'photo.jpg', 'public.jpeg', 1);
            INSERT INTO message_attachment_join VALUES (1, 1);",
            CLIENT_VERSION_ROW.replace("{v}", "15009")
        ))
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let result = parse_bytes(data);
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(markers[0].metadata["source_table"], "attachment");
    assert_eq!(
        markers[0].metadata["unresolved_fields"],
        json!(["filename"])
    );
    let attachments: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "iMessageAttachment")
        .collect();
    assert_eq!(attachments.len(), 1, "the attachment is still inventoried");
    assert!(attachments[0].metadata["filename"].is_null());
    assert_eq!(attachments[0].metadata["transfer_name"], "photo.jpg");
}

/// The corpus-diff harness: every real store this parser was validated against
/// parses with no schema marker and at least the records observed when the
/// range was declared. Files outside the tree are skipped when absent;
/// `SEANCE_APP_SCHEMA_CORPUS` names the directory holding the CTF-derived
/// copies.
#[test]
fn real_message_stores_in_the_validated_range_carry_no_stale_marker() {
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let corpus = std::env::var_os("SEANCE_APP_SCHEMA_CORPUS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| workspace.join("test_data").join("app_schema_corpus"));
    let expect = |label: &str, min_records: usize| seance_sqlite_util::CorpusExpectation {
        label: label.into(),
        min_records,
    };
    let expectations = [
        (
            workspace.join("reference/plaso/test_data/imessage_chat.db"),
            9005,
            expect("plaso test_data/imessage_chat.db (_ClientVersion 9005)", 10),
        ),
        (
            corpus.join("macos2021_chat.db"),
            14005,
            expect("Magnet 2021 macOS CTF chat.db (_ClientVersion 14005)", 0),
        ),
        (
            corpus.join("ios2022_sms.db"),
            15009,
            expect("Magnet 2022 CTF iPhone 8 sms.db (_ClientVersion 15009)", 13),
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
        assert!(
            SUPPORTED_CLIENT_VERSION.contains(version),
            "the declared range must include the observed version {version}"
        );
        let result = parse_bytes(std::fs::read(&path).unwrap());
        assert!(
            stale_markers(&result).is_empty(),
            "{}: a real store in range must not warn: {:?}",
            expect.label,
            stale_markers(&result)
        );
        assert!(
            !result.iter().any(|a| a.metadata["status"] == "ParseFailed"),
            "{}: {result:?}",
            expect.label
        );
        let messages = result
            .iter()
            .filter(|a| a.metadata["subtype"] == "chat_message")
            .count();
        seance_sqlite_util::check_corpus(&expect, messages).unwrap();
        eprintln!("{}: {messages} messages", expect.label);
        checked += 1;
    }
    eprintln!("checked {checked} real message store(s)");
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
        json!({ "name": "sms.db", "is_directory": true }),
    );
    let out = IMessageParser.process(&artifact).unwrap();
    assert!(out.is_empty(), "a directory is not a sms.db: {out:?}");
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
    let ds: Arc<dyn DataSource> = Arc::new(seance_core::test_support::TruncatedSource::cut_to(
        create_imessage_test_db(),
        4,
    ));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "sms.db" }),
    );
    let out = IMessageParser.process(&artifact).unwrap();
    // What may be said is that the read was short — the stager's own record —
    // and nothing about what the file is.
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].metadata["type"], "SqliteSpillIncomplete", "{out:?}");
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["records_recovered"], 0);
}
