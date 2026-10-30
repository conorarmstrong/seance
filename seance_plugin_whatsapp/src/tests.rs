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

use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

/// Create a synthetic iOS WhatsApp ChatStorage.sqlite with known data.
fn create_ios_whatsapp_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_whatsapp_ios_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                Z_ENT INTEGER DEFAULT 0,
                ZCHATSESSION INTEGER,
                ZTEXT TEXT,
                ZMESSAGEDATE REAL,
                ZISFROMME INTEGER DEFAULT 0,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZSTARRED INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZTOJID TEXT,
                ZMEDIAITEM INTEGER
            );
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZCONTACTJID TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 1
            );
            CREATE TABLE ZWAPROFILEPUSHNAME (
                Z_PK INTEGER PRIMARY KEY,
                ZJID TEXT,
                ZPUSHNAME TEXT
            );
            CREATE TABLE ZWAMEDIAITEM (
                Z_PK INTEGER PRIMARY KEY,
                ZMESSAGE INTEGER,
                ZMEDIALOCALPATH TEXT,
                ZMEDIAURL TEXT,
                ZFILESIZE INTEGER DEFAULT 0,
                ZMEDIATYPE INTEGER DEFAULT 0
            );

            -- Chat sessions
            INSERT INTO ZWACHATSESSION VALUES (1, '15551234567@s.whatsapp.net', 'Alice', 695000000.0, 1);
            INSERT INTO ZWACHATSESSION VALUES (2, '120363001234@g.us', 'Family Group', 695000100.0, 2);

            -- Push names
            INSERT INTO ZWAPROFILEPUSHNAME VALUES (1, '15559876543@s.whatsapp.net', 'Bob');

            -- Messages (ZMESSAGEDATE is Core Data epoch: seconds since 2001-01-01)
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 1, 'Hello from WhatsApp!', 695000000.0, 0, 0, 0, '15551234567@s.whatsapp.net', NULL, NULL);
            INSERT INTO ZWAMESSAGE VALUES (2, 1, 1, 'Hey, how are you?', 695000060.0, 1, 0, 0, NULL, '15551234567@s.whatsapp.net', NULL);
            INSERT INTO ZWAMESSAGE VALUES (3, 1, 2, 'Group message here', 695000100.0, 0, 0, 1, '15559876543@s.whatsapp.net', NULL, NULL);
            INSERT INTO ZWAMESSAGE VALUES (4, 1, 1, NULL, 695000200.0, 0, 1, 0, '15551234567@s.whatsapp.net', NULL, 1);

            -- Media item
            INSERT INTO ZWAMEDIAITEM VALUES (1, 4, '/var/mobile/Media/photo.jpg', NULL, 123456, 1);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Create a synthetic Android WhatsApp msgstore.db with known data.
fn create_android_whatsapp_db() -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_android_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_id TEXT,
                key_remote_jid TEXT,
                key_from_me INTEGER DEFAULT 0,
                data TEXT,
                timestamp INTEGER DEFAULT 0,
                status INTEGER DEFAULT 0,
                media_wa_type INTEGER DEFAULT 0,
                media_size INTEGER DEFAULT 0,
                starred INTEGER DEFAULT 0
            );
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY,
                raw_string TEXT,
                user TEXT,
                server TEXT
            );
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY,
                jid TEXT,
                subject TEXT,
                created_timestamp INTEGER DEFAULT 0
            );

            -- JIDs
            INSERT INTO jid VALUES (1, '15551234567@s.whatsapp.net', '15551234567', 's.whatsapp.net');
            INSERT INTO jid VALUES (2, '120363001234@g.us', '120363001234', 'g.us');

            -- Chats
            INSERT INTO chat VALUES (1, '15551234567@s.whatsapp.net', NULL, 1672848000000);
            INSERT INTO chat VALUES (2, '120363001234@g.us', 'Work Group', 1672848000000);

            -- Messages (timestamps in milliseconds since Unix epoch)
            INSERT INTO message VALUES (1, 'key-001', '15551234567@s.whatsapp.net', 0, 'Hello from Android!', 1672848000000, 0, 0, 0, 0);
            INSERT INTO message VALUES (2, 'key-002', '15551234567@s.whatsapp.net', 1, 'Reply from me', 1672848060000, 5, 0, 0, 0);
            INSERT INTO message VALUES (3, 'key-003', '120363001234@g.us', 0, 'Group chat', 1672848120000, 0, 0, 0, 1);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Modern Android WhatsApp msgstore: renamed columns (`text_data`, `from_me`)
/// and JID linkage via `chat_row_id` -> `chat._id` -> `chat.jid_row_id` ->
/// `jid._id`. No legacy `data`/`key_from_me`/`key_remote_jid` columns exist.
fn create_android_modern_msgstore_db() -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_modern_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER,
                from_me INTEGER DEFAULT 0,
                key_id TEXT,
                sender_jid_row_id INTEGER,
                status INTEGER DEFAULT 0,
                timestamp INTEGER DEFAULT 0,
                message_type INTEGER DEFAULT 0,
                text_data TEXT
            );
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY,
                jid_row_id INTEGER,
                subject TEXT
            );
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY,
                user TEXT,
                server TEXT,
                raw_string TEXT
            );

            INSERT INTO jid VALUES (1, '15551234567', 's.whatsapp.net', '15551234567@s.whatsapp.net');
            INSERT INTO jid VALUES (2, '120363001234', 'g.us', '120363001234@g.us');
            -- Group member: the actual sender of the received group message.
            INSERT INTO jid VALUES (3, '447700900999', 's.whatsapp.net', '447700900999@s.whatsapp.net');

            INSERT INTO chat VALUES (1, 1, NULL);
            INSERT INTO chat VALUES (2, 2, 'Modern Group');

            INSERT INTO message VALUES (1, 1, 0, 'k1', 0, 0, 1672848000000, 0, 'Hi from modern schema');
            INSERT INTO message VALUES (2, 1, 1, 'k2', 0, 5, 1672848060000, 0, 'Reply modern');
            INSERT INTO message VALUES (3, 2, 0, 'k3', 3, 0, 1672848120000, 0, 'Group modern');"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Transitional Android schema: modern text/from_me column names, but the
/// remote party is referenced through `key_remote_jid` as an INTEGER foreign key
/// into `jid._id` (not a string matching `jid.raw_string`).
fn create_android_transitional_intfk_db() -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_transitional_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_id TEXT,
                key_remote_jid INTEGER,
                from_me INTEGER DEFAULT 0,
                text_data TEXT,
                timestamp INTEGER DEFAULT 0,
                status INTEGER DEFAULT 0
            );
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY,
                raw_string TEXT,
                user TEXT,
                server TEXT
            );
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY,
                jid_row_id INTEGER,
                subject TEXT
            );

            INSERT INTO jid VALUES (1, '447700900123@s.whatsapp.net', '447700900123', 's.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);

            INSERT INTO message VALUES (1, 'kk1', 1, 0, 'transitional hi', 1672848000000, 0);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Android msgstore whose `message_media` table has no `message_row_id`
/// (linkage held in the string `message_url` column instead).
fn create_android_media_no_rowid_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_whatsapp_media_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_remote_jid TEXT,
                key_from_me INTEGER DEFAULT 0,
                data TEXT,
                timestamp INTEGER DEFAULT 0
            );
            CREATE TABLE message_media (
                message_url TEXT,
                file_path TEXT,
                file_size INTEGER
            );

            INSERT INTO message VALUES (1, '15551234567@s.whatsapp.net', 0, 'has media', 1672848000000);
            INSERT INTO message_media VALUES ('https://mmg.whatsapp.net/x', '/storage/WhatsApp/Media/IMG-1.jpg', 45678);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Modern column names and `chat_row_id` linkage, but a `chat` table with no
/// `subject` column. Selecting `c.subject` unconditionally would fail
/// prepare() and collapse the whole database to a ParseFailed stub.
fn create_android_chat_without_subject_db() -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_nosubject_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER,
                from_me INTEGER DEFAULT 0,
                text_data TEXT,
                timestamp INTEGER DEFAULT 0
            );
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY,
                jid_row_id INTEGER
            );
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY,
                raw_string TEXT
            );

            INSERT INTO jid VALUES (1, '15551112222@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1);
            INSERT INTO message VALUES (1, 1, 0, 'no subject column', 1672848000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// An integer `key_remote_jid` with no `jid` table to resolve it. Selecting the
/// raw integer as the JID string fails the String decode on every row, which
/// would drop the entire conversation.
fn create_android_intfk_without_jid_table_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_whatsapp_nojid_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_remote_jid INTEGER,
                from_me INTEGER DEFAULT 0,
                text_data TEXT,
                timestamp INTEGER DEFAULT 0
            );

            INSERT INTO message VALUES (1, 7, 0, 'orphan jid', 1672848000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn test_module_metadata() {
    let parser = WhatsAppParser;
    assert_eq!(parser.id(), "plugin.messaging.whatsapp");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_skips_non_whatsapp_file() {
    let parser = WhatsAppParser;
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
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({}));
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_identification_only_ios() {
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "WhatsApp");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_identification_only_android() {
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "msgstore.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "WhatsApp");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_ios_whatsapp_parsing() {
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let data = create_ios_whatsapp_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    // Messages and media are both emitted; count them separately so adding one
    // does not silently change the other's expectation.
    let messages: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsApp")
        .collect();
    assert_eq!(
        messages.len(),
        4,
        "Expected 4 messages, got {}",
        messages.len()
    );

    // The fixture's media row links to message 4, so it is reported against
    // that message rather than only against the conversation.
    let media: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsAppAttachment")
        .collect();
    assert_eq!(media.len(), 1, "Expected the fixture's one media item");
    assert_eq!(media[0].metadata["message_rowid"], 4);
    assert_eq!(media[0].metadata["transfer_name"], "photo.jpg");
    assert_eq!(media[0].metadata["mime_type"], "image/jpeg");

    // Check first received message
    let received = result
        .iter()
        .find(|a| a.metadata["pk"] == 1)
        .expect("Should find pk=1");
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["text"], "Hello from WhatsApp!");
    assert_eq!(received.metadata["platform"], "iOS");
    assert_eq!(received.metadata["is_from_me"], false);

    // Check sent message
    let sent = result
        .iter()
        .find(|a| a.metadata["pk"] == 2)
        .expect("Should find pk=2");
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    // Check group message
    let group = result
        .iter()
        .find(|a| a.metadata["pk"] == 3)
        .expect("Should find pk=3");
    assert_eq!(group.metadata["is_group"], true);
    assert_eq!(group.metadata["starred"], true);

    // Contact resolution: partner_name (chat session) takes priority over push_name
    // For group chats, partner_name is the group name ("Family Group")
    assert_eq!(group.metadata["contact_name"], "Family Group");
}

#[test]
fn test_ios_whatsapp_through_short_reading_source() {
    // Read the DB back in small chunks, as a window over a disk image does. The
    // short-read handling in the temp-file spill must still recover every
    // message; a single read_at would write a truncated temp DB and lose rows.
    let parser = WhatsAppParser;
    let data = create_ios_whatsapp_db();
    let ds: Arc<dyn DataSource> = Arc::new(DribbleSource::new(data, 500));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = parser.process(&artifact).unwrap();
    let messages = result
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsApp")
        .count();
    assert_eq!(
        messages, 4,
        "short-reading source must recover all messages, got {messages}"
    );
}

/// A ChatStorage.sqlite whose messages have no chat-session row, so the peer can
/// only come from the message's own JID columns: `ZTOJID` on a sent message,
/// `ZFROMJID` on a received one.
fn create_ios_sessionless_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_wa_ios_nosess_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                Z_ENT INTEGER DEFAULT 0,
                ZCHATSESSION INTEGER,
                ZTEXT TEXT,
                ZMESSAGEDATE REAL,
                ZISFROMME INTEGER,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZSTARRED INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZTOJID TEXT,
                ZMEDIAITEM INTEGER
            );
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZCONTACTJID TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 1
            );

            -- Sent: the peer is on ZTOJID, ZFROMJID is NULL (sender is the owner).
            INSERT INTO ZWAMESSAGE VALUES (1, 1, NULL, 'on my way', 695000000.0, 1, 0, 0, NULL, '15551234567@s.whatsapp.net', NULL);
            -- Received: the peer is on ZFROMJID.
            INSERT INTO ZWAMESSAGE VALUES (2, 1, NULL, 'see you', 695000060.0, 0, 0, 0, '15551234567@s.whatsapp.net', NULL, NULL);
            -- Direction never recorded (NULL ZISFROMME).
            INSERT INTO ZWAMESSAGE VALUES (3, 1, NULL, 'no direction', 695000120.0, NULL, 0, 0, '15559998888@s.whatsapp.net', NULL, NULL);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// BUG-252: a sent message carries the remote party on `ZTOJID`. Reading only
/// `ZFROMJID` reported the peer as Unknown (or as the device owner).
#[test]
fn test_ios_sent_message_takes_contact_from_to_jid() {
    let parser = WhatsAppParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_sessionless_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = parser.process(&artifact).unwrap();

    let sent = result
        .iter()
        .find(|a| a.metadata["pk"] == 1)
        .expect("sent message");
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["contact"], "15551234567@s.whatsapp.net");
    assert_eq!(sent.metadata["remote_jid"], "15551234567@s.whatsapp.net");
    assert_eq!(sent.metadata["phone_number"], "15551234567");

    // Received messages still resolve through ZFROMJID, so both directions
    // thread on the same peer.
    let received = result
        .iter()
        .find(|a| a.metadata["pk"] == 2)
        .expect("received message");
    assert_eq!(
        received.metadata["remote_jid"],
        "15551234567@s.whatsapp.net"
    );
    assert_eq!(received.metadata["phone_number"], "15551234567");
}

/// BUG-253: a NULL `ZISFROMME` means the direction was never recorded. It must
/// stay unknown instead of being asserted as "received".
#[test]
fn test_ios_null_is_from_me_stays_unknown() {
    let parser = WhatsAppParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_sessionless_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = parser.process(&artifact).unwrap();

    let unknown = result
        .iter()
        .find(|a| a.metadata["pk"] == 3)
        .expect("message with no direction flag");
    assert!(
        unknown.metadata["is_from_me"].is_null(),
        "unrecorded direction must not be asserted"
    );
    assert!(unknown.metadata["direction"].is_null());
    // The peer is still resolved from the JID that is present.
    assert_eq!(unknown.metadata["remote_jid"], "15559998888@s.whatsapp.net");
}

/// BUG-253, Android: a NULL `key_from_me` is unknown, not received.
#[test]
fn test_android_null_from_me_stays_unknown() {
    let temp_path = std::env::temp_dir().join(format!("test_wa_and_nodir_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (
                _id INTEGER PRIMARY KEY, key_id TEXT, key_remote_jid TEXT,
                key_from_me INTEGER, data TEXT, timestamp INTEGER,
                status INTEGER DEFAULT 0, media_wa_type INTEGER DEFAULT 0,
                media_size INTEGER DEFAULT 0, starred INTEGER DEFAULT 0);
             CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
             INSERT INTO jid VALUES (1, '15551234567@s.whatsapp.net');
             INSERT INTO message VALUES (1,'k1','15551234567@s.whatsapp.net',NULL,'no flag',1673307200000,0,0,0,0);",
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
        json!({"name": "msgstore.db"}),
    );
    let result = WhatsAppParser.process(&artifact).unwrap();
    let msg = result
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("message");
    assert!(msg.metadata["is_from_me"].is_null());
    assert!(msg.metadata["direction"].is_null());
    assert_eq!(msg.metadata["text"], "no flag");
}

#[test]
fn test_ios_timestamp_conversion() {
    // Core Data timestamp 695000000 + 978307200 = 1673307200
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let data = create_ios_whatsapp_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    let first = result.iter().find(|a| a.metadata["pk"] == 1).unwrap();
    let expected_unix = (695000000.0 + 978_307_200.0) as i64;
    assert_eq!(first.metadata["date"].as_i64().unwrap(), expected_unix);
    // This message landed exactly on a second, so there is no fraction to
    // publish and `date_ns` must not appear rather than repeat the seconds.
    assert!(first.metadata.get("date_ns").is_none());
}

/// An iOS ChatStorage holding two messages inside the *same* second, 250 ms and
/// 750 ms in. Only ZWAMESSAGE is needed: the parser confirms the variant on that
/// table alone.
fn create_ios_subsecond_whatsapp_db() -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_ios_subsec_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                Z_ENT INTEGER DEFAULT 0,
                ZCHATSESSION INTEGER,
                ZTEXT TEXT,
                ZMESSAGEDATE REAL,
                ZISFROMME INTEGER DEFAULT 0,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZSTARRED INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZTOJID TEXT,
                ZMEDIAITEM INTEGER
            );
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 1, 'first', 695000000.25, 0, 0, 0, '15551234567@s.whatsapp.net', NULL, NULL);
            INSERT INTO ZWAMESSAGE VALUES (2, 1, 1, 'the reply', 695000000.75, 1, 0, 0, NULL, '15551234567@s.whatsapp.net', NULL);"
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn ios_message_keeps_the_sub_second_that_orders_a_reply_after_its_message() {
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_ios_subsecond_whatsapp_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );

    let result = WhatsAppParser.process(&artifact).unwrap();
    let first = result.iter().find(|a| a.metadata["pk"] == 1).unwrap();
    let reply = result.iter().find(|a| a.metadata["pk"] == 2).unwrap();

    // Both messages sit on the same whole second: `date` alone cannot order
    // them, which is exactly what the truncating decode left behind.
    let base = 695_000_000 + 978_307_200;
    assert_eq!(first.metadata["date"].as_i64().unwrap(), base);
    assert_eq!(reply.metadata["date"].as_i64().unwrap(), base);

    // `date_ns` is the field `seance_db::chat_timeline_row` reads to fill
    // `timeline_events.timestamp_subsec_nanos`, so this is the fraction
    // reaching the unified timeline rather than stopping in the parser.
    let first_ns = first.metadata["date_ns"].as_i64().unwrap();
    let reply_ns = reply.metadata["date_ns"].as_i64().unwrap();
    assert_eq!(first_ns, base * 1_000_000_000 + 250_000_000);
    assert_eq!(reply_ns, base * 1_000_000_000 + 750_000_000);
    assert!(
        first_ns < reply_ns,
        "the reply must still sort after the message it answers"
    );
    // The whole-second part of `date_ns` has to agree with `date`, or the
    // timeline projection discards it as a disagreement between two fields.
    assert_eq!(first_ns.div_euclid(1_000_000_000), base);
}

#[test]
fn test_android_whatsapp_parsing() {
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let data = create_android_whatsapp_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let count = messages(&result).len();
    assert_eq!(count, 3, "Expected 3 messages, got {count}");

    // Check first received message
    let received = result
        .iter()
        .find(|a| a.metadata["id"] == 1)
        .expect("Should find id=1");
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["text"], "Hello from Android!");
    assert_eq!(received.metadata["platform"], "Android");

    // Check timestamp conversion (ms -> seconds)
    assert_eq!(received.metadata["date"].as_i64().unwrap(), 1672848000);
    assert_eq!(
        received.metadata["timestamp_ms"].as_i64().unwrap(),
        1672848000000
    );

    // Check sent message
    let sent = result
        .iter()
        .find(|a| a.metadata["id"] == 2)
        .expect("Should find id=2");
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    // Check group message
    let group = result
        .iter()
        .find(|a| a.metadata["id"] == 3)
        .expect("Should find id=3");
    assert_eq!(group.metadata["is_group"], true);
    assert_eq!(group.metadata["starred"], true);
}

#[test]
fn test_android_modern_msgstore_parsing() {
    // BUG-184/185: modern schema uses text_data/from_me/chat_row_id and resolves
    // the JID through chat.jid_row_id -> jid._id. Legacy-column queries return
    // zero messages here; probing must recover text, direction, and JID.
    let parser = WhatsAppParser;
    let data = create_android_modern_msgstore_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let messages: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsApp")
        .collect();
    assert_eq!(messages.len(), 3, "modern schema must yield all 3 messages");

    let received = result
        .iter()
        .find(|a| a.metadata["id"] == 1)
        .expect("Should find id=1");
    assert_eq!(received.metadata["text"], "Hi from modern schema");
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(
        received.metadata["remote_jid"], "15551234567@s.whatsapp.net",
        "JID must resolve through chat_row_id -> chat.jid_row_id -> jid"
    );
    assert_eq!(received.metadata["phone_number"], "15551234567");

    let sent = result.iter().find(|a| a.metadata["id"] == 2).unwrap();
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    let group = result.iter().find(|a| a.metadata["id"] == 3).unwrap();
    assert_eq!(group.metadata["is_group"], true);
    assert_eq!(group.metadata["chat_subject"], "Modern Group");
}

#[test]
fn test_android_group_sender_resolved_via_sender_jid_row_id() {
    // BUG-226: in a group chat the chat JID names the group, not the person who
    // sent a received message. `message.sender_jid_row_id` -> `jid._id` must be
    // joined so the actual sender is attributable.
    let parser = WhatsAppParser;
    let data = create_android_modern_msgstore_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();

    let group = result.iter().find(|a| a.metadata["id"] == 3).unwrap();
    assert_eq!(group.metadata["is_group"], true);
    assert_eq!(
        group.metadata["sender_jid"], "447700900999@s.whatsapp.net",
        "group sender must resolve through sender_jid_row_id"
    );
    assert_eq!(group.metadata["sender_phone"], "447700900999");
    // The thread key still names the group, not the sender.
    assert_eq!(group.metadata["remote_jid"], "120363001234@g.us");

    // A 1:1 message has no separate sender row; it must stay null, not
    // borrow the chat JID.
    let one_to_one = result.iter().find(|a| a.metadata["id"] == 1).unwrap();
    assert!(one_to_one.metadata["sender_jid"].is_null());
    assert!(one_to_one.metadata["sender_phone"].is_null());
}

#[test]
fn test_android_transitional_intfk_jid() {
    // BUG-185: key_remote_jid is an integer FK into jid._id, not a string that
    // matches jid.raw_string. The join must use the integer key so attribution
    // (JID / phone) is correct rather than "Unknown".
    let parser = WhatsAppParser;
    let data = create_android_transitional_intfk_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let msg = result
        .iter()
        .find(|a| a.metadata["id"] == 1)
        .expect("Should find id=1");
    assert_eq!(msg.metadata["text"], "transitional hi");
    assert_eq!(
        msg.metadata["remote_jid"], "447700900123@s.whatsapp.net",
        "integer key_remote_jid must join to jid._id"
    );
    assert_eq!(msg.metadata["phone_number"], "447700900123");
}

#[test]
fn test_android_media_message_url_fallback_keeps_rows() {
    // BUG-186: when message_media lacks message_row_id, the fallback must not
    // bind the string message_url column as an i64 rowid (which drops every
    // row). Attachments must still surface.
    let parser = WhatsAppParser;
    let data = create_android_media_no_rowid_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let media: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsAppAttachment")
        .collect();
    assert_eq!(
        media.len(),
        1,
        "media rows must not be dropped when message_row_id is absent"
    );
    assert_eq!(media[0].metadata["transfer_name"], "IMG-1.jpg");
    // No integer linkage column, so message_rowid is null rather than fabricated.
    assert!(media[0].metadata["message_rowid"].is_null());
}

#[test]
fn test_android_chat_without_subject_still_parses() {
    // BUG-184: every selected column must be probed. A `chat` table without
    // `subject` used to fail prepare(), turning the whole database into a
    // ParseFailed stub instead of losing only the group subject.
    let parser = WhatsAppParser;
    let data = create_android_chat_without_subject_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    assert!(
        result.iter().all(|a| a.metadata["status"] != "ParseFailed"),
        "a missing chat.subject must not fail the whole parse"
    );
    let msg = result
        .iter()
        .find(|a| a.metadata["type"] == "WhatsApp")
        .expect("message must be extracted");
    assert_eq!(msg.metadata["text"], "no subject column");
    assert_eq!(msg.metadata["remote_jid"], "15551112222@s.whatsapp.net");
    assert!(msg.metadata["chat_subject"].is_null());
}

#[test]
fn test_android_integer_jid_without_jid_table_keeps_messages() {
    // BUG-185: an integer key_remote_jid with no `jid` table cannot resolve to
    // a JID. Report it absent rather than selecting the integer into a String
    // (which fails decode on every row and drops the conversation) or passing
    // the row id off as a contact.
    let parser = WhatsAppParser;
    let data = create_android_intfk_without_jid_table_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "msgstore.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let msg = result
        .iter()
        .find(|a| a.metadata["type"] == "WhatsApp")
        .expect("message must survive an unresolvable JID");
    assert_eq!(msg.metadata["text"], "orphan jid");
    assert!(
        msg.metadata["remote_jid"].is_null(),
        "an unresolvable integer FK must not be reported as a JID"
    );
    assert!(msg.metadata["phone_number"].is_null());
}

#[test]
fn test_column_is_integer_uses_stored_type_when_undeclared() {
    // BUG-185: a column declared with no type has no affinity, so the declared
    // type says nothing. Fall back to the stored storage class.
    let dir = std::env::temp_dir().join(format!("wa_decltype_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("t.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE message (a, b, c INTEGER, d TEXT);
         INSERT INTO message VALUES (5, 'x@s.whatsapp.net', 1, 'y');",
    )
    .unwrap();

    let mut probe = SchemaProbe::new();
    assert!(column_is_integer(&mut probe, &conn, "message", "a"));
    assert!(!column_is_integer(&mut probe, &conn, "message", "b"));
    assert!(column_is_integer(&mut probe, &conn, "message", "c"));
    assert!(!column_is_integer(&mut probe, &conn, "message", "d"));
    assert!(!column_is_integer(&mut probe, &conn, "message", "missing"));
    assert!(!probe.undetermined(), "{:?}", probe.failures());

    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_coredata_secs_to_unix_conversion() {
    // iOS ZMESSAGEDATE is Core Data epoch: seconds since 2001-01-01.
    // 695000000 + 978307200 = 1673307200
    assert_eq!(
        Some(695000000.0).and_then(cocoa_secs_to_unix_nanos),
        Some((1673307200, 0))
    );
    // The column is REAL and the fraction is what orders two messages inside
    // one second, so it is decoded rather than truncated away.
    assert_eq!(
        Some(695000000.5).and_then(cocoa_secs_to_unix_nanos),
        Some((1673307200, 500_000_000))
    );
    // NULL and the 0 sentinel must stay absent, never a fabricated 2001/1970 date.
    assert_eq!(Some(0.0).and_then(cocoa_secs_to_unix_nanos), None);
    assert_eq!(None.and_then(cocoa_secs_to_unix_nanos), None);
}

#[test]
fn test_android_millis_to_unix_conversion() {
    // Android timestamps are milliseconds since the Unix epoch.
    assert_eq!(
        android_millis_to_unix(Some(1672848000000)),
        Some(1672848000)
    );
    // NULL and the 0 sentinel must stay absent, never a fabricated 1970 date.
    assert_eq!(android_millis_to_unix(Some(0)), None);
    assert_eq!(android_millis_to_unix(None), None);
}

#[test]
fn test_extract_phone_from_jid() {
    assert_eq!(
        extract_phone_from_jid("15551234567@s.whatsapp.net"),
        Some("15551234567".to_string())
    );
    assert_eq!(
        extract_phone_from_jid("120363001234@g.us"),
        Some("120363001234".to_string())
    );
    assert_eq!(extract_phone_from_jid(""), None);
    assert_eq!(extract_phone_from_jid("@s.whatsapp.net"), None);
}

#[test]
fn test_parent_id_chain() {
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let data = create_ios_whatsapp_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
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
    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let data = vec![0u8; 1024];
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    // Should produce a ParseFailed identification artifact
    assert!(result.len() <= 1);
}

#[test]
fn test_real_whatsapp_db() {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let db_path = crate_dir
        .parent()
        .unwrap()
        .join("test_data")
        .join("whatsapp_chat.db");

    if !db_path.exists() {
        eprintln!("Skipping test_real_whatsapp_db: {:?} not found", db_path);
        return;
    }

    let data = std::fs::read(&db_path).unwrap();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let parser = WhatsAppParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    assert!(
        !result.is_empty(),
        "Expected at least some records from real WhatsApp DB"
    );

    let messages: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();

    for msg in &messages {
        assert!(msg.metadata.get("date").is_some(), "Message missing date");
        assert!(
            msg.metadata.get("direction").is_some(),
            "Message missing direction"
        );
    }

    eprintln!("Parsed {} records from real WhatsApp DB", result.len());
}

/// Column probes now go through the shared [`SchemaProbe`], which lower-cases
/// every name and, unlike the old `table_columns` wrapper, retains the reason
/// when a probe cannot be answered. The convenient contract — case-insensitive
/// presence, `false` for an absent column or an absent table, and NOTHING
/// recorded when every probe was answered — must be unchanged, because
/// the field map builds SQL from it.
#[test]
fn has_column_is_case_insensitive_and_absence_safe() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, Key_Id TEXT, TIMESTAMP INTEGER);",
    )
    .unwrap();

    let mut probe = SchemaProbe::new();
    assert!(probe.has_column(&conn, "message", "key_id"));
    assert!(probe.has_column(&conn, "message", "KEY_ID"));
    assert!(probe.has_column(&conn, "message", "timestamp"));
    assert!(!probe.has_column(&conn, "message", "no_such_column"));
    // A table that does not exist probes as "no columns", never an error.
    assert!(!probe.has_column(&conn, "no_such_table", "key_id"));

    // The field map keeps the WhatsApp-specific sugar on top of that: the
    // first present candidate under the `m` alias, else NULL — and, unlike
    // the helpers it replaced, it records which logical field went to NULL.
    let fields = FieldMap::resolve(
        &probe.columns(&conn, "message"),
        &[
            ("key_id", &["key_id"][..]),
            ("starred", &["starred"][..]),
            ("text", &["text_data", "key_id"][..]),
            ("nope", &["nope"][..]),
        ],
    );
    assert_eq!(field_expr(&fields, "m", "key_id"), "m.key_id");
    assert_eq!(field_expr(&fields, "m", "starred"), "NULL");
    assert_eq!(field_expr(&fields, "m", "text"), "m.key_id");
    assert_eq!(field_expr(&fields, "m", "nope"), "NULL");
    assert_eq!(
        fields.unresolved(),
        &["starred".to_string(), "nope".to_string()]
    );

    // Every question above was ANSWERED, so the parse owes no marker: a probe
    // that flagged a healthy schema would make the marker meaningless.
    assert!(!probe.undetermined(), "{:?}", probe.failures());
}

/// Open a database built from `bytes` read-only, the way `process` does.
fn open_bytes(bytes: &[u8]) -> (TempDb, Connection) {
    let temp = TempDb::write(bytes, "whatsapp_test").unwrap();
    let conn = temp.open().unwrap();
    (temp, conn)
}

/// The message walks are `ORDER BY … DESC LIMIT n`: at the cap they drop the
/// OLDEST messages, and a bare `LIMIT` cannot tell "the chat held exactly n"
/// from "we stopped reading". Same defect class as the iMessage caps
/// (bugs2 B2-126).
#[test]
fn a_capped_ios_message_walk_says_it_stopped_early() {
    let (_temp, conn) = open_bytes(&create_ios_whatsapp_db());

    let capped = parse_ios_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    let messages: Vec<&Artifact> = capped
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .collect();
    assert_eq!(messages.len(), 2, "the cap must still be enforced");

    let marker = capped
        .iter()
        .find(|a| a.metadata["status"] == "CapReached")
        .expect("a capped walk must emit an incompleteness marker");
    assert_eq!(marker.metadata["source_table"], "ZWAMESSAGE");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["content_incomplete_reason"], "cap_reached");

    // The database holds 4 messages; a budget of 4 read all of them, so nothing
    // may claim truncation.
    let whole = parse_ios_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 4).unwrap();
    assert!(
        !whole.iter().any(|a| a.metadata["status"] == "CapReached"),
        "a walk that read every row must not claim it stopped early"
    );
}

#[test]
fn a_capped_android_message_walk_says_it_stopped_early() {
    let (_temp, conn) = open_bytes(&create_android_whatsapp_db());

    let capped = parse_android_messages_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    let marker = capped
        .iter()
        .find(|a| a.metadata["status"] == "CapReached")
        .expect("a capped Android walk must emit an incompleteness marker");
    // Named after the records it qualifies, never `"WhatsApp"` itself: the
    // conversation aggregation in `seance_db` groups ParsedRecords by
    // `metadata.$.type`, and a marker carrying the message type would be filed
    // as a message and invent a one-message conversation.
    assert_eq!(marker.metadata["type"], "WhatsAppIncomplete");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(marker.metadata["max_entries"], 1);
    assert_eq!(marker.metadata["rows_read"], 1);
}

/// B2-123: a msgstore the spill could not stage in full still opens, and every
/// row it can reach is returned as though the recovery were complete.
#[test]
fn a_short_read_msgstore_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(create_ios_whatsapp_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = WhatsAppParser.process(&artifact).unwrap();

    let message = result
        .iter()
        .find(|a| a.metadata["subtype"] == "chat_message")
        .expect("the readable prefix still parses");
    assert_eq!(
        message.metadata["content_incomplete"], true,
        "a message pulled out of a partial database must carry that fact"
    );
    assert_eq!(message.metadata["content_incomplete_reason"], "short_read");
    assert!(
        result
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: a database read whole stays unmarked, so a marker means
/// something when it is there.
#[test]
fn a_complete_msgstore_carries_no_incompleteness_marks() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_whatsapp_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = WhatsAppParser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

/// B3-023: a message row the walk fetched but could not decode used to vanish
/// into a `debug!` line. What an examiner learns from the marker: the message
/// count is a floor, not a total. A wrong answer looks like "1 WhatsApp message"
/// for a msgstore that holds two, one of them corrupt.
#[test]
fn undecodable_android_message_rows_are_tallied_not_silently_dropped() {
    let temp_path = std::env::temp_dir().join(format!("test_wa_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        // `_id` declared INTEGER: INTEGER affinity keeps `1` an integer and
        // stores the non-numeric `'corrupt'` as TEXT, so exactly one of the two
        // rows makes `row.get::<i64>` fail, as a corrupt page would. A
        // TEXT-affinity column would convert BOTH values to text and drop the
        // whole table, which would not test the tally at all.
        conn.execute_batch(
            "CREATE TABLE messages (
                _id INTEGER,
                key_remote_jid TEXT,
                key_from_me INTEGER,
                data TEXT,
                timestamp INTEGER,
                media_wa_type INTEGER,
                media_size INTEGER
            );
            INSERT INTO messages VALUES (1, '15551234567@s.whatsapp.net', 0, 'readable', 1673307200000, 0, 0);
            INSERT INTO messages VALUES ('corrupt', '15551234567@s.whatsapp.net', 0, 'unreachable', 1673307260000, 0, 0);",
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
        json!({"name": "msgstore.db"}),
    );
    let result = WhatsAppParser.process(&artifact).unwrap();

    let messages = result
        .iter()
        .filter(|a| a.metadata["subtype"] == "chat_message")
        .count();
    assert_eq!(messages, 1, "only the decodable row yields a message");

    let marker = result
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a dropped row must produce an incompleteness marker");
    assert_eq!(marker.metadata["type"], "WhatsAppIncomplete");
    assert_eq!(marker.metadata["source_table"], "messages");
    assert_eq!(marker.metadata["rows_dropped"], 1);
    assert_eq!(marker.metadata["records_recovered"], 1);
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(marker.metadata["inventory_incomplete"], true);
}

/// B3-023 control: a msgstore whose rows all decode must carry no dropped-row
/// marker, or the marker means nothing.
#[test]
fn a_fully_decodable_whatsapp_database_has_no_dropped_row_marker() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_whatsapp_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "ChatStorage.sqlite"}),
    );
    let result = WhatsAppParser.process(&artifact).unwrap();
    assert!(!result
        .iter()
        .any(|a| a.metadata["status"] == "RowsUndecodable"));
}

/// An Android `message_media` table whose every row is undecodable.
///
/// `file_path` is read as a non-null `String`; an INTEGER stored there survives
/// the `IS NOT NULL` filter and fails the decode, which is exactly the shape a
/// partially recovered page produces.
fn create_android_media_all_undecodable_db(with_legacy_message_media: bool) -> Vec<u8> {
    let temp_path =
        std::env::temp_dir().join(format!("test_whatsapp_media_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message_media (message_row_id INTEGER, file_path, file_size INTEGER);
             INSERT INTO message_media VALUES (1, 4242, 45678);",
        )
        .unwrap();
        if with_legacy_message_media {
            conn.execute_batch(
                "CREATE TABLE message (_id INTEGER PRIMARY KEY, media_name TEXT, media_size INTEGER);
                 INSERT INTO message VALUES (1, 'IMG-legacy.jpg', 900);",
            )
            .unwrap();
        }
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// B3-023, the emptiness hole: the `message_media` marker used to be emitted
/// only inside `if !out.is_empty()`. A media table whose rows all failed to
/// decode therefore produced NOTHING — no records and no marker — and the walk
/// fell through to the legacy schema with a fresh counter. The attachments the
/// device held vanished, and "no media" is what the examiner read for a phone
/// whose media inventory was unreadable.
///
/// Against the unfixed code this returns an empty vector, so the length assert
/// fails.
#[test]
fn an_all_undecodable_media_table_still_declares_what_it_lost() {
    let (_temp, conn) = open_bytes(&create_android_media_all_undecodable_db(false));
    let out = parse_android_media(&conn, Uuid::new_v4(), Uuid::new_v4());

    assert_eq!(
        out.len(),
        1,
        "an unreadable media table must not report as an empty one: {out:?}"
    );
    assert_eq!(out[0].metadata["type"], "WhatsAppMediaIncomplete");
    assert_eq!(out[0].metadata["subtype"], "parse_incomplete");
    assert_eq!(out[0].metadata["status"], "RowsUndecodable");
    assert_eq!(out[0].metadata["source_table"], "message_media");
    assert_eq!(out[0].metadata["rows_dropped"], json!(1));
    assert_eq!(out[0].metadata["records_recovered"], json!(0));
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(out[0].metadata["inventory_incomplete"], json!(true));
    assert!(
        out[0].metadata["first_error"].is_string(),
        "the decoder's reason must reach the artifact, not just the log"
    );
}

/// The same table, with the legacy schema also present so the walk falls
/// through to it. The legacy records must be returned AND the modern table's
/// loss must still be declared — and the legacy walk's `records_recovered`
/// must count media records only, never the carried marker.
#[test]
fn a_fallthrough_to_the_legacy_media_schema_keeps_the_modern_table_s_marker() {
    let (_temp, conn) = open_bytes(&create_android_media_all_undecodable_db(true));
    let out = parse_android_media(&conn, Uuid::new_v4(), Uuid::new_v4());

    let media: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["status"] != json!("RowsUndecodable"))
        .collect();
    assert_eq!(media.len(), 1, "the legacy row is still recovered: {out:?}");

    let marker = out
        .iter()
        .find(|a| a.metadata["status"] == json!("RowsUndecodable"))
        .expect("the modern table's undecodable rows must still be declared");
    assert_eq!(marker.metadata["source_table"], "message_media");
    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(
        marker.metadata["records_recovered"],
        json!(0),
        "the marker counts the walk it came from, not the legacy fallback"
    );
}

// --- B8-015 / B8-023: a probe that fails closed into a positive claim ---

/// Damage page 1's b-tree without touching the file header, so the database
/// OPENS and then answers every catalogue query with `SQLITE_CORRUPT`.
///
/// This is the normal forensic case the finding is about: a carved or partially
/// recovered `msgstore.db` / `ChatStorage.sqlite`. `TempDb::spill` cannot mark
/// it — the bytes were all staged — so nothing but the probes can tell the
/// examiner that the store was unreadable rather than empty.
///
/// Bytes 103..105 are page 1's b-tree cell count. SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6` (681 for the default 4096-byte
/// page), so 0xFFFF is corrupt for every page size it supports.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

fn process_named(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    WhatsAppParser.process(&artifact).unwrap()
}

/// B8-015. The schema probes ended in `.unwrap_or(false)`, so `SQLITE_CORRUPT`
/// on the `sqlite_master` read was indistinguishable from "the table is not
/// there". Both probes then answered false, the parser logged "no recognizable
/// WhatsApp schema, skipping" and returned `Ok(Vec::new())` — and an empty
/// artifact list for a `msgstore.db` renders exactly like a phone that never had
/// WhatsApp installed. Refusing to answer is right; answering "there was nothing
/// there" is a fabricated finding.
///
/// Against the unfixed code this returns an empty vector and every assert below
/// fails.
#[test]
fn a_corrupt_msgstore_is_not_reported_as_a_phone_without_whatsapp() {
    let out = process_named(
        corrupt_the_catalogue(create_android_whatsapp_db()),
        "msgstore.db",
    );

    assert!(
        !out.is_empty(),
        "an unreadable WhatsApp store must never render as one that held no messages"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("WhatsAppIncomplete"));
    assert_ne!(
        marker.metadata["type"],
        json!("WhatsApp"),
        "a marker filed under the message type becomes a phantom conversation"
    );
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["records_recovered"], json!(0));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    // The sentence must reach the keys the examiner-facing reader shows.
    assert_eq!(
        marker.metadata["content_incomplete_detail"],
        marker.metadata["detail"]
    );
    assert!(marker.metadata["detail"]
        .as_str()
        .expect("a detail sentence")
        .contains("undetermined"));
    // No chat records were invented to go with it.
    assert!(!out
        .iter()
        .any(|a| a.metadata["subtype"] == json!("chat_message")));
}

/// The iOS store has the same defect and needs the same answer.
#[test]
fn a_corrupt_chatstorage_is_not_reported_as_a_phone_without_whatsapp() {
    let out = process_named(
        corrupt_the_catalogue(create_ios_whatsapp_db()),
        "ChatStorage.sqlite",
    );
    assert!(!out.is_empty());
    let marker = out
        .iter()
        .find(|a| a.metadata["status"] == json!("StoreUnreadable"))
        .expect("an unreadable ChatStorage.sqlite must be declared");
    assert_eq!(marker.metadata["type"], json!("WhatsAppIncomplete"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
}

/// The control that gives the marker its meaning: a readable SQLite database
/// that genuinely is not WhatsApp's must still produce silence. If "not there"
/// and "could not find out" both produced a marker, the marker would say
/// nothing.
#[test]
fn a_readable_database_that_is_not_whatsapp_still_produces_nothing() {
    let temp_path = std::env::temp_dir().join(format!("test_wa_notours_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (a INTEGER); INSERT INTO unrelated VALUES (1);")
            .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let out = process_named(bytes, "msgstore.db");
    assert!(
        out.is_empty(),
        "a database whose catalogue ANSWERED, and answered `not WhatsApp`, is a finding: {out:?}"
    );
}

/// B8-023. The column probes fed `NULL` into the SELECT whenever
/// `PRAGMA table_info` failed, so a store whose column list would not read still
/// ran its query — with the text, the direction, or the JID join silently
/// replaced by `NULL` — and presented the result as a complete parse. The
/// convenient `false` is unchanged; what is new is that the parse can no longer
/// end without declaring it.
#[test]
fn whatsapp_column_probes_record_what_they_could_not_determine() {
    let temp = TempDb::write(
        &corrupt_the_catalogue(create_android_whatsapp_db()),
        "wa_probe",
    )
    .unwrap();
    let conn = temp
        .open()
        .expect("a damaged page 1 still OPENS; it fails on first read");

    let mut probe = SchemaProbe::new();
    // Same conservative answers the old `.unwrap_or(false)` produced …
    let cols = probe.columns(&conn, "message");
    assert!(cols.is_empty());
    let fields = FieldMap::resolve(&cols, ANDROID_MESSAGE_FIELDS);
    assert_eq!(field_expr(&fields, "m", "key_id"), "NULL");
    assert_eq!(field_expr(&fields, "m", "text"), "NULL");
    assert!(!column_is_integer(
        &mut probe,
        &conn,
        "message",
        "key_remote_jid"
    ));
    assert!(!probe.has_table(&conn, "message_media"));

    // … and now the reason is retained instead of being spent as a finding.
    assert!(
        probe.undetermined(),
        "a column list that would not read must not pass as an absent column"
    );
    let marker = probe
        .marker(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "WhatsAppIncomplete",
            "message",
            3,
        )
        .expect("an undetermined probe owes the examiner a marker");
    assert_eq!(marker.metadata["status"], json!("SchemaUndetermined"));
    assert_eq!(marker.metadata["records_recovered"], json!(3));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert!(marker.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("lower bound"));
}

/// The same control one level down: on a healthy msgstore every probe is
/// answered, so a full parse must carry no schema marker at all.
#[test]
fn a_healthy_msgstore_parse_carries_no_schema_marker() {
    let out = process_named(create_android_whatsapp_db(), "msgstore.db");
    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == json!("SchemaUndetermined")),
        "a schema marker on a readable database would make the marker meaningless: {out:?}"
    );
    assert!(out
        .iter()
        .any(|a| a.metadata["subtype"] == json!("chat_message")));
}

/// The opposite error to B8-015, and the one the catalogue check introduced if
/// left ungated: refusing to answer is right, but so is refusing to ASSERT.
///
/// The filename gate opens anything whose name contains "whatsapp", and a real
/// Android or iOS extraction is full of `whatsapp.log`, `com.whatsapp.apk` and
/// `com.whatsapp_preferences.xml`. Failing the catalogue read on one of those
/// must stay silent, exactly as it did before: emitting a "WhatsApp Database
/// (parse failed)" record files a positive claim — under `type: "WhatsApp"`,
/// which is the key the record-type census groups on — about a file this tool
/// never had reason to think was a store.
#[test]
fn a_file_that_merely_mentions_whatsapp_is_not_claimed_as_a_failed_database() {
    for name in [
        "whatsapp.log",
        "com.whatsapp.apk",
        "com.whatsapp_preferences.xml",
    ] {
        let out = process_named(b"not a database, just a file".to_vec(), name);
        assert!(
            out.is_empty(),
            "{name} is not a chat store and must not be reported as one: {out:?}"
        );
    }
}

/// The control that keeps that silence from swallowing the real case: a file
/// NAMED for a WhatsApp store, which is not a database, still gets the
/// identification record it always had.
#[test]
fn a_store_named_file_that_is_not_a_database_is_still_identified() {
    let out = process_named(vec![0u8; 1024], "msgstore.db");
    assert_eq!(out.len(), 1, "{out:?}");
    let md = &out[0].metadata;
    assert_eq!(md["status"], json!("ParseFailed"));
    // The record is a statement ABOUT the store, never one of its messages.
    // `conversation_summaries` selects ParsedRecords on `metadata.$.type` with
    // no subtype filter and its thread key COALESCEs to the literal `'unknown'`,
    // so a failure typed `"WhatsApp"` is counted as a message in a conversation
    // the custodian never had.
    assert_eq!(md["type"], json!("WhatsAppIncomplete"));
    assert_ne!(
        md["type"],
        json!("WhatsApp"),
        "a parse failure filed under the message type invents a conversation"
    );
    // And it is visible to the completeness census and the court report, which
    // key on the standard pair: without it a msgstore that would not parse
    // reports as a database that simply held no messages.
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(
        md["content_incomplete_reason"],
        json!("unresolved_structure")
    );
    assert_eq!(md["inventory_incomplete"], json!(true));
    assert_eq!(
        md["inventory_incomplete_reason"],
        json!("unresolved_structure")
    );
    // The sentence lands on the key the examiner-facing reader shows.
    assert!(md["content_incomplete_detail"]
        .as_str()
        .is_some_and(|s| s.contains("msgstore.db")));
}

/// HUNT-070. On the Android 14 reference image the app directory
/// `com.whatsapp`, the media folders (`WhatsApp Images`, `WhatsApp Video`,
/// …) and eleven more names that merely mention the app each produced a
/// record reading "WhatsApp (iOS) Database (not parsed - no data)" — twenty-six
/// iOS databases asserted on a device that has never run iOS, beside the real
/// `msgstore.db` that parsed. A name that only mentions the app is a reason
/// to *open* a file, never to declare a database; and a directory has no
/// bytes to open. Only a name that identifies a store on its own (`msgstore.db`,
/// `ChatStorage.sqlite`) and cannot be read is worth a record.
#[test]
fn a_directory_that_merely_mentions_whatsapp_is_not_declared_an_ios_database() {
    for name in [
        "com.whatsapp",
        "WhatsApp Images",
        "WhatsApp Video Notes",
        "Whatsapp",
    ] {
        let dir = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({ "name": name, "is_directory": true }),
        );
        let out = WhatsAppParser.process(&dir).unwrap();
        assert!(
            out.is_empty(),
            "{name:?} is a mention, not a store: {:?}",
            out.first().map(|a| a.metadata["name"].clone())
        );
    }

    // A store's own name with no bytes behind it is still worth declaring —
    // and it is declared by the variant its name gives, not as iOS by default.
    let store = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        serde_json::json!({ "name": "msgstore.db" }),
    );
    let out = WhatsAppParser.process(&store).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["platform"], "Android");
    assert!(out[0].metadata["name"]
        .as_str()
        .unwrap()
        .starts_with("WhatsApp (Android)"));
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

fn db_from(batch: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_whatsapp_schema_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(batch).unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

fn injected(app: &'static str) -> SchemaSupport {
    SchemaSupport {
        app,
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a WhatsApp build",
        },
    }
}

/// A msgstore whose `PRAGMA user_version` is beyond the range a parser was
/// validated against must say so — and must still parse what it can. The
/// crate's own declaration is Unranged (no real msgstore.db is held), so the
/// Validated bound here is injected; the range is a test value and asserts
/// nothing about any WhatsApp build.
#[test]
fn an_android_schema_version_beyond_the_validated_range_is_declared_and_still_parsed() {
    let mut bytes = create_android_whatsapp_db();
    // Stamp the version through SQLite, not the header: the fixture is a
    // finished file, so re-open it and set the pragma.
    {
        let temp = TempDb::write(&bytes, "whatsapp_uv").unwrap();
        let conn = Connection::open(temp.path()).unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
        drop(conn);
        bytes = std::fs::read(temp.path()).unwrap();
    }
    let (_temp, conn) = open_bytes(&bytes);
    let out = parse_android_messages_with(
        &conn,
        Uuid::new_v4(),
        Uuid::new_v4(),
        MAX_MESSAGE_ENTRIES,
        &injected("whatsapp-android"),
    )
    .unwrap();

    assert_eq!(messages(&out).len(), 3, "the messages are still recovered");
    let stale = schema_records(&out);
    assert_eq!(stale.len(), 1, "{out:?}");
    let m = &stale[0].metadata;
    assert_eq!(m["type"], json!(INCOMPLETE_TYPE));
    assert_eq!(m["subtype"], json!("parser_stale"));
    assert_eq!(m["status"], json!("SchemaOutsideValidated"));
    assert_eq!(m["schema_version_seen"], json!(99));
    assert_eq!(m["schema_version_supported"], json!("1..=3"));
    assert_eq!(m["source_table"], json!("message"));
    assert!(m["message"].as_str().unwrap().contains("NEWER"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A renamed text column on the modern `message` table used to be
/// substituted as `NULL` and the conversation emitted as one that "had no
/// text" — a complete-looking parse with every body missing. The FieldMap
/// records the substitution, so the schema record names the field.
#[test]
fn a_renamed_android_text_column_yields_a_marker_naming_the_unresolved_field() {
    let db = db_from(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, message_body TEXT, timestamp INTEGER);
         INSERT INTO message VALUES (1, '15551234567@s.whatsapp.net', 1, 'unreachable', 1672848000000);",
    );
    let out = process_named(db, "msgstore.db");

    let marker = schema_records(&out);
    assert_eq!(marker.len(), 1, "{out:?}");
    let m = &marker[0].metadata;
    assert_eq!(m["type"], json!(INCOMPLETE_TYPE));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("text"));
    // The rest of the row survives: the timeline and the direction are read.
    let msgs = messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["date"], json!(1672848000));
    assert_eq!(msgs[0].metadata["direction"], json!("sent"));
    assert_eq!(
        msgs[0].metadata["remote_jid"],
        json!("15551234567@s.whatsapp.net")
    );
    assert!(msgs[0].metadata["text"].is_null());
    assert_eq!(m["records_recovered"], json!(1));
}

/// The same defect on the iOS store used to be worse: `ZTEXT` was named in a
/// fixed query, so a renamed column failed `prepare()` and the WHOLE database
/// became a "parse failed" stub. Now the fields that resolve are read and the
/// one that did not is named.
#[test]
fn a_renamed_ios_text_column_yields_a_marker_and_the_other_fields_are_still_read() {
    let db = db_from(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZCHATSESSION INTEGER, ZBODY TEXT, ZMESSAGEDATE REAL, ZISFROMME INTEGER, ZFROMJID TEXT, ZTOJID TEXT);
         INSERT INTO ZWAMESSAGE VALUES (1, 1, 'unreachable', 695000000.0, 0, '15551234567@s.whatsapp.net', NULL);",
    );
    let out = process_named(db, "ChatStorage.sqlite");

    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == json!("ParseFailed")),
        "a renamed column is not a store that would not parse: {out:?}"
    );
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["type"], json!(INCOMPLETE_TYPE));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["source_table"], json!("ZWAMESSAGE"));
    assert_eq!(m["content_incomplete"], json!(true));
    let msgs = messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["direction"], json!("received"));
    assert_eq!(
        msgs[0].metadata["remote_jid"],
        json!("15551234567@s.whatsapp.net")
    );
    assert!(msgs[0].metadata["text"].is_null());
}

/// No real msgstore.db is held by this project, so the Android declaration is
/// Unranged: the record says so, reports the version the store carries, and
/// carries NO range — a `1..=N` here would be a claim about databases this
/// project has never opened.
#[test]
fn a_parser_with_no_reference_database_declares_that_rather_than_a_range() {
    let db = db_from(
        "PRAGMA user_version = 7;
         CREATE TABLE message (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, data TEXT, timestamp INTEGER);
         INSERT INTO message VALUES (1, '15551234567@s.whatsapp.net', 1, 'x', 1672848000000);",
    );
    let out = process_named(db, "msgstore.db");
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["type"], json!(INCOMPLETE_TYPE));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["app"], json!("whatsapp-android"));
    assert_eq!(m["schema_version_seen"], json!(7));
    assert_eq!(m["schema_version_locator"], json!("user_version"));
    assert!(m.get("schema_version_supported").is_none(), "{m}");
    assert!(m.get("supported_range").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("cannot detect drift"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert_eq!(messages(&out).len(), 1);
}

/// The iOS store is Core Data: its model version is in `Z_METADATA`, which
/// this build does not read, and `PRAGMA user_version` is NOT that version —
/// it reads 0 on every Core Data store this project has opened. So the iOS
/// record reports neither a version nor "no version recorded".
#[test]
fn the_ios_store_reports_its_version_as_not_read_rather_than_as_zero() {
    let out = process_named(create_ios_whatsapp_db(), "ChatStorage.sqlite");
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["app"], json!("whatsapp-ios"));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_locator"], json!("coredata_model"));
    assert!(m.get("schema_version_seen").is_none(), "{m}");
    assert!(m.get("schema_version_recorded").is_none(), "{m}");
    assert!(m["schema_version_detail"]
        .as_str()
        .unwrap()
        .contains("Z_METADATA"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// `PRAGMA user_version` reads 0 on a msgstore that never set it — SQLite's
/// default. That is the absence of a version, never "version 0".
#[test]
fn a_user_version_of_zero_is_the_absence_of_a_version_not_a_version_of_zero() {
    let out = process_named(create_android_whatsapp_db(), "msgstore.db");
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_recorded"], json!(false));
    assert!(m.get("schema_version_seen").is_none(), "{m}");

    let (_temp, conn) = open_bytes(&create_android_whatsapp_db());
    let out = parse_android_messages_with(
        &conn,
        Uuid::new_v4(),
        Uuid::new_v4(),
        MAX_MESSAGE_ENTRIES,
        &injected("whatsapp-android"),
    )
    .unwrap();
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaVersionNotRecorded"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A version the store would not answer is never spent as "in range".
#[test]
fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
    let fields = FieldMap::resolve(
        &[
            "text_data".to_string(),
            "timestamp".to_string(),
            "from_me".to_string(),
        ]
        .into_iter()
        .collect(),
        ANDROID_MESSAGE_FIELDS,
    );
    let rec = SchemaCheck {
        support: &injected("whatsapp-android"),
        version: SchemaVersion::Undetermined("PRAGMA user_version would not read".into()),
        fields: &fields,
        required: ANDROID_REQUIRED_FIELDS,
        record_type: INCOMPLETE_TYPE,
        store: "message",
    }
    .marker(Uuid::new_v4(), Uuid::new_v4(), 3)
    .expect("an unanswered version is a record, not silence");
    assert_eq!(rec.metadata["status"], json!("SchemaVersionUndetermined"));
    assert!(rec.metadata.get("schema_version_seen").is_none());
}

/// The legacy `messages` table is read through the same map, so a renamed
/// column there is named too instead of failing `prepare()` for the whole store.
#[test]
fn a_renamed_legacy_messages_column_is_named_rather_than_failing_the_store() {
    let db = db_from(
        "CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, body TEXT, timestamp INTEGER);
         INSERT INTO messages VALUES (1, '15551234567@s.whatsapp.net', 0, 'unreachable', 1672848000000);",
    );
    let out = process_named(db, "msgstore.db");
    assert!(!out
        .iter()
        .any(|a| a.metadata["status"] == json!("ParseFailed")));
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["source_table"], json!("messages"));
    assert_eq!(messages(&out).len(), 1);
}

/// The real Hickman Android 14 (Pixel 7a, WhatsApp 2.24.14.81) live store:
/// every logical field of the modern `message` table resolves and the 230
/// messages it holds are all read. Skips when absent; fails when absent and
/// `SEANCE_APP_SCHEMA_CORPUS_REQUIRED` is set. `SEANCE_ANDROID14_WHATSAPP`
/// names the directory holding `msgstore.db` (`~/forensic_corpora/
/// hickman_android14/whatsapp`).
#[test]
fn the_real_android14_msgstore_resolves_every_field() {
    let dir = std::env::var_os("SEANCE_ANDROID14_WHATSAPP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../test_data/whatsapp_android14")
        });
    let path = dir.join("msgstore.db");
    if !path.exists() {
        assert!(
            std::env::var_os("SEANCE_APP_SCHEMA_CORPUS_REQUIRED").is_none(),
            "{} not found and SEANCE_APP_SCHEMA_CORPUS_REQUIRED is set",
            path.display()
        );
        eprintln!("skipping {}: not found", path.display());
        return;
    }
    let bytes = std::fs::read(&path).unwrap();
    let (_temp, conn) = open_bytes(&bytes);
    let out = parse_android_messages(&conn, Uuid::new_v4(), Uuid::new_v4()).unwrap();
    assert_eq!(messages(&out).len(), 230);
    // Unranged declares itself, but no field may be unresolved on a real store.
    for a in schema_records(&out) {
        assert_ne!(
            a.metadata["status"],
            json!("SchemaFieldsUnresolved"),
            "{}",
            a.metadata
        );
    }
}

#[test]
fn the_declared_schema_support_is_unranged_with_its_reason() {
    assert!(matches!(
        ANDROID_SCHEMA_SUPPORT.bound,
        SchemaBound::Unranged { .. }
    ));
    assert!(matches!(
        IOS_SCHEMA_SUPPORT.bound,
        SchemaBound::Unranged { .. }
    ));
    for (required, fields) in [
        (ANDROID_REQUIRED_FIELDS, ANDROID_MESSAGE_FIELDS),
        (LEGACY_REQUIRED_FIELDS, LEGACY_MESSAGE_FIELDS),
        (IOS_REQUIRED_FIELDS, IOS_MESSAGE_FIELDS),
    ] {
        assert!(required.iter().all(|r| fields.iter().any(|(l, _)| l == r)));
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
        json!({ "name": "msgstore.db", "is_directory": true }),
    );
    let out = WhatsAppParser.process(&artifact).unwrap();
    assert!(out.is_empty(), "a directory is not a msgstore.db: {out:?}");
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
    let ds: Arc<dyn DataSource> =
        Arc::new(TruncatedSource::cut_to(create_android_whatsapp_db(), 4));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "msgstore.db" }),
    );
    let out = WhatsAppParser.process(&artifact).unwrap();
    // What may be said is that the read was short — the stager's own record —
    // and nothing about what the file is.
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].metadata["type"], "SqliteSpillIncomplete", "{out:?}");
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["records_recovered"], 0);
}
