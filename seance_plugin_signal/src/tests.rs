use super::*;
use seance_core::test_support::TruncatedSource;

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

use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use seance_core::data_source::DataSource;
use seance_sqlite_util::SupportedRange;
use serde_json::json;
use std::sync::Arc;

type TestCtr = ctr::Ctr128BE<aes::Aes256>;
type TestHmac = hmac::Hmac<sha2::Sha256>;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A synthetic decrypted Signal database (modern unified `message` schema).
fn create_signal_db() -> Vec<u8> {
    let temp = std::env::temp_dir().join(format!("test_signal_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, system_joined_name TEXT,
                 profile_joined_name TEXT, group_id TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, date INTEGER);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, from_recipient_id INTEGER,
                 to_recipient_id INTEGER, body TEXT, date_sent INTEGER, date_received INTEGER,
                 type INTEGER, read INTEGER);
             CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER);

             INSERT INTO recipient VALUES (1, '+15550000001', 'Me Owner', NULL, NULL);
             INSERT INTO recipient VALUES (2, '+15551234567', 'Alice Example', NULL, NULL);
             INSERT INTO thread VALUES (10, 2, 1600000200000);

             -- type 20 = inbox (received), 23 = sent
             INSERT INTO message VALUES (100, 10, 2, 1, 'Incoming hi', 1600000000000, 1600000001000, 20, 1);
             INSERT INTO message VALUES (101, 10, 1, 2, 'Sent reply', 1600000100000, 1600000100000, 23, 1);

             INSERT INTO attachment VALUES (1, 100);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    data
}

/// A SQLite DB that is not a Signal store (no `recipient` table).
fn create_non_signal_db() -> Vec<u8> {
    let temp = std::env::temp_dir().join(format!("test_nonsignal_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE foo (id INTEGER PRIMARY KEY, bar TEXT); INSERT INTO foo VALUES (1,'x');",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    data
}

fn signal_messages(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "Signal")
        .collect()
}

// ---------------------------------------------------------------------------
// Minimal protobuf writer (test-only) + a mirror of FullBackupExporter.
// ---------------------------------------------------------------------------

fn pbw_varint(mut v: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            o.push(b | 0x80);
        } else {
            o.push(b);
            break;
        }
    }
    o
}
fn pbw_key(field: u32, wire: u8) -> Vec<u8> {
    pbw_varint(((field as u64) << 3) | wire as u64)
}
fn pbw_bytes(field: u32, data: &[u8]) -> Vec<u8> {
    let mut o = pbw_key(field, 2);
    o.extend(pbw_varint(data.len() as u64));
    o.extend_from_slice(data);
    o
}
fn pbw_varint_field(field: u32, v: u64) -> Vec<u8> {
    let mut o = pbw_key(field, 0);
    o.extend(pbw_varint(v));
    o
}
fn pbw_string(field: u32, s: &str) -> Vec<u8> {
    pbw_bytes(field, s.as_bytes())
}

/// Build a `BackupFrame{ statement: SqlStatement{ statement, parameters } }`.
fn make_statement_frame(sql: &str, params: &[SqlParam]) -> Vec<u8> {
    let mut stmt = pbw_string(1, sql);
    for p in params {
        let inner = match p {
            SqlParam::Str(s) => pbw_string(1, s),
            SqlParam::Int(i) => pbw_varint_field(2, *i as u64),
            SqlParam::Double(d) => {
                let mut o = pbw_key(3, 1);
                o.extend_from_slice(&d.to_le_bytes());
                o
            }
            SqlParam::Blob(b) => pbw_bytes(4, b),
            SqlParam::Null => pbw_varint_field(5, 1),
        };
        stmt.extend(pbw_bytes(2, &inner));
    }
    pbw_bytes(2, &stmt)
}

/// Build a `BackupFrame{ attachment: Attachment{ rowId, attachmentId, length } }`.
fn make_attachment_frame(row_id: u64, attachment_id: u64, length: u64) -> Vec<u8> {
    let mut a = pbw_varint_field(1, row_id);
    a.extend(pbw_varint_field(2, attachment_id));
    a.extend(pbw_varint_field(3, length));
    pbw_bytes(4, &a)
}

fn make_end_frame() -> Vec<u8> {
    pbw_varint_field(6, 1)
}

/// A faithful mirror of Signal-Android's `FullBackupExporter` write path, used
/// only to construct a valid backup for the decryption round-trip test.
struct BackupWriter {
    out: Vec<u8>,
    iv: [u8; 16],
    counter: u32,
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
}

impl BackupWriter {
    fn new(passphrase: &str, salt: &[u8], iv: [u8; 16]) -> Self {
        let backup_key = super::derive_backup_key(passphrase, salt);
        let (cipher_key, mac_key) = super::derive_backup_subkeys(&backup_key);

        // Header frame (plaintext, length-prefixed).
        let mut hdr = pbw_bytes(1, &iv);
        hdr.extend(pbw_bytes(2, salt));
        let header_frame = pbw_bytes(1, &hdr); // BackupFrame field 1 = header
        let mut out = Vec::new();
        out.extend_from_slice(&(header_frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_frame);

        let counter = u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]);
        Self {
            out,
            iv,
            counter,
            cipher_key,
            mac_key,
        }
    }

    fn write_frame(&mut self, frame: &[u8]) {
        self.iv[..4].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let mut ct = frame.to_vec();
        let mut cipher = TestCtr::new_from_slices(&self.cipher_key, &self.iv).unwrap();
        cipher.apply_keystream(&mut ct);
        let mut mac = TestHmac::new_from_slice(&self.mac_key).unwrap();
        mac.update(&ct);
        let full = mac.finalize().into_bytes();
        let mut body = ct;
        body.extend_from_slice(&full[..10]);
        self.out
            .extend_from_slice(&(body.len() as u32).to_be_bytes());
        self.out.extend_from_slice(&body);
    }

    /// Attachment blob: `length` ciphertext bytes + 10-byte HMAC (iv-prefixed),
    /// no length prefix. Advances the counter once, like `readAttachmentTo`.
    fn write_blob(&mut self, blob: &[u8]) {
        self.iv[..4].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let mut ct = blob.to_vec();
        let mut cipher = TestCtr::new_from_slices(&self.cipher_key, &self.iv).unwrap();
        cipher.apply_keystream(&mut ct);
        let mut mac = TestHmac::new_from_slice(&self.mac_key).unwrap();
        mac.update(&self.iv);
        mac.update(&ct);
        let full = mac.finalize().into_bytes();
        self.out.extend_from_slice(&ct);
        self.out.extend_from_slice(&full[..10]);
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

const BACKUP_PASS: &str = "12345 67890 12345 67890 12345 67890"; // spaces are stripped
const BACKUP_SALT: [u8; 32] = [0x11u8; 32];
const BACKUP_IV: [u8; 16] = [0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// Construct a valid encrypted backup that rebuilds a small Signal DB, with an
/// attachment blob mid-stream to exercise blob-skip + counter alignment.
fn build_test_backup(passphrase: &str) -> Vec<u8> {
    let mut w = BackupWriter::new(passphrase, &BACKUP_SALT, BACKUP_IV);

    w.write_frame(&make_statement_frame(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, system_joined_name TEXT, group_id TEXT)",
        &[],
    ));
    let ins_r =
        "INSERT INTO recipient (_id, e164, system_joined_name, group_id) VALUES (?, ?, ?, ?)";
    w.write_frame(&make_statement_frame(
        ins_r,
        &[
            SqlParam::Int(1),
            SqlParam::Str("+15550000001".into()),
            SqlParam::Str("Me Owner".into()),
            SqlParam::Null,
        ],
    ));
    w.write_frame(&make_statement_frame(
        ins_r,
        &[
            SqlParam::Int(2),
            SqlParam::Str("+15551234567".into()),
            SqlParam::Str("Alice Example".into()),
            SqlParam::Null,
        ],
    ));
    w.write_frame(&make_statement_frame(
        "CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, date INTEGER)",
        &[],
    ));
    w.write_frame(&make_statement_frame(
        "INSERT INTO thread (_id, recipient_id, date) VALUES (?, ?, ?)",
        &[
            SqlParam::Int(10),
            SqlParam::Int(2),
            SqlParam::Int(1_600_000_200_000),
        ],
    ));
    w.write_frame(&make_statement_frame(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, from_recipient_id INTEGER,
             to_recipient_id INTEGER, body TEXT, date_sent INTEGER, date_received INTEGER, type INTEGER)",
        &[],
    ));
    let ins_m = "INSERT INTO message (_id, thread_id, from_recipient_id, to_recipient_id, body,
         date_sent, date_received, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    w.write_frame(&make_statement_frame(
        ins_m,
        &[
            SqlParam::Int(100),
            SqlParam::Int(10),
            SqlParam::Int(2),
            SqlParam::Int(1),
            SqlParam::Str("Incoming hi".into()),
            SqlParam::Int(1_600_000_000_000),
            SqlParam::Int(1_600_000_001_000),
            SqlParam::Int(20),
        ],
    ));
    w.write_frame(&make_statement_frame(
        "CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER)",
        &[],
    ));
    w.write_frame(&make_statement_frame(
        "INSERT INTO attachment (_id, message_id) VALUES (?, ?)",
        &[SqlParam::Int(1), SqlParam::Int(100)],
    ));

    // Attachment frame + its raw blob (5 bytes). The following statement must
    // still decrypt, proving the counter stayed aligned across the blob.
    w.write_frame(&make_attachment_frame(1, 1, 5));
    w.write_blob(b"hello");

    w.write_frame(&make_statement_frame(
        ins_m,
        &[
            SqlParam::Int(101),
            SqlParam::Int(10),
            SqlParam::Int(1),
            SqlParam::Int(2),
            SqlParam::Str("Sent reply".into()),
            SqlParam::Int(1_600_000_100_000),
            SqlParam::Int(1_600_000_100_000),
            SqlParam::Int(23),
        ],
    ));
    w.write_frame(&make_end_frame());
    w.finish()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_module_metadata() {
    let p = SignalParser;
    assert_eq!(p.id(), "plugin.messaging.signal");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
    assert!(p.subscribes_to().contains(&ArtifactType::FileContent));
    assert_eq!(p.input_capability(), InputCapability::Stream);
}

#[test]
fn test_detection_names() {
    assert!(is_signal_db_name("signal.db"));
    assert!(is_signal_db_name(
        "/data/.../org.thoughtcrime.securesms/plaintext.db"
    ));
    assert!(is_signal_db_name("signal_export.sqlite"));
    assert!(!is_signal_db_name("msgstore.db"));
    assert!(!is_signal_db_name("mmssms.db"));

    assert!(is_signal_backup_name("signal-2024-01-01.backup"));
    assert!(!is_signal_backup_name("signal.db"));
}

#[test]
fn test_synthetic_parsing_and_direction() {
    let parser = SignalParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_signal_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let msgs = signal_messages(&result);
    assert_eq!(msgs.len(), 2, "expected 2 messages, got {}", msgs.len());

    let received = msgs.iter().find(|a| a.metadata["rowid"] == 100).unwrap();
    assert_eq!(received.metadata["is_from_me"], false);
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["text"], "Incoming hi");
    assert_eq!(received.metadata["service"], "Signal");
    assert_eq!(received.metadata["contact"], "Alice Example");
    assert_eq!(received.metadata["chat_identifier"], "+15551234567");
    assert_eq!(received.metadata["sender"], "Alice Example");
    assert_eq!(received.metadata["has_attachments"], true);
    // date_received (ms) -> seconds.
    assert_eq!(received.metadata["date"].as_i64().unwrap(), 1_600_000_001);
    assert!(received.metadata["date_rfc3339"]
        .as_str()
        .unwrap()
        .starts_with("2020-"));

    let sent = msgs.iter().find(|a| a.metadata["rowid"] == 101).unwrap();
    assert_eq!(sent.metadata["is_from_me"], true);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["sender"], "Me");
    assert_eq!(sent.metadata["contact"], "Alice Example");
    assert_eq!(sent.metadata["has_attachments"], false);

    // Contacts emitted.
    let contacts: Vec<_> = result
        .iter()
        .filter(|a| a.metadata["type"] == "SignalContact")
        .collect();
    assert_eq!(contacts.len(), 2);

    // Summary present with the right counts.
    let summary = result
        .iter()
        .find(|a| a.metadata["type"] == "SignalSummary")
        .unwrap();
    assert_eq!(summary.metadata["message_count"], 2);
    assert_eq!(summary.metadata["contact_count"], 2);
    assert_eq!(summary.metadata["thread_count"], 1);
    assert_eq!(summary.subtype(), Some("summary"));
}

#[test]
fn test_parent_and_case_chain() {
    let parser = SignalParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_signal_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
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
fn test_schema_gate_rejects_non_signal() {
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_non_signal_db()));
    // Name passes the pre-filter, so only the schema gate can reject it.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        0,
        "non-Signal schema must yield zero artifacts"
    );
}

#[test]
fn test_identification_only_no_data() {
    let parser = SignalParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "signal.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_garbage_no_panic_db() {
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 4096]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    // Not SQLite, named as Signal's store: one honest "not read" record, no
    // panic. Zero records here read as "no Signal data" (HUNT-071).
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        1,
        "garbage must yield one not-read record, no panic"
    );
    assert_eq!(result[0].metadata["type"], "SignalIncomplete");
    assert_eq!(result[0].metadata["status"], "StoreNotSqlite");
}

#[test]
fn test_garbage_no_panic_backup() {
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0x00u8; 4096]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "junk.backup"}),
    );
    // A `.backup` suffix is not Signal's naming and zero bytes are not a
    // header frame: nothing is asserted about it, and nothing panics
    // (HUNT-071 — this test previously pinned a "Signal backup" marker for it).
    let result = parser.process(&artifact).unwrap();
    assert!(result.is_empty());

    // Signal's own naming over the same bytes is reported, not asserted.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0x00u8; 4096]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal-2024-01-01-00-00-00.backup"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "SignalIncomplete");
    assert_eq!(result[0].metadata["status"], "BackupHeaderUnrecognised");

    // decrypt_backup directly on garbage errors cleanly.
    assert!(decrypt_backup(&[0u8; 100], "pass").is_err());
}

#[test]
fn hkdf_rfc5869_case3() {
    // RFC 5869 Test Case 3 (SHA-256, empty salt, empty info, L=42) — exactly how
    // Signal invokes HKDF (zero salt). Validates the HKDF half of the KDF.
    let ikm = [0x0bu8; 22];
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 42];
    hk.expand(b"", &mut okm).unwrap();
    let expected: [u8; 42] = [
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a,
        0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73,
        0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    ];
    assert_eq!(okm, expected);
}

#[test]
fn kdf_deterministic_and_salt_sensitive() {
    let a = derive_backup_key("30 digit pass", &[1, 2, 3, 4]);
    let b = derive_backup_key("30digitpass", &[1, 2, 3, 4]); // spaces stripped -> same
    assert_eq!(a, b, "spaces in the passphrase must be ignored");

    let c = derive_backup_key("30digitpass", &[9, 9, 9, 9]);
    assert_ne!(a, c, "different salt must change the key");

    // Subkeys are 32+32 and differ from each other.
    let (ck, mk) = super::derive_backup_subkeys(&a);
    assert_ne!(ck, mk);
}

#[test]
fn backup_roundtrip_decrypts_and_parses() {
    let backup = build_test_backup(BACKUP_PASS);

    // Direct decrypt yields a real SQLite file.
    let replay = decrypt_backup(&backup, BACKUP_PASS).expect("decrypt");
    let db = replay.db;
    assert!(
        db.len() >= 16 && &db[..16] == SQLITE_MAGIC,
        "reconstructed a SQLite DB"
    );
    assert!(
        replay.incomplete.is_none(),
        "a backup replayed to its End frame is complete"
    );
    assert_eq!(replay.rows_lost, 0);

    // Feed the reconstructed DB through the DB path.
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    let msgs = signal_messages(&result);
    // Both messages present -> the statement after the attachment blob decrypted
    // correctly, proving counter alignment across the blob.
    assert_eq!(msgs.len(), 2, "expected 2 messages after round-trip");

    let received = msgs.iter().find(|a| a.metadata["rowid"] == 100).unwrap();
    assert_eq!(received.metadata["direction"], "received");
    assert_eq!(received.metadata["text"], "Incoming hi");
    assert_eq!(received.metadata["contact"], "Alice Example");
    assert_eq!(received.metadata["has_attachments"], true);

    let sent = msgs.iter().find(|a| a.metadata["rowid"] == 101).unwrap();
    assert_eq!(sent.metadata["is_from_me"], true);
    assert_eq!(sent.metadata["sender"], "Me");
}

#[test]
fn backup_wrong_passphrase_errors() {
    let backup = build_test_backup(BACKUP_PASS);
    // A different passphrase yields a wrong macKey -> MAC verification fails.
    let err = decrypt_backup(&backup, "99999 99999 99999 99999 99999 99999");
    assert!(
        err.is_err(),
        "wrong passphrase must fail, not silently succeed"
    );
}

#[test]
fn backup_via_process_emits_marker_and_records() {
    let backup = build_test_backup(BACKUP_PASS);
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(backup));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.backup"}),
    );
    let cred = signal_credential(&artifact, BACKUP_PASS);
    let result = seance_core::credential::scoped(Some(cred), || parser.process(&artifact)).unwrap();

    let marker = result
        .iter()
        .find(|a| a.metadata["type"] == "SignalBackup")
        .expect("SignalBackup marker present");
    assert_eq!(marker.metadata["detected"], true);
    assert_eq!(marker.metadata["decrypted"], true);
    assert_eq!(marker.metadata["message_count"], 2);

    assert_eq!(signal_messages(&result).len(), 2);
}

#[test]
fn backup_via_process_no_passphrase_marker() {
    let backup = build_test_backup(BACKUP_PASS);
    let parser = SignalParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(backup));
    // No passphrase credential supplied.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.backup"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    let marker = &result[0];
    assert_eq!(marker.metadata["type"], "SignalBackup");
    assert_eq!(marker.metadata["detected"], true);
    assert_eq!(marker.metadata["decrypted"], false);
    assert!(marker.metadata.get("reason").is_some());
}

#[test]
fn looks_like_backup_detects_header() {
    let backup = build_test_backup(BACKUP_PASS);
    assert!(looks_like_backup(&backup[..64.min(backup.len())]));
    assert!(!looks_like_backup(&[0xffu8; 64]));
}

// ---------------------------------------------------------------------------
// Cap and read honesty (bugs2 B2-123, B2-128, B2-129, B2-131)
// ---------------------------------------------------------------------------

/// Open a database built from `bytes` read-only, the way `process` does.
fn open_bytes(bytes: &[u8]) -> (TempDb, Connection) {
    let temp = TempDb::write(bytes, "signal_test").unwrap();
    let conn = temp.open().unwrap();
    (temp, conn)
}

fn summary_of(result: &[Artifact]) -> &Artifact {
    result
        .iter()
        .find(|a| a.metadata["type"] == "SignalSummary")
        .expect("summary record present")
}

/// B2-128: the message walk is `ORDER BY … DESC LIMIT n` and the summary
/// reported the capped emit count as `message_count`, with nothing to say the
/// walk stopped. "2 messages" then reads as the whole store rather than the
/// newest 2.
#[test]
fn a_capped_message_walk_marks_the_summary_incomplete() {
    let (_temp, conn) = open_bytes(&create_signal_db());

    let capped = parse_signal_db_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db", 1, 100);
    let s = summary_of(&capped);
    assert_eq!(s.metadata["message_count"], 1);
    assert_eq!(
        s.metadata["content_incomplete"], true,
        "a capped message walk must mark the summary incomplete"
    );
    assert_eq!(s.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(s.metadata["messages_truncated"], true);

    let marker = capped
        .iter()
        .find(|a| a.metadata["status"] == "CapReached")
        .expect("a capped walk must emit its own incompleteness record");
    assert_eq!(marker.metadata["type"], "SignalIncomplete");
    assert_eq!(marker.metadata["source_table"], "message");
    assert_eq!(marker.metadata["max_entries"], 1);

    // The marker must not be filed as a message: `seance_db` groups
    // conversations by `metadata.$.type`, so a marker typed "Signal" would
    // invent a one-message conversation.
    assert!(
        signal_messages(&capped).len() == 1,
        "the incompleteness marker must not count as a message"
    );

    // A budget that covers the store must not claim truncation.
    let whole = parse_signal_db_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db", 2, 100);
    let s = summary_of(&whole);
    assert!(s.metadata.get("content_incomplete").is_none());
    // The schema-support disclosure is the only `SignalIncomplete` record a
    // whole, healthy parse carries, and it claims no incompleteness.
    assert!(!whole
        .iter()
        .any(|a| a.metadata["type"] == "SignalIncomplete"
            && a.metadata["warning_class"] != "ParserStaleWarning"));
    assert!(whole
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// B2-129: `contact_count` counted every recipient row while the emitted
/// inventory was capped, so the contact list could be shorter than the number
/// printed beside it with nothing to explain the gap.
#[test]
fn a_capped_contact_inventory_is_stated_not_implied() {
    let (_temp, conn) = open_bytes(&create_signal_db());

    let capped = parse_signal_db_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db", 100, 1);
    let contacts: Vec<_> = capped
        .iter()
        .filter(|a| a.metadata["type"] == "SignalContact")
        .collect();
    assert_eq!(contacts.len(), 1, "the contact cap must be enforced");

    let s = summary_of(&capped);
    assert_eq!(s.metadata["contact_count"], 2, "recipients actually read");
    assert_eq!(
        s.metadata["contacts_emitted"], 1,
        "records actually emitted"
    );
    assert_eq!(s.metadata["contacts_truncated"], true);
    assert_eq!(s.metadata["content_incomplete"], true);
    assert!(capped
        .iter()
        .any(|a| a.metadata["type"] == "SignalContactIncomplete"));

    // Which contacts survive a cap must be reproducible: ascending recipient id,
    // not HashMap order.
    let again = parse_signal_db_capped(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db", 100, 1);
    let first: Vec<_> = again
        .iter()
        .filter(|a| a.metadata["type"] == "SignalContact")
        .map(|a| a.metadata["recipient_id"].clone())
        .collect();
    assert_eq!(
        contacts[0].metadata["recipient_id"], first[0],
        "a capped contact inventory must drop the same rows every run"
    );
}

/// B2-131: a `prepare`/`query_map` the schema refuses returned an empty map, so
/// "this device had no recipients" and "we could not read the recipient table"
/// produced identical output.
#[test]
fn an_unreadable_lookup_table_is_reported_not_silently_empty() {
    let temp = std::env::temp_dir().join(format!("test_signal_badthread_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        // `thread` exists (so the Signal schema gate passes) but carries no
        // recipient reference column of any generation.
        conn.execute_batch(
            "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, date INTEGER);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
                 date_received INTEGER, type INTEGER);
             INSERT INTO recipient VALUES (1, '+15551234567');
             INSERT INTO thread VALUES (10, 1600000200000);
             INSERT INTO message VALUES (100, 10, 'hi', 1600000001000, 20);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    let (_t, conn) = open_bytes(&data);

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");

    let s = summary_of(&out);
    assert_eq!(s.metadata["parse_incomplete"], true);
    assert_eq!(
        s.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    let failure = out
        .iter()
        .find(|a| a.metadata["status"] == "TableUnreadable")
        .expect("an unreadable table must be a finding of its own");
    assert!(failure.metadata["load_errors"]
        .as_array()
        .map(|v| !v.is_empty())
        .unwrap_or(false));
}

/// B2-123 / B2-124: the Signal database was read with `read_capped` and staged
/// with no comparison against the declared size, so a truncated store parsed as
/// a complete recovery.
#[test]
fn a_short_read_signal_db_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(create_signal_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = SignalParser.process(&artifact).unwrap();

    let msgs = signal_messages(&result);
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

/// The counterpart: a database read whole stays unmarked.
#[test]
fn a_complete_signal_db_carries_no_incompleteness_marks() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_signal_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = SignalParser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

// --- Backup replay honesty (B3-014) ----------------------------------------

/// B3-014: hitting the frame ceiling logged a warning and returned the partial
/// reconstruction as a successful decrypt. What an examiner learns: whether the
/// messages recovered from a backup are all of them. A wrong answer here reads
/// as "the conversation stopped", when in truth the replay did.
#[test]
fn a_replay_that_hits_the_frame_ceiling_reports_the_reconstruction_as_partial() {
    let backup = build_test_backup(BACKUP_PASS);
    // Three frames in: enough to create `recipient` and insert one row, far
    // short of the messages that follow.
    let replay =
        decrypt_backup_limited(&backup, BACKUP_PASS, 3).expect("partial replay still decrypts");
    assert_eq!(replay.frames_read, 3);
    assert_eq!(
        replay.incomplete,
        Some(IncompleteReason::CapReached),
        "a replay stopped by the ceiling is not a complete backup"
    );
}

/// The same ceiling seen from the product entry point: the `SignalBackup`
/// summary an examiner reads must not say a partial decrypt was whole.
#[test]
fn a_capped_replay_marks_the_backup_summary_incomplete() {
    let backup = build_test_backup(BACKUP_PASS);
    let replay = decrypt_backup_limited(&backup, BACKUP_PASS, 3).expect("partial replay");
    // Reconstructed bytes carry no source size of their own, so the shortfall
    // has to be handed to the staging explicitly.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "signal.backup"}),
    );
    let out = SignalParser.process_db(&artifact, &replay.db, "signal.backup", replay.incomplete);
    assert!(
        out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                == Some("DatabaseNotStagedInFull")),
        "a partial reconstruction must be reported in its own right"
    );
    for a in &out {
        if a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("parse_incomplete") {
            continue;
        }
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(a.metadata["content_incomplete_reason"], "cap_reached");
    }
}

/// A full backup run through `process` keeps saying so, or the marker above
/// means nothing.
#[test]
fn a_whole_backup_summary_is_not_marked_incomplete() {
    let backup = build_test_backup(BACKUP_PASS);
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(backup));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.backup"}),
    );
    let cred = signal_credential(&artifact, BACKUP_PASS);
    let result =
        seance_core::credential::scoped(Some(cred), || SignalParser.process(&artifact)).unwrap();
    let marker = result
        .iter()
        .find(|a| a.metadata["type"] == "SignalBackup")
        .expect("SignalBackup marker");
    assert_eq!(marker.metadata["decrypted"], true);
    assert!(marker.metadata.get("content_incomplete").is_none());
    assert!(
        marker.metadata["frames_replayed"].as_u64().unwrap() > 5,
        "the summary states how much of the backup was replayed"
    );
    assert!(result
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// A row-bearing statement that cannot be replayed is a message that is in the
/// backup and not in the reconstruction. Counting it is what stops a lossy
/// replay from presenting as faithful.
#[test]
fn insert_statements_that_fail_to_replay_are_counted_as_lost_rows() {
    let mut w = BackupWriter::new(BACKUP_PASS, &BACKUP_SALT, BACKUP_IV);
    w.write_frame(&make_statement_frame(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT)",
        &[],
    ));
    // No such table: the row it carries cannot land anywhere.
    w.write_frame(&make_statement_frame(
        "INSERT INTO no_such_table (_id) VALUES (?)",
        &[SqlParam::Int(1)],
    ));
    w.write_frame(&make_end_frame());
    let backup = w.finish();

    let replay = decrypt_backup(&backup, BACKUP_PASS).expect("decrypt");
    assert_eq!(replay.rows_lost, 1);
    assert_eq!(
        replay.incomplete,
        Some(IncompleteReason::UnresolvedStructure),
        "a reconstruction missing rows the backup held is not complete"
    );
}

/// Same class as the frame ceiling, from the other direction: a backup whose
/// bytes stop on a frame boundary decrypts every frame it has and then hits
/// clean EOF. Nothing said the `End` frame never arrived, so a truncated
/// acquisition replayed as a finished backup.
///
/// What an examiner learns: whether the conversations recovered from a backup
/// are all of them. A wrong answer here reads as "the messaging stopped on that
/// date", when in truth the file did.
#[test]
fn a_backup_whose_bytes_stop_before_the_end_frame_is_reported_truncated() {
    let mut w = BackupWriter::new(BACKUP_PASS, &BACKUP_SALT, BACKUP_IV);
    w.write_frame(&make_statement_frame(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT)",
        &[],
    ));
    w.write_frame(&make_statement_frame(
        "INSERT INTO recipient (_id, e164) VALUES (?, ?)",
        &[SqlParam::Int(1), SqlParam::Str("+15550000001".into())],
    ));
    // No End frame: the acquisition stopped here, on a frame boundary.
    let truncated = w.finish();

    let replay = decrypt_backup(&truncated, BACKUP_PASS).expect("the prefix still decrypts");
    assert!(
        !replay.ended_cleanly,
        "a backup with no End frame did not end, it ran out"
    );
    assert_eq!(
        replay.incomplete,
        Some(IncompleteReason::ShortRead),
        "a truncated backup must not present as a complete reconstruction"
    );
    assert_eq!(replay.rows_lost, 0, "the frames it did hold all applied");

    // ...and a backup that does reach its End frame stays unmarked, or the
    // marker means nothing.
    let whole = build_test_backup(BACKUP_PASS);
    let replay = decrypt_backup(&whole, BACKUP_PASS).expect("decrypt");
    assert!(replay.ended_cleanly);
    assert!(replay.incomplete.is_none());
}

// ---------------------------------------------------------------------------
// B3-023: rows that would not decode were dropped by `flatten()` and a bare
// `continue`, and the counts beside them were then presented as exact.
//
// A corrupt page, a partially recovered record, a column of an unexpected type:
// each one is a row that IS in the store and did not reach the case. Reported as
// "312 messages" with nothing else said, the 28 that were damaged — and so the
// ones most likely to be the reason the device was seized — are invisible.
// ---------------------------------------------------------------------------

/// Build a Signal database from `extra_sql`, on top of the tables the schema
/// gate needs, and open it the way `process` does.
fn signal_db_with(extra_sql: &str) -> (TempDb, Connection) {
    let temp = std::env::temp_dir().join(format!("test_signal_gaps_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        // `_id` is left untyped so a test can store the wrong type in it. An
        // `INTEGER PRIMARY KEY` is the rowid and SQLite refuses anything else,
        // which would make the corrupt-row cases untestable.
        conn.execute_batch(
            "CREATE TABLE recipient (_id, e164 TEXT, system_joined_name TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER);
             INSERT INTO recipient VALUES (1, '+15550000001', 'Me Owner');
             INSERT INTO recipient VALUES (2, '+15551234567', 'Alice Example');
             INSERT INTO thread VALUES (10, 2);",
        )
        .unwrap();
        conn.execute_batch(extra_sql).unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    open_bytes(&data)
}

fn dropped_row_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["status"] == "RowsUndecodable")
        .collect()
}

#[test]
fn a_message_row_that_will_not_decode_is_counted_not_swallowed() {
    // `_id` has no declared type, so the second row really does hold a TEXT
    // value where the walk reads an integer — the shape a corrupt or partially
    // recovered record arrives in.
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id, thread_id INTEGER, body TEXT, date_received INTEGER,
             type INTEGER);
         INSERT INTO message VALUES (100, 10, 'this one survived', 1600000002000, 20);
         INSERT INTO message VALUES ('corrupt', 10, 'this one did not', 1600000001000, 20);",
    );

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    assert_eq!(signal_messages(&out).len(), 1, "one row decodes");

    let s = summary_of(&out);
    assert_eq!(
        s.metadata["message_count"], 1,
        "the count is what was recovered"
    );
    assert_eq!(
        s.metadata["rows_dropped"], 1,
        "and the row that was not recovered is stated beside it"
    );
    assert_eq!(s.metadata["counts_are_floor"], true);
    assert_eq!(s.metadata["content_incomplete"], true);
    assert_eq!(
        s.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(s.metadata["inventory_incomplete"], true);
    assert!(
        s.metadata["name"].as_str().unwrap().contains("at least"),
        "the headline count must not read as a total: {}",
        s.metadata["name"]
    );

    let markers = dropped_row_markers(&out);
    assert_eq!(
        markers.len(),
        1,
        "one marker for the one walk that lost rows"
    );
    let m = markers[0];
    assert_eq!(m.metadata["source_table"], "message");
    assert_eq!(m.metadata["rows_dropped"], 1);
    // SIG-001. The decoder's reason reached `debug!` and nothing else, so the
    // examiner was told the list is a floor and never what defeated the
    // decoder — the part that says whether the loss is recoverable. Every other
    // messenger names it, through `seance_sqlite_util::RowDrops`.
    let first_error = m.metadata["first_error"]
        .as_str()
        .expect("the marker must name the decoder's reason, not only the count");
    assert!(
        !first_error.is_empty(),
        "an empty reason is the same silence under a different key"
    );
    let detail = m.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap_or("");
    assert!(
        detail.contains("first error:"),
        "the examiner-facing sentence must carry the reason too: {detail}"
    );
    assert_eq!(m.metadata["records_recovered"], 1);
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(m.metadata["inventory_incomplete"], true);
    assert_eq!(m.metadata["subtype"], "parse_incomplete");
    // Never filed as a message: `seance_db` groups conversations by
    // `metadata.$.type`, so a marker typed "Signal" invents a conversation.
    assert_ne!(m.metadata["type"], json!("Signal"));
}

#[test]
fn a_message_column_that_will_not_decode_is_marked_on_the_message_itself() {
    // A BLOB in a TEXT `body`. `row.get::<Option<String>>().ok().flatten()` read
    // that as "no body", so the record said the message carried no text — a
    // statement about what was said, made out of a decode failure.
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
             date_received INTEGER, type INTEGER);
         INSERT INTO message VALUES (100, 10, X'00FF10', 1600000001000, 20);",
    );

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let msgs = signal_messages(&out);
    assert_eq!(msgs.len(), 1, "the row itself still decodes and is emitted");
    let m = msgs[0];

    assert!(
        m.metadata.get("text").is_none(),
        "no text was recovered, so none is claimed"
    );
    assert_eq!(
        m.metadata["content_incomplete"], true,
        "a message whose body would not decode must not read as a message with no text"
    );
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(m.metadata["undecoded_columns"], json!(["body"]));
    assert!(m.metadata["incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("not recovered rather than not present"));
}

#[test]
fn an_attachment_index_row_that_will_not_decode_is_counted() {
    // Absence from this index becomes `has_attachments: false` on the message —
    // a positive claim that nothing was sent with it. A row that would not
    // decode produced exactly that claim, silently.
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
             date_received INTEGER, type INTEGER);
         INSERT INTO message VALUES (100, 10, 'with a picture', 1600000001000, 20);
         CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id);
         INSERT INTO attachment VALUES (1, 100);
         INSERT INTO attachment VALUES (2, 'corrupt');",
    );

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let markers = dropped_row_markers(&out);
    assert_eq!(markers.len(), 1);
    assert_eq!(
        markers[0].metadata["source_table"],
        "the attachment attachment index"
    );
    assert_eq!(markers[0].metadata["rows_dropped"], 1);
    assert_eq!(markers[0].metadata["records_recovered"], 1);
    assert_eq!(summary_of(&out).metadata["rows_dropped"], 1);
}

#[test]
fn a_recipient_row_that_will_not_decode_is_counted() {
    // A recipient lost here is a correspondent every message of theirs is then
    // attributed to "Recipient {id}".
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
             date_received INTEGER, type INTEGER);
         INSERT INTO message VALUES (100, 10, 'hi', 1600000001000, 20);
         INSERT INTO recipient VALUES ('corrupt', '+15559999999', 'Bob Example');",
    );

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let markers = dropped_row_markers(&out);
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].metadata["source_table"], "recipient");
    assert_eq!(markers[0].metadata["rows_dropped"], 1);
    assert_eq!(markers[0].metadata["records_recovered"], 2);

    let s = summary_of(&out);
    assert_eq!(
        s.metadata["contact_count"], 2,
        "two recipients decoded; the third is reported as lost, not counted as read"
    );
    assert_eq!(s.metadata["rows_dropped"], 1);
    let by_source = s.metadata["rows_dropped_by_source"].as_array().unwrap();
    assert_eq!(by_source.len(), 1);
    assert_eq!(by_source[0]["source"], "recipient");
}

/// The counterweight. If a clean parse carried these marks, the marks on a
/// damaged one would carry no information — and an examiner who sees the
/// warning on every case stops reading it.
#[test]
fn a_database_that_read_in_full_carries_no_row_gap_marks_at_all() {
    let (_temp, conn) = open_bytes(&create_signal_db());
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");

    assert!(dropped_row_markers(&out).is_empty());
    let s = summary_of(&out);
    for key in [
        "rows_dropped",
        "counts_are_floor",
        "rows_dropped_by_source",
        "content_incomplete",
        "inventory_incomplete",
        "parse_incomplete",
        "load_errors",
    ] {
        assert!(
            s.metadata.get(key).is_none(),
            "a complete parse must not set `{key}`"
        );
    }
    assert!(
        !s.metadata["name"].as_str().unwrap().contains("at least"),
        "a complete parse reports a total, not a floor"
    );
    for m in signal_messages(&out) {
        assert!(m.metadata.get("content_incomplete").is_none());
        assert!(m.metadata.get("undecoded_columns").is_none());
        assert!(
            m.metadata.get("inventory_incomplete").is_none(),
            "a whole conversation must not be shown to the examiner as a short list"
        );
    }
    assert!(
        summary_of(&out)
            .metadata
            .get("threads_with_unresolved_recipient")
            .is_none(),
        "an ordinary thread map resolves, and must raise nothing"
    );
}

/// The loss has to arrive where the examiner is looking.
///
/// The `SignalIncomplete` markers and the `SignalSummary` are their own record
/// types, and nothing routes an examiner to them: the conversation viewer is
/// scoped to `type: "Signal"` (RecordsViewerPage fetches one type and banners
/// it from `readIncompleteness`), and the Communications page reads the same 16
/// message types. Before this, a Signal store that lost rows rendered as a
/// clean thread with an exact-looking count and no banner anywhere the examiner
/// would see it.
#[test]
fn a_store_that_lost_rows_marks_the_messages_the_examiner_actually_opens() {
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id, thread_id INTEGER, body TEXT, date_received INTEGER,
             type INTEGER);
         INSERT INTO message VALUES (100, 10, 'this one survived', 1600000002000, 20);
         INSERT INTO message VALUES ('corrupt', 10, 'this one did not', 1600000001000, 20);",
    );
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");

    let msgs = signal_messages(&out);
    assert_eq!(msgs.len(), 1);
    for m in &msgs {
        assert_eq!(
            m.metadata["inventory_incomplete"], true,
            "the message record the conversation viewer renders must carry the shortfall"
        );
        assert_eq!(
            m.metadata["inventory_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(m.metadata["inventory_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("not all of them"));
        // The message itself decoded whole; only the list it belongs to is
        // short, and saying otherwise would overstate the damage.
        assert!(m.metadata.get("content_incomplete").is_none());
    }

    let contacts: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "SignalContact")
        .collect();
    assert!(!contacts.is_empty());
    for c in contacts {
        assert_eq!(c.metadata["inventory_incomplete"], true);
    }
}

/// A legacy `recipient_ids` column holding a group id is the ordinary state of
/// a group thread on that schema. Counting it as an undecodable row put a
/// fabricated loss in the case, turned an exact message count into "at least",
/// and emitted a marker asserting rows "could not be decoded" over a database
/// that was read in full.
#[test]
fn a_thread_whose_group_id_will_not_resolve_is_not_reported_as_a_lost_row() {
    let temp = std::env::temp_dir().join(format!("test_signal_legacy_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_ids TEXT);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
                 date_received INTEGER, type INTEGER);
             INSERT INTO recipient VALUES (1, '+15550000001');
             INSERT INTO thread VALUES (10, '__textsecure_group__!abcdef');
             INSERT INTO message VALUES (100, 10, 'group chatter', 1600000001000, 20);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    let (_t, conn) = open_bytes(&data);

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    assert_eq!(signal_messages(&out).len(), 1);
    assert!(
        dropped_row_markers(&out).is_empty(),
        "no row was lost, so no row may be reported lost"
    );

    let s = summary_of(&out);
    assert!(s.metadata.get("rows_dropped").is_none());
    assert!(s.metadata.get("counts_are_floor").is_none());
    assert!(
        !s.metadata["name"].as_str().unwrap().contains("at least"),
        "an exact count must not be presented as a floor: {}",
        s.metadata["name"]
    );
    // ...but the doubtful attribution is still stated, in its own words.
    assert_eq!(s.metadata["threads_with_unresolved_recipient"], 1);
    assert!(s.metadata["attribution_detail"]
        .as_str()
        .unwrap()
        .contains("may not be the one the device recorded"));
    // And a message whose list is whole is not branded short.
    assert!(signal_messages(&out)[0]
        .metadata
        .get("inventory_incomplete")
        .is_none());
}

/// A head read that fails is not a device with no Signal on it.
#[test]
fn a_source_whose_first_bytes_will_not_read_is_reported_not_skipped() {
    /// Refuses every read.
    #[derive(Debug)]
    struct UnreadableSource;
    impl DataSource for UnreadableSource {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("device read error"))
        }
        fn size(&self) -> u64 {
            4096
        }
    }

    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(UnreadableSource) as Arc<dyn DataSource>),
        json!({ "name": "signal.db" }),
    );
    let out = SignalParser.process(&art).unwrap();
    assert_eq!(
        out.len(),
        1,
        "an unreadable Signal artifact must leave a record, not nothing"
    );
    assert_eq!(out[0].metadata["status"], "SourceUnreadable");
    assert_eq!(out[0].metadata["content_incomplete"], true);
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["inventory_incomplete"], true);
    assert!(out[0].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("never classified"));

    // A file that is not named as a Signal artifact stays none of our business.
    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(UnreadableSource) as Arc<dyn DataSource>),
        json!({ "name": "notes.txt" }),
    );
    assert!(SignalParser.process(&other).unwrap().is_empty());
}

// --- Direction honesty (B7-001) ----------------------------------------------

/// A Signal store whose message `type` column is NULL on one row.
fn create_signal_db_with_null_type() -> Vec<u8> {
    let temp = std::env::temp_dir().join(format!("test_signal_nulltype_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, system_joined_name TEXT,
                 profile_joined_name TEXT, group_id TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, date INTEGER);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, from_recipient_id INTEGER,
                 to_recipient_id INTEGER, body TEXT, date_sent INTEGER, date_received INTEGER,
                 type INTEGER, read INTEGER);
             CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER);

             INSERT INTO recipient VALUES (1, '+15550000001', 'Me Owner', NULL, NULL);
             INSERT INTO recipient VALUES (2, '+15551234567', 'Alice Example', NULL, NULL);
             INSERT INTO thread VALUES (10, 2, 1600000200000);

             -- The direction column was never recorded on this row.
             INSERT INTO message VALUES (100, 10, 1, 2, 'Who wrote this', 1600000000000, 1600000001000, NULL, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    data
}

/// A NULL `type` never recorded who wrote the message. Before the fix
/// `unwrap_or(false)` turned it into `direction: "received"` /
/// `is_from_me: false` — an affirmative attribution to the correspondent that
/// nothing downstream could tell from a real one.
#[test]
fn a_null_message_type_leaves_the_direction_unknown() {
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_signal_db_with_null_type()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = SignalParser.process(&artifact).unwrap();
    let msgs = signal_messages(&result);
    assert_eq!(msgs.len(), 1);
    let m = &msgs[0].metadata;
    assert!(
        m.get("direction").is_none(),
        "an unrecorded direction must be omitted, not asserted as received: {:?}",
        m.get("direction")
    );
    assert!(
        m.get("is_from_me").is_none(),
        "an unrecorded direction must not attribute the message to either party"
    );
    assert_eq!(m["text"], "Who wrote this");
    assert!(
        m["name"].as_str().unwrap().starts_with("message:"),
        "the display name must not claim a direction either: {}",
        m["name"]
    );
}

/// A file the case already calls a Signal database, whose catalogue will not
/// read, is a store this build could not examine — not a device with no Signal
/// messages. Before the fix `has_signal_schema` answered `false` for a
/// catalogue error (`unwrap_or(false)`) and `parse_staged` returned zero
/// artifacts, which renders identically to "Signal was never used here".
#[test]
fn a_corrupt_signal_store_is_reported_not_returned_as_an_empty_history() {
    let mut data = create_signal_db();
    // Keep the header so the module still routes it as SQLite, then destroy the
    // pages behind it.
    for b in data.iter_mut().skip(16) {
        *b = 0xFF;
    }
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.db"}),
    );
    let result = SignalParser.process(&artifact).unwrap();
    let marker = result
        .iter()
        .find(|a| a.metadata["status"] == "StoreUnreadable")
        .expect("an unreadable Signal store must be reported, not silently dropped");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
}

/// The counterpart, and the reason the report is name-gated: this module is
/// offered every SQLite file in the evidence, so an unrelated database that is
/// not a Signal store must still produce nothing at all. A finding raised on
/// every unreadable SQLite file in an image is one an examiner learns to skip.
#[test]
fn an_unrelated_sqlite_file_reports_nothing() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_non_signal_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "somethingelse.db"}),
    );
    assert!(SignalParser.process(&artifact).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// HUNT-071: a name is not a classification, and silence is not a finding
// ---------------------------------------------------------------------------

/// Bytes that no Signal parser accepts: not the SQLite header, and a first
/// "frame length" far past what a backup header frame could be.
fn not_signal_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2654435761) as u8 ^ 0x5a)
        .collect()
}

fn process_named(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": name}),
    );
    SignalParser.process(&artifact).unwrap()
}

/// GalleryVault writes `setting.backup` and `file_count.backup` under its
/// own directory. Ending in `.backup` is the whole of the resemblance; the
/// bytes are not a Signal header frame, so the case must not carry a "Signal
/// backup (locked - passphrase required)" record for another app's file.
#[test]
fn a_backup_suffix_on_another_apps_file_is_not_a_signal_backup() {
    let out = process_named("setting.backup", not_signal_bytes(512));
    assert!(
        out.is_empty(),
        "another app's .backup file was recorded as Signal: {:?}",
        out.iter()
            .map(|a| a.metadata["name"].clone())
            .collect::<Vec<_>>()
    );
}

/// A file carrying Signal's own backup name whose first frame does not parse
/// is a finding — the examiner must learn the header was rejected, not read
/// "locked - passphrase required" as if the file were a backup.
#[test]
fn a_signal_named_backup_with_no_header_frame_is_reported_not_asserted() {
    let out = process_named("signal-2024-07-28-10-00-00.backup", not_signal_bytes(512));
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "SignalIncomplete");
    assert_eq!(m["status"], "BackupHeaderUnrecognised");
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["inventory_incomplete"], true);
    assert_ne!(m["type"], "SignalBackup");
    let detail = m["detail"].as_str().unwrap();
    assert!(detail.contains("did not parse"), "{detail}");
    assert!(!m["name"].as_str().unwrap().contains("passphrase"));
}

/// A genuine backup still routes on its bytes when the name says nothing.
#[test]
fn a_renamed_backup_is_still_detected_by_its_header_frame() {
    let out = process_named("export.bin", build_test_backup(BACKUP_PASS));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "SignalBackup");
    assert_eq!(out[0].metadata["detected"], true);
}

/// Signal for Android keeps `signal.db` SQLCipher-encrypted. The first 16
/// bytes are salt, not the SQLite header, so the store is not openable — and
/// before this fix the module returned nothing, which the case rendered as
/// "no Signal data on this device" for a 7 MB message store.
#[test]
fn an_encrypted_signal_db_is_reported_not_silently_absent() {
    let out = process_named(
        "/data/data/org.thoughtcrime.securesms/databases/signal.db",
        not_signal_bytes(4096 * 3),
    );
    assert_eq!(out.len(), 1, "an unopenable signal.db must leave a record");
    let m = &out[0].metadata;
    assert_eq!(m["type"], "SignalIncomplete");
    assert_eq!(m["status"], "StoreNotSqlite");
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["inventory_incomplete"], true);
    assert_eq!(m["sqlcipher_consistent"], true);
    let detail = m["detail"].as_str().unwrap();
    assert!(detail.contains("not the SQLite header"), "{detail}");
    assert!(detail.contains("SQLCipher"), "{detail}");
    assert!(detail.contains("not evidence of absence"), "{detail}");
    assert_eq!(m["subtype"], "parse_incomplete");
}

/// The same non-SQLite bytes under a size that is not a whole number of
/// SQLCipher pages: still reported, but not called SQLCipher-consistent.
#[test]
fn a_non_sqlite_signal_db_of_odd_size_is_not_called_sqlcipher_consistent() {
    let out = process_named("signal.db", not_signal_bytes(4096 + 17));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["status"], "StoreNotSqlite");
    assert_eq!(out[0].metadata["sqlcipher_consistent"], false);
}

/// The permissive name gate stays permissive for SQLite bytes (a renamed
/// plaintext copy is parsed on its schema), but a name that merely ends in
/// `.backup` is not Signal's naming.
#[test]
fn signal_backup_naming_is_signals_not_any_backup_suffix() {
    assert!(is_signal_backup_name("signal-2024-07-28-10-00-00.backup"));
    assert!(is_signal_backup_name(
        "/sdcard/Signal/Backups/signal-2024-07-28-10-00-00.backup"
    ));
    assert!(is_signal_backup_name("SIGNAL.BACKUP"));
    assert!(!is_signal_backup_name("setting.backup"));
    assert!(!is_signal_backup_name("file_count.backup"));
    assert!(!is_signal_backup_name("signal.db"));
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

fn schema_records(arts: &[Artifact]) -> Vec<&Artifact> {
    arts.iter()
        .filter(|a| a.metadata["warning_class"] == json!("ParserStaleWarning"))
        .collect()
}

fn injected() -> SchemaSupport {
    SchemaSupport {
        app: "signal-android",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(1, Some(3)),
            evidence: "test value, not a Signal build",
        },
    }
}

/// `create_signal_db` with `PRAGMA user_version` set through SQLite.
fn signal_db_at_version(v: i64) -> Vec<u8> {
    let temp = TempDb::write(&create_signal_db(), "signal_uv").unwrap();
    {
        let conn = Connection::open(temp.path()).unwrap();
        conn.execute_batch(&format!("PRAGMA user_version = {v};"))
            .unwrap();
    }
    std::fs::read(temp.path()).unwrap()
}

/// A store whose `PRAGMA user_version` is beyond the range a parser was
/// validated against must say so — and must still parse what it can. The
/// crate's own declaration is Unranged (no plaintext Signal store is held; the
/// two real ones on this machine are SQLCipher-encrypted), so the Validated
/// bound here is injected; the range is a test value and asserts nothing about
/// any Signal build.
#[test]
fn a_schema_version_beyond_the_validated_range_is_declared_and_the_store_is_still_parsed() {
    let (_t, conn) = open_bytes(&signal_db_at_version(99));
    let out = parse_signal_db_with(
        &conn,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "signal.db",
        MAX_MESSAGE_ENTRIES,
        MAX_CONTACT_ENTRIES,
        &injected(),
    );

    assert_eq!(
        signal_messages(&out).len(),
        2,
        "the messages are still recovered"
    );
    let stale = schema_records(&out);
    assert_eq!(stale.len(), 1, "{out:?}");
    let m = &stale[0].metadata;
    assert_eq!(m["type"], json!("SignalIncomplete"));
    assert_eq!(m["subtype"], json!("parser_stale"));
    assert_eq!(m["status"], json!("SchemaOutsideValidated"));
    assert_eq!(m["schema_version_seen"], json!(99));
    assert_eq!(m["schema_version_supported"], json!("1..=3"));
    assert_eq!(m["source_table"], json!("message"));
    assert!(m["message"].as_str().unwrap().contains("NEWER"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A renamed body column used to be read as "no body" on every row — a
/// complete-looking parse of a conversation in which nothing was said. The
/// FieldMap names the LOGICAL field, and the rest of the row is still read.
#[test]
fn a_renamed_body_column_yields_a_marker_naming_the_unresolved_field() {
    let (_t, conn) = signal_db_with(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, text_body TEXT,
             date_received INTEGER, type INTEGER);
         INSERT INTO message VALUES (100, 10, 'unreachable', 1600000001000, 23);",
    );
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");

    let marker = schema_records(&out);
    assert_eq!(marker.len(), 1, "{out:?}");
    let m = &marker[0].metadata;
    assert_eq!(m["type"], json!("SignalIncomplete"));
    assert_eq!(m["status"], json!("SchemaFieldsUnresolved"));
    assert_eq!(m["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("text"));
    let msgs = signal_messages(&out);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].metadata["direction"], json!("sent"));
    assert_eq!(msgs[0].metadata["date"], json!(1600000001));
    assert!(msgs[0].metadata.get("text").is_none());
    assert_eq!(m["records_recovered"], json!(1));
}

/// No plaintext Signal store is held by this project, so the crate declares
/// Unranged: the record says so, reports the version the store carries, and
/// carries NO range — a `1..=N` here would be a claim about databases this
/// project has never opened.
#[test]
fn a_parser_with_no_reference_database_declares_that_rather_than_a_range() {
    let (_t, conn) = open_bytes(&signal_db_at_version(7));
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let rec = schema_records(&out);
    assert_eq!(rec.len(), 1, "{out:?}");
    let m = &rec[0].metadata;
    assert_eq!(m["type"], json!("SignalIncomplete"));
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["app"], json!("signal-android"));
    assert_eq!(m["schema_version_seen"], json!(7));
    assert_eq!(m["schema_version_locator"], json!("user_version"));
    assert!(m.get("schema_version_supported").is_none(), "{m}");
    assert!(m.get("supported_range").is_none(), "{m}");
    assert!(m["schema_support"]
        .as_str()
        .unwrap()
        .contains("no plaintext reference database"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert_eq!(signal_messages(&out).len(), 2);
}

/// The Unranged reason must name the true blocker. The held iOS keychain
/// export carries the raw SQLCipher key spec for `grdb/signal.sqlite`
/// (`GRDBDatabaseCipherKeySpec`, 48 bytes), and since HUNT-183
/// `seance_sqlcipher` decrypts that SQLCipher 4 raw-key / HMAC-SHA512 form, so
/// neither "no key" nor "the reader cannot decrypt it" is true any more. What
/// keeps this Android parser unranged is that the one store that has been read
/// is Signal for iOS's GRDB schema, which is not this parser's.
#[test]
fn the_unranged_reason_names_the_ios_schema_not_absent_keys_or_tooling() {
    let SchemaBound::Unranged { why } = SCHEMA_SUPPORT.bound else {
        panic!("Signal is Unranged until a plaintext store is read");
    };
    assert!(why.contains("SQLCipher 4"), "{why}");
    assert!(
        !why.contains("SQLCipher 3 passphrase / HMAC-SHA1 only"),
        "the SQLCipher 3-only limit closed with HUNT-183: {why}"
    );
    assert!(why.contains("iOS"), "{why}");
    assert!(why.contains("not this Android schema"), "{why}");
    assert!(!why.contains("without key"), "{why}");
    assert!(!why.contains("no key"), "{why}");

    let (_t, conn) = open_bytes(&signal_db_at_version(7));
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let m = &schema_records(&out)[0].metadata;
    let support = m["schema_support"].as_str().unwrap();
    assert!(support.contains("SQLCipher 4"), "{support}");
    assert!(!support.contains("no key"), "{support}");
}

/// The schema record is one per message TABLE walked, not one per store: a
/// legacy store split into `sms` and `mms` carries two, each naming its own
/// table and its own recovered count. "Exactly one per store" would be false
/// for exactly the stores an examiner is most likely to meet in old backups.
#[test]
fn a_legacy_sms_plus_mms_store_carries_one_schema_record_per_table_walked() {
    let temp = std::env::temp_dir().join(format!("test_signal_smsmms_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT);
             CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_ids TEXT);
             CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
                 date INTEGER, type INTEGER);
             CREATE TABLE mms (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT,
                 date INTEGER, msg_box INTEGER);
             INSERT INTO recipient VALUES (1, '+15550000001');
             INSERT INTO thread VALUES (10, '1');
             INSERT INTO sms VALUES (100, 10, 'one', 1600000001000, 20);
             INSERT INTO sms VALUES (101, 10, 'two', 1600000002000, 20);
             INSERT INTO mms VALUES (200, 10, 'three', 1600000003000, 20);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp).unwrap();
    let _ = std::fs::remove_file(&temp);
    let (_t, conn) = open_bytes(&data);

    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let recs = schema_records(&out);
    let mut tables: Vec<(&str, u64)> = recs
        .iter()
        .map(|a| {
            (
                a.metadata["source_table"].as_str().unwrap(),
                a.metadata["records_recovered"].as_u64().unwrap(),
            )
        })
        .collect();
    tables.sort();
    assert_eq!(tables, vec![("mms", 1), ("sms", 2)], "{out:?}");
}

/// `PRAGMA user_version` reads 0 on a store that never set it — SQLite's
/// default. That is the absence of a version, never "version 0".
#[test]
fn a_user_version_of_zero_is_the_absence_of_a_version_not_a_version_of_zero() {
    let (_t, conn) = open_bytes(&create_signal_db());
    let out = parse_signal_db(&conn, Uuid::new_v4(), Uuid::new_v4(), "signal.db");
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaNotRanged"));
    assert_eq!(m["schema_version_recorded"], json!(false));
    assert!(m.get("schema_version_seen").is_none(), "{m}");

    let out = parse_signal_db_with(
        &conn,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "signal.db",
        MAX_MESSAGE_ENTRIES,
        MAX_CONTACT_ENTRIES,
        &injected(),
    );
    let m = &schema_records(&out)[0].metadata;
    assert_eq!(m["status"], json!("SchemaVersionNotRecorded"));
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// A version the store would not answer is never spent as "in range".
#[test]
fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
    let fields = FieldMap::resolve(
        &[
            "body".to_string(),
            "date_received".to_string(),
            "type".to_string(),
        ]
        .into_iter()
        .collect(),
        MESSAGE_FIELDS,
    );
    let rec = SchemaCheck {
        support: &injected(),
        version: SchemaVersion::Undetermined("PRAGMA user_version would not read".into()),
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "SignalIncomplete",
        store: "message",
    }
    .marker(Uuid::new_v4(), Uuid::new_v4(), 3)
    .expect("an unanswered version is a record, not silence");
    assert_eq!(rec.metadata["status"], json!("SchemaVersionUndetermined"));
    assert!(rec.metadata.get("schema_version_seen").is_none());
}

/// Build a `BackupFrame{ version: DatabaseVersion{ version } }` (field 5,
/// inner field 1), the frame Signal-Android's exporter writes before the
/// statements and its importer replays with `db.version = version.version`.
fn make_version_frame(version: u64) -> Vec<u8> {
    pbw_bytes(5, &pbw_varint_field(1, version))
}

/// The backup carries the database version in its own frame, and the replay
/// used to drop it — so the reconstructed database read `user_version` 0 and
/// the schema record would have called a versioned backup "not recorded".
/// Replaying it the way the importer does makes the version what the backup
/// said it was.
#[test]
fn a_backup_s_database_version_frame_is_replayed_into_user_version() {
    let mut w = BackupWriter::new(BACKUP_PASS, &BACKUP_SALT, BACKUP_IV);
    w.write_frame(&make_version_frame(42));
    w.write_frame(&make_statement_frame(
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT)",
        &[],
    ));
    w.write_frame(&make_end_frame());
    let backup = w.finish();

    let replay = decrypt_backup(&backup, BACKUP_PASS).expect("decrypt");
    assert_eq!(replay.database_version, Some(42));
    let (_t, conn) = open_bytes(&replay.db);
    assert_eq!(user_version(&conn), SchemaVersion::Found(42));

    // A backup without the frame stays what SQLite's default says: unset.
    let replay = decrypt_backup(&build_test_backup(BACKUP_PASS), BACKUP_PASS).expect("decrypt");
    assert_eq!(replay.database_version, None);
    let (_t, conn) = open_bytes(&replay.db);
    assert_eq!(user_version(&conn), SchemaVersion::NotRecorded);
}

#[test]
fn the_declared_schema_support_is_unranged_for_want_of_a_real_store() {
    assert!(matches!(SCHEMA_SUPPORT.bound, SchemaBound::Unranged { .. }));
    assert!(REQUIRED_FIELDS
        .iter()
        .all(|r| MESSAGE_FIELDS.iter().any(|(l, _)| l == r)));
}

// --- SQLCipher with a plaintext header (Signal iOS) -------------------------

/// The iOS Signal store, as this project holds it: `~/ctf-evidence/ios2022ffs`
/// member `.../AppGroup/92EFD8F4-.../grdb/signal.sqlite`, 1,249,280 bytes.
/// Its first 32 bytes are transcribed here byte for byte — a valid SQLite
/// header (page size 4096, WAL, reserved-bytes-per-page 0x50, 305 pages) —
/// and everything after byte 32 is ciphertext, reproduced as a fixed
/// pseudo-random pattern. Bytes 60..63 of the real file read 360193054: a
/// header field INSIDE the encrypted region, which no plaintext database has.
fn ios_signal_sqlcipher_store() -> Vec<u8> {
    const HEADER: [u8; 32] = [
        0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33,
        0x00, 0x10, 0x00, 0x02, 0x02, 0x50, 0x40, 0x20, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x01, 0x31,
    ];
    let pages = 0x131usize;
    let mut bytes = Vec::with_capacity(pages * 4096);
    bytes.extend_from_slice(&HEADER);
    let mut x: u32 = 0xf9e8_cec9;
    while bytes.len() < pages * 4096 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((x >> 24) as u8);
    }
    bytes
}

/// The plaintext-header SQLCipher store opens — its magic is real — and then
/// answers every catalogue read with "unsupported file format". That used to
/// be filed as `unresolved_structure` ("a damaged store"), which sends an
/// examiner looking for corruption in a file that is intact and encrypted; and
/// nothing said the version field was ciphertext, so a header read would have
/// reported 360193054 as a schema version.
#[test]
fn a_sqlcipher_store_with_a_plaintext_header_is_reported_as_encrypted_not_damaged() {
    let out = process_named(
        "/private/var/mobile/Containers/Shared/AppGroup/92EFD8F4/grdb/signal.sqlite",
        ios_signal_sqlcipher_store(),
    );
    // The header also declares WAL mode, so the shared staging stamp for a
    // `-wal` this source cannot reach is emitted beside the finding; the real
    // evidence did carry a 156,592-byte `signal.sqlite-wal`.
    let rec = out
        .iter()
        .find(|a| a.metadata["status"] == "StoreEncrypted")
        .unwrap_or_else(|| panic!("an encrypted store must be reported as one: {out:?}"));
    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == "StoreUnreadable"),
        "an intact encrypted store is not a damaged one: {out:?}"
    );
    let m = &rec.metadata;
    assert_eq!(m["type"], "SignalIncomplete");
    assert_eq!(m["subtype"], "parse_incomplete");
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["content_incomplete_reason"], "encrypted");
    assert_eq!(m["inventory_incomplete"], true);
    assert_eq!(m["inventory_incomplete_reason"], "encrypted");
    assert_eq!(m["sqlcipher_consistent"], true);
    assert_eq!(m["reserved_bytes_per_page"], 0x50);
    let detail = m["detail"].as_str().unwrap();
    assert!(detail.contains("plaintext header"), "{detail}");
    assert!(detail.contains("not evidence of absence"), "{detail}");
    // The record says why it was not opened — no key was supplied for it —
    // and where one can be (HUNT-227), not that no key exists for it.
    assert!(detail.contains("SQLCipher 4"), "{detail}");
    assert!(detail.contains("no key was supplied"), "{detail}");
    assert!(detail.contains("Needs attention queue"), "{detail}");
    assert!(!detail.contains("holds no key"), "{detail}");
    assert_eq!(m["scheme"], "sqlcipher4_raw_key_plaintext_header");
    assert!(
        !detail.contains("SQLCipher 3 passphrase / HMAC-SHA1 stores only"),
        "{detail}"
    );
    // No version is read out of the encrypted header region.
    assert!(m.get("schema_version_seen").is_none(), "{m}");
    assert!(schema_records(&out).is_empty());
}

/// A plaintext store that happens to reserve bytes per page still opens and
/// reads: the reserve is only consulted once the catalogue has refused.
#[test]
fn a_readable_store_with_reserved_page_bytes_is_still_parsed() {
    let mut bytes = create_signal_db();
    // A plain SQLite file has 0 here; setting it after the fact does not
    // make the catalogue unreadable for a small database, so this pins that
    // the byte alone never triggers the encrypted verdict.
    bytes[20] = 0x20;
    let (_t, conn) = open_bytes(&bytes);
    if has_signal_schema(&conn).is_ok() {
        let out = process_named("signal.db", bytes);
        assert_eq!(signal_messages(&out).len(), 2);
        assert!(!out.iter().any(|a| a.metadata["status"] == "StoreEncrypted"));
    }
}

/// The real thing, when it is provisioned: `SEANCE_SIGNAL_IOS_SQLITE` names
/// the `grdb/signal.sqlite` member extracted from the iOS 2022 FFS zip
/// (`~/ctf-evidence/ios2022ffs/Jess_CTF_iPhone8/*_files_full.zip`, member
/// `/private/var/mobile/Containers/Shared/AppGroup/92EFD8F4-8BF3-42D7-8DF7-E2F512630E22/grdb/signal.sqlite`).
/// Absent, the run says so; named and missing, it fails.
#[test]
fn the_real_ios_signal_store_is_reported_as_encrypted_with_no_version_read() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_SIGNAL_IOS_SQLITE") else {
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..16], SQLITE_MAGIC);
    assert_eq!(
        bytes[20], 0x50,
        "the real store reserves SQLCipher 4's 80 bytes"
    );
    let out = process_named("grdb/signal.sqlite", bytes);
    let rec = out
        .iter()
        .find(|a| a.metadata["status"] == "StoreEncrypted")
        .unwrap_or_else(|| panic!("{out:?}"));
    assert_eq!(rec.metadata["content_incomplete_reason"], "encrypted");
    assert_eq!(rec.metadata["reserved_bytes_per_page"], 0x50);
    assert!(rec.metadata.get("schema_version_seen").is_none());
    assert!(signal_messages(&out).is_empty());
    assert!(schema_records(&out).is_empty());
}

// ---------------------------------------------------------------------------
// SEC-204: the Android backup passphrase through the credential route
// ---------------------------------------------------------------------------

fn backup_artifact_without_a_passphrase() -> Artifact {
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(build_test_backup(BACKUP_PASS)));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.backup"}),
    )
}

#[test]
fn a_backup_passphrase_credential_decrypts_and_is_reported_accepted() {
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    let artifact = backup_artifact_without_a_passphrase();
    let cred = Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::SignalBackupPassphrase,
        BACKUP_PASS.to_string(),
        "erin",
    ));
    let result = credential::scoped(Some(cred.clone()), || SignalParser.process(&artifact))
        .expect("the right passphrase decrypts");

    assert_eq!(cred.outcome(), Some(CredentialOutcome::Accepted));
    let marker = result
        .iter()
        .find(|a| a.metadata["type"] == "SignalBackup")
        .expect("SignalBackup marker present");
    assert_eq!(marker.metadata["decrypted"], true);
    assert_eq!(signal_messages(&result).len(), 2);
}

#[test]
fn a_wrong_backup_passphrase_credential_is_reported_rejected() {
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    const WRONG: &str = "99999 99999 99999 99999 99999 99999";
    let artifact = backup_artifact_without_a_passphrase();
    let cred = Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::SignalBackupPassphrase,
        WRONG.to_string(),
        "erin",
    ));
    let result = credential::scoped(Some(cred.clone()), || SignalParser.process(&artifact))
        .expect("a refused passphrase is a verdict, not a module error");
    assert!(signal_messages(&result).is_empty());
    match cred.outcome() {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains(WRONG), "{reason}");
            assert!(!reason.contains("99999"), "{reason}");
            assert!(reason.contains("MAC"), "{reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

fn signal_credential(
    artifact: &Artifact,
    secret: &str,
) -> Arc<seance_core::credential::RunCredential> {
    Arc::new(seance_core::credential::RunCredential::new(
        artifact.id,
        seance_core::credential::CredentialKind::SignalBackupPassphrase,
        secret.to_string(),
        "erin",
    ))
}

/// SEC-204 review. The ingest field `signal_backup_password` is scrubbed at
/// ingest (`*_password` becomes the redaction marker before any module runs),
/// so it can never carry a passphrase to this parser in production. It is no
/// longer read: a value in metadata — the real passphrase or the redaction
/// marker — leaves the backup locked, and the marker is never tried as a
/// passphrase (which would have been recorded as a wrong one).
#[test]
fn a_backup_passphrase_in_artifact_metadata_is_no_longer_read() {
    for value in [BACKUP_PASS, seance_core::ingestion::REDACTED_SECRET] {
        let ds: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(build_test_backup(BACKUP_PASS)));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({"name": "signal.backup", "signal_backup_password": value}),
        );
        let result = SignalParser.process(&artifact).unwrap();
        assert_eq!(result.len(), 1, "{value}: {result:?}");
        let marker = &result[0];
        assert_eq!(marker.metadata["type"], "SignalBackup");
        assert_eq!(marker.metadata["decrypted"], false);
        assert!(
            marker.metadata.get("error").is_none(),
            "{value}: nothing was tried"
        );
        let reason = marker.metadata["reason"].as_str().unwrap();
        assert!(reason.contains("signal_backup_passphrase"), "{reason}");
        assert!(!reason.contains("signal_backup_password"), "{reason}");
    }
}

/// SEC-204 review. A first-frame MAC failure cannot tell a wrong passphrase
/// from a corrupt first frame; the rejection and the error both say so.
#[test]
fn a_first_frame_mac_failure_names_a_corrupt_frame_as_well_as_a_wrong_passphrase() {
    let err = decrypt_backup(
        &build_test_backup(BACKUP_PASS),
        "99999 99999 99999 99999 99999 99999",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("wrong passphrase"), "{err}");
    assert!(err.contains("corrupt"), "{err}");

    let artifact = backup_artifact_without_a_passphrase();
    let cred = signal_credential(&artifact, "99999 99999 99999 99999 99999 99999");
    seance_core::credential::scoped(Some(cred.clone()), || SignalParser.process(&artifact))
        .unwrap();
    match cred.outcome() {
        Some(seance_core::credential::CredentialOutcome::Rejected { reason }) => {
            assert!(reason.contains("wrong"), "{reason}");
            assert!(reason.contains("corrupt"), "{reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

/// SEC-204 review. A backup that ends after its header has no frame whose MAC
/// could test the passphrase: the passphrase is not reported accepted.
#[test]
fn a_backup_with_no_encrypted_frame_does_not_report_the_passphrase_accepted() {
    let full = build_test_backup(BACKUP_PASS);
    let header_len = u32::from_be_bytes([full[0], full[1], full[2], full[3]]) as usize;
    let header_only = full[..4 + header_len].to_vec();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(header_only));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "signal.backup"}),
    );
    let cred = signal_credential(&artifact, BACKUP_PASS);
    let _ = seance_core::credential::scoped(Some(cred.clone()), || SignalParser.process(&artifact));
    assert_eq!(
        cred.outcome(),
        None,
        "no MAC verified, so nothing tested the passphrase"
    );
}
