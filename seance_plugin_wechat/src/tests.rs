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

/// A decrypted WeChat EnMicroMsg.db (plain SQLite) with a message table.
fn decrypted_wechat_db() -> Vec<u8> {
    decrypted_wechat_db_with(0, "content")
}

/// Three-message store at `user_version`, with the body column under
/// `text_col`. No real WeChat store is held, so 0 (SQLite's default) is the
/// only version this fixture can honestly carry by default.
fn decrypted_wechat_db_with(user_version: i64, text_col: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("test_wechat_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA user_version = {user_version};
             CREATE TABLE message (msgId INTEGER PRIMARY KEY, talker TEXT, {text_col} TEXT, createTime INTEGER, isSend INTEGER, type INTEGER);
             INSERT INTO message VALUES (1, 'wxid_abc', 'Hi from WeChat', 1673000000000, 0, 1);
             INSERT INTO message VALUES (2, 'wxid_abc', 'reply sent', 1673000060000, 1, 1);
             INSERT INTO message VALUES (3, 'room1@chatroom', 'group msg', 1673000120000, 0, 1);"
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
    WeChatParser.process(&art).unwrap()
}

fn by_rowid(arts: &[Artifact], rowid: i64) -> &Artifact {
    arts.iter()
        .find(|a| a.metadata.get("rowid").and_then(|v| v.as_i64()) == Some(rowid))
        .expect("record present")
}

#[test]
fn parses_decrypted_message_table() {
    let arts = run("EnMicroMsg.db", decrypted_wechat_db());
    assert_eq!(messages(&arts).len(), 3);

    let recv = by_rowid(&arts, 1);
    assert_eq!(recv.metadata["type"], "WeChat");
    assert_eq!(recv.metadata["direction"], "received");
    assert_eq!(recv.metadata["is_from_me"], false);
    assert_eq!(recv.metadata["text"], "Hi from WeChat");
    assert_eq!(recv.metadata["contact"], "wxid_abc");
    // createTime is Unix ms -> seconds.
    assert_eq!(recv.metadata["date"].as_i64(), Some(1_673_000_000));

    let sent = by_rowid(&arts, 2);
    assert_eq!(sent.metadata["direction"], "sent");
    assert_eq!(sent.metadata["is_from_me"], true);

    let group = by_rowid(&arts, 3);
    assert_eq!(group.metadata["chat_identifier"], "room1@chatroom");
}

/// BUG-253: a NULL `isSend` never recorded the direction, so it must stay
/// unknown instead of being asserted as received.
#[test]
fn null_is_send_leaves_direction_unknown() {
    let path = std::env::temp_dir().join(format!("test_wechat_nodir_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (msgId INTEGER PRIMARY KEY, talker TEXT, content TEXT, createTime INTEGER, isSend INTEGER, type INTEGER);
             INSERT INTO message VALUES (1, 'wxid_abc', 'no direction', 1673000000000, NULL, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let arts = run("EnMicroMsg.db", data);
    let arts = messages(&arts);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("direction").is_none());
    assert!(arts[0].metadata.get("is_from_me").is_none());
    assert_eq!(arts[0].metadata["text"], "no direction");
}

#[test]
fn flags_encrypted_database() {
    // A SQLCipher DB starts with the random salt, not the SQLite magic.
    let mut encrypted = vec![0x9a, 0x7c, 0x11, 0x42, 0xff, 0x00, 0xde, 0xad];
    encrypted.extend_from_slice(&[0x42u8; 4096]); // opaque ciphertext
    let arts = run("EnMicroMsg.db", encrypted);
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["type"], "EncryptedMessengerDatabase");
    assert_eq!(arts[0].metadata["app"], "WeChat");
    assert_eq!(arts[0].metadata["encryption"], "SQLCipher");
    assert_eq!(arts[0].metadata["status"], "Encrypted");
}

#[test]
fn skips_non_wechat_name() {
    assert!(run("other.db", decrypted_wechat_db()).is_empty());
}

#[test]
fn passphrase_from_metadata() {
    // Derived from IMEI + uin.
    let p =
        sqlcipher_passphrase(&json!({"wechat_imei": "35000imei", "wechat_uin": "12345"})).unwrap();
    assert_eq!(p.len(), 7);
    assert!(p.iter().all(|b| b.is_ascii_hexdigit()));
    // A raw key wins over IMEI/uin.
    assert_eq!(
        sqlcipher_passphrase(
            &json!({"sqlcipher_key": "abc", "wechat_imei": "x", "wechat_uin": "y"})
        )
        .unwrap(),
        b"abc"
    );
    // No key material -> None (falls back to flagging).
    assert!(sqlcipher_passphrase(&json!({"other": 1})).is_none());
}

#[test]
fn encrypted_with_wrong_key_still_flags_not_wrong_rows() {
    // A SQLCipher-shaped blob that the supplied key can't decrypt must be flagged
    // (the decrypted bytes aren't valid SQLite) — never parsed into wrong rows.
    let mut enc = vec![0x9a, 0x7c, 0x11, 0x42];
    enc.extend_from_slice(&[0x42u8; 2044]); // 2048 bytes, not the SQLite magic
    let ds: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(ByteSliceDataSource::new(enc));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "EnMicroMsg.db", "sqlcipher_key": "not-the-real-key" }),
    );
    let out = WeChatParser.process(&art).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "EncryptedMessengerDatabase");
}

/// Gated end-to-end: decrypt + parse a real encrypted EnMicroMsg.db when one is
/// provided (a faithful SQLCipher plaintext can't be synthesised offline — the
/// reserve layout differs from a plain rusqlite DB — so this runs only against a
/// real fixture; the crypto framing itself is covered in seance_sqlcipher).
#[test]
fn decrypts_real_fixture_when_present() {
    let path = "test_data/EnMicroMsg_encrypted.db";
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("Skipping: {path} not found (provide a real encrypted WeChat DB + key)");
        return;
    };
    let (Ok(imei), Ok(uin)) = (
        std::env::var("SEANCE_WECHAT_IMEI"),
        std::env::var("SEANCE_WECHAT_UIN"),
    ) else {
        eprintln!("Skipping: set SEANCE_WECHAT_IMEI / SEANCE_WECHAT_UIN to validate decryption");
        return;
    };
    let ds: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "EnMicroMsg.db", "wechat_imei": imei, "wechat_uin": uin }),
    );
    let out = WeChatParser.process(&art).unwrap();
    assert!(
        out.iter().any(|a| a.metadata["type"] == "WeChat"),
        "should decrypt + parse messages"
    );
}

#[test]
fn module_metadata() {
    let p = WeChatParser;
    assert_eq!(p.id(), "plugin.messaging.wechat");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}
fn run_source(ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "EnMicroMsg.db" }),
    );
    WeChatParser.process(&art).unwrap()
}

/// B2-124: the database was staged without comparing what came back against
/// what the source declared, so a truncated store parsed as a complete one.
/// What an examiner learns: whether the messages on screen are the whole
/// conversation. A wrong answer here is an absence conclusion the evidence does
/// not support.
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source(Arc::new(truncated(decrypted_wechat_db())));
    let msg = by_rowid(&out, 1);
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
    let out = run("EnMicroMsg.db", decrypted_wechat_db());
    assert_eq!(messages(&out).len(), 3);
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// The magic probe loops over short reads. A source that answers four bytes per
/// call holds a perfectly good database; refusing it — or, worse, filing it as
/// SQLCipher-encrypted because the first `read_at` was short — would lose the
/// whole store on nothing more than the shape of the read.
#[test]
fn a_source_that_answers_in_small_chunks_is_still_parsed() {
    let out = run_source(Arc::new(DribbleSource::new(decrypted_wechat_db(), 4)));
    assert_eq!(
        messages(&out).len(),
        3,
        "a chunked source is not an encrypted database"
    );
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

// --- B8-013 / B8-035: probes and provenance ---

/// Damage page 1's b-tree without touching the file header, so the database
/// OPENS and then answers every catalogue query with `SQLITE_CORRUPT` — the
/// state a carved or partially recovered store arrives in.
///
/// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6`.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

/// B8-015's class on the WeChat surface: `parse_messages` answered an
/// unreadable store with `Vec::new()`, and an empty artifact list for a file
/// named `EnMicroMsg.db` renders exactly like a phone that never had WeChat.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn a_corrupt_wechat_store_is_not_reported_as_a_phone_without_wechat() {
    let out = run(
        "EnMicroMsg.db",
        corrupt_the_catalogue(decrypted_wechat_db()),
    );
    assert!(
        !out.is_empty(),
        "a WeChat store this tool could not read must not render as one with no messages"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("WeChatIncomplete"));
    assert_ne!(
        marker.metadata["type"],
        json!("WeChat"),
        "a marker filed under the message type becomes a phantom conversation"
    );
    assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert!(!out
        .iter()
        .any(|a| a.metadata["subtype"] == json!("chat_message")));
}

/// The control that gives that marker its meaning: a readable SQLite database
/// with no `message` table ANSWERED the question — so it is not "unreadable".
/// But `EnMicroMsg.db` names WeChat and nothing else, and silence here renders
/// exactly like a phone with no WeChat messages; the answer is a schema note
/// saying the table this parser reads was not there, never a manufactured row.
#[test]
fn a_readable_database_without_the_message_table_is_not_silently_empty() {
    let path = std::env::temp_dir().join(format!("test_wechat_other_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (a INTEGER); INSERT INTO unrelated VALUES (1);")
            .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let out = run("EnMicroMsg.db", bytes);
    assert!(messages(&out).is_empty(), "no row is manufactured: {out:?}");
    assert!(
        !out.iter()
            .any(|a| a.metadata["status"] == "StoreUnreadable"),
        "an ANSWERED absence is not an unreadable store: {out:?}"
    );
    let notes = schema_notes(&out);
    assert_eq!(notes.len(), 1, "{out:?}");
    assert_eq!(notes[0].metadata["status"], "SchemaTableAbsent");
    assert_eq!(notes[0].metadata["table"], "message");
    assert_eq!(notes[0].metadata["content_incomplete"], true);
    assert_eq!(
        notes[0].metadata["content_incomplete_reason"],
        "unvalidated"
    );
}

/// B8-035: the gate required `content` + `createTime`, then hard-coded `talker`
/// and `isSend` into the SELECT. A schema that renamed or dropped either one
/// failed `prepare()`, and the parser returned an empty list — a WeChat
/// database with no messages.
///
/// Against the unfixed code `prepare()` fails and this returns nothing.
#[test]
fn a_message_table_without_talker_or_issend_still_yields_its_messages() {
    let path = std::env::temp_dir().join(format!("test_wechat_nocols_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE message (msgId INTEGER PRIMARY KEY, content TEXT, createTime INTEGER);
             INSERT INTO message VALUES (1, 'text with no peer column', 1673000000000);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let out = run("EnMicroMsg.db", bytes);
    let msgs = messages(&out);
    assert_eq!(
        msgs.len(),
        1,
        "the message is recoverable; only the peer and direction are not: {out:?}"
    );
    assert_eq!(msgs[0].metadata["text"], "text with no peer column");
    assert_eq!(msgs[0].metadata["date"].as_i64(), Some(1_673_000_000));
    // Absent, not guessed: a schema that never recorded the direction must not
    // have one asserted for it.
    assert!(msgs[0].metadata.get("direction").is_none());
    assert!(msgs[0].metadata.get("is_from_me").is_none());
    assert!(msgs[0].metadata.get("contact").is_none());
    // And disclosed, not passed over: the note names both logical fields the
    // records omit, without claiming the parse incomplete.
    let note = schema_notes(&out)
        .into_iter()
        .find(|a| a.metadata["status"] == "SchemaOptionalFieldsUnresolved")
        .expect("the absent peer and direction columns are disclosed");
    assert_eq!(
        note.metadata["schema_unresolved_fields"],
        json!(["peer", "is_sent"])
    );
    assert!(note.metadata.get("content_incomplete").is_none());
}

/// SQLCipher-shaped plaintext for `SqlCipherConfig::wechat()` (1024-byte pages,
/// 48 reserved bytes). It is deliberately NOT an openable database — byte 21
/// must be 64 for SQLite to accept a header, and it is zeroed here — so the
/// decrypt path is exercised without needing a real encrypted fixture.
fn wechat_shaped_plaintext(pages: usize) -> Vec<u8> {
    let cfg = seance_sqlcipher::SqlCipherConfig::wechat();
    let ps = cfg.page_size;
    let reserve = 48usize;
    let usable = ps - reserve;
    let mut v = vec![0u8; pages * ps];
    v[0..16].copy_from_slice(b"SQLite format 3\0");
    v[16..18].copy_from_slice(&(ps as u16).to_be_bytes());
    v[20] = reserve as u8;
    for i in 0..pages {
        let start = if i == 0 { 22 } else { 0 };
        for j in start..usable {
            v[i * ps + j] = ((i * 7 + j * 13) & 0xff) as u8;
        }
    }
    // SQLite requires 64 at byte 21; zero guarantees SQLITE_NOTADB on read.
    v[21] = 0;
    v
}

/// B8-013: the SQLCipher path called `decrypt`, which throws away the one fact
/// `seance_sqlcipher` exists to hand over — that not one page HMAC was
/// verified. Decrypted WeChat messages then looked like ordinary recovered
/// evidence, and a tampered or bit-rotted page yields plausible rows that read
/// exactly like sound ones.
///
/// Against the unfixed code the decrypted-but-unparseable store fell through to
/// the `EncryptedMessengerDatabase` record, which carries no integrity keys at
/// all, so every assert below fails.
#[test]
fn a_decrypted_wechat_store_carries_its_integrity_provenance() {
    let cfg = seance_sqlcipher::SqlCipherConfig::wechat();
    let pass = b"d41d8cd";
    let salt = [0x5au8; 16];
    let enc = seance_sqlcipher::encrypt_for_test(&wechat_shaped_plaintext(3), pass, &salt, &cfg);

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(enc));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "EnMicroMsg.db", "sqlcipher_key": "d41d8cd" }),
    );
    let out = WeChatParser.process(&art).unwrap();

    assert!(
        !out.is_empty(),
        "a store this tool DECRYPTED must not vanish from the case"
    );
    assert!(
        !out.iter()
            .any(|a| a.metadata["type"] == json!("EncryptedMessengerDatabase")),
        "the key worked; reporting the database as still encrypted is a false claim: {out:?}"
    );
    for a in &out {
        assert_eq!(a.metadata["decryption"], json!("SQLCipher"));
        // BUG-012 closed: the pages of an untampered store now authenticate,
        // and the record says so. This assertion was `json!(false)` for as long
        // as that was the truth.
        assert_eq!(
            a.metadata["integrity_verified"],
            json!(true),
            "every page of this fixture carries a valid HMAC, so the record must \
             report it as authenticated"
        );
        assert_eq!(a.metadata["decrypted_pages"], json!(3));
        let statement = a.metadata["integrity_statement"]
            .as_str()
            .expect("the examiner-facing sentence must travel with the plaintext");
        assert!(
            statement.contains("HMAC"),
            "the statement must name what was checked: {statement}"
        );
        assert!(
            a.metadata.get("integrity_failed_pages").is_none(),
            "nothing failed, so no page may be named as having done so"
        );
    }
}

/// A store with a tampered page is still surfaced, and every record it produced
/// names the page that failed.
///
/// The forensic point of BUG-012: an examiner must be able to tell a
/// conversation reconstructed from sound pages from one reconstructed out of a
/// page altered after the fact. Before the HMAC was verified the two were
/// indistinguishable on the page.
#[test]
fn a_tampered_store_names_the_page_that_failed() {
    let cfg = seance_sqlcipher::SqlCipherConfig::wechat();
    let mut enc = seance_sqlcipher::encrypt_for_test(
        &wechat_shaped_plaintext(3),
        b"d41d8cd",
        &[0x5au8; 16],
        &cfg,
    );
    // Flip a bit inside page 2's ciphertext.
    enc[cfg.page_size + 80] ^= 0x01;

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(enc));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "EnMicroMsg.db", "sqlcipher_key": "d41d8cd" }),
    );
    let out = WeChatParser.process(&art).unwrap();

    assert!(!out.is_empty(), "a tampered store must not vanish");
    for a in &out {
        assert_eq!(
            a.metadata["integrity_verified"],
            json!(false),
            "a store with an altered page must never read as authenticated"
        );
        assert_eq!(
            a.metadata["integrity_failed_pages"],
            json!([2]),
            "the failing page must be named on every record drawn from the store"
        );
    }
}

/// ROADMAP §1.4a. No real WeChat database is held by this project (the gated
/// `test_data/EnMicroMsg_encrypted.db` has never been provided), so this parser
/// declares NO validated range — a range endpoint not read out of a real file
/// would be a number copied from somewhere. It records the version it saw and
/// says it was compared against nothing. There is no "out of range" test here;
/// there cannot be.
#[test]
fn a_wechat_store_declares_no_validated_range_and_records_the_version_it_saw() {
    let arts = run("EnMicroMsg.db", decrypted_wechat_db_with(5, "content"));
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 3);
    seance_core::test_support::assert_no_incompleteness_stamps(msgs.iter().copied());

    let notes = schema_notes(&arts);
    assert_eq!(notes.len(), 1, "{arts:?}");
    let note = notes[0];
    assert_eq!(note.metadata["type"], "WeChatIncomplete");
    assert_eq!(note.metadata["status"], "SchemaNotRanged");
    assert_eq!(note.metadata["schema_version_seen"], 5);
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
fn a_wechat_store_that_never_recorded_a_version_is_disclosed_as_unrecorded_not_older() {
    let arts = run("EnMicroMsg.db", decrypted_wechat_db());
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
/// store full of messages (the B8-035 shape, one column over). Now what can be
/// parsed is, and the note names the LOGICAL field that went.
#[test]
fn a_wechat_store_that_renamed_the_body_column_claims_incompleteness_and_names_the_field() {
    let arts = run("EnMicroMsg.db", decrypted_wechat_db_with(0, "msg_text"));
    let msgs = messages(&arts);
    assert_eq!(msgs.len(), 3, "what can be parsed still is: {arts:?}");
    assert!(msgs.iter().all(|m| m.metadata.get("text").is_none()));
    assert_eq!(by_rowid(&arts, 2).metadata["direction"], "sent");

    let note = schema_notes(&arts)
        .into_iter()
        .find(|a| a.metadata["status"] == "SchemaFieldsUnresolved")
        .expect("the missing body column must be reported");
    assert_eq!(note.metadata["schema_unresolved_fields"], json!(["text"]));
    assert_eq!(note.metadata["content_incomplete"], true);
    assert_eq!(note.metadata["content_incomplete_reason"], "unvalidated");
    assert_eq!(note.metadata["inventory_incomplete"], true);
    assert_eq!(note.metadata["records_recovered"], 3);
    assert_eq!(note.metadata["subtype"], "parser_stale");
}
