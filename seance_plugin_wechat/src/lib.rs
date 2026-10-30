#![forbid(unsafe_code)]
//! WeChat (Android `EnMicroMsg.db`) message parser.
//!
//! [`WeChatParser`] self-selects WeChat's `EnMicroMsg.db` and handles the two
//! states an examiner encounters it in:
//!
//! - **Decrypted** (a plain SQLite database — the examiner has already removed
//!   the SQLCipher layer with the device key, as is routine): the `message`
//!   table is parsed into `chat_message`
//!   [`ParsedRecord`](ArtifactType::ParsedRecord)s, matching the shape used by
//!   the other messaging parsers.
//! - **Still encrypted** (SQLCipher — the file does not begin with the SQLite
//!   magic): if the examiner supplied key material (a raw `sqlcipher_key`, or the
//!   device `wechat_imei` + `wechat_uin` the key derives from), it is decrypted
//!   in place via [`seance_sqlcipher`] and then parsed; otherwise a single
//!   `EncryptedMessengerDatabase` record flags it for triage.
//!
//! Decryption is safe by construction: a wrong key yields bytes that are not a
//! valid SQLite database, so the reader rejects them and the file is flagged
//! rather than yielding wrong rows. The SQLCipher framing is validated in the
//! `seance_sqlcipher` crate; end-to-end confirmation against a real
//! `EnMicroMsg.db` is a gated test.
//!
//! # Schema (decrypted)
//!
//! `message`: `msgId`, `talker` (peer / chatroom id), `content` (text),
//! `createTime` (Unix **milliseconds**), `isSend` (1 = sent), `type`. The
//! columns are resolved through a field map, so a column the schema lacks is
//! **named** on a schema note rather than silently read as empty.
//!
//! # Schema version
//!
//! No real WeChat database is held by this project, so this parser declares
//! **no validated schema range**: a range endpoint not read out of a real file
//! would be a number copied from somewhere. It records the `PRAGMA user_version`
//! it sees on a `schema_support` note and states that it was compared against
//! nothing. The declaration gains a range when a device sample arrives.
//!
//! # Honesty & robustness
//!
//! A non-WeChat file, a missing `message` table, or corrupt rows never panic and
//! never fail the pipeline.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_catalogue, probe_columns, probe_table, stage_sqlite_db,
    unreadable_store_marker, ChatMessage, FieldMap, Presence, RowDrops, SqliteEntry, TempDb,
    MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub mod schema;
use schema::{
    assess, read_user_version, Observation, SchemaSupport, SupportBound, USER_VERSION_LOCATOR,
};

pub struct WeChatParser;

/// Every logical field read from `message`, with the physical column(s) that
/// have carried it. Written from the schema description this parser was built
/// to; no real store has confirmed it (see `MESSAGE_SUPPORT`).
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("peer", &["talker"]),
    ("text", &["content"]),
    ("sent_at", &["createTime"]),
    ("is_sent", &["isSend"]),
];

/// Without a body and a time a `message` row is not a message record.
const MESSAGE_REQUIRED: &[&str] = &["text", "sent_at"];

const MESSAGE_SUPPORT: SchemaSupport = SchemaSupport {
    app: "wechat-android",
    store: "EnMicroMsg.db",
    table: "message",
    record_type: INCOMPLETE_TYPE,
    locator: USER_VERSION_LOCATOR,
    bound: SupportBound::Unranged {
        why: "no real WeChat database is held by this project, so no schema version has been \
              read out of one; the version seen is recorded, not ranged",
    },
};

impl ForensicsModule for WeChatParser {
    fn id(&self) -> &str {
        "plugin.messaging.wechat"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact_name(artifact);
        if !is_wechat_db(name) {
            return Ok(Vec::new());
        }

        debug!("WeChatParser inspecting {name}");
        // The shared gate skips directories and artifacts with no reachable
        // content, probes the SQLite magic with a LOOPING read (a windowed or
        // container-backed source may answer a 16-byte request with 4, and a
        // single `read_at` would file a plain database as SQLCipher-encrypted),
        // then stages the database with its `-wal` sibling and records whether
        // it was staged in full. SQLite opens a truncated file and answers from
        // the pages it can reach, so without that record the surviving rows
        // read as the whole store (B2-124).
        let temp = match stage_sqlite_db(artifact, "wechat", MAX_DB_BYTES) {
            SqliteEntry::Staged(temp) => temp,
            // A FULL header that is not SQLite's is SQLCipher. The variant is
            // what keeps that honest: a source that ran out before sixteen
            // bytes has shown no header at all and lands in
            // `SqliteEntry::HeaderUnreadable`, so it cannot reach this arm and
            // assert something the evidence does not support.
            SqliteEntry::NotSqlite { data } => {
                // Decrypt in place when key material was supplied (a raw
                // passphrase, or the device IMEI + uin the WeChat key is derived
                // from). The ciphertext has to be in hand before SQLite will
                // open anything, so this path reads it itself instead of
                // spilling.
                let declared = data.size();
                let content = read_capped(data.as_ref(), MAX_DB_BYTES);
                // SQLCipher decrypts page by page, so a prefix of the ciphertext
                // decrypts to a prefix of the database and parses into a subset
                // of the conversations. That is still worth recovering — but it
                // is not the whole store, and it must not be emitted as though
                // it were.
                let short = if (content.len() as u64) >= declared {
                    None
                } else if declared > MAX_DB_BYTES {
                    Some(IncompleteReason::CapReached)
                } else {
                    Some(IncompleteReason::ShortRead)
                };
                if let Some(pass) = sqlcipher_passphrase(&artifact.metadata) {
                    // `decrypt_with_provenance`, not `decrypt`: the plaintext
                    // alone drops the one thing an examiner must be told about
                    // it — not one page HMAC was verified, so a tampered or
                    // bit-rotted page yields plausible messages that read
                    // exactly like sound ones. `seance_sqlcipher` documents that
                    // the caller has to carry that fact; this was the only
                    // product consumer of the crate and it carried nothing
                    // (B8-013).
                    if let Some(decryption) = seance_sqlcipher::decrypt_with_provenance(
                        &content,
                        &pass,
                        &seance_sqlcipher::SqlCipherConfig::wechat(),
                    ) {
                        if let Ok(mut temp) = TempDb::write(&decryption.plaintext, "wechat") {
                            if let Some(reason) = short {
                                temp.mark_content_incomplete(reason);
                            }
                            let mut out =
                                parse_messages(temp.path(), artifact.case_id, artifact.id);
                            temp.stamp_incompleteness(
                                artifact.case_id,
                                artifact.id,
                                name,
                                &mut out,
                            );
                            stamp_decryption_provenance(&mut out, &decryption);
                            // Returned even when empty. The key WORKED — the
                            // first page decrypted to a SQLite header — so
                            // falling through to the `Encrypted` record would
                            // report a database this tool did decrypt as one it
                            // could not, which is the same class of manufactured
                            // claim as the rest of this pass.
                            return Ok(out);
                        }
                    }
                }
                // No key, wrong key, or unexpected params: flag it for triage.
                return Ok(vec![encrypted_record(artifact.case_id, artifact.id)]);
            }
            // `EnMicroMsg.db` names WeChat and nothing else, and the header
            // matched, so this is a WeChat store this tool identified and did
            // not examine. An empty list here reads exactly like a phone that
            // never had WeChat installed.
            SqliteEntry::StagingFailed(e) => {
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    INCOMPLETE_TYPE,
                    format!("the WeChat database `{name}` carried the SQLite header and could not be staged for examination: {e}"),
                )])
            }
            _ => return Ok(Vec::new()),
        };
        let mut out = parse_messages(temp.path(), artifact.case_id, artifact.id);
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

fn is_wechat_db(name: &str) -> bool {
    name.to_ascii_lowercase().rsplit('/').next().unwrap_or("") == "enmicromsg.db"
}

/// Identification record for a still-encrypted WeChat database.
fn encrypted_record(case_id: Uuid, parent_id: Uuid) -> Artifact {
    seance_sqlite_util::encrypted_store_record(
        case_id,
        parent_id,
        "WeChat",
        "SQLCipher",
        "SQLCipher-encrypted; decrypt with the device key (MD5(IMEI+uin)) to parse messages.",
        "WeChat database (encrypted)".to_string(),
        &[],
    )
}

/// Carry onto every record what is, and is not, known about the decryption it
/// came out of.
///
/// What an examiner learns: these messages were recovered through SQLCipher and
/// their pages were NOT authenticated. What a wrong answer looks like: a
/// conversation in a report, attributed to a suspect, reconstructed out of a
/// page altered after the fact — indistinguishable, on the page, from one that
/// was not. `seance_sqlcipher::Decryption` exists so that a caller cannot
/// receive plaintext without also receiving that fact; before this it received
/// it and dropped it (B8-013).
///
/// `integrity_verified` was always read from the decryption rather than
/// hard-coded `false`, which is why closing BUG-012 needed no change to the
/// logic here: these records started saying "verified" the day the per-page
/// HMAC landed. What did change is that the statement is now stamped in **both**
/// directions — a record that authenticated says so affirmatively, rather than
/// carrying a silence an examiner has to interpret — and any page that failed is
/// named.
fn stamp_decryption_provenance(
    artifacts: &mut [Artifact],
    decryption: &seance_sqlcipher::Decryption,
) {
    for artifact in artifacts.iter_mut() {
        let Some(map) = artifact.metadata.as_object_mut() else {
            continue;
        };
        map.insert("decryption".into(), json!("SQLCipher"));
        map.insert("decrypted_pages".into(), json!(decryption.pages));
        map.insert(
            "integrity_verified".into(),
            json!(decryption.integrity_verified),
        );
        // Stamped whether or not it passed. "Verified" is a finding worth
        // stating, not merely the absence of a warning.
        map.insert(
            "integrity_statement".into(),
            json!(decryption.integrity_statement),
        );
        if !decryption.failed_pages.is_empty() {
            // Which pages, not just how many: an examiner has to be able to
            // work out which rows are affected.
            map.insert(
                "integrity_failed_pages".into(),
                json!(decryption.failed_pages),
            );
        }
    }
}

/// SQLCipher passphrase from the artifact metadata, if the examiner supplied it:
/// a raw `sqlcipher_key`, or `wechat_imei` + `wechat_uin` for the derived key.
fn sqlcipher_passphrase(meta: &serde_json::Value) -> Option<Vec<u8>> {
    if let Some(k) = meta.get("sqlcipher_key").and_then(|v| v.as_str()) {
        if !k.is_empty() {
            return Some(k.as_bytes().to_vec());
        }
    }
    let imei = meta.get("wechat_imei").and_then(|v| v.as_str())?;
    let uin = meta.get("wechat_uin").and_then(|v| v.as_str())?;
    if imei.is_empty() || uin.is_empty() {
        return None;
    }
    Some(seance_sqlcipher::wechat_passphrase(imei, uin))
}

/// The record type every WeChat incompleteness marker is filed under.
///
/// Never `"WeChat"`: `seance_db` groups conversations by `metadata.$.type`, so a
/// marker carrying the message type would be aggregated as a message and shown
/// as a phantom one-message conversation.
const INCOMPLETE_TYPE: &str = "WeChatIncomplete";

/// The record that says an `EnMicroMsg.db` was identified and could not be read.
/// Zero artifacts would render identically to a phone that never had WeChat.
fn unreadable(case_id: Uuid, parent_id: Uuid, detail: String) -> Vec<Artifact> {
    vec![unreadable_store_marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        detail,
    )]
}

fn parse_messages(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    // The caller has already established that this file is named EnMicroMsg.db
    // and either carried the SQLite header or decrypted to something that did,
    // so a store that will not open, or will not answer, is one this tool could
    // not read — reported, never returned as an empty conversation list
    // (B8-035, the silent-empty class of B8-015).
    let conn = match open_readonly(path) {
        Ok(c) => c,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the staged WeChat database would not open: {e}"),
            )
        }
    };
    // Ask whether the catalogue reads at all BEFORE any absence below is treated
    // as a fact about the phone: on a damaged page 1 every probe fails for the
    // same reason, and answering them "not there" reports a corrupt store as an
    // account with no history.
    if let Err(why) = probe_catalogue(&conn) {
        return unreadable(
            case_id,
            parent_id,
            format!(
                "the WeChat database opened and its schema catalogue would not read, so whether \
                 it holds messages is undetermined rather than answered: {why}"
            ),
        );
    }
    match probe_table(&conn, "message") {
        // The catalogue ANSWERED, so this is a finding and not an unreadable
        // store — but `EnMicroMsg.db` names WeChat and nothing else, and
        // silence renders exactly like a phone with no WeChat messages. The
        // schema note says the table this parser reads was not there.
        Presence::Absent => {
            let obs = Observation {
                version: read_user_version(&conn),
                fields: None,
                required: MESSAGE_REQUIRED,
                recovered: 0,
            };
            return assess(&MESSAGE_SUPPORT, &obs, case_id, parent_id);
        }
        Presence::Undetermined(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `message` table could not be looked for: {why}"),
            )
        }
        Presence::Present => {}
    }
    let cols = match probe_columns(&conn, "message") {
        Ok(c) => c,
        // The table IS listed and its column list will not read: a damaged
        // store, never "no such columns".
        Err(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("`message` is present and its column list would not read: {why}"),
            )
        }
    };
    let fields = FieldMap::resolve(&cols, MESSAGE_FIELDS);
    let version = read_user_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: MESSAGE_REQUIRED,
            recovered,
        };
        assess(&MESSAGE_SUPPORT, &obs, case_id, parent_id)
    };
    // A table with neither a body nor a time is not the one this parser
    // knows; say so rather than manufacture rows from it.
    if MESSAGE_REQUIRED.iter().all(|f| fields.column(f).is_none()) {
        return assessment(0);
    }
    let id_col = if cols.contains("msgid") {
        "msgId"
    } else {
        "rowid"
    };
    // `talker` and `isSend` were once hard-coded into the SELECT, so a schema
    // that renamed either failed `prepare()` and returned an empty list — a
    // WeChat database with no messages (B8-035). Every `NULL` below stands for
    // a logical field the map recorded as unresolved and the assessment names;
    // `build_record` treats an absent talker/direction as unknown, never as
    // asserted.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let talker_expr = col("peer");
    let text_expr = col("text");
    let time_expr = col("sent_at");
    let is_send_expr = col("is_sent");
    let sql = format!(
        "SELECT {id_col}, {talker_expr}, {text_expr}, {time_expr}, {is_send_expr} \
         FROM message ORDER BY {time_expr}"
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `message` query would not prepare: {e}"),
            )
        }
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `message` walk would not run: {e}"),
            )
        }
    };

    let mut out = Vec::new();
    // Rows the query returned that could not be decoded. `flatten()` used to
    // swallow these, so the message count read as exact (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (id, talker, content, create_ms, is_send) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("WeChat: skipping undecodable message row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        out.push(build_record(
            case_id, parent_id, id, talker, content, create_ms, is_send,
        ));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(case_id, parent_id, INCOMPLETE_TYPE, "message", recovered));
    out.extend(assessment(recovered));
    out
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: i64,
    talker: Option<String>,
    content: Option<String>,
    create_ms: Option<i64>,
    is_send: Option<i64>,
) -> Artifact {
    // `isSend` is 1 for a message the device owner sent. A NULL — or a schema
    // with no direction column — never recorded it, so it stays unknown rather
    // than being asserted as inbound. `ChatMessage` derives `direction` from
    // this single value, so the two cannot disagree.
    let is_from_me = is_send.map(|v| v == 1);
    let date_s = create_ms.filter(|&d| d > 0).map(|d| d.div_euclid(1000));
    // WeChat's `talker` is both the conversation key and the only identity the
    // `message` table carries for the other party, so it is emitted as both.
    let talker = talker.filter(|s| !s.is_empty());

    ChatMessage::new("WeChat", "WeChat", "Android")
        .text(content)
        .date_secs(date_s)
        .from_me(is_from_me)
        .chat_identifier(talker.clone())
        .contact(talker)
        .extra("rowid", json!(id))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
