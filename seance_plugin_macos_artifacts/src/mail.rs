//! Apple Mail's on-device index — `Envelope Index` (`ROADMAP` §3.10).
//!
//! # What this reads, and what it is not
//!
//! macOS Mail keeps a SQLite index of every message it has seen at
//! `~/Library/Mail/V*/MailData/Envelope Index`. It is an **index**, not the
//! mail: the subject, the sender, the recipients, the mailbox, the dates, the
//! read and flagged state, the size, the attachment names and Mail's own
//! one-line snippet — but no body, and no RFC 5322 headers.
//!
//! That distinction is the whole reason this reader is careful about what it
//! publishes. A record from a PST or an `.eml` carries a body and a real
//! `Message-ID`; one from here cannot, and must not be rendered as a message
//! whose body happened to be empty. So the body fields are **stated absences**
//! rather than empty strings, and `messages.message_id` — which is an *integer
//! hash* in this schema, not the header — is published under its own name with
//! that said on it. Putting a hash in the field that elsewhere holds an RFC 5322
//! `Message-ID` would make two different things look like one.
//!
//! # The mail is still worth having without the mail
//!
//! Who wrote to whom, when, about what, in which mailbox, with which files
//! attached and whether it was read — on a machine whose mail was
//! server-hosted, the index is frequently the only copy of that on the disk.
//! A deleted message whose `.emlx` is gone can still have its row here, and
//! `deleted` is on the record for exactly that reason.
//!
//! # The two things this reader will not assert
//!
//! **The timestamp basis.** These columns are integers, and Apple Mail has
//! written them as Unix epoch seconds in every version examined — but no
//! database this project holds has a populated row to confirm it against, so
//! the record names the basis it read them under instead of presenting the
//! instant as established. See [`DATE_BASIS`].
//!
//! **That it has been run against a populated mailbox.** The schema here is
//! Apple's own, read from a real macOS 11 `Envelope Index` (Mail V8, database
//! version 4.30006, from the Magnet 2021 CTF image). Its tables are **empty** —
//! Mail was opened on that machine and no account ever synced — so every join
//! below is exercised against rows written into Apple's schema rather than
//! against rows Apple wrote. That is on every record as
//! `basis: "schema_verified_rows_unverified"`, for the reason the macOS memory
//! tier ships with its own such label: an examiner can discount a result that
//! says what it has not been proven against, and cannot discount a result they
//! were never shown.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{cap_marker, probe_table, CapCounter, Presence, TempDb};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{basename_lower, staged_looks_like_sqlite, to_rfc3339, MAX_DB_BYTES};

/// Messages emitted from one index.
///
/// A mailbox of a quarter of a million messages is ordinary on a machine that
/// has had one account for a decade, and each row here is small. The walk is
/// newest-first so a truncated read keeps the recent end, which is the end a
/// case is usually about, and the truncation is reported.
const ROW_CAP: usize = 250_000;

/// Recipient rows read per message.
///
/// A mailing-list message can name thousands. Sixty-four is more than any
/// human correspondence and the count is published beside the list, so a
/// truncated recipient list is never mistaken for the whole one.
const RECIPIENT_CAP: usize = 64;

/// Attachment rows read per message.
const ATTACHMENT_CAP: usize = 64;

/// What the integer date columns were read as.
///
/// Published on every record rather than assumed silently. Apple Mail has
/// written `date_sent`, `date_received` and `date_last_viewed` as Unix epoch
/// seconds in every version examined, and this reader reads them that way — but
/// no `Envelope Index` this project holds has a populated row to confirm it
/// against, and a date read under the wrong epoch is off by 31 years while
/// looking entirely ordinary. Core Data's own 2001 epoch, used by
/// `knowledgeC.db` a few files away, is the mistake this names to avoid.
pub const DATE_BASIS: &str = "read as Unix epoch seconds, which is what Apple Mail writes in \
                              every version examined; NOT confirmed against a populated \
                              database, because no Envelope Index this project holds has one. \
                              A date read under Core Data's 2001 epoch instead would be 31 \
                              years out and would look entirely ordinary";

/// What this reader has and has not been proven against.
pub const VALIDATION_BASIS: &str = "schema_verified_rows_unverified";

/// The sentence that label stands for.
pub const VALIDATION_STATEMENT: &str = "the schema these joins were written against is Apple's \
                                        own, read from a real macOS 11 Envelope Index (Mail V8, \
                                        database version 4.30006); that database's tables are \
                                        empty, so no row here has been read from a mailbox Apple \
                                        populated. Treat the field mapping as unconfirmed on \
                                        real mail until it is graded against one";

/// Which header a recipient row belongs to.
///
/// `recipients.type` is an integer. The three values are stated as Mail uses
/// them and an unrecognised one is reported as the number rather than guessed
/// into a header, because putting a blind-copied address in the `To` column
/// would misstate who could see whom.
fn recipient_header(kind: Option<i64>) -> (&'static str, Option<i64>) {
    match kind {
        Some(0) => ("to", None),
        Some(1) => ("cc", None),
        Some(2) => ("bcc", None),
        Some(other) => ("unrecognised", Some(other)),
        None => ("unstated", None),
    }
}

/// Emits one `EmailMessage` record per indexed message.
pub struct AppleMailParser;

fn is_envelope_index(name: &str) -> bool {
    // Mail has shipped this file under one name since V2, with no extension.
    // The `-wal` and `-shm` siblings are not it: reading a write-ahead log as
    // a database yields nothing, and claiming to have read the mailbox from
    // one would be worse than declining.
    basename_lower(name) == "envelope index"
}

impl ForensicsModule for AppleMailParser {
    fn id(&self) -> &str {
        "macos.apple_mail"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_envelope_index(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = TempDb::spill(ds.as_ref(), "envelope_index", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            if !staged_looks_like_sqlite(temp.path()) {
                return Ok(Vec::new());
            }
            let conn = temp.open().context("open Envelope Index")?;
            match probe_table(&conn, "messages") {
                Presence::Present => {}
                Presence::Absent => return Ok(Vec::new()),
                Presence::Undetermined(why) => anyhow::bail!("schema unreadable: {why}"),
            }
            parse_messages(&conn, artifact.case_id, artifact.id, name, ROW_CAP)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "AppleMailParser: {} indexed message(s) from {name}",
                    artifacts.len()
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("AppleMailParser failed on {name}: {e}");
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "EmailParseStatus",
                        "subtype": "parse_incomplete",
                        "file_name": name,
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "content_incomplete": true,
                        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    }),
                )
                .with_parent(artifact.id)])
            }
        }
    }
}

/// One message's recipients, and whether the list is all of them.
struct Recipients {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    /// Addresses whose `type` this build does not recognise, kept out of the
    /// three header lists rather than guessed into one.
    unrecognised: Vec<String>,
    total: usize,
    truncated: bool,
}

/// One `LIMIT cap + 1` read, not a `COUNT(*)` and then a read.
///
/// A separate count per message is a second index walk per message, and on a
/// schema whose `recipients` index is missing or unusable — which an
/// attacker-supplied database can arrange, and a corrupt one can be — each
/// count becomes a full table scan and the reader is quadratic in the mailbox.
/// Reading one row past the cap says both what to show and whether there was
/// more, which is the only thing the count was for.
fn recipients_of(conn: &Connection, message: i64) -> Result<Recipients> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT r.type, a.address, a.comment FROM recipients r \
             LEFT JOIN addresses a ON a.ROWID = r.address_id \
             WHERE r.message_id = ?1 ORDER BY r.position LIMIT ?2",
        )
        .context("prepare recipients query")?;
    let mut rows = stmt
        .query(rusqlite::params![message, RECIPIENT_CAP as i64 + 1])
        .context("query recipients")?;
    let mut out = Recipients {
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        unrecognised: Vec::new(),
        total: 0,
        truncated: false,
    };
    while let Some(row) = rows.next().context("read recipient row")? {
        out.total += 1;
        if out.total > RECIPIENT_CAP {
            // The one row past the cap. It is counted and not listed, and
            // `total` is then a floor rather than a total -- which
            // `truncated` is what says.
            out.truncated = true;
            break;
        }
        let kind: Option<i64> = row.get(0)?;
        let address: Option<String> = row.get(1)?;
        let comment: Option<String> = row.get(2)?;
        let rendered = render_address(address.as_deref(), comment.as_deref());
        match recipient_header(kind).0 {
            "to" => out.to.push(rendered),
            "cc" => out.cc.push(rendered),
            "bcc" => out.bcc.push(rendered),
            _ => out.unrecognised.push(rendered),
        }
    }
    Ok(out)
}

/// `Display Name <address>` where Mail recorded a name, the bare address where
/// it did not, and a stated absence where it recorded neither — never an empty
/// string, which reads as an address that is there and blank.
fn render_address(address: Option<&str>, comment: Option<&str>) -> String {
    let address = address.map(str::trim).filter(|a| !a.is_empty());
    let comment = comment.map(str::trim).filter(|c| !c.is_empty());
    match (address, comment) {
        (Some(a), Some(c)) => format!("{c} <{a}>"),
        (Some(a), None) => a.to_string(),
        (None, Some(c)) => format!("{c} (no address recorded)"),
        (None, None) => "(no address recorded)".to_string(),
    }
}

/// One message's attachment names, and whether the list is all of them.
struct Attachments {
    names: Vec<String>,
    total: usize,
    truncated: bool,
}

fn attachments_of(conn: &Connection, message: i64) -> Result<Attachments> {
    let mut stmt = conn
        .prepare_cached("SELECT name FROM attachments WHERE message = ?1 ORDER BY name LIMIT ?2")
        .context("prepare attachments query")?;
    let mut rows = stmt
        .query(rusqlite::params![message, ATTACHMENT_CAP as i64 + 1])
        .context("query attachments")?;
    let mut names = Vec::new();
    let mut total = 0usize;
    let mut truncated = false;
    while let Some(row) = rows.next().context("read attachment row")? {
        total += 1;
        if total > ATTACHMENT_CAP {
            truncated = true;
            break;
        }
        let name: Option<String> = row.get(0)?;
        names.push(name.unwrap_or_else(|| "(unnamed attachment)".to_string()));
    }
    Ok(Attachments {
        names,
        total,
        truncated,
    })
}

/// A date column, as a value and as the basis it was read under.
fn date_fields(value: Option<i64>) -> (Option<i64>, Option<String>) {
    // Zero is Mail's "not recorded", not 1970-01-01. Rendering it as an
    // instant would put a 1970 date on every message Mail never displayed.
    let value = value.filter(|v| *v > 0);
    (value, value.and_then(to_rfc3339))
}

fn parse_messages(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    row_cap: usize,
) -> Result<Vec<Artifact>> {
    let mut cap = CapCounter::new(row_cap);
    // Newest first, so a truncated read keeps the recent end.
    let mut stmt = conn
        .prepare(
            "SELECT m.ROWID, m.message_id, m.date_sent, m.date_received, m.date_last_viewed, \
             m.size, m.read, m.flagged, m.deleted, m.snippet, m.subject_prefix, \
             s.subject, a.address, a.comment, b.url, m.conversation_id, m.type \
             FROM messages m \
             LEFT JOIN subjects s ON s.ROWID = m.subject \
             LEFT JOIN addresses a ON a.ROWID = m.sender \
             LEFT JOIN mailboxes b ON b.ROWID = m.mailbox \
             ORDER BY m.date_received DESC LIMIT ?1",
        )
        .context("prepare messages query")?;
    let mut rows = stmt.query([cap.limit()]).context("query messages")?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().context("read message row")? {
        if !cap.admit() {
            break;
        }
        let rowid: i64 = row.get(0)?;
        let message_id_hash: Option<i64> = row.get(1)?;
        let (sent, sent_rfc) = date_fields(row.get(2)?);
        let (received, received_rfc) = date_fields(row.get(3)?);
        let (viewed, viewed_rfc) = date_fields(row.get(4)?);
        let size: Option<i64> = row.get(5)?;
        let read: Option<i64> = row.get(6)?;
        let flagged: Option<i64> = row.get(7)?;
        let deleted: Option<i64> = row.get(8)?;
        let snippet: Option<String> = row.get(9)?;
        let subject_prefix: Option<String> = row.get(10)?;
        let subject: Option<String> = row.get(11)?;
        let sender_address: Option<String> = row.get(12)?;
        let sender_comment: Option<String> = row.get(13)?;
        let mailbox_url: Option<String> = row.get(14)?;
        let conversation: Option<i64> = row.get(15)?;
        let kind: Option<i64> = row.get(16)?;

        let recipients = recipients_of(conn, rowid)?;
        let attachments = attachments_of(conn, rowid)?;

        // Mail stores the `Re: ` / `Fwd: ` prefix apart from the subject it
        // normalised away, so the subject an examiner would read is the two
        // joined. Kept as separate fields too, since the prefix is the
        // evidence that a message is a reply.
        let full_subject = match (subject_prefix.as_deref(), subject.as_deref()) {
            (Some(p), Some(s)) if !p.is_empty() => Some(format!("{p}{s}")),
            (_, Some(s)) => Some(s.to_string()),
            (Some(p), None) if !p.is_empty() => Some(p.to_string()),
            _ => None,
        };

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("EmailMessage"));
        meta.insert("analysis_type".into(), json!("email"));
        meta.insert("subtype".into(), json!("apple_mail_index"));
        meta.insert("format".into(), json!("apple_mail_envelope_index"));
        meta.insert("container".into(), json!(file_name));
        meta.insert(
            "from".into(),
            json!(sender_address
                .as_deref()
                .map(str::trim)
                .filter(|a| !a.is_empty())),
        );
        meta.insert("from_name".into(), json!(sender_comment));
        meta.insert("to".into(), json!(recipients.to));
        meta.insert("cc".into(), json!(recipients.cc));
        meta.insert("bcc".into(), json!(recipients.bcc));
        if !recipients.unrecognised.is_empty() {
            meta.insert(
                "recipients_unrecognised_type".into(),
                json!(recipients.unrecognised),
            );
        }
        meta.insert("recipient_count".into(), json!(recipients.total));
        meta.insert("recipients_truncated".into(), json!(recipients.truncated));
        if recipients.truncated {
            meta.insert(
                "recipient_count_is_a_floor".into(),
                json!(format!(
                    "more than {RECIPIENT_CAP} addresses were named and the read stopped there, so the count is at least this many rather than exactly this many"
                )),
            );
        }
        if attachments.truncated {
            meta.insert(
                "attachment_count_is_a_floor".into(),
                json!(format!(
                    "more than {ATTACHMENT_CAP} attachments were named and the read stopped there, so the count is at least this many rather than exactly this many"
                )),
            );
        }
        meta.insert("subject".into(), json!(full_subject));
        meta.insert("subject_prefix".into(), json!(subject_prefix));
        meta.insert("date".into(), json!(received_rfc));
        meta.insert("date_epoch".into(), json!(received));
        meta.insert("date_sent".into(), json!(sent_rfc));
        meta.insert("date_sent_epoch".into(), json!(sent));
        meta.insert("date_last_viewed".into(), json!(viewed_rfc));
        meta.insert("date_last_viewed_epoch".into(), json!(viewed));
        meta.insert("date_basis".into(), json!(DATE_BASIS));
        meta.insert("size".into(), json!(size));
        meta.insert("read".into(), json!(read.map(|v| v != 0)));
        meta.insert("flagged".into(), json!(flagged.map(|v| v != 0)));
        meta.insert("deleted".into(), json!(deleted.map(|v| v != 0)));
        meta.insert("mailbox".into(), json!(mailbox_url));
        meta.insert(
            "conversation_id".into(),
            json!(conversation.filter(|c| *c >= 0)),
        );
        meta.insert("message_type".into(), json!(kind));
        meta.insert("snippet".into(), json!(snippet));
        meta.insert("attachment_count".into(), json!(attachments.total));
        meta.insert("attachments".into(), json!(attachments.names));
        meta.insert("attachments_truncated".into(), json!(attachments.truncated));
        meta.insert("has_attachments".into(), json!(attachments.total > 0));
        // An INTEGER hash in this schema, not the RFC 5322 header. Published
        // under its own name so it cannot be read as one.
        meta.insert("message_id_hash".into(), json!(message_id_hash));
        meta.insert(
            "message_id_hash_note".into(),
            json!(
                "Mail stores an integer hash of the RFC 5322 Message-ID here, not the header \
                   itself, so it identifies a message only within this database"
            ),
        );
        // The body is not in the index at all, and an empty string here would
        // read as a message that had none.
        meta.insert("body_text".into(), json!(null));
        meta.insert("body_html".into(), json!(null));
        meta.insert(
            "body_absent_reason".into(),
            json!(
                "the Envelope Index holds no message bodies -- it is Mail's index, and the \
                   body lives in an .emlx file this record does not reach"
            ),
        );
        meta.insert("basis".into(), json!(VALIDATION_BASIS));
        meta.insert("basis_statement".into(), json!(VALIDATION_STATEMENT));
        // Every record is short of a whole message by construction, and says
        // which parts and why rather than reading as a complete one.
        meta.insert("content_complete".into(), json!(false));
        meta.insert("content_incomplete".into(), json!(true));
        meta.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::Unvalidated.as_str()),
        );
        meta.insert(
            "content_incomplete_detail".into(),
            json!(format!(
                "{VALIDATION_STATEMENT}. The index also holds no body: see \
                           body_absent_reason"
            )),
        );

        let who = sender_address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .unwrap_or("(sender?)");
        let what = full_subject.as_deref().unwrap_or("(no subject)");
        meta.insert("name".into(), json!(format!("{who}: {what}")));

        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
                .with_parent(parent_id)
                .with_subtype("apple_mail_index"),
        );
    }

    if cap.truncated() {
        // The walk is newest-first, so what a cap drops is the oldest end --
        // which is what `cap_marker`'s own sentence says.
        //
        // `cap_marker` files it under subtype `parse_incomplete`, and that is
        // left alone: overwritten with the messages' own subtype, the marker
        // was filed with the rows it failed to finish (HUNT-179).
        out.push(cap_marker(
            case_id,
            parent_id,
            "EmailParseStatus",
            "messages",
            &cap,
        ));
    }
    let _ = file_name;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    /// Apple's own DDL, dumped from a real macOS 11 `Envelope Index`.
    ///
    /// The schema is the part of this fixture that this project did not write,
    /// which is what `documentation/TESTING.md`'s rule about using at least one
    /// input written elsewhere asks for. Its provenance is in
    /// `tests/fixtures/README.md`; the rows below are ours, and every record
    /// the reader emits says so.
    const APPLE_SCHEMA: &str = include_str!("../tests/fixtures/envelope_index_v8_schema.sql");

    /// One message to write into Apple's schema.
    struct Message {
        rowid: i64,
        sender: &'static str,
        sender_name: &'static str,
        subject_prefix: Option<&'static str>,
        subject: &'static str,
        date_sent: i64,
        date_received: i64,
        date_last_viewed: i64,
        read: i64,
        flagged: i64,
        deleted: i64,
        mailbox: &'static str,
        snippet: Option<&'static str>,
        /// `(type, address, display name)` — type 0 to, 1 cc, 2 bcc.
        recipients: &'static [(i64, &'static str, &'static str)],
        attachments: &'static [&'static str],
    }

    fn build(messages: &[Message]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("envidx_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Envelope Index");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(APPLE_SCHEMA)
                .expect("Apple's own schema applies cleanly");
            let mut address_id = 1i64;
            let mut mailbox_id = 1i64;
            // Apple's schema declares `UNIQUE(address, comment)` on
            // `addresses`, and Mail reuses the row rather than inserting a
            // second one. The builder does the same, so the fixture obeys the
            // constraint the real database is under instead of working round
            // it.
            let mut addresses: std::collections::HashMap<(String, String), i64> =
                std::collections::HashMap::new();
            let mut mailboxes: std::collections::HashMap<&str, i64> =
                std::collections::HashMap::new();
            let mut address_of =
                |conn: &Connection, address: &str, comment: &str, next: &mut i64| -> i64 {
                    let key = (address.to_string(), comment.to_string());
                    if let Some(id) = addresses.get(&key) {
                        return *id;
                    }
                    let id = *next;
                    *next += 1;
                    conn.execute(
                        "INSERT INTO addresses (ROWID, address, comment) VALUES (?1,?2,?3)",
                        rusqlite::params![id, address, comment],
                    )
                    .unwrap();
                    addresses.insert(key, id);
                    id
                };
            for (subject_id, m) in (1i64..).zip(messages.iter()) {
                let sender_id = address_of(&conn, m.sender, m.sender_name, &mut address_id);
                conn.execute(
                    "INSERT INTO subjects (ROWID, subject, normalized_subject) VALUES (?1,?2,?3)",
                    rusqlite::params![subject_id, m.subject, m.subject],
                )
                .unwrap();
                // `mailboxes.url` is UNIQUE in Apple's schema, and two
                // messages in one mailbox share the row.
                let mailbox_row = match mailboxes.get(m.mailbox) {
                    Some(id) => *id,
                    None => {
                        let id = mailbox_id;
                        mailbox_id += 1;
                        conn.execute(
                            "INSERT INTO mailboxes (ROWID, url) VALUES (?1,?2)",
                            rusqlite::params![id, m.mailbox],
                        )
                        .unwrap();
                        mailboxes.insert(m.mailbox, id);
                        id
                    }
                };
                // `global_message_id` is NOT NULL with a foreign key, so the
                // row it names exists -- Apple's schema is being honoured
                // rather than worked around.
                conn.execute(
                    "INSERT INTO message_global_data (ROWID) VALUES (?1)",
                    rusqlite::params![m.rowid],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO messages (ROWID, message_id, global_message_id, sender, \
                     subject_prefix, subject, date_sent, date_received, date_last_viewed, \
                     mailbox, flags, read, flagged, size, type, conversation_id, snippet, \
                     deleted) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11,?12,?13,0,-1,?14,?15)",
                    rusqlite::params![
                        m.rowid,
                        // Mail's integer hash of the RFC 5322 Message-ID.
                        m.rowid * 7919,
                        m.rowid,
                        sender_id,
                        m.subject_prefix,
                        subject_id,
                        m.date_sent,
                        m.date_received,
                        m.date_last_viewed,
                        mailbox_row,
                        m.read,
                        m.flagged,
                        4096,
                        m.snippet,
                        m.deleted,
                    ],
                )
                .unwrap();
                for (position, (kind, address, name)) in m.recipients.iter().enumerate() {
                    let rid = address_of(&conn, address, name, &mut address_id);
                    conn.execute(
                        "INSERT INTO recipients (message_id, type, address_id, position) \
                         VALUES (?1,?2,?3,?4)",
                        rusqlite::params![m.rowid, kind, rid, position as i64],
                    )
                    .unwrap();
                }
                for (index, name) in m.attachments.iter().enumerate() {
                    conn.execute(
                        "INSERT INTO attachments (message, attachment_id, name) \
                         VALUES (?1,?2,?3)",
                        rusqlite::params![m.rowid, format!("att{index}"), name],
                    )
                    .unwrap();
                }
            }
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn run_named(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name }),
        );
        AppleMailParser.process(&art).unwrap()
    }

    fn run(bytes: Vec<u8>) -> Vec<Artifact> {
        run_named(bytes, "Users/e/Library/Mail/V8/MailData/Envelope Index")
    }

    fn one() -> Message {
        Message {
            rowid: 1,
            sender: "lilytuckrige@yahoo.com",
            sender_name: "Lily Tuckrige",
            subject_prefix: None,
            subject: "Tuesday's lesson",
            // 2021-02-21T12:00:00Z and a minute later.
            date_sent: 1_613_908_800,
            date_received: 1_613_908_860,
            date_last_viewed: 1_613_909_000,
            read: 1,
            flagged: 0,
            deleted: 0,
            mailbox: "imap://eliflatt@imap.mail.me.com/INBOX",
            snippet: Some("Could we move it to Thursday?"),
            recipients: &[
                (0, "eliflatt@icloud.com", "Eli Flatt"),
                (1, "office@school.example", "School Office"),
            ],
            attachments: &["timetable.pdf"],
        }
    }

    #[test]
    fn a_message_row_becomes_an_email_record_with_the_people_the_index_names() {
        let out = run(build(&[one()]));
        let m = &out
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .expect("one message record")
            .metadata;
        assert_eq!(m["from"], "lilytuckrige@yahoo.com");
        assert_eq!(m["from_name"], "Lily Tuckrige");
        assert_eq!(m["subject"], "Tuesday's lesson");
        assert_eq!(m["to"], json!(["Eli Flatt <eliflatt@icloud.com>"]));
        assert_eq!(m["cc"], json!(["School Office <office@school.example>"]));
        assert_eq!(m["bcc"], json!([]));
        assert_eq!(m["recipient_count"], 2);
        assert_eq!(m["mailbox"], "imap://eliflatt@imap.mail.me.com/INBOX");
        assert_eq!(m["attachment_count"], 1);
        assert_eq!(m["attachments"], json!(["timetable.pdf"]));
        assert_eq!(m["has_attachments"], true);
        assert_eq!(m["read"], true);
        assert_eq!(m["flagged"], false);
        assert_eq!(m["deleted"], false);
        assert_eq!(m["snippet"], "Could we move it to Thursday?");
        assert_eq!(m["format"], "apple_mail_envelope_index");
    }

    #[test]
    fn a_blind_copy_is_never_reported_in_the_to_column() {
        // Who could see whom is the finding. Folding a bcc into `to` would
        // assert that a recipient knew about a copy the sender hid from them.
        let mut msg = one();
        msg.recipients = &[
            (0, "a@example.com", "A"),
            (2, "hidden@example.com", "Hidden"),
        ];
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(m["to"], json!(["A <a@example.com>"]));
        assert_eq!(m["bcc"], json!(["Hidden <hidden@example.com>"]));
        assert_eq!(m["cc"], json!([]));
    }

    #[test]
    fn a_recipient_type_this_build_does_not_know_is_kept_out_of_all_three_headers() {
        // Mail could add a value; guessing it into `to` would put an address
        // in a column that claims something about who saw the message.
        let mut msg = one();
        msg.recipients = &[(7, "unknown@example.com", "Unknown")];
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(m["to"], json!([]));
        assert_eq!(m["cc"], json!([]));
        assert_eq!(m["bcc"], json!([]));
        assert_eq!(
            m["recipients_unrecognised_type"],
            json!(["Unknown <unknown@example.com>"])
        );
        assert_eq!(m["recipient_count"], 1, "and it is still counted");
    }

    #[test]
    fn the_index_holds_no_body_and_says_so_rather_than_showing_an_empty_one() {
        // An empty string in `body_text` reads as a message that had no body.
        // This record cannot reach a body at all, and the difference is the
        // whole point of the field.
        let out = run(build(&[one()]));
        let m = &out[0].metadata;
        assert_eq!(m["body_text"], json!(null));
        assert_eq!(m["body_html"], json!(null));
        let why = m["body_absent_reason"].as_str().unwrap();
        assert!(why.contains("holds no message bodies"), "{why}");
        assert!(why.contains(".emlx"), "{why}");
    }

    #[test]
    fn the_integer_hash_is_not_published_as_an_rfc_message_id() {
        // `messages.message_id` is an integer hash in this schema. Putting it
        // in the field that elsewhere holds the RFC 5322 header would make two
        // different things look like one.
        let out = run(build(&[one()]));
        let m = &out[0].metadata;
        assert!(
            m.get("message_id").is_none(),
            "there is no RFC 5322 Message-ID in this index to publish"
        );
        assert_eq!(m["message_id_hash"], 7919);
        assert!(m["message_id_hash_note"]
            .as_str()
            .unwrap()
            .contains("not the header"));
    }

    #[test]
    fn a_recipient_list_past_the_cap_reports_its_count_as_a_floor() {
        // The cap path, which no test exercised. A count that is really "at
        // least this many" printed as a total understates who saw the message.
        let names: Vec<(i64, String, String)> = (0..RECIPIENT_CAP + 5)
            .map(|i| (0i64, format!("r{i}@example.com"), format!("R{i}")))
            .collect();
        let leaked: &'static [(i64, &'static str, &'static str)] = Box::leak(
            names
                .iter()
                .map(|(k, a, n)| {
                    (
                        *k,
                        Box::leak(a.clone().into_boxed_str()) as &'static str,
                        Box::leak(n.clone().into_boxed_str()) as &'static str,
                    )
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let mut msg = one();
        msg.recipients = leaked;
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(m["to"].as_array().map(Vec::len), Some(RECIPIENT_CAP));
        assert_eq!(m["recipients_truncated"], true);
        assert_eq!(
            m["recipient_count"],
            RECIPIENT_CAP + 1,
            "what was counted: the read stops one row past the cap, so the count is 65 beside \
             a list of 64 -- at least this many, which is what the floor sentence says"
        );
        assert!(m["recipient_count_is_a_floor"]
            .as_str()
            .unwrap()
            .contains("at least this many"));
    }

    #[test]
    fn an_attachment_list_past_the_cap_reports_its_count_as_a_floor() {
        let names: Vec<String> = (0..ATTACHMENT_CAP + 3)
            .map(|i| format!("f{i}.pdf"))
            .collect();
        let leaked: &'static [&'static str] = Box::leak(
            names
                .iter()
                .map(|n| Box::leak(n.clone().into_boxed_str()) as &'static str)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let mut msg = one();
        msg.attachments = leaked;
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(
            m["attachments"].as_array().map(Vec::len),
            Some(ATTACHMENT_CAP)
        );
        assert_eq!(m["attachments_truncated"], true);
        assert!(m["attachment_count_is_a_floor"]
            .as_str()
            .unwrap()
            .contains("at least this many"));
        assert_eq!(m["has_attachments"], true);
    }

    #[test]
    fn the_message_ceiling_says_what_it_dropped() {
        // The row cap, which no test reached either. The walk is newest-first,
        // so a cap drops the oldest end -- and the marker has to say so.
        let messages: Vec<Message> = (0..3)
            .map(|i| {
                let mut m = one();
                m.rowid = i + 1;
                m.date_received = 1_613_908_860 - i;
                m
            })
            .collect();
        let bytes = build(&messages);
        // Drive the cap directly rather than building a quarter of a million
        // rows: the marker is what is under test.
        let temp = std::env::temp_dir().join(format!("envcap_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp).unwrap();
        let path = temp.join("Envelope Index");
        std::fs::write(&path, &bytes).unwrap();
        let conn = Connection::open(&path).unwrap();
        let mut cap = CapCounter::new(1);
        assert!(cap.admit());
        assert!(!cap.admit(), "the second row is past a cap of one");
        assert!(cap.truncated());
        let marker = cap_marker(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "EmailParseStatus",
            "messages",
            &cap,
        );
        let detail = marker.metadata["content_incomplete_detail"]
            .as_str()
            .or_else(|| marker.metadata["detail"].as_str())
            .unwrap_or_default();
        assert!(
            detail.contains("oldest") || detail.contains("beyond"),
            "the marker says which end was dropped: {:?}",
            marker.metadata
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn every_record_names_the_epoch_it_read_the_dates_under() {
        // A date read under Core Data's 2001 epoch instead of Unix's would be
        // 31 years out and would look entirely ordinary. No database this
        // project holds can confirm which Mail wrote, so the record states
        // what it assumed rather than presenting the instant as established.
        let out = run(build(&[one()]));
        let m = &out[0].metadata;
        assert_eq!(m["date_epoch"], 1_613_908_860);
        assert_eq!(m["date"], "2021-02-21T12:01:00+00:00");
        assert_eq!(m["date_sent_epoch"], 1_613_908_800);
        assert_eq!(m["date_last_viewed_epoch"], 1_613_909_000);
        let basis = m["date_basis"].as_str().unwrap();
        assert!(basis.contains("Unix epoch seconds"), "{basis}");
        assert!(basis.contains("NOT confirmed"), "{basis}");
        assert!(basis.contains("2001 epoch"), "{basis}");
    }

    #[test]
    fn a_zero_date_is_an_absent_one_and_not_the_first_instant_of_1970() {
        // Every message Mail never displayed has a zero `date_last_viewed`,
        // and rendering that as a date would put a 1970 timestamp on most of
        // a mailbox.
        let mut msg = one();
        msg.date_last_viewed = 0;
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(m["date_last_viewed"], json!(null));
        assert_eq!(m["date_last_viewed_epoch"], json!(null));
        assert_eq!(
            m["date"], "2021-02-21T12:01:00+00:00",
            "the others are unaffected"
        );
    }

    #[test]
    fn a_reply_keeps_the_prefix_mail_stores_apart_from_the_subject() {
        // Mail normalises `Re: ` out of the subject and keeps it in its own
        // column, so the subject an examiner would read is the two joined --
        // and the prefix on its own is the evidence that a message is a reply.
        let mut msg = one();
        msg.subject_prefix = Some("Re: ");
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(m["subject"], "Re: Tuesday's lesson");
        assert_eq!(m["subject_prefix"], "Re: ");
    }

    #[test]
    fn a_deleted_message_still_in_the_index_is_reported_as_deleted() {
        // The reason the index is worth reading on a machine whose mail was
        // server-hosted: the row outlives the message.
        let mut msg = one();
        msg.deleted = 1;
        let out = run(build(&[msg]));
        assert_eq!(out[0].metadata["deleted"], true);
    }

    #[test]
    fn a_sender_with_no_address_recorded_is_a_stated_absence_not_a_blank() {
        let mut msg = one();
        msg.sender = "";
        msg.sender_name = "";
        let out = run(build(&[msg]));
        let m = &out[0].metadata;
        assert_eq!(
            m["from"],
            json!(null),
            "absent, rather than an empty address"
        );
        assert!(m["name"].as_str().unwrap().starts_with("(sender?)"));
    }

    #[test]
    fn every_record_says_it_has_not_been_read_from_a_mailbox_apple_populated() {
        // The reason this ships at all rather than being withheld: an examiner
        // can discount a result labelled unproven, and cannot discount one
        // they were never shown. The same choice the macOS memory tier makes.
        let out = run(build(&[one()]));
        let m = &out[0].metadata;
        assert_eq!(m["basis"], "schema_verified_rows_unverified");
        let said = m["basis_statement"].as_str().unwrap();
        assert!(said.contains("Apple's"), "{said}");
        assert!(said.contains("tables are empty"), "{said}");
        assert_eq!(m["content_complete"], false);
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "unvalidated");
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("body_absent_reason"));
    }

    #[test]
    fn newest_first_so_a_truncated_read_keeps_the_end_a_case_is_about() {
        let mut older = one();
        older.rowid = 2;
        older.subject = "last year";
        older.date_received = 1_500_000_000;
        let out = run(build(&[one(), older]));
        let subjects: Vec<&str> = out
            .iter()
            .filter(|a| a.metadata["type"] == "EmailMessage")
            .map(|a| a.metadata["subject"].as_str().unwrap())
            .collect();
        assert_eq!(subjects, vec!["Tuesday's lesson", "last year"]);
    }

    #[test]
    fn a_file_that_is_not_the_index_is_not_read_as_one() {
        // The `-wal` and `-shm` siblings sit beside it in every mailbox, and
        // reading a write-ahead log as a database and reporting "no messages"
        // would be a false absence.
        for name in [
            "Envelope Index-wal",
            "Envelope Index-shm",
            "Envelope",
            "knowledgeC.db",
        ] {
            assert!(
                run_named(build(&[one()]), name).is_empty(),
                "{name} must not be read as the index"
            );
        }
        // And the real name is matched whatever the case and wherever it sits.
        assert!(!run_named(build(&[one()]), "ENVELOPE INDEX").is_empty());
    }

    #[test]
    fn a_database_that_is_not_an_envelope_index_yields_nothing_rather_than_failing() {
        // A file named `Envelope Index` that is some other SQLite database --
        // or not a database at all -- must produce no records and no claim.
        let dir = std::env::temp_dir().join(format!("envidx_other_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE unrelated (a INTEGER);")
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(run(bytes).is_empty());
        assert!(run(b"not a database at all".to_vec()).is_empty());
    }

    #[test]
    fn an_empty_index_reports_no_messages_and_no_failure() {
        // The state of the only real Envelope Index this project holds: Mail
        // was opened and no account synced. It is not a parse failure.
        let out = run(build(&[]));
        assert!(
            out.iter().all(|a| a.metadata["type"] != "EmailMessage"),
            "no message rows"
        );
        assert!(
            out.iter().all(|a| a.metadata["status"] != "ParseFailed"),
            "and no failure claimed: {out:?}"
        );
    }

    /// HUNT-179. `cap_marker()` files the marker under subtype
    /// `parse_incomplete`, and `.with_subtype("apple_mail_index")` overwrote
    /// it, so a capped Envelope Index read was filed with the messages.
    #[test]
    fn the_cap_marker_keeps_its_parse_incomplete_subtype() {
        let messages: Vec<Message> = (0..3)
            .map(|i| {
                let mut m = one();
                m.rowid = i + 1;
                m.date_received = 1_613_908_860 - i;
                m
            })
            .collect();
        let bytes = build(&messages);
        let temp = std::env::temp_dir().join(format!("envcap2_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp).unwrap();
        let path = temp.join("Envelope Index");
        std::fs::write(&path, &bytes).unwrap();
        let conn = Connection::open(&path).unwrap();
        let out = parse_messages(&conn, Uuid::new_v4(), Uuid::new_v4(), "Envelope Index", 1)
            .expect("the capped walk succeeds");
        drop(conn);
        let _ = std::fs::remove_dir_all(&temp);
        let marker = out
            .iter()
            .find(|a| a.metadata["status"] == "CapReached")
            .expect("a cap of one over three messages leaves a marker");
        assert_eq!(
            marker.metadata["subtype"],
            json!("parse_incomplete"),
            "the cap marker was filed under the data records' subtype"
        );
        assert_eq!(marker.metadata["type"], json!("EmailParseStatus"));
    }
}
