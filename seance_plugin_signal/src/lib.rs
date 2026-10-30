#![forbid(unsafe_code)]
//! Signal Messenger Parser Module
//!
//! Detects Signal Messenger artifacts and turns them into chat/contact
//! `ParsedRecord` artifacts that render in the existing Conversation viewer /
//! Comms / Connections graph. It has two capabilities, in priority order:
//!
//! ## (A) Signal SQLite database — fully implemented and tested
//!
//! A decrypted Signal Android database (`signal.db`, or a `plaintext.db` export)
//! is a plain SQLite file. We detect it by the presence of Signal-specific
//! tables (`recipient` plus a message store `message`/`sms`/`mms` plus `thread`)
//! and emit one chat record per message joining body + timestamp + thread +
//! recipient + sent/received direction. The emitted field names match the
//! WhatsApp / android_sms plugins so Signal messages render with no viewer
//! changes: `text`, `date`, `contact`, `sender`, `is_from_me`, `direction`,
//! `chat_identifier`, `chat_display_name`, `service`, `has_attachments`.
//!
//! Signal schemas vary a lot by app version, so every column is probed via
//! `PRAGMA table_info` and missing columns are skipped (never a panic).
//!
//! Direction is derived from the message `type` bitmask, the canonical Signal
//! source (`MmsSmsColumns.Types`): base type = `type & 0x1F`; outgoing base
//! types are 21..=26 (OUTBOX/SENDING/SENT/SENT_FAILED/PENDING_*), inbox is 20.
//!
//! ## (B) Signal Android backup (`*.backup`) — decryption implemented, see notes
//!
//! The encrypted Android export is a sequence of length-prefixed frames. The
//! first frame is a plaintext `Header` protobuf carrying a 16-byte `iv` and a
//! `salt`. Key derivation mirrors Signal-Android `FullBackupExporter` /
//! `BackupProtos`:
//!
//! 1. `backupKey` = SHA-512 iterated 250000 times, seeded with `salt` then each
//!    round hashing `(runningHash || passphraseAsciiBytesWithoutSpaces)`,
//!    truncated to 32 bytes (Signal's key stretch).
//! 2. `HKDF-SHA256(ikm=backupKey, salt=<32 zero bytes>, info="Backup Export")`
//!    -> 64 bytes = 32-byte AES-256 cipher key || 32-byte HMAC-SHA256 key.
//!
//! Each subsequent frame on the wire is `[4-byte big-endian length][ciphertext
//! || 10-byte truncated HMAC]`. The HMAC-SHA256 (`macKey`) is computed over the
//! **ciphertext only** (not the length prefix; the task brief's "length +
//! ciphertext" is inaccurate versus the real `FullBackupImporter`) and compared
//! against the trailing 10 bytes. The ciphertext is AES-256-CTR with the 16-byte
//! IV as the initial counter block; before each frame the IV's first 4 bytes are
//! overwritten with a big-endian per-frame counter (initialised from the IV's
//! first 4 bytes and incremented once per frame, and once per attachment blob).
//!
//! Frames are `BackupFrame` protobufs (oneof: header / statement / preference /
//! attachment / version / end / avatar / sticker / keyValue). We replay the
//! `statement` frames (SQL + typed parameters) into a fresh SQLite database and
//! then run capability (A) over it. Attachment/avatar/sticker frames are
//! followed by a raw encrypted blob (`length` bytes + a 10-byte HMAC, no length
//! prefix); we skip those blobs (their content is not needed to read the chats)
//! while keeping the frame counter aligned.
//!
//! ### Verification status (honest)
//!
//! - The KDF's HKDF-SHA256 half is checked against RFC 5869 Test Case 3 (see
//!   `tests::hkdf_rfc5869_case3`), exactly as Signal invokes it (zero salt).
//! - The framing + AES-CTR + truncated-HMAC + counter logic and the statement
//!   replay are validated end to end by a self-constructed round trip
//!   (`tests::backup_roundtrip_*`): a backup is written with a mirror of
//!   `FullBackupExporter`, decrypted, and the reconstructed messages asserted.
//! - The 250000-round SHA-512 stretch matches the documented Signal-Android code
//!   by construction and is exercised by the round trip, but has **not** yet been
//!   validated against a real Signal-produced `.backup` (no fixture available).
//!   Treat capability (B) as "implemented, pending real-image validation".
//!
//! ## Schema support
//!
//! Each message table walked is read through a `FieldMap` (see
//! `schema_support`) and emits one `SignalIncomplete` record of
//! `warning_class: ParserStaleWarning` — one per table, so a legacy `sms` +
//! `mms` store carries two, and a table whose column list could not be read
//! carries none. Each says: no validated range (no plaintext Signal store has
//! been read by this project — `SCHEMA_SUPPORT` says why), the `PRAGMA
//! user_version` the store carries (a replayed backup carries the value of its
//! `DatabaseVersion` frame; 0 is "not recorded", never version 0), and any
//! logical field no column resolved — the only case that stamps
//! `content_incomplete` (reason `unvalidated`).
//!
//! ## SQLCipher with a plaintext header (Signal for iOS)
//!
//! `grdb/signal.sqlite` carries a genuine 32-byte SQLite header — reserve byte
//! 0x50 — followed by ciphertext. It opens and then refuses every catalogue
//! read; without a key that is reported as `StoreEncrypted` (reason
//! `encrypted`, scheme `sqlcipher4_raw_key_plaintext_header`), never as a
//! damaged store, and no version is read out of its header, whose bytes 60..63
//! are inside the ciphertext.
//!
//! With the store's raw key spec supplied for that one file (`HUNT-227`,
//! through `POST /cases/{id}/artifacts/{id}/credential`, visible to this module
//! for one run via `seance_core::credential`), it is decrypted with
//! `seance_sqlcipher` — the main file and its committed WAL frames, every page
//! authenticated — and Signal-iOS's GRDB schema is read by `ios_grdb`. That
//! reader is graded structurally: the one real store held has no messages
//! (`VALIDATION.md` `SIGNAL-IOS-1`).

use anyhow::{anyhow, Context, Result};
use rusqlite::types::Value as SqlValue;
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{cap_marker, unix_seconds_from_magnitude, CapCounter, FieldMap, TempDb};

mod ios_grdb;
#[cfg(test)]
mod schema_golden_tests;
mod schema_support;
#[cfg(test)]
use schema_support::SchemaVersion;
use schema_support::{user_version, SchemaBound, SchemaCheck, SchemaSupport};

/// What this parser may say about a Signal Android schema version.
///
/// Unranged, and it stays so until a plaintext Signal store — a decrypted
/// `signal.db` or a real `.backup` with its passphrase — is opened by this
/// project. Two real Signal stores ARE held here and neither has been read,
/// for two different reasons, neither of which is "no key":
///
/// - `~/ctf-evidence/android2022` carries `signal.db` SQLCipher-encrypted
///   under a key wrapped by the device keystore; the wrapped key is not
///   something this project holds in usable form.
/// - `~/ctf-evidence/ios2022ffs` carries the iOS `grdb/signal.sqlite`,
///   SQLCipher with a 32-byte plaintext header (header bytes 60..63 read
///   360193054, which is ciphertext, not a version) and 80 reserved bytes per
///   page. The key for it IS held: the same export's keychain plist carries
///   the raw SQLCipher key spec (`genp` item `GRDBDatabaseCipherKeySpec`,
///   access group `U68MSDN6DR.org.whispersystems.signal`, 48 bytes of
///   `v_Data`), and since HUNT-183 the in-tree `seance_sqlcipher` decrypts
///   this SQLCipher 4 form — raw key, HMAC-SHA512 (the 80-byte reserve is
///   16 IV + 64 HMAC-SHA512), plaintext header — graded on this very store.
///   It does not validate this parser's range: it is Signal for iOS's GRDB
///   schema (`model_TSInteraction`, `model_TSThread`, …), not this Android
///   schema, and it is read by `ios_grdb` under its own declaration.
///
/// A range declared from documentation would be a claim about databases this
/// project has never opened. Once a real store is read, its `PRAGMA
/// user_version` — Signal's migration number, which the backup carries in its
/// `DatabaseVersion` frame — becomes the single-point range `n..=n`, with the
/// file named as evidence.
const SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "signal-android",
    bound: SchemaBound::Unranged {
        why: "no plaintext reference database of this app has been read by this project: the \
              Android Signal store held is SQLCipher-encrypted under a keystore-wrapped key \
              not held in usable form, and the one whose raw key spec is held (the iOS \
              grdb/signal.sqlite, a SQLCipher 4 raw-key / HMAC-SHA512 store the in-tree \
              SQLCipher reader decrypts) carries Signal for iOS's GRDB schema, not this \
              Android schema; the schema version is recorded, not ranged",
    },
};

/// Logical fields of a message table (`message`, or legacy `sms`/`mms`) and
/// the physical columns that have carried each. The physical name doubles as
/// the alias the row reader reads by, so a candidate added here for a renamed
/// column flows through without touching the reader.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("thread", &["thread_id"]),
    ("from", &["from_recipient_id"]),
    ("to", &["to_recipient_id"]),
    ("address", &["address"]),
    ("text", &["body"]),
    ("date", &["date"]),
    ("sent_at", &["date_sent"]),
    ("received_at", &["date_received"]),
    ("type", &["type"]),
    ("read", &["read"]),
];

/// Without a body and a direction a row is not an evidentiary message: a
/// renamed `type` used to make every message direction-unknown with nothing on
/// the record saying so. The three timestamp columns are alternatives, so none
/// is required on its own.
const REQUIRED_FIELDS: &[&str] = &["text", "type"];
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use tracing::{debug, info, warn};
use uuid::Uuid;

// Crypto (RustCrypto). `ctr` re-exports the `cipher` traits, so no extra dep.
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Maximum number of chat records extracted per database.
const MAX_MESSAGE_ENTRIES: usize = 500_000;
/// Maximum number of contact records emitted.
const MAX_CONTACT_ENTRIES: usize = 100_000;
/// Cap on a decrypted DB temp-file size we will read into memory / write out.
const MAX_DB_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Cap on an encrypted `.backup` we will buffer. Larger backups are detected but
/// not decrypted (bounded allocation on untrusted input).
const MAX_BACKUP_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Reject an absurd frame length prefix before allocating for it.
const MAX_FRAME_LEN: usize = 100 * 1024 * 1024;
/// Hard stop on the number of frames replayed from one backup.
const MAX_FRAMES: usize = 20_000_000;
/// SHA-512 key-stretch rounds (Signal-Android `getBackupKey`).
const KDF_ROUNDS: usize = 250_000;
/// HKDF info string (Signal-Android backup export).
const HKDF_INFO: &[u8] = b"Backup Export";
/// SQLite file magic.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
pub struct SignalParser;

// ===========================================================================
// Detection helpers
// ===========================================================================

/// Permissive filename pre-filter for a Signal SQLite database. Authoritative
/// gate is [`has_signal_schema`] after opening; this only decides whether to
/// open the file, so renamed copies are still parsed.
fn is_signal_db_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("signal.db")
        || n.ends_with("plaintext.db")
        || (n.contains("signal") && (n.ends_with(".db") || n.ends_with(".sqlite")))
}

/// Signal's own backup naming, `signal-YYYY-MM-DD-HH-MM-SS.backup`, judged on
/// the final path component. A file named this way whose bytes do not parse
/// is a finding to report; a file merely ending in `.backup` is not — the
/// classification itself comes from [`looks_like_backup`]. (GalleryVault
/// writes `setting.backup` and `file_count.backup`, and on the suffix alone a
/// case once carried two "Signal backup (locked - passphrase required)"
/// records for another app's files.)
fn is_signal_backup_name(name: &str) -> bool {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    base.starts_with("signal") && base.ends_with(".backup")
}

/// SQLCipher's default page size. Signal for Android's `signal.db` is a
/// SQLCipher store, so a file that is a whole number of these pages with no
/// SQLite header is *consistent with* that — not proof of it.
const SQLCIPHER_PAGE_BYTES: u64 = 4096;

/// A file the case names as a Signal database whose first bytes are not the
/// SQLite header. It was not opened; returning nothing for it filed a 7 MB
/// message store as "no Signal data on this device".
fn not_sqlite_store(artifact: &Artifact, name: &str, size: u64) -> Vec<Artifact> {
    let sqlcipher_consistent = size > 0 && size.is_multiple_of(SQLCIPHER_PAGE_BYTES);
    let detail = format!(
        "{name} is named as a Signal database but its first 16 bytes are not the SQLite \
         header, so it was not opened. Signal for Android keeps this store SQLCipher-encrypted \
         under a key held in the device keystore, which this build cannot decrypt; the file \
         is {size} bytes, {} a whole number of {SQLCIPHER_PAGE_BYTES}-byte SQLCipher pages. \
         Nothing here establishes what it held, and its absence from the message list is not \
         evidence of absence",
        if sqlcipher_consistent {
            "which is"
        } else {
            "which is not"
        }
    );
    let metadata = json!({
        "type": "SignalIncomplete",
        "subtype": "parse_incomplete",
        "service": "Signal",
        "status": "StoreNotSqlite",
        "file_name": name,
        "size": size,
        "sqlcipher_consistent": sqlcipher_consistent,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete": true,
        "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "detail": detail,
        "name": format!("Signal database (not SQLite - encrypted or unrecognised, not read): {name}"),
    });
    vec![
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype("parse_incomplete"),
    ]
}

/// A file carrying Signal's backup name whose first frame is not a Signal
/// backup header. Before this the name alone produced a "locked - passphrase
/// required" record, which reads as "a Signal backup exists here".
fn unrecognised_backup(artifact: &Artifact, name: &str) -> Vec<Artifact> {
    let metadata = json!({
        "type": "SignalIncomplete",
        "subtype": "parse_incomplete",
        "service": "Signal",
        "status": "BackupHeaderUnrecognised",
        "file_name": name,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete": true,
        "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "detail": format!(
            "{name} is named as a Signal backup but its first frame did not parse as a Signal \
             backup header, so it was not treated as one; nothing here establishes what it \
             held"
        ),
        "name": format!("Signal backup (header not recognised, not read): {name}"),
    });
    vec![
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype("parse_incomplete"),
    ]
}

/// Authoritative Signal-database schema check. Signal uses a `recipient` table
/// (its defining feature; WhatsApp uses `jid`/`chat`, Android telephony uses
/// `sms` with no `recipient`) alongside a message store and a `thread` table.
///
/// `Err` when the catalogue itself would not read. That is NOT "this is not a
/// Signal database": it is a database whose schema could not be examined, and
/// answering `false` for it filed a corrupt Signal store as an unrelated file
/// and produced nothing at all.
fn has_signal_schema(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(table_exists(conn, "recipient")?
        && table_exists(conn, "thread")?
        && (table_exists(conn, "message")?
            || table_exists(conn, "sms")?
            || table_exists(conn, "mms")?))
}

/// The record that says a file named as a Signal store was not examined.
///
/// `named` is the whole point: this module is offered every SQLite file in the
/// evidence, so an unnamed one that will not open is simply not ours and stays
/// silent. A file the case already calls a Signal database is different —
/// returning nothing for it puts "no Signal messages" in the report, drawn from
/// a failure rather than from the device.
fn unreadable_store(artifact: &Artifact, name: &str, named: bool, detail: String) -> Vec<Artifact> {
    if !named {
        return Vec::new();
    }
    let metadata = json!({
        "type": "SignalIncomplete",
        "subtype": "parse_incomplete",
        "service": "Signal",
        "status": "StoreUnreadable",
        "file_name": name,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete": true,
        "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "detail": format!(
            "{name} is named as a Signal database and {detail}; nothing here establishes what \
             it held, and its absence from the message list is not evidence of absence"
        ),
        "name": format!("Signal database (not read): {name}"),
    });
    let record = Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
        .with_subtype("parse_incomplete");
    vec![record]
}

/// The reserved-bytes-per-page of a staged file whose first 16 bytes are the
/// SQLite magic, when that byte is non-zero.
///
/// Plain SQLite writes 0 there; SQLCipher reserves the tail of every page for
/// its per-page IV and HMAC (0x50 = 80 bytes for SQLCipher 4). Signal for iOS
/// sets `cipher_plaintext_header_size = 32`, so its `signal.sqlite` carries a
/// genuine header — magic, page size, WAL flag, reserve, page count — followed
/// by ciphertext: it OPENS, and then every catalogue read answers "unsupported
/// file format". Measured on the store this project holds
/// (`~/ctf-evidence/ios2022ffs`, `.../grdb/signal.sqlite`): reserve 0x50, page
/// count 0x131, high-entropy bytes from offset 32. Only consulted once the
/// catalogue has refused, so a readable store that happens to reserve bytes is
/// never called encrypted on the byte alone.
///
/// The rest of the header has to be one SQLite would accept — page size a
/// power of two from 512 to 65536 (1 encodes 65536), file-format versions 1 or
/// 2, the reserve smaller than the page — or the byte is damage, not a
/// reserve: a store whose pages behind the magic were overwritten reads 0xFF
/// there and is a corrupt store, which the caller reports as one.
fn plaintext_header_reserve(path: &std::path::Path) -> Option<u8> {
    use std::io::Read;
    let mut head = [0u8; 32];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .ok()?;
    if &head[..16] != SQLITE_MAGIC {
        return None;
    }
    let page_size = match u16::from_be_bytes([head[16], head[17]]) {
        1 => 65_536u32,
        n if n.is_power_of_two() && n >= 512 => u32::from(n),
        _ => return None,
    };
    let versions_valid = (1..=2).contains(&head[18]) && (1..=2).contains(&head[19]);
    let reserve = head[20];
    (versions_valid && reserve != 0 && u32::from(reserve) < page_size).then_some(reserve)
}

/// The record for a store that opened on a genuine SQLite header and would not
/// read behind it, while its header reserves SQLCipher's per-page bytes.
///
/// `encrypted`, not `unresolved_structure`: the second sends an examiner
/// looking for damage in a file that is intact and locked. And no version is
/// read out of it — bytes 60..63 of such a header are inside the ciphertext,
/// and would report a uniformly random integer as an app schema version.
fn encrypted_plaintext_header_store(
    artifact: &Artifact,
    name: &str,
    named: bool,
    reserve: u8,
    refusal: &str,
) -> Vec<Artifact> {
    if !named {
        return Vec::new();
    }
    let encrypted = IncompleteReason::Encrypted.as_str();
    let detail = format!(
        "{name} is named as a Signal database and carries a genuine SQLite header that \
         reserves {reserve} bytes per page, behind which the store would not read \
         ({refusal}); that is consistent with SQLCipher with a plaintext header, which \
         Signal for iOS writes as a SQLCipher 4 raw-key / HMAC-SHA512 store. It was not \
         decrypted because no key was supplied for it. Its raw key spec (on iOS, the keychain \
         item GRDBDatabaseCipherKeySpec, 48 bytes) can be supplied for this file from the \
         Needs attention queue, which re-runs this parser with it. Nothing here establishes \
         what it held, and its absence from the message list is not evidence of absence"
    );
    let metadata = json!({
        "type": "SignalIncomplete",
        "subtype": "parse_incomplete",
        "service": "Signal",
        "status": "StoreEncrypted",
        "file_name": name,
        // The attention queue offers the key-spec field for this scheme only:
        // an Android store's key is a different thing and would not open it.
        "scheme": "sqlcipher4_raw_key_plaintext_header",
        "sqlcipher_consistent": true,
        "reserved_bytes_per_page": reserve,
        "content_incomplete": true,
        "content_incomplete_reason": encrypted,
        "content_incomplete_detail": detail,
        "inventory_incomplete": true,
        "inventory_incomplete_reason": encrypted,
        "inventory_incomplete_detail": detail,
        "detail": detail,
        "name": format!("Signal database (encrypted, plaintext header): {name}"),
    });
    vec![
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype("parse_incomplete"),
    ]
}

/// Content sniff for a Signal backup: the first frame parses as a `BackupFrame`
/// whose `header` carries a 16-byte IV. Lets renamed backups be detected.
fn looks_like_backup(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    if len == 0 || len > 4096 || 4 + len > head.len() {
        return false;
    }
    parse_header_frame(&head[4..4 + len])
        .map(|(iv, _salt)| iv.len() == 16)
        .unwrap_or(false)
}

// ===========================================================================
// SQLite helpers
// ===========================================================================

/// True if a table with the given name exists.
///
/// `Err`, never `false`, when the catalogue could not be read: "no such table"
/// and "could not tell" are different findings and only one of them is evidence.
fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )
}

/// One walk's undecodable rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowGap {
    /// What was being read: a table name, or a table's column list.
    source: String,
    /// Rows fetched from it that would not decode.
    dropped: usize,
    /// The decoder's message for the first of them (SIG-001).
    first_error: Option<String>,
    /// Rows of the same walk that did decode, so the loss can be stated
    /// alongside the count it makes a floor of.
    recovered: usize,
}

/// Everything this parse fetched and could not read.
///
/// Rows are dropped by `rows.flatten()`, which is why that call does not appear
/// in this crate any more. A `rusqlite` row `Err` is a row that IS in the
/// database and whose values this build could not decode — a corrupt page, a
/// column of an unexpected type, a record recovered only in part. Discarding it
/// leaves the tally beside it looking exact, so a summary reads "312 messages"
/// over a store that held 340, and the 28 nobody can see are the ones that were
/// damaged (B3-023).
#[derive(Debug, Default, PartialEq, Eq)]
struct ParseGaps {
    /// Undecodable rows, by the walk that fetched them.
    rows: Vec<RowGap>,
    /// Tables and queries this build's SQL could not read at all.
    load_errors: Vec<String>,
    /// Threads that store a counterparty reference this build could not turn
    /// into a recipient id.
    ///
    /// Deliberately NOT a [`RowGap`]: those rows decoded, and no message was
    /// lost. What is wrong is the attribution — every message in such a thread
    /// falls through to a fallback counterparty. Counting it as a dropped row
    /// would put a number in `rows_dropped` and a "could not be decoded"
    /// sentence in the case over evidence that was read in full, and a report
    /// that overstates the damage is as unusable in court as one that hides it.
    unresolved_thread_recipients: usize,
}

impl ParseGaps {
    /// Record undecodable rows. A walk that lost nothing records nothing, so
    /// the markers below only ever appear over evidence that really is short.
    fn record_rows(&mut self, source: impl Into<String>, dropped: &Drops, recovered: usize) {
        if dropped.count == 0 {
            return;
        }
        self.rows.push(RowGap {
            source: source.into(),
            dropped: dropped.count,
            first_error: dropped.first_error.clone(),
            recovered,
        });
    }

    fn load_error(&mut self, detail: impl Into<String>) {
        let detail = detail.into();
        warn!("Signal: {}", detail);
        self.load_errors.push(detail);
    }

    fn total_dropped(&self) -> usize {
        self.rows.iter().map(|g| g.dropped).sum()
    }

    /// Whether the counts this parse reports are exact.
    ///
    /// Only losses that remove a record bear on this. An unresolved thread
    /// recipient is reported separately: it makes a *name* doubtful, not a
    /// count short, and prefixing the headline with "at least" over it would
    /// tell an examiner messages are missing when none are.
    fn is_complete(&self) -> bool {
        self.rows.is_empty() && self.load_errors.is_empty()
    }
}

/// Drain a mapped-row iterator, counting the rows that would not decode.
///
/// The counted replacement for `rows.flatten()`. Everything that decodes is
/// handed to `keep`; everything that does not is added to `dropped` so the
/// caller can say how much of the table is missing from what it emits.
fn count_undecodable<T>(
    rows: impl Iterator<Item = rusqlite::Result<T>>,
    what: &str,
    dropped: &mut Drops,
    mut keep: impl FnMut(T),
) {
    for row in rows {
        match row {
            Ok(v) => keep(v),
            Err(e) => {
                dropped.record(&e);
                debug!("Signal: {what} row would not decode: {e}");
            }
        }
    }
}

/// Undecodable rows from one walk: how many, and why the first of them failed.
///
/// The reason used to reach `debug!` and nothing else, so a Signal row that
/// would not decode was disclosed to the examiner as a bare count while every
/// other messenger named the decoder's error (SIG-001). The count says the list
/// is a floor; the reason is what says whether the loss is recoverable.
///
/// The FIRST error is kept rather than the last, matching
/// `seance_sqlite_util::RowDrops`: it is the one nearest the cause, and on a
/// badly damaged table the last is usually the same failure repeated.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Drops {
    count: usize,
    first_error: Option<String>,
}

impl Drops {
    fn record(&mut self, error: &dyn std::fmt::Display) {
        self.count = self.count.saturating_add(1);
        if self.first_error.is_none() {
            self.first_error = Some(error.to_string());
        }
    }
}

/// Read one optional column, recording the name when a value is there and will
/// not decode.
///
/// The replacement for `row.get(..).ok().flatten()`, which collapses three
/// different facts into `None`: the column was not selected, the column is
/// NULL, and the column holds something this build could not read. For `body`
/// that last one is the difference between a message that carried no text and a
/// message whose text was not recovered — and only one of those is evidence
/// that nothing was said.
///
/// A column absent from the SELECT list stays silent: the query only asks for
/// columns this schema generation has, so its absence is expected and not a
/// gap.
fn opt_col<T: rusqlite::types::FromSql>(
    row: &rusqlite::Row<'_>,
    name: &'static str,
    undecoded: &mut Vec<&'static str>,
) -> Option<T> {
    match row.get::<_, Option<T>>(name) {
        Ok(v) => v,
        Err(rusqlite::Error::InvalidColumnName(_)) => None,
        Err(e) => {
            debug!("Signal: column {name} would not decode: {e}");
            undecoded.push(name);
            None
        }
    }
}

/// Column-name set for a table. Table names passed here are hardcoded literals,
/// so direct interpolation is safe.
///
/// An empty result means the column list could not be read, never that a table
/// has no columns — callers check `table_exists` first, so the two cannot be
/// confused. Both a `PRAGMA` that will not run and a column name that will not
/// decode are recorded: a column this build cannot see is a column it does not
/// select, so the rows it goes on to emit are quietly short a field.
fn columns(conn: &Connection, table: &str, gaps: &mut ParseGaps) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut dropped = Drops::default();
    match conn.prepare(&format!("PRAGMA table_info({table})")) {
        Ok(mut stmt) => match stmt.query_map([], |r| r.get::<_, String>(1)) {
            Ok(rows) => count_undecodable(rows, table, &mut dropped, |c| {
                set.insert(c);
            }),
            Err(e) => gaps.load_error(format!("{table}: column list would not query: {e}")),
        },
        Err(e) => gaps.load_error(format!("{table}: column list would not prepare: {e}")),
    }
    gaps.record_rows(format!("{table} column list"), &dropped, set.len());
    set
}

/// Convert a raw Signal epoch value to whole Unix seconds, or `None` where the
/// column recorded no instant.
///
/// The unit judgement is [`unix_seconds_from_magnitude`] and nothing else. It
/// used to be a local two-branch rule — below 10^11 seconds, at or above it
/// milliseconds — which is right for the millisecond form Signal itself writes
/// and wrong for the third unit this corpus contains: a 16-digit microsecond
/// value was divided by a thousand and dated the message to the year 55840.
/// `chat.rs` documents `date` as whole seconds, and the shared band table is
/// what makes that documentation true.
///
/// One behaviour changed with it, deliberately: a NEGATIVE value is now `None`
/// rather than being divided and written. Signal shipped in 2010, so a negative
/// epoch is a corrupt or unset column and not a message from the 1960s, and it
/// must not anchor a timeline entry there. `NULL` and `0` were already `None`
/// for the same reason and still are.
fn normalize_epoch_secs(raw: Option<i64>) -> Option<i64> {
    raw.and_then(unix_seconds_from_magnitude)
}

fn to_rfc3339(secs: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

/// Buffer a whole database / backup, applying this module's admission policy on
/// top of the shared [`read_capped`] loop: an empty source and an oversized one
/// are *refused* rather than silently truncated, so the caller can emit the
/// honest "detected but not read" marker instead of parsing a partial backup.
fn read_bounded(ds: &dyn DataSource, max: u64) -> Result<Vec<u8>> {
    let size = ds.size();
    if size == 0 {
        anyhow::bail!("empty data source");
    }
    if size > max {
        anyhow::bail!("data source too large: {} bytes", size);
    }
    Ok(read_capped(ds, max))
}

// ===========================================================================
// Capability (A): parse a decrypted Signal SQLite database
// ===========================================================================

/// Resolved recipient identity.
#[derive(Clone)]
struct Recipient {
    display: String,
    identifier: String,
    is_group: bool,
}

fn pick(map: &HashMap<&'static str, String>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = map.get(*k) {
            if !v.is_empty() {
                return Some(v.clone());
            }
        }
    }
    None
}

fn join_name(map: &HashMap<&'static str, String>, given: &str, family: &str) -> Option<String> {
    let g = map.get(given).map(|s| s.as_str()).unwrap_or("");
    let f = map.get(family).map(|s| s.as_str()).unwrap_or("");
    let joined = format!("{g} {f}");
    let joined = joined.trim();
    if joined.is_empty() {
        None
    } else {
        Some(joined.to_string())
    }
}

/// Build `recipient_id -> Recipient`. Every candidate column is probed; missing
/// ones are simply absent. Degrades to "Recipient {id}" when no name is stored.
///
/// `Err` when the table could not be read at all — an absent table, or a
/// `prepare`/`query_map` this schema generation refuses. That must not collapse
/// to an empty map: "no recipients are stored on this device" and "we could not
/// read the recipient table" are different findings, and only one of them is
/// evidence.
fn build_recipient_map(
    conn: &Connection,
    gaps: &mut ParseGaps,
) -> Result<HashMap<i64, Recipient>, String> {
    let mut map = HashMap::new();
    if !table_exists(conn, "recipient").map_err(|e| format!("recipient table probe: {e}"))? {
        return Err("recipient table absent".to_string());
    }
    let cols = columns(conn, "recipient", gaps);
    if cols.is_empty() {
        // The table is there and its column list is not. Carrying on would
        // select none of the name columns and rename every correspondent to
        // "Recipient {id}" — a plausible-looking contact list nobody could tell
        // from a device that stores no names.
        return Err("recipient column list unreadable".to_string());
    }

    // String-valued columns worth fetching, across Signal versions.
    const CAND: &[&str] = &[
        "system_joined_name",
        "system_display_name",
        "profile_joined_name",
        "signal_profile_name",
        "system_given_name",
        "system_family_name",
        "profile_given_name",
        "profile_family_name",
        "username",
        "nickname_given_name",
        "e164",
        "phone",
        "group_id",
    ];
    let present: Vec<&'static str> = CAND.iter().copied().filter(|c| cols.contains(*c)).collect();
    let id_col = if cols.contains("_id") { "_id" } else { "rowid" };

    let mut sel = format!("{id_col} AS rid");
    for c in &present {
        sel.push_str(&format!(", {c}"));
    }
    let sql = format!("SELECT {sel} FROM recipient");

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("prepare recipient query: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            let rid: i64 = row.get("rid")?;
            let mut vals: HashMap<&'static str, String> = HashMap::new();
            let mut undecoded: Vec<&'static str> = Vec::new();
            for c in &present {
                if let Some(v) = opt_col::<String>(row, c, &mut undecoded) {
                    vals.insert(*c, v);
                }
            }
            Ok((rid, vals, undecoded))
        })
        .map_err(|e| format!("query recipient rows: {e}"))?;

    let mut dropped = Drops::default();
    let mut undecoded_names: Vec<String> = Vec::new();
    count_undecodable(rows, "recipient", &mut dropped, |(rid, m, undecoded)| {
        if !undecoded.is_empty() {
            // The name this contact is filed under was chosen without a column
            // that is there and would not read, so it may not be the name the
            // device actually shows.
            undecoded_names.push(format!("recipient {rid}: {}", undecoded.join(", ")));
        }
        let display = pick(
            &m,
            &[
                "system_joined_name",
                "system_display_name",
                "profile_joined_name",
                "signal_profile_name",
            ],
        )
        .or_else(|| join_name(&m, "system_given_name", "system_family_name"))
        .or_else(|| join_name(&m, "profile_given_name", "profile_family_name"))
        .or_else(|| {
            pick(
                &m,
                &[
                    "username",
                    "nickname_given_name",
                    "e164",
                    "phone",
                    "group_id",
                ],
            )
        })
        .unwrap_or_else(|| format!("Recipient {rid}"));

        let identifier = pick(&m, &["e164", "phone", "username", "group_id"])
            .unwrap_or_else(|| format!("recipient:{rid}"));

        let is_group = m.contains_key("group_id");
        map.insert(
            rid,
            Recipient {
                display,
                identifier,
                is_group,
            },
        );
    });
    gaps.record_rows("recipient", &dropped, map.len());
    if !undecoded_names.is_empty() {
        gaps.load_error(format!(
            "{} recipient row(s) carry a name column that would not decode, so the contact \
             those messages are attributed to may not be the name on the device: {}",
            undecoded_names.len(),
            undecoded_names.join("; ")
        ));
    }

    Ok(map)
}

/// Build `thread_id -> recipient_id` from the `thread` table.
///
/// `Err` when the table cannot be read, for the same reason as
/// [`build_recipient_map`]: an empty thread map silently reattributes every
/// message to its fallback counterparty.
fn build_thread_map(conn: &Connection, gaps: &mut ParseGaps) -> Result<HashMap<i64, i64>, String> {
    let mut map = HashMap::new();
    if !table_exists(conn, "thread").map_err(|e| format!("thread table probe: {e}"))? {
        return Err("thread table absent".to_string());
    }
    let cols = columns(conn, "thread", gaps);
    if cols.is_empty() {
        return Err("thread column list unreadable".to_string());
    }
    let id_col = if cols.contains("_id") { "_id" } else { "rowid" };

    // Modern: recipient_id. Older: thread_recipient_id or recipient_ids (a
    // space-separated list, first token used).
    let rcol = ["recipient_id", "thread_recipient_id", "recipient_ids"]
        .into_iter()
        .find(|c| cols.contains(*c));
    let Some(rcol) = rcol else {
        return Err("thread table carries no recipient reference column".to_string());
    };

    let sql = format!("SELECT {id_col} AS tid, {rcol} AS rid FROM thread");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("prepare thread query: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            let tid: i64 = row.get("tid")?;
            // recipient reference may be INTEGER or a TEXT id list.
            let rid = row.get::<_, Option<i64>>("rid").ok().flatten().or_else(|| {
                row.get::<_, Option<String>>("rid")
                    .ok()
                    .flatten()
                    .and_then(|s| {
                        s.split_whitespace()
                            .next()
                            .and_then(|t| t.parse::<i64>().ok())
                    })
            });
            // A thread with no counterparty stored is an ordinary empty thread.
            // A thread that stores one this build could not turn into an id is
            // not, and only the second is worth an examiner's attention — a
            // warning raised on the ordinary case is a warning they learn to
            // skip.
            let stored = !matches!(
                row.get::<_, rusqlite::types::Value>("rid"),
                Ok(rusqlite::types::Value::Null) | Err(_)
            );
            Ok((tid, rid, stored))
        })
        .map_err(|e| format!("query thread rows: {e}"))?;
    let mut dropped = Drops::default();
    let mut unresolved = 0usize;
    count_undecodable(
        rows,
        "thread",
        &mut dropped,
        |(tid, rid, stored)| match rid {
            Some(rid) => {
                map.insert(tid, rid);
            }
            // Its messages now fall through to a fallback counterparty and are
            // attributed to somebody this thread never named.
            None if stored => unresolved = unresolved.saturating_add(1),
            None => {}
        },
    );
    gaps.record_rows("thread", &dropped, map.len());
    // Not `record_rows`: these rows read in full. A legacy `recipient_ids`
    // column holding a group id (`__textsecure_group__!...`) resolves to no
    // recipient row, which is the ordinary state of a group thread on that
    // schema — reporting it as an undecodable row would put a fabricated loss
    // in the case and make an exact message count read as a floor.
    gaps.unresolved_thread_recipients =
        gaps.unresolved_thread_recipients.saturating_add(unresolved);
    Ok(map)
}

/// Set of message ids that have at least one attachment. Reads the modern
/// `attachment.message_id` or the legacy `part.mid`.
///
/// Not best-effort any more, because the absence of an id from this set becomes
/// `has_attachments: false` on the message — a positive statement that nothing
/// was sent with it. A query that would not run produced exactly that statement
/// for every message in the database, from a failure. Every way this walk can
/// come up short is now recorded in `gaps`.
fn build_attachment_msgids(conn: &Connection, gaps: &mut ParseGaps) -> HashSet<i64> {
    let mut set = HashSet::new();
    let candidates: &[(&str, &str)] = &[("attachment", "message_id"), ("part", "mid")];
    for (table, col) in candidates {
        match table_exists(conn, table) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                // Not "no attachments": the index could not be looked for, and
                // every message would otherwise read as having carried nothing.
                gaps.load_error(format!(
                    "{table}: attachment index could not be looked for ({e}), so every message \
                     reads as having no attachment"
                ));
                continue;
            }
        }
        let cols = columns(conn, table, gaps);
        if cols.is_empty() {
            gaps.load_error(format!(
                "{table}: attachment index unreadable, so every message reads as having no \
                 attachment"
            ));
            continue;
        }
        if !cols.contains(*col) {
            continue;
        }
        let sql = format!("SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL");
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                gaps.load_error(format!("prepare {table} attachment index: {e}"));
                continue;
            }
        };
        let rows = match stmt.query_map([], |r| r.get::<_, i64>(0)) {
            Ok(r) => r,
            Err(e) => {
                gaps.load_error(format!("query {table} attachment index: {e}"));
                continue;
            }
        };
        let before = set.len();
        let mut dropped = Drops::default();
        count_undecodable(rows, table, &mut dropped, |id| {
            set.insert(id);
        });
        gaps.record_rows(
            format!("the {table} attachment index"),
            &dropped,
            set.len() - before,
        );
    }
    set
}

/// Signal `type` bitmask -> outgoing? (`MmsSmsColumns.Types`).
fn is_outgoing_type(t: i64) -> bool {
    matches!(t & 0x1F, 21..=26)
}

/// What one message-store walk produced.
struct MessageWalk {
    artifacts: Vec<Artifact>,
    /// The row budget, so the caller can see whether the walk stopped at it.
    cap: CapCounter,
    /// Set when the store could not be read at all (schema this build's SQL does
    /// not fit). An empty walk with this set is "unreadable", not "no messages".
    error: Option<String>,
    /// The field map the query was written from, for the schema record.
    /// `None` when the column list could not be read: "no column recognised"
    /// is then not what happened, and `gaps` already says what did.
    fields: Option<FieldMap>,
}

/// Parse messages from one store table (`message`, `sms`, or `mms`).
#[allow(clippy::too_many_arguments)]
fn parse_message_table(
    conn: &Connection,
    table: &str,
    recipients: &HashMap<i64, Recipient>,
    threads: &HashMap<i64, i64>,
    attachments: &HashSet<i64>,
    case_id: Uuid,
    parent_id: Uuid,
    remaining: usize,
    gaps: &mut ParseGaps,
) -> MessageWalk {
    let mut out = Vec::new();
    let mut cap = CapCounter::new(remaining);
    let cols = columns(conn, table, gaps);
    if cols.is_empty() {
        return MessageWalk {
            artifacts: out,
            cap,
            error: Some(format!("{table}: PRAGMA table_info returned no columns")),
            fields: None,
        };
    }
    let id_col = if cols.contains("_id") { "_id" } else { "rowid" };

    // Only select columns that resolve, each under the name the row reader
    // reads by; a logical field no candidate matched is left out here and
    // recorded on the map, so the schema record can name it.
    let fields = FieldMap::resolve(&cols, MESSAGE_FIELDS);
    let mut sel = format!("{id_col} AS mid");
    for (logical, candidates) in MESSAGE_FIELDS {
        if let (Some(col), Some(alias)) = (fields.column(logical), candidates.first()) {
            sel.push_str(&format!(", {col} AS {alias}"));
        }
    }
    let order = ["received_at", "sent_at", "date"]
        .into_iter()
        .find_map(|f| fields.column(f))
        .unwrap_or("mid");

    // One row past the budget is fetched purely so the walk can tell "this store
    // held exactly `remaining` messages" from "we stopped reading".
    let sql = format!(
        "SELECT {sel} FROM {table} ORDER BY {order} DESC LIMIT {}",
        cap.limit()
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            return MessageWalk {
                artifacts: out,
                cap,
                error: Some(format!("prepare {table} query: {e}")),
                fields: Some(fields),
            }
        }
    };

    let rows = stmt.query_map([], |row| {
        let mut undecoded: Vec<&'static str> = Vec::new();
        // `address` is probed as both an id and a literal string, so exactly
        // one of the two always fails to decode on a schema that has it. Only
        // the outcome where NEITHER worked is a loss, so it is judged after.
        let mut address_undecoded: Vec<&'static str> = Vec::new();
        let address_id = opt_col::<i64>(row, "address", &mut address_undecoded);
        let address_str = opt_col::<String>(row, "address", &mut address_undecoded);
        if address_id.is_none() && address_str.is_none() && !address_undecoded.is_empty() {
            undecoded.push("address");
        }
        Ok(MsgRow {
            mid: row.get::<_, i64>("mid")?,
            thread_id: opt_col(row, "thread_id", &mut undecoded),
            from_id: opt_col(row, "from_recipient_id", &mut undecoded),
            to_id: opt_col(row, "to_recipient_id", &mut undecoded),
            address_id,
            address_str,
            body: opt_col(row, "body", &mut undecoded),
            date: opt_col(row, "date", &mut undecoded),
            date_sent: opt_col(row, "date_sent", &mut undecoded),
            date_received: opt_col(row, "date_received", &mut undecoded),
            mtype: opt_col(row, "type", &mut undecoded),
            read: opt_col(row, "read", &mut undecoded),
            undecoded,
        })
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return MessageWalk {
                artifacts: out,
                cap,
                error: Some(format!("query {table} rows: {e}")),
                fields: Some(fields),
            }
        }
    };

    let mut dropped = Drops::default();
    for row in rows {
        if !cap.admit() {
            break;
        }
        let r = match row {
            Ok(r) => r,
            Err(e) => {
                // A message that IS in the store and would not decode. Counted,
                // never merely logged: the tally this walk feeds is what an
                // examiner reads as the size of the conversation (B3-023).
                dropped.record(&e);
                debug!("Signal: {table} message row would not decode: {e}");
                continue;
            }
        };
        out.push(row_to_artifact(
            &r,
            table,
            recipients,
            threads,
            attachments,
            case_id,
            parent_id,
        ));
    }
    gaps.record_rows(table, &dropped, out.len());
    MessageWalk {
        artifacts: out,
        cap,
        error: None,
        fields: Some(fields),
    }
}

struct MsgRow {
    mid: i64,
    thread_id: Option<i64>,
    from_id: Option<i64>,
    to_id: Option<i64>,
    address_id: Option<i64>,
    address_str: Option<String>,
    body: Option<String>,
    date: Option<i64>,
    date_sent: Option<i64>,
    date_received: Option<i64>,
    mtype: Option<i64>,
    read: Option<i64>,
    /// Columns present on this row whose value would not decode.
    ///
    /// Kept per row rather than tallied, because the consequence differs by
    /// column: an undecodable `body` is a message whose text was not recovered,
    /// an undecodable `date` is a message with no place on the timeline. The
    /// record has to say which, where the examiner reads it.
    undecoded: Vec<&'static str>,
}

#[allow(clippy::too_many_arguments)]
fn row_to_artifact(
    r: &MsgRow,
    service: &str,
    recipients: &HashMap<i64, Recipient>,
    threads: &HashMap<i64, i64>,
    attachments: &HashSet<i64>,
    case_id: Uuid,
    parent_id: Uuid,
) -> Artifact {
    // `type` is the only column that says who wrote the message. A NULL never
    // recorded it, so the direction stays unknown rather than being asserted as
    // inbound: attributing a message to the wrong party is among the most
    // consequential errors this tool can make, and a fabricated "received" is
    // indistinguishable downstream from one the store actually held. Matching
    // Telegram/iMessage, an unknown direction is omitted, not defaulted.
    let is_from_me = r.mtype.map(is_outgoing_type);
    let direction = is_from_me.map(|m| if m { "sent" } else { "received" });

    // The conversation partner: the thread's recipient (groups the chat), then
    // the message's own counterparty. Which of `to_id` / `from_id` holds the
    // partner depends on the direction, so with the direction unknown neither is
    // used — only the direction-independent thread partner and address.
    let thread_partner = r.thread_id.and_then(|t| threads.get(&t)).copied();
    let counterparty = match is_from_me {
        Some(true) => r.to_id.or(thread_partner),
        Some(false) => r.from_id.or(r.address_id).or(thread_partner),
        None => thread_partner,
    }
    .or(r.address_id)
    .or(thread_partner);

    let chat_ref = thread_partner.or(counterparty);
    let chat_recip = chat_ref.and_then(|id| recipients.get(&id));

    let (contact, chat_identifier, is_group) = match chat_recip {
        Some(rc) => (rc.display.clone(), rc.identifier.clone(), rc.is_group),
        None => {
            // Fall back to a literal address string or the thread id.
            let ident = r
                .address_str
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| r.thread_id.map(|t| format!("thread:{t}")))
                .unwrap_or_else(|| "unknown".to_string());
            (ident.clone(), ident, false)
        }
    };

    // The actual sender label ("Me" for outgoing). With the direction unknown
    // the sender is only named when the row itself names one: falling back to
    // the chat partner would put a name on a message that may have been the
    // owner's own.
    let sender = match is_from_me {
        Some(true) => Some("Me".to_string()),
        Some(false) => Some(
            r.from_id
                .or(r.address_id)
                .and_then(|id| recipients.get(&id))
                .map(|rc| rc.display.clone())
                .or_else(|| r.address_str.clone().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| contact.clone()),
        ),
        None => r
            .from_id
            .or(r.address_id)
            .and_then(|id| recipients.get(&id))
            .map(|rc| rc.display.clone())
            .or_else(|| r.address_str.clone().filter(|s| !s.is_empty())),
    };

    let has_attachments = attachments.contains(&r.mid);
    // First column present wins, and the unit is judged from its magnitude.
    let date_raw = r.date_received.or(r.date_sent).or(r.date);
    let date_secs = normalize_epoch_secs(date_raw);

    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("Signal"));
    meta.insert("service".into(), json!("Signal"));
    // Absent, not false: an unknown direction must not read as "received", and
    // an unnamed sender must not read as the chat partner.
    if let Some(from_me) = is_from_me {
        meta.insert("is_from_me".into(), json!(from_me));
    }
    if let Some(d) = direction {
        meta.insert("direction".into(), json!(d));
    }
    meta.insert("contact".into(), json!(contact));
    if let Some(s) = &sender {
        meta.insert("sender".into(), json!(s));
    }
    meta.insert("chat_identifier".into(), json!(chat_identifier));
    meta.insert("chat_display_name".into(), json!(contact));
    meta.insert("has_attachments".into(), json!(has_attachments));
    meta.insert("is_group".into(), json!(is_group));
    meta.insert("rowid".into(), json!(r.mid));
    meta.insert("store".into(), json!(service));
    if let Some(t) = r.thread_id {
        meta.insert("thread_id".into(), json!(t));
    }
    if let Some(b) = &r.body {
        meta.insert("text".into(), json!(b));
    }
    if let Some(mt) = r.mtype {
        meta.insert("message_type".into(), json!(mt));
    }
    if let Some(rd) = r.read {
        meta.insert("read".into(), json!(rd != 0));
    }
    match date_secs {
        Some(secs) => {
            meta.insert("date".into(), json!(secs));
            if let Some(rfc) = to_rfc3339(secs) {
                meta.insert("date_rfc3339".into(), json!(rfc));
            }
        }
        // The column held a value and no reading of it is an instant. That the
        // store wrote a 0 or a negative is an observation worth keeping, so it
        // is kept — under a key no consumer can mistake for a time, matching
        // the `_unusable`/`_raw` pair the utmp parser already uses for this.
        // Neither `date` nor `date_rfc3339` is written: a
        // "1970-01-01T00:00:00+00:00" string standing next to an omitted
        // `date` would be the same false claim in another field. With every
        // date column NULL there is nothing to show and no mark is made, so
        // "the store held no timestamp" stays distinct from "the store held one
        // that cannot be read".
        None => {
            if let Some(raw) = date_raw {
                meta.insert("date_unusable".into(), json!(true));
                meta.insert("date_raw".into(), json!(raw));
            }
        }
    }
    // Columns this row holds that would not decode. Stamped on the message
    // itself: an absent `text` on a record with no mark reads as a message that
    // carried none, which is a statement about what was said.
    if !r.undecoded.is_empty() {
        meta.insert("content_incomplete".into(), json!(true));
        meta.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        meta.insert("undecoded_columns".into(), json!(r.undecoded));
        meta.insert(
            "incomplete_detail".into(),
            json!(format!(
                "this row's {} column(s) would not decode ({}), so what is missing here was \
                 not recovered rather than not present",
                r.undecoded.len(),
                r.undecoded.join(", ")
            )),
        );
    }

    let preview = r
        .body
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    meta.insert(
        "name".into(),
        json!(format!(
            "{}: {} — {}",
            direction.unwrap_or("message"),
            contact,
            if preview.is_empty() {
                if has_attachments {
                    "(attachment)"
                } else {
                    "(no text)"
                }
            } else {
                &preview
            }
        )),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("chat_message")
}

/// Emit contact records from the recipient table.
///
/// Returns the artifacts and the row budget that produced them. Iteration is by
/// ascending recipient id, not `HashMap` order: when the cap bites, *which*
/// contacts are dropped must be reproducible across runs rather than a different
/// arbitrary subset each time the same evidence is processed.
fn contact_artifacts(
    recipients: &HashMap<i64, Recipient>,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> (Vec<Artifact>, CapCounter) {
    let mut out = Vec::new();
    let mut cap = CapCounter::new(max_entries);
    let mut ids: Vec<i64> = recipients.keys().copied().collect();
    ids.sort_unstable();
    for rid in ids {
        if !cap.admit() {
            break;
        }
        let rc = &recipients[&rid];
        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("SignalContact"));
        meta.insert("service".into(), json!("Signal"));
        meta.insert("recipient_id".into(), json!(rid));
        meta.insert("contact".into(), json!(rc.display));
        meta.insert("identifier".into(), json!(rc.identifier));
        meta.insert("is_group".into(), json!(rc.is_group));
        meta.insert(
            "name".into(),
            json!(format!("Signal contact: {}", rc.display)),
        );
        out.push(
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype("contact"),
        );
    }
    (out, cap)
}

/// Parse a decrypted Signal database into chat + contact + summary records.
fn parse_signal_db(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Vec<Artifact> {
    parse_signal_db_capped(
        conn,
        case_id,
        parent_id,
        file_name,
        MAX_MESSAGE_ENTRIES,
        MAX_CONTACT_ENTRIES,
    )
}

/// [`parse_signal_db`] with the row budgets supplied, so the cap-reached paths
/// are reachable in a test without seeding half a million messages.
fn parse_signal_db_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    max_messages: usize,
    max_contacts: usize,
) -> Vec<Artifact> {
    parse_signal_db_with(
        conn,
        case_id,
        parent_id,
        file_name,
        max_messages,
        max_contacts,
        &SCHEMA_SUPPORT,
    )
}

/// [`parse_signal_db_capped`] under an explicit schema declaration, so the
/// out-of-range paths are reachable in a test while the crate's own
/// declaration stays Unranged.
#[allow(clippy::too_many_arguments)]
fn parse_signal_db_with(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    max_messages: usize,
    max_contacts: usize,
    support: &SchemaSupport,
) -> Vec<Artifact> {
    // A lookup table that could not be read is recorded, not swallowed: an empty
    // recipient map silently renames every correspondent to "Recipient {id}",
    // and an empty thread map re-attributes messages to a fallback counterparty.
    let mut gaps = ParseGaps::default();
    let recipients = match build_recipient_map(conn, &mut gaps) {
        Ok(m) => m,
        Err(e) => {
            gaps.load_error(format!("recipients: {e}"));
            HashMap::new()
        }
    };
    let threads = match build_thread_map(conn, &mut gaps) {
        Ok(m) => m,
        Err(e) => {
            gaps.load_error(format!("threads: {e}"));
            HashMap::new()
        }
    };
    let attachments = build_attachment_msgids(conn, &mut gaps);

    let mut artifacts = Vec::new();

    // Message stores, newest-schema first. `message` is the modern unified
    // table; older builds split into `sms`/`mms`.
    let mut message_count = 0usize;
    let mut messages_truncated = false;
    // One schema record per message table walked, appended after the walks
    // so its recovered count is the walk's own.
    let mut schema_records: Vec<Artifact> = Vec::new();
    let version = user_version(conn);
    let mut schema_record = |table: &str, fields: Option<&FieldMap>, recovered: usize| {
        if let Some(fields) = fields {
            schema_records.extend(
                SchemaCheck {
                    support,
                    version: version.clone(),
                    fields,
                    required: REQUIRED_FIELDS,
                    record_type: "SignalIncomplete",
                    store: table,
                }
                .marker(case_id, parent_id, recovered),
            );
        }
    };
    // A probe that errored is recorded, then treated as "not this schema" so the
    // legacy tables are still tried. Without the record, a catalogue this build
    // could not read produced a store with no messages and nothing to say so.
    let has_modern = match table_exists(conn, "message") {
        Ok(v) => v,
        Err(e) => {
            gaps.load_error(format!("message table probe: {e}"));
            false
        }
    };
    if has_modern {
        let walk = parse_message_table(
            conn,
            "message",
            &recipients,
            &threads,
            &attachments,
            case_id,
            parent_id,
            max_messages,
            &mut gaps,
        );
        message_count += walk.artifacts.len();
        messages_truncated |= walk.cap.truncated();
        schema_record("message", walk.fields.as_ref(), walk.artifacts.len());
        if let Some(e) = walk.error {
            gaps.load_error(format!("message store: {e}"));
        }
        if walk.cap.truncated() {
            artifacts.push(cap_marker(
                case_id,
                parent_id,
                "SignalIncomplete",
                "message",
                &walk.cap,
            ));
        }
        artifacts.extend(walk.artifacts);
    } else {
        for table in ["sms", "mms"] {
            let present = match table_exists(conn, table) {
                Ok(v) => v,
                Err(e) => {
                    gaps.load_error(format!("{table} table probe: {e}"));
                    false
                }
            };
            if present && message_count < max_messages {
                let walk = parse_message_table(
                    conn,
                    table,
                    &recipients,
                    &threads,
                    &attachments,
                    case_id,
                    parent_id,
                    max_messages - message_count,
                    &mut gaps,
                );
                message_count += walk.artifacts.len();
                messages_truncated |= walk.cap.truncated();
                schema_record(table, walk.fields.as_ref(), walk.artifacts.len());
                if let Some(e) = walk.error {
                    gaps.load_error(format!("{table} store: {e}"));
                }
                if walk.cap.truncated() {
                    artifacts.push(cap_marker(
                        case_id,
                        parent_id,
                        "SignalIncomplete",
                        table,
                        &walk.cap,
                    ));
                }
                artifacts.extend(walk.artifacts);
            }
        }
    }

    artifacts.extend(schema_records);

    let contact_count = recipients.len();
    let (contacts, contact_cap) = contact_artifacts(&recipients, case_id, parent_id, max_contacts);
    let contacts_emitted = contacts.len();
    artifacts.extend(contacts);
    if contact_cap.truncated() {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "SignalContactIncomplete",
            "recipient",
            &contact_cap,
        ));
    }

    stamp_short_listing(&mut artifacts, &gaps);

    // Summary (subtype "summary" so comms/timeline normalisers skip it).
    //
    // `message_count` is what this tool extracted, not what the device holds:
    // the walk is newest-first, so a cap drops the OLDEST messages. Saying "N
    // messages" with no marker would present the newest N as the whole store.
    let mut summary = serde_json::Map::new();
    summary.insert("type".into(), json!("SignalSummary"));
    summary.insert("service".into(), json!("Signal"));
    summary.insert("message_count".into(), json!(message_count));
    summary.insert("contact_count".into(), json!(contact_count));
    // The recipient rows read vs the contact records emitted: these differ when
    // the contact cap bites, and the difference must be visible rather than
    // leaving the inventory quietly shorter than the count beside it.
    summary.insert("contacts_emitted".into(), json!(contacts_emitted));
    summary.insert("thread_count".into(), json!(threads.len()));
    summary.insert("file_name".into(), json!(file_name));
    if messages_truncated || contact_cap.truncated() {
        summary.insert("truncated".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        summary.insert("messages_truncated".into(), json!(messages_truncated));
        summary.insert("contacts_truncated".into(), json!(contact_cap.truncated()));
        summary.insert("max_message_entries".into(), json!(max_messages));
        summary.insert("max_contact_entries".into(), json!(max_contacts));
    }
    // Rows that were in the database and would not decode. `message_count` and
    // `contact_count` are then floors, and the summary is the one place an
    // examiner reads them, so it has to say so beside them rather than leave
    // them looking like totals.
    if !gaps.rows.is_empty() {
        let dropped = gaps.total_dropped();
        summary.insert("rows_dropped".into(), json!(dropped));
        summary.insert("counts_are_floor".into(), json!(true));
        summary.insert(
            "rows_dropped_by_source".into(),
            json!(gaps
                .rows
                .iter()
                .map(|g| json!({
                    "source": g.source,
                    "dropped": g.dropped,
                    "recovered": g.recovered,
                }))
                .collect::<Vec<_>>()),
        );
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    // Threads whose stored counterparty this build could not resolve. No
    // message is missing, so the counts stay exact and nothing is called a
    // dropped row; what is doubtful is who those messages are filed under, and
    // an examiner correlating contacts has to be told before they rely on it.
    if gaps.unresolved_thread_recipients > 0 {
        summary.insert(
            "threads_with_unresolved_recipient".into(),
            json!(gaps.unresolved_thread_recipients),
        );
        summary.insert(
            "attribution_detail".into(),
            json!(format!(
                "{} thread(s) store a counterparty reference this build could not resolve to a \
                 recipient; their messages are attributed to a fallback counterparty, so the \
                 correspondent shown for them may not be the one the device recorded",
                gaps.unresolved_thread_recipients
            )),
        );
    }
    if !gaps.load_errors.is_empty() {
        summary.insert("parse_incomplete".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("load_errors".into(), json!(gaps.load_errors.clone()));
    }
    summary.insert(
        "name".into(),
        json!(format!(
            "Signal: {}{} messages, {} contacts",
            if gaps.is_complete() { "" } else { "at least " },
            message_count,
            contact_count
        )),
    );
    artifacts.push(
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(summary),
        )
        .with_parent(parent_id)
        .with_subtype("summary"),
    );

    // A table this build's SQL could not read is its own finding: without it,
    // "no recipients" / "no messages" is the only thing the case shows, and it
    // reads as a fact about the device.
    if !gaps.load_errors.is_empty() {
        // Typed apart from "Signal": `seance_db` groups conversations by
        // `metadata.$.type`, so filing this under the message type would invent
        // a one-message conversation out of a failure notice.
        let metadata = json!({
            "type": "SignalIncomplete",
            "subtype": "parse_incomplete",
            "service": "Signal",
            "status": "TableUnreadable",
            "file_name": file_name,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "load_errors": gaps.load_errors.clone(),
            "name": format!("Signal: part of {file_name} could not be read"),
        });
        artifacts.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("parse_incomplete"),
        );
    }

    // One marker per walk that lost rows, naming the table, so the loss is a
    // record in the case and not a debug line.
    for gap in &gaps.rows {
        artifacts.push(dropped_rows_marker(case_id, parent_id, file_name, gap));
    }

    artifacts
}

/// Mark the messages and contacts this parse did publish as a SHORT list, when
/// rows of the store they came from would not decode.
///
/// The marker records below are typed apart from the messages on purpose, and
/// that is exactly why they are not enough on their own. The examiner does not
/// browse record types looking for notices: they open the Signal conversation
/// viewer, which is scoped to records of `type: "Signal"`
/// (`frontend/src/pages/analysis/RecordsViewerPage.tsx` fetches one type and
/// raises its banner from `readIncompleteness` over those records), or the
/// Communications page, which reads the same 16 message types
/// (`frontend/src/pages/comms/normalize.ts`). Neither fetches `SignalSummary`
/// or `SignalIncomplete`. Without this the conversation an examiner reads shows
/// a clean, exact-looking thread over a store that lost rows.
///
/// `inventory_incomplete`, not `content_incomplete`: each record here decoded
/// whole. What is short is the LIST it belongs to. A parse that lost nothing
/// stamps nothing, so an unmarked conversation still means the whole one.
fn stamp_short_listing(artifacts: &mut [Artifact], gaps: &ParseGaps) {
    if gaps.rows.is_empty() {
        return;
    }
    let sources: Vec<&str> = gaps.rows.iter().map(|g| g.source.as_str()).collect();
    let detail = format!(
        "{} row(s) of this Signal store would not decode ({}), so this list is short of \
         messages or contacts the database holds and the records shown are not all of them",
        gaps.total_dropped(),
        sources.join(", ")
    );
    for artifact in artifacts.iter_mut() {
        let Some(map) = artifact.metadata.as_object_mut() else {
            continue;
        };
        if !matches!(
            map.get("type").and_then(|v| v.as_str()),
            Some("Signal") | Some("SignalContact")
        ) {
            continue;
        }
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        map.insert("inventory_incomplete_detail".into(), json!(detail.clone()));
    }
}

/// The artifact that says a SQL walk fetched rows it could not decode.
///
/// What an examiner learns: how many rows of `gap.source` were in the database
/// and undecodable, so the count beside them is a floor and not a total. A
/// wrong answer looks like an exact-sounding "312 messages" for a store that
/// held 340, with the 28 that were damaged — and therefore the ones most likely
/// to matter — dropped into a log line nothing downstream reads (B3-023).
///
/// `type` is deliberately not `"Signal"`: `seance_db` groups conversations by
/// `metadata.$.type`, so reusing the message type would file this notice as a
/// message and invent a one-message conversation out of it.
fn dropped_rows_marker(case_id: Uuid, parent_id: Uuid, file_name: &str, gap: &RowGap) -> Artifact {
    let RowGap {
        source,
        dropped,
        first_error,
        recovered,
    } = gap;
    // The decoder's reason, where there is one. Without it the examiner is told
    // the list is a floor and never what defeated the decoder, which is the part
    // that says whether the loss is recoverable (SIG-001).
    let detail = match first_error {
        Some(err) => format!(
            "{dropped} row(s) of {source} in {file_name} could not be decoded and are absent \
             from the {recovered} record(s) recovered from it, so that count is a lower bound \
             (first error: {err})"
        ),
        None => format!(
            "{dropped} row(s) of {source} in {file_name} could not be decoded and are absent \
             from the {recovered} record(s) recovered from it, so that count is a lower bound"
        ),
    };
    let metadata = json!({
        "type": "SignalIncomplete",
        "subtype": "parse_incomplete",
        "service": "Signal",
        "status": "RowsUndecodable",
        "source_table": source,
        "file_name": file_name,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete": true,
        "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "rows_dropped": dropped,
        "records_recovered": recovered,
        "first_error": first_error,
        // Both `<flag>_detail` keys, not only a bare `detail`:
        // `frontend/src/lib/incompleteness.ts` keys the parser's sentence off
        // `content_incomplete_detail` / `inventory_incomplete_detail` and reads
        // nothing named `detail`. Without them the examiner met "unresolved
        // structure" and never the count, the table or the file it came from.
        // `detail` is kept beside them for consumers already on it.
        "content_incomplete_detail": detail,
        "inventory_incomplete_detail": detail,
        "detail": detail,
        "name": format!("Signal: incomplete — {detail}"),
    });
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(parent_id)
        .with_subtype("parse_incomplete")
}

// ===========================================================================
// Capability (B): Signal Android backup decryption
// ===========================================================================

/// Signal's key stretch: SHA-512 iterated [`KDF_ROUNDS`] times, seeded with the
/// salt, hashing `(runningHash || passphraseBytes)` each round, truncated to 32
/// bytes. `passphrase` has spaces removed and is taken as ASCII bytes, exactly
/// as `FullBackupExporter.getBackupKey`.
pub fn derive_backup_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let input: Vec<u8> = passphrase.bytes().filter(|b| *b != b' ').collect();

    let mut digest = Sha512::new();
    if !salt.is_empty() {
        digest.update(salt);
    }
    let mut hash: Vec<u8> = input.clone();
    for _ in 0..KDF_ROUNDS {
        digest.update(&hash);
        digest.update(&input);
        hash = digest.finalize_reset().to_vec();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key
}

/// `HKDF-SHA256(ikm=backupKey, salt=zeros, info="Backup Export")` -> (cipherKey,
/// macKey). `Hkdf::new(None, ..)` uses a HashLen-zero salt, matching Signal's
/// explicit `new byte[32]`.
fn derive_backup_subkeys(backup_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, backup_key);
    let mut okm = [0u8; 64];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("64 bytes is within HKDF output limit");
    let mut cipher_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    cipher_key.copy_from_slice(&okm[..32]);
    mac_key.copy_from_slice(&okm[32..]);
    (cipher_key, mac_key)
}

/// A typed SQL parameter from a `statement` frame.
#[derive(Debug, Clone, PartialEq)]
enum SqlParam {
    Str(String),
    Int(i64),
    Double(f64),
    Blob(Vec<u8>),
    Null,
}

impl SqlParam {
    fn to_sql_value(&self) -> SqlValue {
        match self {
            SqlParam::Str(s) => SqlValue::Text(s.clone()),
            SqlParam::Int(i) => SqlValue::Integer(*i),
            SqlParam::Double(d) => SqlValue::Real(*d),
            SqlParam::Blob(b) => SqlValue::Blob(b.clone()),
            SqlParam::Null => SqlValue::Null,
        }
    }
}

struct SqlStatement {
    sql: String,
    params: Vec<SqlParam>,
}

/// A decrypted frame, classified for the replay loop.
enum Frame {
    Statement(SqlStatement),
    /// The `DatabaseVersion` frame: Signal's migration number for the store
    /// the statements rebuild.
    Version(u32),
    End,
    Other,
}

/// Streaming reader over the encrypted frame sequence. Header is parsed in
/// [`BackupReader::new`]; [`BackupReader::next_frame`] yields decrypted frames.
struct BackupReader<'a> {
    data: &'a [u8],
    pos: usize,
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
    counter: u32,
    /// Frames whose MAC has verified. A MAC failure before any has verified
    /// is [`WrongPassphrase`] (wrong passphrase or corrupt first frame); one
    /// after is a corrupt backup that the passphrase did open.
    macs_verified: u64,
}

/// The first frame's MAC did not verify. Either the passphrase derived the
/// wrong MAC key or the first frame's bytes are corrupt: the MAC cannot tell
/// the two apart, so this is reported as a rejection that names both
/// (`SEC-204`). Every other decryption failure is a failure of the backup.
#[derive(Debug)]
pub(crate) struct WrongPassphrase;

impl std::fmt::Display for WrongPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "bad frame MAC on the first frame (wrong passphrase, or the first frame is corrupt)",
        )
    }
}

impl std::error::Error for WrongPassphrase {}

impl<'a> BackupReader<'a> {
    fn new(data: &'a [u8], passphrase: &str) -> Result<Self> {
        let len =
            read_u32_be(data, 0).ok_or_else(|| anyhow!("backup too short for header"))? as usize;
        if len == 0 || len > MAX_FRAME_LEN || 4 + len > data.len() {
            anyhow::bail!("invalid backup header length");
        }
        let (iv_bytes, salt) = parse_header_frame(&data[4..4 + len])
            .ok_or_else(|| anyhow!("first frame is not a valid Signal backup header"))?;
        if iv_bytes.len() != 16 {
            anyhow::bail!("backup header IV must be 16 bytes, got {}", iv_bytes.len());
        }

        let backup_key = derive_backup_key(passphrase, &salt);
        let (cipher_key, mac_key) = derive_backup_subkeys(&backup_key);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_bytes);
        let counter = u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]);

        Ok(Self {
            data,
            pos: 4 + len,
            cipher_key,
            mac_key,
            iv,
            counter,
            macs_verified: 0,
        })
    }

    fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.pos >= self.data.len() {
            return Ok(None); // clean EOF
        }
        let len = read_u32_be(self.data, self.pos)
            .ok_or_else(|| anyhow!("truncated frame length"))? as usize;
        self.pos += 4;
        if !(10..=MAX_FRAME_LEN).contains(&len) {
            anyhow::bail!("invalid frame length {}", len);
        }
        if self.pos + len > self.data.len() {
            anyhow::bail!("truncated frame body");
        }
        let frame = &self.data[self.pos..self.pos + len];
        self.pos += len;

        let (ciphertext, their_mac) = frame.split_at(len - 10);

        // Verify HMAC-SHA256 over the ciphertext, truncated to 10 bytes. A wrong
        // passphrase yields a wrong macKey and fails here.
        let mut mac = HmacSha256::new_from_slice(&self.mac_key).expect("hmac key length");
        mac.update(ciphertext);
        if mac.verify_truncated_left(their_mac).is_err() {
            if self.macs_verified == 0 {
                return Err(anyhow::Error::new(WrongPassphrase));
            }
            anyhow::bail!("bad frame MAC (corrupt backup)");
        }
        self.macs_verified += 1;

        // AES-256-CTR with the counter written into the IV's first 4 bytes.
        self.iv[..4].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let mut plaintext = ciphertext.to_vec();
        let mut cipher = Aes256Ctr::new_from_slices(&self.cipher_key, &self.iv)
            .map_err(|_| anyhow!("AES-CTR init failed"))?;
        cipher.apply_keystream(&mut plaintext);

        let parsed = parse_backup_frame(&plaintext);

        // Attachment/avatar/sticker frames are followed by a raw blob
        // (`length` bytes + 10-byte HMAC, no length prefix). Skip it while
        // keeping the counter aligned (one increment per blob).
        if let Some(blob_len) = parsed.blob_len {
            self.counter = self.counter.wrapping_add(1);
            let to_skip = blob_len
                .checked_add(10)
                .ok_or_else(|| anyhow!("blob length overflow"))?;
            if self.pos + to_skip > self.data.len() {
                anyhow::bail!("truncated attachment blob");
            }
            self.pos += to_skip;
        }

        if parsed.end {
            Ok(Some(Frame::End))
        } else if let Some(stmt) = parsed.statement {
            Ok(Some(Frame::Statement(stmt)))
        } else if let Some(v) = parsed.version {
            Ok(Some(Frame::Version(v)))
        } else {
            Ok(Some(Frame::Other))
        }
    }
}

fn read_u32_be(data: &[u8], pos: usize) -> Option<u32> {
    if pos + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
    ]))
}

/// A decrypted Signal backup replayed into SQLite bytes, together with what the
/// replay could NOT reconstruct.
///
/// The bytes alone are not enough to report honestly: a replay that stopped at
/// [`MAX_FRAMES`], or that could not execute some of the backup's `INSERT`
/// statements, still yields a database that opens cleanly and reads as a
/// complete message store. The missing conversations then look like
/// conversations that never happened (B3-014).
#[derive(Debug)]
pub struct BackupReplay {
    /// Reconstructed database bytes.
    pub db: Vec<u8>,
    /// Frames read from the backup before the replay ended.
    pub frames_read: usize,
    /// Why the reconstruction is a PREFIX of the backup, if it is.
    /// `None` means every frame was read and every row-bearing statement
    /// applied — only then is the database the whole backup.
    pub incomplete: Option<IncompleteReason>,
    /// `INSERT` statements the replay could not execute. Each one is at least
    /// one message, contact or thread that is in the backup but not in the
    /// reconstruction.
    pub rows_lost: usize,
    /// Non-row statements (schema, index, trigger) that failed. Recorded for
    /// provenance; they do not by themselves mean content is missing.
    pub schema_statements_failed: usize,
    /// The `DatabaseVersion` frame's value, when the backup carried one. It is
    /// replayed into the reconstruction's `PRAGMA user_version` exactly as
    /// Signal-Android's importer does, so the schema record reads the version
    /// the backup declared rather than SQLite's unset default.
    pub database_version: Option<u32>,
    /// Whether the backup's terminating `End` frame was reached.
    ///
    /// `false` means the byte stream simply ran out. A backup cut on a frame
    /// boundary — a partial acquisition, or a source that delivered fewer bytes
    /// than it declared — decrypts and replays every frame it has and then
    /// stops, with nothing to distinguish that from a backup that ended because
    /// it was finished. The conversations in the missing tail then look like
    /// conversations that never happened, which is the same defect the frame
    /// ceiling had.
    pub ended_cleanly: bool,
    /// Frames whose MAC verified under the derived key. `0` means nothing
    /// tested the passphrase (a backup that ends after its header), so it is
    /// not reported as accepted (`SEC-204`).
    pub macs_verified: u64,
}

/// Decrypt a Signal Android backup and replay its `statement` frames into a
/// fresh SQLite database.
///
/// Never panics on malformed input: a bad header, wrong passphrase (MAC
/// failure), or truncation returns `Err`. A replay that ran but could not carry
/// everything across returns `Ok` with [`BackupReplay::incomplete`] set — the
/// caller MUST carry that onto what it emits.
pub fn decrypt_backup(data: &[u8], passphrase: &str) -> Result<BackupReplay> {
    decrypt_backup_limited(data, passphrase, MAX_FRAMES)
}

/// [`decrypt_backup`] with an explicit frame ceiling, so the cap-reached path is
/// reachable in a test without building a twenty-million-frame backup.
pub(crate) fn decrypt_backup_limited(
    data: &[u8],
    passphrase: &str,
    max_frames: usize,
) -> Result<BackupReplay> {
    let mut reader = BackupReader::new(data, passphrase)?;

    let temp = std::env::temp_dir().join(format!("seance_signal_replay_{}.db", Uuid::new_v4()));

    let mut frames = 0usize;
    let mut capped = false;
    let mut saw_end = false;
    let mut rows_lost = 0usize;
    let mut schema_statements_failed = 0usize;
    let mut database_version: Option<u32> = None;

    let build = (|| -> Result<()> {
        let conn = Connection::open(&temp).context("open replay db")?;
        // Speed: this is a throwaway reconstruction, not durable storage.
        let _ = conn.execute_batch(
            "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA foreign_keys=OFF;",
        );

        while let Some(frame) = reader.next_frame()? {
            frames += 1;
            if frames > max_frames {
                // The cap is a safety stop, not an end-of-backup: everything
                // after this frame is missing from the reconstruction and the
                // caller has to say so.
                warn!(
                    "Signal backup exceeded {} frames; stopping replay",
                    max_frames
                );
                frames -= 1;
                capped = true;
                break;
            }
            match frame {
                Frame::Statement(stmt) => match apply_statement(&conn, &stmt) {
                    StatementOutcome::Applied => {}
                    StatementOutcome::RowLost => rows_lost += 1,
                    StatementOutcome::SchemaFailed => schema_statements_failed += 1,
                },
                Frame::Version(v) => {
                    // The importer's `db.version = version.version`: the
                    // reconstruction then carries the version the backup
                    // declared. A pragma that will not apply is not a lost
                    // row; the version stays unrecorded and is reported so.
                    if conn
                        .execute_batch(&format!("PRAGMA user_version = {v};"))
                        .is_ok()
                    {
                        database_version = Some(v);
                    }
                }
                Frame::End => {
                    saw_end = true;
                    break;
                }
                Frame::Other => {}
            }
        }
        Ok(())
    })();

    let result = build.and_then(|()| {
        let meta = fs::metadata(&temp).context("stat replay db")?;
        if meta.len() > MAX_DB_SIZE {
            anyhow::bail!("reconstructed db too large: {} bytes", meta.len());
        }
        fs::read(&temp).context("read replay db")
    });

    let _ = fs::remove_file(&temp);

    let db = result?;
    // Ordered by how much of the backup is missing. Cap first: it is the
    // coarsest loss (an unread tail) and the one an examiner acts on by
    // re-running with a higher ceiling. A stream that ran out before its `End`
    // frame is the same shape of loss arriving from the other direction — the
    // bytes stopped, not the backup — and must not read as a finished replay.
    let incomplete = if capped {
        Some(IncompleteReason::CapReached)
    } else if !saw_end {
        Some(IncompleteReason::ShortRead)
    } else if rows_lost > 0 {
        Some(IncompleteReason::UnresolvedStructure)
    } else {
        None
    };
    Ok(BackupReplay {
        db,
        frames_read: frames,
        incomplete,
        rows_lost,
        schema_statements_failed,
        database_version,
        ended_cleanly: saw_end,
        macs_verified: reader.macs_verified,
    })
}

/// What happened to one replayed statement.
enum StatementOutcome {
    /// Applied, or deliberately skipped as one of Signal's internal tables.
    Applied,
    /// A row-bearing statement (`INSERT`) failed: a message, contact or thread
    /// present in the backup is absent from the reconstruction.
    RowLost,
    /// A schema statement (CREATE/INDEX/TRIGGER) failed. No content is lost by
    /// this alone, but it is recorded rather than swallowed.
    SchemaFailed,
}

/// Execute one replayed statement, tolerating individual failures (best-effort
/// reconstruction: an unsupported virtual-table create or a constraint error
/// must not abort the whole replay) but REPORTING them, so a reconstruction
/// that dropped rows is not returned as a faithful copy of the backup.
fn apply_statement(conn: &Connection, stmt: &SqlStatement) -> StatementOutcome {
    let trimmed = stmt.sql.trim_start().to_ascii_lowercase();
    // Signal never restores its internal FTS/sqlite_ tables verbatim; replaying
    // "CREATE TABLE sqlite_*" errors, so skip it (matches FullBackupImporter).
    if trimmed.starts_with("create table sqlite_") {
        return StatementOutcome::Applied;
    }
    let values: Vec<SqlValue> = stmt.params.iter().map(|p| p.to_sql_value()).collect();
    match conn.execute(&stmt.sql, rusqlite::params_from_iter(values)) {
        Ok(_) => StatementOutcome::Applied,
        Err(e) => {
            debug!("Skipping replayed statement (error: {})", e);
            if trimmed.starts_with("insert") || trimmed.starts_with("replace") {
                StatementOutcome::RowLost
            } else {
                StatementOutcome::SchemaFailed
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal protobuf reader (hand-rolled; avoids a build-script codegen dep).
// ---------------------------------------------------------------------------

enum WireVal<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
    /// 32-bit fixed. Signal's SqlParameter has no fixed32 field, so the payload
    /// is unused; we still consume the 4 bytes to keep the reader aligned.
    Fixed32,
}

struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_varint(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() || shift >= 64 {
                return None;
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
    }

    /// Next `(field_number, value)` or None at end / on malformed input.
    fn next(&mut self) -> Option<(u32, WireVal<'a>)> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = self.read_varint()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        let val = match wire {
            0 => WireVal::Varint(self.read_varint()?),
            1 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                WireVal::Fixed64(a)
            }
            2 => {
                let len = self.read_varint()? as usize;
                let b = self.take(len)?;
                WireVal::Bytes(b)
            }
            5 => {
                self.take(4)?;
                WireVal::Fixed32
            }
            _ => return None, // group / unknown wire type: bail
        };
        Some((field, val))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

/// Parse a plaintext header frame: `BackupFrame{ header: Header{ iv, salt } }`.
/// BackupFrame field 1 = header; Header field 1 = iv, field 2 = salt.
fn parse_header_frame(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut r = PbReader::new(bytes);
    while let Some((field, val)) = r.next() {
        if field == 1 {
            if let WireVal::Bytes(hdr) = val {
                let mut iv = None;
                let mut salt = Vec::new();
                let mut hr = PbReader::new(hdr);
                while let Some((f, v)) = hr.next() {
                    match (f, v) {
                        (1, WireVal::Bytes(b)) => iv = Some(b.to_vec()),
                        (2, WireVal::Bytes(b)) => salt = b.to_vec(),
                        _ => {}
                    }
                }
                return iv.map(|iv| (iv, salt));
            }
        }
    }
    None
}

struct ParsedFrame {
    end: bool,
    statement: Option<SqlStatement>,
    /// Present for attachment/avatar/sticker frames: the trailing blob length.
    blob_len: Option<usize>,
    /// Present for the `DatabaseVersion` frame.
    version: Option<u32>,
}

/// Parse a decrypted `BackupFrame`. Field numbers (BackupProtos.proto):
/// 2 = statement, 4 = attachment, 5 = version, 6 = end, 7 = avatar, 8 = sticker.
fn parse_backup_frame(bytes: &[u8]) -> ParsedFrame {
    let mut out = ParsedFrame {
        end: false,
        statement: None,
        blob_len: None,
        version: None,
    };
    let mut r = PbReader::new(bytes);
    while let Some((field, val)) = r.next() {
        match (field, val) {
            (2, WireVal::Bytes(b)) => out.statement = parse_statement(b),
            // Attachment.length = field 3.
            (4, WireVal::Bytes(b)) => out.blob_len = pb_uint_field(b, 3),
            // DatabaseVersion.version = field 1.
            (5, WireVal::Bytes(b)) => {
                out.version = pb_uint_field(b, 1).and_then(|v| u32::try_from(v).ok())
            }
            (6, WireVal::Varint(v)) => out.end = v != 0,
            // Avatar.length = field 2.
            (7, WireVal::Bytes(b)) => out.blob_len = pb_uint_field(b, 2),
            // Sticker.length = field 2.
            (8, WireVal::Bytes(b)) => out.blob_len = pb_uint_field(b, 2),
            _ => {}
        }
    }
    out
}

/// Read a varint field `field_num` from a sub-message as usize.
fn pb_uint_field(bytes: &[u8], field_num: u32) -> Option<usize> {
    let mut r = PbReader::new(bytes);
    while let Some((f, v)) = r.next() {
        if f == field_num {
            if let WireVal::Varint(x) = v {
                return Some(x as usize);
            }
        }
    }
    None
}

/// Parse a `SqlStatement{ statement: string(1), parameters: repeated(2) }`.
fn parse_statement(bytes: &[u8]) -> Option<SqlStatement> {
    let mut sql = None;
    let mut params = Vec::new();
    let mut r = PbReader::new(bytes);
    while let Some((field, val)) = r.next() {
        match (field, val) {
            (1, WireVal::Bytes(b)) => sql = Some(String::from_utf8_lossy(b).into_owned()),
            (2, WireVal::Bytes(b)) => {
                if let Some(p) = parse_param(b) {
                    params.push(p);
                }
            }
            _ => {}
        }
    }
    sql.map(|sql| SqlStatement { sql, params })
}

/// Parse a `SqlParameter`: 1=string, 2=uint64, 3=double, 4=bytes, 5=bool(null).
fn parse_param(bytes: &[u8]) -> Option<SqlParam> {
    let mut r = PbReader::new(bytes);
    while let Some((field, val)) = r.next() {
        match (field, val) {
            (1, WireVal::Bytes(b)) => {
                return Some(SqlParam::Str(String::from_utf8_lossy(b).into_owned()))
            }
            (2, WireVal::Varint(v)) => return Some(SqlParam::Int(v as i64)),
            (3, WireVal::Fixed64(b)) => return Some(SqlParam::Double(f64::from_le_bytes(b))),
            (4, WireVal::Bytes(b)) => return Some(SqlParam::Blob(b.to_vec())),
            (5, WireVal::Varint(v)) if v != 0 => {
                return Some(SqlParam::Null);
            }
            _ => {}
        }
    }
    // A parameter with no recognised field is treated as NULL.
    Some(SqlParam::Null)
}

// ===========================================================================
// ForensicsModule
// ===========================================================================

impl SignalParser {
    /// Evidence path: spill the database (with its `-wal` sibling, so recent
    /// uncheckpointed messages are read too), gate on the Signal schema, parse.
    ///
    /// The spill — rather than a read-then-write — is what lets a database that
    /// could not be staged in full be reported as such: SQLite opens a truncated
    /// file happily and answers from the pages it can reach, so without this the
    /// rows that survived would read as the whole message store.
    fn process_evidence_db(
        &self,
        artifact: &Artifact,
        evidence: &dyn DataSource,
        name: &str,
    ) -> Vec<Artifact> {
        // RAII temp spill: the file is removed on drop, so a parse panic between
        // spill and completion cannot leak /tmp/seance_signal_*.db.
        let temp = match TempDb::spill(evidence, "signal", MAX_DB_SIZE) {
            Ok(t) => t,
            Err(e) => {
                warn!("Signal: failed to stage DB {}: {}", name, e);
                return unreadable_store(
                    artifact,
                    name,
                    is_signal_db_name(name) || is_signal_backup_name(name),
                    format!("it could not be staged for examination: {e}"),
                );
            }
        };
        // A key spec an examiner supplied for this file (HUNT-227), and a file
        // that has the shape it opens: a genuine SQLite header reserving
        // SQLCipher's per-page bytes.
        let run_credential = seance_core::credential::for_artifact(
            artifact.id,
            &[seance_core::credential::CredentialKind::SignalIosKeySpec],
        );
        let mut out = match (&run_credential, plaintext_header_reserve(temp.path())) {
            (Some(cred), Some(_)) => self.process_ios_store(artifact, evidence, &temp, name, cred),
            _ => self.parse_staged(artifact, &temp, name),
        };
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        out
    }

    /// The Signal for iOS store, opened with the key spec supplied for it.
    ///
    /// The key spec is parsed straight into a [`seance_sqlcipher::RawKeySpec`]
    /// (zeroed on drop, redacted in `Debug`) and used for this call only. A
    /// spec that does not decrypt page 1 is reported back as rejected and the
    /// "encrypted" record is returned unchanged — the orchestrator does not
    /// persist it, so the record already in the case stands.
    fn process_ios_store(
        &self,
        artifact: &Artifact,
        evidence: &dyn DataSource,
        temp: &TempDb,
        name: &str,
        cred: &seance_core::credential::RunCredential,
    ) -> Vec<Artifact> {
        use seance_sqlcipher::{
            decrypt_v4_raw_key, decrypt_v4_raw_key_wal, RawKeySpec, SqlCipher4Config,
        };
        let key = match RawKeySpec::from_text(cred.expose_secret()) {
            Ok(k) => k,
            Err(e) => {
                cred.rejected(format!(
                    "the key spec is not in a form SQLCipher takes: {e}"
                ));
                return self.parse_staged(artifact, temp, name);
            }
        };
        let bytes = match fs::read(temp.path()) {
            Ok(b) => b,
            Err(e) => {
                cred.rejected(format!("the staged store could not be read back: {e}"));
                return self.parse_staged(artifact, temp, name);
            }
        };
        let cfg = SqlCipher4Config::signal_ios();
        let Some(decrypted) = decrypt_v4_raw_key(&bytes, &key, &cfg) else {
            cred.rejected(
                "the key spec did not decrypt the store: page 1 is not a SQLite page under it, \
                 or the spec carries no salt, or its salt is not this store's",
            );
            return self.parse_staged(artifact, temp, name);
        };
        cred.accepted();

        let wal = evidence
            .open_sibling("-wal")
            .map(|w| read_capped(w.as_ref(), MAX_DB_SIZE))
            .filter(|w| !w.is_empty())
            .and_then(|w| decrypt_v4_raw_key_wal(&w, &key, &cfg));
        drop(key);

        let staged = match TempDb::write(&decrypted.plaintext, "signal_ios") {
            Ok(t) => t,
            Err(e) => {
                return unreadable_store(
                    artifact,
                    name,
                    true,
                    format!("the decrypted store could not be staged: {e}"),
                )
            }
        };
        if let Some(w) = &wal {
            let wal_path = format!("{}-wal", staged.path().display());
            if let Err(e) = fs::write(&wal_path, &w.plaintext_wal) {
                warn!(
                    "Signal: the decrypted WAL for {} was not staged: {}",
                    name, e
                );
                let _ = fs::remove_file(&wal_path);
            }
        }
        let conn = match staged.open() {
            Ok(c) => c,
            Err(e) => {
                return unreadable_store(
                    artifact,
                    name,
                    true,
                    format!("the decrypted store would not open: {e}"),
                )
            }
        };
        if !ios_grdb::is_grdb_signal_schema(&conn) {
            return unreadable_store(
                artifact,
                name,
                true,
                "it decrypted, and it does not carry Signal for iOS's GRDB schema \
                 (model_TSInteraction, model_TSThread)"
                    .to_string(),
            );
        }
        let facts = ios_grdb::DecryptionFacts {
            pages: decrypted.pages,
            integrity_verified: decrypted.integrity_verified,
            integrity_statement: decrypted.integrity_statement.clone(),
            wal: wal.as_ref().map(|w| ios_grdb::WalFacts {
                frames_committed: w.frames_committed,
                frames_not_committed: w.frames_not_committed,
                integrity_verified: w.integrity_verified,
                integrity_statement: w.integrity_statement.clone(),
            }),
        };
        ios_grdb::parse_ios_store(&conn, artifact.case_id, artifact.id, name, &facts)
    }

    /// Reconstructed-database path: a decrypted backup replayed into fresh
    /// SQLite bytes, which has no `-wal` sibling of its own and no evidence
    /// source behind it.
    ///
    /// `incomplete` is the replay's own shortfall ([`BackupReplay::incomplete`]).
    /// The bytes are synthesized, so `TempDb` cannot work it out by comparing
    /// against a source size; it is marked explicitly, and every record parsed
    /// out of a partial replay then carries `content_incomplete` (B3-014).
    fn process_db(
        &self,
        artifact: &Artifact,
        bytes: &[u8],
        name: &str,
        incomplete: Option<IncompleteReason>,
    ) -> Vec<Artifact> {
        let mut temp = match TempDb::write(bytes, "signal") {
            Ok(t) => t,
            Err(e) => {
                warn!("Signal: failed to stage DB {}: {}", name, e);
                // The backup decrypted and the replayed database could not be
                // staged: without this the case shows a decrypted backup and no
                // messages, which reads as a backup that held none.
                return unreadable_store(
                    artifact,
                    name,
                    true,
                    format!("the replayed database could not be staged: {e}"),
                );
            }
        };
        if let Some(reason) = incomplete {
            temp.mark_content_incomplete(reason);
        }
        let mut out = self.parse_staged(artifact, &temp, name);
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        out
    }

    /// Open a staged database, gate it on the Signal schema, and parse it.
    ///
    /// The module is offered every SQLite file in the evidence, so a database
    /// that will not open or whose schema is not Signal's is ordinarily silence:
    /// raising a finding on each of them would bury the real ones. But when the
    /// FILE IS NAMED as a Signal artifact, silence is a claim — "no Signal data
    /// on this device" — and a store this build could not examine must not make
    /// it. Those two cases are what `named` separates (B7-023 class).
    fn parse_staged(&self, artifact: &Artifact, temp: &TempDb, name: &str) -> Vec<Artifact> {
        let named = is_signal_db_name(name) || is_signal_backup_name(name);
        let conn = match temp.open() {
            Ok(c) => c,
            Err(e) => {
                debug!("Signal: {} is not SQLite: {}", name, e);
                if let Some(reserve) = plaintext_header_reserve(temp.path()) {
                    return encrypted_plaintext_header_store(
                        artifact,
                        name,
                        named,
                        reserve,
                        &e.to_string(),
                    );
                }
                return unreadable_store(
                    artifact,
                    name,
                    named,
                    format!("the staged database would not open: {e}"),
                );
            }
        };
        match has_signal_schema(&conn) {
            Ok(true) => parse_signal_db(&conn, artifact.case_id, artifact.id, name),
            Ok(false) => {
                info!("Signal: {} lacks Signal schema, skipping", name);
                Vec::new()
            }
            Err(e) => {
                // A catalogue that will not read behind a header reserving
                // SQLCipher's per-page bytes is a locked store, not a damaged
                // one (Signal for iOS, plaintext header).
                if let Some(reserve) = plaintext_header_reserve(temp.path()) {
                    return encrypted_plaintext_header_store(
                        artifact,
                        name,
                        named,
                        reserve,
                        &e.to_string(),
                    );
                }
                unreadable_store(
                    artifact,
                    name,
                    named,
                    format!("the schema catalogue would not read: {e}"),
                )
            }
        }
    }

    /// Backup path: detect, take the passphrase from the run's credential,
    /// decrypt, parse.
    fn process_backup(
        &self,
        artifact: &Artifact,
        bytes: &[u8],
        name: &str,
    ) -> Result<Vec<Artifact>, ModuleError> {
        // SEC-204: the passphrase arrives only as a credential supplied for
        // this run (kind `signal_backup_passphrase`), zeroed when the run
        // ends. The artifact's metadata is not read for one: the ingest field
        // `signal_backup_password` is replaced by the redaction marker before
        // any module runs (`*_password` is scrubbed at ingest), so reading it
        // could only ever try that marker as a passphrase.
        let run_credential = seance_core::credential::for_artifact(
            artifact.id,
            &[seance_core::credential::CredentialKind::SignalBackupPassphrase],
        )
        .filter(|c| !c.expose_secret().is_empty());

        let mut marker = serde_json::Map::new();
        marker.insert("type".into(), json!("SignalBackup"));
        marker.insert("service".into(), json!("Signal"));
        marker.insert("file_name".into(), json!(name));
        marker.insert("detected".into(), json!(true));

        let Some(cred) = run_credential else {
            marker.insert("decrypted".into(), json!(false));
            marker.insert(
                "reason".into(),
                json!(
                    "no passphrase supplied (supply it with POST …/credential, kind \
                     'signal_backup_passphrase')"
                ),
            );
            marker.insert(
                "name".into(),
                json!(format!(
                    "Signal backup (locked - passphrase required): {}",
                    name
                )),
            );
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(marker),
            )
            .with_parent(artifact.id)
            .with_subtype("summary")]);
        };

        let decrypted = decrypt_backup(bytes, cred.expose_secret());
        let replay = match decrypted {
            Ok(replay) => replay,
            // The only failure reported as a verdict on the secret. The MAC
            // cannot tell a wrong passphrase from a corrupt first frame, so
            // the reason names both. Our own words, never the value.
            Err(e) if e.downcast_ref::<WrongPassphrase>().is_some() => {
                cred.rejected(
                    "the first frame's MAC did not verify: the passphrase is wrong, or the \
                     first frame is corrupt — the MAC cannot tell the two apart",
                );
                return Ok(Vec::new());
            }
            // A failure on the backup, not on the passphrase (a header that
            // does not parse, a frame corrupt after the first MAC verified):
            // a module error, so the audit does not record a verdict on a
            // secret that was never reached.
            Err(e) => {
                return Err(ModuleError::ParsingError(format!(
                    "Signal backup could not be decrypted: {e}"
                )))
            }
        };
        // A backup that ends after its header has no frame whose MAC tested
        // the passphrase: no verdict is reported (the run is `not_used`).
        if replay.macs_verified > 0 {
            cred.accepted();
        }

        Ok({
            // Reconstructed DB -> run capability (A).
            let mut out = Vec::new();
            let records = self.process_db(artifact, &replay.db, name, replay.incomplete);
            let message_count = records
                .iter()
                .filter(|a| a.metadata["type"] == "Signal")
                .count();
            let contact_count = records
                .iter()
                .filter(|a| a.metadata["type"] == "SignalContact")
                .count();

            marker.insert("decrypted".into(), json!(true));
            marker.insert("message_count".into(), json!(message_count));
            marker.insert("contact_count".into(), json!(contact_count));
            marker.insert("frames_replayed".into(), json!(replay.frames_read));
            // Always stated, so "the backup ended" and "the bytes ran out"
            // are different findings on the record rather than the same
            // silence.
            marker.insert("ended_cleanly".into(), json!(replay.ended_cleanly));
            if replay.rows_lost > 0 {
                marker.insert("rows_lost".into(), json!(replay.rows_lost));
            }
            if replay.schema_statements_failed > 0 {
                marker.insert(
                    "schema_statements_failed".into(),
                    json!(replay.schema_statements_failed),
                );
            }
            // A replay that stopped at the frame ceiling, or that could not
            // apply every row-bearing statement, decrypted only a PREFIX of
            // the backup. Without this the summary says "decrypted: true"
            // over a message store missing its later conversations.
            if let Some(reason) = replay.incomplete {
                marker.insert("content_incomplete".into(), json!(true));
                marker.insert("content_incomplete_reason".into(), json!(reason.as_str()));
                if reason == IncompleteReason::CapReached {
                    marker.insert("max_frames".into(), json!(MAX_FRAMES));
                }
                marker.insert(
                    "incomplete_detail".into(),
                    json!(match reason {
                        IncompleteReason::CapReached => format!(
                            "replay stopped at the {MAX_FRAMES}-frame ceiling; frames after \
                                 that were not applied, so later messages and contacts are absent"
                        ),
                        IncompleteReason::ShortRead => format!(
                            "the backup stream ran out after {} frames without its End \
                                 frame; the backup is truncated, so the messages and contacts \
                                 in the missing tail were never replayed",
                            replay.frames_read
                        ),
                        _ => format!(
                            "{} row-bearing statements could not be replayed; the messages, \
                                 contacts or threads they carried are absent",
                            replay.rows_lost
                        ),
                    }),
                );
            }
            marker.insert(
                "name".into(),
                json!(format!(
                    "Signal backup decrypted{}: {} messages ({})",
                    if replay.incomplete.is_some() {
                        " (PARTIAL)"
                    } else {
                        ""
                    },
                    message_count,
                    name
                )),
            );
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    serde_json::Value::Object(marker),
                )
                .with_parent(artifact.id)
                .with_subtype("summary"),
            );
            out.extend(records);
            out
        })
    }
}

impl ForensicsModule for SignalParser {
    fn id(&self) -> &str {
        "plugin.messaging.signal"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let Some(ds) = artifact.data.as_ref() else {
            // No data: emit an identification-only record for recognisable names.
            if is_signal_backup_name(&name) || is_signal_db_name(&name) {
                let kind = if is_signal_backup_name(&name) {
                    "Signal backup"
                } else {
                    "Signal database"
                };
                let metadata = json!({
                    "type": "SignalIdentified",
                    "service": "Signal",
                    "file_name": name,
                    "status": "Identified",
                    "name": format!("{} (not parsed - no data): {}", kind, name),
                });
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    metadata,
                )
                .with_parent(artifact.id)]);
            }
            return Ok(Vec::new());
        };

        // Sniff the first bytes to route without trusting the filename.
        let mut head = vec![0u8; 8192.min(ds.size().max(1) as usize)];
        let n = match ds.read_at(0, &mut head) {
            Ok(n) => n,
            Err(e) => {
                // The sniff failed, so this file was never classified. Treating
                // that as zero bytes routed a recognisable Signal artifact
                // straight out of the module and filed it, in the case, as "no
                // Signal data on this device".
                warn!("Signal: could not read the head of {}: {}", name, e);
                if !is_signal_db_name(&name) && !is_signal_backup_name(&name) {
                    return Ok(Vec::new());
                }
                let detail = format!(
                    "{name} is named as a Signal artifact and its first bytes could not be \
                     read, so it was never classified or parsed; nothing here establishes \
                     what it held"
                );
                let metadata = json!({
                    "type": "SignalIncomplete",
                    "subtype": "parse_incomplete",
                    "service": "Signal",
                    "status": "SourceUnreadable",
                    "file_name": name,
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::ShortRead.as_str(),
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::ShortRead.as_str(),
                    "error": e.to_string(),
                    "detail": detail,
                    "name": format!("Signal artifact (not read): {name}"),
                });
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    metadata,
                )
                .with_parent(artifact.id)
                .with_subtype("parse_incomplete")]);
            }
        };
        head.truncate(n);

        let is_sqlite = head.len() >= 16 && &head[..16] == SQLITE_MAGIC;

        if is_sqlite {
            // We always run the schema gate (cheap) so a renamed Signal DB is
            // still caught. The admission policy that `read_bounded` applied is
            // kept: an empty source and one past the byte cap are refused rather
            // than staged as a prefix of themselves.
            let size = ds.size();
            if size == 0 || size > MAX_DB_SIZE {
                debug!("Signal: refusing {} ({} bytes)", name, size);
                // A refusal is not an examination. For a file the case already
                // calls a Signal database, returning nothing puts "no Signal
                // messages" in the report on the strength of a size check.
                return Ok(unreadable_store(
                    artifact,
                    &name,
                    is_signal_db_name(&name),
                    format!(
                        "it is {size} bytes, outside the {MAX_DB_SIZE}-byte limit this build \
                         will stage, so it was not opened"
                    ),
                ));
            }
            return Ok(self.process_evidence_db(artifact, ds.as_ref(), &name));
        }

        // The bytes classify a backup; the name only says the sniff was worth
        // running. A `.backup` suffix on another app's file asserts nothing.
        if looks_like_backup(&head) {
            let bytes = match read_bounded(ds.as_ref(), MAX_BACKUP_SIZE) {
                Ok(b) => b,
                Err(e) => {
                    // Detected but unreadable (e.g. too large): emit a marker.
                    let metadata = json!({
                        "type": "SignalBackup",
                        "service": "Signal",
                        "file_name": name,
                        "detected": true,
                        "decrypted": false,
                        "error": e.to_string(),
                        "name": format!("Signal backup (not read): {}", name),
                    });
                    return Ok(vec![Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        metadata,
                    )
                    .with_parent(artifact.id)
                    .with_subtype("summary")]);
                }
            };
            return self.process_backup(artifact, &bytes, &name);
        }

        if is_signal_backup_name(&name) {
            return Ok(unrecognised_backup(artifact, &name));
        }

        // Named as a Signal database, not SQLite: SQLCipher salt, or something
        // else entirely. Either way it was not opened, and that is a finding.
        if is_signal_db_name(&name) {
            return Ok(not_sqlite_store(artifact, &name, ds.size()));
        }

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests;

/// The magnitude contract, stated for this parser: whatever unit the Signal
/// store recorded, `date` must come out a whole Unix second an examiner could
/// read as a date.
///
/// It lives beside the record builder rather than in `tests.rs` because it is a
/// statement about the record this file emits, and it is the guard that stops a
/// future edit reintroducing a two-branch `raw < 10^11 ? raw : raw / 1000`
/// normaliser — which reads a 16-digit microsecond value as milliseconds and
/// dates the message to the year 55840.
#[cfg(test)]
mod magnitude_contract {
    use super::*;
    use seance_sqlite_util::chat::is_plausible_instant_secs;

    /// 2023-11-14T22:13:20Z — the one instant every row below claims, written
    /// in each unit this corpus is known to contain.
    const INSTANT_SECS: i64 = 1_700_000_000;
    const SAME_INSTANT_IN_EVERY_UNIT: [(&str, i64); 3] = [
        ("seconds", 1_700_000_000),
        ("milliseconds", 1_700_000_000_123),
        ("microseconds", 1_700_000_000_123_456),
    ];

    /// A message row carrying `date_received` and nothing else that bears on
    /// the timestamp, so the assertions below turn on the unit alone.
    fn row(date_received: Option<i64>) -> MsgRow {
        MsgRow {
            mid: 1,
            thread_id: Some(1),
            from_id: None,
            to_id: None,
            address_id: None,
            address_str: Some("+15550100".to_string()),
            body: Some("hi".to_string()),
            date: None,
            date_sent: None,
            date_received,
            mtype: Some(20),
            read: Some(1),
            undecoded: Vec::new(),
        }
    }

    fn record(date_received: Option<i64>) -> Artifact {
        row_to_artifact(
            &row(date_received),
            "sms",
            &HashMap::new(),
            &HashMap::new(),
            &HashSet::new(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
    }

    #[test]
    fn every_unit_of_one_instant_is_written_as_the_same_plausible_second() {
        for (unit, raw) in SAME_INSTANT_IN_EVERY_UNIT {
            let a = record(Some(raw));
            let secs = a.metadata["date"]
                .as_i64()
                .unwrap_or_else(|| panic!("the {unit} row wrote a non-integer date"));
            assert!(
                is_plausible_instant_secs(secs),
                "{unit} value {raw} was written as {secs}, which is not a date a \
                 message could carry"
            );
            assert_eq!(
                secs, INSTANT_SECS,
                "{unit} value {raw} names a different instant than the other units"
            );
        }
    }

    #[test]
    fn a_column_that_recorded_no_instant_is_absent_rather_than_placed() {
        for raw in [0, -1_700_000_000_000] {
            let a = record(Some(raw));
            assert!(
                a.metadata.get("date").is_none(),
                "{raw} was written as {:?}",
                a.metadata.get("date")
            );
            // No fabricated instant beside the omitted key.
            assert!(a.metadata.get("date_rfc3339").is_none());
            // The observation survives under keys that cannot be read as a time.
            assert_eq!(a.metadata["date_unusable"], true);
            assert_eq!(a.metadata["date_raw"], raw);
        }
    }

    #[test]
    fn a_row_with_no_timestamp_column_at_all_carries_no_marks() {
        // Absent is not the same as unusable: with every date column NULL there
        // is no raw value to show, and a `date_unusable` flag would claim the
        // store held something it did not.
        let a = record(None);
        assert!(a.metadata.get("date").is_none());
        assert!(a.metadata.get("date_unusable").is_none());
        assert!(a.metadata.get("date_raw").is_none());
    }
}
