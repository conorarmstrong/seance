#![forbid(unsafe_code)]
//! Shared SQLite-open plumbing for the ~20 plugins that parse a database out of
//! an artifact: read (capped) → spill to a temp file → open read-only → read the
//! column set. Each of these was copy-pasted per plugin, with the temp file
//! removed only on the happy path (a parse panic — caught by the orchestrator's
//! `catch_unwind` — leaked `/tmp/seance_*.db`). Here the spill is an RAII
//! [`TempDb`] that removes itself on `Drop`, so cleanup is guaranteed.
//!
//! It also owns the *honesty contract* those plugins share — the incompleteness
//! markers ([`dropped_rows_marker`], [`cap_marker`], [`unreadable_store_marker`],
//! [`query_failed_marker`], [`schema_undetermined_marker`]), the three-valued schema probes
//! ([`Presence`]), and the chat-record shell ([`chat::ChatMessage`]). Each of
//! those was previously reimplemented per plugin, and a contract implemented
//! thirteen times drifts: some copies stamped `content_incomplete` and some did
//! not, which is a silent wrong answer in a court document.

pub mod adopt;
pub mod chat;
pub mod spilled;
pub mod stale;

pub use chat::{
    direction_of, unix_seconds_from_magnitude, ChatMessage, CHAT_MESSAGE_SUBTYPE,
    DIRECTION_RECEIVED, DIRECTION_SENT,
};
pub use stale::{
    check_corpus, check_schema_version, read_user_version, CorpusExpectation, FieldMap,
    SchemaVersionCheck, StaleWarning, StoreSchemaVersion, SupportedRange,
};

use rusqlite::{Connection, OpenFlags};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::io::{is_sqlite_header, read_capped, read_full, IncompleteReason};
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Write-ahead log sibling of a SQLite database. On live/forensic evidence the
/// most recent rows frequently exist *only* here, uncheckpointed.
const WAL_SUFFIX: &str = "-wal";

/// Wal-index SQLite materialises beside a WAL database when it reads one. We
/// never write it, but it must be cleaned up with the spill.
const SHM_SUFFIX: &str = "-shm";

/// Cap on a spilled WAL. A legitimate WAL is small; an arbitrarily large one is
/// a disk/OOM vector on hostile or corrupt evidence.
const MAX_WAL_BYTES: u64 = 512 * 1024 * 1024;

/// A database spilled to a temporary file, removed when this handle drops.
///
/// Replaces the plugins' `write_temp_db` / `extract_to_temp` + best-effort
/// `remove_file` pattern; because removal is in `Drop`, a panic anywhere between
/// spill and parse no longer leaks the temp file.
/// Recorded when the source could not be asked for a `-wal` at all, as
/// distinct from being asked and having none.
pub const WAL_NOT_REACHABLE: &str = "wal_not_reachable";

/// Does this database's own header say it is in WAL mode?
///
/// Byte 18 of the SQLite header is the file-format *write* version: 1 is a
/// rollback journal, 2 is a write-ahead log. Only a database that says 2 can
/// have uncheckpointed rows sitting in a `-wal` beside it.
fn in_wal_mode(bytes: &[u8]) -> bool {
    bytes.len() > 18 && bytes.starts_with(b"SQLite format 3\0") && bytes[18] == 2
}

#[derive(Debug)]
pub struct TempDb {
    path: PathBuf,
    /// Set when the `-wal` sibling exists but was NOT staged in full, so the
    /// opened database is missing uncheckpointed rows. Callers stamp it on the
    /// artifacts they emit; "we could not take the whole WAL" must never look
    /// like "there was no WAL" (BUG-277).
    wal_incomplete: Option<&'static str>,
    /// Set when the MAIN database file itself was not staged in full: over the
    /// caller's byte cap, or the source returned fewer bytes than it declared.
    /// SQLite happily opens a truncated file and answers queries from the pages
    /// it can reach, so the parse yields a subset of tables and rows that is
    /// indistinguishable from a complete recovery unless this is carried out to
    /// the artifacts.
    content_incomplete: Option<&'static str>,
}

impl TempDb {
    /// Spill `bytes` to a uniquely-named temp file tagged with `tag`
    /// (`seance_<tag>_<uuid>.db`).
    ///
    /// No sidecars: use this only when `bytes` are synthesized (decrypted or
    /// reconstructed) and therefore have no `-wal` of their own. When the bytes
    /// come from an evidence file, prefer [`TempDb::write_with_sidecars`] or
    /// [`TempDb::spill`] so uncheckpointed rows are not lost.
    pub fn write(bytes: &[u8], tag: &str) -> std::io::Result<TempDb> {
        let path = std::env::temp_dir().join(format!("seance_{tag}_{}.db", uuid::Uuid::new_v4()));
        std::fs::write(&path, bytes)?;
        Ok(TempDb {
            path,
            wal_incomplete: None,
            content_incomplete: None,
        })
    }

    /// Spill `bytes` and, when `ds` can reach one, its `-wal` sibling, so the
    /// opened database also sees committed-but-uncheckpointed rows.
    ///
    /// Use when the caller already holds the database bytes. The rollback
    /// journal is deliberately *not* spilled: a `-journal` holds pre-images
    /// (older data), and a hot journal makes a read-only open fail outright
    /// (`SQLITE_READONLY_ROLLBACK`). Journal pre-images are recovered by the
    /// forensic SQLite parser instead.
    pub fn write_with_sidecars(
        bytes: &[u8],
        tag: &str,
        ds: &dyn DataSource,
    ) -> std::io::Result<TempDb> {
        let mut db = Self::write(bytes, tag)?;
        db.attach_wal(ds, in_wal_mode(bytes));
        Ok(db)
    }

    /// Read up to `max_bytes` of `ds` (capped, short-read-safe), spill it, and
    /// attach its `-wal` sibling when one is reachable.
    ///
    /// Records WHY the spill is short when it is: `cap_reached` when the
    /// database is bigger than `max_bytes`, `short_read` when the source could
    /// not deliver the bytes it declared. Both cases still open and parse — a
    /// partial database is better than none — but the caller MUST carry
    /// [`TempDb::content_incomplete_reason`] onto the artifacts, or a subset of
    /// the tables is presented as the whole recovery.
    pub fn spill(ds: &dyn DataSource, tag: &str, max_bytes: u64) -> std::io::Result<TempDb> {
        let declared = ds.size();
        let bytes = read_capped(ds, max_bytes);
        let mut db = Self::write_with_sidecars(&bytes, tag, ds)?;
        db.content_incomplete = if (bytes.len() as u64) >= declared {
            None
        } else if declared > max_bytes {
            Some(IncompleteReason::CapReached.as_str())
        } else {
            Some(IncompleteReason::ShortRead.as_str())
        };
        Ok(db)
    }

    /// Spill `ds`'s `-wal` sibling beside the main spill, if it has one.
    ///
    /// Best effort: a database with no reachable sibling (bare byte buffer, or a
    /// disk-image entry whose source cannot enumerate neighbours) simply parses
    /// without it, exactly as before.
    fn attach_wal(&mut self, ds: &dyn DataSource, in_wal_mode: bool) {
        // "There is no -wal" and "I could not look for one" are opposite
        // findings: the first says this database was checkpointed and is whole,
        // the second says its newest rows — on a phone, usually the ones that
        // matter — are missing from what was parsed. They used to be recorded
        // identically, as nothing at all (HUNT-101).
        //
        // Only a database that says it is in WAL mode can be missing a WAL, so
        // only that case is declared: a journal-mode database has no `-wal` to
        // reach, and marking every one of them incomplete would be a warning an
        // examiner learns to ignore.
        //
        // The source is ASKED first and only questioned about its capability
        // when it answers "none": a source that can produce a sibling has
        // settled the matter, whatever it claims about itself, so a new
        // implementor cannot lose its WAL by forgetting to say it has one.
        let Some(sibling) = ds.open_sibling(WAL_SUFFIX) else {
            if in_wal_mode && !ds.supports_siblings() {
                self.wal_incomplete = Some(WAL_NOT_REACHABLE);
            }
            return;
        };
        let declared = sibling.size();
        if declared == 0 {
            return;
        }
        // Over the cap the WAL is NOT staged: `read_capped` would silently keep
        // the first 512 MiB, and SQLite would then replay a prefix of the frames
        // as if that were the whole log — the newest rows dropped with no
        // outward difference from a database that had no WAL at all (BUG-277).
        if declared > MAX_WAL_BYTES {
            self.wal_incomplete = Some(IncompleteReason::CapReached.as_str());
            return;
        }
        let bytes = read_capped(sibling.as_ref(), MAX_WAL_BYTES);
        if bytes.is_empty() {
            self.wal_incomplete = Some(IncompleteReason::ShortRead.as_str());
            return;
        }
        // A WAL cut short mid-frame replays as an arbitrary prefix; refuse it and
        // say so rather than present a partial replay as a complete parse.
        if (bytes.len() as u64) < declared {
            self.wal_incomplete = Some(IncompleteReason::ShortRead.as_str());
            return;
        }
        let wal = self.suffixed(WAL_SUFFIX);
        if std::fs::write(&wal, &bytes).is_err() {
            // A partially written WAL would make SQLite reject the database
            // entirely, so drop it and read the main file alone.
            let _ = std::fs::remove_file(&wal);
            self.wal_incomplete = Some(IncompleteReason::ShortRead.as_str());
        }
    }

    /// Why the `-wal` sibling was not staged in full, if it was not.
    ///
    /// `None` means either there was no reachable WAL or it was staged whole.
    /// `Some(reason)` means the opened database is missing uncheckpointed rows;
    /// parsers should stamp it onto what they emit.
    pub fn wal_incomplete_reason(&self) -> Option<&'static str> {
        self.wal_incomplete
    }

    /// Why the MAIN database file was not staged in full, if it was not.
    ///
    /// `Some("cap_reached")` means the file is larger than the caller's cap;
    /// `Some("short_read")` means the source stopped early. Either way the
    /// tables and rows recovered are a subset of what the database holds.
    pub fn content_incomplete_reason(&self) -> Option<&'static str> {
        self.content_incomplete
    }

    /// Record that the bytes staged here were not the whole file.
    ///
    /// [`TempDb::spill`] works this out for itself, and is what a parser should
    /// use. This exists for the paths that cannot spill directly because the
    /// bytes have to be transformed first — a SQLCipher database has to be
    /// decrypted before SQLite will open it, so the caller reads the ciphertext
    /// and hands over plaintext. Without this the transformed path would be the
    /// one place where a partial database still parsed as a complete one.
    pub fn mark_content_incomplete(&mut self, reason: IncompleteReason) {
        self.content_incomplete = Some(reason.as_str());
    }

    /// The metadata keys a parser must copy onto every artifact it emits from
    /// this spill, as `(key, value)` string pairs.
    ///
    /// Empty when the database AND its WAL were staged whole — so an artifact
    /// carrying no marker really does mean "this is everything the database
    /// had". Otherwise it yields `content_incomplete: true` (a JSON **boolean**,
    /// exactly what [`TempDb::stamp_incompleteness`] writes) plus the specific
    /// `content_incomplete_reason` / `wal_incomplete_reason` strings, e.g.
    ///
    /// ```rust,ignore
    /// for (key, value) in db.incompleteness_fields() {
    ///     metadata.insert(key.to_string(), value);
    /// }
    /// ```
    ///
    /// The values are already typed `serde_json::Value` because the pairs used
    /// to be all strings: a caller doing `json!(value)` wrote the *string*
    /// `"true"`, which every consumer testing `content_incomplete == true`
    /// reads as absent — an incomplete parse presenting as a complete one.
    ///
    /// Without this, a parse of a truncated file, or of a database whose
    /// uncheckpointed WAL was refused, is indistinguishable from a complete
    /// one: the newest messages simply are not there and nothing says so.
    pub fn incompleteness_fields(&self) -> Vec<(&'static str, JsonValue)> {
        let mut fields = Vec::new();
        if self.wal_incomplete.is_none() && self.content_incomplete.is_none() {
            return fields;
        }
        fields.push(("content_incomplete", json!(true)));
        if let Some(reason) = self.content_incomplete {
            fields.push(("content_incomplete_reason", json!(reason)));
        }
        if let Some(reason) = self.wal_incomplete {
            fields.push(("wal_incomplete_reason", json!(reason)));
        }
        fields
    }

    /// Apply this spill's incompleteness to everything parsed out of it.
    ///
    /// This is the *applied* form of [`TempDb::incompleteness_fields`] and the
    /// only call a parser needs: run it on the artifact list just before
    /// returning it, and a truncated database can no longer be reported as a
    /// complete recovery.
    ///
    /// Two things happen when the spill was short:
    ///
    /// 1. every artifact gains `content_incomplete: true` plus the specific
    ///    `content_incomplete_reason` / `wal_incomplete_reason`, so a record
    ///    pulled out of a partial database carries that fact wherever it is
    ///    exported to. A reason the record already carried is never
    ///    overwritten: it stays in `content_incomplete_reason` and both are
    ///    listed in `content_incomplete_reasons` (HUNT-186); and
    /// 2. one `parse_incomplete` marker is appended. It is what an examiner
    ///    sees when the truncation cut so deep that **no** rows were recovered:
    ///    without it, "the database was unreadable past byte N" and "this
    ///    device had no messages" are the same empty result.
    ///
    /// When the database and its `-wal` were both staged whole this is a no-op,
    /// so an unmarked artifact still means the parse really was complete.
    pub fn stamp_incompleteness(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        file_name: &str,
        artifacts: &mut Vec<Artifact>,
    ) {
        let content = self.content_incomplete;
        let wal = self.wal_incomplete;
        if content.is_none() && wal.is_none() {
            return;
        }

        for artifact in artifacts.iter_mut() {
            let Some(map) = artifact.metadata.as_object_mut() else {
                continue;
            };
            map.insert("content_incomplete".into(), json!(true));
            if let Some(reason) = content {
                merge_incomplete_reason(map, reason);
            }
            if let Some(reason) = wal {
                map.entry("wal_incomplete_reason")
                    .or_insert_with(|| json!(reason));
            }
        }

        let detail = match (content, wal) {
            (Some(c), Some(w)) => format!(
                "the database file was not staged in full ({c}) and its \
                 write-ahead log was refused ({w})"
            ),
            (Some(c), None) => {
                format!("the database file was not staged in full ({c})")
            }
            (None, Some(w)) => format!(
                "the write-ahead log was refused ({w}); rows committed but \
                 not yet checkpointed are missing"
            ),
            (None, None) => unreachable!("returned above when both reasons are absent"),
        };

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("SqliteSpillIncomplete"));
        meta.insert("subtype".into(), json!("parse_incomplete"));
        meta.insert("status".into(), json!("DatabaseNotStagedInFull"));
        meta.insert("file_name".into(), json!(file_name));
        meta.insert("content_incomplete".into(), json!(true));
        if let Some(reason) = content {
            meta.insert("content_incomplete_reason".into(), json!(reason));
        }
        if let Some(reason) = wal {
            meta.insert("wal_incomplete_reason".into(), json!(reason));
        }
        meta.insert("records_recovered".into(), json!(artifacts.len()));
        meta.insert("detail".into(), json!(detail.clone()));
        meta.insert(
            "name".into(),
            json!(format!("{file_name}: partial database — {detail}")),
        );

        artifacts.push(
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype("parse_incomplete"),
        );
    }

    fn suffixed(&self, suffix: &str) -> PathBuf {
        PathBuf::from(format!("{}{}", self.path.display(), suffix))
    }

    /// Path to the spilled database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the spilled database read-only.
    pub fn open(&self) -> rusqlite::Result<Connection> {
        open_readonly(&self.path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        // The spill name is uuid-unique, so these can only be ours: the `-wal`
        // we staged and the `-shm` SQLite materialises while reading it. (SQLite
        // also creates an empty `-wal` for a WAL-mode database opened without
        // one, and never removes it on a read-only connection.)
        let _ = std::fs::remove_file(self.suffixed(WAL_SUFFIX));
        let _ = std::fs::remove_file(self.suffixed(SHM_SUFFIX));
    }
}

/// Row budget for a walk that has to be able to prove it saw everything.
///
/// A bare `LIMIT n` cannot: a query that comes back with exactly `n` rows looks
/// identical whether the table held `n` or ten million, so the walk reports a
/// truncated newest-first slice as the complete history. This binds `n + 1` —
/// one probe row past the cap — and latches [`CapCounter::truncated`] the moment
/// that row appears.
///
/// ```rust,ignore
/// let mut cap = CapCounter::new(MAX_MESSAGE_ENTRIES);
/// let rows = stmt.query_map([cap.limit()], ..)?;
/// for row in rows {
///     if !cap.admit() {
///         break; // the probe row: over the cap, and now we know it
///     }
///     ..
/// }
/// if cap.truncated() { /* emit the marker — never just log it */ }
/// ```
///
/// What a wrong answer looks like: the oldest messages in a long conversation
/// silently absent, with nothing on any artifact to say the walk stopped early.
#[derive(Debug, Clone)]
pub struct CapCounter {
    cap: usize,
    seen: usize,
    truncated: bool,
}

impl CapCounter {
    /// A budget of `cap` emitted rows.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            seen: 0,
            truncated: false,
        }
    }

    /// The value to bind as the query's `LIMIT`: the cap plus the probe row.
    pub fn limit(&self) -> i64 {
        // usize -> i64 saturating: a cap beyond i64::MAX is not reachable in
        // practice, and saturating keeps this total rather than panicking.
        self.cap.saturating_add(1).min(i64::MAX as usize) as i64
    }

    /// Account for one fetched row. `true` to process it, `false` when it is the
    /// probe row — the caller must stop, and [`CapCounter::truncated`] is now set.
    pub fn admit(&mut self) -> bool {
        if self.seen >= self.cap {
            self.truncated = true;
            return false;
        }
        self.seen += 1;
        true
    }

    /// True once the walk has seen a row beyond its cap.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Rows admitted so far.
    pub fn admitted(&self) -> usize {
        self.seen
    }

    /// The configured cap.
    pub fn cap(&self) -> usize {
        self.cap
    }
}

/// The artifact that says a walk stopped at a parser cap.
///
/// A cap that only logs, or only counts, is invisible to everything downstream:
/// the examiner sees N records and no reason to doubt N is all there was. This
/// record is the reason to doubt.
///
/// `record_type` must NOT be the `type` the walk's own records carry — the
/// conversation aggregation in `seance_db` groups ParsedRecords by
/// `metadata.$.type`, so reusing it would file this marker as a message and
/// invent a one-message conversation. Name it after the records it qualifies,
/// e.g. `"iMessageIncomplete"` for `"iMessage"`.
pub fn cap_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    source_table: &str,
    cap: &CapCounter,
) -> Artifact {
    let detail = format!(
        "the {source_table} walk stopped at the {} record parser cap; the records beyond it \
         (oldest first, where the query is newest-first) were not extracted",
        cap.cap()
    );
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("CapReached"));
    meta.insert("source_table".into(), json!(source_table));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("truncated".into(), json!(true));
    meta.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::CapReached.as_str()),
    );
    meta.insert("max_entries".into(), json!(cap.cap()));
    // Rows the walk took from the query, not artifacts produced: a malformed
    // row is admitted against the budget and then skipped, so this is an upper
    // bound on the records and must not be read as a record count.
    meta.insert("rows_read".into(), json!(cap.admitted()));
    // `content_incomplete_detail` is the key the examiner-facing reader looks
    // for (`frontend/src/lib/incompleteness.ts` keys the sentence off
    // `<flag>_detail`). A bare `detail` is read by nothing on that path, so the
    // sentence explaining WHAT stopped never reached the person the stamp
    // exists for — they were shown the machine token alone. `detail` is kept
    // beside it because existing consumers and tests read it.
    meta.insert("content_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("detail".into(), json!(detail.clone()));
    meta.insert(
        "name".into(),
        json!(format!("{record_type}: incomplete — {detail}")),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// The artifact that says a SQL walk fetched rows it could not decode.
///
/// What an examiner learns: how many rows of `source_table` were present in the
/// database but undecodable, so the record count is a floor rather than a
/// total. A wrong answer looks like an exact-sounding "42 messages" for a store
/// that held 60 — the other 18, corrupt, partially recovered, or of an
/// unexpected column type, dropped into a `debug!` line nothing downstream
/// reads (B3-023).
///
/// # `record_type` is a parameter, and must stay one
///
/// It must NOT be the `type` the walk's own records carry. `seance_db` groups
/// ParsedRecords by `metadata.$.type` (`thread_key_expr` /
/// `conversation_summaries`), so a marker reusing the walk's type would be
/// filed as a message and invent a one-message conversation in the
/// Conversations view. Name it after the records it qualifies:
/// `"iMessageIncomplete"` for `"iMessage"`, `"ViberIncomplete"` for `"Viber"`,
/// `"TelegramMessageIncomplete"` for `"TelegramMessage"`.
///
/// For the same reason the marker carries no `service` / `platform` key: those
/// are the messaging-record keys `seance_db::chat_timeline_row` falls back to
/// when `type` is absent, and putting them on a `parse_incomplete` record is
/// the same hazard one step removed.
///
/// # `first_error`
///
/// The decoder's own message for the first row that failed, when the walk kept
/// it. `None` costs the examiner the *reason* — a datatype mismatch reads very
/// differently from a corrupt page — but never the fact: the counts and both
/// incompleteness pairs are stamped either way.
///
/// # Why this lives here
///
/// This is the single definition of the undecodable-row honesty contract.
/// It was pasted into thirteen messaging plugins, which meant thirteen places
/// to change and thirteen chances for one of them to quietly stop stamping
/// `content_incomplete` — and a plugin that stops stamping it produces a court
/// document whose message count reads as exact when it is not.
pub fn dropped_rows_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    source_table: &str,
    dropped: usize,
    recovered: usize,
    first_error: Option<&str>,
) -> Artifact {
    let detail = match first_error {
        Some(err) => format!(
            "{dropped} row(s) of {source_table} could not be decoded and are absent from the \
             {recovered} record(s) recovered, so that count is a lower bound (first error: \
             {err})"
        ),
        None => format!(
            "{dropped} row(s) of {source_table} could not be decoded and are absent from the \
             {recovered} record(s) recovered, so that count is a lower bound"
        ),
    };
    let unresolved = IncompleteReason::UnresolvedStructure.as_str();
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("RowsUndecodable"));
    meta.insert("source_table".into(), json!(source_table));
    // Both pairs: the rows are missing CONTENT, and they are also missing from
    // the INVENTORY of what the table held. The census in `seance_db` counts
    // the two separately, and a marker that set only one under-reports.
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(unresolved));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(unresolved));
    meta.insert("rows_dropped".into(), json!(dropped));
    meta.insert("records_recovered".into(), json!(recovered));
    if let Some(err) = first_error {
        meta.insert("first_error".into(), json!(err));
    }
    // Both `<flag>_detail` keys, not only a bare `detail`: the examiner-facing
    // reader (`frontend/src/lib/incompleteness.ts`) keys the parser's sentence
    // off `content_incomplete_detail` / `inventory_incomplete_detail` and reads
    // nothing named `detail`. Without these the examiner met "unresolved
    // structure" and never the count, the table, or the decoder's reason —
    // a stamp whose explanation stopped one key short of the surface that
    // shows it. `detail` is kept beside them for the consumers already on it.
    meta.insert("content_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("inventory_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("detail".into(), json!(detail.clone()));
    meta.insert(
        "name".into(),
        json!(format!("{record_type}: incomplete — {detail}")),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// The rows a SQL walk fetched and could not decode, with the decoder's reason
/// for the first of them.
///
/// Counting drops in a bare `usize` and sending the error to a `debug!` line
/// was the B3-023 shape: the count never left the process and the artifact set
/// said nothing, so the records recovered read as everything the table held.
/// Pairing the count with the reason — and handing out the marker from the same
/// place — means a walk that records a drop cannot forget to declare it:
/// [`RowDrops::marker`] yields `Some` exactly when something was dropped, so
/// `out.extend(drops.marker(..))` is both the whole obligation and impossible
/// to satisfy with the wrong count.
#[derive(Debug, Default, Clone)]
pub struct RowDrops {
    dropped: usize,
    first_error: Option<String>,
}

impl RowDrops {
    /// A walk that has dropped nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one row the decoder refused.
    ///
    /// The FIRST error is kept, not the last: it is the one nearest the cause
    /// (a schema generation the query does not match, or the first damaged
    /// page), and on a badly corrupt table the last error is usually just the
    /// same failure repeated.
    pub fn record(&mut self, error: impl std::fmt::Display) {
        self.dropped += 1;
        if self.first_error.is_none() {
            self.first_error = Some(error.to_string());
        }
    }

    /// How many rows the walk could not decode.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// The decoder's message for the first row that failed, if any row did.
    pub fn first_error(&self) -> Option<&str> {
        self.first_error.as_deref()
    }

    /// The marker for this walk, or `None` when every row decoded.
    ///
    /// `recovered` is the number of records the walk actually produced and must
    /// be counted BEFORE the marker joins the list, or the marker counts
    /// itself. `record_type` follows the rule in [`dropped_rows_marker`]: it is
    /// never the type the walk's own records carry.
    pub fn marker(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
        source_table: &str,
        recovered: usize,
    ) -> Option<Artifact> {
        if self.dropped == 0 {
            return None;
        }
        Some(dropped_rows_marker(
            case_id,
            parent_id,
            record_type,
            source_table,
            self.dropped,
            recovered,
            self.first_error(),
        ))
    }
}

/// Bytes of file header probed before a database is staged: the whole SQLite
/// magic, `"SQLite format 3\0"`.
pub const SQLITE_HEADER_PROBE: usize = 16;

/// The byte cap the messaging plugins stage an app database under (512 MiB).
///
/// A chat store larger than this is staged as a prefix and the parse is marked
/// incomplete — see [`TempDb::spill`] — rather than being allowed to exhaust
/// the disk on hostile or corrupt evidence. Parsers whose stores are routinely
/// larger (iMessage, WhatsApp, the address book) pass their own bigger cap;
/// this is only the shared default, never a ceiling the caller cannot raise.
pub const MAX_DB_BYTES: u64 = 512 * 1024 * 1024;

/// What the shared SQLite entry gate decided about an artifact.
///
/// Each variant is a distinct fact about the evidence, and the caller has to
/// dispose of each one explicitly. That is the point of naming them: when this
/// control flow was copied line for line into ten messenger plugins, two of the
/// distinctions were invisible at the call site and were answered wrongly —
/// "the header is something else" versus "there were not enough bytes to read a
/// header" (Messenger read the second as proof of encryption), and "the header
/// said SQLite and staging failed" versus "this is not our file" (only Telegram
/// tells those apart; the rest still return an empty list for a database they
/// identified and did not examine, which reads as a device with no messages).
///
/// The first of those distinctions used to be a `probed: usize` field that every
/// caller had to guard with `probed >= SQLITE_HEADER_PROBE` by hand. It is now
/// two variants, [`SqliteEntry::NotSqlite`] and
/// [`SqliteEntry::HeaderUnreadable`], because a guard that three separate
/// parsers must remember to write is a guard one of them will eventually drop —
/// and dropping it manufactures an *encrypted store* finding out of a four-byte
/// read.
#[derive(Debug)]
pub enum SqliteEntry {
    /// The artifact cannot hold a database: it is a directory entry, or it has
    /// no reachable content to read.
    NoContent,
    /// A full [`SQLITE_HEADER_PROBE`] bytes were read and they are **not** the
    /// SQLite magic.
    ///
    /// This is a positive finding about the evidence, and it is the only arm a
    /// parser may treat as proof that a store it identified by name is
    /// encrypted (LINE, WeChat, Messenger all do). Matching this variant is
    /// what guarantees enough of the file was seen to say so.
    NotSqlite {
        /// The source, for parsers that can still act on a non-SQLite file —
        /// decrypt it, or record that an encrypted store was present.
        data: Arc<dyn DataSource>,
    },
    /// Fewer than [`SQLITE_HEADER_PROBE`] bytes were delivered, so the magic
    /// could not be judged at all — the file is too short, or the window
    /// backing it is.
    ///
    /// This is a fact about this tool, not about the evidence. It must never be
    /// spent as [`SqliteEntry::NotSqlite`]: Messenger once did exactly that and
    /// a four-byte file produced an `EncryptedMessengerDatabase` record
    /// asserting an encrypted Messenger store was on the device.
    HeaderUnreadable {
        /// How many of the requested [`SQLITE_HEADER_PROBE`] bytes arrived.
        probed: usize,
        /// The source, for a parser that has some other use for a fragment.
        data: Arc<dyn DataSource>,
    },
    /// The header matched and the database is staged, with its `-wal` sibling
    /// where one was reachable. Parse it, then run
    /// [`TempDb::stamp_incompleteness`] over what came back.
    Staged(TempDb),
    /// The header matched and the database could not be staged.
    ///
    /// This is a database this tool identified and did not examine. Returning
    /// an empty artifact list for it puts "no messages" in the case file, so
    /// this arm must emit [`unreadable_store_marker`], never `Ok(vec![])`.
    StagingFailed(std::io::Error),
}

/// The artifact that says a store was identified by name, carried the SQLite
/// header, and could not be examined.
///
/// What an examiner learns: this device HELD a database for this app, and this
/// tool did not read it — so the absence of messages in the report is the
/// tool's silence, not the device's. A wrong answer here is the worst kind
/// this crate can produce, because it is invisible: an empty artifact list for
/// an unstaged store renders identically to a phone on which the app was never
/// installed, and an examiner has nothing to notice.
///
/// `record_type` follows the same rule as [`dropped_rows_marker`] — it names
/// the records it qualifies (`"ViberIncomplete"`), never the type the walk's
/// own records carry, because `seance_db` groups conversations by
/// `metadata.$.type` and a marker filed as `"Viber"` becomes a phantom
/// one-message thread.
///
/// `detail` is the parser's sentence about what went wrong, and is stamped on
/// `content_incomplete_detail` / `inventory_incomplete_detail` as well as the
/// bare `detail`, because those are the keys the examiner-facing reader
/// (`frontend/src/lib/incompleteness.ts`) shows.
pub fn unreadable_store_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    detail: String,
) -> Artifact {
    let unresolved = IncompleteReason::UnresolvedStructure.as_str();
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("StoreUnreadable"));
    // Both pairs: nothing of the CONTENT was read, and nothing of the store's
    // INVENTORY is known either. A marker that set only one would let a census
    // that counts them separately report the other as sound.
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(unresolved));
    meta.insert("content_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(unresolved));
    meta.insert("inventory_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("records_recovered".into(), json!(0));
    meta.insert("detail".into(), json!(detail.clone()));
    meta.insert(
        "name".into(),
        json!(format!("{record_type}: unreadable — {detail}")),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// Add `reason` to a record's `content_incomplete_reason` without losing one
/// the record already carried.
///
/// The stamp used to overwrite: on a short read a `SchemaFieldsUnresolved`
/// note lost `unvalidated` to `short_read` (HUNT-186), so the more specific
/// reason — the one the record was written to state — vanished. The reason the
/// record already carried stays primary; when the two differ, both are listed
/// under `content_incomplete_reasons`, first-recorded first — the same pair of
/// keys the jump-list summary writes — and the record's own
/// `content_incomplete_detail`, when it has one, gains a clause naming the
/// spill's reason, because that sentence is what the screen shows.
fn merge_incomplete_reason(map: &mut serde_json::Map<String, JsonValue>, reason: &str) {
    let existing = map
        .get("content_incomplete_reason")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let Some(existing) = existing else {
        map.insert("content_incomplete_reason".into(), json!(reason));
        return;
    };
    let mut reasons: Vec<JsonValue> = match map.get("content_incomplete_reasons") {
        Some(JsonValue::Array(list)) => list.clone(),
        _ => vec![json!(existing)],
    };
    if reasons.iter().any(|r| r.as_str() == Some(reason)) {
        return;
    }
    reasons.push(json!(reason));
    map.insert(
        "content_incomplete_reasons".into(),
        JsonValue::Array(reasons),
    );
    // The sentence gains the spill's half too, so a surface that shows only
    // the primary reason and its sentence (a report, an export) still says it.
    if let Some(detail) = map
        .get("content_incomplete_detail")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
    {
        map.insert(
            "content_incomplete_detail".into(),
            json!(format!(
                "{detail}; separately, the database file this record was read from was not \
                 staged in full ({reason})"
            )),
        );
    }
}

/// The record that says a parser found its table, read its column list, and
/// the statement it reads the rows with would not prepare or run.
///
/// This is the door `B8-039` left open (HUNT-189): after the table and its
/// columns were established, a `conn.prepare`/`query_map` failure — a store
/// that declares a collation this tool does not have (Android's `LOCALIZED`,
/// registered by the framework and not by stock SQLite), a view that will not
/// compile, a malformed schema — returned an empty list, which renders exactly
/// like a device with no messages. The shape is the `DatabaseUnreadable`
/// record the iOS readers carry (`HUNT-190`), filed under the parser's own
/// `*Incomplete` type for the same reason as [`unreadable_store_marker`].
///
/// `sqlite_error` is SQLite's own message, kept verbatim on the record.
pub fn query_failed_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    source_table: &str,
    sqlite_error: &str,
) -> Artifact {
    let unresolved = IncompleteReason::UnresolvedStructure.as_str();
    let detail = format!(
        "`{source_table}` is present and its columns were read, and the query this parser \
         reads its rows with did not run ({sqlite_error}), so none of its rows were examined — \
         no records from it is this tool's failure to read the table, not an empty table"
    );
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("DatabaseUnreadable"));
    meta.insert("source_table".into(), json!(source_table));
    meta.insert("sqlite_error".into(), json!(sqlite_error));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(unresolved));
    meta.insert("content_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(unresolved));
    meta.insert("inventory_incomplete_detail".into(), json!(detail.clone()));
    meta.insert("records_recovered".into(), json!(0));
    meta.insert("detail".into(), json!(detail.clone()));
    meta.insert(
        "name".into(),
        json!(format!(
            "{record_type}: `{source_table}` could not be queried — {sqlite_error}"
        )),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// What a schema probe learned about a table. **Three** answers, not two.
///
/// `sqlite_master`/`PRAGMA` reads were spelled `.unwrap_or(false)` in every
/// messenger plugin, which collapses the third answer into the second — and the
/// two are opposite findings. [`Presence::Absent`] is a fact about the evidence:
/// the store did not have that table. [`Presence::Undetermined`] is a fact about
/// this tool: it could not find out. A corrupt or partially carved
/// `msgstore.db` answers every catalogue query with `SQLITE_CORRUPT`, and a
/// parser that reads that as "no message table" goes on to report **"this phone
/// had no WhatsApp history"** — a positive claim about a device, manufactured
/// out of a read error (B8-015 / B8-039). Refusing to answer is correct;
/// answering "there was nothing there" is a fabricated finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// The catalogue listed it.
    Present,
    /// The catalogue answered, and it was not there. This is a finding.
    Absent,
    /// The catalogue would not answer, so nothing is known either way. Carries
    /// SQLite's own message. This is NOT a finding.
    Undetermined(String),
}

impl Presence {
    /// True only for [`Presence::Present`] — never for a probe that failed.
    pub fn is_present(&self) -> bool {
        matches!(self, Presence::Present)
    }

    /// True only for [`Presence::Absent`]: the evidence really did not have it.
    ///
    /// Deliberately not the negation of [`Presence::is_present`]: `!is_present()`
    /// is the `unwrap_or(false)` bug written a second way.
    pub fn is_absent(&self) -> bool {
        matches!(self, Presence::Absent)
    }

    /// Why the probe could not be answered, when it could not be.
    pub fn undetermined_reason(&self) -> Option<&str> {
        match self {
            Presence::Undetermined(why) => Some(why),
            _ => None,
        }
    }
}

/// Read the schema catalogue once, to establish that it can be read at all.
///
/// Every other probe in this module reads `sqlite_master` or a `PRAGMA` behind
/// it, so this is the question that has to be asked first: on a database whose
/// page 1 is damaged, every later probe fails for the same reason, and the
/// parser needs to know that before it starts calling absences findings.
pub fn probe_catalogue(conn: &Connection) -> Result<(), String> {
    conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|_| ())
    .map_err(|e| format!("the schema catalogue would not read: {e}"))
}

/// Is `table` in the schema catalogue? Answers [`Present`](Presence::Present),
/// [`Absent`](Presence::Absent), or [`Undetermined`](Presence::Undetermined).
///
/// Views count as present: every caller means "can I `SELECT` from this name",
/// and a view answers a `SELECT` exactly as a table does. (Recent `msgstore.db`
/// generations keep `messages` as a compatibility view over the `message`
/// table.)
///
/// `table` comes from compile-time constants at every call site, not user input.
pub fn probe_table(conn: &Connection, table: &str) -> Presence {
    match conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type IN ('table','view') AND name = ?1",
        [table],
        |r| r.get::<_, bool>(0),
    ) {
        Ok(true) => Presence::Present,
        Ok(false) => Presence::Absent,
        Err(e) => Presence::Undetermined(format!("could not look for the `{table}` table: {e}")),
    }
}

/// Lower-cased column names of `table`, or the reason they could not be read.
///
/// This is [`table_columns`] with the third answer kept. `PRAGMA table_info` on
/// a table that does not exist SUCCEEDS with zero rows, so `Ok(empty)` really
/// does mean "no such table"; an `Err` only ever means the pragma itself would
/// not run, which callers must not spend as "the column is absent" — that
/// substitutes `NULL` for the message text or the direction column and presents
/// the result as a complete parse (B8-012 / B8-023).
///
/// Row errors mid-iteration are propagated too: `table_columns` flattens them
/// away, which turns a column list that stopped half-way into a short but
/// confident answer.
pub fn probe_columns(conn: &Connection, table: &str) -> Result<HashSet<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("the column list for `{table}` would not prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| format!("the column list for `{table}` would not run: {e}"))?;
    let mut set = HashSet::new();
    for row in rows {
        let name =
            row.map_err(|e| format!("the column list for `{table}` stopped mid-read: {e}"))?;
        set.insert(name.to_ascii_lowercase());
    }
    Ok(set)
}

/// Lower-cased column name -> declared type, or the reason they could not be
/// read. [`table_column_types`] with the third answer kept; see
/// [`probe_columns`].
pub fn probe_column_types(
    conn: &Connection,
    table: &str,
) -> Result<HashMap<String, String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("the column types for `{table}` would not prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, String>(2).unwrap_or_default(),
            ))
        })
        .map_err(|e| format!("the column types for `{table}` would not run: {e}"))?;
    let mut map = HashMap::new();
    for row in rows {
        let (name, decl) =
            row.map_err(|e| format!("the column types for `{table}` stopped mid-read: {e}"))?;
        map.insert(name.to_ascii_lowercase(), decl.to_ascii_uppercase());
    }
    Ok(map)
}

/// The schema probes a parse ran, and which of them could not be answered.
///
/// This is the structural end of the `.unwrap_or(false)` class. A parser threads
/// one of these through its probes and gets the convenient `bool` back — but the
/// failures are retained, so the single obligation at the end,
/// `out.extend(probe.marker(..))`, yields `Some` exactly when something could
/// not be determined. It is deliberately the same shape as [`RowDrops`]: a walk
/// that records a loss cannot forget to declare it.
///
/// What a wrong answer looks like without it: a damaged chat store parsed with
/// every optional column substituted as `NULL`, emitted as a complete recovery
/// of a conversation that "had no text and no direction" — or, when the message
/// table itself was the probe that failed, emitted as nothing at all, which
/// renders identically to a phone on which the app was never installed.
#[derive(Debug, Default, Clone)]
pub struct SchemaProbe {
    failures: Vec<String>,
}

impl SchemaProbe {
    /// A parse that has not yet failed to determine anything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a probe this module does not perform itself — a parser's own
    /// `typeof()` sample, or any other schema question whose failure must not be
    /// spent as an answer.
    ///
    /// Reasons are de-duplicated: probing five columns of the same broken table
    /// yields the same sentence five times, and repeating it in the marker's
    /// detail buries the fact rather than stating it.
    pub fn record_failure(&mut self, why: String) {
        if !self.failures.contains(&why) {
            self.failures.push(why);
        }
    }

    /// Is `table` there? A probe that could not be answered is recorded and
    /// reported as `false`, so the caller's control flow is unchanged — the
    /// difference is that the parse can no longer end without saying so.
    pub fn has_table(&mut self, conn: &Connection, table: &str) -> bool {
        match probe_table(conn, table) {
            Presence::Present => true,
            Presence::Absent => false,
            Presence::Undetermined(why) => {
                self.record_failure(why);
                false
            }
        }
    }

    /// Lower-cased column names of `table`; empty when they could not be read,
    /// with the reason recorded.
    pub fn columns(&mut self, conn: &Connection, table: &str) -> HashSet<String> {
        match probe_columns(conn, table) {
            Ok(cols) => cols,
            Err(why) => {
                self.record_failure(why);
                HashSet::new()
            }
        }
    }

    /// Does `table` have `column`, case-insensitively?
    pub fn has_column(&mut self, conn: &Connection, table: &str, column: &str) -> bool {
        self.columns(conn, table)
            .contains(&column.to_ascii_lowercase())
    }

    /// Declared types of `table`'s columns; empty when they could not be read,
    /// with the reason recorded.
    pub fn column_types(&mut self, conn: &Connection, table: &str) -> HashMap<String, String> {
        match probe_column_types(conn, table) {
            Ok(types) => types,
            Err(why) => {
                self.record_failure(why);
                HashMap::new()
            }
        }
    }

    /// True once any probe could not be answered.
    pub fn undetermined(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Every distinct reason a probe could not be answered.
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    /// One sentence naming everything that could not be determined, or `None`
    /// when every probe was answered.
    pub fn detail(&self) -> Option<String> {
        if self.failures.is_empty() {
            return None;
        }
        Some(self.failures.join("; "))
    }

    /// The marker this parse owes the examiner, or `None` when every probe was
    /// answered.
    ///
    /// `recovered` is the number of records the parse actually produced and must
    /// be counted BEFORE the marker joins the list, or the marker counts itself.
    /// `record_type` follows the rule in [`dropped_rows_marker`]: never the type
    /// the parse's own records carry.
    pub fn marker(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
        store: &str,
        recovered: usize,
    ) -> Option<Artifact> {
        let detail = self.detail()?;
        Some(schema_undetermined_marker(
            case_id,
            parent_id,
            record_type,
            store,
            &detail,
            recovered,
        ))
    }
}

/// The artifact that says a store's schema could not be read, so what the parse
/// did NOT find is unknown rather than absent.
///
/// What an examiner learns: the tables and columns this parse worked from are
/// the ones it could see, and it could not see all of them — so a missing
/// conversation, a missing direction, or an empty message body may be the
/// database's damage rather than the device's history. A wrong answer here is
/// silent by construction: without this record, a store whose catalogue would
/// not read produces either fewer records or none, and both render exactly like
/// a device that had less to say.
///
/// `record_type` follows the same rule as [`dropped_rows_marker`] — it names the
/// records it qualifies (`"WhatsAppIncomplete"`), never the type the parse's own
/// records carry, because `seance_db` groups conversations by `metadata.$.type`
/// and a marker filed as `"WhatsApp"` becomes a phantom one-message thread.
pub fn schema_undetermined_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    store: &str,
    detail: &str,
    recovered: usize,
) -> Artifact {
    let unresolved = IncompleteReason::UnresolvedStructure.as_str();
    let sentence = format!(
        "the schema of `{store}` could not be read in full, so anything this parse did not find \
         is undetermined rather than absent, and the {recovered} record(s) recovered are a lower \
         bound: {detail}"
    );
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("SchemaUndetermined"));
    meta.insert("source_table".into(), json!(store));
    // Both pairs: the CONTENT read may be short, and the INVENTORY of what the
    // store held is not known either. The census in `seance_db` counts the two
    // separately, and a marker that set only one lets the other read as sound.
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(unresolved));
    meta.insert("content_incomplete_detail".into(), json!(sentence.clone()));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(unresolved));
    meta.insert(
        "inventory_incomplete_detail".into(),
        json!(sentence.clone()),
    );
    meta.insert("schema_probe_failed".into(), json!(true));
    meta.insert("schema_probe_detail".into(), json!(detail));
    meta.insert("records_recovered".into(), json!(recovered));
    meta.insert("detail".into(), json!(sentence.clone()));
    meta.insert(
        "name".into(),
        json!(format!("{record_type}: schema undetermined — {sentence}")),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// The `name` an artifact was ingested under, or `""` when it has none.
///
/// The filename gate of every SQLite plugin starts here, and it is the string
/// the plugin must also pass to [`TempDb::stamp_incompleteness`] — the staged
/// copy lives at a random temp path, so the evidence name is only available
/// from the artifact.
pub fn artifact_name(artifact: &Artifact) -> &str {
    artifact
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// True when the artifact is a directory entry rather than a file.
///
/// A directory can carry the name a plugin self-selects on (`main.db` as a
/// folder, an extracted-bundle path), and staging one wastes the read and can
/// produce a zero-byte "database".
pub fn is_directory_entry(artifact: &Artifact) -> bool {
    artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        == Some(true)
}

/// The shared entry gate: reject what cannot be a database, probe the SQLite
/// magic, and stage the file for reading.
///
/// The caller keeps the parts that are genuinely its own — the filename
/// predicate, the `tag`, the byte cap, the schema-specific parse, and what to
/// do about each [`SqliteEntry`] variant. Everything between was identical
/// across the messaging plugins, including the one rule that is easy to get
/// wrong and invisible when you do:
///
/// **the header probe loops.** A windowed or container-backed [`DataSource`] is
/// entitled to return fewer bytes than asked for, so a single `read_at` that
/// came back with 8 bytes would file a real chat database as "not SQLite" and
/// drop the entire message store with no record that it existed (B2-124). That
/// fix had to be applied ten times; now there is one place to apply it.
///
/// Staging uses [`TempDb::spill`], so the `-wal` sibling comes along (a seized
/// phone usually has its newest messages only there) and short staging is
/// recorded for [`TempDb::stamp_incompleteness`] to carry onto the records.
pub fn stage_sqlite_db(artifact: &Artifact, tag: &str, max_bytes: u64) -> SqliteEntry {
    if is_directory_entry(artifact) {
        return SqliteEntry::NoContent;
    }
    let Some(data) = artifact.data.as_ref() else {
        return SqliteEntry::NoContent;
    };
    let mut head = [0u8; SQLITE_HEADER_PROBE];
    let probed = read_full(data.as_ref(), 0, &mut head);
    // Short of a full probe, nothing is known about the header — not even when
    // the bytes that did arrive contradict the magic, because concluding
    // "encrypted" from four random-looking bytes is a claim the evidence does
    // not support. The two answers are separate variants so no caller can spend
    // one as the other.
    if probed < SQLITE_HEADER_PROBE {
        return SqliteEntry::HeaderUnreadable {
            probed,
            data: Arc::clone(data),
        };
    }
    if !is_sqlite_header(&head[..probed]) {
        return SqliteEntry::NotSqlite {
            data: Arc::clone(data),
        };
    }
    match TempDb::spill(data.as_ref(), tag, max_bytes) {
        Ok(temp) => SqliteEntry::Staged(temp),
        Err(e) => SqliteEntry::StagingFailed(e),
    }
}

/// Open a SQLite database read-only with no mutex — the standard forensic open
/// (never mutate evidence; single-threaded access per connection).
pub fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Lower-cased column names of `table`, via `PRAGMA table_info`. Empty when the
/// table is absent or the pragma fails, so callers can test for a column with
/// `columns.contains("x")` without a schema round-trip. `table` comes from
/// compile-time constants at every call site, not user input.
///
/// **Prefer [`probe_columns`] or [`SchemaProbe::columns`].** This function
/// answers "absent" and "could not read the column list" identically, and a
/// caller that spends the second as the first substitutes `NULL` for a message's
/// text or direction and still presents the parse as complete (B8-012 /
/// B8-023). Kept because it is the convenient form when the caller has already
/// established, via [`probe_catalogue`], that the catalogue reads.
pub fn table_columns(conn: &Connection, table: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(mut stmt) = conn.prepare(&format!("PRAGMA table_info({table})")) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) {
            for c in rows.flatten() {
                set.insert(c.to_ascii_lowercase());
            }
        }
    }
    set
}

/// Lower-cased column name -> its **declared type**, via `PRAGMA table_info`.
///
/// [`table_columns`] answers "does this column exist"; this answers "what was it
/// declared as", which app-database parsers need to tell schema generations
/// apart — e.g. WhatsApp's `key_remote_jid` is a TEXT JID on legacy schemas but
/// an INTEGER foreign key on transitional ones, and reading the wrong one drops
/// every row. The declared type may be empty (SQLite columns can be declared
/// with no type, which gives them no affinity); callers that need certainty
/// should fall back to `typeof()` on a sample row.
///
/// **Prefer [`probe_column_types`] or [`SchemaProbe::column_types`]** for the
/// same reason as [`table_columns`]: this form cannot say "I could not find
/// out", and reading the wrong schema generation drops every row.
/// Stage a named SQLite store and parse it, or say why it could not be read.
///
/// The gate every app-store parser needs, in one place. It skips directories
/// and artifacts with no reachable content, probes the SQLite magic with a
/// LOOPING read -- a windowed or container-backed source may answer a 16-byte
/// request with 4, and a single `read_at` would file a real database as "not
/// SQLite" -- then stages the database with its `-wal` sibling and records
/// whether it was staged in full. SQLite opens a truncated file and answers
/// from the pages it can reach, so without that record the surviving rows read
/// as the whole message store (B2-124).
///
/// A store that carried the SQLite header and would not stage yields an
/// incompleteness marker rather than an empty list, because an empty list from
/// a parser that recognised the file reads exactly like a device that never had
/// the app installed.
///
/// Callers whose stores can also be *encrypted* keep their own match, because
/// `SqliteEntry::NotSqlite` means something specific to them; this covers the
/// plain case.
pub fn process_named_sqlite_db<P>(
    artifact: &Artifact,
    tag: &str,
    incomplete_record_type: &str,
    app_label: &str,
    parse: P,
) -> Vec<Artifact>
where
    P: FnOnce(&std::path::Path, Uuid, Uuid) -> Vec<Artifact>,
{
    dispose_sqlite_entry(
        stage_sqlite_db(artifact, tag, MAX_DB_BYTES),
        artifact.case_id,
        artifact.id,
        artifact_name(artifact),
        incomplete_record_type,
        app_label,
        parse,
    )
}

/// What to do with each [`SqliteEntry`], for a store whose filename identifies
/// the app on its own.
///
/// Separated from [`process_named_sqlite_db`] so the one arm that cannot be
/// exercised through the gate — staging failing on a real filesystem — is
/// reachable from a test. That arm is the honesty contract itself: `Ok(vec![])`
/// there is indistinguishable, in the finished report, from a device that never
/// had the app installed.
pub fn dispose_sqlite_entry<P>(
    entry: SqliteEntry,
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    incomplete_record_type: &str,
    app_label: &str,
    parse: P,
) -> Vec<Artifact>
where
    P: FnOnce(&std::path::Path, Uuid, Uuid) -> Vec<Artifact>,
{
    let temp = match entry {
        SqliteEntry::Staged(temp) => temp,
        SqliteEntry::StagingFailed(e) => {
            return vec![unreadable_store_marker(
                case_id,
                parent_id,
                incomplete_record_type,
                format!(
                    "the {app_label} database `{name}` carried the SQLite header and could \
                     not be staged for examination: {e}"
                ),
            )]
        }
        // Not a database, or nothing to read: this parser has nothing to say.
        // Never a marker — a module that files a finding against every file it
        // does not recognise teaches the examiner to skip the findings that
        // matter.
        SqliteEntry::NoContent
        | SqliteEntry::NotSqlite { .. }
        | SqliteEntry::HeaderUnreadable { .. } => return Vec::new(),
    };
    let mut out = parse(temp.path(), case_id, parent_id);
    temp.stamp_incompleteness(case_id, parent_id, name, &mut out);
    out
}

/// The staged entry, for a parser whose store is named for its app and whose
/// no-bytes, not-SQLite and failure answers are its own (ROADMAP §5.11: the
/// WhatsApp, iMessage and Android SMS entries).
///
/// Through [`stage_sqlite_db`], so a directory entry is never staged and a
/// short header read is never spent as a finding about the file: `Ok(Err(v))`
/// is the whole answer for [`SqliteEntry::NoContent`] (nothing) and
/// [`SqliteEntry::HeaderUnreadable`] (the stager's own
/// `SqliteSpillIncomplete` record over what did arrive — a fact about this
/// read, never "not a database", and not silence for a file named as the
/// store). [`SqliteEntry::NotSqlite`] is still staged, so the caller's own
/// not-SQLite rule runs as before; [`SqliteEntry::StagingFailed`] is the `Err`.
pub fn stage_named_store(
    artifact: &Artifact,
    tag: &str,
    max_bytes: u64,
) -> std::io::Result<Result<TempDb, Vec<Artifact>>> {
    match stage_sqlite_db(artifact, tag, max_bytes) {
        SqliteEntry::Staged(temp) => Ok(Ok(temp)),
        SqliteEntry::NotSqlite { data } => TempDb::spill(data.as_ref(), tag, max_bytes).map(Ok),
        SqliteEntry::NoContent => Ok(Err(Vec::new())),
        SqliteEntry::HeaderUnreadable { data, .. } => {
            let temp = TempDb::spill(data.as_ref(), tag, max_bytes)?;
            let mut out = Vec::new();
            temp.stamp_incompleteness(
                artifact.case_id,
                artifact.id,
                artifact_name(artifact),
                &mut out,
            );
            Ok(Err(out))
        }
        SqliteEntry::StagingFailed(e) => Err(e),
    }
}

/// The record for a messenger store this build identified and cannot read.
///
/// Saying nothing here reads as a device with no messages from that app, which
/// is the opposite of what was found: the store was located, and it is
/// encrypted. Every caller therefore emits one of these instead of returning
/// an empty vector.
///
/// `encryption` is a required parameter rather than an optional field on
/// purpose. Three hand-written copies of this record existed and one of them
/// (LINE) omitted the scheme entirely, so an examiner comparing two encrypted
/// stores in the same case saw a named cipher for one and a blank for the
/// other -- which reads as "not applicable" rather than "not identified".
/// Where the scheme genuinely was not established, say so in this string; do
/// not leave it out and do not guess a cipher from the file name.
///
/// `extra` carries anything app-specific (Messenger names its `store`), and is
/// merged last so a caller cannot silently overwrite the fields above.
pub fn encrypted_store_record(
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    encryption: &str,
    note: &str,
    name: String,
    extra: &[(&str, serde_json::Value)],
) -> Artifact {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("EncryptedMessengerDatabase"));
    meta.insert("subtype".into(), json!("encrypted_database"));
    meta.insert("app".into(), json!(app));
    meta.insert("encryption".into(), json!(encryption));
    meta.insert("status".into(), json!("Encrypted"));
    meta.insert("note".into(), json!(note));
    meta.insert("name".into(), json!(name));
    for (key, value) in extra {
        if !meta.contains_key(*key) {
            meta.insert((*key).to_string(), value.clone());
        }
    }
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("encrypted_database")
}

/// One cell as text, coercing a number to its decimal form.
///
/// SQLite is dynamically typed: a column declared `TEXT` may hold an integer
/// and vice versa, and app versions drift. Reading only `ValueRef::Text` drops
/// values that are plainly there, so integers and reals are rendered rather
/// than refused. A BLOB is not, because bytes that are not UTF-8 text are not
/// a string and guessing an encoding would put invented characters in a report.
///
/// An empty string is returned as `Some("")`: the column held a value and that
/// value was empty. Callers that want empty treated as absent must say so with
/// [`row_text_present`], because "the field was blank" and "there was no field"
/// are different findings.
pub fn row_text(row: &rusqlite::Row, idx: usize) -> Option<String> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx).ok()? {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_string),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        _ => None,
    }
}

/// [`row_text`], with an empty string treated as no value.
///
/// For columns where the application writes `""` to mean "unset" -- a display
/// name never filled in, a title the app leaves blank -- and an empty string in
/// a report would read as a recovered value that happens to be empty.
pub fn row_text_present(row: &rusqlite::Row, idx: usize) -> Option<String> {
    row_text(row, idx).filter(|s| !s.is_empty())
}

/// One cell as an integer, from an integer or a real.
///
/// A real is truncated toward zero, which is what every caller of this shape
/// wants: these are ids, counts and epoch timestamps that a schema change
/// turned into a float.
///
/// Text is **not** parsed here. Use [`row_i64_text_ok`] where the schema is
/// known to store numbers as strings.
pub fn row_i64(row: &rusqlite::Row, idx: usize) -> Option<i64> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx).ok()? {
        ValueRef::Integer(i) => Some(i),
        ValueRef::Real(f) => Some(f as i64),
        _ => None,
    }
}

/// [`row_i64`], also accepting a number written as text.
///
/// Messaging schemas do this constantly across app versions -- a message id or
/// a millisecond timestamp stored in a `TEXT` column. Refusing it loses a
/// timestamp that is plainly present, which is why the lenient form exists; it
/// is separate from [`row_i64`] so that accepting a stringified number is a
/// decision a reader can see at the call site rather than a silent coercion
/// everywhere.
pub fn row_i64_text_ok(row: &rusqlite::Row, idx: usize) -> Option<i64> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx).ok()? {
        ValueRef::Integer(i) => Some(i),
        ValueRef::Real(f) => Some(f as i64),
        ValueRef::Text(t) => std::str::from_utf8(t).ok()?.trim().parse().ok(),
        _ => None,
    }
}

pub fn table_column_types(conn: &Connection, table: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&format!("PRAGMA table_info({table})")) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, String>(2).unwrap_or_default(),
            ))
        }) {
            for (name, decl) in rows.flatten() {
                map.insert(name.to_ascii_lowercase(), decl.to_ascii_uppercase());
            }
        }
    }
    map
}

/// True if `content` begins with the SQLite 3 file-header magic. Re-exported from
/// `seance_core::io` so a plugin's magic check and its DB open live together.
pub fn looks_like_sqlite(content: &[u8]) -> bool {
    is_sqlite_header(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::test_support::{DribbleSource, TruncatedSource};

    /// Build a real database in a temp file, return its bytes.
    fn sample_db_bytes() -> Vec<u8> {
        let td =
            std::env::temp_dir().join(format!("seance_sqlutil_seed_{}.db", uuid::Uuid::new_v4()));
        {
            let conn = Connection::open(&td).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY, Body TEXT, TS INTEGER);
                 INSERT INTO messages (Body, TS) VALUES ('hi', 1);",
            )
            .unwrap();
        }
        let bytes = std::fs::read(&td).unwrap();
        let _ = std::fs::remove_file(&td);
        bytes
    }

    #[test]
    fn temp_db_roundtrips_and_reads_columns() {
        let bytes = sample_db_bytes();
        assert!(looks_like_sqlite(&bytes));

        let temp = TempDb::write(&bytes, "test").unwrap();
        let path = temp.path().to_path_buf();
        assert!(path.is_file());

        let conn = temp.open().unwrap();
        let cols = table_columns(&conn, "messages");
        // PRAGMA lower-cases, so case-insensitive column probes work.
        assert!(cols.contains("body"));
        assert!(cols.contains("ts"));
        assert!(!cols.contains("nope"));

        // Absent table → empty set, not an error.
        assert!(table_columns(&conn, "no_such_table").is_empty());

        drop(conn);
        drop(temp);
        // Drop removed the spill file.
        assert!(!path.exists(), "TempDb must remove its file on drop");
    }

    #[test]
    fn open_readonly_rejects_writes() {
        let temp = TempDb::write(&sample_db_bytes(), "ro").unwrap();
        let conn = temp.open().unwrap();
        assert!(conn
            .execute("INSERT INTO messages (Body) VALUES ('x')", [])
            .is_err());
    }

    /// A WAL-mode database whose newest row is still only in the `-wal`.
    /// Returns the directory (kept alive by the caller) and the db path; the
    /// seed connection must stay open, since closing it checkpoints the WAL.
    fn wal_db_with_uncheckpointed_row() -> (PathBuf, PathBuf, Connection) {
        let dir = std::env::temp_dir().join(format!("seance_walcase_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("msgstore.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);
             INSERT INTO messages (body) VALUES ('checkpointed');",
        )
        .unwrap();
        // Fold everything so far into the main file, then leave the newest row
        // in the WAL alone — exactly the state a live phone is seized in.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        conn.execute_batch("INSERT INTO messages (body) VALUES ('only in wal');")
            .unwrap();
        (dir, db, conn)
    }

    #[test]
    fn spill_carries_the_wal_sibling_so_uncheckpointed_rows_are_read() {
        let (dir, db_path, seed) = wal_db_with_uncheckpointed_row();
        let ds = seance_core::data_source::FileDataSource::new(db_path.clone()).unwrap();

        // Main file alone: the uncheckpointed row is invisible (the old bug).
        let bare = TempDb::write(&read_capped(&ds, 64 << 20), "walbare").unwrap();
        let bare_rows: i64 = bare
            .open()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            bare_rows, 1,
            "main DB alone must hold only the checkpointed row"
        );

        // With the `-wal` sibling spilled beside it, both rows are readable.
        let temp = TempDb::spill(&ds, "walspill", 64 << 20).unwrap();
        assert!(
            temp.path().with_extension("db-wal").is_file(),
            "spill must place the -wal beside the temp database"
        );
        let conn = temp.open().unwrap();
        let bodies: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT body FROM messages ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        };
        assert_eq!(bodies, vec!["checkpointed", "only in wal"]);

        let wal_copy = temp.path().with_extension("db-wal");
        drop(conn);
        drop(temp);
        assert!(!wal_copy.exists(), "Drop must remove the spilled -wal too");

        drop(seed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A WAL that claims more bytes than the cap allows, without allocating
    /// them: only `size()` is consulted before the refusal.
    #[derive(Debug)]
    struct OversizedWal;

    impl DataSource for OversizedWal {
        fn read_at(&self, _offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            for b in buf.iter_mut() {
                *b = 0;
            }
            Ok(buf.len())
        }
        fn size(&self) -> u64 {
            MAX_WAL_BYTES + 1
        }
    }

    /// A database whose only sibling is an oversized `-wal`. The bytes are
    /// served by the shared honest source; only `open_sibling` is special.
    /// `resident_bytes` is deliberately not forwarded, so staging takes the
    /// `read_at` path this test was written against.
    #[derive(Debug)]
    struct DbWithOversizedWal {
        db: seance_core::data_source::ByteSliceDataSource,
    }

    impl DbWithOversizedWal {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                db: seance_core::data_source::ByteSliceDataSource::new(bytes),
            }
        }
    }

    impl DataSource for DbWithOversizedWal {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.db.read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.db.size()
        }
        fn open_sibling(&self, suffix: &str) -> Option<std::sync::Arc<dyn DataSource>> {
            if suffix != WAL_SUFFIX {
                return None;
            }
            Some(std::sync::Arc::new(OversizedWal))
        }
    }

    #[test]
    fn oversized_wal_is_refused_and_reported_incomplete() {
        // BUG-277: staging the first 512 MiB of a larger WAL would replay a
        // prefix of the frames as though it were the whole log. The spill must
        // skip it and say the parse is missing uncheckpointed rows.
        let ds = DbWithOversizedWal::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "bigwal", 64 << 20).unwrap();
        assert!(
            !temp.path().with_extension("db-wal").exists(),
            "an over-cap WAL must not be staged as if it were complete"
        );
        assert_eq!(temp.wal_incomplete_reason(), Some("cap_reached"));
        // The main database still parses.
        let n: i64 = temp
            .open()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn a_fully_staged_wal_reports_no_incompleteness() {
        let (dir, db_path, seed) = wal_db_with_uncheckpointed_row();
        let ds = seance_core::data_source::FileDataSource::new(db_path).unwrap();
        let temp = TempDb::spill(&ds, "walok", 64 << 20).unwrap();
        assert_eq!(temp.wal_incomplete_reason(), None);
        drop(temp);
        drop(seed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_over_cap_main_database_reports_content_incompleteness() {
        // B2-011: `read_capped` keeps the first `max_bytes` and SQLite then
        // answers queries from whatever pages that prefix contains. The parse
        // must be marked as covering part of the database, not all of it.
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "capped", 512).unwrap();
        assert_eq!(temp.content_incomplete_reason(), Some("cap_reached"));
        assert_eq!(
            temp.incompleteness_fields(),
            vec![
                ("content_incomplete", json!(true)),
                ("content_incomplete_reason", json!("cap_reached")),
            ]
        );
    }

    /// B7-037: the pairs were all `&str`, so a caller following the documented
    /// `metadata.insert(key, json!(value))` wrote the *string* `"true"`.
    /// Consumers (report census, API filters, the UI) test the boolean, so a
    /// short parse stamped that way reads as complete.
    #[test]
    fn incompleteness_fields_carry_a_json_boolean_not_the_string_true() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "typedfields", 512).unwrap();

        let fields = temp.incompleteness_fields();
        let flag = fields
            .iter()
            .find(|(k, _)| *k == "content_incomplete")
            .map(|(_, v)| v)
            .expect("a capped spill must expose the standard flag");
        assert_eq!(
            flag,
            &json!(true),
            "content_incomplete must be a boolean; the string \"true\" reads as absent"
        );
        assert!(
            flag.as_bool() == Some(true),
            "consumers test as_bool(); a string value silently fails that test"
        );

        // What a parser stamps by hand must equal what stamp_incompleteness
        // writes, or the two honesty paths disagree.
        let mut by_hand = serde_json::Map::new();
        for (key, value) in fields {
            by_hand.insert(key.to_string(), value);
        }
        let mut artifacts = vec![Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({ "kind": "row" }),
        )];
        let case_id = uuid::Uuid::new_v4();
        temp.stamp_incompleteness(case_id, uuid::Uuid::new_v4(), "typedfields", &mut artifacts);
        let stamped = artifacts[0].metadata.as_object().unwrap();
        for (key, value) in &by_hand {
            assert_eq!(
                stamped.get(key),
                Some(value),
                "manual stamp of {key} must match stamp_incompleteness"
            );
        }
    }

    #[test]
    fn a_short_read_of_the_main_database_is_reported_as_such() {
        let ds = TruncatedSource::halved(sample_db_bytes());
        let temp = TempDb::spill(&ds, "shortdb", 64 << 20).unwrap();
        assert_eq!(
            temp.content_incomplete_reason(),
            Some("short_read"),
            "a source that could not supply its declared bytes must not parse as complete"
        );
    }

    #[test]
    fn a_whole_database_reports_no_incompleteness_at_all() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "wholedb", 64 << 20).unwrap();
        assert_eq!(temp.content_incomplete_reason(), None);
        assert!(
            temp.incompleteness_fields().is_empty(),
            "an unmarked artifact must mean the parse really was complete"
        );
    }

    #[test]
    fn wal_incompleteness_reaches_the_fields_a_parser_stamps() {
        let ds = DbWithOversizedWal::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "walfields", 64 << 20).unwrap();
        assert_eq!(
            temp.incompleteness_fields(),
            vec![
                ("content_incomplete", json!(true)),
                ("wal_incomplete_reason", json!("cap_reached")),
            ]
        );
    }

    /// B2-123: the spill knew the database was short and nothing carried it to
    /// the records, so a truncated store parsed as a complete recovery.
    #[test]
    fn stamping_marks_every_record_and_appends_a_marker() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "stamped", 512).unwrap();
        assert_eq!(temp.content_incomplete_reason(), Some("cap_reached"));

        let case_id = uuid::Uuid::new_v4();
        let parent_id = uuid::Uuid::new_v4();
        let mut artifacts = vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "Chat", "name": "a message"}),
        )];
        temp.stamp_incompleteness(case_id, parent_id, "msgstore.db", &mut artifacts);

        assert_eq!(artifacts.len(), 2, "the marker must be appended");
        assert_eq!(artifacts[0].metadata["content_incomplete"], json!(true));
        assert_eq!(
            artifacts[0].metadata["content_incomplete_reason"],
            json!("cap_reached")
        );
        let marker = &artifacts[1];
        assert_eq!(marker.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(marker.metadata["file_name"], json!("msgstore.db"));
        assert_eq!(marker.metadata["records_recovered"], json!(1));
        assert_eq!(marker.parent_id, Some(parent_id));
    }

    /// The case the marker exists for: the truncation was deep enough that no
    /// rows came back at all. "Nothing recovered" must not render as "nothing
    /// was there".
    #[test]
    fn an_empty_parse_of_a_short_database_still_says_so() {
        let ds = TruncatedSource::halved(sample_db_bytes());
        let temp = TempDb::spill(&ds, "emptyshort", 64 << 20).unwrap();
        let mut artifacts: Vec<Artifact> = Vec::new();
        temp.stamp_incompleteness(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "sms.db",
            &mut artifacts,
        );
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].metadata["content_incomplete_reason"],
            json!("short_read")
        );
        assert_eq!(artifacts[0].metadata["records_recovered"], json!(0));
    }

    /// HUNT-186: a record that already said WHY it was incomplete — a schema
    /// note whose required field no column resolved (`unvalidated`) — had its
    /// reason overwritten by the spill's `short_read`, so the examiner lost the
    /// more specific of the two. The first reason stays primary and both are
    /// listed.
    #[test]
    fn stamping_keeps_a_reason_a_record_already_carried() {
        let ds = TruncatedSource::halved(sample_db_bytes());
        let temp = TempDb::spill(&ds, "mergestamp", 64 << 20).unwrap();
        assert_eq!(temp.content_incomplete_reason(), Some("short_read"));
        let case_id = uuid::Uuid::new_v4();
        let mut artifacts = vec![
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "ViberIncomplete",
                    "status": "SchemaFieldsUnresolved",
                    "content_incomplete": true,
                    "content_incomplete_reason": "unvalidated",
                    "content_incomplete_detail": "`messages` has no column for `text`",
                }),
            ),
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({"type": "Viber", "name": "a message"}),
            ),
        ];
        temp.stamp_incompleteness(
            case_id,
            uuid::Uuid::new_v4(),
            "viber_messages",
            &mut artifacts,
        );

        let note = &artifacts[0].metadata;
        assert_eq!(
            note["content_incomplete_reason"],
            json!("unvalidated"),
            "the record's own reason must survive the stamp"
        );
        assert_eq!(
            note["content_incomplete_reasons"],
            json!(["unvalidated", "short_read"]),
            "both reasons must be listed, the record's own first"
        );
        // The sentence the screen shows carries the spill's half too.
        let detail = note["content_incomplete_detail"].as_str().unwrap();
        assert!(
            detail.starts_with("`messages` has no column for `text`")
                && detail.contains("short_read"),
            "{detail}"
        );
        // A record that carried no reason simply gains the spill's.
        let msg = &artifacts[1].metadata;
        assert_eq!(msg["content_incomplete_reason"], json!("short_read"));
        assert!(msg.get("content_incomplete_reasons").is_none());
    }

    /// Stamping the same spill twice must not list its reason twice.
    #[test]
    fn stamping_does_not_repeat_a_reason_already_listed() {
        let ds = TruncatedSource::halved(sample_db_bytes());
        let temp = TempDb::spill(&ds, "mergetwice", 64 << 20).unwrap();
        let case_id = uuid::Uuid::new_v4();
        let mut artifacts = vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"content_incomplete": true, "content_incomplete_reason": "short_read"}),
        )];
        temp.stamp_incompleteness(case_id, uuid::Uuid::new_v4(), "x.db", &mut artifacts);
        assert_eq!(
            artifacts[0].metadata["content_incomplete_reason"],
            json!("short_read")
        );
        assert!(artifacts[0]
            .metadata
            .get("content_incomplete_reasons")
            .is_none());
    }

    /// HUNT-189: the shared record for a statement that would not prepare or
    /// run on a table this parser had already found and read the columns of.
    #[test]
    fn a_query_that_did_not_run_is_a_record_naming_the_query_and_the_error() {
        let case_id = uuid::Uuid::new_v4();
        let parent_id = uuid::Uuid::new_v4();
        let m = query_failed_marker(
            case_id,
            parent_id,
            "ViberIncomplete",
            "messages",
            "no such collation sequence: LOCALIZED",
        );
        assert_eq!(m.metadata["type"], json!("ViberIncomplete"));
        assert_eq!(m.metadata["status"], json!("DatabaseUnreadable"));
        assert_eq!(m.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(m.metadata["source_table"], json!("messages"));
        assert_eq!(m.metadata["records_recovered"], json!(0));
        assert_eq!(m.metadata["content_incomplete"], json!(true));
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        let detail = m.metadata["content_incomplete_detail"].as_str().unwrap();
        assert!(
            detail.contains("`messages`") && detail.contains("LOCALIZED"),
            "{detail}"
        );
        assert_eq!(
            m.metadata["sqlite_error"],
            json!("no such collation sequence: LOCALIZED")
        );
        assert_eq!(m.parent_id, Some(parent_id));
    }

    /// A whole database must stay unmarked, or the marker means nothing.
    #[test]
    fn stamping_a_complete_spill_changes_nothing() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "wholestamp", 64 << 20).unwrap();
        let mut artifacts = vec![Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "Chat"}),
        )];
        temp.stamp_incompleteness(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "chat.db",
            &mut artifacts,
        );
        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].metadata.get("content_incomplete").is_none());
    }

    /// A `LIMIT n` walk cannot tell "exactly n rows" from "more than n"; the
    /// probe row is what makes the difference observable.
    #[test]
    fn cap_counter_detects_the_row_past_the_cap() {
        let mut cap = CapCounter::new(2);
        assert_eq!(
            cap.limit(),
            3,
            "LIMIT must fetch one probe row past the cap"
        );
        assert!(cap.admit());
        assert!(cap.admit());
        assert!(!cap.truncated(), "exactly `cap` rows is not truncation");
        assert!(!cap.admit(), "the probe row must not be emitted");
        assert!(cap.truncated());
        assert_eq!(cap.admitted(), 2);
    }

    #[test]
    fn a_walk_that_fits_under_its_cap_is_not_flagged() {
        let mut cap = CapCounter::new(5);
        for _ in 0..3 {
            assert!(cap.admit());
        }
        assert!(!cap.truncated());
        assert_eq!(cap.admitted(), 3);
    }

    #[test]
    fn cap_marker_carries_the_cap_and_the_reason() {
        let mut cap = CapCounter::new(1);
        assert!(cap.admit());
        assert!(!cap.admit());
        let m = cap_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "iMessage",
            "message",
            &cap,
        );
        assert_eq!(m.metadata["type"], json!("iMessage"));
        assert_eq!(m.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(m.metadata["content_incomplete"], json!(true));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            json!("cap_reached")
        );
        assert_eq!(m.metadata["max_entries"], json!(1));
        assert_eq!(m.metadata["rows_read"], json!(1));
        // The sentence has to land on the key the examiner-facing reader looks
        // at. `frontend/src/lib/incompleteness.ts` keys it off `<flag>_detail`
        // and reads nothing named `detail`; without this the examiner is shown
        // "cap_reached" and never what the cap was or which table it stopped.
        assert_eq!(
            m.metadata["content_incomplete_detail"],
            m.metadata["detail"]
        );
        assert!(m.metadata["content_incomplete_detail"]
            .as_str()
            .expect("a detail sentence on the flag's own key")
            .contains("parser cap"));
    }

    /// B3-023: rows were iterated with `flatten()`, so a row that would not
    /// decode vanished with no counter and no marker — the survivors then read
    /// as the whole store. This is the shared contract those thirteen plugin
    /// copies now share; every field asserted here is one a consumer keys on.
    #[test]
    fn dropped_rows_marker_states_the_count_is_a_floor() {
        let m = dropped_rows_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "ViberIncomplete",
            "messages",
            18,
            42,
            None,
        );
        assert_eq!(m.metadata["type"], json!("ViberIncomplete"));
        assert_eq!(m.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(m.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(m.metadata["status"], json!("RowsUndecodable"));
        assert_eq!(m.metadata["source_table"], json!("messages"));
        assert_eq!(m.metadata["rows_dropped"], json!(18));
        assert_eq!(m.metadata["records_recovered"], json!(42));
        // Both pairs, as booleans: the census in `seance_db` counts content and
        // inventory separately, and `json_extract(...) = 1` reads the string
        // "true" as absent — a marked record presenting as a complete one.
        assert_eq!(m.metadata["content_incomplete"], json!(true));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            m.metadata["inventory_incomplete_reason"],
            json!("unresolved_structure")
        );
        // The examiner-facing text must say the count is a floor, not a total.
        let detail = m.metadata["detail"].as_str().expect("a detail string");
        assert!(
            detail.contains("lower bound"),
            "the detail must say the recovered count is a floor: {detail}"
        );
        assert_eq!(
            m.metadata["name"],
            json!(format!("ViberIncomplete: incomplete — {detail}"))
        );
        // …and it must land on the keys the examiner-facing reader actually
        // looks at. `frontend/src/lib/incompleteness.ts` keys the parser's
        // sentence off `<flag>_detail` per scope and reads nothing named
        // `detail`, so a marker carrying only `detail` shows the examiner
        // "unresolved structure" and never the count, the table, or the reason.
        assert_eq!(m.metadata["content_incomplete_detail"], json!(detail));
        assert_eq!(m.metadata["inventory_incomplete_detail"], json!(detail));
    }

    /// The extraction hazard this function is most likely to be broken by: a
    /// later "simplification" that derives the marker's `type` from the walk's
    /// own record type instead of taking it as a parameter. `seance_db` groups
    /// ParsedRecords by `metadata.$.type`, so that marker would be aggregated
    /// as a message and shown as a one-message conversation.
    #[test]
    fn dropped_rows_marker_type_is_the_caller_s_and_carries_no_messaging_keys() {
        let m = dropped_rows_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "TelegramMessageIncomplete",
            "messages_v2",
            1,
            1,
            None,
        );
        assert_eq!(m.metadata["type"], json!("TelegramMessageIncomplete"));
        assert_ne!(
            m.metadata["type"],
            json!("TelegramMessage"),
            "the marker must never carry the walk's own record type"
        );
        // `service` and `platform` are what chat_timeline_row falls back to
        // when `type` is missing; a parse_incomplete record must not carry the
        // keys that make it look like a message.
        assert!(m.metadata.get("service").is_none());
        assert!(m.metadata.get("platform").is_none());
        assert_ne!(m.metadata["subtype"], json!("chat_message"));
    }

    /// The reason the rows would not decode is worth as much as the count: a
    /// datatype mismatch across a schema generation reads very differently from
    /// a corrupt page. When the walk kept it, it must reach the artifact and
    /// not just a `debug!` line.
    #[test]
    fn dropped_rows_marker_carries_the_first_error_when_the_walk_kept_one() {
        let with = dropped_rows_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "iMessageIncomplete",
            "message",
            2,
            7,
            Some("Invalid column type Text at index: 0"),
        );
        assert_eq!(
            with.metadata["first_error"],
            json!("Invalid column type Text at index: 0")
        );
        assert!(with.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("first error: Invalid column type Text at index: 0"));

        // Absent, not the string "unknown": a marker that says "first error:
        // unknown" claims the walk looked and could not tell, which is a
        // different fact from a walk that never kept the error.
        let without = dropped_rows_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "iMessageIncomplete",
            "message",
            2,
            7,
            None,
        );
        assert!(without.metadata.get("first_error").is_none());
        assert!(!without.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("first error"));
    }

    /// A store that was identified by name, carried the SQLite header, and
    /// could not be staged is a database this tool did not examine. Nine of the
    /// messaging plugins used to answer `Ok(vec![])` for it, which renders
    /// identically to a phone that never had the app — the examiner has nothing
    /// to notice. Every field asserted here is one a consumer keys on.
    #[test]
    fn an_unreadable_store_is_declared_rather_than_rendered_as_an_empty_one() {
        let detail = "the Viber database `viber_messages` carried the SQLite header and could \
                      not be staged for examination: No space left on device"
            .to_string();
        let m = unreadable_store_marker(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "ViberIncomplete",
            detail.clone(),
        );
        assert_eq!(m.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(m.metadata["type"], json!("ViberIncomplete"));
        assert_ne!(
            m.metadata["type"],
            json!("Viber"),
            "the marker must never carry the walk's own record type"
        );
        assert_eq!(m.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(m.metadata["status"], json!("StoreUnreadable"));
        assert_eq!(m.metadata["records_recovered"], json!(0));
        // Both pairs: nothing of the content was read, and nothing of the
        // inventory is known either.
        assert_eq!(m.metadata["content_incomplete"], json!(true));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            m.metadata["inventory_incomplete_reason"],
            json!("unresolved_structure")
        );
        // On the keys the examiner-facing reader shows, not only a bare
        // `detail` it does not look at.
        assert_eq!(m.metadata["content_incomplete_detail"], json!(detail));
        assert_eq!(m.metadata["inventory_incomplete_detail"], json!(detail));
        assert_eq!(m.metadata["detail"], json!(detail));
        assert_eq!(
            m.metadata["name"],
            json!(format!("ViberIncomplete: unreadable — {detail}"))
        );
        // The same hazard as every other marker in this crate.
        assert!(m.metadata.get("service").is_none());
        assert!(m.metadata.get("platform").is_none());
    }

    /// The arm above, wired. Every plugin whose filename identifies its app
    /// routes through this disposition, so the rule is written once instead of
    /// ten times — Twitter was the copy that had drifted and answered
    /// `Ok(vec![])` for a store it had identified and could not stage.
    ///
    /// Staging failure cannot be provoked through a real filesystem in a unit
    /// test, which is exactly why the arm went unnoticed; the entry is
    /// synthesised here instead.
    #[test]
    fn a_store_that_would_not_stage_yields_a_marker_not_an_empty_list() {
        let case = uuid::Uuid::new_v4();
        let parent = uuid::Uuid::new_v4();
        let out = dispose_sqlite_entry(
            SqliteEntry::StagingFailed(std::io::Error::other("No space left on device")),
            case,
            parent,
            "1234567890-56.db",
            "TwitterIncomplete",
            "Twitter",
            |_, _, _| panic!("parse must not run for a store that did not stage"),
        );
        assert_eq!(
            out.len(),
            1,
            "silence here reads as a device without the app"
        );
        assert_eq!(out[0].metadata["type"], json!("TwitterIncomplete"));
        assert_eq!(out[0].metadata["status"], json!("StoreUnreadable"));
        assert_eq!(out[0].metadata["content_incomplete"], json!(true));
        assert!(out[0].metadata["detail"]
            .as_str()
            .unwrap()
            .contains("1234567890-56.db"));
        assert_eq!(out[0].parent_id, Some(parent));
        assert_eq!(out[0].case_id, case);
    }

    /// The counterpart: a file this parser simply does not recognise produces
    /// nothing at all. A module that files a finding against every database it
    /// does not own teaches the examiner to skip the findings that matter.
    #[test]
    fn a_file_that_is_not_a_database_yields_no_marker() {
        let bytes = vec![0u8; 4];
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
        for entry in [
            SqliteEntry::NoContent,
            SqliteEntry::NotSqlite {
                data: Arc::clone(&ds),
            },
            SqliteEntry::HeaderUnreadable {
                probed: 4,
                data: Arc::clone(&ds),
            },
        ] {
            let out = dispose_sqlite_entry(
                entry,
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                "main.db",
                "SkypeIncomplete",
                "Skype",
                |_, _, _| panic!("parse must not run"),
            );
            assert!(out.is_empty());
        }
    }

    /// A walk that dropped nothing must produce no marker, or the marker stops
    /// meaning anything; a walk that dropped something must produce one without
    /// the caller having to remember an `if`.
    #[test]
    fn row_drops_marks_exactly_when_something_was_dropped() {
        let clean = RowDrops::new();
        assert_eq!(clean.dropped(), 0);
        assert!(clean.first_error().is_none());
        assert!(clean
            .marker(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                "KikIncomplete",
                "messagesTable",
                9
            )
            .is_none());

        let mut drops = RowDrops::new();
        drops.record("Invalid column type Text at index: 0");
        // The FIRST error is the one nearest the cause; a later one on a badly
        // corrupt table is usually the same failure repeated.
        drops.record("some later, less useful error");
        assert_eq!(drops.dropped(), 2);
        assert_eq!(
            drops.first_error(),
            Some("Invalid column type Text at index: 0")
        );
        let m = drops
            .marker(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                "KikIncomplete",
                "messagesTable",
                9,
            )
            .expect("a dropped row must produce a marker");
        assert_eq!(m.metadata["rows_dropped"], json!(2));
        assert_eq!(m.metadata["records_recovered"], json!(9));
        assert_eq!(
            m.metadata["first_error"],
            json!("Invalid column type Text at index: 0")
        );
        assert_eq!(m.metadata["content_incomplete"], json!(true));
    }
    fn entry_artifact(name: &str, data: Option<Arc<dyn DataSource>>) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            data,
            json!({ "name": name }),
        )
    }

    #[test]
    fn the_entry_gate_reads_the_name_and_the_directory_flag() {
        let a = entry_artifact("data/msgstore.db", None);
        assert_eq!(artifact_name(&a), "data/msgstore.db");
        assert!(!is_directory_entry(&a));

        let mut dir = entry_artifact("main.db", None);
        dir.metadata = json!({ "name": "main.db", "is_directory": true });
        assert!(is_directory_entry(&dir));
        assert!(matches!(
            stage_sqlite_db(&dir, "gate", MAX_DB_BYTES),
            SqliteEntry::NoContent
        ));

        // An artifact with no name must not panic or invent one.
        let unnamed = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({}),
        );
        assert_eq!(artifact_name(&unnamed), "");
    }

    #[test]
    fn the_entry_gate_refuses_an_artifact_with_no_reachable_content() {
        let a = entry_artifact("msgstore.db", None);
        assert!(matches!(
            stage_sqlite_db(&a, "gate", MAX_DB_BYTES),
            SqliteEntry::NoContent
        ));
    }

    /// B2-124: a windowed source is entitled to answer a 16-byte request with
    /// 4 bytes. A single `read_at` here would report `NotSqlite` for a real
    /// database and the whole message store would be dropped with nothing
    /// saying it had been seen. The probe must loop.
    #[test]
    fn the_entry_gate_stages_a_database_delivered_four_bytes_at_a_time() {
        let ds: Arc<dyn DataSource> = Arc::new(DribbleSource::new(sample_db_bytes(), 4));
        let a = entry_artifact("msgstore.db", Some(ds));
        let SqliteEntry::Staged(temp) = stage_sqlite_db(&a, "dribble", MAX_DB_BYTES) else {
            panic!("a dribbled SQLite database must still be staged");
        };
        let n: i64 = temp
            .open()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(temp.content_incomplete_reason(), None);
    }

    /// "The header is something else" and "there were not enough bytes to
    /// judge" must be distinguishable: LINE, WeChat and Messenger read the
    /// former as an encrypted store, and reading a 4-byte file that way would
    /// put an encrypted-database record in the case for a file that is not one.
    #[test]
    fn the_entry_gate_separates_a_wrong_header_from_a_header_it_could_not_read() {
        let full: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(b"NOT-A-SQLITE-DB-AT-ALL".to_vec()),
        );
        // A full probe that disagrees with the magic is the one arm a parser
        // may read as "encrypted store".
        match stage_sqlite_db(&entry_artifact("main.db", Some(full)), "gate", MAX_DB_BYTES) {
            SqliteEntry::NotSqlite { .. } => {}
            other => panic!("expected NotSqlite, got {other:?}"),
        }

        let short: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(b"SQLi".to_vec()),
        );
        // A source that ran out lands in a DIFFERENT variant, so the guard that
        // keeps a four-byte file from becoming an encrypted-store finding is
        // the match itself and cannot be forgotten.
        match stage_sqlite_db(
            &entry_artifact("main.db", Some(short)),
            "gate",
            MAX_DB_BYTES,
        ) {
            SqliteEntry::HeaderUnreadable { probed, .. } => assert!(
                probed < SQLITE_HEADER_PROBE,
                "a source that ran out must report how far it got"
            ),
            other => panic!("expected HeaderUnreadable, got {other:?}"),
        }

        // Bytes that arrived and contradict the magic are still NOT a finding
        // when the probe was short: four random-looking bytes are not proof of
        // encryption.
        let short_wrong: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(b"ZZZZ".to_vec()),
        );
        match stage_sqlite_db(
            &entry_artifact("main.db", Some(short_wrong)),
            "gate",
            MAX_DB_BYTES,
        ) {
            SqliteEntry::HeaderUnreadable { probed, .. } => assert_eq!(probed, 4),
            other => panic!("expected HeaderUnreadable, got {other:?}"),
        }
    }

    /// A staged database over the cap still parses, and still reports that it
    /// is a prefix — the gate must not lose what `spill` worked out.
    #[test]
    fn the_entry_gate_keeps_the_spill_s_incompleteness() {
        let ds: Arc<dyn DataSource> = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            sample_db_bytes(),
        ));
        let SqliteEntry::Staged(temp) =
            stage_sqlite_db(&entry_artifact("m.db", Some(ds)), "gc", 512)
        else {
            panic!("an over-cap database must still be staged and parsed");
        };
        assert_eq!(temp.content_incomplete_reason(), Some("cap_reached"));
    }

    /// A database whose file header is intact but whose page-1 b-tree is not.
    ///
    /// It OPENS — SQLite reads nothing until the first statement — and then
    /// answers every catalogue query with `SQLITE_CORRUPT`. That is the state a
    /// carved or partially recovered chat store arrives in, and it is exactly
    /// the case `.unwrap_or(false)` reported as "the table is not there".
    ///
    /// Bytes 103..105 are page 1's b-tree cell count. SQLite rejects a page
    /// whose cell count exceeds `(page_size - 8) / 6` (681 for the default
    /// 4096-byte page), so 0xFFFF is corrupt for every page size it supports.
    fn corrupt_catalogue_bytes() -> Vec<u8> {
        let mut bytes = sample_db_bytes();
        bytes[103] = 0xFF;
        bytes[104] = 0xFF;
        bytes
    }

    fn corrupt_catalogue_conn() -> (TempDb, Connection) {
        let temp = TempDb::write(&corrupt_catalogue_bytes(), "corrupt").unwrap();
        let conn = temp
            .open()
            .expect("a damaged page 1 still OPENS; it fails on first read");
        (temp, conn)
    }

    /// B8-015 / B8-039: the whole point of the type. "Not there" and "could not
    /// find out" must be different values, because only the first is a finding
    /// about the device.
    #[test]
    fn a_table_probe_separates_absent_from_undetermined() {
        let temp = TempDb::write(&sample_db_bytes(), "presence").unwrap();
        let conn = temp.open().unwrap();
        assert_eq!(probe_table(&conn, "messages"), Presence::Present);
        assert_eq!(probe_table(&conn, "no_such_table"), Presence::Absent);
        assert!(probe_catalogue(&conn).is_ok());

        let (_corrupt, bad) = corrupt_catalogue_conn();
        let answer = probe_table(&bad, "messages");
        assert!(
            answer.undetermined_reason().is_some(),
            "a catalogue that will not read must not answer `Absent`: got {answer:?}"
        );
        assert!(!answer.is_present());
        assert!(
            !answer.is_absent(),
            "reporting `Absent` here is what puts \"this device had no messages\" in the case file"
        );
        assert!(probe_catalogue(&bad).is_err());
    }

    /// `PRAGMA table_info` on a table that does not exist SUCCEEDS with zero
    /// rows, so `Ok(empty)` is a real answer and `Err` is the only "could not
    /// find out" — the distinction `table_columns` cannot express.
    #[test]
    fn a_column_probe_separates_no_such_table_from_no_answer() {
        let temp = TempDb::write(&sample_db_bytes(), "cols").unwrap();
        let conn = temp.open().unwrap();
        let cols = probe_columns(&conn, "messages").expect("a readable table lists its columns");
        assert!(cols.contains("body"));
        assert_eq!(
            probe_columns(&conn, "no_such_table"),
            Ok(HashSet::new()),
            "an absent table is an answered probe with no columns, not a failure"
        );

        let (_corrupt, bad) = corrupt_catalogue_conn();
        assert!(
            probe_columns(&bad, "messages").is_err(),
            "a column list that will not read must not answer as an empty column set"
        );
        assert!(probe_column_types(&bad, "messages").is_err());
    }

    /// The accumulator keeps the convenient `bool` and still makes the parse
    /// declare what it could not determine — the RowDrops contract, applied to
    /// schema probes.
    #[test]
    fn schema_probe_yields_a_marker_exactly_when_something_was_undetermined() {
        let temp = TempDb::write(&sample_db_bytes(), "probeok").unwrap();
        let conn = temp.open().unwrap();
        let mut clean = SchemaProbe::new();
        assert!(probe_catalogue(&conn).is_ok());
        assert!(clean.has_table(&conn, "messages"));
        assert!(!clean.has_table(&conn, "no_such_table"));
        assert!(clean.has_column(&conn, "messages", "BODY"));
        assert!(!clean.has_column(&conn, "messages", "nope"));
        assert!(!clean.undetermined());
        assert_eq!(clean.detail(), None);
        assert!(clean
            .marker(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                "WhatsAppIncomplete",
                "msgstore.db",
                7
            )
            .is_none());

        let (_corrupt, bad) = corrupt_catalogue_conn();
        let mut broken = SchemaProbe::new();
        // Same false the old code produced — the difference is that it is now
        // recorded rather than spent as a finding.
        assert!(!broken.has_table(&bad, "message"));
        assert!(!broken.has_column(&bad, "message", "text_data"));
        assert!(broken.undetermined());
        let m = broken
            .marker(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                "WhatsAppIncomplete",
                "msgstore.db",
                0,
            )
            .expect("an undetermined probe owes the examiner a marker");
        assert_eq!(m.metadata["type"], json!("WhatsAppIncomplete"));
        assert_eq!(m.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(m.metadata["status"], json!("SchemaUndetermined"));
        assert_eq!(m.metadata["records_recovered"], json!(0));
        assert_eq!(m.metadata["content_incomplete"], json!(true));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        // The sentence must reach the keys the examiner-facing reader shows.
        assert_eq!(
            m.metadata["content_incomplete_detail"],
            m.metadata["detail"]
        );
        assert_eq!(
            m.metadata["inventory_incomplete_detail"],
            m.metadata["detail"]
        );
        assert!(m.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("undetermined rather than absent"));
        // Same hazard as every other marker in this crate.
        assert!(m.metadata.get("service").is_none());
        assert!(m.metadata.get("platform").is_none());
        assert_ne!(m.metadata["type"], json!("WhatsApp"));
    }

    /// Probing five columns of one broken table must state the reason once, not
    /// five times: a repeated sentence buries the fact it exists to state.
    #[test]
    fn schema_probe_states_each_reason_once() {
        let (_corrupt, bad) = corrupt_catalogue_conn();
        let mut probe = SchemaProbe::new();
        for col in ["a", "b", "c", "d", "e"] {
            assert!(!probe.has_column(&bad, "message", col));
        }
        assert_eq!(probe.failures().len(), 1, "{:?}", probe.failures());
    }

    /// A view answers a `SELECT` exactly as a table does, and recent
    /// `msgstore.db` generations keep `messages` as a view over `message`.
    #[test]
    fn a_view_probes_as_present() {
        let temp = TempDb::write(&sample_db_bytes(), "viewprobe").unwrap();
        let seed = Connection::open(temp.path()).unwrap();
        seed.execute_batch("CREATE VIEW messages_v AS SELECT * FROM messages;")
            .unwrap();
        drop(seed);
        let conn = temp.open().unwrap();
        assert_eq!(probe_table(&conn, "messages_v"), Presence::Present);
    }

    #[test]
    fn spill_without_a_sibling_still_works() {
        // A bare byte buffer has no siblings; the spill must behave as before.
        let ds = seance_core::data_source::ByteSliceDataSource::new(sample_db_bytes());
        let temp = TempDb::spill(&ds, "nosib", 64 << 20).unwrap();
        assert!(!temp.path().with_extension("db-wal").exists());
        let conn = temp.open().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}

/// The two choices the four local copies of these readers had silently made
/// differently, now named and pinned.
#[cfg(test)]
mod row_reader_tests {
    use super::*;
    use rusqlite::Connection;

    fn one_row<T>(sql: &str, f: impl FnOnce(&rusqlite::Row) -> T) -> T {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.query_row(sql, [], |r| Ok(f(r))).expect("one row")
    }

    #[test]
    fn an_empty_string_is_a_value_unless_the_caller_says_otherwise() {
        // fbmessenger and line kept `Some("")`; ios_artifacts and win_timeline
        // filtered it away. Both are defensible and they are now different
        // functions, because "the field was blank" and "there was no field"
        // are different findings.
        assert_eq!(
            one_row("SELECT ''", |r| row_text(r, 0)),
            Some(String::new())
        );
        assert_eq!(one_row("SELECT ''", |r| row_text_present(r, 0)), None);
        assert_eq!(
            one_row("SELECT 'x'", |r| row_text_present(r, 0)),
            Some("x".into())
        );
    }

    #[test]
    fn a_number_written_as_text_is_read_only_by_the_lenient_form() {
        // SQLite is dynamically typed and messaging schemas drift: an id or a
        // millisecond timestamp lands in a TEXT column across app versions.
        // The strict form refuses it; the lenient one takes it. Refusing
        // silently is how a timestamp that is plainly present goes missing.
        assert_eq!(one_row("SELECT '1700000000'", |r| row_i64(r, 0)), None);
        assert_eq!(
            one_row("SELECT '1700000000'", |r| row_i64_text_ok(r, 0)),
            Some(1_700_000_000)
        );
        assert_eq!(
            one_row("SELECT ' 42 '", |r| row_i64_text_ok(r, 0)),
            Some(42)
        );
        assert_eq!(
            one_row("SELECT 'not a number'", |r| row_i64_text_ok(r, 0)),
            None
        );
    }

    #[test]
    fn numbers_render_as_text_and_blobs_do_not() {
        // A number in a text column is plainly there; a BLOB that is not UTF-8
        // is not a string, and guessing an encoding would put invented
        // characters in a report.
        assert_eq!(one_row("SELECT 7", |r| row_text(r, 0)), Some("7".into()));
        assert_eq!(
            one_row("SELECT 1.5", |r| row_text(r, 0)),
            Some("1.5".into())
        );
        assert_eq!(one_row("SELECT x'ff00'", |r| row_text(r, 0)), None);
        assert_eq!(one_row("SELECT 2.9", |r| row_i64(r, 0)), Some(2));
    }
}

#[cfg(test)]
mod encrypted_store_tests {
    use super::*;

    #[test]
    fn every_encrypted_store_names_its_scheme_and_cannot_be_overwritten() {
        // `encryption` is a parameter, not an optional field, because one of
        // the three hand-written copies of this record left it out and an
        // examiner comparing two encrypted stores saw a named cipher for one
        // and a blank for the other.
        let a = encrypted_store_record(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "LINE",
            "not identified (a full non-SQLite header; the scheme was not established)",
            "app-level decryption required",
            "LINE database (encrypted)".to_string(),
            // `extra` must not be able to rewrite the fields above it.
            &[
                ("store", json!("x")),
                ("app", json!("NotLine")),
                ("status", json!("Plain")),
            ],
        );
        assert_eq!(a.metadata["app"], "LINE");
        assert_eq!(a.metadata["status"], "Encrypted");
        assert_eq!(a.metadata["store"], "x");
        assert!(a.metadata["encryption"]
            .as_str()
            .is_some_and(|e| e.contains("not identified")));
        assert_eq!(a.metadata["type"], "EncryptedMessengerDatabase");
    }
}

#[cfg(test)]
mod sibling_reachability_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    /// HUNT-101. "There is no `-wal`" and "I could not look for one" are
    /// opposite findings about a SQLite database: the first says it was
    /// checkpointed and is whole, the second says its newest rows are missing.
    /// They were recorded identically — as nothing — so a parse that stopped at
    /// the last checkpoint was indistinguishable from a complete one.
    #[test]
    fn a_source_that_cannot_look_for_a_wal_says_so() {
        // A bare byte buffer cannot enumerate neighbours. Byte 18 is the
        // file-format write version: 2 says this database is in WAL mode, so a
        // `-wal` beside it is where its newest rows are.
        let mut header = b"SQLite format 3\0".to_vec();
        header.extend_from_slice(&[0u8; 8]);
        header[18] = 2;
        header[19] = 2;
        let source = ByteSliceDataSource::new(header);
        let db = TempDb::spill(&source, "sibling_test", 1024 * 1024).expect("spilled");
        assert_eq!(
            db.wal_incomplete_reason(),
            Some("wal_not_reachable"),
            "a source that cannot look must not report the same as one that looked and found none"
        );
    }

    /// A journal-mode database has no `-wal` to be missing, and marking every
    /// one of them incomplete would be a warning an examiner learns to ignore.
    #[test]
    fn a_journal_mode_database_is_not_marked_for_a_wal_it_never_had() {
        let mut header = b"SQLite format 3\0".to_vec();
        header.extend_from_slice(&[0u8; 8]);
        header[18] = 1;
        header[19] = 1;
        let source = ByteSliceDataSource::new(header);
        let db = TempDb::spill(&source, "sibling_test", 1024 * 1024).expect("spilled");
        assert_eq!(db.wal_incomplete_reason(), None);
    }
}
