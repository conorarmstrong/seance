#![forbid(unsafe_code)]
//! Database Layer for Seance Forensics Framework
//!
//! This module provides SQLite-based storage for forensic artifacts, cases, and timeline events.
//!
//! # SQL Injection Safety
//!
//! This module constructs some SQL queries dynamically for flexibility (sorting, optional filters).
//! All dynamic query construction follows strict security practices to prevent SQL injection:
//!
//! ## Security Principles Applied:
//!
//! 1. **Parameterized Queries**: All user-provided VALUES are bound using sqlx `.bind()`,
//!    never concatenated into SQL strings
//!
//! 2. **Whitelist Validation**: Any user input that affects SQL structure (e.g., sort columns)
//!    is validated against a whitelist of known-safe values via `match` statements
//!
//! 3. **No Direct Concatenation**: User input never appears directly in SQL strings.
//!    Only hardcoded column names and validated keywords are used
//!
//! 4. **Integer Parameters**: LIMIT and OFFSET use numeric types, not string concatenation
//!
//! ## Dynamic Query Patterns Used:
//!
//! - **UPDATE with optional fields**: Builds `SET name = ?1, ref = ?2` with hardcoded column names
//! - **ORDER BY sorting**: Validates sort column against whitelist, validates direction (ASC/DESC)
//! - **Optional filters**: Conditionally adds WHERE clauses with parameterized values
//!
//! ## Audit Locations:
//!
//! - `update_case()`: Dynamic UPDATE with hardcoded columns
//! - `get_timeline_events_filtered()`: Dynamic ORDER BY with whitelisted columns
//!
//! All locations marked with `SECURITY:` comments explaining safety guarantees.

#![allow(clippy::type_complexity, clippy::too_many_arguments)]
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, SqlitePool,
};
use std::str::FromStr;
use tracing::{debug, info, warn};
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

mod assignments;
pub use assignments::*;
mod bookmark_folders;
pub use bookmark_folders::*;

/// Most email records [`SqliteConnection::communication_graph`] aggregates into
/// the contact network. Reaching it means edges exist that the graph never
/// weighed, and the graph must report itself truncated.
pub const COMMUNICATION_GRAPH_EMAIL_CAP: usize = 50_000;

/// Most GPS points [`SqliteConnection::get_geo_points`] returns.
///
/// Public because the export/report layer has no truncation channel on this
/// call: a returned length equal to this number is the caller's ONLY evidence
/// that the point set was bounded, and a court exhibit that omits GPS fixes
/// without saying so is the failure this guards. Callers must mirror it.
pub const GEO_POINT_EXPORT_CAP: usize = 100_000;

/// Most GPS points [`SqliteConnection::get_geo_map_points`] will load before it
/// refuses. A map has no page order and no scrollback, so exceeding this is an
/// error rather than an arbitrary, unreproducible subset of a suspect's
/// movements drawn as if it were all of them.
pub const GEO_MAP_POINT_CAP: usize = 200_000;

/// Most events [`SqliteConnection::get_related_timeline_events`] returns.
///
/// "Related" reaches every sibling under the same parent, which under a
/// filesystem or a large directory is the whole volume timeline. Loading it
/// unbounded hangs the request; returning a silent slice of it mislabels the
/// volume timeline as this artifact's own history. The call is bounded here and
/// reports the bound, and the artifact's own/parent/child events are filled in
/// before any sibling so the answer to "what happened around THIS file" can
/// never be crowded out by its neighbours.
pub const RELATED_TIMELINE_CAP: usize = 2_000;

/// Rows removed per statement when a case is deleted. Small enough that one
/// batch is a short write the WAL absorbs and readers wait out; large enough
/// that a multi-million-row case is gone in hundreds of statements, not
/// millions.
pub const DELETE_BATCH_ROWS: usize = 20_000;

/// How many times a single delete batch is retried before the purge stops and
/// leaves the case marked `deleting` for the next startup. A batch fails when
/// SQLite is busy behind a concurrent ingest, which is transient: aborting the
/// whole purge on one busy window stalled three cases until restart (HUNT-086).
const DELETE_BATCH_RETRIES: u32 = 5;

/// Batches between WAL checkpoints while a case is being purged. A purge
/// writes nothing but deletions, and every deleted page goes to the WAL until
/// something checkpoints it; under a concurrent ingest nothing does.
const DELETE_CHECKPOINT_EVERY: u64 = 20;

/// Batches between the stronger checkpoints that also give the WAL *file* back.
/// A passive checkpoint copies pages into the database but can only reset the
/// log when no reader holds an older snapshot, so beside a second purge or a
/// live case the file keeps growing anyway — 9 GB in three minutes, measured.
/// `TRUNCATE` waits for that quiet moment (bounded by the busy timeout) and is
/// therefore run rarely rather than every time.
const DELETE_TRUNCATE_EVERY: u64 = 200;

/// Largest page [`SqliteConnection::get_child_artifacts`] and
/// [`SqliteConnection::get_child_artifacts_filtered`] will return. FileEntries
/// are stored flat under their FileSystem artifact, so "the children of this
/// volume" is every file on it; the tree pages instead of loading that.
pub const CHILD_ARTIFACT_PAGE_MAX: usize = 1_000;

/// The name a bookmark is listed under when its artifact's metadata would not
/// parse: distinct from the "Unknown" of metadata that parsed but names nothing.
pub const UNREADABLE_METADATA_NAME: &str = "Unreadable metadata";

/// Largest page [`SqliteConnection::list_artifact_bookmarks`] will return.
pub const BOOKMARK_PAGE_MAX: usize = 1_000;

/// Largest page [`SqliteConnection::list_jobs_page`] will return.
pub const JOB_PAGE_MAX: usize = 500;

/// Largest page [`SqliteConnection::get_processing_log_for_artifact_page`] will
/// return. Matches the ceiling the API already clamps its `limit` to.
pub const PROCESSING_LOG_PAGE_MAX: usize = 1_000;

/// A listing that can say in what way it is less than everything.
///
/// This is the crate's one shape for a bounded query. Two facts have to reach
/// the examiner and they are NOT the same fact:
///
/// * `has_more` — the query stopped at `limit`. Further rows match and are
///   intact. Asking for the next `offset`, or raising the limit, finds them.
///   Nothing is damaged.
/// * `undecodable` — rows this page READ and then could not turn into an item:
///   an id that is not a UUID, a metadata blob that is not JSON, an artifact
///   type this build does not know. Paging further never finds them; they are
///   absent from every page. The evidence, or this build's ability to read it,
///   is damaged.
///
/// An examiner acts differently on each — one is "look at the next page", the
/// other is "this listing is short of the evidence and the shortfall is
/// permanent" — so collapsing them into a single `truncated` boolean destroys
/// the distinction that decides what happens next.
///
/// `items.len()` is not a completeness signal and must never be used as one. A
/// page that read `limit` rows and dropped two undecodable ones is short AND
/// has more; a caller that stops paging on a short page loses the rest of the
/// listing. Decide on `has_more`, always.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BoundedList<T> {
    /// The rows that decoded. At most `limit` of them, and fewer when
    /// `undecodable` is non-zero.
    pub items: Vec<T>,
    /// The ceiling actually applied, after clamping the caller's request into
    /// `1..=` the query's maximum. Reported because a caller that asked for
    /// more than the maximum got less than it asked for.
    pub limit: usize,
    /// Rows skipped before the first item.
    pub offset: usize,
    /// True when at least one further row exists past this page, decided by a
    /// `LIMIT + 1` probe rather than by the page being full.
    pub has_more: bool,
    /// Rows inside this page's window that could not be decoded and so are
    /// absent from `items`. Never a reason to page further; always a reason to
    /// disclose that the listing is short of the evidence.
    pub undecodable: usize,
}

impl<T> BoundedList<T> {
    /// True only when this listing is the whole answer: nothing beyond it, and
    /// nothing dropped from it.
    pub fn is_complete(&self) -> bool {
        !self.has_more && self.undecodable == 0
    }
}

/// Clamp a caller's requested page size into `1..=max`.
///
/// A zero page is rejected upward rather than honoured: zero rows with
/// `has_more: true` is a listing that discloses nothing an examiner can use,
/// and the returned [`BoundedList::limit`] shows the clamp was applied.
pub fn clamp_page_size(requested: Option<usize>, max: usize) -> usize {
    requested.unwrap_or(max).clamp(1, max)
}

/// Bind value for a `LIMIT ?` that fetches one row past `limit`.
///
/// The probe row is what lets a query answer "is there more" without a second
/// `COUNT(*)`, and it is why a full page is distinguishable from the end of the
/// data. Truncate the fetched rows back to `limit` before decoding them so the
/// probe row is never returned and never counted as undecodable.
pub fn probe_limit(limit: usize) -> i64 {
    i64::try_from(limit)
        .unwrap_or(i64::MAX - 1)
        .saturating_add(1)
}

/// A tree node: one child artifact plus how many children it has of its own.
///
/// The count rides along because the evidence tree needs it for every row, and
/// asking per row was an N+1 that scaled with the page size.
#[derive(Debug, Clone)]
pub struct ChildArtifact {
    pub artifact: seance_core::artifact::Artifact,
    /// Direct children of this artifact. `> 0` means the node is expandable.
    pub child_count: i64,
}

/// A bounded set of timeline events together with the bound that produced it.
///
/// Every field is part of the answer. A caller that renders `events` and drops
/// `truncated` is telling an examiner that a capped slice is the complete set
/// of events for that artifact or window — the exact claim this type exists to
/// prevent.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineEventPage {
    pub events: Vec<seance_core::models::TimelineEventResponse>,
    /// True when the query stopped at `cap`: more events matched than are here,
    /// and `events.len()` is a lower bound on the real total.
    pub truncated: bool,
    /// The ceiling that was actually applied.
    pub cap: usize,
}

/// A user account row (multi-user RBAC). `password_hash` is a bcrypt hash and
/// must never be serialized back to API clients.
#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub active: bool,
    /// When true, the user must change their password before doing anything
    /// else (a bootstrap admin seeded with the default password).
    pub must_change_password: bool,
    /// Unix seconds when the password last changed; 0 = never since the column
    /// was added. The auth middleware rejects a token whose `iat` predates this
    /// so a stolen session dies on credential rotation (BUG-076).
    pub password_changed_at: i64,
    /// Unix seconds before which this user's tokens are no longer sessions;
    /// 0 = nothing has invalidated them since the column was added.
    ///
    /// Stamped when an admin **deactivates** the account. Deactivation alone is
    /// already refused on every request, but that refusal lasts only as long as
    /// the account stays deactivated: without this stamp, reactivating brought
    /// every token held from before the deactivation back to life (SEC-002).
    /// The stamp is deliberately **not** cleared on reactivation — clearing it
    /// is what the defect did.
    pub sessions_invalid_before: i64,
}

/// Raw row shape as stored in SQLite: UUID as BLOB, `active` as INTEGER.
/// Decoded into `UserRow` (BLOB -> Uuid, INTEGER -> bool) via `map_user_row`.
#[derive(sqlx::FromRow)]
struct RawUserRow {
    id: Vec<u8>,
    username: String,
    password_hash: String,
    role: String,
    active: i64,
    must_change_password: i64,
    password_changed_at: i64,
    sessions_invalid_before: i64,
}

/// Is this the shape of a theme name?
///
/// `<skin>:<mode>`, where the skin is 1-32 lowercase letters, digits or dashes
/// and the mode is exactly `light` or `dark`.
///
/// The **catalogue** of skins is deliberately not checked here. Which skins
/// exist is the frontend's knowledge — it holds the palettes — and a server
/// that also held the list would need a redeploy to add one, and would reject a
/// newer client's perfectly good choice in the meantime. A client that reads
/// back a skin it does not recognise falls back to the default, which is the
/// same thing it does for a user who never chose.
///
/// What is checked is what the server is answerable for: this string is
/// supplied by a client and handed back to every session that user opens, so it
/// must be bounded and must not be able to carry anything but a name.
/// [`is_valid_theme`] over an optional value, for callers that need to tell a
/// rejected value apart from a failed write.
///
/// `None` — clearing the choice — is always valid.
pub fn is_valid_theme_value(value: Option<&str>) -> bool {
    value.is_none_or(is_valid_theme)
}

fn is_valid_theme(value: &str) -> bool {
    let Some((skin, mode)) = value.split_once(':') else {
        return false;
    };
    if !matches!(mode, "light" | "dark") {
        return false;
    }
    !skin.is_empty()
        && skin.len() <= 32
        && skin
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The label the bookmarks list shows in its ARTIFACT column.
///
/// # Why this is not just `$.name` (HELP-002)
///
/// Bookmarking four `NtfsLogFileRecord` rows produced four bookmarks whose
/// ARTIFACT column all read **Unknown**, distinguished only by the examiner's
/// own note. That was honest — a `$LogFile` transaction has no name, it is
/// identified by its LSN and record number — and useless: the bookmark list is
/// a curation surface whose whole purpose is returning to a *specific* record,
/// and four identical labels cannot be told apart at a glance.
///
/// So a record with no name falls back to the identifier its own kind is known
/// by. The per-type keys are taken from the tailored viewers in
/// `frontend/src/pages/analysis/viewers.tsx` — the leading columns each viewer
/// shows — rather than invented here, so the label an examiner reads in the
/// bookmark list is the same field they were looking at when they bookmarked it.
///
/// `Unknown` is kept for the case it was always right for: a record carrying
/// nothing identifying at all. Replacing it with a synthesised string — a row
/// number, a truncated UUID — would be inventing an identity the evidence does
/// not have.
fn bookmark_display_name(metadata: &serde_json::Value) -> String {
    /// `(record type, [(label, key)])`, in the order the label is composed.
    ///
    /// Two keys at most: this is a table column, and a third field makes it
    /// unreadable before it makes it more distinguishing. A type whose leading
    /// viewer column is a *timestamp* is deliberately not listed — a bookmark
    /// labelled by time is no easier to tell apart than one labelled Unknown,
    /// and the list is already ordered by time.
    const IDENTIFIERS: &[(&str, &[(&str, &str)])] = &[
        // NTFS journals: neither carries a name; each is identified by its
        // sequence number, and the USN entry by the file it touched.
        (
            "NtfsLogFileRecord",
            &[("LSN", "lsn"), ("record", "record_number")],
        ),
        ("UsnJournalEntry", &[("", "file_name"), ("USN", "usn")]),
        // A YARA match is identified by the rule that matched.
        ("YaraMatch", &[("rule", "rule"), ("", "namespace")]),
        // The utmp family: a login is a user at a terminal.
        ("LoginSession", &[("", "user"), ("on", "tty")]),
        ("FailedLogin", &[("", "user"), ("on", "tty")]),
        ("LastLogin", &[("", "user"), ("uid", "uid")]),
        ("BootEvent", &[("", "kind"), ("record", "record_index")]),
        // Browser artefacts that are not a page: a cookie is host + name, a
        // saved login is site + user, an autofill entry is field + value.
        ("BrowserCookie", &[("", "host"), ("", "cookie_name")]),
        ("BrowserLogin", &[("", "origin_url"), ("", "username")]),
        ("BrowserAutofill", &[("", "field_name"), ("", "value")]),
        // Windows execution and event artefacts.
        (
            "EvtxLogEntry",
            &[("event", "event_id"), ("", "provider_name")],
        ),
        ("PrefetchEntry", &[("", "executable_name")]),
        ("ShimcacheEntry", &[("", "path")]),
        ("AmcacheEntry", &[("", "file_path")]),
        ("ShellHistoryEntry", &[("", "command")]),
        ("RegistryHive", &[("", "hive_type"), ("", "root_key_name")]),
        ("UsbDevice", &[("", "friendly_name"), ("", "product")]),
        ("ShellBagEntry", &[("", "path"), ("", "folder_name")]),
    ];

    /// Keys worth trying whatever the record type is, for a record whose type
    /// this table does not know. Ordered most-identifying first.
    const GENERIC_IDENTIFIERS: &[&str] = &[
        "title",
        "display_name",
        "url",
        "command",
        "rule",
        "identifier",
        "subject",
        "sha256",
    ];

    /// One field, as the record holds it.
    ///
    /// Strings and numbers as themselves; everything else (objects, arrays,
    /// booleans, null) skipped, because a label reading `[object Object]` is
    /// worse than Unknown. A whitespace-only string identifies nothing and is
    /// skipped too.
    ///
    /// NOT bounded and NOT normalised here, and that is a correction. An earlier
    /// version cut this at 120 characters and collapsed interior whitespace, on
    /// the argument that it fed a table cell. It also feeds the bookmarks CSV
    /// export and the report, where it is printed AS the artifact's name — so a
    /// long path in an exhibit was cut with an ellipsis and a name carrying a
    /// newline was silently rewritten, by a helper whose job was labelling. The
    /// screen bounds what it shows; the record is exported as it is.
    fn field(metadata: &serde_json::Value, key: &str) -> Option<String> {
        match metadata.get(key) {
            Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
    }

    // Unchanged: a record that has a name is called by it.
    if let Some(name) = ["name", "filename", "path"]
        .iter()
        .find_map(|k| field(metadata, k))
    {
        return name;
    }

    // The same derivation `RECORD_TYPE_EXPR` makes: a `$LogFile` record written
    // before `UI-009`'s emit fix carries no `$.type`, and is recognised by the
    // pair of fields only that parser writes. Without this the legacy rows —
    // the exact rows `HELP-002` was raised on — still read "Unknown".
    let legacy_logfile = metadata.get("redo_operation").is_some() && metadata.get("lsn").is_some();
    let record_type = ["type", "subtype"]
        .iter()
        .find_map(|k| metadata.get(*k).and_then(|v| v.as_str()))
        .unwrap_or(if legacy_logfile {
            "NtfsLogFileRecord"
        } else {
            ""
        });

    if let Some((_, keys)) = IDENTIFIERS.iter().find(|(t, _)| *t == record_type) {
        let parts: Vec<String> = keys
            .iter()
            .filter_map(|(label, key)| {
                field(metadata, key).map(|v| {
                    if label.is_empty() {
                        v
                    } else {
                        format!("{label} {v}")
                    }
                })
            })
            .collect();
        if !parts.is_empty() {
            return parts.join(" · ");
        }
    }

    GENERIC_IDENTIFIERS
        .iter()
        .find_map(|k| field(metadata, k))
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Decode one `ad_hoc_jobs` row (columns as selected by the job queries).
///
/// Every field is required and nothing is defaulted: an unrecognised status is
/// an error, not a `Failed` job (that would report a module outcome nothing
/// reported), and a negative `artifacts_produced` is an error, not a wrapped
/// `usize`. Callers either propagate the error or count the row as undecodable.
fn decode_job_row(row: &sqlx::sqlite::SqliteRow) -> Result<seance_core::profile::AdHocJob> {
    use seance_core::profile::JobStatus;
    let uuid = |col: &str| -> Result<Uuid> {
        let bytes: Vec<u8> = row.try_get(col)?;
        Uuid::from_slice(&bytes).with_context(|| format!("Invalid ad-hoc job {col}"))
    };
    let status_str: String = row.try_get("status")?;
    let status = match status_str.as_str() {
        "pending" => JobStatus::Pending,
        "running" => JobStatus::Running,
        "complete" => JobStatus::Complete,
        "failed" => JobStatus::Failed,
        other => anyhow::bail!("ad-hoc job has an unrecognised status '{other}'"),
    };
    let produced: i64 = row.try_get("artifacts_produced")?;
    Ok(seance_core::profile::AdHocJob {
        id: uuid("id")?,
        case_id: uuid("case_id")?,
        module_id: row.try_get("module_id")?,
        target_artifact_id: uuid("target_artifact_id")?,
        status,
        artifacts_produced: usize::try_from(produced)
            .context("ad-hoc job has a negative artifacts_produced")?,
        error_message: row.try_get("error_message")?,
        created_at: row.try_get("created_at")?,
        completed_at: row.try_get("completed_at")?,
    })
}

#[derive(Debug, Clone)]
pub struct SqliteConnection {
    pool: SqlitePool,
    /// Serializes audit-log writes so concurrent writers cannot both read the
    /// same chain head and fork the hash chain. Shared across clones.
    audit_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Optional server-held key (from `SEANCE_AUDIT_HMAC_KEY`) that turns the
    /// audit hash chain into a keyed HMAC chain, so it cannot be recomputed by
    /// anyone with only DB access. When `None`, the chain is a plain SHA-256
    /// chain (backward compatible). Held here, never persisted to the DB.
    audit_hmac_key: Option<Vec<u8>>,
    /// Retired audit keys (from `SEANCE_AUDIT_HMAC_KEY_PREVIOUS`), so a rotation
    /// keeps the rows written under the old key verifiable instead of turning
    /// the whole earlier history into a "broken chain". Each row records the
    /// fingerprint of the key it was written under, and the verifier picks the
    /// matching key from this list. Never persisted to the DB.
    audit_hmac_previous_keys: Vec<Vec<u8>>,
    /// Number of recursive-subtree statements issued by scoped record listings.
    /// Shared across clones. See [`SqliteConnection::scoped_record_walks`].
    scoped_record_walks: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Size of the write-ahead log sitting beside the database a URL names, if
/// there is one. Used only to explain a slow open; a URL this cannot parse
/// (`:memory:`, anything unusual) simply yields `None`.
fn wal_bytes_beside(database_url: &str) -> Option<u64> {
    let path = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url);
    let path = path.split('?').next()?;
    if path.is_empty() || path.contains(":memory:") {
        return None;
    }
    std::fs::metadata(format!("{path}-wal"))
        .ok()
        .map(|m| m.len())
}

impl SqliteConnection {
    /// The ingest runs of `case_id` matching `predicate` (an SQL fragment over
    /// the table's own columns, from a fixed set of call sites), newest first.
    async fn ingest_runs_where(
        &self,
        case_id: Uuid,
        predicate: &str,
    ) -> Result<Vec<seance_core::profile::IngestRun>> {
        let sql = format!(
            "SELECT id, case_id, source_artifact_id, source_label, started_at, finished_at, \
             status, artifacts_recorded, detail FROM ingest_runs \
             WHERE case_id = ? AND {predicate} ORDER BY started_at DESC, id ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await
            .context("Failed to list ingest runs")?;
        rows.iter().map(Self::ingest_run_from_row).collect()
    }

    fn ingest_run_from_row(
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<seance_core::profile::IngestRun> {
        let uuid = |col: &str| -> Result<Uuid> {
            let bytes: Vec<u8> = row.try_get(col)?;
            Uuid::from_slice(&bytes).with_context(|| format!("ingest_runs.{col} is not a UUID"))
        };
        Ok(seance_core::profile::IngestRun {
            id: uuid("id")?,
            case_id: uuid("case_id")?,
            source_artifact_id: uuid("source_artifact_id")?,
            source_label: row.try_get("source_label")?,
            started_at: row.try_get("started_at")?,
            finished_at: row.try_get("finished_at")?,
            status: row.try_get("status")?,
            artifacts_recorded: row.try_get("artifacts_recorded")?,
            detail: row.try_get("detail")?,
        })
    }

    /// How many artifacts sit under `root` (excluding the root itself).
    async fn subtree_size(&self, case_id: Uuid, root: Uuid) -> Result<i64> {
        let cte = subtree_cte(case_id);
        let n: i64 = sqlx::query_scalar(&format!("{cte} SELECT MAX(COUNT(*) - 1, 0) FROM subtree"))
            .bind(case_id.as_bytes().to_vec())
            .bind(root.as_bytes().to_vec())
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    pub async fn new(database_url: &str) -> Result<Self> {
        // Foreign key enforcement is OFF by default in SQLite and is a
        // per-connection setting. sqlx currently defaults it ON, but we set it
        // explicitly so every pooled connection is guaranteed to enforce the
        // ON DELETE CASCADE / SET NULL actions declared in the migrations,
        // regardless of sqlx defaults changing.
        // All of these are PER-CONNECTION settings (except WAL, which is
        // database-level but harmless to request per connection). Setting them
        // on the connect options applies them to EVERY pooled connection as it
        // is opened. Previously they were run once via `.execute(&pool)`, which
        // only configured a single connection -- the other 15 kept SQLite's
        // defaults (notably busy_timeout=0), so under a heavy concurrent write
        // load a writer on an unconfigured connection failed instantly with
        // SQLITE_BUSY instead of waiting. A 30s timeout lets a large ingest's
        // write storm drain rather than dropping batches.
        let connect_options = SqliteConnectOptions::from_str(database_url)
            .context("Invalid SQLite database URL")?
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(30))
            .pragma("cache_size", "-64000") // 64MB page cache
            .pragma("temp_store", "MEMORY")
            .pragma("mmap_size", "268435456") // 256MB memory-mapped I/O
            // Bound ANALYZE to sampling ~400 rows per index so optimize() stays
            // cheap even on the multi-hundred-thousand-row artifacts table.
            .pragma("analysis_limit", "400")
            // Defer WAL checkpoints during a bulk ingest. The default 1000-page
            // (~4MB) autocheckpoint fires repeatedly mid-ingest, each time
            // briefly blocking writers; let the WAL grow to ~8MB between
            // checkpoints and truncate it in optimize() once ingest settles.
            .pragma("wal_autocheckpoint", "2000");

        let pool = SqlitePoolOptions::new()
            .max_connections(16) // Increased for parallel workers
            .connect_with(connect_options)
            .await
            .map_err(|e| match wal_bytes_beside(database_url) {
                // Opening a database whose WAL is enormous means recovering it
                // first, which can run for minutes and times the pool out with
                // nothing to say about why (HUNT-088). Say why.
                Some(bytes) if bytes > 1_000_000_000 => anyhow::Error::new(e).context(format!(
                    "Failed to connect to SQLite database: its write-ahead log is {:.1} GB and \
                     has to be recovered before any connection opens, which can take minutes. \
                     Let it finish, or checkpoint it first with \
                     `sqlite3 <database> 'PRAGMA wal_checkpoint(TRUNCATE)'`",
                    bytes as f64 / 1_000_000_000.0
                )),
                _ => anyhow::Error::new(e).context("Failed to connect to SQLite database"),
            })?;

        info!("SQLite configured (per-connection): WAL, synchronous=NORMAL, 64MB cache, 256MB mmap, 30s busy_timeout");

        // A keyed audit chain requires a stable server-held secret. Read it from
        // the environment (raw UTF-8 bytes of the value); when unset the chain
        // stays a plain SHA-256 chain. Do NOT invent a per-run key -- it must be
        // stable across restarts for the existing chain to keep verifying.
        let audit_hmac_key = std::env::var("SEANCE_AUDIT_HMAC_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .map(|k| k.into_bytes());
        // Retired keys, colon-separated, oldest or newest first -- order does
        // not matter because each row names its key by fingerprint. A rotation
        // is: move the old value here, put the new one in SEANCE_AUDIT_HMAC_KEY.
        let audit_hmac_previous_keys: Vec<Vec<u8>> =
            std::env::var("SEANCE_AUDIT_HMAC_KEY_PREVIOUS")
                .ok()
                .map(|v| parse_retired_audit_keys(&v))
                .unwrap_or_default();
        if let Some(key) = &audit_hmac_key {
            info!(
                "Audit log using keyed HMAC-SHA256 chain (SEANCE_AUDIT_HMAC_KEY set, fingerprint {}; {} retired key(s) held for verification).",
                audit_key_fingerprint(key),
                audit_hmac_previous_keys.len()
            );
        } else {
            warn!(
                "SEANCE_AUDIT_HMAC_KEY not set: the audit hash chain is unkeyed and can be \
                 recomputed by anyone with database write access. Set it to a stable secret to \
                 make the chain tamper-evident."
            );
        }

        Ok(Self {
            pool,
            audit_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            audit_hmac_key,
            audit_hmac_previous_keys,
            scoped_record_walks: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Whether audit rows written through this handle are keyed, i.e. whether
    /// `SEANCE_AUDIT_HMAC_KEY` was set when it was opened.
    ///
    /// The server asks this at startup so an unkeyed chain on a network-exposed
    /// bind is a refusal rather than a warning: the chain of custody is the
    /// product, and a default that lets it be rewritten is not a default a
    /// deployment should reach by omission (DEPLOY-001).
    pub fn audit_chain_keyed(&self) -> bool {
        self.audit_hmac_key.is_some()
    }

    /// How many recursive `subtree` walks scoped record listings have issued on
    /// this handle (see [`SqliteConnection::list_records_by_type`]).
    ///
    /// A scoped listing drags a full recursive walk of the artifact tree behind
    /// every statement it runs, and that cost is invisible from the outside:
    /// the answers are correct, just unreachable. The listing used to walk the
    /// tree twice per page -- once to COUNT, once to read the window -- while
    /// its memory-API caller paged the same scope dozens of times, so a single
    /// endpoint could pay for hundreds of walks and never return. The counter
    /// exists so tests can pin the walk count to one per page rather than
    /// re-discovering the regression as a timeout.
    pub fn scoped_record_walks(&self) -> u64 {
        self.scoped_record_walks
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Post-ingest maintenance: refresh the query-planner statistics and fold
    /// the deferred WAL back into the main database file.
    ///
    /// ANALYZE lets the planner pick among the overlapping `artifacts` indices
    /// from real cardinality instead of guessing; it is bounded by the
    /// per-connection `analysis_limit` pragma, so it samples rather than doing a
    /// full table scan. The truncating WAL checkpoint keeps the -wal file (grown
    /// large by the deferred `wal_autocheckpoint`) from lingering after ingest.
    pub async fn optimize(&self) -> Result<()> {
        sqlx::query("ANALYZE")
            .execute(&self.pool)
            .await
            .context("ANALYZE failed")?;
        // Best-effort: a concurrent reader can make TRUNCATE fall back to a
        // partial checkpoint (reported as "busy"), which is not an error here.
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await;
        Ok(())
    }
}

/// Extract the `md5`/`sha1`/`sha256` metadata keys (as written by the file
/// hasher and carver) for storage in the indexed hash columns. Values are
/// stored verbatim; hash-set matching compares case-insensitively.
fn extract_metadata_hashes(
    metadata: &serde_json::Value,
) -> (Option<String>, Option<String>, Option<String>) {
    let get = |key: &str| {
        metadata
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    // Prefer the canonical keys written by the hasher/carver; fall back to the
    // legacy *_hash keys some records/tests still use.
    (
        get("md5").or_else(|| get("md5_hash")),
        get("sha1").or_else(|| get("sha1_hash")),
        get("sha256").or_else(|| get("sha256_hash")),
    )
}

/// A parsed timeline timestamp: the UTC instant plus the provenance needed to
/// reconstruct the source's original wall-clock reading (D5 sub-second
/// precision, D6 source timezone).
#[derive(Debug, PartialEq, Eq)]
struct ParsedTimestamp {
    /// Whole seconds since the Unix epoch (UTC).
    secs: i64,
    /// Sub-second component in nanoseconds (0..=999_999_999).
    subsec_nanos: i64,
    /// Seconds east of UTC of the source's timezone, or None when the source
    /// supplied a bare Unix-integer timestamp (offset unknowable).
    offset_seconds: Option<i32>,
}

/// Parse a timeline event `timestamp` metadata value.
///
/// Plugins store timestamps either as i64 unix seconds or as RFC3339 strings.
/// Both are accepted; returns None only when neither form parses. An RFC3339
/// string preserves its fractional seconds and UTC offset; a bare integer has
/// neither (subsec 0, offset unknown).
fn parse_timeline_timestamp(value: &serde_json::Value) -> Option<ParsedTimestamp> {
    if let Some(ts) = value.as_i64() {
        return Some(ParsedTimestamp {
            secs: ts,
            subsec_nanos: 0,
            offset_seconds: None,
        });
    }
    let dt = chrono::DateTime::parse_from_rfc3339(value.as_str()?).ok()?;
    Some(ParsedTimestamp {
        secs: dt.timestamp(),
        subsec_nanos: i64::from(dt.timestamp_subsec_nanos()),
        offset_seconds: Some(dt.offset().local_minus_utc()),
    })
}

/// Produce the `timeline_events.full_details` value, which MUST be valid
/// JSON: migration 0005 defines a generated column via
/// `json_extract(full_details, '$.filename')`, so a non-JSON value fails the
/// insert with "malformed JSON". Plugins that omit full_details fall back to
/// the whole metadata document; plain-text values are wrapped as JSON strings.
fn timeline_full_details(metadata: &serde_json::Value, metadata_json: &str) -> String {
    match metadata.get("full_details").and_then(|v| v.as_str()) {
        Some(details) if serde_json::from_str::<serde_json::Value>(details).is_ok() => {
            details.to_string()
        }
        Some(details) => serde_json::Value::String(details.to_string()).to_string(),
        None => metadata_json.to_string(),
    }
}

/// Resolve one virtual-column JSON path (`$.a`, `$.a.b`, `$.a[0].b`) against a
/// timeline event's `full_details` document.
///
/// The timeline extract used to strip `$.` and do a single top-level map
/// lookup, so `$.items[0].name` was searched for as the literal key
/// `items[0].name`. `seance_core::virtual_columns` accepts and stores those
/// paths, the column renders as configured, and every row comes back blank —
/// a value that is present in the evidence reads as absent.
fn resolve_json_path<'a>(
    document: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let trimmed = path
        .strip_prefix("$.")
        .or_else(|| path.strip_prefix('$'))
        .unwrap_or(path);
    if trimmed.is_empty() {
        return None;
    }
    let mut current = document;
    for segment in trimmed.split('.') {
        if segment.is_empty() {
            return None;
        }
        // "key[0][1]" -> object key "key", then each array index in turn.
        let (key, mut rest) = match segment.find('[') {
            Some(i) => segment.split_at(i),
            None => (segment, ""),
        };
        if !key.is_empty() {
            current = current.get(key)?;
        }
        while let Some(after_open) = rest.strip_prefix('[') {
            let close = after_open.find(']')?;
            let index: usize = after_open[..close].trim().parse().ok()?;
            current = current.get(index)?;
            rest = &after_open[close + 1..];
        }
        if !rest.is_empty() {
            return None;
        }
    }
    Some(current)
}

/// Build a cycle-safe, **unbounded** recursive-CTE walk of an artifact's
/// `parent_id` subtree, exposed to the enclosing query as `subtree(id)`.
///
/// The anchor binds `case_id` first, then the scope artifact's id; the
/// recursive step embeds the (validated, hex-encoded) case id as a blob
/// literal so it adds no placeholder and cannot pull a cross-case `parent_id`
/// into the walk. `parent_id` has no FK enforcing same-case, so that filter is
/// the guarantee.
///
/// The scope artifact itself is part of `subtree`. A caller that wants
/// descendants only excludes it in its own `WHERE` (the old CTEs did this with
/// `s.depth > 0`); anchoring on the scope artifact's `id` rather than on its
/// children is what keeps the "this artifact really belongs to this case"
/// check on the anchor row.
///
/// Forensic meaning: these walks used to stop at `depth < 32`. Nothing said so.
/// A file nested deeper than 32 parent links -- an archive inside an archive
/// inside a disk image, or a deep filesystem tree -- vanished from the browse
/// list, from the record counts and from the directory treemap simultaneously,
/// so three independent views agreed on the same wrong answer and an examiner
/// had no way to notice. The cap is gone: `UNION` (not `UNION ALL`) makes the
/// walk terminate on a cyclic `parent_id` by refusing to re-add an id already
/// in the result, which is what the cap was standing in for.
///
/// # `CROSS JOIN`, and why it must not be "tidied" into a plain `JOIN`
///
/// Every recursive walk over `artifacts` in this file writes the queue first and
/// joins with `CROSS JOIN`. That is load-bearing, not style.
///
/// SQLite may reorder an inner join, and for a recursive CTE it has no
/// cardinality estimate for the queue, so it chooses `artifacts` as the outer
/// loop: each step then SEARCHes `idx_artifacts_case_id` — *every artifact in
/// the case* — and SCANs the queue for each row. That is quadratic in the size
/// of the case, and it is not a slow query, it is a query that does not finish:
/// on a 163,000-artifact case the counts-by-source walk ran past ten minutes
/// and was still going, while the same walk with the order pinned takes 0.8s.
/// The endpoint gave up at its 300-second timeout and the gallery sat on
/// "Loading images…" for ever (`UI-024`).
///
/// `CROSS JOIN` is SQLite's documented way to fix the join order, and it turns
/// the recursive step into a seek of `idx_artifacts_browse_children
/// (case_id, parent_id)`. **Writing the queue first without `CROSS` does not
/// work** — the planner reorders it anyway; that was measured, not assumed.
///
/// `expr_index_plan_test.rs` EXPLAINs every one of these walks and fails if a
/// recursive step goes back to scanning the queue, so the guarantee cannot be
/// lost silently. The comms ranking learned the same lesson separately, which
/// is why it carries `CROSS JOIN ... INDEXED BY` too.
pub fn subtree_cte(case_id: Uuid) -> String {
    format!(
        "WITH RECURSIVE subtree(id) AS ( \
             SELECT id FROM artifacts WHERE case_id = ? AND id = ? \
             UNION \
             SELECT a.id FROM subtree s CROSS JOIN artifacts a ON a.parent_id = s.id \
             WHERE a.case_id = X'{}' \
         ) ",
        case_id.simple()
    )
}

/// The stored metadata of a `TimelineEvent` whose timestamp could not be
/// parsed, with a derived `timeline_omitted` object saying that it has no
/// `timeline_events` row and why. Every original field is kept untouched; the
/// raw timestamp is repeated inside the marker so the reason is checkable
/// without the surrounding record. Metadata that is not a JSON object cannot
/// carry a marker and is stored as given (the caller has already logged it).
fn timeline_omitted_metadata_json(metadata: &serde_json::Value) -> Result<String> {
    let mut marked = metadata.clone();
    if let Some(obj) = marked.as_object_mut() {
        obj.insert(
            "timeline_omitted".to_string(),
            serde_json::json!({
                "reason": "timestamp missing or unparseable; no timeline row was created",
                "raw_timestamp": metadata["timestamp"],
            }),
        );
    }
    serde_json::to_string(&marked).context("Failed to serialize artifact metadata")
}

/// One `timeline_events` row, in the column order every insert site binds:
/// `(id, case_id, artifact_id, timestamp, timestamp_subsec_nanos,
/// source_utc_offset_seconds, timestamp_desc, source_module, short_desc,
/// full_details)`.
type TimelineEventRowValues = (
    Uuid,
    Uuid,
    Uuid,
    i64,
    i64,
    Option<i32>,
    String,
    String,
    String,
    String,
);

/// `source_module` carried by every timeline row derived from a file's own
/// filesystem timestamps.
///
/// One value for all filesystems on purpose: it is the axis an examiner filters
/// on to separate "what the volume metadata says happened" from application and
/// operating-system evidence, and the file's path in `full_details` already
/// says which volume it came from.
pub const FILE_TIMELINE_SOURCE_MODULE: &str = "filesystem.mac_times";

/// The filesystem timestamps a [`FileEntry`](ArtifactType::FileEntry) can
/// carry, in reporting order, paired with the `timestamp_desc` an examiner
/// reads on the timeline.
///
/// This is the key vocabulary every filesystem parser in the tree already
/// writes. It is deliberately literal about what each one MEANS: `changed` is
/// the inode change time on ext4/XFS/APFS/Btrfs/F2FS (metadata, not content,
/// and emphatically not a creation time), `mft_modified` is the NTFS
/// $STANDARD_INFORMATION record-change time, `deleted_time` is ext4's `dtime`
/// and the Recycle Bin's deletion stamp. A filesystem that does not record a
/// given time omits the key and no row is produced for it.
const FILE_ENTRY_TIME_KINDS: [(&str, &str); 6] = [
    ("created", "Created"),
    ("modified", "Modified"),
    ("accessed", "Accessed"),
    ("changed", "Metadata Changed"),
    ("mft_modified", "MFT Modified"),
    ("deleted_time", "Deleted"),
];

/// Project a [`FileEntry`](ArtifactType::FileEntry)'s own filesystem timestamps
/// onto the unified timeline.
///
/// # Why this lives on the write path
///
/// Before this projection the timeline was populated ONLY by plugins that build
/// `TimelineEvent` artifacts themselves. On NTFS the $MFT parser does, so an
/// NTFS image had a timeline; on ext4, XFS, APFS, Btrfs, F2FS, FAT/exFAT, HFS+,
/// ISO9660, SquashFS, in iOS backups and in archive members, the parser wrote
/// real `created`/`modified`/`accessed` values into each entry's metadata and
/// the timeline stayed EMPTY — the dashboard reading "No dated events" over
/// evidence that demonstrably carried dates. Projecting here, beside the chat
/// projection, means one implementation covers every producer that exists and
/// every one added later, with no parser change and no way for a new filesystem
/// to be silently absent from the timeline.
///
/// # Volume
///
/// The obvious shape — four rows per file — makes a 24,000-file volume 96,000
/// rows of which most are duplicates: a copied or freshly written file usually
/// carries one instant under three or four names. Timestamps naming the SAME
/// instant are therefore coalesced into ONE row whose `timestamp_desc` lists
/// every kind ("Created, Modified, Accessed"), which is how `mactime` has
/// presented MACB for decades and is strictly more informative than N identical
/// rows. Volume then tracks the distinct instants in the evidence rather than a
/// multiple of the file count.
///
/// Nothing is capped. A cap would drop files from the timeline with no way for
/// an examiner to know which, and every timeline read is already bounded and
/// declares its own truncation.
///
/// # Granularity of tags
///
/// All rows for one file share its `artifact_id`, and `timeline_tags` is keyed
/// by `artifact_id`, so tagging one of a file's MAC rows tags the file. That is
/// the same granularity every non-`TimelineEvent` source already has.
fn file_entry_timeline_rows(artifact: &Artifact) -> Vec<TimelineEventRowValues> {
    if artifact.artifact_type != ArtifactType::FileEntry {
        return Vec::new();
    }
    let m = &artifact.metadata;
    // The producer emits its own, richer events for this file (see
    // FILE_TIMELINE_SELF_EMITTED_KEY). Projecting as well would report every
    // one of its files twice at the same instant.
    if m.get(seance_core::artifact::FILE_TIMELINE_SELF_EMITTED_KEY)
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return Vec::new();
    }

    // Group by instant, preserving first-seen (FILE_ENTRY_TIME_KINDS) order.
    // At most six entries, so a linear scan is the whole cost.
    let mut groups: Vec<(ParsedTimestamp, Vec<&'static str>)> = Vec::new();
    for (key, desc) in FILE_ENTRY_TIME_KINDS {
        let Some(value) = m.get(key) else { continue };
        // Null, and the empty string some parsers write for an out-of-range
        // field, are how a producer says "this filesystem did not record it".
        // Neither is a malformed timestamp, so neither is worth a warning.
        if value.is_null() || value.as_str() == Some("") {
            continue;
        }
        let Some(ts) = parse_timeline_timestamp(value) else {
            // Present but unreadable. It stays off the timeline rather than
            // being pinned to a guessed instant; the raw value survives on the
            // artifact, where an examiner can still see it.
            warn!(
                "FileEntry {}: `{}` is present but not a parseable timestamp ({}); \
                 it is left off the timeline rather than guessed at",
                artifact.id, key, value
            );
            continue;
        };
        match groups.iter().position(|(seen, _)| *seen == ts) {
            Some(pos) => groups[pos].1.push(desc),
            None => groups.push((ts, vec![desc])),
        }
    }
    if groups.is_empty() {
        return Vec::new();
    }

    let name = m.get("name").and_then(|v| v.as_str());
    let path = m
        .get("path")
        .and_then(|v| v.as_str())
        .or_else(|| m.get("relative_path").and_then(|v| v.as_str()));
    let is_directory = m
        .get("is_directory")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let deleted = m.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false);

    // The one line an examiner reads on the timeline row. The full path when
    // there is one: two files called `index.db` on the same volume are not the
    // same evidence, and the timeline is where that confusion is costly.
    let display = path.or(name).unwrap_or("(unnamed)");
    let kind = if is_directory { "DIR" } else { "FILE" };
    let short_desc = if deleted {
        format!("{kind} {display} (deleted)")
    } else {
        format!("{kind} {display}")
    };

    // A compact projection, NOT the entry's whole metadata document. An $MFT or
    // ext4 entry carries its run list, attribute set and hashes; copying that
    // into every timeline row would multiply the largest blob in the database
    // by the number of dated files. `filename` is mandatory: migration 0005
    // generates an indexed column from `json_extract(full_details,
    // '$.filename')`, and the timeline's filename filter and sort read it.
    let file_name = name
        .map(str::to_string)
        .or_else(|| path.map(|p| p.rsplit(['/', '\\']).next().unwrap_or(p).to_string()));
    let mut details = serde_json::Map::new();
    if let Some(f) = file_name {
        details.insert("filename".to_string(), serde_json::json!(f));
    }
    if let Some(p) = path {
        details.insert("path".to_string(), serde_json::json!(p));
    }
    for key in ["size", "inode", "record_number"] {
        match m.get(key) {
            Some(v) if !v.is_null() => {
                details.insert(key.to_string(), v.clone());
            }
            _ => {}
        }
    }
    details.insert("is_directory".to_string(), serde_json::json!(is_directory));
    if deleted {
        details.insert("deleted".to_string(), serde_json::json!(true));
    }
    let full_details = serde_json::Value::Object(details).to_string();

    groups
        .into_iter()
        .map(|(ts, descs)| {
            let timestamp_desc = descs.join(", ");
            // Derived, not random: the event id is a pure function of the file
            // and the kinds it stands for, so the same artifact table always
            // yields the same timeline ids and a retried batch cannot leave two
            // rows behind for one timestamp.
            let id = Uuid::new_v5(&artifact.id, timestamp_desc.as_bytes());
            (
                id,
                artifact.case_id,
                artifact.id,
                ts.secs,
                ts.subsec_nanos,
                ts.offset_seconds,
                timestamp_desc,
                FILE_TIMELINE_SOURCE_MODULE.to_string(),
                short_desc.clone(),
                full_details.clone(),
            )
        })
        .collect()
}

/// Direction-aware one-line summary of a chat message, for its timeline row.
/// e.g. `iMessage to +420731485450: Ahoj Jirko, v kolik budes na vlakaci?`
fn chat_short_desc(m: &serde_json::Value, platform: &str, direction: Option<&str>) -> String {
    let who = m
        .get("contact_name")
        .and_then(|v| v.as_str())
        .or_else(|| m.get("contact").and_then(|v| v.as_str()))
        .or_else(|| m.get("chat_identifier").and_then(|v| v.as_str()))
        .or_else(|| m.get("conversation_id").and_then(|v| v.as_str()))
        .unwrap_or("unknown");
    let rel = match direction {
        Some("sent") => "to",
        Some("received") => "from",
        _ => "with",
    };
    // Collapse whitespace so a multi-line message stays a single timeline line.
    let preview: String = m
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect();
    if preview.is_empty() {
        format!("{platform} {rel} {who}")
    } else {
        format!("{platform} {rel} {who}: {preview}")
    }
}

/// Project a `chat_message` [`ParsedRecord`](ArtifactType::ParsedRecord) onto a
/// timeline row, so messages (iMessage, WhatsApp, SMS, Messenger, recovered
/// bodies, ...) land on the unified timeline beside web history, email, and
/// system artifacts. Every chat plugin emits the same `subtype:"chat_message"`
/// shape, so this one projection covers all of them without touching a single
/// parser. Returns `None` for non-chat artifacts or a message with no usable
/// timestamp (undated recovered bodies are intentionally left off the timeline
/// rather than pinned to the epoch).
fn chat_timeline_row(artifact: &Artifact, metadata_json: &str) -> Option<TimelineEventRowValues> {
    if artifact.artifact_type != ArtifactType::ParsedRecord {
        return None;
    }
    let m = &artifact.metadata;
    if m.get("subtype").and_then(|v| v.as_str()) != Some("chat_message") {
        return None;
    }
    let mut ts = parse_timeline_timestamp(m.get("date")?)?;
    // `date` is whole seconds. Parsers that read a nanosecond clock (iMessage's
    // Apple-epoch column is nanoseconds since 2001) also emit `date_ns`, and
    // dropping it collapsed every message in the same second to an identical
    // timestamp — the unified timeline then ordered a reply before the message
    // it answered. Only trust `date_ns` when its whole-second part agrees with
    // `date`; a disagreement means one of the two is wrong and guessing which
    // would invent an ordering.
    if let Some(ns) = m.get("date_ns").and_then(|v| v.as_i64()) {
        if ns.div_euclid(1_000_000_000) == ts.secs {
            ts.subsec_nanos = ns.rem_euclid(1_000_000_000);
        }
    }
    let platform = m
        .get("type")
        .and_then(|v| v.as_str())
        .or_else(|| m.get("service").and_then(|v| v.as_str()))
        .or_else(|| m.get("platform").and_then(|v| v.as_str()))
        .unwrap_or("Chat");
    let direction = m.get("direction").and_then(|v| v.as_str());
    let timestamp_desc = match direction {
        Some("sent") => "Message Sent",
        Some("received") => "Message Received",
        _ => "Message",
    }
    .to_string();
    Some((
        artifact.id,
        artifact.case_id,
        artifact.id,
        ts.secs,
        ts.subsec_nanos,
        ts.offset_seconds,
        timestamp_desc,
        format!("chat.{platform}"),
        chat_short_desc(m, platform, direction),
        timeline_full_details(m, metadata_json),
    ))
}

#[async_trait]
impl DatabaseConnection for SqliteConnection {
    async fn initialize(&self) -> Result<()> {
        info!("Running database migrations...");
        MIGRATOR
            .run(&self.pool)
            .await
            .context("Failed to run migrations")?;
        info!("Database migrations complete.");
        Ok(())
    }

    async fn create_case(&self, name: &str, examiner: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let created_at = Utc::now().to_rfc3339();
        let status = "active".to_string();

        sqlx::query(
            "INSERT INTO cases (id, name, created_at, status, examiner_name) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(created_at)
        .bind(status)
        .bind(examiner)
        .execute(&self.pool)
        .await
        .context("Failed to create new case")?;

        info!("Created new case: {} (ID: {}) by {}", name, id, examiner);
        Ok(id)
    }

    async fn record_artifact(&self, artifact: &Artifact) -> Result<()> {
        debug!(
            "Recording artifact: {:?} (ID: {})",
            artifact.artifact_type, artifact.id
        );

        let parent_id_bytes = artifact.parent_id.map(|id| id.as_bytes().to_vec());
        let metadata_json = serde_json::to_string(&artifact.metadata)
            .context("Failed to serialize artifact metadata")?;
        let created_at = Utc::now().to_rfc3339();

        // Populate the indexed hash columns from any md5/sha1/sha256 metadata
        // keys so files carrying hashes at insert (e.g. carver output) are
        // immediately matchable against hash sets.
        let (md5, sha1, sha256) = extract_metadata_hashes(&artifact.metadata);

        // Artifact insert + timeline event insert must be atomic: a failure in
        // either leaves no partial record behind.
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        sqlx::query(
            "INSERT INTO artifacts (id, case_id, parent_id, artifact_type, metadata_json, created_at, md5_hash, sha1_hash, sha256_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(artifact.id)
        .bind(artifact.case_id)
        .bind(parent_id_bytes)
        .bind(artifact.artifact_type.to_string())
        .bind(&metadata_json)
        .bind(created_at)
        .bind(md5)
        .bind(sha1)
        .bind(sha256)
        .execute(&mut *tx)
        .await
        .context("Failed to record artifact")?;

        // Special handling for TimelineEvent to insert into timeline_events table
        if let ArtifactType::TimelineEvent = artifact.artifact_type {
            // Extract required fields from metadata_json for timeline_events table
            // This assumes a specific structure for TimelineEvent metadata
            let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                .context("Failed to deserialize metadata for timeline event")?;

            let ts = parse_timeline_timestamp(&metadata["timestamp"]).with_context(|| {
                format!(
                    "Timeline event {} has missing or unparseable timestamp: {}",
                    artifact.id, metadata["timestamp"]
                )
            })?;
            let timestamp_desc = metadata["timestamp_desc"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let source_module = metadata["source_module"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let short_desc = metadata["short_desc"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let full_details = timeline_full_details(&metadata, &metadata_json);

            sqlx::query(
                "INSERT INTO timeline_events (id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(artifact.id)
            .bind(artifact.case_id)
            .bind(artifact.id) // artifact_id is the same as event_id for now
            .bind(ts.secs)
            .bind(ts.subsec_nanos)
            .bind(ts.offset_seconds)
            .bind(timestamp_desc)
            .bind(source_module)
            .bind(short_desc)
            .bind(full_details)
            .execute(&mut *tx)
            .await
            .context("Failed to record timeline event")?;
        } else if let Some((id, cid, aid, secs, subsec, offset, ts_desc, src_mod, short, full)) =
            chat_timeline_row(artifact, &metadata_json)
        {
            // A chat message also earns a timeline row (see chat_timeline_row).
            sqlx::query(
                "INSERT INTO timeline_events (id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(cid)
            .bind(aid)
            .bind(secs)
            .bind(subsec)
            .bind(offset)
            .bind(ts_desc)
            .bind(src_mod)
            .bind(short)
            .bind(full)
            .execute(&mut *tx)
            .await
            .context("Failed to record chat timeline event")?;
        } else if artifact.artifact_type == ArtifactType::FileEntry {
            // A file's own MAC times are timeline evidence in their own right
            // (see file_entry_timeline_rows).
            for (id, cid, aid, secs, subsec, offset, ts_desc, src_mod, short, full) in
                file_entry_timeline_rows(artifact)
            {
                sqlx::query(
                    "INSERT INTO timeline_events (id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(id)
                .bind(cid)
                .bind(aid)
                .bind(secs)
                .bind(subsec)
                .bind(offset)
                .bind(ts_desc)
                .bind(src_mod)
                .bind(short)
                .bind(full)
                .execute(&mut *tx)
                .await
                .context("Failed to record filesystem timestamp timeline event")?;
            }
        }

        tx.commit()
            .await
            .context("Failed to commit artifact transaction")?;

        Ok(())
    }

    async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
        if artifacts.is_empty() {
            return Ok(());
        }

        debug!("Batch recording {} artifacts", artifacts.len());

        // Use a transaction for atomic batch insert
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        let created_at = Utc::now().to_rfc3339();

        // Separate artifacts and timeline events for efficient batch processing
        // Pre-allocate with capacity to avoid reallocations
        let mut artifact_inserts = Vec::with_capacity(artifacts.len());
        let mut timeline_inserts = Vec::with_capacity(artifacts.len() / 4); // ~25% are timeline events

        for artifact in artifacts {
            let parent_id_bytes = artifact.parent_id.map(|id| id.as_bytes().to_vec());
            let mut metadata_json = serde_json::to_string(&artifact.metadata)
                .context("Failed to serialize artifact metadata")?;
            let (md5, sha1, sha256) = extract_metadata_hashes(&artifact.metadata);

            // Collect the timeline row FIRST, while metadata_json is still owned
            // here, so it can move into the artifact tuple below without a clone.
            // Read fields straight from artifact.metadata (already a Value) rather
            // than re-parsing the string we just serialized from it.
            if let ArtifactType::TimelineEvent = artifact.artifact_type {
                let metadata = &artifact.metadata;
                if let Some(ts) = parse_timeline_timestamp(&metadata["timestamp"]) {
                    let timestamp_desc = metadata["timestamp_desc"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let source_module = metadata["source_module"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let short_desc = metadata["short_desc"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let full_details = timeline_full_details(metadata, &metadata_json);

                    timeline_inserts.push((
                        artifact.id,
                        artifact.case_id,
                        artifact.id, // artifact_id same as event_id
                        ts.secs,
                        ts.subsec_nanos,
                        ts.offset_seconds,
                        timestamp_desc,
                        source_module,
                        short_desc,
                        full_details,
                    ));
                } else {
                    // `record_artifact` refuses this input outright. The batch
                    // path must not lose a whole ingest to one bad event, so the
                    // artifact is kept -- but a timeline missing an event reads
                    // as a timeline with no such event, so the omission is
                    // written onto the artifact in a derived field.
                    warn!(
                        "Skipping timeline_events row for artifact {}: missing or unparseable timestamp {}",
                        artifact.id, metadata["timestamp"]
                    );
                    metadata_json = timeline_omitted_metadata_json(metadata)?;
                }
            } else if let Some(row) = chat_timeline_row(artifact, &metadata_json) {
                // Chat messages carry their own timestamp; surface them on the
                // unified timeline too (see chat_timeline_row).
                timeline_inserts.push(row);
            } else if artifact.artifact_type == ArtifactType::FileEntry {
                // A file's own MAC times are timeline evidence in their own
                // right (see file_entry_timeline_rows). This is the path the
                // orchestrator's artifact writer uses, so it is the one that
                // decides whether a disk image has a timeline at all.
                timeline_inserts.extend(file_entry_timeline_rows(artifact));
            }

            artifact_inserts.push((
                artifact.id,
                artifact.case_id,
                parent_id_bytes,
                artifact.artifact_type.to_string(),
                metadata_json,
                created_at.clone(),
                md5,
                sha1,
                sha256,
            ));
        }

        // Batch insert artifacts using multi-value INSERT
        // SQLite supports up to 999 variables per query, so chunk if needed
        const MAX_VARS: usize = 999;
        const VARS_PER_ROW: usize = 9;
        let chunk_size = MAX_VARS / VARS_PER_ROW;

        for chunk in artifact_inserts.chunks(chunk_size) {
            if chunk.is_empty() {
                continue;
            }

            // Build multi-row INSERT statement
            let placeholders: Vec<String> = (0..chunk.len())
                .map(|_| "(?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string())
                .collect();
            let sql = format!(
                "INSERT INTO artifacts (id, case_id, parent_id, artifact_type, metadata_json, created_at, md5_hash, sha1_hash, sha256_hash) VALUES {}",
                placeholders.join(", ")
            );

            let mut query = sqlx::query(&sql);
            for (id, case_id, parent_id, art_type, metadata, created, md5, sha1, sha256) in chunk {
                query = query
                    .bind(id)
                    .bind(case_id)
                    .bind(parent_id)
                    .bind(art_type)
                    .bind(metadata)
                    .bind(created)
                    .bind(md5)
                    .bind(sha1)
                    .bind(sha256);
            }

            query
                .execute(&mut *tx)
                .await
                .context("Failed to batch insert artifacts")?;
        }

        // Batch insert timeline events
        const TIMELINE_VARS_PER_ROW: usize = 10;
        let timeline_chunk_size = MAX_VARS / TIMELINE_VARS_PER_ROW;

        for chunk in timeline_inserts.chunks(timeline_chunk_size) {
            if chunk.is_empty() {
                continue;
            }

            let placeholders: Vec<String> = (0..chunk.len())
                .map(|_| "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string())
                .collect();
            let sql = format!(
                "INSERT INTO timeline_events (id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details) VALUES {}",
                placeholders.join(", ")
            );

            let mut query = sqlx::query(&sql);
            for (id, case_id, artifact_id, secs, subsec, offset, ts_desc, src_mod, short, full) in
                chunk
            {
                query = query
                    .bind(id)
                    .bind(case_id)
                    .bind(artifact_id)
                    .bind(secs)
                    .bind(subsec)
                    .bind(offset)
                    .bind(ts_desc)
                    .bind(src_mod)
                    .bind(short)
                    .bind(full);
            }

            query
                .execute(&mut *tx)
                .await
                .context("Failed to batch insert timeline events")?;
        }

        tx.commit()
            .await
            .context("Failed to commit batch transaction")?;

        debug!(
            "Batch recorded {} artifacts and {} timeline events",
            artifact_inserts.len(),
            timeline_inserts.len()
        );
        Ok(())
    }

    async fn get_artifact(&self, artifact_id: Uuid) -> Result<Option<Artifact>> {
        let row = sqlx::query(
            "SELECT id, case_id, parent_id, artifact_type, metadata_json FROM artifacts WHERE id = ?"
        )
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch artifact")?;

        if let Some(row) = row {
            let artifact = Artifact {
                id: row.try_get::<Vec<u8>, _>("id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                case_id: row.try_get::<Vec<u8>, _>("case_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                parent_id: row
                    .try_get::<Option<Vec<u8>>, _>("parent_id")?
                    .map(|bytes| Uuid::from_slice(&bytes))
                    .transpose()
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                artifact_type: seance_core::artifact::ArtifactType::from_str(
                    &row.try_get::<String, _>("artifact_type")?,
                )
                .context("Unknown artifact type")?,
                data: None, // Data sources are not persisted, only metadata
                metadata: serde_json::from_str(&row.try_get::<String, _>("metadata_json")?)
                    .context("Failed to deserialize metadata")?,
            };
            Ok(Some(artifact))
        } else {
            Ok(None)
        }
    }

    async fn create_profile(&self, profile: &seance_core::profile::IngestionProfile) -> Result<()> {
        let enabled_modules_json = serde_json::to_string(&profile.enabled_modules)
            .context("Failed to serialize enabled_modules")?;
        let disabled_modules_json = serde_json::to_string(&profile.disabled_modules)
            .context("Failed to serialize disabled_modules")?;

        sqlx::query(
            "INSERT INTO ingestion_profiles (id, case_id, name, description, enabled_modules, disabled_modules, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(profile.id)
        .bind(profile.case_id)
        .bind(&profile.name)
        .bind(&profile.description)
        .bind(&enabled_modules_json)
        .bind(&disabled_modules_json)
        .bind(profile.is_active as i32)
        .bind(profile.created_at)
        .execute(&self.pool)
        .await
        .context("Failed to create profile")?;

        info!(
            "Created profile: {} for case {}",
            profile.name, profile.case_id
        );
        Ok(())
    }

    async fn get_active_profile(
        &self,
        case_id: Uuid,
    ) -> Result<Option<seance_core::profile::IngestionProfile>> {
        let row = sqlx::query(
            "SELECT id, case_id, name, description, enabled_modules, disabled_modules, is_active, created_at FROM ingestion_profiles WHERE case_id = ? AND is_active = 1",
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch active profile")?;

        if let Some(row) = row {
            let profile = seance_core::profile::IngestionProfile {
                id: row.try_get::<Vec<u8>, _>("id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                case_id: row.try_get::<Vec<u8>, _>("case_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                enabled_modules: serde_json::from_str(
                    &row.try_get::<String, _>("enabled_modules")?,
                )
                .context("Failed to deserialize enabled_modules")?,
                disabled_modules: serde_json::from_str(
                    &row.try_get::<String, _>("disabled_modules")?,
                )
                .context("Failed to deserialize disabled_modules")?,
                is_active: row.try_get::<i32, _>("is_active")? != 0,
                created_at: row.try_get("created_at")?,
            };
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }

    async fn list_profiles(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::profile::IngestionProfile>> {
        let rows = sqlx::query(
            "SELECT id, case_id, name, description, enabled_modules, disabled_modules, is_active, created_at FROM ingestion_profiles WHERE case_id = ? ORDER BY created_at DESC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list profiles")?;

        let mut profiles = Vec::new();
        for row in rows {
            let profile = seance_core::profile::IngestionProfile {
                id: row.try_get::<Vec<u8>, _>("id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                case_id: row.try_get::<Vec<u8>, _>("case_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                enabled_modules: serde_json::from_str(
                    &row.try_get::<String, _>("enabled_modules")?,
                )
                .context("Failed to deserialize enabled_modules")?,
                disabled_modules: serde_json::from_str(
                    &row.try_get::<String, _>("disabled_modules")?,
                )
                .context("Failed to deserialize disabled_modules")?,
                is_active: row.try_get::<i32, _>("is_active")? != 0,
                created_at: row.try_get("created_at")?,
            };
            profiles.push(profile);
        }

        Ok(profiles)
    }

    async fn set_active_profile(&self, case_id: Uuid, profile_id: Uuid) -> Result<()> {
        // Use a transaction to prevent race conditions between concurrent activations
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // First, deactivate all profiles for this case
        sqlx::query("UPDATE ingestion_profiles SET is_active = 0 WHERE case_id = ?")
            .bind(case_id)
            .execute(&mut *tx)
            .await
            .context("Failed to deactivate existing profiles")?;

        // Then activate the specified profile
        let activated =
            sqlx::query("UPDATE ingestion_profiles SET is_active = 1 WHERE id = ? AND case_id = ?")
                .bind(profile_id)
                .bind(case_id)
                .execute(&mut *tx)
                .await
                .context("Failed to activate profile")?
                .rows_affected();

        // Fail CLOSED: activating a profile that does not exist (or belongs to
        // another case) must leave the previous active profile alone. Committing
        // the blanket deactivation would silently drop the case to "no profile",
        // which the orchestrator reads as "run every module" -- a silent change
        // in processing scope (BUG-232). Dropping `tx` here rolls back.
        if activated == 0 {
            anyhow::bail!(
                "Profile {} does not exist in case {}; active profile unchanged",
                profile_id,
                case_id
            );
        }

        tx.commit()
            .await
            .context("Failed to commit profile activation")?;

        info!("Set active profile {} for case {}", profile_id, case_id);
        Ok(())
    }

    async fn delete_profile(&self, profile_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM ingestion_profiles WHERE id = ?")
            .bind(profile_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete profile")?;

        info!("Deleted profile {}", profile_id);
        Ok(())
    }

    async fn create_job(&self, job: &seance_core::profile::AdHocJob) -> Result<()> {
        sqlx::query(
            "INSERT INTO ad_hoc_jobs (id, case_id, module_id, target_artifact_id, status, artifacts_produced, error_message, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(job.id)
        .bind(job.case_id)
        .bind(&job.module_id)
        .bind(job.target_artifact_id)
        .bind(job.status.to_string())
        .bind(job.artifacts_produced as i64)
        .bind(&job.error_message)
        .bind(job.created_at)
        .bind(job.completed_at)
        .execute(&self.pool)
        .await
        .context("Failed to create ad-hoc job")?;

        debug!("Created ad-hoc job {}", job.id);
        Ok(())
    }

    async fn update_job(&self, job: &seance_core::profile::AdHocJob) -> Result<()> {
        let result = sqlx::query(
            "UPDATE ad_hoc_jobs SET status = ?, artifacts_produced = ?, error_message = ?, completed_at = ? WHERE id = ?",
        )
        .bind(job.status.to_string())
        .bind(job.artifacts_produced as i64)
        .bind(&job.error_message)
        .bind(job.completed_at)
        .bind(job.id)
        .execute(&self.pool)
        .await
        .context("Failed to update ad-hoc job")?;
        // An update that touched no row is a job that was never recorded: say so
        // rather than reporting a status the table does not hold.
        if result.rows_affected() == 0 {
            anyhow::bail!("Ad-hoc job {} not found", job.id);
        }

        debug!("Updated ad-hoc job {}", job.id);
        Ok(())
    }

    async fn get_job(&self, job_id: Uuid) -> Result<Option<seance_core::profile::AdHocJob>> {
        let row = sqlx::query(
            "SELECT id, case_id, module_id, target_artifact_id, status, artifacts_produced, error_message, created_at, completed_at FROM ad_hoc_jobs WHERE id = ?",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch ad-hoc job")?;

        row.as_ref().map(decode_job_row).transpose()
    }

    async fn mark_records_superseded(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
        field: &str,
        status: &str,
        by_artifact: Uuid,
    ) -> Result<u64> {
        SqliteConnection::mark_records_superseded(
            self,
            case_id,
            parent_id,
            record_type,
            field,
            status,
            by_artifact,
        )
        .await
    }

    async fn supersede_records_from_an_earlier_run(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        match_field: &str,
        match_value: &str,
        run_started_at: &str,
        by_artifact: Uuid,
        module_id: &str,
    ) -> Result<u64> {
        SqliteConnection::supersede_records_from_an_earlier_run(
            self,
            case_id,
            parent_id,
            match_field,
            match_value,
            run_started_at,
            by_artifact,
            module_id,
        )
        .await
    }

    async fn fail_interrupted_jobs(
        &self,
        created_at_or_before: i64,
        reason: &str,
    ) -> Result<Vec<seance_core::profile::AdHocJob>> {
        // Select and update under one immediate transaction so the set this
        // returns is exactly the set the UPDATE touched: a job that changes
        // status between the two statements is neither listed nor swept.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the interrupted-job sweep")?;
        let ids: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT id FROM ad_hoc_jobs \
             WHERE status IN ('pending', 'running') AND created_at <= ? \
             ORDER BY created_at ASC, id ASC",
        )
        .bind(created_at_or_before)
        .fetch_all(&mut *tx)
        .await
        .context("Failed to list interrupted ad-hoc jobs")?;
        if ids.is_empty() {
            tx.commit()
                .await
                .context("Failed to end the interrupted-job sweep")?;
            return Ok(Vec::new());
        }
        // `completed_at` is when the interruption was RECORDED, not when the
        // process stopped; nothing in the row knows the latter, and the reason
        // text says so to whoever reads it.
        let recorded_at = chrono::Utc::now().timestamp();
        for id in &ids {
            sqlx::query(
                "UPDATE ad_hoc_jobs SET status = 'failed', error_message = ?, completed_at = ? \
                 WHERE id = ? AND status IN ('pending', 'running')",
            )
            .bind(reason)
            .bind(recorded_at)
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to mark an interrupted ad-hoc job failed")?;
        }
        tx.commit()
            .await
            .context("Failed to commit the interrupted-job sweep")?;

        let mut jobs = Vec::with_capacity(ids.len());
        for id in ids {
            let id = Uuid::from_slice(&id).context("ad_hoc_jobs.id is not a UUID")?;
            if let Some(job) = self.get_job(id).await? {
                jobs.push(job);
            }
        }
        Ok(jobs)
    }

    async fn start_ingest_run(&self, run: &seance_core::profile::IngestRun) -> Result<()> {
        sqlx::query(
            "INSERT INTO ingest_runs (id, case_id, source_artifact_id, source_label, started_at, \
             finished_at, status, artifacts_recorded, detail) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(run.id.as_bytes().to_vec())
        .bind(run.case_id.as_bytes().to_vec())
        .bind(run.source_artifact_id.as_bytes().to_vec())
        .bind(&run.source_label)
        .bind(run.started_at)
        .bind(run.finished_at)
        .bind(&run.status)
        .bind(run.artifacts_recorded)
        .bind(&run.detail)
        .execute(&self.pool)
        .await
        .context("Failed to record the start of an ingest run")?;
        Ok(())
    }

    async fn finish_ingest_runs_for_case(
        &self,
        case_id: Uuid,
        status: &str,
        finished_at: i64,
    ) -> Result<Vec<seance_core::profile::IngestRun>> {
        // No count is stored here: the orchestrator closes a run when its
        // queue is idle, and the background artifact writer may still be
        // flushing that run's last rows. A count taken now would be low and
        // read as exact. `list_ingest_runs` counts a closed run's subtree at
        // read time instead; only an interrupted run stores its count, since
        // nothing writes under a killed process's source afterwards.
        let running = self
            .ingest_runs_where(case_id, "status = 'running'")
            .await?;
        let mut closed = Vec::with_capacity(running.len());
        for run in running {
            let changed = sqlx::query(
                "UPDATE ingest_runs SET status = ?, finished_at = ? \
                 WHERE id = ? AND status = 'running'",
            )
            .bind(status)
            .bind(finished_at)
            .bind(run.id.as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .context("Failed to close an ingest run")?
            .rows_affected();
            if changed == 1 {
                closed.push(seance_core::profile::IngestRun {
                    status: status.to_string(),
                    finished_at: Some(finished_at),
                    ..run
                });
            }
        }
        Ok(closed)
    }

    async fn mark_interrupted_ingest_runs(
        &self,
        started_before: i64,
        detail: &str,
    ) -> Result<Vec<seance_core::profile::IngestRun>> {
        // Same shape as the ad-hoc job sweep: select and update under one
        // immediate transaction so the rows returned are the rows marked.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the interrupted-ingest sweep")?;
        let rows = sqlx::query(
            "SELECT id, case_id, source_artifact_id, source_label, started_at, finished_at, \
             status, artifacts_recorded, detail FROM ingest_runs \
             WHERE status = 'running' AND started_at < ? ORDER BY started_at ASC, id ASC",
        )
        .bind(started_before)
        .fetch_all(&mut *tx)
        .await
        .context("Failed to list interrupted ingest runs")?;
        let mut runs = Vec::with_capacity(rows.len());
        for row in rows {
            runs.push(Self::ingest_run_from_row(&row)?);
        }
        if runs.is_empty() {
            tx.commit()
                .await
                .context("Failed to end the interrupted-ingest sweep")?;
            return Ok(runs);
        }
        // `finished_at` is when the interruption was RECORDED, not when the
        // process stopped; nothing in the row knows the latter, and the detail
        // says so to whoever reads it.
        let recorded_at = chrono::Utc::now().timestamp();
        for run in runs.iter_mut() {
            // What the walk had recorded before it stopped: the subtree as it
            // stands now, since nothing has written under it since.
            let cte = subtree_cte(run.case_id);
            let recorded: i64 =
                sqlx::query_scalar(&format!("{cte} SELECT MAX(COUNT(*) - 1, 0) FROM subtree"))
                    .bind(run.case_id.as_bytes().to_vec())
                    .bind(run.source_artifact_id.as_bytes().to_vec())
                    .fetch_one(&mut *tx)
                    .await
                    .context("Failed to count an interrupted ingest run's artifacts")?;
            sqlx::query(
                "UPDATE ingest_runs SET status = 'interrupted', finished_at = ?, \
                 artifacts_recorded = ?, detail = ? WHERE id = ? AND status = 'running'",
            )
            .bind(recorded_at)
            .bind(recorded)
            .bind(detail)
            .bind(run.id.as_bytes().to_vec())
            .execute(&mut *tx)
            .await
            .context("Failed to mark an ingest run interrupted")?;
            run.status = seance_core::profile::IngestRun::INTERRUPTED.to_string();
            run.finished_at = Some(recorded_at);
            run.artifacts_recorded = Some(recorded);
            run.detail = Some(detail.to_string());
        }
        tx.commit()
            .await
            .context("Failed to commit the interrupted-ingest sweep")?;
        Ok(runs)
    }

    async fn list_ingest_runs(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::profile::IngestRun>> {
        let mut runs = self.ingest_runs_where(case_id, "1 = 1").await?;
        for run in runs.iter_mut() {
            // A closed run's count is what its source holds now (see
            // `finish_ingest_runs_for_case`); a running one has no count yet.
            if run.artifacts_recorded.is_none()
                && run.status != seance_core::profile::IngestRun::RUNNING
            {
                run.artifacts_recorded =
                    Some(self.subtree_size(case_id, run.source_artifact_id).await?);
            }
        }
        Ok(runs)
    }

    async fn list_jobs(&self, case_id: Uuid) -> Result<Vec<seance_core::profile::AdHocJob>> {
        let rows = sqlx::query(
            "SELECT id, case_id, module_id, target_artifact_id, status, artifacts_produced, error_message, created_at, completed_at FROM ad_hoc_jobs WHERE case_id = ? ORDER BY created_at DESC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list ad-hoc jobs")?;

        rows.iter().map(decode_job_row).collect()
    }

    async fn record_processing_log(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        module_id: &str,
        status: &str,
        artifacts_produced: usize,
        error_message: Option<&str>,
        duration_ms: u64,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO processing_log (case_id, artifact_id, module_id, status, artifacts_produced, error_message, duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(case_id)
        .bind(artifact_id)
        .bind(module_id)
        .bind(status)
        .bind(artifacts_produced as i64)
        .bind(error_message)
        .bind(duration_ms as i64)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to record processing log")?;

        Ok(())
    }

    async fn record_processing_log_batch(
        &self,
        entries: &[seance_core::db::ProcessingLogRow],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let now = chrono::Utc::now().timestamp();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Multi-row INSERT with chunking (9 vars/row → 111 rows/chunk)
        const MAX_VARS: usize = 999;
        const VARS_PER_ROW: usize = 9;
        let chunk_size = MAX_VARS / VARS_PER_ROW;

        for chunk in entries.chunks(chunk_size) {
            let placeholders: Vec<String> = (0..chunk.len())
                .map(|_| "(?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string())
                .collect();
            let sql = format!(
                "INSERT INTO processing_log (case_id, artifact_id, module_id, status, artifacts_produced, error_message, duration_ms, created_at, zero_yield_modules) VALUES {}",
                placeholders.join(", ")
            );

            let mut query = sqlx::query(&sql);
            for entry in chunk {
                query = query
                    .bind(entry.case_id)
                    .bind(entry.artifact_id)
                    .bind(&entry.module_id)
                    .bind(&entry.status)
                    .bind(entry.artifacts_produced as i64)
                    .bind(entry.error_message.as_deref())
                    .bind(entry.duration_ms as i64)
                    .bind(now)
                    .bind(entry.zero_yield_json());
            }

            query
                .execute(&mut *tx)
                .await
                .context("Failed to record processing log batch")?;
        }

        tx.commit()
            .await
            .context("Failed to commit processing log batch")?;
        Ok(())
    }

    async fn get_processing_log_for_artifact(
        &self,
        artifact_id: Uuid,
        limit: Option<usize>,
    ) -> Result<Vec<seance_core::profile::ProcessingLogEntry>> {
        let limit_val = limit.unwrap_or(100) as i64;
        let rows = sqlx::query(&format!(
            "SELECT id, case_id, artifact_id, module_id, status, artifacts_produced, \
                 error_message, duration_ms, created_at FROM ({}) \
                 ORDER BY created_at DESC LIMIT ?",
            expanded_processing_log("artifact_id = ?")
        ))
        .bind(artifact_id)
        .bind(artifact_id)
        .bind(limit_val)
        .fetch_all(&self.pool)
        .await
        .context("Failed to get processing log for artifact")?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(seance_core::profile::ProcessingLogEntry {
                id: row.try_get("id")?,
                case_id: row.try_get::<Vec<u8>, _>("case_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                artifact_id: row.try_get::<Vec<u8>, _>("artifact_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                module_id: row.try_get("module_id")?,
                status: row.try_get("status")?,
                artifacts_produced: row.try_get::<i64, _>("artifacts_produced")? as usize,
                error_message: row.try_get("error_message")?,
                duration_ms: row.try_get::<i64, _>("duration_ms")? as u64,
                created_at: row.try_get("created_at")?,
            });
        }

        Ok(entries)
    }

    async fn count_processing_log_for_artifact(&self, artifact_id: Uuid) -> Result<usize> {
        // Count what the listing shows: one row per (artifact, module), not per
        // stored (possibly folded) row.
        let row = sqlx::query(&format!(
            "SELECT COUNT(*) as cnt FROM ({})",
            expanded_processing_log("artifact_id = ?")
        ))
        .bind(artifact_id)
        .bind(artifact_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count processing log for artifact")?;

        let count: i64 = row.try_get("cnt")?;
        Ok(count as usize)
    }

    /// Trait entry point for the case-wide processing-log aggregation; the
    /// implementation is the inherent method of the same name.
    async fn get_processing_log_for_case(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<(Vec<CaseProcessingLogEntry>, i64)> {
        SqliteConnection::get_processing_log_for_case(self, case_id, limit).await
    }

    async fn list_jobs_for_artifact(
        &self,
        artifact_id: Uuid,
    ) -> Result<Vec<seance_core::profile::AdHocJob>> {
        let rows = sqlx::query(
            "SELECT id, case_id, module_id, target_artifact_id, status, artifacts_produced, error_message, created_at, completed_at FROM ad_hoc_jobs WHERE target_artifact_id = ? ORDER BY created_at DESC",
        )
        .bind(artifact_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list jobs for artifact")?;

        rows.iter().map(decode_job_row).collect()
    }

    // Delegate to the inherent implementations below so callers holding a
    // `dyn DatabaseConnection` (e.g. the ingestion service) can record
    // integrity baselines and audit events.
    async fn record_integrity_check(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        computed_md5: Option<&str>,
        computed_sha1: Option<&str>,
        computed_sha256: Option<&str>,
        expected_md5: Option<&str>,
        expected_sha1: Option<&str>,
        expected_sha256: Option<&str>,
        status: &str,
        details: Option<&str>,
    ) -> Result<()> {
        SqliteConnection::record_integrity_check(
            self,
            case_id,
            artifact_id,
            computed_md5,
            computed_sha1,
            computed_sha256,
            expected_md5,
            expected_sha1,
            expected_sha256,
            status,
            details,
        )
        .await
    }

    async fn record_audit_event(
        &self,
        case_id: Option<Uuid>,
        user_id: &str,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        details: Option<&str>,
    ) -> Result<()> {
        SqliteConnection::record_audit_event(
            self,
            case_id,
            user_id,
            action,
            resource_type,
            resource_id,
            details,
        )
        .await
    }

    async fn merge_artifact_metadata(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        patch: &serde_json::Value,
    ) -> Result<u64> {
        SqliteConnection::merge_artifact_metadata(self, case_id, artifact_id, patch).await
    }

    async fn apply_file_hash(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        md5: &str,
        sha1: &str,
        sha256: &str,
    ) -> Result<u64> {
        SqliteConnection::apply_file_hash(self, case_id, artifact_id, md5, sha1, sha256).await
    }

    async fn apply_file_hashes_batch(
        &self,
        hashes: &[(Uuid, Uuid, String, String, String)],
    ) -> Result<Vec<Uuid>> {
        SqliteConnection::apply_file_hashes_batch(self, hashes).await
    }

    async fn mark_file_hashes_skipped_batch(
        &self,
        skips: &[(Uuid, Uuid, String)],
    ) -> Result<Vec<Uuid>> {
        SqliteConnection::mark_file_hashes_skipped_batch(self, skips).await
    }
}

// Additional SqliteConnection methods beyond the trait interface
impl SqliteConnection {
    /// Most distinct incompleteness reasons carried into one census. Far more
    /// than any real case produces; a case that exceeds it is disclosed through
    /// [`CaseIncompleteness::distinct_reasons`] rather than silently shortened.
    pub const INCOMPLETE_REASON_CAP: i64 = 50;

    /// Mark what an earlier run of `module_id` wrote under `parent_id` as
    /// superseded by this run. See the trait method for why.
    pub async fn supersede_records_from_an_earlier_run(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        match_field: &str,
        match_value: &str,
        run_started_at: &str,
        by_artifact: Uuid,
        module_id: &str,
    ) -> Result<u64> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE artifacts SET metadata_json = json_set( \
                 json_set( \
                     json_set( \
                         json_set(metadata_json, '$.superseded', json('true')), \
                         '$.superseded_by', ?), \
                     '$.superseded_at', ?), \
                 '$.superseded_reason', ?) \
             WHERE case_id = ? AND parent_id = ? AND id <> ? \
               AND created_at < ? \
               AND json_extract(metadata_json, '$' || '.' || ?) = ? \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1",
        )
        .bind(by_artifact.to_string())
        .bind(now)
        .bind(format!("{module_id} was run again on this artifact"))
        .bind(case_id.as_bytes().to_vec())
        .bind(parent_id.as_bytes().to_vec())
        .bind(by_artifact.as_bytes().to_vec())
        .bind(run_started_at.to_string())
        .bind(match_field)
        .bind(match_value)
        .execute(&self.pool)
        .await
        .context("Failed to mark an earlier run's records superseded")?;
        Ok(result.rows_affected())
    }

    /// Mark every record of `record_type` with `status` under `parent_id` as
    /// superseded by `by_artifact`.
    ///
    /// A record is **marked, never deleted**. What was true before a password
    /// worked — "this backup is encrypted and no files from it are in this
    /// case" — is itself evidence of the order events happened in, and a
    /// register that removed it would leave the case unable to show that the
    /// encrypted state was ever observed. What the mark changes is what reads
    /// it: the completeness census excludes a superseded record from the counts
    /// a report draws its "not recovered" section from, because the later
    /// record is the current statement (HUNT-090).
    ///
    /// Scoped to one parent, so a second backup in the same case — a second
    /// phone, a second extraction — is not answered by another's password. The
    /// superseding record is never marked by its own call.
    ///
    /// Returns how many records were marked.
    pub async fn mark_records_superseded(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
        field: &str,
        status: &str,
        by_artifact: Uuid,
    ) -> Result<u64> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE artifacts SET metadata_json = json_set( \
                 json_set( \
                     json_set(metadata_json, '$.superseded', json('true')), \
                     '$.superseded_by', ?), \
                 '$.superseded_at', ?) \
             WHERE case_id = ? AND parent_id = ? AND id <> ? \
               AND json_extract(metadata_json, '$.type') = ? \
               AND json_extract(metadata_json, '$' || '.' || ?) = ? \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1",
        )
        .bind(by_artifact.to_string())
        .bind(now)
        .bind(case_id.as_bytes().to_vec())
        .bind(parent_id.as_bytes().to_vec())
        .bind(by_artifact.as_bytes().to_vec())
        .bind(record_type)
        .bind(field)
        .bind(status)
        .execute(&self.pool)
        .await
        .context("Failed to mark records superseded")?;
        Ok(result.rows_affected())
    }

    /// Census of plugin-recorded incompleteness across a case.
    ///
    /// Plugins stamp `content_incomplete` (+ `content_incomplete_reason`) on an
    /// artifact whose bytes could not be read or decoded whole, and
    /// `inventory_incomplete` (+ `inventory_incomplete_reason`) on one whose
    /// listing is short of what the container holds. Both are written at ingest
    /// and, until this accessor existed, read by nothing: the examiner and the
    /// court saw a listing with no way to tell a truncated result from a
    /// complete one.
    ///
    /// BOTH reason keys are read. A short listing is the axis where "absence of
    /// evidence is not evidence of absence" bites hardest -- the examiner is
    /// looking at the very listing that is short -- so telling them the count
    /// without the recorded reason would leave them unable to tell an
    /// unresolved container structure from a decryption failure.
    ///
    /// A record a later one **supersedes** is excluded from every figure here,
    /// and counted separately as `superseded`. An encrypted iOS backup ingested
    /// without a password records that no files from it are in the case; when a
    /// password later opens it, that statement stops being true, and a census
    /// that kept counting it would put a backup this case holds 15,972
    /// artifacts from into the report's list of evidence that was NOT recovered
    /// (HUNT-090). The exclusion is never silent: the count is carried so the
    /// report can say how many earlier statements a later run answered.
    ///
    /// Fails closed: a query error propagates. An empty census must only ever
    /// mean "no artifact in this case is marked incomplete", never "the census
    /// could not be taken".
    ///
    /// Consumed by `seance_api::gather_report_data`, which carries it into
    /// [`seance_reporting::ReportData::incompleteness`] and into each
    /// per-category section of the exported HTML/PDF/XLSX report.
    pub async fn get_case_incompleteness(&self, case_id: Uuid) -> Result<CaseIncompleteness> {
        let case_bytes = case_id.as_bytes().to_vec();

        // json_extract yields SQLite 1/0 for JSON true/false. Comparing to 1
        // also matches a legacy string "true" only if it were stored as 1, so a
        // non-boolean value is treated as NOT set rather than guessed at.
        let content_incomplete: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND json_extract(metadata_json, '$.content_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count content-incomplete artifacts")?;

        let inventory_incomplete: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND json_extract(metadata_json, '$.inventory_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count inventory-incomplete artifacts")?;

        // Events kept as artifacts but absent from the timeline for want of a
        // usable timestamp (`record_artifacts_batch` writes the marker). Bounded
        // by the artifact_type filter; fails closed like the counts above.
        let timeline_omitted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'TimelineEvent' \
               AND json_extract(metadata_json, '$.timeline_omitted') IS NOT NULL \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count timeline events omitted from the timeline")?;

        // Counted, not just excluded. "We answered this earlier statement" is
        // itself a fact about the case, and a figure that silently shrank would
        // be indistinguishable from evidence that was never marked at all.
        let superseded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND json_extract(metadata_json, '$.superseded') = 1",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count superseded artifacts")?;

        // Distinct reasons, counted before the cap is applied, so the caller can
        // say how many it is NOT showing.
        let distinct_reasons: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ( \
                 SELECT DISTINCT json_extract(metadata_json, '$.content_incomplete_reason') AS r \
                 FROM artifacts \
                 WHERE case_id = ? AND json_extract(metadata_json, '$.content_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1 \
             )",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count distinct incompleteness reasons")?;

        let reason_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
            "SELECT json_extract(metadata_json, '$.content_incomplete_reason') AS reason, \
                    COUNT(*) AS n \
             FROM artifacts \
             WHERE case_id = ? AND json_extract(metadata_json, '$.content_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1 \
             GROUP BY reason ORDER BY n DESC, reason ASC LIMIT ?",
        )
        .bind(&case_bytes)
        .bind(Self::INCOMPLETE_REASON_CAP)
        .fetch_all(&self.pool)
        .await
        .context("Failed to group incompleteness reasons")?;

        let reasons = reason_rows
            .into_iter()
            .map(|(reason, count)| IncompleteReason { reason, count })
            .collect();

        // The same two queries against the inventory axis. 43 sites across the
        // plugin tree write `inventory_incomplete_reason`; reading only the
        // content reason would report "N artifacts carry a short listing" with
        // no way to tell WHY, in the one section whose whole purpose is that a
        // missing item may still exist in the evidence.
        let distinct_inventory_reasons: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ( \
                 SELECT DISTINCT json_extract(metadata_json, '$.inventory_incomplete_reason') AS r \
                 FROM artifacts \
                 WHERE case_id = ? AND json_extract(metadata_json, '$.inventory_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1 \
             )",
        )
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count distinct inventory-incompleteness reasons")?;

        let inventory_reason_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
            "SELECT json_extract(metadata_json, '$.inventory_incomplete_reason') AS reason, \
                    COUNT(*) AS n \
             FROM artifacts \
             WHERE case_id = ? AND json_extract(metadata_json, '$.inventory_incomplete') = 1 \
               AND COALESCE(json_extract(metadata_json, '$.superseded'), 0) <> 1 \
             GROUP BY reason ORDER BY n DESC, reason ASC LIMIT ?",
        )
        .bind(&case_bytes)
        .bind(Self::INCOMPLETE_REASON_CAP)
        .fetch_all(&self.pool)
        .await
        .context("Failed to group inventory-incompleteness reasons")?;

        let inventory_reasons = inventory_reason_rows
            .into_iter()
            .map(|(reason, count)| IncompleteReason { reason, count })
            .collect();

        // Per-section attribution. A report section is grouped by the timeline
        // `source_module` of the events an artifact produced, so the same join
        // is what lets a section say how many of ITS records came from an
        // incomplete read. An artifact with no timeline event contributes to the
        // case-level figures above but to no section, which is correct: it is
        // not listed in one.
        //
        // Both axes count. Attributing only `content_incomplete` meant a report
        // section built entirely from short LISTINGS -- a container whose
        // catalogue stopped early, an archive walked partway -- said "0
        // incomplete records" while the case-level figures counted every one of
        // them. The section is where an examiner reads the evidence; that is
        // where it has to say the listing is short.
        let module_counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT te.source_module AS source_module, \
                    COUNT(DISTINCT a.id) AS n \
             FROM artifacts a \
             JOIN timeline_events te ON te.artifact_id = a.id AND te.case_id = a.case_id \
             WHERE a.case_id = ? \
               AND (json_extract(a.metadata_json, '$.content_incomplete') = 1 \
                    OR json_extract(a.metadata_json, '$.inventory_incomplete') = 1) \
               AND COALESCE(json_extract(a.metadata_json, '$.superseded'), 0) <> 1 \
             GROUP BY source_module ORDER BY n DESC",
        )
        .bind(&case_bytes)
        .fetch_all(&self.pool)
        .await
        .context("Failed to count incompleteness by source module")?;

        let module_rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT te.source_module AS source_module, \
                    json_extract(a.metadata_json, '$.content_incomplete_reason') AS reason, \
                    COUNT(DISTINCT a.id) AS n \
             FROM artifacts a \
             JOIN timeline_events te ON te.artifact_id = a.id AND te.case_id = a.case_id \
             WHERE a.case_id = ? AND json_extract(a.metadata_json, '$.content_incomplete') = 1 \
               AND COALESCE(json_extract(a.metadata_json, '$.superseded'), 0) <> 1 \
             GROUP BY source_module, reason ORDER BY n DESC, reason ASC",
        )
        .bind(&case_bytes)
        .fetch_all(&self.pool)
        .await
        .context("Failed to group incompleteness by source module")?;

        let inventory_module_rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT te.source_module AS source_module, \
                    json_extract(a.metadata_json, '$.inventory_incomplete_reason') AS reason, \
                    COUNT(DISTINCT a.id) AS n \
             FROM artifacts a \
             JOIN timeline_events te ON te.artifact_id = a.id AND te.case_id = a.case_id \
             WHERE a.case_id = ? AND json_extract(a.metadata_json, '$.inventory_incomplete') = 1 \
               AND COALESCE(json_extract(a.metadata_json, '$.superseded'), 0) <> 1 \
             GROUP BY source_module, reason ORDER BY n DESC, reason ASC",
        )
        .bind(&case_bytes)
        .fetch_all(&self.pool)
        .await
        .context("Failed to group inventory incompleteness by source module")?;

        let mut by_source_module: std::collections::HashMap<String, ModuleIncompleteness> =
            std::collections::HashMap::new();
        // The distinct-artifact count comes from its own query: an artifact
        // marked on BOTH axes must be one incomplete record in the section, not
        // two.
        for (module, count) in module_counts {
            by_source_module.entry(module).or_default().artifacts = count;
        }
        for (module, reason, count) in module_rows {
            let entry = by_source_module.entry(module).or_default();
            entry.reasons.push(IncompleteReason { reason, count });
        }
        for (module, reason, count) in inventory_module_rows {
            let entry = by_source_module.entry(module).or_default();
            // Labelled, because "we could not read this file whole" and "this
            // listing is short of what the container holds" are different
            // claims with different follow-up.
            let reason = Some(match reason {
                Some(r) => format!("inventory: {r}"),
                None => "inventory: unspecified".to_string(),
            });
            entry.reasons.push(IncompleteReason { reason, count });
        }
        for entry in by_source_module.values_mut() {
            entry
                .reasons
                .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
        }

        Ok(CaseIncompleteness {
            content_incomplete,
            inventory_incomplete,
            reasons,
            distinct_reasons,
            inventory_reasons,
            distinct_inventory_reasons,
            by_source_module,
            superseded,
            timeline_omitted,
        })
    }

    /// Files in this case that were recovered by carving rather than read from
    /// a filesystem record.
    ///
    /// `seance_plugin_carver` is the only writer of `metadata.carved` and it
    /// always writes the JSON boolean `true`, so this is an exact count, not an
    /// estimate. The report's File Overview previously printed this figure as
    /// "not determined" on every case on the stated grounds that no query could
    /// answer it; it can, and a carved file is precisely the kind of recovery a
    /// court is told about.
    ///
    /// Counts FileEntry rows only, because the figure is printed beside
    /// `FileOverview::total_files`, which is itself a `FileEntry`-only count
    /// (`list_file_entries` scopes every query to `artifact_type = 'FileEntry'`).
    /// Any other artifact type that came to carry `metadata.carved` would be
    /// counted into a numerator whose denominator excludes it, and a ratio like
    /// that can be made to exceed 1.
    ///
    /// Fails closed: a query error propagates, so "could not count" can never
    /// render as a confident zero.
    pub async fn count_carved_files(&self, case_id: Uuid) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'FileEntry' \
               AND json_extract(metadata_json, '$.carved') = 1",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_one(&self.pool)
        .await
        .context("Failed to count carved files")
    }

    /// Distinct files in this case that are encrypted.
    ///
    /// Two independent conventions record encryption, and the count has to
    /// reconcile them or it is wrong in one direction or the other:
    ///
    /// * `metadata.encrypted = true` is stamped on the FILE artifact itself by
    ///   the filesystem readers (APFS, btrfs, ext4, f2fs) and by the iOS backup
    ///   reader. APFS also writes `encrypted: false`, so the predicate tests for
    ///   `= 1` and never for presence.
    /// * `metadata.is_encrypted = true` is stamped on a separate ASSESSMENT
    ///   record. `seance_plugin_file_analysis` writes one per detection with
    ///   `analysis_type = "encryption_detection"` and the examined file as its
    ///   parent; `seance_plugin_ios_backup` writes one for a whole backup it
    ///   could not open, which is a statement about that record's own subject,
    ///   not about a parent file.
    ///
    /// So an encryption_detection record is folded onto its parent (the file it
    /// is about) and every other marked artifact stands for itself, and the
    /// whole thing is a `UNION` of ids, which dedupes. A file that APFS marked
    /// encrypted AND that file-analysis then fingerprinted as BitLocker is one
    /// encrypted file, not two.
    ///
    /// What a wrong answer would look like: counting the detection records
    /// directly inflates the figure by one per detection on an already-marked
    /// file; counting only `encrypted` omits every file whose encryption was
    /// established by content analysis rather than by a filesystem flag —
    /// including the whole of a raw-image case, where no filesystem reader ever
    /// sets the flag.
    ///
    /// Only ids that ARE `FileEntry` rows of this case are counted, whichever
    /// branch produced them. The figure is printed beside
    /// `FileOverview::total_files`, and that denominator is a `FileEntry`-only
    /// count (`list_file_entries` scopes every query to
    /// `artifact_type = 'FileEntry'`), so a marker sitting on any other artifact
    /// type would be counted into a numerator whose denominator excludes it —
    /// "3 of 2 files encrypted" is not a figure a report can defend.
    ///
    /// What that excludes, and where it still reaches the examiner: an
    /// assessment record that is about ITSELF rather than about a file — the
    /// `seance_plugin_ios_backup` record for a whole backup it could not open —
    /// is not a file and is not counted here. It is not lost: that record
    /// carries the standard `content_incomplete`/`inventory_incomplete` pair, so
    /// the completeness census and the report's "not recovered" section both
    /// carry it. A detection record whose parent is missing, or whose parent is
    /// not a file entry, is excluded on the same grounds.
    ///
    /// Directory entries are INCLUDED when they carry the flag —
    /// `seance_plugin_ios_backup` stamps `encrypted` on its directory records
    /// as well as its file records. That matches `FileOverview::total_files`,
    /// which is also a count of every file entry including directories, so the
    /// two figures are comparable; excluding directories here would make
    /// "Encrypted" a fraction of a different denominator than the one printed
    /// beside it.
    ///
    /// Fails closed: a query error propagates, so "could not count" can never
    /// render as a confident zero.
    pub async fn count_encrypted_files(&self, case_id: Uuid) -> Result<i64> {
        let case_bytes = case_id.as_bytes().to_vec();
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM ( \
                 SELECT id AS fid FROM artifacts \
                  WHERE case_id = ? \
                    AND json_extract(metadata_json, '$.encrypted') = 1 \
                 UNION \
                 SELECT parent_id AS fid FROM artifacts \
                  WHERE case_id = ? \
                    AND parent_id IS NOT NULL \
                    AND json_extract(metadata_json, '$.is_encrypted') = 1 \
                    AND json_extract(metadata_json, '$.analysis_type') = 'encryption_detection' \
                 UNION \
                 SELECT id AS fid FROM artifacts \
                  WHERE case_id = ? \
                    AND json_extract(metadata_json, '$.is_encrypted') = 1 \
                    AND (json_extract(metadata_json, '$.analysis_type') IS NULL \
                         OR json_extract(metadata_json, '$.analysis_type') <> 'encryption_detection') \
             ) marked \
             JOIN artifacts f ON f.id = marked.fid \
              AND f.case_id = ? \
              AND f.artifact_type = 'FileEntry'",
        )
        .bind(&case_bytes)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count encrypted files")
    }

    /// How many processing-log ROWS this case holds, as stored.
    ///
    /// Deliberately the stored count, not the expanded one: this is what a
    /// case's footprint costs, and the gap between it and the number of module
    /// runs the log describes is the whole point of the folded shape
    /// (HUNT-074). Use [`Self::get_processing_log_for_case`] for what the log
    /// SAYS.
    pub async fn count_processing_log_rows(&self, case_id: Uuid) -> Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM processing_log WHERE case_id = ?")
            .bind(case_id.as_bytes().to_vec())
            .fetch_one(&self.pool)
            .await
            .context("Failed to count processing-log rows")
    }

    /// Case-scoped processing-log provenance, aggregated per (module, status).
    ///
    /// The raw `processing_log` table holds one row per artifact per module, so
    /// a real case carries millions. Listing the first N of those in a court
    /// report would render a fraction of the tool provenance as though it were
    /// the whole thing, which is why the report shipped with an empty section
    /// instead. Grouping is what makes the section complete: the number of
    /// distinct (module, status) pairs is bounded by the module count, so the
    /// answer fits and nothing is dropped.
    ///
    /// Returns `(groups, distinct_group_count)`. `groups` is capped at `limit`;
    /// when `distinct_group_count` exceeds `groups.len()` the caller MUST
    /// disclose the shortfall, the same way every other capped listing does.
    ///
    /// Also reachable through
    /// [`seance_core::db::DatabaseConnection::get_processing_log_for_case`],
    /// which this crate's trait impl delegates here.
    pub async fn get_processing_log_for_case(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<(Vec<CaseProcessingLogEntry>, i64)> {
        let case_bytes = case_id.as_bytes().to_vec();

        let expanded = expanded_processing_log("case_id = ?");
        let total_groups: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM (SELECT 1 FROM ({expanded}) GROUP BY module_id, status)"
        ))
        .bind(&case_bytes)
        .bind(&case_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count processing-log groups for case")?;

        #[derive(sqlx::FromRow)]
        struct Row {
            module_id: String,
            status: String,
            runs: i64,
            artifacts_produced: i64,
            duration_ms: Option<i64>,
            error_message: Option<String>,
            error_count: i64,
        }

        let rows = sqlx::query_as::<_, Row>(&format!(
            "SELECT module_id, status, \
                    COUNT(*) AS runs, \
                    SUM(artifacts_produced) AS artifacts_produced, \
                    SUM(duration_ms) AS duration_ms, \
                    MIN(error_message) AS error_message, \
                    SUM(CASE WHEN error_message IS NOT NULL AND error_message <> '' THEN 1 ELSE 0 END) AS error_count \
             FROM ({expanded}) \
             GROUP BY module_id, status \
             ORDER BY artifacts_produced DESC, module_id ASC, status ASC \
             LIMIT ?"
        ))
        .bind(&case_bytes)
        .bind(&case_bytes)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to aggregate processing log for case")?;

        Ok((
            rows.into_iter()
                .map(|r| CaseProcessingLogEntry {
                    module_id: r.module_id,
                    status: r.status,
                    runs: r.runs,
                    artifacts_produced: r.artifacts_produced,
                    duration_ms: r.duration_ms,
                    error_message: r.error_message,
                    error_count: r.error_count,
                })
                .collect(),
            total_groups,
        ))
    }

    /// One page of an artifact's direct children.
    ///
    /// Paged, not capped. FileEntries hang flat off their FileSystem artifact,
    /// so the children of a volume are every file on it; a bare cap would put
    /// the rest out of reach, which is worse than not disclosing them. Order is
    /// `(created_at, id)` — total, so a page boundary can neither repeat a row
    /// nor skip one.
    ///
    /// Rows that will not decode are counted into
    /// [`BoundedList::undecodable`] rather than failing the whole listing: one
    /// artifact with an unknown type used to 500 the entire tree, and a tree
    /// that cannot be opened at all discloses less than a tree that says how
    /// many of its nodes it could not read.
    pub async fn get_child_artifacts(
        &self,
        case_id: Uuid,
        parent_id: Option<Uuid>,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<seance_core::artifact::Artifact>> {
        let limit = clamp_page_size(limit, CHILD_ARTIFACT_PAGE_MAX);
        debug!(
            "get_child_artifacts: case_id={}, parent_id={:?}, limit={}, offset={}",
            case_id, parent_id, limit, offset
        );

        #[derive(sqlx::FromRow, Debug)]
        struct ArtifactRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            artifact_type: String,
            metadata_json: String,
        }

        let case_id_bytes = case_id.as_bytes().to_vec();
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let mut rows: Vec<ArtifactRow> = if let Some(p_id) = parent_id {
            let parent_id_bytes = p_id.as_bytes().to_vec();
            sqlx::query_as::<_, ArtifactRow>(
                "SELECT id, case_id, parent_id, artifact_type, metadata_json \
                 FROM artifacts WHERE case_id = ? AND parent_id = ? \
                 ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?",
            )
            .bind(&case_id_bytes)
            .bind(&parent_id_bytes)
            .bind(probe_limit(limit))
            .bind(offset_i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                debug!("SQL error fetching child artifacts: {:?}", e);
                anyhow::anyhow!("Failed to fetch child artifacts by parent ID: {}", e)
            })?
        } else {
            sqlx::query_as::<_, ArtifactRow>(
                "SELECT id, case_id, parent_id, artifact_type, metadata_json \
                 FROM artifacts WHERE case_id = ? AND parent_id IS NULL \
                 ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?",
            )
            .bind(&case_id_bytes)
            .bind(probe_limit(limit))
            .bind(offset_i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                debug!("SQL error fetching root artifacts: {:?}", e);
                anyhow::anyhow!("Failed to fetch root artifacts: {}", e)
            })?
        };

        // The probe row proves there is more; it is dropped before decoding so
        // it can never be returned nor counted as a decode loss.
        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let mut undecodable = 0usize;
        let mut result_artifacts = Vec::with_capacity(rows.len());
        for row in rows {
            let (Ok(id), Ok(cid)) = (Uuid::from_slice(&row.id), Uuid::from_slice(&row.case_id))
            else {
                undecodable += 1;
                continue;
            };
            let parent = match row.parent_id.as_ref().map(|b| Uuid::from_slice(b)) {
                None => None,
                Some(Ok(p)) => Some(p),
                Some(Err(_)) => {
                    undecodable += 1;
                    continue;
                }
            };
            let Ok(artifact_type) =
                seance_core::artifact::ArtifactType::from_str(&row.artifact_type)
            else {
                undecodable += 1;
                continue;
            };
            let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&row.metadata_json) else {
                undecodable += 1;
                continue;
            };
            result_artifacts.push(seance_core::artifact::Artifact {
                id,
                case_id: cid,
                parent_id: parent,
                artifact_type,
                data: None,
                metadata,
            });
        }

        if undecodable > 0 {
            warn!(
                "case {}: {} child row(s) under parent {:?} would not decode; the listing is \
                 short of the evidence and the caller must disclose it",
                case_id, undecodable, parent_id
            );
        }

        Ok(BoundedList {
            items: result_artifacts,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    /// The one direct child of `parent_id` that is a ParsedRecord of
    /// `record_type`, resolved in SQL.
    ///
    /// Exists because the alternative is loading every child to run a linear
    /// scan for one of them, and under a FileSystem artifact "every child" is
    /// every file on the volume. With [`Self::get_child_artifacts`] now paged,
    /// that scan would also have quietly stopped at the first page and reported
    /// the record absent.
    pub async fn find_child_artifact_by_record_type(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
    ) -> Result<Option<seance_core::artifact::Artifact>> {
        let row = sqlx::query(
            "SELECT id, case_id, parent_id, artifact_type, metadata_json FROM artifacts \
             WHERE case_id = ? AND parent_id = ? AND artifact_type = 'ParsedRecord' \
               AND json_extract(metadata_json, '$.type') = ? \
             ORDER BY created_at ASC, id ASC LIMIT 1",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(parent_id.as_bytes().to_vec())
        .bind(record_type)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to look up child artifact by record type")?;

        let Some(row) = row else {
            return Ok(None);
        };

        // A row that matched but will not decode is NOT "no such record": say
        // so rather than report the artifact absent.
        let id_bytes: Vec<u8> = row.try_get("id").context("Missing artifact ID")?;
        let case_bytes: Vec<u8> = row.try_get("case_id").context("Missing case ID")?;
        let parent_bytes: Option<Vec<u8>> = row.try_get("parent_id").ok().flatten();
        let type_str: String = row.try_get("artifact_type").context("Missing type")?;
        let meta_str: String = row.try_get("metadata_json").context("Missing metadata")?;

        Ok(Some(seance_core::artifact::Artifact {
            id: Uuid::from_slice(&id_bytes).context("Invalid UUID for artifact ID")?,
            case_id: Uuid::from_slice(&case_bytes).context("Invalid UUID for case ID")?,
            parent_id: parent_bytes
                .map(|b| Uuid::from_slice(&b).context("Invalid UUID for parent ID"))
                .transpose()?,
            artifact_type: seance_core::artifact::ArtifactType::from_str(&type_str)
                .context(format!("Unknown artifact type: {}", type_str))?,
            data: None,
            metadata: serde_json::from_str(&meta_str)
                .context("Failed to deserialize artifact metadata")?,
        }))
    }

    /// One page of a node's children for the evidence tree, each carrying its
    /// own child count.
    ///
    /// `child_count` is resolved in the same statement by a correlated
    /// subquery over `idx_artifacts_parent_id`. It used to be one
    /// `count_child_artifacts` round trip per row — an N+1 that made expanding
    /// a node cost a query per child, and that grew with the page size this
    /// change introduces. Folding it in here was cheaper than leaving it, and
    /// leaving it would have made the paged listing slower than the unpaged one
    /// it replaces.
    ///
    /// Ordering, paging and the undecodable-row contract are as
    /// [`Self::get_child_artifacts`].
    pub async fn get_child_artifacts_filtered(
        &self,
        case_id: Uuid,
        parent_id: Option<Uuid>,
        sources_only: bool,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<ChildArtifact>> {
        let limit = clamp_page_size(limit, CHILD_ARTIFACT_PAGE_MAX);
        debug!(
            "get_child_artifacts_filtered: case_id={}, parent_id={:?}, sources_only={}, \
             limit={}, offset={}",
            case_id, parent_id, sources_only, limit, offset
        );

        #[derive(sqlx::FromRow, Debug)]
        struct ArtifactRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            artifact_type: String,
            metadata_json: String,
            child_count: i64,
        }

        let case_id_bytes = case_id.as_bytes().to_vec();
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        // Build query with optional artifact type filtering
        let type_filter = if sources_only {
            " AND a.artifact_type IN ('Container', 'RawEvidence', 'Partition', 'FileSystem', 'SystemArtifact')"
        } else {
            ""
        };
        let columns = "a.id AS id, a.case_id AS case_id, a.parent_id AS parent_id, \
                       a.artifact_type AS artifact_type, a.metadata_json AS metadata_json, \
                       (SELECT COUNT(*) FROM artifacts c WHERE c.parent_id = a.id) AS child_count";

        let mut rows: Vec<ArtifactRow> = if let Some(p_id) = parent_id {
            let parent_id_bytes = p_id.as_bytes().to_vec();
            let query = format!(
                "SELECT {} FROM artifacts a WHERE a.case_id = ? AND a.parent_id = ?{} \
                 ORDER BY a.created_at ASC, a.id ASC LIMIT ? OFFSET ?",
                columns, type_filter
            );
            sqlx::query_as::<_, ArtifactRow>(&query)
                .bind(&case_id_bytes)
                .bind(&parent_id_bytes)
                .bind(probe_limit(limit))
                .bind(offset_i64)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    debug!("SQL error fetching child artifacts: {:?}", e);
                    anyhow::anyhow!("Failed to fetch child artifacts by parent ID: {}", e)
                })?
        } else {
            let query = format!(
                "SELECT {} FROM artifacts a WHERE a.case_id = ? AND a.parent_id IS NULL{} \
                 ORDER BY a.created_at ASC, a.id ASC LIMIT ? OFFSET ?",
                columns, type_filter
            );
            sqlx::query_as::<_, ArtifactRow>(&query)
                .bind(&case_id_bytes)
                .bind(probe_limit(limit))
                .bind(offset_i64)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    debug!("SQL error fetching root artifacts: {:?}", e);
                    anyhow::anyhow!("Failed to fetch root artifacts: {}", e)
                })?
        };

        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let mut undecodable = 0usize;
        let mut result_artifacts = Vec::with_capacity(rows.len());
        for row in rows {
            let (Ok(id), Ok(cid)) = (Uuid::from_slice(&row.id), Uuid::from_slice(&row.case_id))
            else {
                undecodable += 1;
                continue;
            };
            let parent = match row.parent_id.as_ref().map(|b| Uuid::from_slice(b)) {
                None => None,
                Some(Ok(p)) => Some(p),
                Some(Err(_)) => {
                    undecodable += 1;
                    continue;
                }
            };
            let Ok(artifact_type) =
                seance_core::artifact::ArtifactType::from_str(&row.artifact_type)
            else {
                undecodable += 1;
                continue;
            };
            let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&row.metadata_json) else {
                undecodable += 1;
                continue;
            };
            result_artifacts.push(ChildArtifact {
                artifact: seance_core::artifact::Artifact {
                    id,
                    case_id: cid,
                    parent_id: parent,
                    artifact_type,
                    data: None,
                    metadata,
                },
                child_count: row.child_count,
            });
        }

        if undecodable > 0 {
            warn!(
                "case {}: {} child row(s) under parent {:?} would not decode; the tree listing \
                 is short of the evidence and the caller must disclose it",
                case_id, undecodable, parent_id
            );
        }

        Ok(BoundedList {
            items: result_artifacts,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    pub async fn count_child_artifacts(&self, parent_id: Uuid) -> Result<i64> {
        let parent_id_bytes = parent_id.as_bytes().to_vec();

        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM artifacts WHERE parent_id = ?")
            .bind(&parent_id_bytes)
            .fetch_one(&self.pool)
            .await
            .context(format!(
                "Failed to count children for parent ID: {}",
                parent_id
            ))?;

        Ok(result.0)
    }

    /// One page of a case's ad-hoc jobs, newest first.
    ///
    /// The [`seance_core::db::DatabaseConnection::list_jobs`] trait method
    /// returns a bare `Vec` with no `LIMIT` at all, so a caller reading it
    /// cannot tell a complete job list from an out-of-memory-sized one. Every
    /// product path that shows jobs to a user must use this instead; the trait
    /// method stays only because the trait is declared in `seance_core`.
    ///
    /// Order is `(created_at DESC, id DESC)`: jobs queued in one action share a
    /// `created_at`, and an unbroken tie is not a page boundary.
    pub async fn list_jobs_page(
        &self,
        case_id: Uuid,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<seance_core::profile::AdHocJob>> {
        let limit = clamp_page_size(limit, JOB_PAGE_MAX);

        let mut rows = sqlx::query(
            "SELECT id, case_id, module_id, target_artifact_id, status, artifacts_produced, \
             error_message, created_at, completed_at FROM ad_hoc_jobs WHERE case_id = ? \
             ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        )
        .bind(case_id)
        .bind(probe_limit(limit))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("Failed to list ad-hoc jobs")?;

        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let mut undecodable = 0usize;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            // A row that will not decode is counted, never defaulted: an
            // unknown status invents an outcome no module reported, a zero
            // `artifacts_produced` or a 1970 `created_at` a fact the evidence
            // never stated.
            match decode_job_row(&row) {
                Ok(job) => jobs.push(job),
                Err(_) => undecodable += 1,
            }
        }

        if undecodable > 0 {
            warn!(
                "case {}: {} ad-hoc job row(s) would not decode; the job list is short and the \
                 caller must disclose it rather than show it as the whole run history",
                case_id, undecodable
            );
        }

        Ok(BoundedList {
            items: jobs,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    /// One page of an artifact's processing history, newest first.
    ///
    /// The [`seance_core::db::DatabaseConnection::get_processing_log_for_artifact`]
    /// trait method takes a limit but returns a bare `Vec`, so clamping that
    /// limit — which the API already does — turns an over-large request into a
    /// silent truncation. This returns the same rows with the two facts that
    /// make the truncation visible.
    ///
    /// Order is `(created_at DESC, id DESC)`: a module run writes several log
    /// rows in the same second.
    pub async fn get_processing_log_for_artifact_page(
        &self,
        artifact_id: Uuid,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<seance_core::profile::ProcessingLogEntry>> {
        let limit = clamp_page_size(limit, PROCESSING_LOG_PAGE_MAX);

        let expanded = expanded_processing_log("artifact_id = ?");
        let mut rows = sqlx::query(&format!(
            "SELECT id, case_id, artifact_id, module_id, status, artifacts_produced, \
             error_message, duration_ms, created_at FROM ({expanded}) \
             ORDER BY created_at DESC, id DESC, seq ASC LIMIT ? OFFSET ?"
        ))
        .bind(artifact_id)
        .bind(artifact_id)
        .bind(probe_limit(limit))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("Failed to get processing log for artifact")?;

        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let mut undecodable = 0usize;
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let (Ok(case_bytes), Ok(artifact_bytes)) = (
                row.try_get::<Vec<u8>, _>("case_id"),
                row.try_get::<Vec<u8>, _>("artifact_id"),
            ) else {
                undecodable += 1;
                continue;
            };
            let (Ok(case_id), Ok(aid)) = (
                Uuid::from_slice(&case_bytes),
                Uuid::from_slice(&artifact_bytes),
            ) else {
                undecodable += 1;
                continue;
            };
            // Defaulting any of these would state a duration, a produced count
            // or a run time the log never recorded.
            let (Ok(id), Ok(module_id), Ok(status)) = (
                row.try_get::<i64, _>("id"),
                row.try_get::<String, _>("module_id"),
                row.try_get::<String, _>("status"),
            ) else {
                undecodable += 1;
                continue;
            };
            let (Ok(produced), Ok(duration_ms), Ok(created_at), Ok(err)) = (
                row.try_get::<i64, _>("artifacts_produced"),
                row.try_get::<i64, _>("duration_ms"),
                row.try_get::<i64, _>("created_at"),
                row.try_get::<Option<String>, _>("error_message"),
            ) else {
                undecodable += 1;
                continue;
            };

            entries.push(seance_core::profile::ProcessingLogEntry {
                id,
                case_id,
                artifact_id: aid,
                module_id,
                status,
                artifacts_produced: produced.max(0) as usize,
                error_message: err,
                duration_ms: duration_ms.max(0) as u64,
                created_at,
            });
        }

        if undecodable > 0 {
            warn!(
                "artifact {}: {} processing-log row(s) would not decode; the module history is \
                 short and must not read as 'no module did this'",
                artifact_id, undecodable
            );
        }

        Ok(BoundedList {
            items: entries,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    pub async fn get_artifact_details(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<seance_core::artifact::Artifact> {
        #[derive(sqlx::FromRow, Debug)]
        struct ArtifactRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            artifact_type: String,
            metadata_json: String,
        }

        let artifact_id_bytes = artifact_id.as_bytes().to_vec();
        let case_id_bytes = case_id.as_bytes().to_vec();

        let row: ArtifactRow = sqlx::query_as::<_, ArtifactRow>(
            "SELECT id, case_id, parent_id, artifact_type, metadata_json FROM artifacts WHERE id = ? AND case_id = ?"
        )
        .bind(&artifact_id_bytes)
        .bind(&case_id_bytes)
        .fetch_one(&self.pool)
        .await
        .context(format!("Failed to fetch artifact details for ID: {}", artifact_id))?;

        let artifact = seance_core::artifact::Artifact {
            id: Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID")?,
            case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
            parent_id: row
                .parent_id
                .map(|bytes| Uuid::from_slice(&bytes).context("Invalid UUID for parent ID"))
                .transpose()?,
            artifact_type: seance_core::artifact::ArtifactType::from_str(&row.artifact_type)
                .context(format!("Unknown artifact type: {}", row.artifact_type))?,
            data: None,
            metadata: serde_json::from_str(&row.metadata_json)
                .context("Failed to deserialize artifact metadata")?,
        };

        Ok(artifact)
    }

    /// For each artifact id, its record `type` (from metadata) and coarse
    /// `artifact_type`, so a pivot can group a set of hits by what kind of
    /// record each is. Ids not in the case are simply absent from the result;
    /// the map is keyed by id. Chunked so the `IN (...)` list never grows past
    /// SQLite's bound-parameter ceiling.
    ///
    /// The record type is `metadata_json.$.type` where a record sets one (e.g.
    /// `NetworkFlow`, `DnsResolution`, `NtfsIndexEntry`); a `FileEntry` and the
    /// other coarse kinds have no `$.type`, so the coarse `artifact_type` is
    /// returned for them. The pivot reads "5 network flows, 2 DNS resolutions,
    /// 1 file" off exactly this.
    pub async fn record_kinds_for_ids(
        &self,
        case_id: Uuid,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, String>> {
        use std::collections::HashMap;
        let mut out: HashMap<Uuid, String> = HashMap::new();
        if ids.is_empty() {
            return Ok(out);
        }
        let case_id_bytes = case_id.as_bytes().to_vec();
        // 900 leaves headroom under SQLite's default 999-variable limit for
        // the trailing case_id bind.
        for chunk in ids.chunks(900) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT id, COALESCE(json_extract(metadata_json, '$.type'), artifact_type) AS kind \
                 FROM artifacts WHERE case_id = ? AND id IN ({placeholders})"
            );
            let mut query = sqlx::query_as::<_, (Vec<u8>, String)>(&sql).bind(&case_id_bytes);
            for id in chunk {
                query = query.bind(id.as_bytes().to_vec());
            }
            let rows = query
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch record kinds for pivot")?;
            for (id_bytes, kind) in rows {
                if let Ok(id) = Uuid::from_slice(&id_bytes) {
                    out.insert(id, kind);
                }
            }
        }
        Ok(out)
    }

    /// Origin metadata of a named backup container — an iOS-backup file that in
    /// turn holds nested files (e.g. a WhatsApp media `.zip`). Lets a nested
    /// artifact be attributed to the app and correspondent it came from, since
    /// the `domain`/`relative_path` live on the container, not the inner file.
    /// Returns the container's full metadata when a same-named artifact carrying
    /// a backup `domain` exists in the case, `None` when there is none.
    ///
    /// The lookup is by NAME, so it can only be trusted when the name pins one
    /// origin. Two backups in one case that each hold a `WhatsApp media.zip`
    /// would otherwise attribute whichever row SQLite visited first to the other
    /// backup's file. So every candidate is read, in id order, and when they
    /// disagree on the provenance fields (`domain`, `relative_path`, `birth`,
    /// `modified`) this is an **error naming the ambiguity**, never a guess and
    /// never `None`: "no origin" and "could not tell which origin" are different
    /// statements. Metadata that cannot be decoded is an error for the same
    /// reason. A caller that only wants the provenance block may treat `Err` as
    /// "attach none", but should log it.
    pub async fn find_backup_container_origin(
        &self,
        case_id: Uuid,
        name: &str,
    ) -> Result<Option<serde_json::Value>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT metadata_json FROM artifacts \
             WHERE case_id = ? \
               AND json_extract(metadata_json,'$.name') = ? \
               AND json_extract(metadata_json,'$.domain') IS NOT NULL \
             ORDER BY id",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .context("Failed to look up backup container origin")?;

        let mut first: Option<serde_json::Value> = None;
        for (mj,) in rows {
            let candidate: serde_json::Value = serde_json::from_str(&mj)
                .with_context(|| format!("Backup container '{name}' has undecodable metadata"))?;
            match &first {
                None => first = Some(candidate),
                Some(f) => {
                    let key = |v: &serde_json::Value| {
                        ["domain", "relative_path", "birth", "modified"].map(|k| v.get(k).cloned())
                    };
                    anyhow::ensure!(
                        key(f) == key(&candidate),
                        "More than one backup container named '{name}' with different origins \
                         exists in this case; its origin cannot be told from the name alone"
                    );
                }
            }
        }
        Ok(first)
    }

    pub async fn list_cases(&self) -> Result<Vec<seance_core::models::CaseResponse>> {
        #[derive(sqlx::FromRow, Debug)]
        struct CaseRow {
            id: Vec<u8>,
            name: String,
            status: String,
            reference_number: Option<String>,
            examiner_name: Option<String>,
            created_at: String,
            last_accessed_at: Option<String>,
        }

        // A case being deleted is not listed: what remains of it is not a
        // case, and the mark is what keeps that so (HUNT-072).
        let rows: Vec<CaseRow> = sqlx::query_as::<_, CaseRow>(
            "SELECT id, name, status, reference_number, examiner_name, created_at, last_accessed_at FROM cases WHERE status <> 'deleting' ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch cases from database")?;

        let mut result_cases = Vec::with_capacity(rows.len());
        for row in rows {
            result_cases.push(seance_core::models::CaseResponse {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for case ID")?,
                name: row.name,
                status: row.status,
                reference_number: row.reference_number,
                examiner_name: row.examiner_name,
                created_at: row.created_at,
                last_accessed_at: row.last_accessed_at,
            });
        }
        Ok(result_cases)
    }

    pub async fn search_cases(
        &self,
        query: Option<&str>,
        status: Option<&str>,
        sort_by: Option<&str>,
    ) -> Result<Vec<seance_core::models::CaseResponse>> {
        #[derive(sqlx::FromRow, Debug)]
        struct CaseRow {
            id: Vec<u8>,
            name: String,
            status: String,
            reference_number: Option<String>,
            examiner_name: Option<String>,
            created_at: String,
            last_accessed_at: Option<String>,
        }

        // Build dynamic SQL query
        let mut sql = String::from("SELECT id, name, status, reference_number, examiner_name, created_at, last_accessed_at FROM cases WHERE status <> 'deleting'");

        let search_query = query.filter(|q| !q.is_empty());
        let status_filter = status.filter(|s| !s.is_empty());

        // Add search filter. Escape LIKE metacharacters so `_`/`%` in the term
        // match literally instead of as wildcards.
        if search_query.is_some() {
            sql.push_str(" AND (name LIKE ? ESCAPE '\\' OR reference_number LIKE ? ESCAPE '\\' OR examiner_name LIKE ? ESCAPE '\\')");
        }

        // Add status filter
        if status_filter.is_some() {
            sql.push_str(" AND status = ?");
        }

        // Add sorting
        let order_clause = match sort_by {
            Some("created_asc") => " ORDER BY created_at ASC",
            Some("created_desc") => " ORDER BY created_at DESC",
            Some("accessed_desc") => " ORDER BY last_accessed_at DESC",
            Some("name_asc") => " ORDER BY name ASC",
            Some("name_desc") => " ORDER BY name DESC",
            _ => " ORDER BY created_at DESC",
        };
        sql.push_str(order_clause);

        // Build query with parameters
        let mut query_builder = sqlx::query_as::<_, CaseRow>(&sql);

        // Bind search parameters
        if let Some(q) = search_query {
            let search_pattern = format!("%{}%", escape_like(q));
            query_builder = query_builder
                .bind(search_pattern.clone())
                .bind(search_pattern.clone())
                .bind(search_pattern);
        }

        // Bind status parameter
        if let Some(s) = status_filter {
            query_builder = query_builder.bind(s);
        }

        let rows: Vec<CaseRow> = query_builder
            .fetch_all(&self.pool)
            .await
            .context("Failed to search cases in database")?;

        let mut result_cases = Vec::with_capacity(rows.len());
        for row in rows {
            let id = Uuid::from_slice(&row.id).context("Invalid UUID in database")?;
            result_cases.push(seance_core::models::CaseResponse {
                id,
                name: row.name,
                status: row.status,
                reference_number: row.reference_number,
                examiner_name: row.examiner_name,
                created_at: row.created_at,
                last_accessed_at: row.last_accessed_at,
            });
        }

        Ok(result_cases)
    }

    pub async fn count_active_cases(&self) -> Result<i64> {
        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cases WHERE status = 'active'")
            .fetch_one(&self.pool)
            .await
            .context("Failed to count active cases")?;
        Ok(result.0)
    }

    pub async fn count_total_artifacts(&self, case_id: Uuid) -> Result<i64> {
        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM artifacts WHERE case_id = ?")
            .bind(case_id)
            .fetch_one(&self.pool)
            .await
            .context(format!(
                "Failed to count total artifacts for case ID: {}",
                case_id
            ))?;
        Ok(result.0)
    }

    /// One page of a case's artifacts, walked by id.
    ///
    /// Keyset rather than `OFFSET`: this exists to be called repeatedly over a
    /// whole case, and the case that motivated it holds 580,394 artifacts
    /// (`LIVE-028`). `OFFSET n` makes the database walk and discard `n` rows on
    /// every page, so a full sweep of a case costs the square of its size; a
    /// walk by primary key costs the case.
    ///
    /// `after` is the last id of the previous page — pass `None` for the first.
    /// Rows come back in `id` order, which is arbitrary but total and stable,
    /// which is all a sweep needs.
    ///
    /// The artifacts carry **no data source**, like every other artifact loaded
    /// from the database: `data: None`. A caller that re-indexes these is
    /// indexing metadata, not the text extracted from a file's bytes at ingest,
    /// and must say so (`B5-001`).
    pub async fn artifacts_page_after(
        &self,
        case_id: Uuid,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<Artifact>> {
        let limit = limit.clamp(1, 10_000);
        let rows = match after {
            Some(after) => sqlx::query(
                "SELECT id, case_id, parent_id, artifact_type, metadata_json \
                     FROM artifacts WHERE case_id = ? AND id > ? ORDER BY id ASC LIMIT ?",
            )
            .bind(case_id)
            .bind(after)
            .bind(limit),
            None => sqlx::query(
                "SELECT id, case_id, parent_id, artifact_type, metadata_json \
                     FROM artifacts WHERE case_id = ? ORDER BY id ASC LIMIT ?",
            )
            .bind(case_id)
            .bind(limit),
        }
        .fetch_all(&self.pool)
        .await
        .context("Failed to page a case's artifacts")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(Artifact {
                id: row.try_get::<Vec<u8>, _>("id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                case_id: row.try_get::<Vec<u8>, _>("case_id").and_then(|bytes| {
                    Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                parent_id: row
                    .try_get::<Option<Vec<u8>>, _>("parent_id")?
                    .map(|bytes| {
                        Uuid::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(Box::new(e)))
                    })
                    .transpose()?,
                // A row whose type this build does not know stops the page
                // rather than being silently retyped: a sweep that reindexed it
                // as something else would put a wrong type in the index, and
                // the index is what a search result's filters read.
                artifact_type: seance_core::artifact::ArtifactType::from_str(
                    &row.try_get::<String, _>("artifact_type")?,
                )
                .context("Unknown artifact type")?,
                data: None,
                metadata: serde_json::from_str(&row.try_get::<String, _>("metadata_json")?)
                    .context("Failed to deserialize metadata")?,
            });
        }
        Ok(out)
    }

    /// The examiner and handling detail a court-standard report needs.
    ///
    /// Kept separate from [`Db::get_case`] rather than widened into
    /// `CaseResponse`: these fields exist for one consumer, the report builder,
    /// and every other caller of `get_case` -- the case list, the case picker,
    /// the frontend -- would otherwise carry five columns it never reads.
    ///
    /// Every field is optional and stays `None` when never recorded, which is
    /// what lets a report omit them rather than assert a default. A stated
    /// qualification the examiner does not hold is worse than a missing one.
    pub async fn get_case_examiner_details(
        &self,
        case_id: Uuid,
    ) -> Result<seance_core::models::CaseExaminerDetails> {
        #[derive(sqlx::FromRow, Debug)]
        struct Row {
            examiner_role: Option<String>,
            examiner_organisation: Option<String>,
            examiner_contact: Option<String>,
            examiner_qualifications: Option<String>,
            report_classification: Option<String>,
        }

        let row: Row = sqlx::query_as::<_, Row>(
            "SELECT examiner_role, examiner_organisation, examiner_contact, \
                    examiner_qualifications, report_classification \
             FROM cases WHERE id = ?",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch case examiner details")?;

        // Whitespace-only is treated as absent: a field someone tabbed through
        // and left blank is not a recorded fact, and rendering it would put an
        // empty "Qualifications:" line in a court document.
        let clean = |v: Option<String>| v.filter(|s| !s.trim().is_empty());

        Ok(seance_core::models::CaseExaminerDetails {
            role: clean(row.examiner_role),
            organisation: clean(row.examiner_organisation),
            contact: clean(row.examiner_contact),
            qualifications: clean(row.examiner_qualifications),
            report_classification: clean(row.report_classification),
        })
    }

    pub async fn get_case(&self, case_id: Uuid) -> Result<seance_core::models::CaseResponse> {
        #[derive(sqlx::FromRow, Debug)]
        struct CaseRow {
            id: Vec<u8>,
            name: String,
            status: String,
            reference_number: Option<String>,
            examiner_name: Option<String>,
            created_at: String,
            last_accessed_at: Option<String>, // Correctly map this field
        }

        // Note the access, then fetch the row. The note is a write, and a
        // write waits on SQLite's single writer: under a running ingest that
        // wait ran to the 30-second busy timeout and failed, and because the
        // failure was propagated the READ failed with it — `GET /cases/{id}`
        // returned 500 and the UI told the examiner the case "may have been
        // deleted" while the ingest was writing to it (HUNT-078). A read must
        // not depend on a bookkeeping write: the note is best-effort, and the
        // fetch below runs whether or not it landed.
        let now = Utc::now().to_rfc3339();
        if let Err(e) = sqlx::query("UPDATE cases SET last_accessed_at = ? WHERE id = ?")
            .bind(&now)
            .bind(case_id)
            .execute(&self.pool)
            .await
        {
            warn!(
                "Could not note the access to case {} (the read continues): {}",
                case_id, e
            );
        }

        let row: CaseRow = sqlx::query_as::<_, CaseRow>(
            "SELECT id, name, status, reference_number, examiner_name, created_at, last_accessed_at FROM cases WHERE id = ?"
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await
        .context(format!("Failed to fetch case with ID: {}", case_id))?;

        Ok(seance_core::models::CaseResponse {
            id: Uuid::from_slice(&row.id).context("Invalid UUID for case ID")?,
            name: row.name,
            status: row.status,
            reference_number: row.reference_number,
            examiner_name: row.examiner_name,
            created_at: row.created_at,
            last_accessed_at: row.last_accessed_at,
        })
    }

    /// Apply the fields a request actually set, leaving the rest untouched.
    ///
    /// Takes the request rather than a positional list of `Option<String>`.
    /// There are now nine updatable text columns, and nine same-typed
    /// positional arguments is a signature where transposing two of them
    /// compiles cleanly and silently writes an examiner's contact details into
    /// the qualifications field of a court report.
    ///
    /// # Safety of the dynamic SQL
    ///
    /// The statement is built at runtime but is not injectable: column names
    /// come from the hardcoded table below and never from input, placeholders
    /// are numeric, and every value is bound.
    pub async fn update_case(
        &self,
        case_id: Uuid,
        request: &seance_core::models::UpdateCaseRequest,
    ) -> Result<()> {
        // (column, value) in binding order. Adding a column here is the whole
        // change needed to make it updatable.
        let fields: [(&str, &Option<String>); 8] = [
            ("name", &request.name),
            ("reference_number", &request.reference_number),
            ("examiner_name", &request.examiner_name),
            ("examiner_role", &request.examiner_role),
            ("examiner_organisation", &request.examiner_organisation),
            ("examiner_contact", &request.examiner_contact),
            ("examiner_qualifications", &request.examiner_qualifications),
            ("report_classification", &request.report_classification),
        ];

        let set: Vec<String> = fields
            .iter()
            .filter(|(_, value)| value.is_some())
            .enumerate()
            .map(|(i, (column, _))| format!("{column} = ?{}", i + 1))
            .collect();

        if set.is_empty() {
            return Ok(()); // Nothing to update
        }

        let sql = format!(
            "UPDATE cases SET {} WHERE id = ?{}",
            set.join(", "),
            set.len() + 1
        );
        let mut query = sqlx::query(&sql);
        for (_, value) in fields.iter().filter(|(_, v)| v.is_some()) {
            query = query.bind((*value).clone().expect("filtered to Some"));
        }
        query = query.bind(case_id);

        query
            .execute(&self.pool)
            .await
            .context(format!("Failed to update case with ID: {}", case_id))?;

        info!("Updated case: {}", case_id);
        Ok(())
    }

    /// Mark a case as being deleted. From this moment it is absent from every
    /// listing and [`case_status`](Self::case_status) answers `deleting`, so
    /// the rows [`delete_case`](Self::delete_case) has not yet reached are
    /// never shown as a live case. An unknown case is an error.
    pub async fn mark_case_deleting(&self, case_id: Uuid) -> Result<()> {
        let result = sqlx::query("UPDATE cases SET status = 'deleting' WHERE id = ?")
            .bind(case_id)
            .execute(&self.pool)
            .await
            .context("Failed to mark case as deleting")?;
        if result.rows_affected() == 0 {
            anyhow::bail!("Case {} not found", case_id);
        }
        Ok(())
    }

    /// The case's status column, or `None` when no such case exists. One
    /// primary-key lookup; it does not touch `last_accessed_at`.
    pub async fn case_status(&self, case_id: Uuid) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT status FROM cases WHERE id = ?")
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to read case status")
    }

    /// Cases whose deletion was started and not finished — after a crash or
    /// restart mid-delete, these are resumed rather than left half-gone.
    pub async fn cases_pending_deletion(&self) -> Result<Vec<Uuid>> {
        let rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT id FROM cases WHERE status = 'deleting' ORDER BY created_at")
                .fetch_all(&self.pool)
                .await
                .context("Failed to list cases pending deletion")?;
        rows.into_iter()
            .map(|(id,)| Uuid::from_slice(&id).context("Invalid UUID for case ID"))
            .collect()
    }

    /// Delete one batch of rows from `table` for the case; the number removed.
    async fn delete_case_rows_batch(&self, table: &str, case_id: Uuid) -> Result<u64> {
        // `table` is one of the literals in `delete_case`, never user input.
        let sql = format!(
            "DELETE FROM {table} WHERE rowid IN \
             (SELECT rowid FROM {table} WHERE case_id = ? LIMIT {DELETE_BATCH_ROWS})"
        );
        let result = sqlx::query(&sql)
            .bind(case_id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("Failed to delete {table} rows for case"))?;
        Ok(result.rows_affected())
    }

    /// Move what the WAL holds back into the database file.
    ///
    /// `PASSIVE` does as much as it can without waiting for readers and is a
    /// no-op when one is mid-snapshot; `TRUNCATE` also resets the WAL file to
    /// zero length, and may return busy instead. Either way a checkpoint that
    /// does not happen is not an error the caller should fail on — the next
    /// one picks up the work — so this logs and returns.
    async fn checkpoint_wal(&self, mode: &str) {
        if let Err(e) = sqlx::query(&format!("PRAGMA wal_checkpoint({mode})"))
            .execute(&self.pool)
            .await
        {
            debug!("WAL checkpoint ({mode}) did not run: {e}");
        }
    }

    /// Move everything the write-ahead log holds back into the database file
    /// and reset the log to zero length.
    ///
    /// Called when the server is stopping. What the WAL still holds is the next
    /// start's problem: recovering a large one runs before any connection
    /// opens, and a 45 GB log timed the pool out entirely (HUNT-088).
    pub async fn truncate_wal(&self) {
        self.checkpoint_wal("TRUNCATE").await;
    }

    /// Remove a case and every row that belongs to it.
    ///
    /// The case is first marked `deleting` (see
    /// [`mark_case_deleting`](Self::mark_case_deleting)), then its bulk
    /// tables are emptied in batches of [`DELETE_BATCH_ROWS`], each its own
    /// short write, and the `cases` row goes last. This used to be one
    /// transaction over every row: on a 3.2-million-artifact case with 85
    /// million processing-log rows that ran past the request timeout, was
    /// rolled back, and left the case live with its search index already
    /// purged (HUNT-072). Batches let readers through and mean an interrupted
    /// delete resumes from where it stopped instead of starting over — the
    /// `deleting` mark is what makes the partial state safe to leave.
    ///
    /// Batches alone do not keep the WAL small, which this comment used to
    /// claim: nothing checkpoints while a purge and an ingest keep the
    /// database busy, so on a 72-million-row purge the WAL grew to 45 GB
    /// beside a 46 GB database and the next start timed out trying to recover
    /// it (HUNT-088). The purge therefore checkpoints as it goes — passively,
    /// every [`DELETE_CHECKPOINT_EVERY`] batches, so it never waits on a
    /// reader — and truncates the WAL once the case is gone.
    ///
    /// Child-table coverage:
    /// - timeline_events and artifacts declare plain FKs (no cascade), so
    ///   they are deleted explicitly, in FK-dependency order. processing_log
    ///   and integrity_checks cascade, but on a large case they are the bulk
    ///   of the rows, so they are batched here rather than left to one
    ///   cascading statement.
    /// - timeline_tags, ingestion_profiles, ad_hoc_jobs, virtual_columns,
    ///   bookmark_categories, artifact_bookmarks, hash_sets (and via it
    ///   hash_set_entries), filters and the rest declare FOREIGN KEY
    ///   (case_id) REFERENCES cases(id) ON DELETE CASCADE, so deleting the
    ///   cases row removes them (foreign_keys is enabled on every pooled
    ///   connection).
    /// - audit_log is deliberately RETAINED: its FK is ON DELETE SET NULL,
    ///   so audit rows survive case deletion (with case_id nulled). The
    ///   audit trail of a deleted case is evidence in itself.
    pub async fn delete_case(&self, case_id: Uuid) -> Result<()> {
        self.mark_case_deleting(case_id).await?;

        for table in [
            "processing_log",
            "integrity_checks",
            "timeline_events",
            "artifacts",
        ] {
            let mut removed: u64 = 0;
            let mut attempt: u32 = 0;
            let mut batches: u64 = 0;
            loop {
                let n = match self.delete_case_rows_batch(table, case_id).await {
                    Ok(n) => n,
                    Err(e) if attempt < DELETE_BATCH_RETRIES => {
                        attempt += 1;
                        warn!(
                            "Deleting case {}: {} batch failed (attempt {} of {}), retrying: {:#}",
                            case_id, table, attempt, DELETE_BATCH_RETRIES, e
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(
                            250u64 << attempt.min(6),
                        ))
                        .await;
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    break;
                }
                attempt = 0;
                removed = removed.saturating_add(n);
                batches += 1;
                if batches.is_multiple_of(DELETE_TRUNCATE_EVERY) {
                    self.checkpoint_wal("TRUNCATE").await;
                } else if batches.is_multiple_of(DELETE_CHECKPOINT_EVERY) {
                    self.checkpoint_wal("PASSIVE").await;
                }
            }
            if removed > 0 {
                info!(
                    "Deleting case {}: removed {} {} rows",
                    case_id, removed, table
                );
            }
        }

        // Delete the case; FK cascades handle the remaining case-scoped tables
        sqlx::query("DELETE FROM cases WHERE id = ?")
            .bind(case_id)
            .execute(&self.pool)
            .await
            .context(format!("Failed to delete case with ID: {}", case_id))?;

        // The case is gone; give back what its rows left in the WAL.
        self.checkpoint_wal("TRUNCATE").await;

        info!("Deleted case: {}", case_id);
        Ok(())
    }

    /// Delete an artifact and all its descendants recursively
    /// Returns (deleted_artifacts_count, deleted_timeline_events_count)
    pub async fn delete_artifact_recursive(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<(i64, i64)> {
        info!(
            "Starting recursive deletion of artifact {} in case {}",
            artifact_id, case_id
        );

        // Verify artifact belongs to case
        let artifact_check = sqlx::query("SELECT id FROM artifacts WHERE id = ? AND case_id = ?")
            .bind(artifact_id.as_bytes().to_vec())
            .bind(case_id.as_bytes().to_vec())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to verify artifact ownership")?;

        if artifact_check.is_none() {
            return Err(anyhow::anyhow!(
                "Artifact {} not found in case {}",
                artifact_id,
                case_id
            ));
        }

        // A single recursive CTE walks the whole subtree (root + descendants via
        // parent_id); each dependent table is then cleared set-wise. This
        // replaces the old N+1 pattern (one SELECT per node to enumerate, then
        // ~4 DELETEs per node), which turned a large-source delete into hundreds
        // of thousands of round-trips.
        //
        // Order matters: `artifacts` is deleted LAST because the CTE walks
        // parent_id within `artifacts`, so the earlier statements must still see
        // those rows. artifact_bookmarks, integrity_checks and ad_hoc_jobs
        // cascade via their ON DELETE CASCADE FK on artifact_id; timeline_tags
        // (event_id) and processing_log (artifact_id) have no FK and are cleared
        // explicitly to avoid orphans.
        // The recursive step is constrained to the same case, so an adversarial /
        // corrupt `parent_id` pointing at another case's artifact can never pull
        // it (or its subtree) into this delete. `parent_id` has no FK enforcing
        // same-case, so this filter is the guarantee.
        // `UNION`, not `UNION ALL`: a cyclic same-case `parent_id` (corrupt or
        // adversarial) makes an ALL walk re-add ids forever until SQLite aborts
        // the recursion, so the delete FAILS while the browse walk -- which has
        // always used `UNION` -- still shows the subtree. Deduplicating ids
        // terminates the walk on a cycle instead (B5-025).
        const CTE: &str = "WITH RECURSIVE descendants(id) AS ( \
             SELECT id FROM artifacts WHERE id = ? AND case_id = ? \
             UNION \
             SELECT a.id FROM descendants d CROSS JOIN artifacts a ON a.parent_id = d.id \
             WHERE a.case_id = ? \
             )";
        let root = artifact_id.as_bytes().to_vec();
        let case_bytes = case_id.as_bytes().to_vec();

        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin artifact delete transaction")?;

        sqlx::query(&format!(
            "{CTE} DELETE FROM timeline_tags WHERE event_id IN (SELECT id FROM descendants)"
        ))
        .bind(&root)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .execute(&mut *tx)
        .await
        .context("Failed to delete timeline tags for subtree")?;

        sqlx::query(&format!(
            "{CTE} DELETE FROM processing_log WHERE artifact_id IN (SELECT id FROM descendants)"
        ))
        .bind(&root)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .execute(&mut *tx)
        .await
        .context("Failed to delete processing log for subtree")?;

        let te = sqlx::query(&format!(
            "{CTE} DELETE FROM timeline_events WHERE artifact_id IN (SELECT id FROM descendants)"
        ))
        .bind(&root)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .execute(&mut *tx)
        .await
        .context("Failed to delete timeline events for subtree")?;
        let total_timeline_events_deleted = te.rows_affected() as i64;

        let ar = sqlx::query(&format!(
            "{CTE} DELETE FROM artifacts WHERE id IN (SELECT id FROM descendants)"
        ))
        .bind(&root)
        .bind(&case_bytes)
        .bind(&case_bytes)
        .execute(&mut *tx)
        .await
        .context("Failed to delete artifacts for subtree")?;
        let total_artifacts_deleted = ar.rows_affected() as i64;

        tx.commit()
            .await
            .context("Failed to commit artifact delete transaction")?;

        info!(
            "Deleted {} artifacts and {} timeline events",
            total_artifacts_deleted, total_timeline_events_deleted
        );
        Ok((total_artifacts_deleted, total_timeline_events_deleted))
    }

    /// The ids of an artifact and all its descendants -- exactly the set that
    /// `delete_artifact_recursive` removes. Collect this BEFORE deleting so the
    /// same ids can be purged from the search index (which keys on artifact id).
    pub async fn subtree_artifact_ids(&self, artifact_id: Uuid) -> Result<Vec<Uuid>> {
        // The recursive step is scoped to the root artifact's OWN case_id (via a
        // subquery, since this method takes no case_id parameter and its callers
        // live in seance_api). A corrupt/malicious cross-case `parent_id` can
        // therefore never pull another case's artifact into the subtree -- which
        // would otherwise purge the wrong search docs. `parent_id` has no FK
        // enforcing same-case, so this filter is the guarantee.
        // `UNION` (not `UNION ALL`) so a cyclic `parent_id` terminates the walk
        // rather than exhausting recursion (B5-025); the id set is the same.
        const CTE: &str = "WITH RECURSIVE descendants(id) AS ( \
             SELECT id FROM artifacts WHERE id = ? \
             UNION \
             SELECT a.id FROM descendants d CROSS JOIN artifacts a ON a.parent_id = d.id \
             WHERE a.case_id = (SELECT case_id FROM artifacts WHERE id = ?) \
             ) SELECT id FROM descendants";
        let root = artifact_id.as_bytes().to_vec();
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(CTE)
            .bind(&root)
            .bind(&root)
            .fetch_all(&self.pool)
            .await
            .context("Failed to collect artifact subtree ids")?;
        rows.into_iter()
            .map(|b| Uuid::from_slice(&b).context("Invalid UUID in artifact subtree"))
            .collect()
    }

    /// Get deletion impact statistics for an artifact
    /// Returns (total_artifacts, total_timeline_events)
    pub async fn get_artifact_deletion_impact(&self, artifact_id: Uuid) -> Result<(i64, i64)> {
        // Same recursive-CTE subtree as delete_artifact_recursive, counted in
        // two queries instead of one COUNT per descendant. The recursive step is
        // scoped to the root artifact's OWN case_id (subquery, since this method
        // takes no case_id parameter and its callers live in seance_api) so a
        // cross-case `parent_id` cannot inflate the reported deletion impact.
        // `UNION` (not `UNION ALL`) so a cyclic `parent_id` terminates the walk
        // rather than exhausting recursion (B5-025); the id set is the same.
        const CTE: &str = "WITH RECURSIVE descendants(id) AS ( \
             SELECT id FROM artifacts WHERE id = ? \
             UNION \
             SELECT a.id FROM descendants d CROSS JOIN artifacts a ON a.parent_id = d.id \
             WHERE a.case_id = (SELECT case_id FROM artifacts WHERE id = ?) \
             )";
        let root = artifact_id.as_bytes().to_vec();

        let artifact_count: i64 =
            sqlx::query_scalar(&format!("{CTE} SELECT COUNT(*) FROM descendants"))
                .bind(&root)
                .bind(&root)
                .fetch_one(&self.pool)
                .await
                .context("Failed to count deletion-impact artifacts")?;

        let timeline_event_count: i64 = sqlx::query_scalar(&format!(
            "{CTE} SELECT COUNT(*) FROM timeline_events WHERE artifact_id IN (SELECT id FROM descendants)"
        ))
        .bind(&root)
        .bind(&root)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count deletion-impact timeline events")?;

        Ok((artifact_count, timeline_event_count))
    }

    pub async fn create_case_with_metadata(
        &self,
        name: Option<String>,
        reference_number: Option<String>,
        examiner_name: Option<String>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let created_at = Utc::now().to_rfc3339();
        let status = "active".to_string();
        let case_name = name.unwrap_or_else(|| format!("Case {}", id));

        sqlx::query(
            "INSERT INTO cases (id, name, created_at, status, reference_number, examiner_name) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&case_name)
        .bind(created_at)
        .bind(status)
        .bind(reference_number)
        .bind(examiner_name)
        .execute(&self.pool)
        .await
        .context("Failed to create new case")?;

        info!("Created new case: {} (ID: {})", case_name, id);
        Ok(id)
    }

    pub async fn get_case_stats(&self, case_id: Uuid) -> Result<seance_core::models::CaseStats> {
        use std::collections::HashMap;

        let total_artifacts = self.count_total_artifacts(case_id).await?;

        #[derive(sqlx::FromRow, Debug)]
        struct TypeCount {
            artifact_type: String,
            count: i64,
        }

        let type_counts: Vec<TypeCount> = sqlx::query_as::<_, TypeCount>(
            "SELECT artifact_type, COUNT(*) as count FROM artifacts WHERE case_id = ? GROUP BY artifact_type"
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch artifact type counts")?;

        let mut artifact_counts_by_type = HashMap::new();
        for tc in type_counts {
            artifact_counts_by_type.insert(tc.artifact_type, tc.count);
        }

        Ok(seance_core::models::CaseStats {
            total_artifacts,
            artifact_counts_by_type,
        })
    }

    pub async fn get_timeline_events(
        &self,
        case_id: Uuid,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<seance_core::models::TimelineEventResponse>> {
        #[derive(sqlx::FromRow, Debug)]
        struct TimelineRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            timestamp: i64,
            timestamp_desc: String,
            source_module: String,
            short_desc: String,
            full_details: String,
            timestamp_subsec_nanos: i64,
            source_utc_offset_seconds: Option<i32>,
        }

        let limit_val = limit.unwrap_or(100) as i64;
        let offset_val = offset.unwrap_or(0) as i64;

        let rows: Vec<TimelineRow> = sqlx::query_as::<_, TimelineRow>(
            "SELECT id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details
             FROM timeline_events
             WHERE case_id = ?
             ORDER BY timestamp DESC, timestamp_subsec_nanos DESC, id ASC
             LIMIT ? OFFSET ?"
        )
        .bind(case_id)
        .bind(limit_val)
        .bind(offset_val)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch timeline events")?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(seance_core::models::TimelineEventResponse {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for event ID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
                artifact_id: Uuid::from_slice(&row.artifact_id)
                    .context("Invalid UUID for artifact ID")?,
                timestamp: row.timestamp,
                timestamp_subsec_nanos: row.timestamp_subsec_nanos,
                source_utc_offset_seconds: row.source_utc_offset_seconds,
                timestamp_desc: row.timestamp_desc,
                source_module: row.source_module,
                short_desc: row.short_desc,
                full_details: row.full_details,
                is_tagged: None,
                dynamic_fields: None,
                tag_note: None,
            });
        }

        Ok(events)
    }

    /// Get timeline events with optional date range, source module, and text filtering
    pub async fn get_timeline_events_filtered(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<&[String]>,
        search_text: Option<&str>,
        filename_filter: Option<&str>,
        event_type_filter: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        dynamic_columns: Option<&[String]>,
        event_ids: Option<&[Vec<u8>]>,
    ) -> Result<Vec<seance_core::models::TimelineEventResponse>> {
        #[derive(sqlx::FromRow, Debug)]
        struct TimelineRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            timestamp: i64,
            timestamp_desc: String,
            source_module: String,
            short_desc: String,
            full_details: String,
            timestamp_subsec_nanos: i64,
            source_utc_offset_seconds: Option<i32>,
            tag_id: Option<Vec<u8>>,
            tag_note: Option<String>,
        }

        // Build dynamic query based on filters with LEFT JOIN for tags
        let mut query = String::from(
            "SELECT te.id, te.case_id, te.artifact_id, te.timestamp, te.timestamp_subsec_nanos, te.source_utc_offset_seconds, te.timestamp_desc, te.source_module, te.short_desc, te.full_details, \
                    tt.id as tag_id, tt.note as tag_note \
             FROM timeline_events te \
             LEFT JOIN timeline_tags tt ON te.artifact_id = tt.event_id AND te.case_id = tt.case_id \
             WHERE te.case_id = ?"
        );

        // The filter predicates are shared with the count, histogram, extent and
        // export reads (`build_timeline_where`), so a page, its count and an
        // export of the same filter cannot disagree about which events match.
        let (where_suffix, binds) = build_timeline_where(
            "te",
            from_ts,
            to_ts,
            source_modules,
            search_text,
            filename_filter,
            event_type_filter,
            event_ids,
        );
        query.push_str(&where_suffix);

        // Add ORDER BY clause with dynamic sorting
        // Note: Use COALESCE to handle NULL values from JSON extraction
        // For filename/resource sorting, we try multiple common field names
        //
        // SECURITY: This constructs ORDER BY clause dynamically, but is safe because:
        // 1. sort_column is whitelisted via match statement (only predefined values allowed)
        // 2. order is validated to be either "ASC" or "DESC" (no user input passed through)
        // 3. User input is matched against known-safe values, never concatenated directly
        let sort_column = match sort_by.unwrap_or("timestamp") {
            "timestamp" => "te.timestamp",
            "event_type" => "te.timestamp_desc",
            "source" => "te.source_module",
            "filename" => "COALESCE(json_extract(te.full_details, '$.filename'), json_extract(te.full_details, '$.path'), json_extract(te.full_details, '$.name'), '')",
            "description" => "te.short_desc",
            _ => "te.timestamp", // Default fallback for any invalid input
        };
        // Validate order parameter (whitelist validation - only ASC or DESC allowed)
        let order = if sort_order.unwrap_or("desc").to_lowercase() == "asc" {
            "ASC"
        } else {
            "DESC"
        };
        // Sorting on the whole-second timestamp alone put same-second events in
        // artifact-id order, which is arbitrary: EVTX (and any source with
        // sub-second resolution) records the real nanosecond in
        // `timestamp_subsec_nanos`, and within one second that ordering IS the
        // sequence an intrusion is reconstructed from. Break the tie on it in
        // the requested direction before falling back to te.id.
        //
        // Rows written before the column existed hold 0 (migration 0021 added it
        // NOT NULL DEFAULT 0), and a hand-edited NULL sorts exactly where 0
        // does in SQLite, so a pre-column event lands at the top of its second
        // rather than at an arbitrary extreme.
        let subsec_tiebreak = if sort_column == "te.timestamp" {
            format!(" te.timestamp_subsec_nanos {},", order)
        } else {
            String::new()
        };
        // te.id tiebreaker keeps pagination stable when the sort key has duplicates
        query.push_str(&format!(
            " ORDER BY {} {},{} te.id ASC",
            sort_column, order, subsec_tiebreak
        ));

        if let Some(lim) = limit {
            query.push_str(&format!(" LIMIT {}", lim));
        }

        if let Some(off) = offset {
            query.push_str(&format!(" OFFSET {}", off));
        }

        // Build and execute query with bindings
        let case_id_bytes = case_id.as_bytes().to_vec();

        let mut q = sqlx::query_as::<_, TimelineRow>(&query).bind(&case_id_bytes);
        for bind in &binds {
            q = match bind {
                TimelineBind::I64(v) => q.bind(*v),
                TimelineBind::Text(t) => q.bind(t),
                TimelineBind::Blob(bytes) => q.bind(bytes),
            };
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch filtered timeline events")?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            // Extract dynamic fields if requested
            let dynamic_fields = if let Some(cols) = dynamic_columns {
                if !cols.is_empty() {
                    let mut fields = std::collections::HashMap::new();

                    // Parse the JSON once
                    if let Ok(json_value) =
                        serde_json::from_str::<serde_json::Value>(&row.full_details)
                    {
                        for col_path in cols {
                            // The map key is the path with `$.` stripped —
                            // exactly what the client derives from the column
                            // definition to look the value back up. The VALUE
                            // is resolved by walking the path, so nested and
                            // indexed paths (`$.items[0].name`) resolve instead
                            // of silently rendering blank.
                            let Some(field_name) = col_path.strip_prefix("$.") else {
                                continue;
                            };
                            if let Some(value) = resolve_json_path(&json_value, col_path) {
                                fields.insert(field_name.to_string(), value.clone());
                            }
                        }
                    }

                    Some(fields)
                } else {
                    None
                }
            } else {
                None
            };

            events.push(seance_core::models::TimelineEventResponse {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for event ID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
                artifact_id: Uuid::from_slice(&row.artifact_id)
                    .context("Invalid UUID for artifact ID")?,
                timestamp: row.timestamp,
                timestamp_subsec_nanos: row.timestamp_subsec_nanos,
                source_utc_offset_seconds: row.source_utc_offset_seconds,
                timestamp_desc: row.timestamp_desc,
                source_module: row.source_module,
                short_desc: row.short_desc,
                full_details: row.full_details,
                is_tagged: Some(row.tag_id.is_some()),
                tag_note: row.tag_note,
                dynamic_fields,
            });
        }

        Ok(events)
    }

    /// Stream every timeline event matching the export filters through a bounded
    /// channel, one row at a time, from a single consistent query. This lets the
    /// API serialize an arbitrarily large export (hundreds of MB) without ever
    /// materializing the whole result set -- peak memory is the channel capacity,
    /// not the case size. Filters mirror `get_timeline_events_filtered` (date
    /// range, source modules, text search, filename, event type, and the
    /// tagged-only event-id set) including the tags LEFT JOIN, and the same
    /// `timestamp DESC, timestamp_subsec_nanos DESC, id ASC` order, so an export
    /// is byte-for-byte the set the examiner had on screen (BUG-231).
    ///
    /// Each item is `Ok(event)` or `Err(message)`; on a mid-stream DB error the
    /// consumer should abort the transfer rather than emit a truncated file.
    pub fn stream_export_timeline(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<Vec<String>>,
        search_text: Option<String>,
        filename_filter: Option<String>,
        event_type_filter: Option<String>,
        event_ids: Option<Vec<Vec<u8>>>,
    ) -> tokio::sync::mpsc::Receiver<
        std::result::Result<seance_core::models::TimelineEventResponse, String>,
    > {
        use futures::StreamExt;

        #[derive(sqlx::FromRow)]
        struct TimelineRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            timestamp: i64,
            timestamp_desc: String,
            source_module: String,
            short_desc: String,
            full_details: String,
            timestamp_subsec_nanos: i64,
            source_utc_offset_seconds: Option<i32>,
            tag_id: Option<Vec<u8>>,
            tag_note: Option<String>,
        }

        // Everything from WHERE onward (alias `te`), valid with or without the
        // tags join. The SELECT/FROM prefix is chosen at stream time based on
        // whether the case actually has any tags. The predicates are the ones
        // the list and count reads use (`build_timeline_where`): an export that
        // requested a search, a tagged-only set or a column filter is never
        // returned unfiltered -- the wrong custody product.
        let (where_suffix, binds) = build_timeline_where(
            "te",
            from_ts,
            to_ts,
            source_modules.as_deref(),
            search_text.as_deref(),
            filename_filter.as_deref(),
            event_type_filter.as_deref(),
            event_ids.as_deref(),
        );
        let mut query = format!(" WHERE te.case_id = ?{where_suffix}");

        // Same sub-second ordering the on-screen listing uses, so an export is
        // byte-for-byte the sequence the examiner saw.
        query.push_str(" ORDER BY te.timestamp DESC, te.timestamp_subsec_nanos DESC, te.id ASC");

        let pool = self.pool.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(512);

        tokio::spawn(async move {
            // Skip the timeline_tags LEFT JOIN when the case has no tags: with
            // zero matching rows the join only ever yields NULL tag columns, so
            // selecting literal NULLs is byte-identical output while avoiding a
            // per-event index probe into timeline_tags across the whole export.
            // On a count error, fall back to the join (correct output).
            let has_tags = sqlx::query_scalar::<_, i64>(
                "SELECT EXISTS(SELECT 1 FROM timeline_tags WHERE case_id = ?)",
            )
            .bind(case_id.as_bytes().to_vec())
            .fetch_one(&pool)
            .await
            .unwrap_or(1)
                != 0;

            const COLS: &str = "SELECT te.id, te.case_id, te.artifact_id, te.timestamp, te.timestamp_subsec_nanos, te.source_utc_offset_seconds, te.timestamp_desc, te.source_module, te.short_desc, te.full_details, ";
            let select_from = if has_tags {
                format!(
                    "{COLS} tt.id as tag_id, tt.note as tag_note \
                     FROM timeline_events te \
                     LEFT JOIN timeline_tags tt ON te.artifact_id = tt.event_id AND te.case_id = tt.case_id"
                )
            } else {
                format!("{COLS} NULL as tag_id, NULL as tag_note FROM timeline_events te")
            };
            let query = format!("{select_from}{query}");

            let mut q = sqlx::query_as::<_, TimelineRow>(&query).bind(case_id.as_bytes().to_vec());
            for b in &binds {
                q = match b {
                    TimelineBind::Blob(v) => q.bind(v),
                    TimelineBind::I64(i) => q.bind(*i),
                    TimelineBind::Text(s) => q.bind(s),
                };
            }

            let mut stream = q.fetch(&pool);
            while let Some(item) = stream.next().await {
                let msg = match item {
                    Ok(row) => match (
                        Uuid::from_slice(&row.id),
                        Uuid::from_slice(&row.case_id),
                        Uuid::from_slice(&row.artifact_id),
                    ) {
                        (Ok(id), Ok(cid), Ok(aid)) => {
                            Ok(seance_core::models::TimelineEventResponse {
                                id,
                                case_id: cid,
                                artifact_id: aid,
                                timestamp: row.timestamp,
                                timestamp_subsec_nanos: row.timestamp_subsec_nanos,
                                source_utc_offset_seconds: row.source_utc_offset_seconds,
                                timestamp_desc: row.timestamp_desc,
                                source_module: row.source_module,
                                short_desc: row.short_desc,
                                full_details: row.full_details,
                                is_tagged: Some(row.tag_id.is_some()),
                                tag_note: row.tag_note,
                                dynamic_fields: None,
                            })
                        }
                        _ => Err("invalid UUID in timeline row".to_string()),
                    },
                    Err(e) => Err(e.to_string()),
                };
                let is_err = msg.is_err();
                // A send error means the consumer (HTTP client) went away.
                if tx.send(msg).await.is_err() || is_err {
                    break;
                }
            }
        });

        rx
    }

    /// File entries in the case whose name matches one of `names`, compared
    /// case-insensitively.
    ///
    /// The question the cross-view findings ask (`ROADMAP` §2.2 items 3 and 6):
    /// a prefetch record says a program ran — is there a file entry for it in
    /// this case at all, and if so, is every one of them deleted?
    ///
    /// Three properties are what make the answer usable in a finding:
    ///
    /// * **Case-insensitive**, because Windows is and the sources disagree
    ///   about case as a matter of course. `idx_artifacts_type_name_nocase`
    ///   (migration 0040) is declared with this collation.
    /// * **Capped per name**, because a name like `setup.exe` occurs thousands
    ///   of times on a real volume and a finding needs a handful of examples,
    ///   not all of them. The cap is reported per name, so a truncated answer
    ///   is never read as a complete one.
    /// * **`deleted` carried per hit**, because "no file entry for this
    ///   program" and "the only file entry for this program is deleted" are
    ///   different findings and must not be reached from the same answer.
    ///
    /// Keys of the returned map are the requested names lower-cased. A name
    /// with no match is absent from the map, which is a different thing from
    /// present-with-no-hits and cannot occur here.
    pub async fn file_entries_by_name(
        &self,
        case_id: Uuid,
        names: &[String],
        max_per_name: usize,
    ) -> Result<std::collections::HashMap<String, FileNameMatches>> {
        use std::collections::HashMap;

        // Deduplicate on the folded form: the callers hand over one name per
        // execution record and the same program is named by many of them.
        let mut wanted: Vec<String> = names
            .iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        wanted.sort_unstable();
        wanted.dedup();

        let mut out: HashMap<String, FileNameMatches> = HashMap::new();
        if wanted.is_empty() || max_per_name == 0 {
            return Ok(out);
        }

        // Chunked so the IN list stays well inside SQLite's variable limit.
        for chunk in wanted.chunks(200) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT id, name, path, is_deleted, \
                        json_extract(metadata_json, '$.record_number') AS record_number, \
                        json_extract(metadata_json, '$.sequence_number') AS sequence_number \
                 FROM artifacts \
                 WHERE case_id = ? AND artifact_type = 'FileEntry' \
                   AND name COLLATE NOCASE IN ({placeholders})"
            );
            let mut q = sqlx::query(&sql).bind(case_id.as_bytes().to_vec());
            for name in chunk {
                q = q.bind(name.as_str());
            }
            let rows = q
                .fetch_all(&self.pool)
                .await
                .context("Failed to look up file entries by name")?;

            for row in rows {
                let Some(name) = row.try_get::<Option<String>, _>("name").ok().flatten() else {
                    continue;
                };
                let key = name.to_ascii_lowercase();
                let entry = out.entry(key).or_default();
                entry.seen += 1;
                // Past the cap the hits are still counted — the finding needs
                // to know how many there were — but not carried.
                if entry.hits.len() >= max_per_name {
                    entry.truncated = true;
                    continue;
                }
                let id = row
                    .try_get::<Vec<u8>, _>("id")
                    .ok()
                    .and_then(|b| Uuid::from_slice(&b).ok());
                let Some(artifact_id) = id else { continue };
                entry.hits.push(FileNameHit {
                    artifact_id,
                    name,
                    path: row.try_get::<Option<String>, _>("path").ok().flatten(),
                    // The generated column is `json_extract(metadata_json,
                    // '$.deleted')`, which is 1 / 0 / NULL. NULL is "the
                    // parser said nothing", which for a live filesystem entry
                    // means not deleted; only an explicit true is deleted.
                    deleted: row
                        .try_get::<Option<i64>, _>("is_deleted")
                        .ok()
                        .flatten()
                        .is_some_and(|v| v != 0),
                    record_number: row
                        .try_get::<Option<i64>, _>("record_number")
                        .ok()
                        .flatten()
                        .and_then(|v| u64::try_from(v).ok()),
                    sequence_number: row
                        .try_get::<Option<i64>, _>("sequence_number")
                        .ok()
                        .flatten()
                        .and_then(|v| u64::try_from(v).ok()),
                });
            }
        }
        Ok(out)
    }

    /// How many `FileEntry` artifacts the case holds: the population a body
    /// file states before its first row. Counted through the same predicate
    /// [`Self::stream_file_entries`] walks, so the two figures name one set.
    pub async fn count_file_entries(&self, case_id: Uuid) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND artifact_type = 'FileEntry'",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_one(&self.pool)
        .await
        .context("Failed to count file entries")
    }

    /// Stream every `FileEntry` artifact in the case through a bounded channel,
    /// one at a time, from a single consistent query in `id` order — the same
    /// arbitrary-but-total order [`Self::artifacts_page_after`] uses for a
    /// whole-case sweep. This is what the `mactime` body-file export drains: a
    /// case with a million files never materialises in RAM, and peak memory is
    /// the channel capacity.
    ///
    /// The artifacts carry **no data source** (`data: None`), like every other
    /// artifact loaded from the database. Their `md5` sits in the metadata,
    /// merged there by the hasher (`apply_file_hash`), so a consumer needs no
    /// second read.
    ///
    /// Each item is `Ok(artifact)` or `Err(message)`; on a mid-stream error the
    /// consumer must abort rather than emit a file that looks whole. A row
    /// whose metadata does not decode is an error, not a skip: a body file that
    /// silently omitted a file would present the rest as the whole set.
    pub fn stream_file_entries(
        &self,
        case_id: Uuid,
    ) -> tokio::sync::mpsc::Receiver<std::result::Result<Artifact, String>> {
        use futures::StreamExt;

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            metadata_json: String,
        }

        let pool = self.pool.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(512);

        tokio::spawn(async move {
            let mut stream = sqlx::query_as::<_, Row>(
                "SELECT id, parent_id, metadata_json FROM artifacts \
                 WHERE case_id = ? AND artifact_type = 'FileEntry' ORDER BY id ASC",
            )
            .bind(case_id.as_bytes().to_vec())
            .fetch(&pool);

            while let Some(item) = stream.next().await {
                let msg = match item {
                    Ok(row) => {
                        let id = Uuid::from_slice(&row.id).map_err(|e| e.to_string());
                        let parent_id = row
                            .parent_id
                            .as_deref()
                            .map(Uuid::from_slice)
                            .transpose()
                            .map_err(|e| e.to_string());
                        let metadata =
                            serde_json::from_str::<serde_json::Value>(&row.metadata_json)
                                .map_err(|e| format!("undecodable metadata: {e}"));
                        match (id, parent_id, metadata) {
                            (Ok(id), Ok(parent_id), Ok(metadata)) => Ok(Artifact {
                                id,
                                case_id,
                                parent_id,
                                artifact_type: ArtifactType::FileEntry,
                                data: None,
                                metadata,
                            }),
                            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                                Err(format!("file entry row could not be read: {e}"))
                            }
                        }
                    }
                    Err(e) => Err(e.to_string()),
                };
                let is_err = msg.is_err();
                // A send error means the consumer (HTTP client) went away.
                if tx.send(msg).await.is_err() || is_err {
                    break;
                }
            }
        });

        rx
    }

    /// Get total count of timeline events with filters applied
    pub async fn get_timeline_events_count(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<&[String]>,
        search_text: Option<&str>,
        filename_filter: Option<&str>,
        event_type_filter: Option<&str>,
        event_ids: Option<&[Vec<u8>]>,
    ) -> Result<i64> {
        let (where_suffix, binds) = build_timeline_where(
            "",
            from_ts,
            to_ts,
            source_modules,
            search_text,
            filename_filter,
            event_type_filter,
            event_ids,
        );
        let query = format!(
            "SELECT COUNT(*) as count FROM timeline_events WHERE case_id = ?{where_suffix}"
        );

        let case_id_bytes = case_id.as_bytes().to_vec();
        let mut q = sqlx::query(&query).bind(&case_id_bytes);
        for bind in &binds {
            q = match bind {
                TimelineBind::I64(v) => q.bind(*v),
                TimelineBind::Text(t) => q.bind(t),
                TimelineBind::Blob(bytes) => q.bind(bytes),
            };
        }

        let row = q
            .fetch_one(&self.pool)
            .await
            .context("Failed to count timeline events")?;

        let count: i64 = row.try_get("count")?;
        Ok(count)
    }

    /// Get counts of timeline events by source module
    pub async fn get_timeline_source_module_counts(
        &self,
        case_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>> {
        let case_id_bytes = case_id.as_bytes().to_vec();

        let rows = sqlx::query(
            "SELECT source_module, COUNT(*) as count \
             FROM timeline_events \
             WHERE case_id = ? \
             GROUP BY source_module \
             ORDER BY count DESC",
        )
        .bind(&case_id_bytes)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch source module counts")?;

        let mut counts = std::collections::HashMap::new();
        for row in rows {
            let source_module: String = row.try_get("source_module")?;
            let count: i64 = row.try_get("count")?;
            counts.insert(source_module, count);
        }

        Ok(counts)
    }

    /// Get recently ingested artifacts (by created_at)
    pub async fn get_recent_artifacts(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String, String, String)>> {
        let case_id_bytes = case_id.as_bytes().to_vec();

        let query = r#"
            SELECT id, artifact_type, metadata_json, created_at
            FROM artifacts
            WHERE case_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        "#;

        let rows = sqlx::query(query)
            .bind(&case_id_bytes)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        let mut artifacts = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let artifact_type: String = row.try_get("artifact_type")?;
            let metadata_json: String = row.try_get("metadata_json")?;
            let created_at: String = row.try_get("created_at")?;

            artifacts.push((id, artifact_type, metadata_json, created_at));
        }

        Ok(artifacts)
    }

    pub async fn get_analysis_counts(
        &self,
        case_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>> {
        #[derive(sqlx::FromRow, Debug)]
        struct CountRow {
            group_key: String,
            count: i64,
        }

        let case_id_bytes = case_id.as_bytes().to_vec();

        // Group by artifact_type, and for ParsedRecord, also by the 'type' field in metadata
        let query = r#"
            SELECT 
                CASE 
                    WHEN artifact_type = 'ParsedRecord' THEN 
                        'ParsedRecord:' || COALESCE(json_extract(metadata_json, '$.type'), 'Unknown')
                    ELSE 
                        artifact_type
                END as group_key,
                COUNT(*) as count
            FROM artifacts
            WHERE case_id = ?
            GROUP BY group_key
        "#;

        let rows: Vec<CountRow> = sqlx::query_as::<_, CountRow>(query)
            .bind(&case_id_bytes)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch analysis counts")?;

        let mut counts = std::collections::HashMap::new();
        for row in rows {
            counts.insert(row.group_key, row.count);
        }

        Ok(counts)
    }

    /// Timeline events related to one artifact, newest first, bounded by
    /// [`RELATED_TIMELINE_CAP`].
    ///
    /// Related means, in priority order:
    /// 1. the artifact itself,
    /// 2. its parent,
    /// 3. its children,
    /// 4. its siblings (artifacts sharing the same parent).
    ///
    /// The first three are the artifact's own history and are always fetched
    /// first; siblings only fill whatever budget is left. That order is the
    /// point: under a filesystem or a large directory, siblings are every other
    /// file on the volume, so a single chronological query capped at N returns
    /// the N newest events on the volume and can leave out every event of the
    /// artifact the examiner actually asked about. Uncapped, the same query
    /// materialises the whole volume timeline.
    ///
    /// [`TimelineEventPage::truncated`] is true when either half hit its bound,
    /// so a caller can never present a bounded slice as the complete relation.
    pub async fn get_related_timeline_events(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<TimelineEventPage> {
        #[derive(sqlx::FromRow, Debug)]
        struct TimelineRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            timestamp: i64,
            timestamp_desc: String,
            source_module: String,
            short_desc: String,
            full_details: String,
            timestamp_subsec_nanos: i64,
            source_utc_offset_seconds: Option<i32>,
        }

        let case_id_bytes = case_id.as_bytes().to_vec();
        let artifact_id_bytes = artifact_id.as_bytes().to_vec();

        // First, get the artifact to find its parent_id
        let artifact = self.get_artifact_details(case_id, artifact_id).await?;
        let parent_id_bytes = artifact.parent_id.map(|p| p.as_bytes().to_vec());

        // Self + parent + children: the artifact's own history.
        let mut core_rows: Vec<TimelineRow> = sqlx::query_as::<_, TimelineRow>(
            "SELECT DISTINCT te.id, te.case_id, te.artifact_id, te.timestamp, te.timestamp_subsec_nanos, te.source_utc_offset_seconds, te.timestamp_desc,
                    te.source_module, te.short_desc, te.full_details
             FROM timeline_events te
             INNER JOIN artifacts a ON te.artifact_id = a.id
             WHERE te.case_id = ? AND (
                 te.artifact_id = ? OR                          -- The artifact itself
                 (? IS NOT NULL AND te.artifact_id = ?) OR      -- The parent artifact
                 a.parent_id = ?                                -- Children (this is parent)
             )
             ORDER BY te.timestamp DESC, te.timestamp_subsec_nanos DESC, te.id ASC
             LIMIT ?"
        )
        .bind(&case_id_bytes)
        .bind(&artifact_id_bytes)
        .bind(&parent_id_bytes)
        .bind(&parent_id_bytes)
        .bind(&artifact_id_bytes)
        .bind(RELATED_TIMELINE_CAP as i64 + 1)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch related timeline events")?;

        let mut truncated = core_rows.len() > RELATED_TIMELINE_CAP;
        core_rows.truncate(RELATED_TIMELINE_CAP);

        // Siblings fill the remaining budget, never the artifact's own share.
        // The sibling query runs whenever a parent exists, INCLUDING when the
        // budget is already spent, because it asks for `remaining + 1` rows and
        // that one probe row is the only thing that can tell "this artifact has
        // no siblings" apart from "its own history filled the answer and every
        // sibling event was left out". Skipping the query at `remaining == 0`
        // returned exactly the cap with `truncated: false` — a bounded answer
        // presented as the complete relation, which is the defect this whole
        // function was rewritten to stop.
        let remaining = RELATED_TIMELINE_CAP - core_rows.len();
        if let Some(parent_bytes) = parent_id_bytes.as_ref() {
            let mut sibling_rows: Vec<TimelineRow> = sqlx::query_as::<_, TimelineRow>(
                "SELECT DISTINCT te.id, te.case_id, te.artifact_id, te.timestamp, te.timestamp_subsec_nanos, te.source_utc_offset_seconds, te.timestamp_desc,
                        te.source_module, te.short_desc, te.full_details
                 FROM timeline_events te
                 INNER JOIN artifacts a ON te.artifact_id = a.id
                 WHERE te.case_id = ? AND a.parent_id = ? AND te.artifact_id != ?
                 ORDER BY te.timestamp DESC, te.timestamp_subsec_nanos DESC, te.id ASC
                 LIMIT ?"
            )
            .bind(&case_id_bytes)
            .bind(parent_bytes)
            .bind(&artifact_id_bytes)
            .bind(remaining as i64 + 1)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch sibling timeline events")?;

            if sibling_rows.len() > remaining {
                truncated = true;
                sibling_rows.truncate(remaining);
            }
            core_rows.extend(sibling_rows);
        }

        // Both halves were fetched newest-first; the merged list has to be too.
        core_rows.sort_by(|a, b| {
            b.timestamp
                .cmp(&a.timestamp)
                .then_with(|| b.timestamp_subsec_nanos.cmp(&a.timestamp_subsec_nanos))
                .then_with(|| a.id.cmp(&b.id))
        });

        if truncated {
            warn!(
                "case {}: related events for artifact {} hit the {} event ceiling; the response \
                 is reported as truncated",
                case_id, artifact_id, RELATED_TIMELINE_CAP
            );
        }

        let mut events = Vec::with_capacity(core_rows.len());
        for row in core_rows {
            events.push(seance_core::models::TimelineEventResponse {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for event ID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
                artifact_id: Uuid::from_slice(&row.artifact_id)
                    .context("Invalid UUID for artifact ID")?,
                timestamp: row.timestamp,
                timestamp_subsec_nanos: row.timestamp_subsec_nanos,
                source_utc_offset_seconds: row.source_utc_offset_seconds,
                timestamp_desc: row.timestamp_desc,
                source_module: row.source_module,
                short_desc: row.short_desc,
                full_details: row.full_details,
                is_tagged: None,
                dynamic_fields: None,
                tag_note: None,
            });
        }

        Ok(TimelineEventPage {
            events,
            truncated,
            cap: RELATED_TIMELINE_CAP,
        })
    }

    // Timeline Tag Management
    pub async fn create_timeline_tag(
        &self,
        case_id: Uuid,
        event_id: Uuid,
        examiner: Option<&str>,
        note: Option<&str>,
    ) -> Result<Uuid> {
        let created_at = Utc::now().timestamp();

        // Re-tagging keeps the surviving row's id, examiner and created_at (the
        // custody record of who tagged it first, and when) and only updates the
        // note, which a null note never erases. `INSERT OR REPLACE` would delete
        // the row and mint all three afresh.
        let id_bytes: Vec<u8> = sqlx::query_scalar(
            "INSERT INTO timeline_tags (id, case_id, event_id, examiner, note, created_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(case_id, event_id) DO UPDATE SET \
                 note = COALESCE(excluded.note, timeline_tags.note) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(case_id)
        .bind(event_id)
        .bind(examiner)
        .bind(note)
        .bind(created_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create timeline tag")?;
        let tag_id = Uuid::from_slice(&id_bytes).context("Invalid tag id returned by insert")?;

        debug!("Created tag for event {} in case {}", event_id, case_id);
        Ok(tag_id)
    }

    pub async fn delete_timeline_tag(&self, case_id: Uuid, event_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM timeline_tags WHERE case_id = ? AND event_id = ?")
            .bind(case_id)
            .bind(event_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete timeline tag")?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn get_timeline_tag(
        &self,
        case_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<seance_core::models::TimelineTag>> {
        let tag = sqlx::query_as::<_, seance_core::models::TimelineTag>(
            "SELECT id, case_id, event_id, examiner, note, created_at
             FROM timeline_tags
             WHERE case_id = ? AND event_id = ?",
        )
        .bind(case_id)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch timeline tag")?;

        Ok(tag)
    }

    pub async fn list_timeline_tags(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::models::TimelineTag>> {
        let tags = sqlx::query_as::<_, seance_core::models::TimelineTag>(
            "SELECT id, case_id, event_id, examiner, note, created_at
             FROM timeline_tags
             WHERE case_id = ?
             ORDER BY created_at DESC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list timeline tags")?;

        Ok(tags)
    }

    pub async fn update_timeline_tag_note(
        &self,
        case_id: Uuid,
        event_id: Uuid,
        note: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE timeline_tags SET note = ? WHERE case_id = ? AND event_id = ?")
                .bind(note)
                .bind(case_id)
                .bind(event_id)
                .execute(&self.pool)
                .await
                .context("Failed to update timeline tag note")?;

        Ok(result.rows_affected() > 0)
    }

    /// Discover all JSON fields available in timeline events for schema discovery
    pub async fn get_timeline_schema(
        &self,
        case_id: Uuid,
    ) -> Result<seance_core::models::TimelineSchema> {
        use serde_json::Value;
        use std::collections::HashMap;

        /// Events read to discover the available fields. Bounded so schema
        /// discovery stays cheap on a multi-million-event case.
        const SCHEMA_SAMPLE_SIZE: i64 = 1000;

        // The true size of the population the sample is drawn from. Without it
        // "these are the case's fields" and "these are the fields in the first
        // thousand events we happened to read" are the same answer.
        let total_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?")
                .bind(case_id)
                .fetch_one(&self.pool)
                .await
                .context("Failed to count timeline events for schema discovery")?;

        // ORDER BY makes the sample defined and repeatable. Without it SQLite
        // may return a different thousand rows on each call, so the discovered
        // field list and every frequency could change between two identical
        // requests with nothing to explain the difference.
        let rows = sqlx::query(
            "SELECT full_details FROM timeline_events WHERE case_id = ? \
             ORDER BY timestamp DESC, id LIMIT ?",
        )
        .bind(case_id)
        .bind(SCHEMA_SAMPLE_SIZE)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch timeline events for schema discovery")?;

        let sample_size = rows.len() as i64;
        let mut undecodable_events: i64 = 0;
        let mut field_stats: HashMap<String, (i64, Option<Value>)> = HashMap::new();

        // Parse each JSON and extract all field paths
        for row in rows {
            let Ok(full_details) = row.try_get::<String, _>("full_details") else {
                undecodable_events += 1;
                continue;
            };

            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&full_details) {
                for (key, value) in map.iter() {
                    let path = format!("$.{}", key);
                    let entry = field_stats.entry(path).or_insert((0, None));
                    entry.0 += 1;

                    // Store sample value if we don't have one yet
                    if entry.1.is_none() && !value.is_null() {
                        entry.1 = Some(value.clone());
                    }
                }
            } else {
                undecodable_events += 1;
            }
        }

        // Convert to schema fields
        let mut fields: Vec<seance_core::models::TimelineSchemaField> = field_stats
            .into_iter()
            .map(|(path, (frequency, sample_value))| {
                let field_type = match &sample_value {
                    Some(Value::String(_)) => "string",
                    Some(Value::Number(_)) => "number",
                    Some(Value::Bool(_)) => "boolean",
                    Some(Value::Array(_)) => "array",
                    Some(Value::Object(_)) => "object",
                    _ => "unknown",
                }
                .to_string();

                seance_core::models::TimelineSchemaField {
                    path,
                    field_type,
                    frequency,
                    sample_value,
                }
            })
            .collect();

        // Sort by frequency descending
        fields.sort_by_key(|b| std::cmp::Reverse(b.frequency));

        let sampled = total_events > sample_size;
        if sampled {
            warn!(
                "case {}: timeline schema discovered from {} of {} events; rare fields may be \
                 absent and every frequency is a count within the sample",
                case_id, sample_size, total_events
            );
        }
        if undecodable_events > 0 {
            warn!(
                "case {}: {} sampled timeline event(s) had unreadable full_details and \
                 contributed no fields",
                case_id, undecodable_events
            );
        }

        Ok(seance_core::models::TimelineSchema {
            available_fields: fields,
            sampled,
            sample_size,
            total_events,
            undecodable_events,
        })
    }

    // Virtual Column Management
    pub async fn create_virtual_column(
        &self,
        case_id: Uuid,
        col: &seance_core::virtual_columns::VirtualColumnDef,
    ) -> Result<()> {
        let sources_json = serde_json::to_string(&col.sources)
            .context("Failed to serialize virtual column sources")?;
        // Serialize enum to string (e.g. "string", "integer") without quotes for DB storage
        let column_type_json =
            serde_json::to_string(&col.column_type).context("Failed to serialize column type")?;
        let column_type_str = column_type_json.trim_matches('"');

        sqlx::query(
            "INSERT INTO virtual_columns (id, case_id, name, description, column_type, sources_json, default_visible, built_in, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&col.id)
        .bind(case_id.as_bytes().to_vec())
        .bind(&col.name)
        .bind(&col.description)
        .bind(column_type_str)
        .bind(sources_json)
        .bind(col.default_visible)
        .bind(col.built_in)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await
        .context("Failed to create virtual column")?;

        debug!("Created virtual column {} for case {}", col.name, case_id);
        Ok(())
    }

    pub async fn list_virtual_columns(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::virtual_columns::VirtualColumnDef>> {
        #[derive(sqlx::FromRow, Debug)]
        struct VColRow {
            id: String,
            name: String,
            description: Option<String>,
            column_type: String,
            sources_json: String,
            default_visible: bool,
            built_in: bool,
        }

        let rows = sqlx::query_as::<_, VColRow>(
            "SELECT id, name, description, column_type, sources_json, default_visible, built_in FROM virtual_columns WHERE case_id = ?"
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_all(&self.pool)
        .await
        .context("Failed to list virtual columns")?;

        let mut columns = Vec::new();
        for row in rows {
            // Deserialize column type (wrap in quotes to make it valid JSON string for serde if needed,
            // but serde_json::from_str expects a JSON string value "string", not just string)
            let type_json = format!("\"{}\"", row.column_type);
            let column_type: seance_core::virtual_columns::VirtualColumnType =
                serde_json::from_str(&type_json)
                    .context(format!("Invalid column type: {}", row.column_type))?;

            let sources: Vec<seance_core::virtual_columns::VirtualColumnSource> =
                serde_json::from_str(&row.sources_json).context("Invalid sources JSON")?;

            columns.push(seance_core::virtual_columns::VirtualColumnDef {
                id: row.id,
                name: row.name,
                description: row.description.unwrap_or_default(),
                column_type,
                sources,
                default_visible: row.default_visible,
                built_in: row.built_in,
            });
        }

        Ok(columns)
    }

    pub async fn update_virtual_column(
        &self,
        case_id: Uuid,
        col: &seance_core::virtual_columns::VirtualColumnDef,
    ) -> Result<bool> {
        let sources_json = serde_json::to_string(&col.sources)
            .context("Failed to serialize virtual column sources")?;
        let column_type_json =
            serde_json::to_string(&col.column_type).context("Failed to serialize column type")?;
        let column_type_str = column_type_json.trim_matches('"');

        let result = sqlx::query(
            "UPDATE virtual_columns SET name = ?, description = ?, column_type = ?, sources_json = ?, default_visible = ? \
             WHERE id = ? AND case_id = ? AND built_in = 0" // Prevent updating built-in columns or wrong case
        )
        .bind(&col.name)
        .bind(&col.description)
        .bind(column_type_str)
        .bind(sources_json)
        .bind(col.default_visible)
        .bind(&col.id)
        .bind(case_id.as_bytes().to_vec())
        .execute(&self.pool)
        .await
        .context("Failed to update virtual column")?;

        // `false`: no such column in this case, or it is built in. Nothing was
        // written, and the caller must not report the edit as saved.
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_virtual_column(&self, case_id: Uuid, column_id: &str) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM virtual_columns WHERE id = ? AND case_id = ? AND built_in = 0", // Prevent deleting built-in columns
        )
        .bind(column_id)
        .bind(case_id.as_bytes().to_vec())
        .execute(&self.pool)
        .await
        .context("Failed to delete virtual column")?;

        Ok(result.rows_affected() > 0)
    }

    // Bookmark Category Management

    /// Create a new top-level bookmark category.
    pub async fn create_bookmark_category(
        &self,
        case_id: Uuid,
        name: &str,
        color: Option<&str>,
    ) -> Result<Uuid> {
        match self
            .create_bookmark_folder(case_id, name, color, None)
            .await?
        {
            Ok(id) => Ok(id),
            // A top-level folder has no parent to refuse.
            Err(refusal) => Err(anyhow::anyhow!("category refused: {refusal:?}")),
        }
    }

    /// List all bookmark categories for a case
    pub async fn list_bookmark_categories(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::models::BookmarkCategory>> {
        let rows: Vec<(Vec<u8>, Vec<u8>, String, String, i64, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT id, case_id, name, color, created_at, parent_id
             FROM bookmark_categories
             WHERE case_id = ?
             ORDER BY name ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list bookmark categories")?;

        rows.into_iter()
            .map(|(id, case, name, color, created_at, parent)| {
                Ok(seance_core::models::BookmarkCategory {
                    id: Uuid::from_slice(&id).context("Invalid category id")?,
                    case_id: Uuid::from_slice(&case).context("Invalid category case id")?,
                    name,
                    color,
                    created_at,
                    parent_id: parent
                        .map(|p| Uuid::from_slice(&p))
                        .transpose()
                        .context("Invalid category parent id")?,
                })
            })
            .collect()
    }

    /// True when `category_id` exists AND belongs to `case_id`.
    ///
    /// The `artifact_bookmarks.category_id` foreign key only requires the UUID
    /// to exist somewhere, so without this check a bookmark in case A could be
    /// labelled with case B's category — and deleting that category in B would
    /// clear it on A's bookmarks (ON DELETE SET NULL). Callers that accept a
    /// client-supplied category must gate on this (BUG-279).
    pub async fn bookmark_category_in_case(
        &self,
        case_id: Uuid,
        category_id: Uuid,
    ) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM bookmark_categories WHERE id = ? AND case_id = ?")
                .bind(category_id)
                .bind(case_id)
                .fetch_optional(&self.pool)
                .await
                .context("Failed to verify the bookmark category's case")?;
        Ok(row.is_some())
    }

    /// Update a bookmark category
    pub async fn update_bookmark_category(
        &self,
        category_id: Uuid,
        name: Option<&str>,
        color: Option<&str>,
    ) -> Result<bool> {
        let mut updates = Vec::new();
        if name.is_some() {
            updates.push("name = ?");
        }
        if color.is_some() {
            updates.push("color = ?");
        }

        if updates.is_empty() {
            return Ok(false);
        }

        let sql = format!(
            "UPDATE bookmark_categories SET {} WHERE id = ?",
            updates.join(", ")
        );

        let mut query = sqlx::query(&sql);
        if let Some(n) = name {
            query = query.bind(n);
        }
        if let Some(c) = color {
            query = query.bind(c);
        }
        query = query.bind(category_id);

        let result = query
            .execute(&self.pool)
            .await
            .context("Failed to update bookmark category")?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a bookmark category
    pub async fn delete_bookmark_category(&self, case_id: Uuid, category_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM bookmark_categories WHERE id = ? AND case_id = ?")
            .bind(category_id)
            .bind(case_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete bookmark category")?;

        Ok(result.rows_affected() > 0)
    }

    // Artifact Bookmark Management

    /// Create a bookmark for an artifact, or update the existing one.
    ///
    /// Returns the bookmark id, which is STABLE across repeat calls.
    ///
    /// This used to be `INSERT OR REPLACE`, which on the `UNIQUE(case_id,
    /// artifact_id)` constraint deletes the existing row and inserts a fresh
    /// one. A second create therefore minted a new bookmark `id`, reset
    /// `created_at` to now, and overwrote the recorded examiner. "When was this
    /// first bookmarked, and by whom?" is a chain-of-custody question an
    /// examiner is asked in court, and the answer silently became "just now, by
    /// whoever clicked last"; any export or citation that referenced the old id
    /// also stopped resolving.
    ///
    /// So: on conflict the bookmark KEEPS its id, its `created_at` and its
    /// original `examiner`, and only the mutable fields (`note`, `category_id`,
    /// `updated_at`) move. A `None` note or category leaves the stored value
    /// alone rather than erasing an examiner's finding.
    pub async fn create_artifact_bookmark(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        category_id: Option<Uuid>,
        note: Option<&str>,
        examiner: Option<&str>,
    ) -> Result<Uuid> {
        let bookmark_id = Uuid::new_v4();
        let now = Utc::now().timestamp();

        let id_bytes: Vec<u8> = sqlx::query_scalar(
            "INSERT INTO artifact_bookmarks \
                 (id, case_id, artifact_id, category_id, note, examiner, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(case_id, artifact_id) DO UPDATE SET \
                 category_id = COALESCE(excluded.category_id, artifact_bookmarks.category_id), \
                 note = COALESCE(excluded.note, artifact_bookmarks.note), \
                 updated_at = excluded.updated_at \
             RETURNING id",
        )
        .bind(bookmark_id)
        .bind(case_id)
        .bind(artifact_id)
        .bind(category_id)
        .bind(note)
        .bind(examiner)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create artifact bookmark")?;

        let bookmark_id =
            Uuid::from_slice(&id_bytes).context("Invalid bookmark id returned by insert")?;

        debug!(
            "Bookmarked artifact {} in case {} (bookmark {})",
            artifact_id, case_id, bookmark_id
        );
        Ok(bookmark_id)
    }

    /// Get a bookmark for a specific artifact
    pub async fn get_artifact_bookmark(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Option<seance_core::models::ArtifactBookmark>> {
        #[derive(sqlx::FromRow)]
        struct BookmarkRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            category_id: Option<Vec<u8>>,
            note: Option<String>,
            examiner: Option<String>,
            created_at: i64,
            updated_at: i64,
            category_name: Option<String>,
            category_color: Option<String>,
        }

        let row = sqlx::query_as::<_, BookmarkRow>(
            "SELECT b.id, b.case_id, b.artifact_id, b.category_id, b.note, b.examiner,
                    b.created_at, b.updated_at, c.name as category_name, c.color as category_color
             FROM artifact_bookmarks b
             LEFT JOIN bookmark_categories c ON b.category_id = c.id
             WHERE b.case_id = ? AND b.artifact_id = ?",
        )
        .bind(case_id)
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch artifact bookmark")?;

        if let Some(row) = row {
            Ok(Some(seance_core::models::ArtifactBookmark {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for bookmark ID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
                artifact_id: Uuid::from_slice(&row.artifact_id)
                    .context("Invalid UUID for artifact ID")?,
                category_id: row
                    .category_id
                    .map(|bytes| Uuid::from_slice(&bytes))
                    .transpose()
                    .context("Invalid UUID for category ID")?,
                category_name: row.category_name,
                category_color: row.category_color,
                note: row.note,
                examiner: row.examiner,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// One page of a case's bookmarks, newest-touched first, optionally
    /// filtered by category.
    ///
    /// Order is `(updated_at DESC, id DESC)`. `updated_at` alone is a second
    /// resolution stamp and bookmarks created in one action share it, so an
    /// `updated_at`-only order is not a position: rows tied across a page
    /// boundary would be skipped with nothing to show they existed.
    ///
    /// Callers that must have every bookmark — the CSV and report exports —
    /// page until `has_more` is false, and must carry the summed `undecodable`
    /// into the exhibit. A bookmark list is the examiner's own working set of
    /// findings; an export that is quietly short of it is a court exhibit that
    /// omits findings the examiner made.
    pub async fn list_artifact_bookmarks(
        &self,
        case_id: Uuid,
        category_id: Option<Uuid>,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<seance_core::models::BookmarkWithArtifact>> {
        let limit = clamp_page_size(limit, BOOKMARK_PAGE_MAX);
        #[derive(sqlx::FromRow)]
        struct BookmarkRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            category_id: Option<Vec<u8>>,
            note: Option<String>,
            examiner: Option<String>,
            created_at: i64,
            updated_at: i64,
            category_name: Option<String>,
            category_color: Option<String>,
            artifact_type: String,
            metadata_json: String,
        }

        let mut sql = String::from(
            "SELECT b.id, b.case_id, b.artifact_id, b.category_id, b.note, b.examiner,
                    b.created_at, b.updated_at, c.name as category_name, c.color as category_color,
                    a.artifact_type, a.metadata_json
             FROM artifact_bookmarks b
             LEFT JOIN bookmark_categories c ON b.category_id = c.id
             INNER JOIN artifacts a ON b.artifact_id = a.id AND a.case_id = b.case_id
             WHERE b.case_id = ?",
        );

        if category_id.is_some() {
            sql.push_str(" AND b.category_id = ?");
        }
        sql.push_str(" ORDER BY b.updated_at DESC, b.id DESC LIMIT ? OFFSET ?");

        let mut query = sqlx::query_as::<_, BookmarkRow>(&sql).bind(case_id);
        if let Some(cat_id) = category_id {
            query = query.bind(cat_id);
        }
        let query = query
            .bind(probe_limit(limit))
            .bind(i64::try_from(offset).unwrap_or(i64::MAX));

        let mut rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to list artifact bookmarks")?;

        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let mut undecodable = 0usize;
        let mut bookmarks = Vec::with_capacity(rows.len());
        for row in rows {
            // A bookmark row whose ids will not decode used to fail the whole
            // listing. It is now counted and dropped: the examiner still sees
            // every other finding, and the count says the page is short.
            let (Ok(id), Ok(cid), Ok(aid)) = (
                Uuid::from_slice(&row.id),
                Uuid::from_slice(&row.case_id),
                Uuid::from_slice(&row.artifact_id),
            ) else {
                undecodable += 1;
                continue;
            };
            let category = match row.category_id.as_ref().map(|b| Uuid::from_slice(b)) {
                None => None,
                Some(Ok(c)) => Some(c),
                Some(Err(_)) => {
                    undecodable += 1;
                    continue;
                }
            };

            // Extract artifact name from metadata. Metadata that will not parse
            // must not read as an artifact with no name and no path: the
            // bookmark is kept (the examiner's finding is not dropped) under a
            // marker that says what happened, and the log names the row.
            let parsed = serde_json::from_str::<serde_json::Value>(&row.metadata_json);
            if let Err(e) = &parsed {
                warn!(
                    "case {}: bookmarked artifact {} has unreadable metadata_json ({}); \
                     listing it as '{}'",
                    cid, aid, e, UNREADABLE_METADATA_NAME
                );
            }
            let metadata_readable = parsed.is_ok();
            let metadata = parsed.unwrap_or_else(|_| serde_json::json!({}));
            let artifact_name = if metadata_readable {
                bookmark_display_name(&metadata)
            } else {
                UNREADABLE_METADATA_NAME.to_string()
            };
            // Source-location provenance so a finding can be re-verified against
            // the evidence: the path and the byte offset within the source.
            let source_path = metadata
                .get("path")
                .or_else(|| metadata.get("source_path"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let source_offset = metadata
                .get("offset_bytes")
                .or_else(|| metadata.get("offset"))
                .and_then(|v| v.as_i64());

            bookmarks.push(seance_core::models::BookmarkWithArtifact {
                bookmark: seance_core::models::ArtifactBookmark {
                    id,
                    case_id: cid,
                    artifact_id: aid,
                    category_id: category,
                    category_name: row.category_name,
                    category_color: row.category_color,
                    note: row.note,
                    examiner: row.examiner,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                },
                artifact_type: row.artifact_type,
                artifact_name,
                source_path,
                source_offset,
            });
        }

        if undecodable > 0 {
            warn!(
                "case {}: {} bookmark row(s) would not decode; the bookmark listing is short of \
                 the examiner's own findings and the caller must disclose it",
                case_id, undecodable
            );
        }

        Ok(BoundedList {
            items: bookmarks,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    /// Update an artifact bookmark
    pub async fn update_artifact_bookmark(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        category_id: Option<Uuid>,
        note: Option<&str>,
    ) -> Result<bool> {
        let updated_at = Utc::now().timestamp();

        let result = sqlx::query(
            "UPDATE artifact_bookmarks SET category_id = ?, note = ?, updated_at = ?
             WHERE case_id = ? AND artifact_id = ?",
        )
        .bind(category_id)
        .bind(note)
        .bind(updated_at)
        .bind(case_id)
        .bind(artifact_id)
        .execute(&self.pool)
        .await
        .context("Failed to update artifact bookmark")?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a bookmark for an artifact
    pub async fn delete_artifact_bookmark(&self, case_id: Uuid, artifact_id: Uuid) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM artifact_bookmarks WHERE case_id = ? AND artifact_id = ?")
                .bind(case_id)
                .bind(artifact_id)
                .execute(&self.pool)
                .await
                .context("Failed to delete artifact bookmark")?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all bookmarked artifact IDs for a case
    pub async fn get_bookmarked_artifact_ids(&self, case_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT artifact_id FROM artifact_bookmarks WHERE case_id = ?")
            .bind(case_id)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch bookmarked artifact IDs")?;

        let mut ids = Vec::new();
        for row in rows {
            let artifact_id: Vec<u8> = row.try_get("artifact_id")?;
            ids.push(Uuid::from_slice(&artifact_id).context("Invalid UUID for artifact ID")?);
        }

        Ok(ids)
    }

    /// Get bookmark count for a case
    pub async fn count_bookmarks(&self, case_id: Uuid) -> Result<i64> {
        let result: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM artifact_bookmarks WHERE case_id = ?")
                .bind(case_id)
                .fetch_one(&self.pool)
                .await
                .context("Failed to count bookmarks")?;

        Ok(result.0)
    }

    /// Get bookmark count per category for a case
    pub async fn get_bookmark_counts_by_category(
        &self,
        case_id: Uuid,
    ) -> Result<std::collections::HashMap<Option<Uuid>, i64>> {
        let rows = sqlx::query(
            "SELECT category_id, COUNT(*) as count
             FROM artifact_bookmarks
             WHERE case_id = ?
             GROUP BY category_id",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to count bookmarks by category")?;

        let mut counts = std::collections::HashMap::new();
        for row in rows {
            let category_id: Option<Vec<u8>> = row.try_get("category_id")?;
            let count: i64 = row.try_get("count")?;
            let cat_uuid = category_id
                .map(|bytes| Uuid::from_slice(&bytes))
                .transpose()
                .context("Invalid UUID for category ID")?;
            counts.insert(cat_uuid, count);
        }

        Ok(counts)
    }

    // ── The review ledger ────────────────────────────────────────
    //
    // See migration 0031 for why this lives in the database rather than in the
    // browser, and why OPENED and REVIEWED are two columns rather than one.

    /// The most artifact marks one call will accept.
    ///
    /// Openings arrive in bursts as an examiner scrolls, so the API batches
    /// them; a batch is applied row by row inside one transaction, and this
    /// bounds the work a single request can do. A caller that sends more is
    /// REFUSED, never silently truncated: a truncated batch would leave the
    /// browser believing it had recorded openings the server never saw.
    pub const REVIEW_BATCH_MAX: usize = 1_000;

    /// Apply a batch of review marks for one examiner, stamped with `now`
    /// (epoch seconds).
    ///
    /// Split from [`Self::record_artifact_reviews`] only so the no-backdating
    /// rules can be pinned by a test against a clock it controls; production
    /// callers use the wrapper, which reads the wall clock.
    ///
    /// Every mark is applied against the row's CURRENT state, in the order
    /// given, so a batch that names the same artifact twice ends in the state
    /// its last mark asked for and the returned counts describe the transitions
    /// that actually happened rather than the marks that were sent.
    ///
    /// An artifact id that does not belong to `case_id` is refused and returned
    /// in [`ReviewBatchOutcome::rejected`]. The foreign key alone would accept
    /// it — it only requires the id to exist SOMEWHERE — and a ledger that
    /// accepted another case's artifact would then report an opening against a
    /// case whose examiner never saw it.
    pub async fn record_artifact_reviews_at(
        &self,
        case_id: Uuid,
        examiner: &str,
        marks: &[(Uuid, ReviewMark)],
        now: i64,
    ) -> Result<ReviewBatchOutcome> {
        anyhow::ensure!(
            marks.len() <= Self::REVIEW_BATCH_MAX,
            "a review batch may carry at most {} marks, got {}",
            Self::REVIEW_BATCH_MAX,
            marks.len()
        );
        anyhow::ensure!(
            !examiner.is_empty(),
            "a review must be attributed to an examiner"
        );

        let mut outcome = ReviewBatchOutcome::default();
        if marks.is_empty() {
            return Ok(outcome);
        }

        let case_bytes = case_id.as_bytes().to_vec();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to open a transaction for a review batch")?;

        for (artifact_id, mark) in marks {
            let artifact_bytes = artifact_id.as_bytes().to_vec();

            // The row's current state, and the case-scoping gate, in one read.
            // `in_case` distinguishes "this artifact is not in this case" from
            // "this artifact is in this case and has no ledger row yet"; without
            // it the two would both look like a missing row and the first would
            // silently become an insert.
            let existing: Option<(i64, Option<i64>)> = sqlx::query_as(
                "SELECT opened_at, reviewed_at FROM artifact_reviews \
                 WHERE case_id = ? AND artifact_id = ? AND examiner = ?",
            )
            .bind(&case_bytes)
            .bind(&artifact_bytes)
            .bind(examiner)
            .fetch_optional(&mut *tx)
            .await
            .context("Failed to read the current review state")?;

            if existing.is_none() {
                let in_case: Option<(i64,)> =
                    sqlx::query_as("SELECT 1 FROM artifacts WHERE id = ? AND case_id = ?")
                        .bind(&artifact_bytes)
                        .bind(&case_bytes)
                        .fetch_optional(&mut *tx)
                        .await
                        .context("Failed to verify the artifact's case")?;
                if in_case.is_none() {
                    outcome.rejected.push(*artifact_id);
                    continue;
                }
            }

            match (mark, existing) {
                // First contact with this artifact: an opening, stamped now.
                (ReviewMark::Opened, None) => {
                    Self::insert_review_row(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        now,
                        None,
                    )
                    .await?;
                    Self::append_review_event(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        "opened",
                        now,
                    )
                    .await?;
                    outcome.openings_recorded += 1;
                }
                // Already opened. `opened_at` is the FIRST opening and stays put.
                (ReviewMark::Opened, Some(_)) => outcome.unchanged += 1,

                // Reviewed with nothing on file: the opening is recorded at the
                // instant it happened. It is not backdated to some earlier
                // moment the examiner might have first seen the row, because
                // nothing here knows when — or whether — that was.
                (ReviewMark::Reviewed, None) => {
                    Self::insert_review_row(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        now,
                        Some(now),
                    )
                    .await?;
                    Self::append_review_event(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        "opened",
                        now,
                    )
                    .await?;
                    Self::append_review_event(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        "reviewed",
                        now,
                    )
                    .await?;
                    outcome.openings_recorded += 1;
                    outcome.reviews_recorded += 1;
                }
                (ReviewMark::Reviewed, Some((_, Some(_)))) => outcome.unchanged += 1,
                (ReviewMark::Reviewed, Some((_, None))) => {
                    sqlx::query(
                        "UPDATE artifact_reviews SET reviewed_at = ? \
                         WHERE case_id = ? AND artifact_id = ? AND examiner = ?",
                    )
                    .bind(now)
                    .bind(&case_bytes)
                    .bind(&artifact_bytes)
                    .bind(examiner)
                    .execute(&mut *tx)
                    .await
                    .context("Failed to record a review")?;
                    Self::append_review_event(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        "reviewed",
                        now,
                    )
                    .await?;
                    outcome.reviews_recorded += 1;
                }

                // Withdrawal. The row survives with its opening intact, and the
                // withdrawal is APPENDED to the history rather than erasing the
                // review that was made. A review made and retracted and a review
                // never made are different facts about the examination.
                (ReviewMark::Unreviewed, Some((_, Some(_)))) => {
                    sqlx::query(
                        "UPDATE artifact_reviews SET reviewed_at = NULL \
                         WHERE case_id = ? AND artifact_id = ? AND examiner = ?",
                    )
                    .bind(&case_bytes)
                    .bind(&artifact_bytes)
                    .bind(examiner)
                    .execute(&mut *tx)
                    .await
                    .context("Failed to withdraw a review")?;
                    Self::append_review_event(
                        &mut tx,
                        &case_bytes,
                        &artifact_bytes,
                        examiner,
                        "review_withdrawn",
                        now,
                    )
                    .await?;
                    outcome.reviews_withdrawn += 1;
                }
                // Nothing to withdraw. In particular this must NOT create a row:
                // "unreview something I never reviewed" is not an assertion that
                // I opened it.
                (ReviewMark::Unreviewed, _) => outcome.unchanged += 1,
            }
        }

        tx.commit()
            .await
            .context("Failed to commit a review batch")?;

        debug!(
            "Review batch for case {} by {}: {} opening(s), {} review(s), {} withdrawal(s), \
             {} unchanged, {} rejected",
            case_id,
            examiner,
            outcome.openings_recorded,
            outcome.reviews_recorded,
            outcome.reviews_withdrawn,
            outcome.unchanged,
            outcome.rejected.len()
        );
        Ok(outcome)
    }

    /// [`Self::record_artifact_reviews_at`] stamped with the wall clock.
    pub async fn record_artifact_reviews(
        &self,
        case_id: Uuid,
        examiner: &str,
        marks: &[(Uuid, ReviewMark)],
    ) -> Result<ReviewBatchOutcome> {
        self.record_artifact_reviews_at(case_id, examiner, marks, Utc::now().timestamp())
            .await
    }

    async fn insert_review_row(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        case_bytes: &[u8],
        artifact_bytes: &[u8],
        examiner: &str,
        opened_at: i64,
        reviewed_at: Option<i64>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO artifact_reviews (case_id, artifact_id, examiner, opened_at, reviewed_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(case_bytes)
        .bind(artifact_bytes)
        .bind(examiner)
        .bind(opened_at)
        .bind(reviewed_at)
        .execute(&mut **tx)
        .await
        .context("Failed to record an artifact opening")?;
        Ok(())
    }

    async fn append_review_event(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        case_bytes: &[u8],
        artifact_bytes: &[u8],
        examiner: &str,
        action: &str,
        at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO artifact_review_events (id, case_id, artifact_id, examiner, action, at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4())
        .bind(case_bytes)
        .bind(artifact_bytes)
        .bind(examiner)
        .bind(action)
        .bind(at)
        .execute(&mut **tx)
        .await
        .context("Failed to append a review-ledger event")?;
        Ok(())
    }

    /// One examiner's ledger row for one artifact, or `None` when that examiner
    /// has no row for it. `None` means "this examiner has not opened it", never
    /// "opened at time zero".
    pub async fn get_artifact_review(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        examiner: &str,
    ) -> Result<Option<ArtifactReviewRow>> {
        let row: Option<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT opened_at, reviewed_at FROM artifact_reviews \
             WHERE case_id = ? AND artifact_id = ? AND examiner = ?",
        )
        .bind(case_id)
        .bind(artifact_id)
        .bind(examiner)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to read a review row")?;

        Ok(row.map(|(opened_at, reviewed_at)| ArtifactReviewRow {
            artifact_id,
            examiner: examiner.to_string(),
            opened_at,
            reviewed_at,
        }))
    }

    /// The DISTINCT artifact ids in one review state, capped at `cap`, plus the
    /// exact size of the set the cap was applied to.
    ///
    /// The cap and the total are both returned because the client marks rows in
    /// a grid from this list: a list that stopped at its ceiling would otherwise
    /// leave every artifact past it rendered as never-opened, which is a false
    /// absence rather than a missing convenience.
    ///
    /// `examiner` scopes the question. `None` asks it of the whole case — "has
    /// ANYBODY opened this?", which is what a handover needs — and `Some(name)`
    /// asks it of one person. The distinction is never inferred; callers state
    /// it and responses repeat it back.
    pub async fn artifact_review_ids(
        &self,
        case_id: Uuid,
        state: ReviewIdState,
        examiner: Option<&str>,
        cap: usize,
    ) -> Result<ReviewIdPage> {
        // Structure is fixed; only bound values vary.
        let state_clause = match state {
            ReviewIdState::Opened => "",
            ReviewIdState::Reviewed => " AND reviewed_at IS NOT NULL",
        };
        let examiner_clause = if examiner.is_some() {
            " AND examiner = ?"
        } else {
            ""
        };

        let count_sql = format!(
            "SELECT COUNT(DISTINCT artifact_id) FROM artifact_reviews \
             WHERE case_id = ?{state_clause}{examiner_clause}"
        );
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(case_id);
        if let Some(name) = examiner {
            count_q = count_q.bind(name);
        }
        let total: i64 = count_q
            .fetch_one(&self.pool)
            .await
            .context("Failed to count review-ledger ids")?;

        // Fetch one row past the cap so "returned == cap" cannot be mistaken for
        // "the set is exactly cap large".
        let fetch = cap.saturating_add(1);
        let page_sql = format!(
            "SELECT DISTINCT artifact_id FROM artifact_reviews \
             WHERE case_id = ?{state_clause}{examiner_clause} \
             ORDER BY artifact_id LIMIT {fetch}"
        );
        let mut page_q = sqlx::query_scalar::<_, Vec<u8>>(&page_sql).bind(case_id);
        if let Some(name) = examiner {
            page_q = page_q.bind(name);
        }
        let rows = page_q
            .fetch_all(&self.pool)
            .await
            .context("Failed to list review-ledger ids")?;

        let capped = rows.len() > cap;
        let mut ids = Vec::with_capacity(rows.len().min(cap));
        for bytes in rows.into_iter().take(cap) {
            ids.push(Uuid::from_slice(&bytes).context("Invalid UUID in the review ledger")?);
        }
        Ok(ReviewIdPage {
            ids,
            total,
            capped,
            cap,
        })
    }

    /// Per-examiner and case-wide review counts, plus the case's artifact
    /// population.
    ///
    /// The population is what makes a denominator honest: a panel that prints
    /// "412 reviewed" without one is a number an examiner cannot act on and a
    /// number a court cannot check. It is the count of EVERY artifact row
    /// recorded in the case, of every type — the caller must name that
    /// population when it renders it, because it includes rows nobody would ever
    /// open individually (containers, filesystems, partitions).
    pub async fn artifact_review_stats(&self, case_id: Uuid) -> Result<ArtifactReviewStats> {
        #[derive(sqlx::FromRow)]
        struct ExaminerRow {
            examiner: String,
            opened: i64,
            reviewed: i64,
            first_opened_at: i64,
            last_activity_at: i64,
        }

        let per_examiner: Vec<ExaminerRow> = sqlx::query_as(
            // `opened` is COUNT(*) because every ledger row IS an opening, and
            // `reviewed` counts the non-null review stamps. They are reported
            // separately and are never added together: the reviewed set is a
            // SUBSET of the opened set, so a sum would double-count every
            // cleared artifact.
            "SELECT examiner, \
                    COUNT(*) AS opened, \
                    COUNT(reviewed_at) AS reviewed, \
                    MIN(opened_at) AS first_opened_at, \
                    MAX(MAX(opened_at), MAX(COALESCE(reviewed_at, opened_at))) AS last_activity_at \
             FROM artifact_reviews WHERE case_id = ? \
             GROUP BY examiner ORDER BY examiner",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to roll up review counts by examiner")?;

        let distinct_opened: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT artifact_id) FROM artifact_reviews WHERE case_id = ?",
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count opened artifacts")?;

        let distinct_reviewed: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT artifact_id) FROM artifact_reviews \
             WHERE case_id = ? AND reviewed_at IS NOT NULL",
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count reviewed artifacts")?;

        let case_artifact_total = self.count_total_artifacts(case_id).await?;

        Ok(ArtifactReviewStats {
            per_examiner: per_examiner
                .into_iter()
                .map(|r| ExaminerReviewCounts {
                    examiner: r.examiner,
                    opened: r.opened,
                    reviewed: r.reviewed,
                    first_opened_at: r.first_opened_at,
                    last_activity_at: r.last_activity_at,
                })
                .collect(),
            distinct_opened,
            distinct_reviewed,
            case_artifact_total,
        })
    }

    /// The append-only transition history, oldest first.
    ///
    /// This is the half of the ledger that survives a withdrawal. Optionally
    /// narrowed to one artifact and/or one examiner; `limit` bounds the walk and
    /// the caller is expected to say when it bound it.
    pub async fn artifact_review_history(
        &self,
        case_id: Uuid,
        artifact_id: Option<Uuid>,
        examiner: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ArtifactReviewEvent>> {
        #[derive(sqlx::FromRow)]
        struct EventRow {
            artifact_id: Vec<u8>,
            examiner: String,
            action: String,
            at: i64,
        }

        let artifact_clause = if artifact_id.is_some() {
            " AND artifact_id = ?"
        } else {
            ""
        };
        let examiner_clause = if examiner.is_some() {
            " AND examiner = ?"
        } else {
            ""
        };
        // `rowid` breaks ties: several transitions can share one second (a
        // review recorded in the same batch as the opening it implies), and
        // ordering on `at` alone would let them print in an order that reads as
        // a review preceding its own opening.
        let sql = format!(
            "SELECT artifact_id, examiner, action, at FROM artifact_review_events \
             WHERE case_id = ?{artifact_clause}{examiner_clause} \
             ORDER BY at ASC, rowid ASC LIMIT {limit}"
        );
        let mut q = sqlx::query_as::<_, EventRow>(&sql).bind(case_id);
        if let Some(id) = artifact_id {
            q = q.bind(id);
        }
        if let Some(name) = examiner {
            q = q.bind(name);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to read the review-ledger history")?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(ArtifactReviewEvent {
                artifact_id: Uuid::from_slice(&row.artifact_id)
                    .context("Invalid UUID in the review-ledger history")?,
                examiner: row.examiner,
                action: row.action,
                at: row.at,
            });
        }
        Ok(events)
    }

    /// Get timeline events that have been tagged (for report generation)
    pub async fn get_tagged_timeline_events(
        &self,
        case_id: Uuid,
    ) -> Result<
        Vec<(
            seance_core::models::TimelineEventResponse,
            String,
            Option<String>,
        )>,
    > {
        #[derive(sqlx::FromRow)]
        struct TaggedEventRow {
            event_id: Vec<u8>,
            case_id: Vec<u8>,
            artifact_id: Vec<u8>,
            timestamp: i64,
            timestamp_desc: String,
            source_module: String,
            short_desc: String,
            full_details: String,
            timestamp_subsec_nanos: i64,
            source_utc_offset_seconds: Option<i32>,
            tag_note: Option<String>,
            tag_examiner: Option<String>,
        }

        let rows = sqlx::query_as::<_, TaggedEventRow>(
            "SELECT te.id as event_id, te.case_id, te.artifact_id, te.timestamp,
                    te.timestamp_subsec_nanos, te.source_utc_offset_seconds,
                    te.timestamp_desc, te.source_module, te.short_desc, te.full_details,
                    tt.note as tag_note, tt.examiner as tag_examiner
             FROM timeline_events te
             INNER JOIN timeline_tags tt ON te.artifact_id = tt.event_id AND te.case_id = tt.case_id
             WHERE te.case_id = ?
             ORDER BY te.timestamp ASC, te.timestamp_subsec_nanos ASC, te.id ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch tagged timeline events")?;

        let mut results = Vec::new();
        for row in rows {
            let event = seance_core::models::TimelineEventResponse {
                id: Uuid::from_slice(&row.event_id).context("Invalid UUID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID")?,
                artifact_id: Uuid::from_slice(&row.artifact_id).context("Invalid UUID")?,
                timestamp: row.timestamp,
                timestamp_subsec_nanos: row.timestamp_subsec_nanos,
                source_utc_offset_seconds: row.source_utc_offset_seconds,
                timestamp_desc: row.timestamp_desc,
                source_module: row.source_module,
                short_desc: row.short_desc,
                full_details: row.full_details,
                is_tagged: Some(true),
                tag_note: row.tag_note.clone(),
                dynamic_fields: None,
            };
            results.push((
                event,
                row.tag_examiner.clone().unwrap_or_default(),
                row.tag_note,
            ));
        }

        Ok(results)
    }

    /// Get evidence source artifacts for a case (RawEvidence type)
    pub async fn get_evidence_sources(&self, case_id: Uuid) -> Result<Vec<(Uuid, String, String)>> {
        #[derive(sqlx::FromRow)]
        struct SourceRow {
            id: Vec<u8>,
            artifact_type: String,
            metadata_json: String,
        }

        let rows = sqlx::query_as::<_, SourceRow>(
            "SELECT id, artifact_type, metadata_json
             FROM artifacts
             WHERE case_id = ? AND artifact_type IN ('RawEvidence', 'Container')
             ORDER BY created_at ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch evidence sources")?;

        let mut results = Vec::new();
        for row in rows {
            let id = Uuid::from_slice(&row.id).context("Invalid UUID")?;
            let metadata: serde_json::Value =
                serde_json::from_str(&row.metadata_json).unwrap_or_else(|_| serde_json::json!({}));
            let name = metadata
                .get("name")
                .or_else(|| metadata.get("filename"))
                .or_else(|| metadata.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            results.push((id, name, row.artifact_type));
        }

        Ok(results)
    }

    // Hash Set Management

    /// Create a new hash set
    pub async fn create_hash_set(
        &self,
        case_id: Uuid,
        name: &str,
        description: Option<&str>,
        set_type: &str,
        hash_algorithm: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let imported_at = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO hash_sets (id, case_id, name, description, set_type, hash_algorithm, entry_count, imported_at)
             VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        )
        .bind(id)
        .bind(case_id)
        .bind(name)
        .bind(description)
        .bind(set_type)
        .bind(hash_algorithm)
        .bind(imported_at)
        .execute(&self.pool)
        .await
        .context("Failed to create hash set")?;

        info!("Created hash set '{}' for case {}", name, case_id);
        Ok(id)
    }

    /// List all hash sets for a case
    pub async fn list_hash_sets(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<seance_core::models::HashSetInfo>> {
        #[derive(sqlx::FromRow)]
        struct HashSetRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            name: String,
            description: Option<String>,
            set_type: String,
            hash_algorithm: String,
            entry_count: i64,
            imported_at: i64,
        }

        let rows = sqlx::query_as::<_, HashSetRow>(
            "SELECT id, case_id, name, description, set_type, hash_algorithm, entry_count, imported_at
             FROM hash_sets WHERE case_id = ? ORDER BY imported_at DESC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list hash sets")?;

        let mut results = Vec::new();
        for row in rows {
            results.push(seance_core::models::HashSetInfo {
                id: Uuid::from_slice(&row.id).context("Invalid UUID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID")?,
                name: row.name,
                description: row.description,
                set_type: row.set_type,
                hash_algorithm: row.hash_algorithm,
                entry_count: row.entry_count,
                imported_at: row.imported_at,
            });
        }

        Ok(results)
    }

    /// Delete a hash set and all its entries
    pub async fn delete_hash_set(&self, case_id: Uuid, hash_set_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM hash_sets WHERE id = ? AND case_id = ?")
            .bind(hash_set_id)
            .bind(case_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete hash set")?;

        Ok(result.rows_affected() > 0)
    }

    /// Import hash set entries in batch
    pub async fn import_hash_set_entries(
        &self,
        hash_set_id: Uuid,
        entries: &[(String, Option<String>)], // (hash_value, product_name)
    ) -> Result<usize> {
        let chunk_size = 500;
        let mut total_imported = 0;

        for chunk in entries.chunks(chunk_size) {
            let mut query = String::from(
                "INSERT OR IGNORE INTO hash_set_entries (hash_value, hash_set_id, product_name) VALUES "
            );
            let mut first = true;
            for _ in chunk {
                if !first {
                    query.push(',');
                }
                query.push_str("(?, ?, ?)");
                first = false;
            }

            let mut q = sqlx::query(&query);
            for (hash, product) in chunk {
                q = q.bind(hash).bind(hash_set_id).bind(product);
            }

            let result = q
                .execute(&self.pool)
                .await
                .context("Failed to import hash set entries")?;
            total_imported += result.rows_affected() as usize;
        }

        // Update entry count
        sqlx::query(
            "UPDATE hash_sets SET entry_count = (SELECT COUNT(*) FROM hash_set_entries WHERE hash_set_id = ?) WHERE id = ?",
        )
        .bind(hash_set_id)
        .bind(hash_set_id)
        .execute(&self.pool)
        .await
        .context("Failed to update hash set entry count")?;

        Ok(total_imported)
    }

    /// Import VICS entries carrying a category and the preserved attribute bundle.
    ///
    /// Each tuple is `(hash_value, vics_category, vics_attrs_json)`. This is the
    /// category-aware sibling of [`import_hash_set_entries`]; the two share the
    /// same table, so a VICS-imported set behaves like any other hash set for
    /// matching while additionally carrying the category an examiner needs.
    pub async fn import_vics_entries(
        &self,
        hash_set_id: Uuid,
        entries: &[(String, Option<i64>, Option<String>)],
    ) -> Result<usize> {
        let chunk_size = 400;
        let mut total_imported = 0;
        for chunk in entries.chunks(chunk_size) {
            let mut query = String::from(
                "INSERT OR IGNORE INTO hash_set_entries (hash_value, hash_set_id, vics_category, vics_attrs) VALUES ",
            );
            let mut first = true;
            for _ in chunk {
                if !first {
                    query.push(',');
                }
                query.push_str("(?, ?, ?, ?)");
                first = false;
            }
            let mut q = sqlx::query(&query);
            for (hash, cat, attrs) in chunk {
                q = q.bind(hash).bind(hash_set_id).bind(cat).bind(attrs);
            }
            let result = q
                .execute(&self.pool)
                .await
                .context("Failed to import VICS entries")?;
            total_imported += result.rows_affected() as usize;
        }
        sqlx::query(
            "UPDATE hash_sets SET entry_count = (SELECT COUNT(*) FROM hash_set_entries WHERE hash_set_id = ?) WHERE id = ?",
        )
        .bind(hash_set_id)
        .bind(hash_set_id)
        .execute(&self.pool)
        .await
        .context("Failed to update hash set entry count")?;
        Ok(total_imported)
    }

    /// Read back a hash set's entries with their VICS category and attributes,
    /// for exporting to a VICS-compatible JSON. Each tuple is
    /// `(hash_value, vics_category, vics_attrs_json)`.
    pub async fn list_vics_entries(
        &self,
        hash_set_id: Uuid,
    ) -> Result<Vec<(String, Option<i64>, Option<String>)>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            hash_value: String,
            vics_category: Option<i64>,
            vics_attrs: Option<String>,
        }
        let rows = sqlx::query_as::<_, Row>(
            "SELECT hash_value, vics_category, vics_attrs FROM hash_set_entries WHERE hash_set_id = ? ORDER BY hash_value",
        )
        .bind(hash_set_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to read VICS entries")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.hash_value, r.vics_category, r.vics_attrs))
            .collect())
    }

    /// The statement [`Self::lookup_hash`] runs: `(case_id, hash_value)`.
    ///
    /// Compares `LOWER(e.hash_value)` so it rides
    /// `idx_hash_set_entries_lower_hash` (migration 0047); a plain column
    /// comparison, or a different spelling of the expression, would scan every
    /// entry of every set. Public so the plan test EXPLAINs what ships.
    pub const HASH_LOOKUP_SQL: &'static str =
        "SELECT e.hash_value, e.product_name, e.hash_set_id, hs.name as hash_set_name, hs.set_type \
         FROM hash_set_entries e \
         INNER JOIN hash_sets hs ON e.hash_set_id = hs.id \
         WHERE hs.case_id = ? AND LOWER(e.hash_value) = LOWER(?)";

    /// Look up a hash value across all hash sets for a case.
    ///
    /// Matching is on the hex VALUE, case-insensitively, and MUST NOT be filtered
    /// by the set's declared `hash_algorithm`. A single set can legitimately hold
    /// digests of more than one algorithm: a Project VIC / VICS import stores both
    /// the MD5 (32 hex) and the SHA-1 (40 hex) of each medium as separate entries
    /// under one set whose `hash_algorithm` label names only one of them. A
    /// digest's length already identifies its algorithm, so the value match is
    /// exact regardless of the label. Adding a label filter here would drop the
    /// entries whose algorithm differs from the set's advertised one — turning a
    /// known-CSAM file that VICS flagged by its SHA-1 into an unremarkable,
    /// unflagged file. Do not "optimise" this by joining on `hash_algorithm`.
    pub async fn lookup_hash(
        &self,
        case_id: Uuid,
        hash_value: &str,
    ) -> Result<Vec<seance_core::models::HashSetMatch>> {
        #[derive(sqlx::FromRow)]
        struct MatchRow {
            hash_value: String,
            product_name: Option<String>,
            hash_set_id: Vec<u8>,
            hash_set_name: String,
            set_type: String,
        }

        let rows = sqlx::query_as::<_, MatchRow>(Self::HASH_LOOKUP_SQL)
            .bind(case_id)
            .bind(hash_value)
            .fetch_all(&self.pool)
            .await
            .context("Failed to lookup hash")?;

        let mut results = Vec::new();
        for row in rows {
            results.push(seance_core::models::HashSetMatch {
                hash_value: row.hash_value,
                hash_set_name: row.hash_set_name,
                hash_set_id: Uuid::from_slice(&row.hash_set_id).context("Invalid UUID")?,
                set_type: row.set_type,
                product_name: row.product_name,
            });
        }

        Ok(results)
    }

    /// Case-wide list of artifacts whose recorded md5/sha1/sha256 metadata
    /// hash matches a hash-set entry, optionally restricted to one hash set.
    /// Returns (page of hits, total hit count). One row per
    /// (artifact, hash set, matched hash) combination.
    pub async fn list_hash_hits(
        &self,
        case_id: Uuid,
        hash_set_id: Option<Uuid>,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<HashHitRow>, i64)> {
        #[derive(sqlx::FromRow)]
        struct HitDbRow {
            id: Vec<u8>,
            name: Option<String>,
            path: Option<String>,
            hash_set_id: Vec<u8>,
            hash_set_name: String,
            matched_hash: String,
            algorithm: String,
        }

        let body = Self::hash_hits_body_sql(hash_set_id.is_some());

        let page = page.max(1);
        let offset = (page as i64 - 1) * page_size as i64;
        let select_sql = format!(
            "SELECT a.id, a.name, a.path, e.hash_set_id, hs.name AS hash_set_name, \
                    e.hash_value AS matched_hash, \
                    CASE \
                        WHEN LOWER(e.hash_value) = LOWER(a.md5_hash) THEN 'md5' \
                        WHEN LOWER(e.hash_value) = LOWER(a.sha1_hash) THEN 'sha1' \
                        ELSE 'sha256' \
                    END AS algorithm \
             {body} ORDER BY a.name ASC, a.id ASC, e.hash_set_id ASC \
             LIMIT {page_size} OFFSET {offset}"
        );
        let count_sql = format!("SELECT COUNT(*) AS count {body}");

        let case_id_bytes = case_id.as_bytes().to_vec();
        let set_id_bytes = hash_set_id.map(|id| id.as_bytes().to_vec());

        let mut count_q = sqlx::query(&count_sql)
            .bind(&case_id_bytes)
            .bind(&case_id_bytes);
        if let Some(ref set_id) = set_id_bytes {
            count_q = count_q.bind(set_id);
        }
        let total: i64 = count_q
            .fetch_one(&self.pool)
            .await
            .context("Failed to count hash hits")?
            .try_get("count")?;

        let mut rows_q = sqlx::query_as::<_, HitDbRow>(&select_sql)
            .bind(&case_id_bytes)
            .bind(&case_id_bytes);
        if let Some(ref set_id) = set_id_bytes {
            rows_q = rows_q.bind(set_id);
        }
        let rows = rows_q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch hash hits")?;

        let mut hits = Vec::with_capacity(rows.len());
        for row in rows {
            hits.push(HashHitRow {
                artifact_id: Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID")?,
                name: row.name,
                path: row.path,
                hash_set_id: Uuid::from_slice(&row.hash_set_id)
                    .context("Invalid UUID for hash set ID")?,
                hash_set_name: row.hash_set_name,
                matched_hash: row.matched_hash,
                algorithm: row.algorithm,
            });
        }

        Ok((hits, total))
    }

    /// Apply a computed per-file hash to an existing artifact: populate the
    /// indexed md5_hash/sha1_hash/sha256_hash columns and merge the
    /// md5/sha1/sha256 keys into metadata_json (so the Overview and export
    /// read them directly). A no-op (with a warning) if no artifact matches,
    /// which can happen if the parent has not yet been persisted.
    ///
    /// `case_id` is part of the WHERE clause, not decoration: the ids arrive
    /// from the worker pipeline, and a corrupt or cross-case `parent_id` must
    /// not be able to write digests onto another case's evidence (B4-030).
    pub async fn apply_file_hash(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        md5: &str,
        sha1: &str,
        sha256: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE artifacts SET \
                md5_hash = ?, sha1_hash = ?, sha256_hash = ?, \
                metadata_json = json_set(metadata_json, '$.md5', ?, '$.sha1', ?, '$.sha256', ?) \
             WHERE id = ? AND case_id = ?",
        )
        .bind(md5)
        .bind(sha1)
        .bind(sha256)
        .bind(md5)
        .bind(sha1)
        .bind(sha256)
        .bind(artifact_id)
        .bind(case_id)
        .execute(&self.pool)
        .await
        .context("Failed to apply file hash to artifact")?;

        // 0 rows means the parent isn't persisted yet; the orchestrator retries
        // on the next writer flush, so no warning here (it is the normal case).
        Ok(result.rows_affected())
    }

    /// Apply many per-file hashes in ONE transaction instead of one autocommit
    /// UPDATE per file. Each row still merges its hashes via json_set, but the
    /// whole flush commits once, collapsing tens of thousands of tiny
    /// transactions into a single write. Returns the parent ids that matched no
    /// row (parent not yet persisted) so the caller can retry them.
    /// Each entry is `(case_id, artifact_id, md5, sha1, sha256)`; the case scopes
    /// every UPDATE so a corrupt cross-case parent id cannot write digests onto
    /// another case's evidence (B4-030).
    pub async fn apply_file_hashes_batch(
        &self,
        hashes: &[(Uuid, Uuid, String, String, String)],
    ) -> Result<Vec<Uuid>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin file-hash batch transaction")?;
        let mut missed = Vec::new();
        for (case_id, id, md5, sha1, sha256) in hashes {
            let result = sqlx::query(
                "UPDATE artifacts SET \
                    md5_hash = ?, sha1_hash = ?, sha256_hash = ?, \
                    metadata_json = json_set(metadata_json, '$.md5', ?, '$.sha1', ?, '$.sha256', ?) \
                 WHERE id = ? AND case_id = ?",
            )
            .bind(md5.as_str())
            .bind(sha1.as_str())
            .bind(sha256.as_str())
            .bind(md5.as_str())
            .bind(sha1.as_str())
            .bind(sha256.as_str())
            .bind(*id)
            .bind(*case_id)
            .execute(&mut *tx)
            .await
            .context("Failed to apply file hash in batch")?;
            if result.rows_affected() == 0 {
                missed.push(*id);
            }
        }
        tx.commit()
            .await
            .context("Failed to commit file-hash batch transaction")?;
        Ok(missed)
    }

    /// Record on each parent artifact that its content hash was NOT computed,
    /// and why. Entries are `(case_id, artifact_id, reason)`.
    ///
    /// The hasher emits a `file_hash` record carrying `hash_skipped` instead of
    /// digests when it refuses (file over the size ceiling) or fails (short
    /// read) to hash a file. Those records used to be discarded, leaving the
    /// parent with empty hash columns and nothing to say why — identical, to an
    /// examiner, to a file that was hashed and matched nothing.
    ///
    /// Writes the standard incompleteness pair plus the specific reason:
    /// `content_incomplete` (boolean true), `content_incomplete_reason`
    /// (`"hash_skipped_<reason>"`) and `hash_skipped` (the raw reason).
    /// Returns the artifact ids that matched no row so the caller can retry
    /// once the parent has been flushed.
    pub async fn mark_file_hashes_skipped_batch(
        &self,
        skips: &[(Uuid, Uuid, String)],
    ) -> Result<Vec<Uuid>> {
        if skips.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin hash-skipped batch transaction")?;
        let mut missed = Vec::new();
        for (case_id, id, reason) in skips {
            let result = sqlx::query(
                "UPDATE artifacts SET \
                    metadata_json = json_set(metadata_json, \
                        '$.content_incomplete', json('true'), \
                        '$.content_incomplete_reason', ?, \
                        '$.hash_skipped', ?) \
                 WHERE id = ? AND case_id = ?",
            )
            .bind(format!("hash_skipped_{reason}"))
            .bind(reason.as_str())
            .bind(*id)
            .bind(*case_id)
            .execute(&mut *tx)
            .await
            .context("Failed to mark file hash as skipped in batch")?;
            if result.rows_affected() == 0 {
                missed.push(*id);
            }
        }
        tx.commit()
            .await
            .context("Failed to commit hash-skipped batch transaction")?;
        Ok(missed)
    }

    /// The `FROM .. WHERE` shared by [`Self::list_hash_hits`] and
    /// [`Self::count_hash_matches_for_case`]: binds `(case_id, case_id)` and,
    /// when `by_set`, a hash-set id.
    ///
    /// Matches the artifacts' indexed md5_hash/sha1_hash/sha256_hash columns
    /// (populated on insert and by apply_file_hash) case-insensitively against
    /// `LOWER(e.hash_value)`, the expression `idx_hash_set_entries_lower_hash`
    /// (migration 0047) is declared on. `CROSS JOIN` plus `INDEXED BY` pin the
    /// loop order (artifacts outer, entries sought): left to itself the planner
    /// walks `hash_sets` -> every entry of the set -> every case artifact, which
    /// is quadratic. The same pin is on [`Self::KNOWN_STATUS_SQL`] and
    /// [`Self::known_any_match_sql`]. Public so the plan test EXPLAINs what
    /// ships.
    pub fn hash_hits_body_sql(by_set: bool) -> String {
        let set_filter = if by_set { " AND e.hash_set_id = ?" } else { "" };
        format!(
            "FROM artifacts a \
             CROSS JOIN hash_set_entries e INDEXED BY idx_hash_set_entries_lower_hash \
                 ON LOWER(e.hash_value) IN ( \
                 LOWER(a.md5_hash), \
                 LOWER(a.sha1_hash), \
                 LOWER(a.sha256_hash)) \
             JOIN hash_sets hs ON hs.id = e.hash_set_id \
             WHERE a.case_id = ? AND hs.case_id = ?{set_filter}"
        )
    }

    /// The file grid's per-row `known_status` projection: `'notable'` if any
    /// matching case hash set is a notable set, else `'known'` if any matches,
    /// else NULL. Correlated, so it runs for the displayed page only; it
    /// compares `LOWER(hse.hash_value)` to ride
    /// `idx_hash_set_entries_lower_hash` (migration 0047). Public so the plan
    /// test EXPLAINs what ships.
    pub const KNOWN_STATUS_SQL: &'static str = "(SELECT CASE \
                 WHEN MAX(hs.set_type = 'notable') = 1 THEN 'notable' \
                 WHEN COUNT(*) > 0 THEN 'known' \
                 ELSE NULL END \
             FROM hash_set_entries hse INDEXED BY idx_hash_set_entries_lower_hash \
             CROSS JOIN hash_sets hs ON hs.id = hse.hash_set_id \
             WHERE hs.case_id = a.case_id \
               AND LOWER(hse.hash_value) IN (LOWER(a.md5_hash), LOWER(a.sha1_hash), LOWER(a.sha256_hash)))";

    /// The subquery behind the file grid's known-status filter: ids of the
    /// case's artifacts that match any entry of any of the case's hash sets
    /// (callers append `AND hs.set_type = 'notable'` for the notable subset).
    /// `case_id` is a typed `Uuid`, embedded as a blob literal -- no user text.
    /// Compares `LOWER(hse.hash_value)` to ride `idx_hash_set_entries_lower_hash`
    /// (migration 0047). Public so the plan test EXPLAINs what ships.
    pub fn known_any_match_sql(case_id: Uuid) -> String {
        let case_hex = case_id.simple();
        format!(
            "SELECT a2.id FROM artifacts a2 \
             CROSS JOIN hash_set_entries hse INDEXED BY idx_hash_set_entries_lower_hash \
                 ON LOWER(hse.hash_value) IN (LOWER(a2.md5_hash), LOWER(a2.sha1_hash), LOWER(a2.sha256_hash)) \
             JOIN hash_sets hs ON hs.id = hse.hash_set_id \
             WHERE a2.case_id = X'{case_hex}' AND hs.case_id = X'{case_hex}'"
        )
    }

    /// Count the distinct artifacts in a case whose recorded hash matches an
    /// entry in any of the case's hash sets (known-file / notable-file count
    /// for dashboards and filtering).
    pub async fn count_hash_matches_for_case(&self, case_id: Uuid) -> Result<i64> {
        let case_id_bytes = case_id.as_bytes().to_vec();
        let row = sqlx::query(&format!(
            "SELECT COUNT(DISTINCT a.id) AS count {}",
            Self::hash_hits_body_sql(false)
        ))
        .bind(&case_id_bytes)
        .bind(&case_id_bytes)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count hash matches for case")?;

        let count: i64 = row.try_get("count")?;
        Ok(count)
    }

    /// The device's own cached thumbnail for a media file, if the evidence
    /// carries one.
    ///
    /// iOS keeps a thumbnail cache whose directory mirrors the original file's
    /// path and whose contents are named by pixel size
    /// (`Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0001.MOV/5003.JPG`).
    /// For a video that is a real device artifact — what the phone itself
    /// displayed — and the only preview available without decoding the video.
    ///
    /// The lookup is bound to the REQUESTING artifact, not just to a basename:
    /// it prefers the cache directory that mirrors this file's own
    /// `relative_path`, and never leaves the ingested source the file came
    /// from. Matching on the basename alone bound the wrong device JPEG to a
    /// file whenever two imports shared a name (BUG-280).
    pub async fn find_cached_media_thumbnail(
        &self,
        case_id: Uuid,
        media_id: Uuid,
        media_name: &str,
    ) -> Result<Option<Uuid>> {
        // Resolve the requesting artifact: its relative path identifies the one
        // cache directory that belongs to it, and its parent scopes the search
        // to the same ingested source.
        let media: Option<(Option<Vec<u8>>, String)> = sqlx::query_as(
            "SELECT parent_id, metadata_json FROM artifacts WHERE id = ? AND case_id = ?",
        )
        .bind(media_id.as_bytes().to_vec())
        .bind(case_id.as_bytes().to_vec())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to resolve the media artifact for a thumbnail lookup")?;
        let Some((parent_id, metadata_json)) = media else {
            return Ok(None);
        };
        let metadata: serde_json::Value =
            serde_json::from_str(&metadata_json).unwrap_or(serde_json::Value::Null);

        // iOS media names contain '_' (e.g. IMG_0001.MOV), which LIKE treats as a
        // single-char wildcard. Escape LIKE metacharacters in the bound value and
        // declare the escape char so the name matches literally -- otherwise
        // IMG_0001 would also match IMGx0001 and select the wrong thumbnail. The
        // literal '%' path separators in the pattern stay wildcards (unescaped).
        let escape_for_like = |s: &str| {
            s.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        };

        // When the file's own path is known, the cache directory that mirrors it
        // is the ONLY directory that can hold its thumbnail. The cache is rooted
        // at `Media/PhotoData/Thumbnails/<ver>/`, so the media's own `Media/`
        // domain prefix is dropped before matching. No match here means the
        // device cached no preview for this file — falling back to the basename
        // would hand back a different file's JPEG.
        let relative = metadata
            .get("relative_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim_start_matches('/');
        let relative = relative.strip_prefix("Media/").unwrap_or(relative);
        if !relative.is_empty() {
            return self
                .cached_thumbnail_lookup(case_id, escape_for_like(relative), parent_id.as_deref())
                .await;
        }

        // No relative_path recorded: fall back to the basename, still confined
        // to the media file's own ingested source.
        if media_name.is_empty() || media_name.contains('%') || media_name.contains('/') {
            return Ok(None);
        }
        self.cached_thumbnail_lookup(case_id, escape_for_like(media_name), parent_id.as_deref())
            .await
    }

    /// One cached-thumbnail lookup: `middle` is the LIKE-escaped path segment
    /// the cache directory must end with, `parent` scopes the search to the
    /// media file's own ingested source when it has one.
    async fn cached_thumbnail_lookup(
        &self,
        case_id: Uuid,
        middle: String,
        parent: Option<&[u8]>,
    ) -> Result<Option<Uuid>> {
        let mut sql = String::from(
            "SELECT id FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'FileEntry' \
               AND json_extract(metadata_json, '$.relative_path') \
                   LIKE 'Media/PhotoData/Thumbnails/%/' || ? || '/%' ESCAPE '\\' \
               AND COALESCE(json_extract(metadata_json, '$.is_directory'), 0) <> 1",
        );
        if parent.is_some() {
            sql.push_str(" AND parent_id = ?");
        }
        sql.push_str(" ORDER BY COALESCE(json_extract(metadata_json, '$.size'), 0) DESC LIMIT 1");

        let mut q = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(middle);
        if let Some(p) = parent {
            q = q.bind(p.to_vec());
        }
        let row = q
            .fetch_optional(&self.pool)
            .await
            .context("Failed to look up a cached media thumbnail")?;

        Ok(row
            .and_then(|r| r.try_get::<Vec<u8>, _>("id").ok())
            .and_then(|b| Uuid::from_slice(&b).ok()))
    }

    /// Thread key for platforms whose parsers all record the correspondent the
    /// same way (`chat_identifier`, or a conversation/thread id).
    ///
    /// Used for Skype, LINE, Telegram, Viber, Kik, WeChat and Facebook
    /// Messenger. Before they were listed, `thread_key_expr` returned `None` for
    /// them and every conversation query answered with an EMPTY list — the
    /// messages were parsed and stored, but the Conversations view reported the
    /// case had no threads at all, which reads as "this phone had no chats".
    const GENERIC_THREAD_KEY: &'static str =
        "COALESCE(json_extract(a.metadata_json,'$.chat_identifier'), \
         json_extract(a.metadata_json,'$.chat_display_name'), \
         json_extract(a.metadata_json,'$.conversation_id'), \
         json_extract(a.metadata_json,'$.thread_id'), \
         json_extract(a.metadata_json,'$.contact'), 'unknown')";

    /// SQL expression selecting a messaging record's thread key, per platform.
    ///
    /// Hardcoded per record type — never built from client input — because it
    /// is interpolated into the statement. Mirrors the keys the viewers group
    /// on, so a conversation aggregated here matches what the UI shows.
    fn thread_key_expr(record_type: &str) -> Option<&'static str> {
        Some(match record_type {
            "iMessage" => {
                "COALESCE(json_extract(a.metadata_json,'$.chat_identifier'), \
                 json_extract(a.metadata_json,'$.chat_display_name'), \
                 json_extract(a.metadata_json,'$.contact'), 'unknown')"
            }
            "WhatsApp" => {
                "COALESCE(json_extract(a.metadata_json,'$.contact_jid'), \
                 json_extract(a.metadata_json,'$.remote_jid'), \
                 json_extract(a.metadata_json,'$.from_jid'), \
                 json_extract(a.metadata_json,'$.chat_subject'), 'unknown')"
            }
            "AndroidSms" => {
                "COALESCE(json_extract(a.metadata_json,'$.chat_identifier'), \
                 json_extract(a.metadata_json,'$.contact'), \
                 json_extract(a.metadata_json,'$.thread_id'), 'unknown')"
            }
            "Signal" => {
                "COALESCE(json_extract(a.metadata_json,'$.chat_identifier'), \
                 json_extract(a.metadata_json,'$.chat_display_name'), \
                 json_extract(a.metadata_json,'$.contact'), \
                 json_extract(a.metadata_json,'$.thread_id'), 'unknown')"
            }
            "Instagram" | "Snapchat" | "TwitterDM" => {
                "COALESCE(json_extract(a.metadata_json,'$.chat_identifier'), \
                 json_extract(a.metadata_json,'$.conversation_id'), \
                 json_extract(a.metadata_json,'$.thread_id'), 'unknown')"
            }
            // Email has no thread FIELD — it has a chain, and the root of it
            // is what `seance_plugin_email::thread` derives from the RFC 5322
            // headers and publishes as one string. Deliberately with NO
            // `'unknown'` fallback, unlike every arm above: a message carrying
            // none of the three headers cannot have its exchange addressed at
            // all, and grouping every such message in a mailbox under one
            // catch-all key would present a conversation that never existed.
            // The caller drops an empty key, so those messages are absent from
            // the thread list and reachable as records, which is what the
            // record's own `email_thread_unavailable_reason` says (§5.14).
            "EmailMessage" => "json_extract(a.metadata_json,'$.email_thread_key')",
            // Record types exactly as their parsers emit them.
            "Skype" | "LINE" | "TelegramMessage" | "Viber" | "Kik" | "WeChat"
            | "FacebookMessenger" => Self::GENERIC_THREAD_KEY,
            _ => return None,
        })
    }

    /// [`Self::thread_key_expr`], or an error naming the record type.
    ///
    /// An unrecognised type used to answer every conversation query with an
    /// empty success, so a messaging plugin added to the tree but not to
    /// `thread_key_expr` showed "this phone had no chats". "Could not look" is
    /// not "nothing found" -- the same rule [`Self::comms_types`] already holds.
    fn require_thread_key_expr(record_type: &str) -> Result<&'static str> {
        Self::thread_key_expr(record_type).with_context(|| {
            format!("'{record_type}' is not a record type this build can thread into conversations")
        })
    }

    /// Discriminator expression, character-identical to the one carried by
    /// `idx_artifacts_record_type` and `idx_artifacts_record_type_created` so
    /// the indices stay usable. Change it and migration `0035` changes with it.
    ///
    /// # The `NtfsLogFileRecord` arm (UI-009)
    ///
    /// NTFS `$LogFile` records used to carry no `$.type`, so they fell through
    /// onto `$.record_type` — a **numeric** field describing one field of one
    /// record — and the largest record class in an NTFS case appeared under a
    /// card and a viewer heading titled `1`. The parser now writes
    /// `"type": "NtfsLogFileRecord"` and new ingests are right at the source.
    ///
    /// Artifacts written before that fix still carry the old metadata, so an
    /// old case went on reading `1` and never reached the tailored viewer. The
    /// repair is made **here, at read time**, and deliberately not by a
    /// migration back-filling `$.type`: those rows belong to cases that have
    /// been examined and may have been reported on, and rewriting stored
    /// artifact metadata to improve a label is a mutation of the record that
    /// nothing afterwards would show — the audit chain covers the audit log, not
    /// artifact metadata. Deriving it changes what the screen groups by and
    /// leaves every stored byte exactly as the parser wrote it.
    ///
    /// This whole expression is a derivation already — `subtype`,
    /// `record_type` and `analysis_type` are all stand-ins read at query time —
    /// so the arm is the same kind of statement as the three around it, not a
    /// new kind.
    ///
    /// `$.redo_operation` is the discriminator because `seance_plugin_logfile`
    /// is the only emitter of it in the tree; `$.lsn` is required alongside it
    /// because `seance_plugin_memory_windows`'s MFT scanner emits an `lsn` too,
    /// and the pair is what makes the shape recognisably a `$LogFile` record
    /// rather than something that merely resembles one. The arm sits **after**
    /// `$.type`, so a record carrying its own type is never relabelled by it.
    const RECORD_TYPE_EXPR: &'static str = "COALESCE(\
         json_extract(a.metadata_json, '$.type'), \
         json_extract(a.metadata_json, '$.subtype'), \
         CASE WHEN json_extract(a.metadata_json, '$.redo_operation') IS NOT NULL \
              AND json_extract(a.metadata_json, '$.lsn') IS NOT NULL \
              THEN 'NtfsLogFileRecord' END, \
         json_extract(a.metadata_json, '$.record_type'), \
         json_extract(a.metadata_json, '$.analysis_type'), \
         'Unknown')";

    /// SQL expression selecting a comms record's COUNTERPARTY — the other party
    /// to the message, as the communications viewer labels it.
    ///
    /// Mirrors, key for key and in order, the chain in
    /// `frontend/src/pages/comms/normalize.ts:87-97`. The `CAST(... AS TEXT)`
    /// reproduces `metaStr`'s number/bool coercion and the `NULLIF(..., '')` its
    /// rule that an empty string is an absent value
    /// (`frontend/src/pages/analysis/lib.ts:126-140`). Any drift between the two
    /// makes the server rank one thing while the page names another, so the
    /// chain is pinned by `seance_db/tests/comms_ranking_test.rs`.
    ///
    /// DELIBERATELY DIFFERENT from [`Self::thread_key_expr`], and the difference
    /// is visible in the product: Conversations groups by thread, so an iMessage
    /// group chat is one row keyed on `chat_identifier`, whereas this ranks by
    /// correspondent, so the same messages are split across the handles that
    /// sent them. The two screens will disagree on group chats. That is the
    /// intended reading of two different questions — do not "reconcile" them by
    /// reusing `thread_key_expr` here, which additionally returns nothing at all
    /// for `CallLog` and `EmailMessage` and would drop every call and email from
    /// the ranking.
    ///
    /// Hardcoded, never built from client input, because it is interpolated.
    const COMMS_CONTACT_EXPR: &'static str = "COALESCE(\
         NULLIF(CAST(json_extract(a.metadata_json, '$.contact') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.chat_display_name') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.contact_name') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.chat_identifier') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.sender') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.sender_screen_name') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.contact_jid') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.remote_jid') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.from') AS TEXT), ''), \
         NULLIF(CAST(json_extract(a.metadata_json, '$.from_name') AS TEXT), ''))";

    /// The literal `contact` the call-history parser writes when the device
    /// recorded no number at all (`seance_plugin_call_history/src/lib.rs:194`).
    ///
    /// It is a placeholder, not a party. Buried in a sampled list it was merely
    /// noise; at the top of a ranking presented as exact it would seat a phantom
    /// counterparty on a court-facing screen. Those calls are real evidence, so
    /// they are neither ranked nor discarded: they are counted into
    /// [`CommsContactRanking::records_without_counterparty`] and reported as
    /// what they are.
    ///
    /// Applied ONLY to `CallLog`, because only that parser writes it as a
    /// stand-in. A WhatsApp correspondent whose display name genuinely is
    /// "Unknown" is a real party and stays in the table.
    const CALL_LOG_NO_NUMBER: &'static str = "Unknown";

    /// Every conversation in a messaging record type, with its message count and
    /// latest message, aggregated in one pass.
    ///
    /// This is what lets the UI show the complete correspondent list without
    /// downloading the messages: a case with 78k WhatsApp messages returns a few
    /// hundred rows here, and the messages themselves are fetched per thread.
    pub async fn conversation_summaries(
        &self,
        case_id: Uuid,
        record_type: &str,
    ) -> Result<Vec<ConversationSummary>> {
        let key_expr = Self::require_thread_key_expr(record_type)?;
        let type_expr = Self::RECORD_TYPE_EXPR;
        // Window functions give the newest message per thread and its size in a
        // single scan of just this type's rows.
        let sql = format!(
            "WITH m AS ( \
               SELECT {key_expr} AS k, \
                      -- `date_epoch` first: see `conversation_messages` for
                      -- why casting an ISO string here would sort by year.
                      COALESCE(CAST(json_extract(a.metadata_json,'$.date_epoch') AS INTEGER), \
                               CAST(json_extract(a.metadata_json,'$.date') AS INTEGER)) AS t, \
                      -- A chat's preview is its message text; an email's is
                      -- its subject, which is the line a reader recognises the
                      -- exchange by.
                      COALESCE(CAST(json_extract(a.metadata_json,'$.text') AS TEXT), \
                               CAST(json_extract(a.metadata_json,'$.subject') AS TEXT)) AS txt, \
                      -- Names and numbers are kept apart: MAX() picks the
                      -- lexicographic maximum, not the first non-null, so a
                      -- number on one message could otherwise beat a name on
                      -- another within the same conversation.
                      COALESCE(json_extract(a.metadata_json,'$.chat_display_name'), \
                               json_extract(a.metadata_json,'$.chat_subject'), \
                               json_extract(a.metadata_json,'$.contact_name')) AS label, \
                      -- An email thread's name is a subject line, and MAX()
                      -- over the partition would pick the lexicographic
                      -- maximum of every subject in it (a Re: reply beating
                      -- the original for no reason a reader could follow).
                      -- Taken from the newest message instead, like the
                      -- preview: the thread as it currently stands.
                      CAST(json_extract(a.metadata_json,'$.subject') AS TEXT) AS subj, \
                      CAST(json_extract(a.metadata_json,'$.phone_number') AS TEXT) AS number, \
                      CAST(COALESCE(json_extract(a.metadata_json,'$.is_group'),0) AS INTEGER) AS grp, \
                      CAST(COALESCE(json_extract(a.metadata_json,'$.service'), \
                               json_extract(a.metadata_json,'$.platform')) AS TEXT) AS tag \
               FROM artifacts a \
               WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' AND {type_expr} = ? \
             ), \
             r AS ( \
               SELECT k, t, txt, subj, \
                      MAX(label) OVER (PARTITION BY k) AS any_label, \
                      MAX(number) OVER (PARTITION BY k) AS any_number, \
                      MAX(grp) OVER (PARTITION BY k) AS any_grp, \
                      MAX(tag) OVER (PARTITION BY k) AS any_tag, \
                      COUNT(*) OVER (PARTITION BY k) AS n, \
                      ROW_NUMBER() OVER (PARTITION BY k ORDER BY t DESC) AS rn \
               FROM m \
             ) \
             SELECT k, any_label, any_number, n, t, txt, subj, any_grp, any_tag \
             FROM r WHERE rn = 1 \
             ORDER BY t DESC"
        );

        let rows = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(record_type)
            .fetch_all(&self.pool)
            .await
            .context("Failed to aggregate conversations")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let key: String = row.try_get("k").unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            // A real name first, then the number the chat recorded, then the
            // raw key — so a conversation is never labelled worse than the
            // evidence allows.
            let label: Option<String> = row
                .try_get::<Option<String>, _>("any_label")
                .ok()
                .flatten()
                .or_else(|| {
                    row.try_get::<Option<String>, _>("any_number")
                        .ok()
                        .flatten()
                })
                // An email thread's name is the newest message's subject.
                // Last, so it can never displace a chat's own display name.
                .or_else(|| {
                    row.try_get::<Option<String>, _>("subj")
                        .ok()
                        .flatten()
                        .filter(|s| !s.trim().is_empty())
                });
            out.push(ConversationSummary {
                label: label.unwrap_or_else(|| key.clone()),
                key,
                count: row.try_get("n").unwrap_or(0),
                last_time: row
                    .try_get::<Option<i64>, _>("t")
                    .ok()
                    .flatten()
                    .unwrap_or(0),
                last_preview: row.try_get("txt").ok().flatten(),
                is_group: row
                    .try_get::<Option<i64>, _>("any_grp")
                    .ok()
                    .flatten()
                    .unwrap_or(0)
                    != 0,
                tag: row.try_get("any_tag").ok().flatten(),
            });
        }
        Ok(out)
    }

    /// Artifacts whose contents did not reach the case for one of `reasons`,
    /// grouped by what reports them (`ROADMAP.md` §2.11).
    ///
    /// The queue this feeds is about **what can still be done**, so the
    /// grouping is by the record type that reports the problem and, where the
    /// record carries one, the scheme: LUKS and BitLocker both report through
    /// `VolumeDecryption` and need different answers, and a queue that merged
    /// them would offer one of them the wrong instruction.
    ///
    /// Superseded records are excluded. A later run that did read the content
    /// answers the earlier statement of incompleteness, and leaving it in the
    /// queue would ask an examiner to act on a problem that is already solved.
    pub async fn artifacts_blocked_by_reason(
        &self,
        case_id: Uuid,
        reasons: &[&str],
        max_examples: usize,
    ) -> Result<Vec<BlockedGroup>> {
        if reasons.is_empty() || max_examples == 0 {
            return Ok(Vec::new());
        }
        let type_expr = Self::RECORD_TYPE_EXPR;
        let placeholders = vec!["?"; reasons.len()].join(",");
        // One row per blocked artifact, newest first within its group, so the
        // examples are the most recent statements of the problem.
        let sql = format!(
            "SELECT a.id, a.parent_id, a.name, \
                    {type_expr} AS record_type, \
                    COALESCE(json_extract(a.metadata_json, '$.content_incomplete_reason'), \
                             json_extract(a.metadata_json, '$.inventory_incomplete_reason')) \
                      AS reason, \
                    json_extract(a.metadata_json, '$.scheme') AS scheme, \
                    COALESCE(json_extract(a.metadata_json, '$.content_incomplete_detail'), \
                             json_extract(a.metadata_json, '$.inventory_incomplete_detail'), \
                             json_extract(a.metadata_json, '$.detail'), \
                             json_extract(a.metadata_json, '$.message')) AS detail \
             FROM artifacts a \
             WHERE a.case_id = ? \
               AND COALESCE(json_extract(a.metadata_json, '$.superseded'), 0) <> 1 \
               AND (json_extract(a.metadata_json, '$.content_incomplete') = 1 \
                    OR json_extract(a.metadata_json, '$.inventory_incomplete') = 1) \
               AND COALESCE(json_extract(a.metadata_json, '$.content_incomplete_reason'), \
                            json_extract(a.metadata_json, '$.inventory_incomplete_reason')) \
                   IN ({placeholders}) \
             ORDER BY a.created_at DESC, a.id DESC"
        );
        let mut q = sqlx::query(&sql).bind(case_id.as_bytes().to_vec());
        for r in reasons {
            q = q.bind(*r);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to list blocked artifacts")?;

        use std::collections::HashMap;
        let mut groups: HashMap<(String, String, Option<String>), BlockedGroup> = HashMap::new();
        for row in rows {
            let id: Vec<u8> = row.try_get("id").unwrap_or_default();
            let Ok(artifact_id) = Uuid::from_slice(&id) else {
                continue;
            };
            let parent: Option<Vec<u8>> = row.try_get("parent_id").ok().flatten();
            let target_id = parent
                .and_then(|b| Uuid::from_slice(&b).ok())
                .unwrap_or(artifact_id);
            let record_type: String = row
                .try_get::<Option<String>, _>("record_type")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".to_string());
            let reason: String = row
                .try_get::<Option<String>, _>("reason")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unspecified".to_string());
            let scheme: Option<String> = row.try_get::<Option<String>, _>("scheme").ok().flatten();

            let key = (record_type.clone(), reason.clone(), scheme.clone());
            let group = groups.entry(key).or_insert_with(|| BlockedGroup {
                record_type,
                reason,
                scheme,
                count: 0,
                examples: Vec::new(),
                examples_truncated: false,
            });
            group.count += 1;
            if group.examples.len() < max_examples {
                group.examples.push(BlockedArtifact {
                    artifact_id,
                    target_id,
                    name: row.try_get::<Option<String>, _>("name").ok().flatten(),
                    detail: row.try_get::<Option<String>, _>("detail").ok().flatten(),
                });
            } else {
                group.examples_truncated = true;
            }
        }
        let mut out: Vec<BlockedGroup> = groups.into_values().collect();
        // Largest first, then by what reports it, for a stable order.
        out.sort_by(|a, b| {
            b.count.cmp(&a.count).then_with(|| {
                (
                    a.record_type.as_str(),
                    a.reason.as_str(),
                    a.scheme.as_deref(),
                )
                    .cmp(&(
                        b.record_type.as_str(),
                        b.reason.as_str(),
                        b.scheme.as_deref(),
                    ))
            })
        });
        Ok(out)
    }

    /// Pin a pivot result to the case, or refresh the pin that is there.
    ///
    /// Pinning the same value twice is the same assertion, so the second pin
    /// replaces the snapshot rather than filing a duplicate — and keeps the
    /// row's identity, so a report that cited it still cites the same pin.
    pub async fn pin_pivot(&self, pivot: &PinnedPivot) -> Result<()> {
        sqlx::query(
            "INSERT INTO pinned_pivots \
               (id, case_id, value, note, examiner, pinned_at, total_matches, grouped, \
                truncated, groups_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(case_id, value) DO UPDATE SET \
               note = excluded.note, \
               examiner = excluded.examiner, \
               pinned_at = excluded.pinned_at, \
               total_matches = excluded.total_matches, \
               grouped = excluded.grouped, \
               truncated = excluded.truncated, \
               groups_json = excluded.groups_json",
        )
        .bind(pivot.id.as_bytes().to_vec())
        .bind(pivot.case_id.as_bytes().to_vec())
        .bind(&pivot.value)
        .bind(&pivot.note)
        .bind(&pivot.examiner)
        .bind(pivot.pinned_at)
        .bind(pivot.total_matches)
        .bind(pivot.grouped)
        .bind(pivot.truncated as i64)
        .bind(pivot.groups.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to pin a pivot")?;
        Ok(())
    }

    /// The case's pinned pivots, most recently pinned first.
    pub async fn list_pinned_pivots(&self, case_id: Uuid) -> Result<Vec<PinnedPivot>> {
        let rows = sqlx::query(
            "SELECT id, case_id, value, note, examiner, pinned_at, total_matches, grouped, \
                    truncated, groups_json \
             FROM pinned_pivots WHERE case_id = ? ORDER BY pinned_at DESC, value ASC",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_all(&self.pool)
        .await
        .context("Failed to list pinned pivots")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // A pin is the examiner's assertion: an id, value, examiner or time
            // that will not read is an error the report must surface, never a
            // skipped pin or a defaulted field (an empty examiner, a 1970 time).
            let id: Vec<u8> = row.try_get("id").context("Unreadable pinned pivot id")?;
            let cid: Vec<u8> = row
                .try_get("case_id")
                .context("Unreadable pinned pivot case id")?;
            let id = Uuid::from_slice(&id).context("Invalid pinned pivot id")?;
            let case_id = Uuid::from_slice(&cid).context("Invalid pinned pivot case id")?;
            let groups_json: String = row.try_get("groups_json").unwrap_or_default();
            out.push(PinnedPivot {
                id,
                case_id,
                value: row
                    .try_get("value")
                    .with_context(|| format!("Unreadable value on pinned pivot {id}"))?,
                note: row
                    .try_get::<Option<String>, _>("note")
                    .with_context(|| format!("Unreadable note on pinned pivot {id}"))?,
                examiner: row
                    .try_get("examiner")
                    .with_context(|| format!("Unreadable examiner on pinned pivot {id}"))?,
                pinned_at: row
                    .try_get("pinned_at")
                    .with_context(|| format!("Unreadable pinned_at on pinned pivot {id}"))?,
                total_matches: row
                    .try_get("total_matches")
                    .with_context(|| format!("Unreadable total_matches on pinned pivot {id}"))?,
                grouped: row
                    .try_get("grouped")
                    .with_context(|| format!("Unreadable grouped on pinned pivot {id}"))?,
                truncated: row
                    .try_get::<i64, _>("truncated")
                    .with_context(|| format!("Unreadable truncated on pinned pivot {id}"))?
                    != 0,
                // A snapshot that will not decode is carried as JSON null
                // rather than dropped: the pin, its value and its counts are
                // still the examiner's assertion, and losing the row would
                // lose that too.
                groups: serde_json::from_str(&groups_json).unwrap_or(serde_json::Value::Null),
            });
        }
        Ok(out)
    }

    /// Remove a pin. Returns whether a row was there to remove, so the caller
    /// can answer "not found" rather than reporting a delete that did nothing.
    pub async fn unpin_pivot(&self, case_id: Uuid, pivot_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM pinned_pivots WHERE case_id = ? AND id = ?")
            .bind(case_id.as_bytes().to_vec())
            .bind(pivot_id.as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .context("Failed to unpin a pivot")?;
        Ok(result.rows_affected() > 0)
    }

    /// Records of this type whose thread key could not be formed at all.
    ///
    /// Every conversation list is a population-defining surface, so it has to
    /// state what it could not assess. For the chat channels this is always
    /// zero — their key expressions end in the literal `'unknown'`, so every
    /// record groups somewhere — and for email it is the count of messages
    /// carrying none of `Message-ID`, `In-Reply-To` or `References`. Those
    /// messages are real, are reachable as records, and are **not** in any
    /// thread; a list that did not say so would read as the whole of the
    /// mailbox (§5.14).
    pub async fn unthreadable_record_count(&self, case_id: Uuid, record_type: &str) -> Result<i64> {
        let key_expr = Self::require_thread_key_expr(record_type)?;
        let type_expr = Self::RECORD_TYPE_EXPR;
        let sql = format!(
            "SELECT COUNT(*) FROM artifacts a \
             WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' AND {type_expr} = ? \
               AND COALESCE({key_expr}, '') = ''"
        );
        sqlx::query_scalar(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(record_type)
            .fetch_one(&self.pool)
            .await
            .context("Failed to count records with no thread key")
    }

    /// The two statements [`Self::comms_contact_ranking`] runs, built here and
    /// nowhere else.
    ///
    /// Public so the query-plan regression test can EXPLAIN the SQL THAT SHIPS.
    /// It used to plan a hand-written two-type imitation of these statements
    /// instead, and passed on it while the shipped sixteen-type query had
    /// already fallen off the planner's cliff onto a full ParsedRecord scan: a
    /// performance guarantee stated in a comment, asserted by a test, and held
    /// by nobody. Pinned now by `comms_ranking_seeks_by_the_record_type_index`.
    ///
    /// `type_count` is how many record types the VALUES list carries. The
    /// caller must bind, in this order: one record-type name per VALUES row,
    /// then the case id, then — for [`CommsRankingSql::ranking`] only, and only
    /// when `has_needle` — the LIKE pattern.
    pub fn comms_ranking_sql(type_count: usize, has_needle: bool, limit: usize) -> CommsRankingSql {
        let type_expr = Self::RECORD_TYPE_EXPR;
        let contact_expr = Self::COMMS_CONTACT_EXPR;
        // Three separate things keep this off a full scan of the case, and all
        // three are load-bearing:
        //
        // 1. Driving the join from a VALUES list of the wanted types, rather
        //    than `<expr> IN (...)`: faced with an IN list over an indexed
        //    EXPRESSION the planner declines the expression index outright. One
        //    row of `t` per type gives one equality seek per type instead.
        //
        // 2. `CROSS JOIN`, which fixes the LOOP ORDER. Left free, the planner
        //    reverses the loops once the list grows: at the sixteen types this
        //    ranks over by default it made `artifacts` the outer loop, walking
        //    every ParsedRecord in the case and re-parsing the ten-key
        //    counterparty COALESCE per row. Measured on SQLite 3.46 over a
        //    200,000-record case that is 0.44s against 0.04s for the seek, and
        //    the census pays it a second time on the same page load. CROSS JOIN
        //    is SQLite's documented way to say "this order, whatever you
        //    estimate"; it does not change which rows match.
        //
        // 3. `INDEXED BY`, which fixes the INDEX. `optimize()` runs ANALYZE
        //    under `analysis_limit`, and those sampled statistics report the
        //    same row estimate for every equality on this table, so a
        //    single-column index on artifact_type can look as selective to the
        //    planner as the two-column expression index and be chosen over it.
        //    Naming the index removes the guess. If a future migration ever
        //    drops or renames it the statement stops preparing, which is the
        //    failure we want: loud, rather than a page that quietly costs ten
        //    times what its comments claim.
        //
        // The discriminator must stay byte-identical to the expression carried
        // by idx_artifacts_record_type / _created, `Unknown` fallback included,
        // or SQLite cannot match it at all.
        let type_rows = vec!["(?)"; type_count].join(",");
        let cte = format!(
            "WITH t(rt) AS (VALUES {type_rows}), \
             e AS ( \
               SELECT {contact_expr} AS contact, \
                      t.rt AS rtype, \
                      json_extract(a.metadata_json, '$.subtype') AS sub \
               FROM t CROSS JOIN artifacts a INDEXED BY idx_artifacts_record_type \
                 ON a.case_id = ? AND a.artifact_type = 'ParsedRecord' \
                    AND {type_expr} = t.rt \
             ) "
        );

        // A record is a placeholder call rather than a party only when BOTH the
        // type and the literal match; see `CALL_LOG_NO_NUMBER`.
        let placeholder = format!(
            "(rtype = 'CallLog' AND contact = '{}')",
            Self::CALL_LOG_NO_NUMBER
        );

        // The census: at most (types x 2 x 2 x 2) rows however large the case,
        // so it costs one pass and returns almost nothing.
        let census = format!(
            "{cte}SELECT rtype, \
                    CASE WHEN sub IS 'summary' THEN 1 ELSE 0 END AS is_summary, \
                    CASE WHEN contact IS NULL THEN 1 ELSE 0 END AS unplaceable, \
                    CASE WHEN {placeholder} THEN 1 ELSE 0 END AS placeholder, \
                    COUNT(*) AS n \
             FROM e GROUP BY 1, 2, 3, 4"
        );

        // Both sides of the search are folded by the same ASCII rule; see the
        // pattern the caller builds in `comms_contact_ranking` for what that
        // does and does not promise.
        let needle_clause = if has_needle {
            " AND lower(contact) LIKE ? ESCAPE '\\'"
        } else {
            ""
        };

        // `COUNT(*) OVER ()` is evaluated after the GROUP BY and before the
        // LIMIT, so it counts GROUPS: the exact number of distinct
        // correspondents, without a third statement and without being truncated
        // by the cap it is there to describe.
        //
        // LIMIT is limit + 1, the same probe convention as `get_geo_map_points`:
        // a full page is not evidence of more rows, an extra row is.
        let probe = limit.saturating_add(1);
        let ranking = format!(
            "{cte}SELECT contact, COUNT(*) AS n, COUNT(*) OVER () AS distinct_contacts \
             FROM e \
             WHERE sub IS NOT 'summary' AND contact IS NOT NULL AND NOT {placeholder}\
             {needle_clause} \
             GROUP BY contact \
             ORDER BY n DESC, contact ASC \
             LIMIT {probe}"
        );

        CommsRankingSql { census, ranking }
    }

    /// The comms counterparty league table for a case, computed over EVERY
    /// matching record rather than over whatever prefix a browser downloaded.
    ///
    /// LIVE-024: the correlation page tallied "most contacted" in JavaScript
    /// from 2,000 records per type out of up to 78,237. A tally of a sample is a
    /// lower bound, which is survivable; a RANKING of a sample is simply the
    /// wrong order, which is not — and an ingest-ordered prefix is never a
    /// representative sample. So the order is decided here, in SQL, over the
    /// whole match set.
    ///
    /// `channel` restricts to one ParsedRecord type and must be one of
    /// [`COMMS_RECORD_TYPES`]; anything else is an error, never an empty answer.
    /// `needle` is a substring match on the counterparty, applied to `contacts`
    /// only — the census fields describe the case, not the search. `limit`
    /// bounds `contacts`; `has_more` and `distinct_contacts` are what make that
    /// bound readable.
    ///
    /// The search is case-insensitive FOR ASCII LETTERS ONLY, on both sides:
    /// SQLite's built-in `lower()` folds A-Z and nothing else, and no Unicode
    /// collation is available to this crate. A counterparty is therefore always
    /// found by its own spelling, and "SAHIN" finds "Sahin", but "ünal" does not
    /// find "Ünal" — a non-ASCII letter matches only in the case the evidence
    /// stores it in. A caller that presents an empty result must not describe it
    /// as "no correspondent whose name contains this term" without that
    /// qualification; the honest reading of a zero here is "nothing matched the
    /// term as typed".
    pub async fn comms_contact_ranking(
        &self,
        case_id: Uuid,
        channel: Option<&str>,
        needle: Option<&str>,
        limit: usize,
    ) -> Result<CommsContactRanking> {
        // Belt and braces behind the API's own validation. The type names are
        // bound, not interpolated, so an unrecognised one is not an injection
        // risk -- it is a HONESTY risk: it would match no rows and the caller
        // would be handed a well-formed empty ranking, which on screen reads as
        // "this case holds no messages of that kind". Refuse instead.
        let types = Self::comms_types(channel)?;

        // One fold rule, stated once, and shared with the histogram that sits
        // beside this table on the same page: see `comms_like_pattern` for what
        // it does and — just as important — what it does not promise about
        // non-ASCII letters. Pinned by
        // `a_non_ascii_letter_matches_only_in_the_case_it_is_stored_in`.
        let pattern = Self::comms_like_pattern(needle);

        let sql = Self::comms_ranking_sql(types.len(), pattern.is_some(), limit);

        let mut census_q = sqlx::query(&sql.census);
        for t in &types {
            census_q = census_q.bind(*t);
        }
        let census_rows = census_q
            .bind(case_id.as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await
            .context("Failed to take the comms record census")?;

        let mut total_records = 0i64;
        let mut summary_records = 0i64;
        let mut unrankable_records = 0i64;
        let mut records_without_counterparty = 0i64;
        let mut by_type: Vec<(String, i64)> = Vec::new();
        for row in census_rows {
            let n: i64 = row.try_get("n").unwrap_or(0);
            total_records += n;
            // Ordered, not independent: a summary row also carries no
            // counterparty, and counting it twice would break the census. Each
            // record lands in exactly one bucket.
            if row.try_get::<i64, _>("is_summary").unwrap_or(0) != 0 {
                summary_records += n;
            } else if row.try_get::<i64, _>("placeholder").unwrap_or(0) != 0 {
                records_without_counterparty += n;
            } else if row.try_get::<i64, _>("unplaceable").unwrap_or(0) != 0 {
                unrankable_records += n;
            } else {
                let rtype: String = row.try_get("rtype").unwrap_or_default();
                match by_type.iter_mut().find(|(t, _)| *t == rtype) {
                    Some((_, acc)) => *acc += n,
                    None => by_type.push((rtype, n)),
                }
            }
        }
        by_type.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut ranking_q = sqlx::query(&sql.ranking);
        for t in &types {
            ranking_q = ranking_q.bind(*t);
        }
        ranking_q = ranking_q.bind(case_id.as_bytes().to_vec());
        if let Some(ref p) = pattern {
            ranking_q = ranking_q.bind(p.clone());
        }
        let mut rows = ranking_q
            .fetch_all(&self.pool)
            .await
            .context("Failed to rank comms counterparties")?;

        let distinct_contacts: i64 = rows
            .first()
            .and_then(|r| r.try_get("distinct_contacts").ok())
            .unwrap_or(0);
        let has_more = rows.len() > limit;
        rows.truncate(limit);

        let contacts = rows
            .into_iter()
            .map(|row| ContactCount {
                contact: row.try_get("contact").unwrap_or_default(),
                count: row.try_get("n").unwrap_or(0),
            })
            .collect();

        Ok(CommsContactRanking {
            contacts,
            limit,
            has_more,
            distinct_contacts,
            by_type,
            total_records,
            summary_records,
            unrankable_records,
            records_without_counterparty,
        })
    }

    /// The LIKE pattern a comms search term becomes, or `None` where the term
    /// asks for nothing.
    ///
    /// ASCII-lowercased, NOT `to_lowercase()`, because the column beside it is
    /// folded by SQLite's built-in `lower()` and that folds ASCII A-Z only.
    /// Folding the term with Rust's Unicode-aware rule while the column keeps
    /// its non-ASCII capitals meant the two sides could never meet: a search for
    /// "Ünal" became `%ünal%`, was compared against an unfolded `Ünal`, and
    /// matched nothing — the contact's OWN SPELLING found none of its records,
    /// and the empty answer reached the examiner labelled as an exact
    /// server-side count. Both sides now fold by the same ASCII rule, so an
    /// exactly-typed name always matches itself.
    ///
    /// The residual limit is real and deliberately not papered over: SQLite has
    /// no Unicode case folding here (no ICU extension is loaded, and this crate
    /// registers no collation of its own), so "ünal" still will not match
    /// "Ünal" — a non-ASCII letter matches only in the case the evidence stores
    /// it in. NOTE that the comms page's client-side fallback filter uses
    /// JavaScript's `toLowerCase()`, which IS Unicode-aware, so on that one
    /// input the two modes can disagree; widening this side would mean teaching
    /// SQLite to fold Unicode, not silently approximating it here.
    ///
    /// Escaping the LIKE wildcards keeps a contact containing a literal '%'
    /// searchable and one containing none unmatchable by accident.
    ///
    /// Shared by the ranking and the histogram ON PURPOSE: they sit on one page
    /// and are read against each other, so a term that narrows the table
    /// differently from the chart would be two answers to one question.
    fn comms_like_pattern(needle: Option<&str>) -> Option<String> {
        needle.map(str::trim).filter(|s| !s.is_empty()).map(|s| {
            let escaped = s
                .to_ascii_lowercase()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{escaped}%")
        })
    }

    /// The record types a comms query runs over, or an error naming what was
    /// asked for. Never an empty list: an unrecognised channel that matched no
    /// rows would be handed back as a well-formed empty answer, which on screen
    /// reads as "this case holds no messages of that kind".
    fn comms_types(channel: Option<&str>) -> Result<Vec<&'static str>> {
        match channel {
            Some(ch) => {
                let Some(known) = COMMS_RECORD_TYPES.iter().find(|t| **t == ch) else {
                    anyhow::bail!(
                        "'{ch}' is not a communications record type; expected one of: {}",
                        COMMS_RECORD_TYPES.join(", ")
                    );
                };
                Ok(vec![*known])
            }
            None => Ok(COMMS_RECORD_TYPES.to_vec()),
        }
    }

    /// The two statements the comms volume histogram runs, built here and
    /// nowhere else.
    ///
    /// Public so the query-plan regression test can EXPLAIN the SQL THAT SHIPS,
    /// for the same reason [`Self::comms_ranking_sql`] is: a plan test that
    /// plans a hand-written copy of a statement tests the copy.
    ///
    /// `keys` is the ordered metadata key list the timestamp procedure reads —
    /// [`COMMS_TIME_KEYS`] in production. It is a parameter rather than a
    /// constant so the corpus agreement test can drive THIS builder over the
    /// corpus rows that are keyed on something else (a shortcut-target row is
    /// keyed on `target_modified`/`target_created`), instead of proving the
    /// rule against a second, retyped expression. It is interpolated into a
    /// JSON path, so it is shape-checked here and must never come from a
    /// request.
    ///
    /// Callers bind, in this order: one record-type name per VALUES row, then
    /// the case id, then — when asked for — the LIKE pattern, then the exact
    /// contact. Both statements take the same binds in the same order.
    ///
    /// ## Why the epoch expression looks like this
    ///
    /// It is never a bare `CAST`. A `CAST` of a millisecond value is a record
    /// filed in the year 56185, and a `CAST` of `'now'` is every message dated
    /// the moment the examiner opened the page. Per record and per key the
    /// expression dispatches on `json_type()` — NOT `typeof()`, which cannot
    /// tell an absent key from a JSON null, both of which it calls `'null'`,
    /// and the census needs that distinction because "the record holds
    /// something unreadable" and "the record never claimed a time" are
    /// different findings. `json_type()` returns SQL NULL for an absent key and
    /// the string `'null'` for a written null.
    ///
    /// The accepted window is applied INSIDE each key's branch, BEFORE the
    /// `COALESCE` across keys. The browser's rule is "the first key that YIELDS
    /// AN INSTANT wins"; `COALESCE` is "the first non-NULL wins". Measured, the
    /// live shape `{"date":0,"timestamp":1600000000}` is 2020 under the first
    /// rule and 1970 under the second — fifty years apart from the same bytes.
    ///
    /// The window itself does the work; there is no free guard behind it.
    /// `unixepoch(<int>,'unixepoch')` passes through on [-210866760000,
    /// 253402300799], so it rejects a millisecond value only after 1978-01-11
    /// and cannot be leaned on. `'auto'` is never used: `datetime(5373484,
    /// 'auto')` is 9999-12-31, so `'auto'` sends early-1970 seconds to the far
    /// future.
    ///
    /// Text is shape-checked before it is parsed, because `unixepoch(<text>)`
    /// accepts SQLite magic that no evidence supports: `'now'` returns the time
    /// of the query, `'10:00:00'` becomes 2000-01-01, `'2024-03-05T12:00:00'`
    /// is silently read as UTC when the browser would read it in the VIEWER's
    /// zone, and `'2024-02-30'` rolls forward to 2024-03-01. The shape check
    /// admits exactly: a bare `YYYY-MM-DD`, and an RFC-3339 date-time that
    /// carries its own `Z` or `±HH:MM` offset — with `date()` round-tripped
    /// against the date part so a day that does not exist is refused rather
    /// than rolled.
    ///
    /// `json_extract` on malformed `metadata_json` ABORTS THE WHOLE QUERY,
    /// where the browser would lose only that row — one corrupt record would
    /// zero the histogram. Every extraction is therefore guarded by
    /// `json_valid()` (SQLite evaluates `CASE` arms lazily, which is what makes
    /// the guard work at all), and rows that fail it are counted as
    /// `unreadable_metadata` rather than dropped. The reach of that guard is
    /// limited and worth stating: the join's own discriminator cannot be
    /// wrapped without losing the expression index, so this counts a row whose
    /// stored index key still resolves and whose JSON no longer parses — the
    /// shape corruption-after-write leaves behind.
    pub fn comms_histogram_sql(
        keys: &[&str],
        type_count: usize,
        has_needle: bool,
        has_contact: bool,
        bucket_seconds: i64,
    ) -> Result<CommsHistogramSql> {
        anyhow::ensure!(
            bucket_seconds > 0,
            "bucket_seconds must be positive, got {bucket_seconds}"
        );
        anyhow::ensure!(type_count > 0, "at least one record type is required");
        anyhow::ensure!(
            !keys.is_empty(),
            "at least one time key is required; a histogram with no key to read \
             would report every record as having claimed no time"
        );
        for k in keys {
            anyhow::ensure!(
                !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "'{k}' is not a bare metadata key name"
            );
        }

        let type_expr = Self::RECORD_TYPE_EXPR;
        let contact_expr = Self::COMMS_CONTACT_EXPR;
        let type_rows = vec!["(?)"; type_count].join(",");

        // ---- e: read the JSON once ------------------------------------------
        // The scaffolding is `comms_ranking_sql`'s, hint for hint, and for the
        // same measured reason: a VALUES join (an IN list over an indexed
        // EXPRESSION makes the planner abandon the index), CROSS JOIN to pin
        // the loop order, INDEXED BY to pin the index. 0.438s against 0.040s on
        // a 200,000-record case for getting it wrong, and this runs on the same
        // page load as the ranking that already pays it. The discriminator must
        // stay byte-identical to the one idx_artifacts_record_type carries.
        //
        // What is added is the epoch material, projected as columns — NOT
        // `metadata_json` itself, which would carry every message body in the
        // case through four more CTEs.
        let mut e_cols: Vec<String> = vec![
            "json_valid(a.metadata_json) AS ok".into(),
            // The record type, taken from the VALUES side exactly as
            // `comms_ranking_sql` takes it for its own per-type breakdown. It
            // costs nothing — the join has already established that the row's
            // discriminator equals it — and it is the spelling that survives a
            // record whose JSON no longer parses: projecting the discriminator
            // EXPRESSION instead would re-run json_extract over that row's
            // metadata and abort the whole statement, which is the failure the
            // json_valid guards below exist to prevent. It is therefore always
            // one of the bound COMMS_RECORD_TYPES, which is what lets the
            // breakdown be quoted in the tool's own names.
            "t.rt AS rt".into(),
            format!("CASE WHEN json_valid(a.metadata_json) THEN {contact_expr} END AS contact"),
            "CASE WHEN json_valid(a.metadata_json) \
             THEN json_extract(a.metadata_json, '$.subtype') END AS sub"
                .into(),
            "CASE WHEN json_valid(a.metadata_json) \
             THEN json_extract(a.metadata_json, '$.status') END AS status"
                .into(),
        ];
        for (i, k) in keys.iter().enumerate() {
            e_cols.push(format!(
                "CASE WHEN json_valid(a.metadata_json) \
                 THEN json_type(a.metadata_json, '$.{k}') END AS jt{i}"
            ));
            e_cols.push(format!(
                "CASE WHEN json_valid(a.metadata_json) \
                 THEN json_extract(a.metadata_json, '$.{k}') END AS raw{i}"
            ));
        }
        let e_cols = e_cols.join(", ");

        // ---- n: one magnitude and one written instant per key ----------------
        let mut n_cols: Vec<String> = vec![
            "ok".into(),
            "rt".into(),
            "contact".into(),
            "sub".into(),
            "status".into(),
        ];
        for i in 0..keys.len() {
            let txt = format!("trim(raw{i})");
            // At most ONE leading '+', which is all JavaScript's `Number()`
            // accepts: `Number("++1")` is NaN, and `ltrim(x,'+')` would have
            // made it 1.
            let dgt =
                format!("(CASE WHEN substr({txt},1,1) = '+' THEN substr({txt},2) ELSE {txt} END)");
            // A tick count arrives as a digit string, and it is read through
            // INTEGER arithmetic wherever it can be: a FILETIME (~1.3e17) is
            // past the exact integer range of a double, so reading it as one
            // first could snap the count to a neighbouring value and move the
            // result into the next second. That is what the browser's own
            // BigInt path avoids, and what this mirrors.
            let digit_shape = format!("{dgt} <> '' AND {dgt} NOT GLOB '*[^0-9]*'");
            // Whether the literal fits an i64 at all. `CAST(<oversized literal>
            // AS INTEGER)` does not fail — it CLAMPS, silently, to
            // 9223372036854775807, which is a plausible-looking FILETIME and
            // would place a nonsense record in the year 30828.
            let fits_i64 = format!(
                "(length({dgt}) <= 18 \
                  OR (length({dgt}) = 19 AND {dgt} <= '9223372036854775807'))"
            );
            // Everything else `Number()` reads as a number: a decimal point, an
            // exponent, or both. `CAST(<text> AS REAL)` is NOT a parse — it
            // stops at the first character it cannot use and returns what it
            // had, so `'1.2.3'` is 1.2 to SQLite and NaN to JavaScript, and
            // `'1709640000e'` is a 2024 instant to SQLite and NaN to
            // JavaScript. Malformed text becoming a confident instant is the
            // failure mode, so the shape is checked first and the CAST only
            // ever sees a string JavaScript would also have read: one optional
            // point, one optional exponent with digits after it, and a sign
            // ONLY inside that exponent (a leading `-` never reaches here — the
            // caller reads a string containing one as written text, which is
            // what keeps a negative tick count out of the bands).
            let num_shape = format!(
                "{dgt} GLOB '[0-9]*' AND {dgt} NOT GLOB '*[^0-9.eE+]*' \
                 AND length({dgt}) - length(replace({dgt},'.','')) <= 1 \
                 AND length({dgt}) - length(replace(replace({dgt},'e',''),'E','')) <= 1 \
                 AND length({dgt}) - length(replace({dgt},'+','')) <= 1 \
                 AND ({dgt} NOT GLOB '*+*' OR {dgt} GLOB '*[eE]+[0-9]*') \
                 AND {dgt} NOT GLOB '*[eE]*.*' \
                 AND {dgt} NOT GLOB '*[eE]' AND {dgt} NOT GLOB '*+'"
            );
            // A tick count too large for an i64, read EXACTLY without one.
            //
            // The browser reads such a literal with BigInt and
            // `seance_core::timestamp` with an i128, both exactly; SQL has
            // neither, and a double rounds — measured, `"9999999999999999999"`
            // came back one second later than the shared procedure places it.
            // But the FILETIME epoch offset is 11644473600 x 10^7 EXACTLY, so
            // `floor((v - offset) / 10^7)` is `floor(v / 10^7) - 11644473600`,
            // and dividing a decimal string by 10^7 is dropping its last seven
            // characters. No large arithmetic is needed at all. Only the
            // FILETIME band can be reached this way: a value in the
            // millisecond band is below 10^15 and always fits an i64.
            let big_secs =
                format!("(CAST(substr({dgt}, 1, length({dgt}) - 7) AS INTEGER) - 11644473600)");
            // Written date-times, shape-checked before SQLite's parser sees
            // them, and UPPER-CASED before it parses them: RFC 3339 permits a
            // lower-case `t` separator and `z` zone marker, chrono reads both,
            // and SQLite reads `z` but returns NULL for `t`. Upper-casing costs
            // nothing on a string that is already upper-case and is the
            // difference between placing such a record and losing it. `date()` round-tripped against the date part rejects
            // 2024-02-30, which unixepoch() would otherwise roll silently
            // forward to 2024-03-01 — a message moved a day. A zone-less
            // date-time is refused because the browser reads it in the
            // VIEWER's zone, so placing it here would invent an agreement
            // between two machines that do not have one. LIMIT, stated: the
            // lower-case `t` separator that RFC 3339 permits is refused,
            // because SQLite cannot parse it and a shape SQL can only answer
            // NULL for is better refused loudly than accepted and lost.
            let date_shape = format!(
                "{txt} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*' \
                 AND date(substr({txt},1,10)) IS substr({txt},1,10) \
                 AND (length({txt}) = 10 \
                      OR ({txt} GLOB \
                            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][Tt ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]*' \
                          AND ({txt} GLOB '*[Zz]' \
                               OR {txt} GLOB '*[+-][0-9][0-9]:[0-9][0-9]')))"
            );
            n_cols.push(format!(
                "CASE jt{i} \
                   WHEN 'integer' THEN raw{i} \
                   WHEN 'real' THEN raw{i} \
                   WHEN 'text' THEN CASE \
                     WHEN {digit_shape} THEN CASE WHEN {fits_i64} \
                       THEN CAST({dgt} AS INTEGER) END \
                     WHEN {num_shape} THEN CAST({dgt} AS REAL) END \
                 END AS mag{i}"
            ));
            n_cols.push(format!(
                "CASE WHEN jt{i} = 'text' AND {digit_shape} AND NOT {fits_i64} \
                           AND length({dgt}) > 7 \
                           AND {big_secs} BETWEEN -8640000000000 AND 8640000000000 \
                      THEN {big_secs} END AS big{i}"
            ));
            n_cols.push(format!(
                "CASE WHEN jt{i} = 'text' AND ({date_shape}) \
                      THEN unixepoch(upper({txt})) END AS iso{i}"
            ));
            // An absent key and a written JSON null are both "this record
            // claimed no time"; anything else present is a claim that could not
            // be read. json_type() is the only expression that can tell the
            // first two apart from each other AND from a value.
            n_cols.push(format!(
                "CASE WHEN jt{i} IS NOT NULL AND jt{i} <> 'null' THEN 1 ELSE 0 END AS pres{i}"
            ));
        }
        let n_cols = n_cols.join(", ");

        // ---- b: the magnitude bands, in the browser reader's own boundaries --
        let mut b_cols: Vec<String> = vec![
            "ok".into(),
            "rt".into(),
            "contact".into(),
            "sub".into(),
            "status".into(),
        ];
        for i in 0..keys.len() {
            b_cols.push(format!("mag{i}"));
            b_cols.push(format!("big{i}"));
            b_cols.push(format!("iso{i}"));
            b_cols.push(format!("pres{i}"));
        }
        for i in 0..keys.len() {
            let m = format!("mag{i}");
            // Floor division, the idiom `get_timeline_histogram` already uses:
            // SQLite's `/` and `%` truncate toward zero, which would move a
            // pre-1970 instant into the second AFTER the one containing it.
            let ticks = format!("({m} - 116444736000000000)");
            let int_band = format!(
                "CASE \
                   WHEN {m} > 1000000000000000 \
                     THEN ({ticks} - (({ticks} % 10000000) + 10000000) % 10000000) / 10000000 \
                   WHEN {m} > 1000000000000 \
                     THEN ({m} - (({m} % 1000) + 1000) % 1000) / 1000 \
                   WHEN {m} > 100000000 THEN {m} \
                 END"
            );
            // The same three bands on a double. `floor()` is NOT available:
            // this SQLite is built without the maths extension, so the floor is
            // spelled out. The range test is load-bearing here and not in the
            // integer arm: a JSON integer too large for an i64 comes back from
            // json_extract as a REAL (measured: 1.23e39), lands in the FILETIME
            // band, and without the test would be CAST-clamped into a
            // plausible-looking instant.
            let q = format!("(({m} - 116444736000000000.0) / 10000000.0)");
            let ms = format!("CAST({m} AS INTEGER)");
            // The range test is NESTED inside the FILETIME arm, not ANDed into
            // its WHEN. ANDed, a value that fails it falls THROUGH to the
            // millisecond arm, where `CAST(... AS INTEGER)` clamps it to
            // i64::MAX and places the record in 30828 — which is precisely the
            // failure the test was there to prevent. Measured: the corpus row
            // "an integer literal too large for any epoch is not placed" came
            // back as 9223372036854775 with the guard written the other way.
            let real_band = format!(
                "CASE \
                   WHEN {m} > 1000000000000000.0 THEN \
                     CASE WHEN {q} BETWEEN -8640000000000.0 AND 8640000000000.0 \
                       THEN CAST({q} AS INTEGER) \
                            - (CASE WHEN {q} < CAST({q} AS INTEGER) THEN 1 ELSE 0 END) \
                     END \
                   WHEN {m} > 1000000000000.0 \
                     THEN ({ms} - (({ms} % 1000) + 1000) % 1000) / 1000 \
                   WHEN {m} > 100000000.0 THEN {ms} \
                 END"
            );
            // Dispatching on the STORAGE CLASS of the magnitude, which is a
            // different question from the one json_type answered above: not
            // "what did the record write" but "can this be read in exact
            // integer arithmetic". A JSON integer that overflowed an i64 says
            // 'integer' to json_type and arrives here as a double.
            b_cols.push(format!(
                "CASE WHEN typeof({m}) = 'integer' THEN {int_band} \
                      WHEN typeof({m}) = 'real' THEN {real_band} END AS band{i}"
            ));
        }
        let b_cols = b_cols.join(", ");

        // ---- p: place the record, first key that YIELDS AN INSTANT ----------
        let placed: Vec<String> = (0..keys.len())
            .flat_map(|i| [format!("band{i}"), format!("big{i}"), format!("iso{i}")])
            .collect();
        let placed = format!("COALESCE({}) AS placed_secs", placed.join(", "));
        let mut rescued = String::from("CASE ");
        for i in 0..keys.len() {
            rescued.push_str(&format!(
                "WHEN COALESCE(band{i}, big{i}, iso{i}) IS NOT NULL \
                 THEN CASE WHEN big{i} IS NOT NULL THEN 1 \
                           WHEN band{i} IS NOT NULL AND mag{i} > 1000000000000 THEN 1 \
                           ELSE 0 END "
            ));
        }
        rescued.push_str("ELSE 0 END AS rescued");
        let pres_any = format!(
            "CASE WHEN {} THEN 1 ELSE 0 END AS pres_any",
            (0..keys.len())
                .map(|i| format!("pres{i} = 1"))
                .collect::<Vec<_>>()
                .join(" OR ")
        );
        // Two populations, and the narrowing that separates them. `total` is
        // the case narrowed by channel ALONE — LIVE-024: a tile that shrank
        // while an examiner typed would read as evidence disappearing — and
        // `matched` is what the bars sum to.
        let needle_clause = if has_needle {
            " AND lower(contact) LIKE ? ESCAPE '\\'"
        } else {
            ""
        };
        let contact_clause = if has_contact { " AND contact = ?" } else { "" };

        // ---- c: the ordered census class ------------------------------------
        // ORDERED, not independent, and the order is the whole point. v1 asked
        // each question separately and a CallLog summary row — which has no
        // `date` key — answered yes to both "is a summary" and "has no time
        // key": 8 records in, a census that summed to 11. `comms_ranking_sql`
        // already solved this the same way. Every record lands in exactly one
        // class, so the classes sum to the population they describe.
        //
        // STATUS STUBS ARE NOT MESSAGES. Four plugins emit records whose
        // `$.type` IS a comms type but which are database status markers
        // carrying no `$.subtype` (call_history, android_sms, whatsapp,
        // imessage, each with `Identified` and `ParseFailed`). Reporting them
        // as unplaced communications is the wrong sentence twice over: they are
        // not communications, and a `ParseFailed` stub stands for an ENTIRE
        // UNREAD DATABASE, so counting it as one missing message understates
        // the shortfall by an unbounded amount. The discriminator is the ABSENT
        // subtype, not the presence of a status: android_sms and whatsapp both
        // write a `status` on genuine messages.
        //
        // Wave 1 also added `<key>_unusable` / `<key>_raw` at the source, for
        // values that place nowhere. This census deliberately does NOT read
        // them. The class of a record has to be the class the viewer would
        // give it, and the viewer reads `date` and `timestamp`; a server that
        // consulted a third key would call a record `unplaceable_value` on the
        // chart while the browser called it `unplaceable_absent` beside it,
        // which is the exact divergence the shared procedure exists to remove.
        // The cost is real and should be fixed where it belongs: such a record
        // reads as "never claimed a time" when the truth is "claimed a time
        // this tool could not use", and the place to correct that is
        // `seance_core::timestamp`, once, for every expression of the rule.
        let class = "CASE \
              WHEN ok = 0 THEN 'unreadable_metadata' \
              WHEN not_msg = 1 THEN 'not_a_message' \
              WHEN placed_secs IS NULL AND pres_any = 0 THEN 'unplaceable_absent' \
              WHEN placed_secs IS NULL THEN 'unplaceable_value' \
              WHEN rescued = 1 THEN 'placed_by_rescue' \
              ELSE 'placed_as_written' END AS class";

        // MATERIALIZED on the two extraction CTEs, and it is load-bearing.
        // SQLite flattens a single-reference CTE by SUBSTITUTING its column
        // expressions into every place the outer query names them — so `mag0`,
        // read a dozen times by the band CASE below, becomes a dozen fresh
        // evaluations of a chain that ends in `json_valid` + `json_extract`,
        // and each of those re-parses the whole `metadata_json` including the
        // message body. Measured on SQLite 3.46 over a 200,000-record case:
        // 2.26s / 2.89s flattened against 0.52s / 0.52s materialised, beside a
        // ranking that costs 0.58s for its own two statements on the same page
        // load. The cost is two transient tables of small columns — the JSON
        // itself is never carried into them, which is why the epoch material is
        // projected as columns in `e` rather than `metadata_json` being passed
        // down the chain.
        let ctes = format!(
            "WITH t(rt) AS (VALUES {type_rows}), \
             e AS MATERIALIZED ( \
               SELECT {e_cols} \
               FROM t CROSS JOIN artifacts a INDEXED BY idx_artifacts_record_type \
                 ON a.case_id = ? AND a.artifact_type = 'ParsedRecord' \
                    AND {type_expr} = t.rt \
             ), \
             n AS MATERIALIZED (SELECT {n_cols} FROM e), \
             b AS (SELECT {b_cols} FROM n), \
             p AS ( \
               SELECT ok, rt, \
                      CASE WHEN sub IS 'summary' OR (status IS NOT NULL AND sub IS NULL) \
                           THEN 1 ELSE 0 END AS not_msg, \
                      {placed}, {rescued}, {pres_any}, \
                      CASE WHEN 1{needle_clause}{contact_clause} THEN 1 ELSE 0 END AS matched \
               FROM b \
             ), \
             c AS (SELECT matched, placed_secs, rescued, rt, {class} FROM p) "
        );

        // At most one row per (class, type) however large the case: six classes
        // by at most sixteen types, one pass, nothing truncated. The extent
        // rides along on the same pass, because the API needs it BEFORE it can
        // choose a bucket width and a second scan of the case to fetch two
        // integers is a second scan of the case.
        //
        // The TYPE is in the grouping for one reason, and it is the reason the
        // section can say more than a bare total: "we could not place 412
        // records in time — 289 EmailMessage, 123 CallLog" has to come from the
        // pass that produced the 412. A per-type set fetched by a second query
        // could disagree with the census it is meant to explain, and two
        // contradicting exact figures on one screen is the failure this whole
        // feature exists to avoid. Grouping by a column already carried in `c`
        // adds rows to the result, not a scan to the plan: the extraction CTEs
        // are read exactly once either way, which is what the query-plan test
        // pins by asserting both of them stay MATERIALIZED.
        let census = format!(
            "{ctes}SELECT class, rt, COUNT(*) AS n, SUM(matched) AS m, \
                    MIN(CASE WHEN matched = 1 THEN placed_secs END) AS lo, \
                    MAX(CASE WHEN matched = 1 THEN placed_secs END) AS hi \
             FROM c GROUP BY class, rt"
        );

        // Floor-aligned on the epoch, NOT calendar-aligned: FRIENDLY_BUCKET_SECONDS
        // uses 30.4375 days for a "month", so an axis that implied calendar
        // months would be labelling bars with spans they do not cover. Empty
        // interior buckets are omitted; the client gap-fills them, exactly as it
        // already does for `get_timeline_histogram`.
        //
        // SECURITY: bucket_seconds is a validated positive i64 formatted as an
        // integer literal.
        let b = bucket_seconds;
        let buckets = format!(
            "{ctes}SELECT (placed_secs - ((placed_secs % {b}) + {b}) % {b}) AS bucket_start_secs, \
                    COUNT(*) AS n, SUM(rescued) AS rescued_n \
             FROM c \
             WHERE matched = 1 AND class IN ('placed_as_written', 'placed_by_rescue') \
             GROUP BY bucket_start_secs ORDER BY bucket_start_secs ASC"
        );

        Ok(CommsHistogramSql { census, buckets })
    }

    /// The ordered census behind the comms volume histogram, plus the extent of
    /// the records it could place.
    ///
    /// Returned as one value, from one pass, because the API needs the extent
    /// to choose a bucket width AND needs the census on the empty-extent path:
    /// `{buckets: []}` cannot tell "no communications at all" from "records
    /// exist, none placeable", and a chart that cannot tell them apart says
    /// nothing useful about either.
    ///
    /// `channel` restricts to one [`COMMS_RECORD_TYPES`] entry; anything else
    /// is an error, never an empty answer. `needle` is a substring search on
    /// the counterparty and `contact` an exact one; both narrow
    /// `matched_records` and neither narrows `total_records`.
    pub async fn comms_volume_census(
        &self,
        case_id: Uuid,
        keys: &[&str],
        channel: Option<&str>,
        needle: Option<&str>,
        contact: Option<&str>,
    ) -> Result<CommsVolumeCensus> {
        let types = Self::comms_types(channel)?;
        let pattern = Self::comms_like_pattern(needle);
        // The bucket width is irrelevant to the census; 1 is the cheapest
        // legal value and no bucket expression from this statement is run.
        let sql =
            Self::comms_histogram_sql(keys, types.len(), pattern.is_some(), contact.is_some(), 1)?;

        let mut q = sqlx::query(&sql.census);
        for t in &types {
            q = q.bind(*t);
        }
        q = q.bind(case_id.as_bytes().to_vec());
        if let Some(ref p) = pattern {
            q = q.bind(p.clone());
        }
        if let Some(c) = contact {
            q = q.bind(c.to_string());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to take the comms time census")?;

        let mut census = CommsVolumeCensus::default();
        for row in rows {
            let class: String = row.try_get("class").unwrap_or_default();
            // One row per (class, type) now, so a class arrives across as many
            // rows as the case holds types. Every count below accumulates, so
            // the class totals are unchanged by the finer grouping — and the
            // per-type parts are exactly the rows those totals were summed
            // from, which is what makes the breakdown add up by construction.
            let rt: String = row.try_get("rt").unwrap_or_default();
            let n: i64 = row.try_get("n").unwrap_or(0);
            let m: i64 = row.try_get("m").unwrap_or(0);
            census.total_records += n;
            census.matched_records += m;
            match class.as_str() {
                "unreadable_metadata" => census.unreadable_metadata += m,
                "not_a_message" => census.not_a_message += m,
                "unplaceable_absent" => {
                    census.unplaceable_absent += m;
                    Self::add_typed_records(&mut census.by_type_unplaceable_absent, &rt, m);
                }
                "unplaceable_value" => {
                    census.unplaceable_value += m;
                    Self::add_typed_records(&mut census.by_type_unplaceable_value, &rt, m);
                }
                "placed_by_rescue" => census.placed_by_rescue += m,
                "placed_as_written" => census.placed_as_written += m,
                other => {
                    // Unreachable from the statement above, and reported rather
                    // than folded into a neighbouring class: a record filed
                    // under a name the reader does not know is a record whose
                    // absence from the census would be silent.
                    warn!("comms time census returned an unknown class '{other}'");
                }
            }
            if class == "placed_by_rescue" || class == "placed_as_written" {
                let lo: Option<i64> = row.try_get("lo").ok().flatten();
                let hi: Option<i64> = row.try_get("hi").ok().flatten();
                census.min_ts_secs = match (census.min_ts_secs, lo) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                census.max_ts_secs = match (census.max_ts_secs, hi) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
            }
        }

        // Count descending, then type name ascending — byte order, the exact
        // comparator `comms_contact_ranking` sorts its own `by_type` with, so
        // the two per-type lists on one page are ordered by one rule. SQLite is
        // free to return groups in whatever order the grouping happened to
        // produce, and a shortfall sentence that reshuffled between two reads
        // of the same case would read as the evidence having changed.
        for by_type in [
            &mut census.by_type_unplaceable_value,
            &mut census.by_type_unplaceable_absent,
        ] {
            by_type.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        }
        Ok(census)
    }

    /// Add `n` records of type `rt` to a per-type breakdown of one census class.
    ///
    /// A zero is dropped rather than listed. Every type the caller asked about
    /// reaches the census, so a type nothing matched arrives here with a count
    /// of nought, and "EmailMessage 0" inside a shortfall sentence reads as a
    /// finding about EmailMessage when the truth is that the filter excluded
    /// it. A type absent from the list is a type with nothing to report.
    fn add_typed_records(by_type: &mut Vec<(String, i64)>, rt: &str, n: i64) {
        if n == 0 {
            return;
        }
        match by_type.iter_mut().find(|(t, _)| t == rt) {
            Some((_, acc)) => *acc += n,
            None => by_type.push((rt.to_string(), n)),
        }
    }

    /// The bars: one row per non-empty time bucket over the MATCHED population.
    ///
    /// Bucket starts are whole Unix SECONDS — the field name says so, because
    /// `epoch.ts` and the chart component work in milliseconds and a 1000x mix
    /// renders 2024 as 1970-01-20.
    ///
    /// Empty interior buckets are omitted, as `get_timeline_histogram` omits
    /// them; the client gap-fills. The undisclosed `timestamp > 0` filter that
    /// `get_timeline_activity` carries is deliberately NOT copied: it would
    /// delete every genuine pre-1970 record from the chart without saying so.
    pub async fn comms_volume_histogram(
        &self,
        case_id: Uuid,
        keys: &[&str],
        channel: Option<&str>,
        needle: Option<&str>,
        contact: Option<&str>,
        bucket_seconds: i64,
    ) -> Result<Vec<CommsHistogramBucket>> {
        let types = Self::comms_types(channel)?;
        let pattern = Self::comms_like_pattern(needle);
        let sql = Self::comms_histogram_sql(
            keys,
            types.len(),
            pattern.is_some(),
            contact.is_some(),
            bucket_seconds,
        )?;

        let mut q = sqlx::query(&sql.buckets);
        for t in &types {
            q = q.bind(*t);
        }
        q = q.bind(case_id.as_bytes().to_vec());
        if let Some(ref p) = pattern {
            q = q.bind(p.clone());
        }
        if let Some(c) = contact {
            q = q.bind(c.to_string());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to compute the comms volume histogram")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(CommsHistogramBucket {
                bucket_start_secs: row.try_get("bucket_start_secs")?,
                count: row.try_get("n")?,
                rescued_count: row.try_get::<Option<i64>, _>("rescued_n")?.unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Hard cap on one attachment fetch. Bounds the response for a
    /// media-saturated thread; the caller is told when it bites.
    const ATTACHMENT_FETCH_CAP: usize = 2000;

    /// Most messages [`Self::conversation_messages`] returns for one page,
    /// whatever the caller asks for.
    ///
    /// Public because that call has no truncation channel: the returned length
    /// is the caller's ONLY evidence about whether the thread continues, and
    /// that evidence is only readable against the cap that was actually
    /// applied. A caller that requests 1000 and compares against 1000 reads a
    /// full 500-message page as the end of the conversation.
    pub const CONVERSATION_PAGE_CAP: u32 = 500;

    /// Most hits [`Self::search_conversation_messages`] returns, whatever the
    /// caller asks for. Public for the same reason as
    /// [`Self::CONVERSATION_PAGE_CAP`]: the hit list carries no truncation
    /// flag, so the caller has to compare its length against the effective cap
    /// to know the count is a lower bound.
    pub const CONVERSATION_SEARCH_CAP: u32 = 200;

    /// Attachments belonging to a given set of messages, and whether the fetch
    /// hit [`Self::ATTACHMENT_FETCH_CAP`].
    ///
    /// Chat media is a separate record type linked back by message id, and a
    /// database can hold thousands of them, so the client cannot hold the whole
    /// set to find the few that belong to the messages on screen. This fetches
    /// exactly those.
    ///
    /// The `truncated` flag is part of the answer: a media-rich thread that
    /// returns exactly the cap looks identical to one that happens to have that
    /// many attachments, and an examiner reading "12 photos in this
    /// conversation" must not be looking at a silently shortened list.
    pub async fn attachments_for_messages(
        &self,
        case_id: Uuid,
        attachment_type: &str,
        row_ids: &[i64],
        guids: &[String],
    ) -> Result<AttachmentFetch> {
        if row_ids.is_empty() && guids.is_empty() {
            return Ok(AttachmentFetch::default());
        }
        let type_expr = Self::RECORD_TYPE_EXPR;
        let mut clauses: Vec<String> = Vec::new();
        if !row_ids.is_empty() {
            let list = vec!["?"; row_ids.len()].join(",");
            clauses.push(format!(
                "CAST(json_extract(a.metadata_json,'$.message_rowid') AS INTEGER) IN ({list})"
            ));
        }
        if !guids.is_empty() {
            let list = vec!["?"; guids.len()].join(",");
            clauses.push(format!(
                "CAST(json_extract(a.metadata_json,'$.message_guid') AS TEXT) IN ({list})"
            ));
        }
        // Fetch one row beyond the cap: its presence is how we know more exist.
        let probe_limit = Self::ATTACHMENT_FETCH_CAP + 1;
        let sql = format!(
            "SELECT a.id, a.case_id, a.parent_id, a.metadata_json FROM artifacts a \
             WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' AND {type_expr} = ? \
               AND ({}) LIMIT {probe_limit}",
            clauses.join(" OR ")
        );

        let mut q = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(attachment_type);
        for id in row_ids {
            q = q.bind(*id);
        }
        for g in guids {
            q = q.bind(g.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch attachments for messages")?;

        let truncated = rows.len() > Self::ATTACHMENT_FETCH_CAP;
        if truncated {
            warn!(
                "Attachment fetch for case {} hit the {} row cap; the list is incomplete",
                case_id,
                Self::ATTACHMENT_FETCH_CAP
            );
        }
        // Rows the fetch could not decode are counted, never dropped in
        // silence: "this message had no media" and "its media rows would not
        // decode" are the same picture to an examiner otherwise, and the cap
        // flag above says nothing about them.
        let mut undecodable = 0usize;
        let mut out = Vec::with_capacity(rows.len().min(Self::ATTACHMENT_FETCH_CAP));
        for row in rows.into_iter().take(Self::ATTACHMENT_FETCH_CAP) {
            let id_bytes: Vec<u8> = row.try_get("id").unwrap_or_default();
            let case_bytes: Vec<u8> = row.try_get("case_id").unwrap_or_default();
            let parent: Option<Vec<u8>> = row.try_get("parent_id").ok().flatten();
            let meta_str: String = row.try_get("metadata_json").unwrap_or_default();
            let (Ok(id), Ok(cid)) = (Uuid::from_slice(&id_bytes), Uuid::from_slice(&case_bytes))
            else {
                undecodable += 1;
                continue;
            };
            let metadata: serde_json::Value =
                serde_json::from_str(&meta_str).unwrap_or(serde_json::Value::Null);
            let mut artifact = seance_core::artifact::Artifact::new(
                cid,
                seance_core::artifact::ArtifactType::ParsedRecord,
                None,
                metadata,
            );
            artifact.id = id;
            artifact.parent_id = parent.and_then(|b| Uuid::from_slice(&b).ok());
            out.push(artifact);
        }
        if undecodable > 0 {
            warn!(
                "case {}: {} attachment row(s) for the messages on screen could not be decoded; \
                 the media list is incomplete",
                case_id, undecodable
            );
        }
        Ok(AttachmentFetch {
            items: out,
            truncated,
            undecodable,
        })
    }

    /// One page of a single conversation, newest first.
    ///
    /// `before` is a scrollback cursor over the SAME total order the query sorts
    /// by — `(ord, id)`, not `ord` alone. `ord` is the message's date when it
    /// has one, else a sentinel above any real unix date; `id` is the artifact
    /// id that breaks ties. An `ord`-only cursor is not a cursor over these
    /// rows: it asks for `ord < X` and so skips every remaining message that
    /// shares `ord = X` with the last one on the previous page. That is not an
    /// exotic case — an undated recovered body whose source carried no
    /// `recovery_index` collapses to exactly the sentinel, so a thread with
    /// more than one page of them returned the first page and then declared the
    /// rest non-existent. A cursor carrying `id` cannot skip: `id` is unique.
    ///
    /// `limit` is clamped to `1..=`[`Self::CONVERSATION_PAGE_CAP`], and the
    /// returned [`ConversationPage`] answers end-of-thread directly through
    /// `has_more` (a `LIMIT + 1` probe) instead of leaving the caller to infer
    /// it from a page length — an inference that a single undecodable row used
    /// to break by shortening the page.
    pub async fn conversation_messages(
        &self,
        case_id: Uuid,
        record_type: &str,
        thread_key: &str,
        before: Option<ConversationCursor>,
        limit: u32,
    ) -> Result<ConversationPage> {
        let key_expr = Self::require_thread_key_expr(record_type)?;
        let type_expr = Self::RECORD_TYPE_EXPR;
        let limit = limit.clamp(1, Self::CONVERSATION_PAGE_CAP);
        // Single monotonic ordering value: the real date when known, else a
        // sentinel far above any real unix date (1e13) offset by recovery_index.
        // Carved bodies with no timestamp thus sort as "newest" (loaded first)
        // yet remain individually addressable, so the ONE `before`-cursor pages
        // both dated history and the undated tail without stranding either. The
        // frontend computes the identical value for its cursor.
        // `$.date_epoch` is tried FIRST and the order is load-bearing. Chat
        // records store `$.date` as unix seconds; the email readers store an
        // RFC 3339 string there, and `CAST('2026-03-02T…' AS INTEGER)` is
        // `2026` — a perfectly valid integer that COALESCE would accept, so an
        // email thread would page in an order that has nothing to do with when
        // the messages were sent (§5.14). The email readers publish
        // `date_epoch` beside the string for exactly this expression.
        let ord = "COALESCE(CAST(json_extract(a.metadata_json,'$.date_epoch') AS INTEGER), \
                   CAST(json_extract(a.metadata_json,'$.date') AS INTEGER), \
                   10000000000000 + COALESCE(CAST(json_extract(a.metadata_json,'$.recovery_index') AS INTEGER), 0))";
        // The cursor predicate mirrors `ORDER BY {ord} DESC, a.id DESC` exactly.
        // Without the `ord = ? AND a.id < ?` arm, ties at the boundary are lost.
        let cursor = if before.is_some() {
            format!("AND ({ord} < ? OR ({ord} = ? AND a.id < ?)) ")
        } else {
            String::new()
        };
        // One row past the page: its existence is how "the thread continues" is
        // established, rather than inferred from the page being full.
        let probe_limit = limit as usize + 1;
        let sql = format!(
            "SELECT a.id, a.case_id, a.parent_id, a.metadata_json, {ord} AS ord \
             FROM artifacts a \
             WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' AND {type_expr} = ? \
               AND {key_expr} = ? {cursor}\
             ORDER BY {ord} DESC, a.id DESC \
             LIMIT {probe_limit}"
        );

        let mut q = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(record_type)
            .bind(thread_key);
        if let Some(c) = &before {
            q = q.bind(c.ord).bind(c.ord).bind(c.id.as_bytes().to_vec());
        }
        let mut rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch conversation messages")?;

        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);

        // Rows that will not decode are counted and reported. They used to
        // `continue` in silence, which shortened the page; the caller read the
        // short page as the start of the thread and the older half of a
        // conversation ceased to exist.
        let mut undecodable = 0usize;
        let mut next_cursor: Option<ConversationCursor> = None;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id_bytes: Vec<u8> = row.try_get("id").unwrap_or_default();
            let case_bytes: Vec<u8> = row.try_get("case_id").unwrap_or_default();
            let parent: Option<Vec<u8>> = row.try_get("parent_id").ok().flatten();
            let meta_str: String = row.try_get("metadata_json").unwrap_or_default();
            let row_ord: Option<i64> = row.try_get("ord").ok();
            let (Ok(id), Ok(cid)) = (Uuid::from_slice(&id_bytes), Uuid::from_slice(&case_bytes))
            else {
                undecodable += 1;
                continue;
            };
            // The cursor advances only over rows whose position is fully known.
            // A row that could not be decoded, or whose ordering value did not
            // read back as an integer, leaves the cursor where it was: that row
            // is re-read on the next page — a repeat, not a skip — and the
            // reported `undecodable` count explains any shortfall.
            if let Some(row_ord) = row_ord {
                next_cursor = Some(ConversationCursor { ord: row_ord, id });
            }
            let metadata: serde_json::Value =
                serde_json::from_str(&meta_str).unwrap_or(serde_json::Value::Null);
            let mut artifact = seance_core::artifact::Artifact::new(
                cid,
                seance_core::artifact::ArtifactType::ParsedRecord,
                None,
                metadata,
            );
            artifact.id = id;
            artifact.parent_id = parent.and_then(|b| Uuid::from_slice(&b).ok());
            out.push(artifact);
        }
        if undecodable > 0 {
            warn!(
                "case {}: {} message row(s) in thread '{}' could not be decoded; the page is \
                 short by that much and says so",
                case_id, undecodable, thread_key
            );
        }
        if has_more && next_cursor.is_none() {
            // Every row on a full page failed to decode, so there is no
            // position to resume from. Refusing is the only honest answer:
            // returning an empty page would report the rest of the thread as
            // non-existent.
            anyhow::bail!(
                "case {case_id}: no message row in this page of thread '{thread_key}' could be \
                 decoded, so scrollback cannot continue past it; the remaining messages exist \
                 but cannot be reached"
            );
        }
        Ok(ConversationPage {
            records: out,
            has_more,
            next_cursor: if has_more { next_cursor } else { None },
            undecodable,
        })
    }

    /// Full-text-ish search across a chat type's messages: rows whose text
    /// contains `query`, newest first, each tagged with the conversation it
    /// belongs to so the UI can jump straight to it.
    ///
    /// `limit` is clamped to `1..=`[`Self::CONVERSATION_SEARCH_CAP`] and the hit
    /// list carries no truncation flag, so a full-length result means the match
    /// set is a lower bound and the caller must say so. A search that reports
    /// "200 messages mention this number" off a capped list is a claim about
    /// the evidence that the query never established.
    pub async fn search_conversation_messages(
        &self,
        case_id: Uuid,
        record_type: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<ConversationSearchHit>> {
        let key_expr = Self::require_thread_key_expr(record_type)?;
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let type_expr = Self::RECORD_TYPE_EXPR;
        let limit = limit.clamp(1, Self::CONVERSATION_SEARCH_CAP);
        // Escape LIKE wildcards in the user's term so they match literally.
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");

        let sql = format!(
            "SELECT a.id, {key_expr} AS thread_key, \
                    json_extract(a.metadata_json,'$.text') AS text, \
                    CAST(json_extract(a.metadata_json,'$.date') AS INTEGER) AS date \
             FROM artifacts a \
             WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' AND {type_expr} = ? \
               AND json_extract(a.metadata_json,'$.text') LIKE ? ESCAPE '\\' \
             ORDER BY date DESC LIMIT {limit}"
        );

        let rows = sqlx::query(&sql)
            .bind(case_id.as_bytes().to_vec())
            .bind(record_type)
            .bind(pattern)
            .fetch_all(&self.pool)
            .await
            .context("Failed to search conversation messages")?;

        // The caller decides whether the hit list is the whole match set by
        // comparing its length against the same limit. Rows dropped here shrink
        // that length below the limit, so a capped search would report itself
        // complete. Count them and say so rather than dropping in silence.
        let mut undecodable = 0usize;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id_bytes: Vec<u8> = row.try_get("id").unwrap_or_default();
            let Ok(id) = Uuid::from_slice(&id_bytes) else {
                undecodable += 1;
                continue;
            };
            out.push(ConversationSearchHit {
                id,
                thread_key: row.try_get("thread_key").ok().flatten().unwrap_or_default(),
                text: row.try_get("text").ok().flatten().unwrap_or_default(),
                date: row.try_get("date").ok().flatten().unwrap_or(0),
            });
        }
        if undecodable > 0 {
            warn!(
                "case {}: conversation search dropped {} row(s) with an undecodable artifact id; \
                 the hit list is short by that many and the truncation check under-reports",
                case_id, undecodable
            );
        }
        Ok(out)
    }

    /// Paginated ParsedRecord artifacts whose metadata `type` == `record_type`,
    /// optionally restricted to the subtree under `source_id` (recursive over
    /// parent_id, to any depth -- see `subtree_cte`). Returns the page of
    /// artifacts plus the total
    /// matching count. Ordered by created_at then id for stable paging.
    /// Oldest-ingested first.
    ///
    /// The default direction is deliberate and unchanged: every caller that
    /// pages the whole match set relies on a stable total order, and flipping it
    /// under them would reshuffle the registry, memory and analysis loops for no
    /// gain. A caller that can only afford a bounded prefix — and therefore
    /// cares WHICH end of the case it gets — must say so via
    /// [`Self::list_records_by_type_ordered`].
    pub async fn list_records_by_type(
        &self,
        case_id: Uuid,
        record_type: &str,
        source_id: Option<Uuid>,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<seance_core::artifact::Artifact>, i64)> {
        self.list_records_by_type_ordered(
            case_id,
            record_type,
            source_id,
            page,
            page_size,
            RecordOrder::OldestIngestedFirst,
        )
        .await
    }

    /// Whether a record-type label could be the text SQLite prints for a
    /// discriminator that is NOT stored as text.
    ///
    /// The discriminator comes out of JSON, so its SQL type is whatever the
    /// parser wrote: `{"subtype": 1}` extracts as INTEGER, `{"subtype": "1"}` as
    /// TEXT, and SQLite never equates the two. [`Self::record_type_counts`]
    /// folds both into the single label "1", so the listing that label opens has
    /// to fold them the same way or the census counts a population the
    /// drill-down cannot show.
    ///
    /// The test is deliberately a loose superset of SQLite's own rendering —
    /// anything that could begin an integer or a float, plus the non-finite
    /// spellings — because being wrong in this direction only costs the listing
    /// its index (see the caller), while being wrong in the other direction
    /// hides records from an examiner who was just told they exist.
    fn label_may_be_non_text(label: &str) -> bool {
        matches!(label, "Inf" | "-Inf" | "NaN")
            || label
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.'))
    }

    /// The statements [`Self::list_records_by_type_ordered`] runs.
    ///
    /// Public for the same reason as [`Self::comms_ranking_sql`]: the query-plan
    /// regression test EXPLAINs the SQL that ships rather than a copy of it, so
    /// that a change here cannot quietly cost the listing its index while a test
    /// keeps reporting that it has one.
    ///
    /// `record_type` shapes the SQL but is NEVER interpolated into it: it only
    /// chooses between two fixed predicates, and the value itself is still
    /// bound. It is client input, so it must stay bound.
    ///
    /// Bind order is per statement and follows placeholder position in the SQL
    /// text, which the search term makes differ between the two:
    ///
    /// * PAGE: subtree anchor (case_id, source_id) when scoped, then the body's
    ///   case_id re-filter, then the record type, then one LIKE pattern per
    ///   searched key in [`RecordTextFilter::keys`] order. The search predicate
    ///   is appended to the WHERE, so its binds come last.
    /// * COUNT: subtree anchor when scoped, then the LIKE patterns (the
    ///   predicate sits in a `CASE` in the select list, ahead of the FROM),
    ///   then the body's case_id re-filter, then the record type.
    ///
    /// [`Self::bind_record_listing`] is the only thing that binds either, so the
    /// difference is expressed once rather than at each call site.
    ///
    /// ## `refine` and the two SQLite traps it has to walk between
    ///
    /// `json_extract` over malformed `metadata_json` ABORTS THE WHOLE
    /// STATEMENT, so every extraction `refine` adds is guarded by
    /// `json_valid(a.metadata_json)` — the same guard, and for the same reason,
    /// as [`Self::comms_histogram_sql`]. A row that fails the guard cannot match
    /// a search term and cannot yield a sort key, which means the guard's price
    /// is that a corrupt record silently drops out of a filtered count. It is
    /// not allowed to drop out silently: the COUNT statement counts those rows
    /// as `unfilterable` and [`RecordListingPage`] carries the number.
    ///
    /// The LIKE patterns are escaped by the caller ([`escape_like`]) and every
    /// LIKE carries `ESCAPE '\'`, so a term containing `_` or `%` — and record
    /// bodies are full of both — matches literally instead of over-matching.
    pub fn record_listing_sql(
        case_id: Uuid,
        record_type: &str,
        source_scoped: bool,
        order: RecordOrder,
        page_size: u32,
        offset: i64,
        refine: &RecordListingRefinement<'_>,
    ) -> RecordListingSql {
        // The predicate has to select exactly the rows the census counted under
        // this label, and the census's fold is SQLite's own `CAST(... AS TEXT)`.
        //
        // For an ordinary type name the two are already the same population —
        // no number renders as "WhatsApp", and a CAST over a text value is the
        // value — so the comparison stays the bare discriminator, byte-identical
        // to the expression idx_artifacts_record_type_created carries, and the
        // page remains a seek plus LIMIT rows.
        //
        // For a label that could equally be a number's rendering, the CAST goes
        // on, and with it the index: nothing can seek an expression it does not
        // store. That is the deliberate trade. A numeric discriminator is a rare
        // shape (a parser writing `{"subtype": 1}`), and reading such a listing
        // slowly is a cost; showing an examiner a census of two records and then
        // a drill-down holding one of them is a false statement about the
        // evidence.
        let type_expr: std::borrow::Cow<'static, str> = if Self::label_may_be_non_text(record_type)
        {
            format!("CAST({} AS TEXT)", Self::RECORD_TYPE_EXPR).into()
        } else {
            Self::RECORD_TYPE_EXPR.into()
        };
        let (cte, body, total_expr) = if source_scoped {
            (
                // Cycle-safe, uncapped subtree walk (see `subtree_cte`). The
                // old `depth < 32` cap silently excluded records nested deeper
                // than 32 parent links from this type's listing AND its count.
                subtree_cte(case_id),
                // Membership test rather than a join to `subtree`: the subquery
                // is uncorrelated, so SQLite materialises the walk once per
                // statement and drives the query from
                // idx_artifacts_record_type_created. Joining made the walk the
                // outer loop, which re-parsed the metadata JSON of every
                // artifact under the scope on every page.
                // The COALESCE must match idx_artifacts_record_type's expression
                // EXACTLY -- including the 'Unknown' fallback -- or SQLite
                // cannot use the expression index and scans every record, which
                // is why it comes from the one constant rather than a retyping.
                // (The numeric-label form above wraps that constant in a CAST
                // and knowingly gives the index up; every other listing must
                // not.)
                // `a.case_id = ?` re-filters the subtree result so a descendant
                // reached via a cross-case parent_id can never appear.
                format!(
                    "FROM artifacts a \
                     WHERE a.artifact_type = 'ParsedRecord' AND a.case_id = ? \
                       AND {type_expr} = ? \
                       AND a.id IN (SELECT id FROM subtree)"
                ),
                // The count rides along with the page, so a scoped listing walks
                // the tree once per page instead of once to count and once to
                // read. Paged over a large image that doubling was the whole
                // cost of the memory endpoints.
                ", COUNT(*) OVER () AS total_count",
            )
        } else {
            (
                String::new(),
                format!(
                    "FROM artifacts a WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' \
                     AND {type_expr} = ?"
                ),
                // Nothing to save here: with no walk, the covering expression
                // index answers a separate COUNT cheaply, and a window function
                // would cost the page query its index-ordered early exit.
                ", NULL AS total_count",
            )
        };

        // What a later run answered is not a second answer, so the PAGE leaves
        // those rows out. The predicate reads `metadata_json` per row, which the
        // page can afford — it stops after a page's worth — but a COUNT cannot:
        // put on the count statement it read every record in the case and took
        // the record listing on a 1.75M-artifact case to a minute and a half.
        // The count is taken without it and the superseded rows subtracted from
        // an index instead (`idx_artifacts_superseded`, HUNT-107).
        //
        // Guarded by `json_valid`: a record whose metadata will not parse cannot
        // have been superseded, and reading it unguarded fails the statement,
        // which would take the listing down with it.
        let page_body = if refine.exclude_superseded {
            format!(
                "{body} AND COALESCE(CASE WHEN json_valid(a.metadata_json) \
                   THEN json_extract(a.metadata_json, '$.superseded') END, 0) <> 1"
            )
        } else {
            body.clone()
        };

        // The search predicate, appended to the body so its binds come last and
        // the bind order above stays true. Empty when nothing was asked, which
        // leaves every existing statement byte-identical to what it was.
        let search_predicate = refine.search.as_ref().map(|s| s.sql_predicate());
        let page_body = match &search_predicate {
            Some(pred) => format!("{page_body} AND {pred}"),
            None => page_body,
        };

        // ORDER BY. Without a `sort` key this is the ingest order it always
        // was — index-ordered, early-exiting, and (importantly) NOT the
        // record's own event time, which is why the caller has to say so on
        // screen. With one, the key is extracted per row behind the json_valid
        // guard and the index is knowingly given up: sorting a type's whole
        // population by an arbitrary metadata key is a sort, not a seek.
        //
        // `a.id ASC` tie-breaks in BOTH forms. A metadata key is routinely
        // constant across thousands of records (a `rank`, a `folder`), and an
        // ORDER BY that is not a total order lets a row land on two pages or on
        // none as the planner re-shuffles equal keys between statements.
        let order_by = match refine.sort_key {
            Some(key) => format!(
                "CASE WHEN json_valid(a.metadata_json) \
                 THEN json_extract(a.metadata_json, '$.{key}') END {dir}, a.id ASC",
                dir = if refine.sort_descending {
                    "DESC"
                } else {
                    "ASC"
                }
            ),
            None => format!(
                "a.created_at {dir}, a.id {dir}",
                // BOTH columns reverse together. Reversing only `created_at`
                // would leave the tiebreaker running the other way, which is
                // still a total order but no longer one the index can walk --
                // the planner would sort every record of the type in the case
                // to serve one page.
                dir = order.sql_direction()
            ),
        };

        let page = format!(
            "{cte}SELECT a.id, a.case_id, a.parent_id, a.metadata_json{total_expr} \
             {page_body} ORDER BY {order_by} LIMIT {page_size} OFFSET {offset}"
        );

        // The COUNT statement answers three questions over ONE pass of the
        // type's population, because they are three different populations and a
        // response that reports only the first cannot be read:
        //
        //   count        — records matching type + scope + search. This is the
        //                  `T` in the "N of T" line above the table, and it is
        //                  the one thing that was wrong before: leaving it as
        //                  the type's count made that line false the moment
        //                  anybody typed in the filter box.
        //   type_total   — the type's own population, unfiltered, so the screen
        //                  can say "2 of 4 WhatsApp records, filtered from 40".
        //   unfilterable — rows whose metadata will not parse. They were never
        //                  tested against the term, so they are neither matches
        //                  nor established non-matches.
        //
        // With no search term the shape collapses back to the plain `COUNT(*)`
        // the index answers directly, and `unfilterable` is NULL — "not looked
        // up", never zero. Establishing that a row's JSON parses costs a read of
        // every row's JSON, and an unfiltered listing has no reason to pay it.
        // A searched count reads every record's metadata anyway, so excluding
        // the superseded ones there is free and the statement answers both
        // questions. An unsearched count is answered from the index and must
        // stay that way; the caller subtracts (see `list_records_filtered`).
        let count = match &search_predicate {
            Some(pred) => {
                let body = if refine.exclude_superseded {
                    format!(
                        "{body} AND COALESCE(CASE WHEN json_valid(a.metadata_json) \
                           THEN json_extract(a.metadata_json, '$.superseded') END, 0) <> 1"
                    )
                } else {
                    body.clone()
                };
                format!(
                    "{cte}SELECT SUM(CASE WHEN {pred} THEN 1 ELSE 0 END) AS count, \
                            COUNT(*) AS type_total, \
                            SUM(CASE WHEN json_valid(a.metadata_json) THEN 0 ELSE 1 END) \
                                AS unfilterable \
                     {body}"
                )
            }
            None => format!(
                "{cte}SELECT COUNT(*) AS count, COUNT(*) AS type_total, \
                        NULL AS unfilterable {body}"
            ),
        };

        RecordListingSql { page, count }
    }

    /// [`Self::list_records_by_type`] with the ingest direction chosen by the
    /// caller.
    ///
    /// LIVE-024 surfaced why the direction has to be sayable: the comms and
    /// correlation pages load 2,000 records per type and then present them
    /// "newest first", but the 2,000 were the OLDEST ingested, so the "most
    /// recent messages" table on a 78,237-record store could exclude every
    /// genuinely recent message in the case. A caller that truncates needs the
    /// end of the listing it is actually going to show.
    ///
    /// It stayed a new argument rather than a change of default because the
    /// ascending order is load-bearing for the callers that page to the end:
    /// they read `total`, loop until they have it, and depend on a stable total
    /// order for a row to appear on exactly one page. Both directions order on
    /// `(created_at, id)` — `created_at` alone is not a total order, since a
    /// whole ingest batch shares one timestamp — so both are stable, and both
    /// ride idx_artifacts_record_type_created (SQLite walks it backwards for the
    /// descending case; see `newest_first_record_listing_still_uses_the_ordered_index`).
    pub async fn list_records_by_type_ordered(
        &self,
        case_id: Uuid,
        record_type: &str,
        source_id: Option<Uuid>,
        page: u32,
        page_size: u32,
        order: RecordOrder,
    ) -> Result<(Vec<seance_core::artifact::Artifact>, i64)> {
        let listing = self
            .list_records_filtered(
                case_id,
                &RecordListingQuery {
                    record_type,
                    source_id,
                    search: None,
                    sort: None,
                    order,
                    // Every caller of this convenience wrapper is showing or
                    // counting the case's current answers.
                    include_superseded: false,
                    page,
                    page_size,
                },
            )
            .await?;
        Ok((listing.records, listing.total))
    }

    /// One page of a record type, optionally SEARCHED and SORTED server-side.
    ///
    /// This is the general form; [`Self::list_records_by_type_ordered`] and
    /// [`Self::list_records_by_type`] are the unrefined shorthands, so there is
    /// exactly one implementation of "what is a page of records" and no way for
    /// a filtered listing and an unfiltered one to disagree about the
    /// population they draw from.
    ///
    /// The returned [`RecordListingPage::total`] is the size of the FILTERED
    /// set. That is the whole point of the search living here: a table that
    /// filters the rows it happens to have loaded, above a total that counts the
    /// type, prints "12 of 40,000" while showing an examiner twelve rows drawn
    /// from one page of a hundred. Both numbers are true and the sentence they
    /// form is not.
    pub async fn list_records_filtered(
        &self,
        case_id: Uuid,
        query: &RecordListingQuery<'_>,
    ) -> Result<RecordListingPage> {
        #[derive(sqlx::FromRow)]
        struct RecRow {
            id: Vec<u8>,
            case_id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            metadata_json: String,
            /// Exact size of the whole match set, carried on the scoped page so
            /// one statement answers both questions. NULL on the unscoped
            /// listing and on any empty page.
            total_count: Option<i64>,
        }

        let record_type = query.record_type;
        let source_id = query.source_id;
        let page_size = query.page_size;
        let order = query.order;
        let page = query.page.max(1);
        let offset = (page as i64 - 1) * page_size as i64;
        let case_id_bytes = case_id.as_bytes().to_vec();
        let source_bytes = source_id.map(|s| s.as_bytes().to_vec());
        let scoped = source_bytes.is_some();

        let refine = RecordListingRefinement {
            search: query.search,
            sort_key: query.sort.map(|s| s.key),
            sort_descending: query.sort.is_some_and(|s| s.descending),
            exclude_superseded: !query.include_superseded,
        };
        refine.validate()?;
        // The escaped LIKE patterns, one per searched key, in key order. Bound,
        // never interpolated: the term is client input.
        let patterns: Vec<String> = refine
            .search
            .as_ref()
            .map(|s| {
                let pattern = format!("%{}%", escape_like(s.needle));
                vec![pattern; s.keys.len()]
            })
            .unwrap_or_default();

        let search_predicate_present = refine.search.is_some();
        let sql = Self::record_listing_sql(
            case_id,
            record_type,
            scoped,
            order,
            page_size,
            offset,
            &refine,
        );
        let select_sql = sql.page;

        let rows_q = Self::bind_record_listing(
            sqlx::query_as::<_, RecRow>(&select_sql),
            &case_id_bytes,
            source_bytes.as_deref(),
            record_type,
            &patterns,
            RecordStatement::Page,
        );
        if scoped {
            self.scoped_record_walks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let rows = rows_q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch records by type")?;

        // A SEARCHED listing always runs the count statement. The window
        // function riding on the scoped page counts the FILTERED rows, which is
        // the right `total` — but the screen also has to be able to say what the
        // type's own population was, and how many rows were unreadable, and
        // neither of those can be recovered from a filtered page. The extra
        // walk is the price of a filter that means anything.
        let mut type_total: Option<i64> = None;
        let mut unfilterable: Option<i64> = None;
        // How many records of this type and scope a later run answered — an
        // index lookup, not a scan (HUNT-107). Read before the counts, because
        // an unsearched count is taken from the index without the exclusion and
        // has these subtracted from it.
        let superseded_total = if refine.exclude_superseded {
            Some(
                self.count_superseded_records(case_id, record_type, source_id)
                    .await?,
            )
        } else {
            None
        };

        // Only the SCOPED listing carries its count on the page: the window
        // function rides along with the walk so the tree is walked once instead
        // of twice. The unscoped listing selects `NULL AS total_count` to keep
        // the page query's index-ordered early exit, so its rows can never
        // answer the count and it must always ask separately. Reading a NULL
        // there as "zero matches" would report every unscoped listing as empty
        // however many rows it just returned.
        //
        // An empty scoped page carries no count either, and the two reasons a
        // page is empty are not the same fact. No rows from the FIRST page of a
        // listing that asked for at least one row means the match set is empty,
        // and a second statement could only confirm that at the price of
        // another subtree walk -- which is most of the coverage view, where
        // most stages have no records. Any other empty page is "you asked past
        // the end", and reporting that as zero would turn "page 9 of 3" into
        // "there are none", so it pays for the count.
        let carried_total = if scoped && refine.search.is_none() {
            rows.first().and_then(|r| r.total_count)
        } else {
            None
        };
        let total: i64 = match carried_total {
            Some(total) => total,
            None if refine.search.is_none()
                && scoped
                && rows.is_empty()
                && offset == 0
                && page_size > 0 =>
            {
                // An empty unfiltered first page: the match set is empty, and so
                // is the type's population, and nothing was tested for
                // readability.
                type_total = Some(0);
                0
            }
            None => {
                let count_q = Self::bind_record_listing(
                    sqlx::query_as::<_, (Option<i64>, i64, Option<i64>)>(&sql.count),
                    &case_id_bytes,
                    source_bytes.as_deref(),
                    record_type,
                    &patterns,
                    RecordStatement::Count,
                );
                if scoped {
                    self.scoped_record_walks
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // SUM() over no rows is NULL, not 0. Decoding that NULL as an
                // `i64` would fail the request on an empty type; it means "no
                // rows contributed", which for a count is zero.
                let (matched, all, unreadable) = count_q
                    .fetch_one(&self.pool)
                    .await
                    .context("Failed to count records by type")?;
                // The unsearched count is of the type's whole population,
                // superseded records included, because taking them out in SQL
                // costs a full scan of the case's metadata. They come off here.
                let answered = if search_predicate_present {
                    0
                } else {
                    superseded_total.unwrap_or(0)
                };
                type_total = Some((all - answered).max(0));
                unfilterable = unreadable;
                (matched.unwrap_or(0) - answered).max(0)
            }
        };
        // With no search term, the filtered set IS the type's population; the
        // count statement selects the same aggregate twice and this only fills
        // in the branch that never ran it.
        let type_total = type_total.unwrap_or(total);

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(seance_core::artifact::Artifact {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID")?,
                case_id: Uuid::from_slice(&row.case_id).context("Invalid UUID for case ID")?,
                parent_id: row
                    .parent_id
                    .map(|b| Uuid::from_slice(&b).context("Invalid UUID for parent ID"))
                    .transpose()?,
                artifact_type: seance_core::artifact::ArtifactType::ParsedRecord,
                data: None,
                metadata: serde_json::from_str(&row.metadata_json)
                    .context("Failed to deserialize record metadata")?,
            });
        }

        Ok(RecordListingPage {
            records,
            total,
            type_total,
            unfilterable_metadata: unfilterable,
            superseded_total,
        })
    }

    /// How many records of this type and scope a later run answered.
    ///
    /// The listing leaves them out, and a screen that says nothing about them
    /// reads as "that is all the case ever held". Counted with the same subtree
    /// walk the listing uses so the two describe one population.
    pub async fn count_superseded_records(
        &self,
        case_id: Uuid,
        record_type: &str,
        source_id: Option<Uuid>,
    ) -> Result<i64> {
        let type_expr: std::borrow::Cow<'static, str> = if Self::label_may_be_non_text(record_type)
        {
            format!("CAST({} AS TEXT)", Self::RECORD_TYPE_EXPR).into()
        } else {
            Self::RECORD_TYPE_EXPR.into()
        };
        // Written exactly as `idx_artifacts_superseded`'s own `WHERE`, because
        // that is how SQLite decides the partial index applies — and without it
        // this counts by reading every record's metadata.
        let superseded = "json_extract(a.metadata_json, '$.superseded') = 1";
        let (sql, scoped) = match source_id {
            Some(_) => (
                format!(
                    "{cte}SELECT COUNT(*) FROM artifacts a                      WHERE a.artifact_type = 'ParsedRecord' AND a.case_id = ?                        AND {type_expr} = ? AND a.id IN (SELECT id FROM subtree)                        AND {superseded}",
                    cte = subtree_cte(case_id)
                ),
                true,
            ),
            None => (
                format!(
                    "SELECT COUNT(*) FROM artifacts a                      WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord'                        AND {type_expr} = ? AND {superseded}"
                ),
                false,
            ),
        };
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        if scoped {
            // The CTE's seed takes the case first and then the root artifact,
            // before the body's own binds.
            q = q
                .bind(case_id.as_bytes().to_vec())
                .bind(source_id.expect("scoped").as_bytes().to_vec());
        }
        q = q.bind(case_id.as_bytes().to_vec()).bind(record_type);
        q.fetch_one(&self.pool)
            .await
            .context("Failed to count superseded records")
    }

    /// Bind one of the two record-listing statements.
    ///
    /// The two take the same values in DIFFERENT orders, because the search
    /// predicate sits in the page statement's WHERE (last) and in the count
    /// statement's select list (before the FROM). Writing the difference twice
    /// is how a listing ends up counting one population and showing another, so
    /// it is written once, here.
    fn bind_record_listing<'q, O>(
        query: sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments<'q>>,
        case_id_bytes: &'q [u8],
        source_bytes: Option<&'q [u8]>,
        record_type: &'q str,
        patterns: &'q [String],
        statement: RecordStatement,
    ) -> sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments<'q>> {
        let mut q = query;
        // The subtree CTE is the first thing in either statement, so its two
        // anchors bind first when the listing is scoped.
        if let Some(sid) = source_bytes {
            q = q.bind(case_id_bytes).bind(sid);
        }
        // The count statement's search predicate lives in a CASE in the select
        // list, ahead of the FROM; the page statement's lives at the end of the
        // WHERE.
        if statement == RecordStatement::Count {
            for pattern in patterns {
                q = q.bind(pattern.as_str());
            }
        }
        q = q.bind(case_id_bytes).bind(record_type);
        if statement == RecordStatement::Page {
            for pattern in patterns {
                q = q.bind(pattern.as_str());
            }
        }
        q
    }

    /// The statement [`Self::record_type_counts`] runs.
    ///
    /// Public for the same reason as [`Self::comms_ranking_sql`]: the query-plan
    /// regression test has to EXPLAIN the SQL that ships. Its predecessor
    /// planned a hand-written copy that had drifted — the copy had no `CAST`
    /// around the discriminator — and the copy used the expression index while
    /// the shipped statement, which grouped by the CAST result, did not: it
    /// searched idx_artifacts_browse_type_name and built a temp b-tree for the
    /// GROUP BY, the exact two things the test asserted against.
    ///
    /// The CAST now sits OUTSIDE the grouping, in an enclosing select. Grouping
    /// on the bare discriminator is what the index stores, so the grouping is
    /// answered by an index seek in case order; the coercion of a non-string
    /// discriminator (a numeric `subtype` is real, and used to fail the decode
    /// and poison the whole endpoint) then happens over the handful of grouped
    /// rows. Two discriminators that differ only in JSON type — 1 and "1" —
    /// therefore arrive as two rows carrying one label, and
    /// [`Self::record_type_counts`] adds them back together rather than
    /// showing an examiner the same type twice.
    ///
    /// Bind order, unchanged: scoped — subtree anchor (case_id, source_id), then
    /// the body's case_id re-filter; flat — just the body's case_id.
    pub fn record_type_counts_sql(case_id: Uuid, source_scoped: bool) -> String {
        let type_expr = Self::RECORD_TYPE_EXPR;

        // The source-scoped variant mirrors `list_records_by_type` exactly: a
        // cycle-safe subtree walk from the source, re-filtered by `a.case_id` so
        // a descendant reached through a cross-case parent_id can never be
        // counted. Both variants read the same discriminator expression, which
        // must stay the one the expression index carries.
        let (cte, body) = if source_scoped {
            (
                subtree_cte(case_id),
                "FROM artifacts a JOIN subtree s ON a.id = s.id \
                 WHERE a.artifact_type = 'ParsedRecord' AND a.case_id = ?"
                    .to_string(),
            )
        } else {
            (
                String::new(),
                "FROM artifacts a WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord'"
                    .to_string(),
            )
        };

        format!(
            "{cte}SELECT CAST(rt AS TEXT) AS record_type, n AS count \
             FROM (SELECT {type_expr} AS rt, COUNT(*) AS n {body} GROUP BY rt) \
             ORDER BY count DESC, record_type ASC"
        )
    }

    /// One row per (app named by the record, record type) pair, with a count.
    ///
    /// The raw material for "what is on this device" (§2.12). Two different
    /// things can say which application a record came from, and they are kept
    /// apart here rather than merged in SQL so the caller can say *how* each
    /// group was attributed:
    ///
    /// * the record **names** an app — SRUM's `app`, the Windows Timeline's
    ///   `application`, a kext's `bundle_id`;
    /// * or the record's **type** is an app, which is how the messengers and
    ///   browsers identify themselves (`WhatsApp`, `iMessage`).
    ///
    /// Grouping by both columns at once is what makes the totals safe to add: a
    /// record that carries an explicit app *and* an app-shaped type appears in
    /// exactly one row, so no count is reached twice. A record that names no
    /// app and whose type is not an app comes back with `app = None` and a type
    /// the caller will not recognise — which is the unattributed population,
    /// and it is counted, never guessed at.
    pub async fn app_record_counts(
        &self,
        case_id: Uuid,
        source_id: Option<Uuid>,
    ) -> Result<Vec<(Option<String>, String, i64)>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            app: Option<String>,
            record_type: String,
            count: i64,
        }

        let type_expr = Self::RECORD_TYPE_EXPR;
        // Precedence, and why: `app` is SRUM's own resolved application name,
        // `application` the Timeline's, `bundle_id` a macOS identifier. Any one
        // of them is the record's own statement about which program it came
        // from; the first present wins and the rest are not consulted, so one
        // record yields one attribution.
        let app_expr = "COALESCE(             json_extract(a.metadata_json, '$.app'),              json_extract(a.metadata_json, '$.application'),              json_extract(a.metadata_json, '$.bundle_id'))";

        let source_bytes = source_id.map(|s| s.as_bytes().to_vec());
        let (cte, body) = if source_bytes.is_some() {
            (
                subtree_cte(case_id),
                "FROM artifacts a JOIN subtree s ON a.id = s.id                  WHERE a.artifact_type = 'ParsedRecord' AND a.case_id = ?"
                    .to_string(),
            )
        } else {
            (
                String::new(),
                "FROM artifacts a WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord'"
                    .to_string(),
            )
        };

        let sql = format!(
            "{cte}SELECT CAST(app AS TEXT) AS app, CAST(rt AS TEXT) AS record_type,                     n AS count              FROM (SELECT {app_expr} AS app, {type_expr} AS rt, COUNT(*) AS n                    {body} GROUP BY app, rt)              ORDER BY count DESC, record_type ASC"
        );

        let mut query = sqlx::query_as::<_, Row>(&sql);
        if let Some(ref sid) = source_bytes {
            query = query.bind(case_id.as_bytes().to_vec()).bind(sid);
        }
        query = query.bind(case_id.as_bytes().to_vec());
        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to count records by application")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                // An empty string is not an app name; treat it as absent so it
                // cannot open a group with a blank heading.
                let app = r.app.filter(|a| !a.trim().is_empty());
                (app, r.record_type, r.count)
            })
            .collect())
    }

    /// The same census, over the records a later run answered.
    ///
    /// Written as its own statement rather than as a predicate on the one above,
    /// because the predicate reads `metadata_json` for every row in the case and
    /// that took the Analysis index from a fraction of a second to 96 on a
    /// 1.75M-artifact case. This one is answered by `idx_artifacts_superseded`,
    /// a partial index over exactly the superseded rows — a population that is
    /// empty on a case where no module has been re-run. The `WHERE` text matches
    /// the index's own, because that is how SQLite decides a partial index
    /// applies.
    pub fn superseded_type_counts_sql(case_id: Uuid, source_scoped: bool) -> String {
        let type_expr = Self::RECORD_TYPE_EXPR;
        let superseded = "json_extract(a.metadata_json, '$.superseded') = 1";
        let (cte, body) = if source_scoped {
            (
                subtree_cte(case_id),
                format!(
                    "FROM artifacts a JOIN subtree s ON a.id = s.id \
                     WHERE a.artifact_type = 'ParsedRecord' AND a.case_id = ? AND {superseded}"
                ),
            )
        } else {
            (
                String::new(),
                format!(
                    "FROM artifacts a WHERE a.case_id = ? AND a.artifact_type = 'ParsedRecord' \
                     AND {superseded}"
                ),
            )
        };
        format!(
            "{cte}SELECT CAST(rt AS TEXT) AS record_type, n AS count \
             FROM (SELECT {type_expr} AS rt, COUNT(*) AS n {body} GROUP BY rt)"
        )
    }

    /// Distinct ParsedRecord `type` values in a case, each with its count,
    /// ordered by count descending. Records without a `type` are grouped as
    /// "Unknown".
    ///
    /// When `source_id` is given, the counts are scoped to the ParsedRecords in
    /// that source artifact's subtree — the same provenance scoping the record
    /// listing uses, so an examiner can ask "what did THIS acquisition yield?"
    /// and get counts that match the rows they will then see. `None` counts the
    /// whole case.
    pub async fn record_type_counts(
        &self,
        case_id: Uuid,
        source_id: Option<Uuid>,
    ) -> Result<Vec<(String, i64)>> {
        #[derive(sqlx::FromRow)]
        struct TypeCount {
            record_type: String,
            count: i64,
        }

        let case_id_bytes = case_id.as_bytes().to_vec();
        let source_bytes = source_id.map(|s| s.as_bytes().to_vec());

        // The discriminator falls back through common self-describing keys so a
        // record that names its kind under subtype/record_type/analysis_type is
        // grouped honestly instead of dumped into "Unknown". See
        // `record_type_counts_sql` for why the TEXT coercion sits outside the
        // grouping and what that means for the rows that come back.
        let sql = Self::record_type_counts_sql(case_id, source_bytes.is_some());

        // Bind order matches placeholder order. Subtree variant: anchor
        // (case_id, source_id), then the body's case_id re-filter. Flat variant:
        // just the body's case_id.
        let mut query = sqlx::query_as::<_, TypeCount>(&sql);
        if let Some(ref sid) = source_bytes {
            query = query.bind(&case_id_bytes).bind(sid);
        }
        query = query.bind(&case_id_bytes);

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to count record types")?;

        // Two rows can now carry the same label — the grouping is on the raw
        // discriminator, so a record type stored as the number 1 and one stored
        // as the string "1" group separately and only become the same text
        // afterwards. Adding them here keeps the endpoint's promise that each
        // type appears once with the number of records that bear it; showing an
        // examiner two "1" rows would read as two different kinds of record. The
        // list is one row per record type, so this costs nothing.
        let mut counts: Vec<(String, i64)> = Vec::with_capacity(rows.len());
        for r in rows {
            match counts.iter_mut().find(|(t, _)| *t == r.record_type) {
                Some((_, acc)) => *acc += r.count,
                None => counts.push((r.record_type, r.count)),
            }
        }
        // What a later run answered is not a second record of its type: the
        // census counts the type's whole population from the index and takes the
        // superseded rows off it, which is what keeps this fast (HUNT-107). A
        // type whose every record was answered leaves the list; it is not a kind
        // of record this case currently holds.
        let superseded = self.superseded_type_counts(case_id, source_id).await?;
        if !superseded.is_empty() {
            for (record_type, answered) in superseded {
                if let Some((_, count)) = counts.iter_mut().find(|(t, _)| *t == record_type) {
                    *count -= answered;
                }
            }
            counts.retain(|(_, count)| *count > 0);
        }

        // Re-established in Rust because merging can change the order the
        // statement returned: same order, count descending then name ascending.
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        Ok(counts)
    }

    /// Records of each type that a later run of the same module answered.
    ///
    /// Answered by `idx_artifacts_superseded`, so a case where nothing has been
    /// re-run pays a lookup that finds nothing rather than a scan that reads
    /// every record's metadata.
    pub async fn superseded_type_counts(
        &self,
        case_id: Uuid,
        source_id: Option<Uuid>,
    ) -> Result<Vec<(String, i64)>> {
        #[derive(sqlx::FromRow)]
        struct TypeCount {
            record_type: String,
            count: i64,
        }
        let case_id_bytes = case_id.as_bytes().to_vec();
        let source_bytes = source_id.map(|s| s.as_bytes().to_vec());
        let sql = Self::superseded_type_counts_sql(case_id, source_bytes.is_some());
        let mut query = sqlx::query_as::<_, TypeCount>(&sql);
        if let Some(ref sid) = source_bytes {
            query = query.bind(&case_id_bytes).bind(sid);
        }
        query = query.bind(&case_id_bytes);
        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to count superseded record types")?;
        let mut counts: Vec<(String, i64)> = Vec::with_capacity(rows.len());
        for r in rows {
            match counts.iter_mut().find(|(t, _)| *t == r.record_type) {
                Some((_, acc)) => *acc += r.count,
                None => counts.push((r.record_type, r.count)),
            }
        }
        Ok(counts)
    }

    /// Groups of artifacts that share a SHA-256, i.e. duplicate content across the
    /// evidence (§2.8). Ordered by group size (largest first — count-based
    /// prioritisation). `max_groups` caps how many groups are returned;
    /// `max_members` caps the members listed per group (the true `count` is kept).
    ///
    /// Neither cap is reported back: a result of exactly `max_groups` groups is
    /// the caller's only evidence that further duplicate sets exist, and a
    /// group whose `count` exceeds its `members.len()` is the only evidence
    /// that its member list is short. Both must be disclosed rather than
    /// presented as the whole duplicate picture.
    pub async fn duplicate_hash_groups(
        &self,
        case_id: Uuid,
        max_groups: i64,
        max_members: usize,
    ) -> Result<Vec<DuplicateGroup>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Vec<u8>,
            metadata_json: String,
            artifact_type: String,
            hash: String,
            member_count: i64,
        }
        // At least one member per group, or a group would come back with no
        // evidence of what is in it.
        let member_cap = max_members.max(1) as i64;
        // Members of the top-N most-duplicated SHA-256 groups. The inner query
        // uses the sha256 index; the window functions cap the members fetched
        // per group in SQL while still counting the whole group.
        //
        // The member cap MUST be applied in SQL. Fetching every member and
        // trimming afterwards means one hash with a hundred thousand copies
        // materialises a hundred thousand rows in this process to show the
        // caller a hundred of them.
        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, metadata_json, artifact_type, hash, member_count FROM ( \
               SELECT a.id AS id, a.metadata_json AS metadata_json, \
                      a.artifact_type AS artifact_type, a.sha256_hash AS hash, \
                      ROW_NUMBER() OVER (PARTITION BY a.sha256_hash ORDER BY a.rowid) AS rn, \
                      COUNT(*) OVER (PARTITION BY a.sha256_hash) AS member_count \
               FROM artifacts a \
               WHERE a.case_id = ? AND a.sha256_hash IS NOT NULL AND a.sha256_hash != '' \
                 AND a.sha256_hash IN ( \
                   SELECT sha256_hash FROM artifacts \
                   WHERE case_id = ? AND sha256_hash IS NOT NULL AND sha256_hash != '' \
                   GROUP BY sha256_hash HAVING COUNT(*) > 1 \
                   ORDER BY COUNT(*) DESC LIMIT ? \
                 ) \
             ) WHERE rn <= ? \
             ORDER BY hash",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(case_id.as_bytes().to_vec())
        .bind(max_groups)
        .bind(member_cap)
        .fetch_all(&self.pool)
        .await
        .context("Failed to query duplicate hash groups")?;

        let mut groups: Vec<DuplicateGroup> = Vec::new();
        for r in rows {
            let id = Uuid::from_slice(&r.id).context("Invalid UUID in duplicate group")?;
            let meta: serde_json::Value =
                serde_json::from_str(&r.metadata_json).unwrap_or(serde_json::Value::Null);
            let name = meta
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let path = meta
                .get("path")
                .or_else(|| meta.get("source_path"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let member = DuplicateMember {
                id,
                name,
                path,
                artifact_type: r.artifact_type,
            };
            match groups.last_mut() {
                // `count` is the group's true size from the window function,
                // not the number of members fetched: the member list is capped
                // and must never be mistaken for the whole group.
                Some(g) if g.hash == r.hash => g.members.push(member),
                _ => {
                    groups.push(DuplicateGroup {
                        hash: r.hash,
                        count: r.member_count.max(0) as usize,
                        members: vec![member],
                    });
                }
            }
        }
        // Largest groups first (count-based prioritisation).
        groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.hash.cmp(&b.hash)));
        Ok(groups)
    }

    /// File/media category counts for the logical navigator: Pictures, Videos
    /// and Documents by file extension, plus Geolocation (artifacts carrying GPS
    /// coordinates). One cheap aggregate per group — no row materialization.
    pub async fn media_counts(&self, case_id: Uuid) -> Result<MediaCounts> {
        let cid = case_id.as_bytes().to_vec();
        let (pictures, videos, audio, documents): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               COALESCE(SUM(CASE WHEN lower(name) LIKE '%.jpg' OR lower(name) LIKE '%.jpeg' \
                 OR lower(name) LIKE '%.png' OR lower(name) LIKE '%.gif' OR lower(name) LIKE '%.bmp' \
                 OR lower(name) LIKE '%.webp' OR lower(name) LIKE '%.heic' OR lower(name) LIKE '%.tiff' \
                 THEN 1 ELSE 0 END), 0), \
               COALESCE(SUM(CASE WHEN lower(name) LIKE '%.mp4' OR lower(name) LIKE '%.mov' \
                 OR lower(name) LIKE '%.avi' OR lower(name) LIKE '%.mkv' OR lower(name) LIKE '%.webm' \
                 OR lower(name) LIKE '%.m4v' OR lower(name) LIKE '%.wmv' THEN 1 ELSE 0 END), 0), \
               COALESCE(SUM(CASE WHEN lower(name) LIKE '%.mp3' OR lower(name) LIKE '%.m4a' \
                 OR lower(name) LIKE '%.aac' OR lower(name) LIKE '%.wav' OR lower(name) LIKE '%.flac' \
                 OR lower(name) LIKE '%.ogg' OR lower(name) LIKE '%.opus' OR lower(name) LIKE '%.amr' \
                 OR lower(name) LIKE '%.caf' OR lower(name) LIKE '%.aiff' THEN 1 ELSE 0 END), 0), \
               COALESCE(SUM(CASE WHEN lower(name) LIKE '%.pdf' OR lower(name) LIKE '%.doc' \
                 OR lower(name) LIKE '%.docx' OR lower(name) LIKE '%.xls' OR lower(name) LIKE '%.xlsx' \
                 OR lower(name) LIKE '%.ppt' OR lower(name) LIKE '%.pptx' OR lower(name) LIKE '%.txt' \
                 OR lower(name) LIKE '%.rtf' OR lower(name) LIKE '%.odt' THEN 1 ELSE 0 END), 0) \
             FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'FileEntry' \
               AND COALESCE(json_extract(metadata_json, '$.is_directory'), 0) <> 1",
        )
        .bind(&cid)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count media files")?;

        let geolocation: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE case_id = ? AND json_valid(metadata_json) \
               AND json_extract(metadata_json, '$.gps_lat') IS NOT NULL \
               AND json_extract(metadata_json, '$.gps_lon') IS NOT NULL \
               AND (COALESCE(json_extract(metadata_json, '$.type'), '') <> 'exif' \
                    OR json_extract(metadata_json, '$.has_gps') = 1)",
        )
        .bind(&cid)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count geolocation points")?;

        Ok(MediaCounts {
            pictures,
            audio,
            videos,
            documents,
            geolocation,
        })
    }

    /// Parsed-record metadata JSON blobs for entity extraction, newest first,
    /// bounded by `limit`. Returns (artifact_id, metadata_json).
    ///
    /// There is no truncation channel on the return, so a result of exactly
    /// `limit` rows is the caller's only evidence that the scan was bounded and
    /// MUST be disclosed: entity counts drawn from a capped scan are lower
    /// bounds, and "this address appears 12 times" read off a partial scan is a
    /// figure an examiner cannot defend.
    pub async fn list_parsed_record_metadata(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Vec<u8>,
            metadata_json: Option<String>,
        }
        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, metadata_json FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'ParsedRecord' AND metadata_json IS NOT NULL \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch parsed record metadata")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            if let Some(json) = r.metadata_json {
                let id = Uuid::from_slice(&r.id).context("Invalid artifact id")?;
                out.push((id, json));
            }
        }
        Ok(out)
    }

    /// Every `PerceptualHash` record in a case, with the image artifact it was
    /// computed from (`parent_id`) and its PDQ hex. Feeds near-duplicate
    /// clustering. The `LIKE` pre-filter keeps the scan to the perceptual records
    /// rather than every parsed record; `limit` bounds the payload.
    pub async fn list_perceptual_hashes(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PerceptualHashRow>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            metadata_json: Option<String>,
        }
        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, parent_id, metadata_json FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'ParsedRecord' \
             AND metadata_json LIKE '%\"type\":\"PerceptualHash\"%' \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch perceptual hash records")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Some(json) = r.metadata_json else {
                continue;
            };
            let Ok(meta) = serde_json::from_str::<serde_json::Value>(&json) else {
                continue;
            };
            // Guard against a LIKE false-positive (the substring inside some other
            // field): only accept a record whose type really is PerceptualHash.
            if meta.get("type").and_then(|v| v.as_str()) != Some("PerceptualHash") {
                continue;
            }
            let Some(pdq_hex) = meta.get("pdq_hex").and_then(|v| v.as_str()) else {
                continue;
            };
            let record_id = Uuid::from_slice(&r.id).context("Invalid artifact id")?;
            let parent_id = match r.parent_id {
                Some(b) => Some(Uuid::from_slice(&b).context("Invalid parent id")?),
                None => None,
            };
            out.push(PerceptualHashRow {
                record_id,
                parent_id,
                pdq_hex: pdq_hex.to_string(),
            });
        }
        Ok(out)
    }

    /// Communication network for a case: participants (nodes) and who
    /// communicated with whom (weighted edges), aggregated from parsed
    /// messaging and email records. Messaging is device-centric, so its
    /// contacts fan out from a single "This device" node; email forms a
    /// richer sender/recipient network. Node ids are normalized (lower-cased)
    /// addresses/handles so the same peer across records collapses to one node.
    pub async fn communication_graph(&self, case_id: Uuid) -> Result<CommunicationGraph> {
        self.communication_graph_with_email_cap(case_id, COMMUNICATION_GRAPH_EMAIL_CAP)
            .await
    }

    /// [`Self::communication_graph`] with an explicit email row ceiling.
    ///
    /// The ceiling is a parameter only so the truncation disclosure can be
    /// exercised without materialising fifty thousand email records; production
    /// always uses [`COMMUNICATION_GRAPH_EMAIL_CAP`].
    pub async fn communication_graph_with_email_cap(
        &self,
        case_id: Uuid,
        email_row_cap: usize,
    ) -> Result<CommunicationGraph> {
        use std::collections::HashMap;

        const MAX_NODES: usize = 250;
        const SELF_ID: &str = "\u{1}self"; // reserved, cannot collide with a real address
        let case_bytes = case_id.as_bytes().to_vec();

        let mut nodes: HashMap<String, CommNode> = HashMap::new();
        let mut edges: HashMap<(String, String), i64> = HashMap::new();

        fn touch(nodes: &mut HashMap<String, CommNode>, id: &str, label: &str, kind: &str, w: i64) {
            let n = nodes.entry(id.to_string()).or_insert_with(|| CommNode {
                id: id.to_string(),
                label: label.to_string(),
                kind: kind.to_string(),
                weight: 0,
            });
            n.weight += w;
            // Prefer a human label over a bare id if one shows up later.
            if n.label == n.id && label != id && !label.is_empty() {
                n.label = label.to_string();
            }
        }
        fn add_edge(
            nodes: &mut HashMap<String, CommNode>,
            edges: &mut HashMap<(String, String), i64>,
            a_id: &str,
            a_label: &str,
            a_kind: &str,
            b_id: &str,
            b_label: &str,
            b_kind: &str,
            w: i64,
        ) {
            if a_id == b_id {
                return;
            }
            touch(nodes, a_id, a_label, a_kind, w);
            touch(nodes, b_id, b_label, b_kind, w);
            let key = if a_id < b_id {
                (a_id.to_string(), b_id.to_string())
            } else {
                (b_id.to_string(), a_id.to_string())
            };
            *edges.entry(key).or_insert(0) += w;
        }

        // --- Messaging: one edge per (peer) from the device owner. ---
        #[derive(sqlx::FromRow)]
        struct PeerRow {
            peer: Option<String>,
            rtype: Option<String>,
            count: i64,
        }
        // The peer key must cover every messaging type in the filter, not just
        // the iMessage/SMS field names: WhatsApp records the correspondent as a
        // JID (`contact_jid` on iOS, `remote_jid` on Android) or a group
        // `chat_subject`, so keying only on chat_display_name/chat_identifier/
        // contact left `peer` NULL and dropped WhatsApp from the graph entirely.
        // The JID order mirrors `thread_key_expr`, so a graph node is the same
        // key the conversation view threads on.
        //
        // The type list must likewise cover every messaging platform the tree
        // parses. Restricted to iMessage/WhatsApp/SMS/calls, the Connections
        // view of a Signal-and-Instagram case drew an empty graph while the
        // case held tens of thousands of messages — an understated contact
        // network is a wrong investigative conclusion, not a cosmetic gap.
        let msg_rows = sqlx::query_as::<_, PeerRow>(
            "SELECT COALESCE(\
                       json_extract(metadata_json,'$.chat_display_name'), \
                       json_extract(metadata_json,'$.chat_identifier'), \
                       json_extract(metadata_json,'$.contact_jid'), \
                       json_extract(metadata_json,'$.remote_jid'), \
                       json_extract(metadata_json,'$.from_jid'), \
                       json_extract(metadata_json,'$.to_jid'), \
                       json_extract(metadata_json,'$.chat_subject'), \
                       json_extract(metadata_json,'$.conversation_id'), \
                       json_extract(metadata_json,'$.contact')) AS peer, \
                    json_extract(metadata_json,'$.type') AS rtype, \
                    COUNT(*) AS count \
             FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'ParsedRecord' \
               AND json_extract(metadata_json,'$.type') IN (\
                   'iMessage','WhatsApp','AndroidSms','CallLog',\
                   'Signal','Instagram','Snapchat','TwitterDM',\
                   'Skype','LINE','TelegramMessage','Viber','Kik','WeChat',\
                   'FacebookMessenger') \
             GROUP BY peer, rtype",
        )
        .bind(&case_bytes)
        .fetch_all(&self.pool)
        .await
        .context("Failed to aggregate messaging peers")?;

        let mut has_messaging = false;
        let mut records_without_counterparty = 0i64;
        for row in msg_rows {
            let Some(peer) = row.peer else { continue };
            let peer = peer.trim();
            if peer.is_empty() {
                continue;
            }
            // The call-history parser's stand-in for "no number recorded" is a
            // placeholder, not a party (see `CALL_LOG_NO_NUMBER`): drawn as a
            // node it would be a phantom correspondent, so it is counted and
            // disclosed instead. Only a CallLog row is a stand-in; a chat
            // correspondent really named "Unknown" stays.
            if row.rtype.as_deref() == Some("CallLog") && peer == Self::CALL_LOG_NO_NUMBER {
                records_without_counterparty += row.count;
                continue;
            }
            has_messaging = true;
            let pid = normalize_handle(peer);
            add_edge(
                &mut nodes,
                &mut edges,
                SELF_ID,
                "This device",
                "self",
                &pid,
                peer,
                "contact",
                row.count,
            );
        }
        if has_messaging {
            // Ensure the self node exists even if every edge was self-referential.
            touch(&mut nodes, SELF_ID, "This device", "self", 0);
        }

        // --- Email: from <-> each recipient (to + cc). ---
        #[derive(sqlx::FromRow)]
        struct MetaRow {
            metadata_json: Option<String>,
        }
        let email_row_cap = email_row_cap.max(1);
        let email_rows = sqlx::query_as::<_, MetaRow>(
            "SELECT metadata_json FROM artifacts \
             WHERE case_id = ? AND artifact_type = 'ParsedRecord' \
               AND json_extract(metadata_json,'$.type') = 'EmailMessage' \
             LIMIT ?",
        )
        .bind(&case_bytes)
        .bind(email_row_cap as i64)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch email records")?;

        // A full page means there are emails this graph never weighed. The
        // network is then incomplete for a reason that has nothing to do with
        // the node cap, and `truncated: false` alongside it would tell an
        // examiner the contact network they are looking at is the whole one.
        let email_rows_capped = email_rows.len() >= email_row_cap;
        // Rows the aggregation could not use are counted, not silently skipped:
        // "no email edges" and "every email row was undecodable" must not look
        // the same.
        let mut email_rows_unusable: usize = 0;

        for row in email_rows {
            let Some(json) = row.metadata_json else {
                email_rows_unusable += 1;
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
                email_rows_unusable += 1;
                continue;
            };
            let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("").trim();
            if from.is_empty() {
                email_rows_unusable += 1;
                continue;
            }
            let from_name = v
                .get("from_name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim();
            let from_id = normalize_handle(from);
            let from_label = if from_name.is_empty() {
                from
            } else {
                from_name
            };

            let mut recipients: Vec<String> = Vec::new();
            for key in ["to", "cc"] {
                if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
                    for r in arr {
                        if let Some(s) = r.as_str() {
                            let s = s.trim();
                            if !s.is_empty() {
                                recipients.push(s.to_string());
                            }
                        }
                    }
                } else if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
                    let s = s.trim();
                    if !s.is_empty() {
                        recipients.push(s.to_string());
                    }
                }
            }
            for r in recipients {
                let rid = normalize_handle(&r);
                add_edge(
                    &mut nodes, &mut edges, &from_id, from_label, "email", &rid, &r, "email", 1,
                );
            }
        }

        if email_rows_unusable > 0 {
            warn!(
                "communication graph for case {}: {} email record(s) contributed no edge \
                 (missing metadata, undecodable JSON, or no sender)",
                case_id, email_rows_unusable
            );
        }
        if email_rows_capped {
            warn!(
                "communication graph for case {}: email aggregation stopped at the {} row cap; \
                 the network is reported as truncated",
                case_id, email_row_cap
            );
        }

        // Cap to the heaviest MAX_NODES participants; drop edges to dropped nodes.
        let total_nodes = nodes.len();
        let mut kept: Vec<CommNode> = nodes.into_values().collect();
        kept.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.id.cmp(&b.id)));
        // Truncation is EITHER cap: more participants than the node ceiling, or
        // email rows the query never read. Reporting only the first understated
        // the network on any case with more than 50k emails.
        let truncated = kept.len() > MAX_NODES || email_rows_capped;
        kept.truncate(MAX_NODES);
        let keep_ids: std::collections::HashSet<&str> =
            kept.iter().map(|n| n.id.as_str()).collect();

        let mut out_edges: Vec<CommEdge> = edges
            .into_iter()
            .filter(|((a, b), _)| keep_ids.contains(a.as_str()) && keep_ids.contains(b.as_str()))
            .map(|((source, target), weight)| CommEdge {
                source,
                target,
                weight,
            })
            .collect();
        // Heaviest first, ties by (source, target): the edges come out of a
        // `HashMap`, whose order differs between calls, and the same question
        // must get the same answer every time it is asked.
        out_edges.sort_by(|a, b| {
            b.weight
                .cmp(&a.weight)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.target.cmp(&b.target))
        });

        Ok(CommunicationGraph {
            nodes: kept,
            edges: out_edges,
            truncated,
            total_participants: total_nodes as i64,
            unusable_email_records: email_rows_unusable as i64,
            records_without_counterparty,
        })
    }

    // --- User management (multi-user RBAC) ---

    /// Insert a new user. `password_hash` MUST already be a bcrypt hash; this
    /// layer never sees plaintext (hashing stays in the API layer, matching
    /// `AuthConfig`). `role` must be `admin` or `examiner`; an invalid role is
    /// rejected by the CHECK constraint. Returns the new user's UUID.
    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let created_at = Utc::now().timestamp();

        sqlx::query(
            // `sessions_invalid_before` is stamped at creation, and that closes a
            // route `SEC-002` did not cover. The middleware keys a token on its
            // username; delete an account and re-create the username and every
            // un-revoked token minted for the OLD account presented as the new
            // one — row found, active, no stamp to fail against — attributed to
            // the new row with its role. A row born with the stamp refuses any
            // token minted before it existed.
            "INSERT INTO users (id, username, password_hash, role, active, created_at, sessions_invalid_before) VALUES (?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(id)
        .bind(username)
        .bind(password_hash)
        .bind(role)
        .bind(created_at)
        // One second BEFORE now, and the difference is not cosmetic. The
        // middleware refuses `iat <= stamp` in whole seconds, and an account is
        // routinely created and signed into within the same second — a
        // bootstrap script, an admin adding an examiner who is waiting, every
        // test in this tree. Stamped at `now`, the first login of every new
        // account was refused. Stamped at `now - 1`, what is refused is any
        // token minted before the second the row was born in — which is every
        // token a previous holder of this username could have — and the window
        // left open is a token minted for the OLD account in the very second the
        // new one was created, after the old one was deleted: three events in
        // one second, and the token still dies at the old account's deletion
        // stamp if that account was ever deactivated first.
        .bind(Utc::now().timestamp() - 1)
        .execute(&self.pool)
        .await
        .context("Failed to create user")?;

        info!("Created user '{}' with role '{}'", username, role);
        Ok(id)
    }

    /// Look up a user by username for the login path. Returns the stored
    /// bcrypt hash and role so the caller can verify the password and mint a
    /// token carrying the real role. Returns `None` when no such user exists.
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserRow>> {
        Self::map_user_row(
            sqlx::query_as::<_, RawUserRow>(
                "SELECT id, username, password_hash, role, active, must_change_password, password_changed_at, sessions_invalid_before FROM users WHERE username = ?",
            )
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch user by username")?,
        )
    }

    /// List all users (admin management view). The bcrypt hash is included in
    /// `UserRow`; API responses must never serialize it back to clients.
    pub async fn list_users(&self) -> Result<Vec<UserRow>> {
        let rows: Vec<RawUserRow> = sqlx::query_as::<_, RawUserRow>(
            "SELECT id, username, password_hash, role, active, must_change_password, password_changed_at, sessions_invalid_before FROM users ORDER BY username ASC",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to list users")?;

        rows.into_iter()
            .map(|r| {
                Ok(UserRow {
                    id: Uuid::from_slice(&r.id).context("Invalid UUID for user ID")?,
                    username: r.username,
                    password_hash: r.password_hash,
                    role: r.role,
                    active: r.active != 0,
                    must_change_password: r.must_change_password != 0,
                    password_changed_at: r.password_changed_at,
                    sessions_invalid_before: r.sessions_invalid_before,
                })
            })
            .collect()
    }

    /// Activate or deactivate a user. A deactivated user cannot log in.
    /// Returns `true` when a matching row existed (so the API can 404).
    ///
    /// **Deactivating also ends the sessions that were live at the time**, and
    /// ends them permanently (SEC-002). The middleware's existing refusal of a
    /// token for an inactive user lasts only while the account stays inactive,
    /// so before this stamp existed, reactivating an account resurrected every
    /// token minted before it was deactivated. `sessions_invalid_before` is
    /// stamped here and never cleared: reactivation restores the account, not
    /// the sessions, and an examiner returning to work signs in again.
    ///
    /// Reactivating stamps nothing. Moving the stamp forward on reactivation
    /// would invalidate tokens minted *during* the deactivated period, and there
    /// are none — every request in that window was refused.
    pub async fn set_user_active(&self, id: Uuid, active: bool) -> Result<bool> {
        let result = if active {
            sqlx::query("UPDATE users SET active = 1 WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
        } else {
            // Whole Unix seconds, matching `password_changed_at`, because the
            // middleware compares both against the same whole-second `iat` and
            // rejects the equal second in each case.
            sqlx::query("UPDATE users SET active = 0, sessions_invalid_before = ? WHERE id = ?")
                .bind(Utc::now().timestamp())
                .bind(id)
                .execute(&self.pool)
                .await
        }
        .context("Failed to update user active status")?;
        Ok(result.rows_affected() > 0)
    }

    /// Replace a user's password hash. `new_hash` MUST be a bcrypt hash.
    /// Clears any `must_change_password` flag: changing the password satisfies
    /// the forced-rotation requirement. Returns `true` when a matching row existed.
    pub async fn update_user_password(&self, id: Uuid, new_hash: &str) -> Result<bool> {
        // Stamp password_changed_at so the auth middleware can reject any JWT
        // issued before this rotation (BUG-076).
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 0, password_changed_at = ? WHERE id = ?",
        )
        .bind(new_hash)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update user password")?;
        Ok(result.rows_affected() > 0)
    }

    /// The skin this user chose, or `None` if they never have.
    ///
    /// `None` and "the default skin" are deliberately different answers. A user
    /// who has never chosen follows whatever this build ships as its default and
    /// keeps following it if that default changes; a user who chose the default
    /// explicitly has said something, and it stays said.
    pub async fn get_user_theme(&self, username: &str) -> Result<Option<String>> {
        let theme: Option<Option<String>> =
            sqlx::query_scalar("SELECT theme FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .context("Failed to read the user's theme")?;
        Ok(theme.flatten().filter(|t| !t.is_empty()))
    }

    /// Record a user's chosen skin, or clear it with `None`.
    ///
    /// Returns `true` when a matching row existed, so the API can 404 rather
    /// than report a success it did not have.
    ///
    /// The value is validated by [`is_valid_theme`] before it is stored. This is
    /// a string chosen by the client and echoed back to every session that user
    /// opens, so the two things that matter are that it cannot be unbounded and
    /// that it cannot carry anything but the shape a theme name has.
    pub async fn set_user_theme(&self, id: Uuid, theme: Option<&str>) -> Result<bool> {
        if let Some(value) = theme {
            anyhow::ensure!(
                is_valid_theme(value),
                "not a theme name: expected `<skin>:light` or `<skin>:dark`, got {value:?}"
            );
        }
        let result = sqlx::query("UPDATE users SET theme = ? WHERE id = ?")
            .bind(theme)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update the user's theme")?;
        Ok(result.rows_affected() > 0)
    }

    /// Set (or clear) the forced-password-change flag for a user. Used by the
    /// admin bootstrap to require rotation of a default-seeded password.
    pub async fn set_must_change_password(&self, id: Uuid, must_change: bool) -> Result<bool> {
        let result = sqlx::query("UPDATE users SET must_change_password = ? WHERE id = ?")
            .bind(if must_change { 1 } else { 0 })
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update must_change_password")?;
        Ok(result.rows_affected() > 0)
    }

    /// Record that the session identified by `jti` has been ended before its
    /// token expires (SEC-001). Idempotent: logging the same token out twice
    /// keeps the first `revoked_at`.
    pub async fn revoke_token(
        &self,
        jti: &str,
        user_id: Option<Uuid>,
        username: &str,
        expires_at: i64,
        revoked_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, username, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(jti)
        .bind(user_id)
        .bind(username)
        .bind(expires_at)
        .bind(revoked_at)
        .execute(&self.pool)
        .await
        .context("Failed to record revoked token")?;
        Ok(())
    }

    /// Whether the token identified by `jti` has been revoked. One primary-key
    /// lookup; the auth middleware runs it on every authenticated request.
    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM revoked_tokens WHERE jti = ?")
            .bind(jti)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to check token revocation")?;
        Ok(found.is_some())
    }

    /// Drop revocation rows for tokens that have expired on their own by `now`
    /// (Unix seconds): a token past its `exp` is refused by signature
    /// validation before the revocation list is consulted, so the row no
    /// longer guards anything. Returns the number of rows removed.
    pub async fn purge_expired_revoked_tokens(&self, now: i64) -> Result<u64> {
        // Keep a margin below `now`. A revocation row must outlive every reading
        // of the token it revokes: if a validator ever accepts a token past its
        // `exp` (jsonwebtoken's default leeway is 60s, which this build sets to
        // zero), deleting the row at exactly `exp` would leave the token
        // acceptable and unrevoked. Sweeping only what expired a margin ago
        // means the two cannot open that window between them.
        const PURGE_MARGIN_SECS: i64 = 300;
        let now = now.saturating_sub(PURGE_MARGIN_SECS);
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("Failed to purge expired revoked tokens")?;
        Ok(result.rows_affected())
    }

    /// Number of user rows. Used at startup to decide whether to bootstrap the
    /// initial admin, and as the login-path fallback guard (env admin only
    /// works while this is 0).
    pub async fn count_users(&self) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .context("Failed to count users")?;
        Ok(count)
    }

    /// Number of active admin users. Used to prevent deleting or demoting the
    /// last admin, which would lock out all admin-only functions.
    pub async fn count_admins(&self) -> Result<i64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1")
                .fetch_one(&self.pool)
                .await
                .context("Failed to count admins")?;
        Ok(count)
    }

    /// Shared BLOB-UUID / INTEGER-bool decoding for a single optional user row.
    fn map_user_row(row: Option<RawUserRow>) -> Result<Option<UserRow>> {
        match row {
            Some(r) => Ok(Some(UserRow {
                id: Uuid::from_slice(&r.id).context("Invalid UUID for user ID")?,
                username: r.username,
                password_hash: r.password_hash,
                role: r.role,
                active: r.active != 0,
                must_change_password: r.must_change_password != 0,
                password_changed_at: r.password_changed_at,
                sessions_invalid_before: r.sessions_invalid_before,
            })),
            None => Ok(None),
        }
    }

    /// Look up a user by id (management view). Returns `None` when absent.
    /// Used by role/delete handlers and to resolve the target of an access grant.
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<Option<UserRow>> {
        Self::map_user_row(
            sqlx::query_as::<_, RawUserRow>(
                "SELECT id, username, password_hash, role, active, must_change_password, password_changed_at, sessions_invalid_before FROM users WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch user by id")?,
        )
    }

    /// Update a user's role. `role` must be `admin` or `examiner` (enforced by
    /// the CHECK constraint). Returns `true` when a matching row existed.
    pub async fn update_user_role(&self, id: Uuid, role: &str) -> Result<bool> {
        let result = sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update user role")?;
        Ok(result.rows_affected() > 0)
    }

    /// Hard-delete a user. The `case_access` FK (ON DELETE CASCADE) removes any
    /// grants held by this user. Returns `true` when a matching row existed.
    pub async fn delete_user(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete user")?;
        Ok(result.rows_affected() > 0)
    }

    // --- Per-case access control (multi-user RBAC) ---

    /// Grant (or update) a user's access level to a case. Upserts on the
    /// (case_id, user_id) primary key, so re-granting changes the level rather
    /// than failing on a duplicate. `access_level` must be `read_only`,
    /// `read_write`, or `owner` (enforced by the CHECK constraint).
    /// `granted_by` is the acting user's id (`None` for system-granted rows).
    pub async fn grant_case_access(
        &self,
        case_id: Uuid,
        user_id: Uuid,
        access_level: &str,
        granted_by: Option<Uuid>,
    ) -> Result<()> {
        let granted_at = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO case_access (case_id, user_id, access_level, granted_by, granted_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(case_id, user_id) DO UPDATE SET \
                 access_level = excluded.access_level, \
                 granted_by = excluded.granted_by, \
                 granted_at = excluded.granted_at",
        )
        .bind(case_id)
        .bind(user_id)
        .bind(access_level)
        .bind(granted_by)
        .bind(granted_at)
        .execute(&self.pool)
        .await
        .context("Failed to grant case access")?;
        Ok(())
    }

    /// Revoke a user's access to a case. Returns `true` when a row was removed
    /// (so the API can 404 an attempt to revoke a grant that does not exist).
    pub async fn revoke_case_access(&self, case_id: Uuid, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM case_access WHERE case_id = ? AND user_id = ?")
            .bind(case_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .context("Failed to revoke case access")?;
        Ok(result.rows_affected() > 0)
    }

    /// List all access grants for a case as `(user_id, username, access_level)`,
    /// joined to `users` so callers can render names. Ordered by username.
    pub async fn list_case_access(&self, case_id: Uuid) -> Result<Vec<(Uuid, String, String)>> {
        #[derive(sqlx::FromRow)]
        struct AccessRow {
            user_id: Vec<u8>,
            username: String,
            access_level: String,
        }

        let rows: Vec<AccessRow> = sqlx::query_as::<_, AccessRow>(
            "SELECT ca.user_id AS user_id, u.username AS username, ca.access_level AS access_level \
             FROM case_access ca JOIN users u ON u.id = ca.user_id \
             WHERE ca.case_id = ? ORDER BY u.username ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list case access")?;

        rows.into_iter()
            .map(|r| {
                Ok((
                    Uuid::from_slice(&r.user_id).context("Invalid UUID for case_access user_id")?,
                    r.username,
                    r.access_level,
                ))
            })
            .collect()
    }

    /// Case IDs a user holds any access grant for. Drives the case-list filter
    /// for non-admins (admins see every case and never consult this).
    pub async fn list_accessible_case_ids(&self, user_id: Uuid) -> Result<Vec<Uuid>> {
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT case_id FROM case_access WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to list accessible case ids")?;
        rows.into_iter()
            .map(|b| Uuid::from_slice(&b).context("Invalid UUID for case_access case_id"))
            .collect()
    }

    /// Whether a user holds any access grant for a case. This is purely the
    /// per-case grant check; role-based bypass for admins is applied in the API
    /// layer so this method stays a single, auditable authorization primitive.
    pub async fn user_can_access_case(&self, user_id: Uuid, case_id: Uuid) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM case_access WHERE user_id = ? AND case_id = ?",
        )
        .bind(user_id)
        .bind(case_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to check case access")?;
        Ok(count > 0)
    }

    /// The access level a user holds on a case (`read_only` | `read_write` |
    /// `owner`), or `None` if the user holds no grant. Used to enforce that a
    /// `read_only` grantee cannot mutate case data.
    pub async fn case_access_level(&self, user_id: Uuid, case_id: Uuid) -> Result<Option<String>> {
        let level: Option<String> = sqlx::query_scalar(
            "SELECT access_level FROM case_access WHERE user_id = ? AND case_id = ?",
        )
        .bind(user_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to read case access level")?;
        Ok(level)
    }

    // --- Audit Logging ---

    /// Record an audit event as the next link in the tamper-evident hash chain.
    ///
    /// The chain is GLOBAL (spans all cases): each row's `entry_hash` is
    /// SHA256 over the previous chained row's `entry_hash` plus this row's
    /// content fields. Rows written before migration 0017 have NULL
    /// `entry_hash` and are outside the chain; the first row written after
    /// the migration is the genesis row (NULL `prev_hash`).
    ///
    /// `case_id` is deliberately excluded from the hash: audit rows survive
    /// case deletion via ON DELETE SET NULL, and nulling `case_id` must not
    /// break the chain.
    pub async fn record_audit_event(
        &self,
        case_id: Option<Uuid>,
        user_id: &str,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        details: Option<&str>,
    ) -> Result<()> {
        let timestamp = Utc::now().to_rfc3339();

        // Serialize audit writes: two concurrent writers reading the same
        // chain head would fork the chain.
        let _guard = self.audit_lock.lock().await;

        // Read the head and append the row inside ONE write transaction, taken
        // with BEGIN IMMEDIATE so it holds the database's write lock from the
        // read onward. `audit_lock` serialises writers in this process; it
        // cannot see a second process — `seance reset-admin` or a CLI scan
        // run against a workspace the server is also writing — and two
        // processes that both read the head and then both insert would leave
        // two rows chained from one predecessor, which the verifier reports as
        // a break at the second. With the lock taken at the read, the second
        // process's read waits (up to the pool's 30 s busy timeout) for the
        // first's commit and chains from the row it wrote (HUNT-038).
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to open the audit write transaction")?;

        let prev_hash: Option<String> = sqlx::query_scalar(
            "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to read audit chain head")?;

        let resource_id_str = resource_id.map(|u| u.to_string());
        let entry_hash = compute_audit_entry_hash(
            self.audit_hmac_key.as_deref(),
            prev_hash.as_deref(),
            &timestamp,
            user_id,
            action,
            resource_type,
            resource_id_str.as_deref(),
            details,
        );

        // The row names the key it was hashed under by fingerprint (NULL when
        // unkeyed), so a later verifier under a rotated or newly introduced key
        // knows which digest to recompute rather than guessing. The key itself
        // is never stored.
        let key_fingerprint = self.audit_hmac_key.as_deref().map(audit_key_fingerprint);

        sqlx::query(
            "INSERT INTO audit_log (case_id, timestamp, user_id, action, resource_type, resource_id, details, prev_hash, entry_hash, key_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(case_id)
        .bind(&timestamp)
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(details)
        .bind(&prev_hash)
        .bind(&entry_hash)
        .bind(&key_fingerprint)
        .execute(&mut *tx)
        .await
        .context("Failed to record audit event")?;
        tx.commit()
            .await
            .context("Failed to commit the audit event")?;

        debug!("Audit: {} by {} (case: {:?})", action, user_id, case_id);
        Ok(())
    }

    /// The `entry_hash` stored for one audit row, or `None` when no such row
    /// exists.
    ///
    /// This is what makes an external anchor answerable. Comparing an anchor
    /// against the CURRENT head cannot work: the audit log grows on every
    /// examiner action, so the head legitimately moves and a head comparison
    /// would report tampering during ordinary use. Anchoring names a ROW —
    /// "entry 300 hashed to X" — and this looks that row up: still present with
    /// the same hash means nothing at or before it was removed or rewritten;
    /// absent means the tail was truncated past it; present with a different
    /// hash means it was rewritten.
    pub async fn audit_entry_hash(&self, id: i64) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT entry_hash FROM audit_log WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to read audit entry hash")
            .map(|row: Option<Option<String>>| row.flatten())
    }

    /// Verify the audit-log hash chain by recomputing every chained row's hash
    /// in id order.
    ///
    /// The chain is global, so verification always walks ALL chained rows —
    /// `_case_id` is accepted for API symmetry but a break anywhere invalidates
    /// the audit trail for every case. Legacy rows (NULL `entry_hash`, written
    /// before migration 0017) are skipped and not counted.
    ///
    /// Each row is recomputed under the key its `key_fingerprint` names: the
    /// current `SEANCE_AUDIT_HMAC_KEY`, or a retired one from
    /// `SEANCE_AUDIT_HMAC_KEY_PREVIOUS`. A row with no fingerprint is either
    /// unkeyed or was written keyed before fingerprints existed (migration 0032),
    /// so the configured keys are tried first and the unkeyed digest last. That
    /// fallback is allowed only while no keyed row has yet been seen: an unkeyed
    /// row that verifies AFTER a keyed one is exactly what replacing the tail of
    /// a keyed chain from database access alone would produce, and is a break.
    ///
    /// What a `valid` result is worth depends on which rows were keyed: see
    /// [`AuditChainStatus::tamper_evident`] and
    /// [`AuditChainStatus::tamper_evident_from`], which every caller must report
    /// beside the verdict.
    pub async fn verify_audit_chain(&self, _case_id: Option<Uuid>) -> Result<AuditChainStatus> {
        let rows = sqlx::query(
            "SELECT id, timestamp, user_id, action, resource_type, resource_id, details, prev_hash, entry_hash, key_fingerprint FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch audit log for chain verification")?;

        let current_key = self.audit_hmac_key.as_deref();
        let current_fingerprint = current_key.map(audit_key_fingerprint);
        let retired_keys: Vec<(String, &[u8])> = self
            .audit_hmac_previous_keys
            .iter()
            .map(|k| (audit_key_fingerprint(k), k.as_slice()))
            .collect();

        let mut prev_hash: Option<String> = None;
        let mut checked = 0i64;
        let mut keyed_rows = 0i64;
        let mut unkeyed_rows = 0i64;
        // The last chained row seen — the head published on success.
        let mut head_id: Option<i64> = None;
        let mut head_hash: Option<String> = None;
        // First row of the run of keyed rows that reaches the chain head. Reset
        // by an unkeyed row, though in a chain that verifies an unkeyed row can
        // only precede the keyed run, never interrupt it.
        let mut keyed_run_start: Option<i64> = None;
        let mut chain_started = false;

        // Every exit builds the same status from the same counters, so a
        // break can never be reported with stale keyed/unkeyed figures.
        let finish = |valid: bool,
                      checked: i64,
                      keyed_rows: i64,
                      unkeyed_rows: i64,
                      keyed_run_start: Option<i64>,
                      broken_at: Option<i64>,
                      break_reason: Option<String>| AuditChainStatus {
            valid,
            checked,
            broken_at,
            // Tamper-evident when no checked row was written unkeyed AND a
            // server-held secret is protecting the log — either because one is
            // configured now, or because every row already checked recomputed
            // under one.
            //
            // Requiring the CURRENT key alone was wrong: a row matched by
            // fingerprint against a RETIRED key is counted keyed, so verifying
            // an archived database on a workstation that holds only
            // SEANCE_AUDIT_HMAC_KEY_PREVIOUS produced `keyed_rows == N,
            // unkeyed_rows == 0, tamper_evident == false`, and the report then
            // rendered the PARTIALLY-keyed disclosure — "rows before entry 1
            // were written unkeyed" — when no row precedes the first and none
            // was unkeyed.
            //
            // Requiring `keyed_rows > 0` alone is wrong in the other direction,
            // and this is the case that matters most: a chain that BREAKS AT ITS
            // FIRST ROW has counted no keyed row yet, because a row is counted
            // only after it verifies. A keyed chain whose opening row was
            // rewritten would then report itself not tamper-evident — at the
            // exact moment the key had just proved its worth by detecting the
            // rewrite. The key is what made the alteration visible; saying the
            // log is not tamper-evident there understates the finding.
            //
            // An empty chain with no key configured is not tamper-evident either
            // way: there is nothing for the adjective to describe.
            tamper_evident: (current_key.is_some() || keyed_rows > 0) && unkeyed_rows == 0,
            keyed_rows,
            unkeyed_rows,
            tamper_evident_from: keyed_run_start,
            break_reason,
            // Set only on the success path below; a broken chain has no head to
            // publish.
            head_id: None,
            head_hash: None,
            key_configured: current_key.is_some(),
        };

        for row in rows {
            let id: i64 = row.try_get("id")?;
            let entry_hash: Option<String> = row.try_get("entry_hash")?;
            let Some(entry_hash) = entry_hash else {
                if chain_started {
                    // A NULL entry_hash AFTER the chain began is a tamper marker:
                    // nulling a row's hash was previously enough to exclude it
                    // from verification. Treat it as a break, not a skip. Only
                    // leading legacy rows (before the first chained row) are
                    // allowed to be NULL.
                    return Ok(finish(
                        false,
                        checked,
                        keyed_rows,
                        unkeyed_rows,
                        keyed_run_start,
                        Some(id),
                        Some(format!(
                            "row {id} has no entry hash but follows chained rows; a chained row's hash cannot be absent"
                        )),
                    ));
                }
                continue; // pre-chain legacy row
            };
            chain_started = true;
            checked += 1;

            let stored_prev: Option<String> = row.try_get("prev_hash")?;
            let timestamp: String = row.try_get("timestamp")?;
            let user_id: String = row.try_get("user_id")?;
            let action: String = row.try_get("action")?;
            let resource_type: Option<String> = row.try_get("resource_type")?;
            let resource_id: Option<Vec<u8>> = row.try_get("resource_id")?;
            let details: Option<String> = row.try_get("details")?;
            let fingerprint: Option<String> = row.try_get("key_fingerprint")?;

            let resource_id_str = match resource_id {
                Some(bytes) => Some(
                    Uuid::from_slice(&bytes)
                        .context("Invalid resource_id UUID in audit log")?
                        .to_string(),
                ),
                None => None,
            };

            let recompute = |key: Option<&[u8]>| {
                compute_audit_entry_hash(
                    key,
                    prev_hash.as_deref(),
                    &timestamp,
                    &user_id,
                    &action,
                    resource_type.as_deref(),
                    resource_id_str.as_deref(),
                    details.as_deref(),
                )
            };

            if stored_prev != prev_hash {
                return Ok(finish(
                    false,
                    checked,
                    keyed_rows,
                    unkeyed_rows,
                    keyed_run_start,
                    Some(id),
                    Some(format!(
                        "row {id}'s prev_hash does not match the entry hash of the row before it"
                    )),
                ));
            }

            // Which key this row claims, and whether the digest agrees.
            let row_keyed: bool = match fingerprint.as_deref() {
                Some(fp) if current_fingerprint.as_deref() == Some(fp) => {
                    if recompute(current_key) != entry_hash {
                        return Ok(finish(
                            false,
                            checked,
                            keyed_rows,
                            unkeyed_rows,
                            keyed_run_start,
                            Some(id),
                            Some(format!(
                                "row {id} does not recompute under the current key (fingerprint {fp}); its content or hash has been altered"
                            )),
                        ));
                    }
                    true
                }
                Some(fp) => match retired_keys.iter().find(|(rfp, _)| rfp == fp) {
                    Some((_, key)) => {
                        if recompute(Some(key)) != entry_hash {
                            return Ok(finish(
                                false,
                                checked,
                                keyed_rows,
                                unkeyed_rows,
                                keyed_run_start,
                                Some(id),
                                Some(format!(
                                    "row {id} does not recompute under the retired key it names (fingerprint {fp}); its content or hash has been altered"
                                )),
                            ));
                        }
                        true
                    }
                    None => {
                        // The row says which key it needs and the server does not
                        // hold it. That is not a tampered row, but it is a chain
                        // this server cannot vouch for, and the fix is named.
                        let reason = if current_key.is_none() && retired_keys.is_empty() {
                            format!(
                                "row {id} was written under key fingerprint {fp} but no audit key is configured; set SEANCE_AUDIT_HMAC_KEY (or list the retired key in SEANCE_AUDIT_HMAC_KEY_PREVIOUS) to verify it"
                            )
                        } else {
                            format!(
                                "row {id} was written under key fingerprint {fp}, which matches neither SEANCE_AUDIT_HMAC_KEY nor any key in SEANCE_AUDIT_HMAC_KEY_PREVIOUS; add the retired key there to verify it"
                            )
                        };
                        return Ok(finish(
                            false,
                            checked,
                            keyed_rows,
                            unkeyed_rows,
                            keyed_run_start,
                            Some(id),
                            Some(reason),
                        ));
                    }
                },
                None => {
                    // No fingerprint: written unkeyed, or keyed before migration
                    // 0032 recorded fingerprints. Prefer the keyed reading -- a
                    // row that recomputes under a server-held secret was written
                    // by the server -- and fall back to unkeyed only where an
                    // unkeyed row could legitimately sit.
                    let keyed_match = current_key
                        .filter(|k| recompute(Some(k)) == entry_hash)
                        .is_some()
                        || retired_keys
                            .iter()
                            .any(|(_, k)| recompute(Some(k)) == entry_hash);
                    if keyed_match {
                        true
                    } else if recompute(None) == entry_hash {
                        if keyed_rows > 0 {
                            // The signature of a tail replacement: everything
                            // after some keyed row rewritten from database
                            // access alone. Never a downgrade to "unkeyed".
                            return Ok(finish(
                                false,
                                checked,
                                keyed_rows,
                                unkeyed_rows,
                                keyed_run_start,
                                Some(id),
                                Some(format!(
                                    "row {id} recomputes only as an unkeyed digest but follows keyed rows; a keyed chain cannot legitimately continue unkeyed"
                                )),
                            ));
                        }
                        false
                    } else {
                        return Ok(finish(
                            false,
                            checked,
                            keyed_rows,
                            unkeyed_rows,
                            keyed_run_start,
                            Some(id),
                            Some(format!(
                                "row {id} does not recompute under any configured key or as an unkeyed digest; its content or hash has been altered"
                            )),
                        ));
                    }
                }
            };

            if row_keyed {
                keyed_rows += 1;
                keyed_run_start.get_or_insert(id);
            } else {
                unkeyed_rows += 1;
                keyed_run_start = None;
            }

            head_id = Some(id);
            head_hash = Some(entry_hash.clone());
            prev_hash = Some(entry_hash);
        }

        let mut status = finish(
            true,
            checked,
            keyed_rows,
            unkeyed_rows,
            keyed_run_start,
            None,
            None,
        );
        status.head_id = head_id;
        status.head_hash = head_hash;
        Ok(status)
    }

    pub async fn get_audit_log(
        &self,
        case_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>> {
        self.get_audit_log_filtered(case_id, None, None, None, None, None, limit, offset)
            .await
    }

    /// How many audit rows record `action` against `resource_id`, whatever
    /// their `case_id` — the rows of a deleted case have it nulled, so a
    /// case-scoped read cannot find the row that says the case is gone.
    pub async fn count_audit_actions_for_resource(
        &self,
        action: &str,
        resource_id: Uuid,
    ) -> Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = ? AND resource_id = ?")
            .bind(action)
            .bind(resource_id)
            .fetch_one(&self.pool)
            .await
            .context("Failed to count audit rows")
    }

    pub async fn get_audit_log_count(&self, case_id: Uuid) -> Result<i64> {
        self.get_audit_log_count_filtered(case_id, None, None, None, None, None)
            .await
    }

    // --- Evidence Integrity ---

    pub async fn record_integrity_check(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        computed_md5: Option<&str>,
        computed_sha1: Option<&str>,
        computed_sha256: Option<&str>,
        expected_md5: Option<&str>,
        expected_sha1: Option<&str>,
        expected_sha256: Option<&str>,
        status: &str,
        details: Option<&str>,
    ) -> Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO integrity_checks (case_id, artifact_id, timestamp, computed_md5, computed_sha1, computed_sha256, expected_md5, expected_sha1, expected_sha256, status, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(case_id)
        .bind(artifact_id)
        .bind(&timestamp)
        .bind(computed_md5)
        .bind(computed_sha1)
        .bind(computed_sha256)
        .bind(expected_md5)
        .bind(expected_sha1)
        .bind(expected_sha256)
        .bind(status)
        .bind(details)
        .execute(&self.pool)
        .await
        .context("Failed to record integrity check")?;

        Ok(())
    }

    /// Merge a JSON object into an artifact's metadata via SQLite `json_patch`,
    /// scoped by case. Preserves every existing key not named in the patch.
    pub async fn merge_artifact_metadata(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        patch: &serde_json::Value,
    ) -> Result<u64> {
        let patch_json =
            serde_json::to_string(patch).context("Failed to serialize metadata patch")?;
        let result = sqlx::query(
            "UPDATE artifacts SET metadata_json = json_patch(metadata_json, ?) \
             WHERE id = ? AND case_id = ?",
        )
        .bind(patch_json)
        .bind(artifact_id)
        .bind(case_id)
        .execute(&self.pool)
        .await
        .context("Failed to merge artifact metadata")?;
        Ok(result.rows_affected())
    }

    pub async fn get_integrity_checks(&self, artifact_id: Uuid) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, computed_md5, computed_sha1, computed_sha256, expected_md5, expected_sha1, expected_sha256, status, details FROM integrity_checks WHERE artifact_id = ? ORDER BY id DESC",
        )
        .bind(artifact_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch integrity checks")?;

        let mut checks = Vec::with_capacity(rows.len());
        for row in rows {
            checks.push(serde_json::json!({
                "id": row.try_get::<i64, _>("id")?,
                "timestamp": row.try_get::<String, _>("timestamp")?,
                "computed_md5": row.try_get::<Option<String>, _>("computed_md5")?,
                "computed_sha1": row.try_get::<Option<String>, _>("computed_sha1")?,
                "computed_sha256": row.try_get::<Option<String>, _>("computed_sha256")?,
                "expected_md5": row.try_get::<Option<String>, _>("expected_md5")?,
                "expected_sha1": row.try_get::<Option<String>, _>("expected_sha1")?,
                "expected_sha256": row.try_get::<Option<String>, _>("expected_sha256")?,
                "status": row.try_get::<String, _>("status")?,
                "details": row.try_get::<Option<String>, _>("details")?,
            }));
        }

        Ok(checks)
    }

    // NOTE: update_artifact_hashes was removed deliberately. Acquisition hashes
    // are an immutable baseline; re-computed hashes are recorded as
    // non-authoritative integrity_checks rows instead (see record_integrity_check).

    // ── Filter CRUD ──────────────────────────────────────────────

    /// Save a filter (create or update).
    pub async fn save_filter(
        &self,
        id: Uuid,
        case_id: Option<Uuid>,
        name: &str,
        description: &str,
        filter_json: &str,
        is_predefined: bool,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO filters (id, case_id, name, description, filter_json, is_predefined, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, description = excluded.description,
                 filter_json = excluded.filter_json, updated_at = excluded.updated_at",
        )
        .bind(id)
        .bind(case_id)
        .bind(name)
        .bind(description)
        .bind(filter_json)
        .bind(is_predefined)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .context("Failed to save filter")?;
        Ok(())
    }

    /// Get all filters available for a case (case-specific + global predefined).
    pub async fn get_filters(&self, case_id: Uuid) -> Result<Vec<FilterRow>> {
        let rows = sqlx::query_as::<_, FilterRow>(
            "SELECT id, case_id, name, description, filter_json, is_predefined, created_at, updated_at
             FROM filters
             WHERE case_id = ? OR case_id IS NULL
             ORDER BY is_predefined DESC, name ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to get filters")?;
        Ok(rows)
    }

    /// Get a single filter by ID.
    pub async fn get_filter(&self, filter_id: Uuid) -> Result<FilterRow> {
        let row = sqlx::query_as::<_, FilterRow>(
            "SELECT id, case_id, name, description, filter_json, is_predefined, created_at, updated_at
             FROM filters WHERE id = ?",
        )
        .bind(filter_id)
        .fetch_one(&self.pool)
        .await
        .context("Filter not found")?;
        Ok(row)
    }

    /// Delete a filter by ID (only non-predefined).
    pub async fn delete_filter(&self, filter_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM filters WHERE id = ? AND is_predefined = 0")
            .bind(filter_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete filter")?;
        Ok(result.rows_affected() > 0)
    }

    /// Seed predefined filters if they don't exist yet.
    pub async fn seed_predefined_filters(&self) -> Result<()> {
        use seance_core::filter::predefined_filters;

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM filters WHERE is_predefined = 1")
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0,));

        if count.0 > 0 {
            return Ok(());
        }

        for (name, description, condition) in predefined_filters() {
            let filter_json = serde_json::to_string(&condition)
                .context("Failed to serialize predefined filter")?;
            self.save_filter(Uuid::new_v4(), None, name, description, &filter_json, true)
                .await?;
        }

        Ok(())
    }

    /// Apply a filter condition to artifacts and return the matching page.
    ///
    /// With `parent_id = Some(..)` only that level's children are evaluated —
    /// the caller asked for a scoped apply. With `parent_id = None` the whole
    /// case is scanned in batches: the predefined filters ("All Graphics",
    /// "Deleted Files", "Large Files", …) test `FileEntry` fields that live
    /// deep in the tree, and evaluating only the top-level sources reported
    /// zero matches on evidence full of hits (BUG-270).
    ///
    /// Both scopes run the same bounded, batched scan. The scoped path used to
    /// load every child of `parent_id` into memory and filter there, always
    /// reporting `scan_complete: true` — a flat container with a million
    /// children was both an unbounded allocation and an unqualified claim that
    /// everything had been examined.
    pub async fn get_filtered_artifacts(
        &self,
        case_id: Uuid,
        parent_id: Option<Uuid>,
        filter: &seance_core::filter::FilterCondition,
        limit: u32,
        offset: u32,
    ) -> Result<FilteredArtifactPage> {
        let want_from = offset as u64;
        let want_to = want_from.saturating_add(limit as u64);
        let mut items: Vec<Artifact> = Vec::new();
        let mut decode_error: Option<anyhow::Error> = None;

        let summary = self
            .scan_filter_matches(
                case_id,
                parent_id,
                filter,
                |index, row, artifact_type, metadata| {
                    // Only the requested window is materialised, so a filter that
                    // matches a million files still costs one page of memory.
                    if index < want_from || index >= want_to {
                        return;
                    }
                    let built = (|| -> Result<Artifact> {
                        Ok(Artifact {
                            id: Uuid::from_slice(&row.id)
                                .context("Invalid UUID for artifact ID")?,
                            case_id,
                            parent_id: row
                                .parent_id
                                .as_deref()
                                .map(|b| Uuid::from_slice(b).context("Invalid UUID for parent ID"))
                                .transpose()?,
                            artifact_type,
                            data: None,
                            metadata,
                        })
                    })();
                    match built {
                        Ok(artifact) => items.push(artifact),
                        // An id that will not decode is a hard failure here, exactly
                        // as it was before this scan was shared: it is remembered and
                        // re-raised once the scan unwinds, rather than being folded
                        // into `undecodable`, which counts rows the FILTER could not
                        // be evaluated against.
                        Err(e) => {
                            decode_error.get_or_insert(e);
                        }
                    }
                },
            )
            .await?;

        if let Some(e) = decode_error {
            return Err(e);
        }

        Ok(FilteredArtifactPage {
            items,
            total: summary.total,
            scan_complete: summary.scan_complete,
            undecodable: summary.undecodable,
        })
    }

    /// Resolve a filter to the SET OF ARTIFACT IDS it matches, bounded by
    /// `id_cap`.
    ///
    /// This is what lets a saved filter be opened in the file grid: the grid
    /// pages, sorts, selects and exports in SQL, and it can only do that over a
    /// population it can name in a statement. Resolving the ids through THE SAME
    /// scan the filter apply runs is deliberate — the alternative, compiling a
    /// `FilterCondition` into SQL, would give the product two engines that have
    /// to agree about what a filter means, and where they disagreed the grid and
    /// the apply would state different facts about the case with nothing on
    /// screen to say which was right.
    ///
    /// The price is a ceiling: `total` is the whole match count (a lower bound
    /// when `scan_complete` is false), while `ids` stops at `id_cap` and
    /// `id_cap_reached` says when it did. A grid opened on a population larger
    /// than the ceiling is showing part of it, and has to say so.
    pub async fn filtered_artifact_ids(
        &self,
        case_id: Uuid,
        parent_id: Option<Uuid>,
        filter: &seance_core::filter::FilterCondition,
        id_cap: usize,
    ) -> Result<FilteredIdSet> {
        let mut ids: Vec<Uuid> = Vec::new();
        let mut decode_error: Option<anyhow::Error> = None;

        let summary = self
            .scan_filter_matches(
                case_id,
                parent_id,
                filter,
                |_index, row, _type, _metadata| {
                    if ids.len() >= id_cap {
                        // Counting continues past the ceiling: the population's size
                        // is reported even when the population itself is not.
                        return;
                    }
                    match Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID") {
                        Ok(id) => ids.push(id),
                        Err(e) => {
                            decode_error.get_or_insert(e);
                        }
                    }
                },
            )
            .await?;

        if let Some(e) = decode_error {
            return Err(e);
        }

        Ok(FilteredIdSet {
            id_cap_reached: summary.total > ids.len() as u64,
            ids,
            total: summary.total,
            scan_complete: summary.scan_complete,
            undecodable: summary.undecodable,
            id_cap,
        })
    }

    /// The one batched, bounded scan behind every filter application.
    ///
    /// `on_match` is called once per matching row, in scan order, with the row's
    /// zero-based index among the matches. It cannot stop the scan: a caller
    /// that has all the rows it wants still needs the count to keep running, or
    /// the total it reports would be its own page size.
    async fn scan_filter_matches<F>(
        &self,
        case_id: Uuid,
        parent_id: Option<Uuid>,
        filter: &seance_core::filter::FilterCondition,
        mut on_match: F,
    ) -> Result<FilterScanSummary>
    where
        F: FnMut(u64, &FilterScanRow, seance_core::artifact::ArtifactType, serde_json::Value),
    {
        // A filter nested past the evaluator's limit evaluates to `false` for
        // every row: refuse it rather than return an empty population (CR-047).
        filter
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid filter: {e}"))?;
        let case_id_bytes = case_id.as_bytes().to_vec();
        let parent_id_bytes = parent_id.map(|p| p.as_bytes().to_vec());
        // Two static statements rather than one with `(? IS NULL OR ...)`, so
        // the scoped form can still use the parent_id index.
        let scan_sql = if parent_id_bytes.is_some() {
            "SELECT rowid AS rowid, id, parent_id, artifact_type, metadata_json \
             FROM artifacts WHERE case_id = ? AND parent_id = ? AND rowid > ? \
             ORDER BY rowid LIMIT ?"
        } else {
            "SELECT rowid AS rowid, id, parent_id, artifact_type, metadata_json \
             FROM artifacts WHERE case_id = ? AND rowid > ? ORDER BY rowid LIMIT ?"
        };
        let mut cursor: i64 = 0;
        let mut scanned: u64 = 0;
        let mut total: u64 = 0;
        let mut scan_complete = true;
        let mut undecodable: u64 = 0;

        loop {
            let mut q = sqlx::query_as::<_, FilterScanRow>(scan_sql).bind(&case_id_bytes);
            if let Some(ref parent) = parent_id_bytes {
                q = q.bind(parent);
            }
            let rows: Vec<FilterScanRow> = q
                .bind(cursor)
                .bind(FILTER_SCAN_BATCH as i64)
                .fetch_all(&self.pool)
                .await
                .context("Failed to scan artifacts for a filter apply")?;

            if rows.is_empty() {
                break;
            }

            for row in rows {
                cursor = row.rowid;
                scanned += 1;
                // A row whose metadata or type will not decode cannot be
                // evaluated. It is skipped rather than aborting the whole apply,
                // but it is COUNTED: a filter that never examined a row must not
                // report the same "complete scan" as one that examined it and
                // found no match.
                let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&row.metadata_json)
                else {
                    undecodable += 1;
                    continue;
                };
                let Ok(artifact_type) =
                    seance_core::artifact::ArtifactType::from_str(&row.artifact_type)
                else {
                    undecodable += 1;
                    continue;
                };
                if !filter.evaluate(&format!("{:?}", artifact_type), &metadata) {
                    continue;
                }
                on_match(total, &row, artifact_type, metadata);
                total += 1;
            }

            if scanned >= MAX_FILTER_SCAN_ROWS {
                // Stopping early must never be indistinguishable from "that was
                // all there was": `total` is a lower bound from here on.
                warn!(
                    "Filter apply for case {} stopped after scanning {} artifacts; \
                     the match count is a lower bound",
                    case_id, scanned
                );
                scan_complete = false;
                break;
            }
        }

        if undecodable > 0 {
            warn!(
                "Filter apply for case {} could not evaluate {} artifact row(s) (undecodable \
                 metadata or unknown artifact type); the match count omits them",
                case_id, undecodable
            );
        }

        Ok(FilterScanSummary {
            total,
            scan_complete,
            undecodable,
        })
    }

    // ── SQL-side file browsing ───────────────────────────────────

    /// List FileEntry artifacts with filtering, sorting, and pagination done
    /// in SQL (via the generated columns from migration 0018), instead of
    /// loading every row into memory.
    ///
    /// Returns the requested page plus the total row count for the filter set.
    /// `page` is 1-based (0 is clamped to 1). When `include_metadata` is false
    /// the returned rows carry `metadata_json: None` for a lean payload.
    ///
    /// SECURITY: sort_by/sort_order are whitelist-validated; all filter values
    /// are bound parameters; page/page_size are formatted as integers.
    pub async fn list_file_entries(
        &self,
        case_id: Uuid,
        scope: FileListScope,
        filters: &FileEntryFilters,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        page: u32,
        page_size: u32,
        include_metadata: bool,
    ) -> Result<(Vec<FileEntryRow>, i64)> {
        #[derive(sqlx::FromRow)]
        struct FileEntryDbRow {
            id: Vec<u8>,
            parent_id: Option<Vec<u8>>,
            name: Option<String>,
            path: Option<String>,
            size: Option<i64>,
            is_directory: Option<i64>,
            is_deleted: Option<i64>,
            modified: Option<String>,
            created: Option<String>,
            accessed: Option<String>,
            #[sqlx(default)]
            known_status: Option<String>,
            #[sqlx(default)]
            metadata_json: Option<String>,
        }

        // Optional filters: structure is hardcoded, values are bound.
        let mut filter_sql = String::new();
        let mut filter_binds: Vec<String> = Vec::new();
        // Escape LIKE metacharacters so `_`/`%` in a name or extension match
        // literally (e.g. `report_final.docx` must not also match `reportxfinal`).
        // Each LIKE carries ESCAPE '\' to honour the escaped value.
        if let Some(ref needle) = filters.name_contains {
            filter_sql.push_str(" AND a.name LIKE ? ESCAPE '\\'");
            filter_binds.push(format!("%{}%", escape_like(needle)));
        }
        if let Some(ref ext) = filters.extension {
            filter_sql.push_str(" AND a.name LIKE ? ESCAPE '\\'");
            filter_binds.push(format!("%.{}", escape_like(ext.trim_start_matches('.'))));
        }
        if !filters.extensions.is_empty() {
            let ors = vec!["a.name LIKE ? ESCAPE '\\'"; filters.extensions.len()].join(" OR ");
            filter_sql.push_str(&format!(" AND ({ors})"));
            for ext in &filters.extensions {
                filter_binds.push(format!("%.{}", escape_like(ext.trim_start_matches('.'))));
            }
        }
        if filters.deleted_only {
            filter_sql.push_str(" AND a.is_deleted = 1");
        }
        match filters.directories {
            Some(true) => filter_sql.push_str(" AND a.is_directory = 1"),
            // IS NOT 1 keeps rows where the key is absent (NULL)
            Some(false) => filter_sql.push_str(" AND a.is_directory IS NOT 1"),
            None => {}
        }
        // The known-status FILTER uses non-correlated set membership rather than
        // the per-row correlated KNOWN_STATUS_EXPR (which the projection still
        // uses, but only for the <=page_size displayed rows). The matching-id
        // subqueries reference only their own row (a2/hse/hs), so SQLite
        // materialises each ONCE instead of re-running the hash-set join for
        // every candidate row. case_id is a validated path param, embedded as a
        // blob literal (no user text). Semantics mirror the CASE exactly:
        // notable = in a notable set; known = in some set but no notable set;
        // unknown = in no set.
        if filters.known.is_some() {
            let any_match = Self::known_any_match_sql(case_id);
            let notable_match = format!("{any_match} AND hs.set_type = 'notable'");
            match filters.known.as_deref() {
                Some("notable") => filter_sql.push_str(&format!(" AND a.id IN ({notable_match})")),
                // Any hash-set hit, notable or not.
                Some("any") => filter_sql.push_str(&format!(" AND a.id IN ({any_match})")),
                Some("known") => filter_sql.push_str(&format!(
                    " AND a.id IN ({any_match}) AND a.id NOT IN ({notable_match})"
                )),
                Some("unknown") => filter_sql.push_str(&format!(" AND a.id NOT IN ({any_match})")),
                _ => {}
            }
        }

        // The saved-filter population, when the grid was opened on one.
        //
        // The ids travel as ONE bound JSON array rather than as an IN list of
        // blob literals: 50,000 ids rendered as `X'...'` is close to two
        // megabytes of statement text to parse on both the page query and the
        // count, twice per request. `json_each` unpacks the array into rows,
        // `unhex` turns each 32-character id back into the 16-byte blob the `id`
        // column stores, and SQLite materialises the result once per statement
        // as an ephemeral index.
        //
        // `Some(empty)` renders as `'[]'`, which yields no rows and therefore
        // matches nothing. That is the intended reading and it is why the
        // restriction is an Option around a Vec rather than a possibly-empty
        // Vec: "no restriction" and "restricted to nothing" are opposite
        // answers, and a bare empty Vec cannot tell them apart.
        // "Show unique only": the file's SHA-256 is carried by nothing else in
        // the case. A file with no hash is excluded rather than assumed unique
        // — it cannot be shown to be one of a kind, and the count of those is
        // reported beside the grid so the population is readable (§2.8). The
        // correlated GROUP BY runs against `idx_artifacts_sha256`, the same
        // index the duplicates view groups on.
        if filters.unique == UniqueFilter::Unassessable {
            // The other side of the same coin: rows "show unique only" had to
            // set aside because they carry no hash. Counted through this same
            // builder so it is the same scope and the same filters, not an
            // approximation of them.
            filter_sql.push_str(" AND (a.sha256_hash IS NULL OR a.sha256_hash = '')");
        }
        if filters.unique == UniqueFilter::OnlyUnique {
            // The case id is inlined as a hex literal rather than bound: the
            // positional binds here are all `String`, the id is a blob, and
            // `subtree_cte` already establishes this pattern for the same
            // reason. It is a UUID from the request scope, never user text.
            filter_sql.push_str(&format!(
                " AND a.sha256_hash IS NOT NULL AND a.sha256_hash != '' \
                  AND a.sha256_hash NOT IN ( \
                    SELECT sha256_hash FROM artifacts \
                    WHERE case_id = X'{}' AND sha256_hash IS NOT NULL \
                      AND sha256_hash != '' \
                    GROUP BY sha256_hash HAVING COUNT(*) > 1 \
                  )",
                case_id.simple()
            ));
        }

        if let Some(ids) = &filters.restrict_to_ids {
            filter_sql.push_str(" AND a.id IN (SELECT unhex(value) FROM json_each(?))");
            let mut json = String::with_capacity(ids.len() * 35 + 2);
            json.push('[');
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push('"');
                // `simple()` is 32 lowercase hex digits with no dashes, which is
                // exactly what `unhex` wants.
                json.push_str(&id.simple().to_string());
                json.push('"');
            }
            json.push(']');
            filter_binds.push(json);
        }

        // Scope: direct children of a folder, the whole subtree under a source
        // (uncapped cycle-safe recursive walk over parent_id -- see
        // `subtree_cte`), or one level of
        // the path-derived tree. `scope_binds` are extra values bound after the
        // scope id and before the filter binds.
        // The recursive CTEs (Subtree / PathChildren) walk `parent_id`; a
        // cross-case `parent_id` could otherwise surface another case's files.
        // The recursive step is constrained to this case (embedded as a validated
        // blob literal, matching the known-status filter above -- no user text),
        // so a descendant reached via a cross-case link can never appear.
        let (cte, body, scope_id, scope_binds): (String, String, Option<Uuid>, Vec<String>) = match scope
        {
            FileListScope::CaseWide => (
                String::new(),
                format!(
                    "FROM artifacts a WHERE a.case_id = ? AND a.artifact_type = 'FileEntry'{}",
                    filter_sql
                ),
                None,
                Vec::new(),
            ),
            FileListScope::DirectChildren(parent_id) => (
                String::new(),
                format!(
                    "FROM artifacts a WHERE a.case_id = ? AND a.parent_id = ? AND a.artifact_type = 'FileEntry'{}",
                    filter_sql
                ),
                Some(parent_id),
                Vec::new(),
            ),
            // Descendants only (the scope artifact itself is not a listed
            // file), walked without a depth cap: see `subtree_cte`. The root
            // is excluded by id -- a validated UUID rendered as a blob literal,
            // never user text -- which replaces the old `s.depth > 0`.
            FileListScope::Subtree(root_id) => (
                subtree_cte(case_id),
                format!(
                    "FROM artifacts a JOIN subtree s ON a.id = s.id \
                     WHERE a.id <> X'{}' AND a.artifact_type = 'FileEntry'{}",
                    root_id.simple(),
                    filter_sql
                ),
                Some(root_id),
                Vec::new(),
            ),
            // One level of the path-derived tree: immediate children of `prefix`.
            // Children start with `<prefix>/` and have no further '/' after it.
            // The prefix test is a case-sensitive `substr` equality, not LIKE:
            // SQLite's LIKE folds ASCII case, which would merge `/Users` with a
            // sibling `/users` on a case-sensitive filesystem, and needs
            // wildcard escaping besides. `substr` counts characters, so the
            // length is a character count (a byte length would misplace the cut
            // under a multi-byte name). The empty-name guard drops the
            // filesystem root sentinel entry (path "/").
            FileListScope::PathChildren(root_id, prefix) => {
                let start = prefix.chars().count() + 1;
                (
                    subtree_cte(case_id),
                    format!(
                        "FROM artifacts a JOIN subtree s ON a.id = s.id \
                         WHERE a.id <> X'{}' \
                           AND a.artifact_type = 'FileEntry' AND a.name IS NOT NULL AND a.name <> '' \
                           AND substr(a.path, 1, {start}) = ? \
                           AND instr(substr(a.path, {}), '/') = 0{}",
                        root_id.simple(),
                        start + 1,
                        filter_sql
                    ),
                    Some(root_id),
                    vec![format!("{prefix}/")],
                )
            }
        };

        // SECURITY: whitelist-validated sort column and direction.
        let sort_column = match sort_by.unwrap_or("name") {
            "name" => "a.name",
            "size" => "a.size",
            "modified" => "a.modified",
            "created" => "json_extract(a.metadata_json, '$.created')",
            _ => "a.name",
        };
        let order = if sort_order.unwrap_or("asc").eq_ignore_ascii_case("desc") {
            "DESC"
        } else {
            "ASC"
        };

        let page = page.max(1);
        let offset = (page as i64 - 1) * page_size as i64;

        let metadata_col = if include_metadata {
            ", a.metadata_json"
        } else {
            ""
        };
        let known_status_expr = Self::KNOWN_STATUS_SQL;
        let select_sql = format!(
            // CAST created/accessed to TEXT: json_extract returns the JSON
            // value's native type, so a parser that stored an integer timestamp
            // would make sqlx fail to decode the whole page into Option<String>
            // and 500 the request. The virtual columns (name/path/modified) are
            // already TEXT-affinity, and size/is_* are INTEGER-affinity.
            "{cte}SELECT a.id, a.parent_id, a.name, a.path, a.size, a.is_directory, a.is_deleted, a.modified, \
                    CAST(json_extract(a.metadata_json, '$.created') AS TEXT) AS created, \
                    CAST(json_extract(a.metadata_json, '$.accessed') AS TEXT) AS accessed, \
                    {known_status_expr} AS known_status{metadata_col} \
             {body} ORDER BY {sort_column} {order}, a.id ASC LIMIT {page_size} OFFSET {offset}"
        );
        let count_sql = format!("{cte}SELECT COUNT(*) AS count {body}");

        let case_id_bytes = case_id.as_bytes().to_vec();
        // Case-wide listing has no scope artifact, so it binds case_id only.
        let scope_id_bytes = scope_id.map(|id| id.as_bytes().to_vec());

        let mut count_q = sqlx::query(&count_sql).bind(&case_id_bytes);
        if let Some(ref sid) = scope_id_bytes {
            count_q = count_q.bind(sid);
        }
        for bind in &scope_binds {
            count_q = count_q.bind(bind);
        }
        for bind in &filter_binds {
            count_q = count_q.bind(bind);
        }
        let total: i64 = count_q
            .fetch_one(&self.pool)
            .await
            .context("Failed to count file entries")?
            .try_get("count")?;

        let mut rows_q = sqlx::query_as::<_, FileEntryDbRow>(&select_sql).bind(&case_id_bytes);
        if let Some(ref sid) = scope_id_bytes {
            rows_q = rows_q.bind(sid);
        }
        for bind in &scope_binds {
            rows_q = rows_q.bind(bind);
        }
        for bind in &filter_binds {
            rows_q = rows_q.bind(bind);
        }
        let rows = rows_q
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch file entries")?;

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            entries.push(FileEntryRow {
                id: Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID")?,
                parent_id: row
                    .parent_id
                    .map(|bytes| Uuid::from_slice(&bytes).context("Invalid UUID for parent ID"))
                    .transpose()?,
                name: row.name,
                path: row.path,
                size: row.size,
                is_directory: row.is_directory.unwrap_or(0) != 0,
                is_deleted: row.is_deleted.unwrap_or(0) != 0,
                modified: row.modified,
                created: row.created,
                accessed: row.accessed,
                known_status: row.known_status,
                metadata_json: row.metadata_json,
            });
        }

        Ok((entries, total))
    }

    /// Disk layout regions (Partition / UnallocatedSpace / FileSystem) anywhere
    /// under a root evidence artifact, ordered by disk offset. Metadata keys
    /// match seance_plugin_partition's output.
    pub async fn get_disk_regions(
        &self,
        case_id: Uuid,
        root_artifact_id: Uuid,
    ) -> Result<Vec<DiskRegion>> {
        #[derive(sqlx::FromRow)]
        struct RegionRow {
            id: Vec<u8>,
            artifact_type: String,
            parent_id: Option<Vec<u8>>,
            offset_bytes: Option<i64>,
            size_bytes: Option<i64>,
            name: Option<String>,
            scheme: Option<String>,
            fs_type: Option<String>,
        }

        let rows = sqlx::query_as::<_, RegionRow>(
            // Each metadata arm is CAST to TEXT. `json_extract` returns whatever
            // type the JSON held, and this row is decoded through a derived
            // `FromRow` typed `Option<String>` — so one numeric label (a numeric
            // FAT volume label, or any third-party parser) made the decode fail
            // and `?` took the WHOLE disk map down with it, 500ing the panel for
            // every region over one odd value. Casting keeps the label rather
            // than discarding it: a volume really named `12345` is still named.
            //
            // A region's name falls back through the keys the parsers actually
            // write. The filesystem parser leaves the `name` COLUMN null and
            // records the volume in metadata, so reading the column alone
            // labelled all twelve volumes of an APFS container "APFS" and left
            // an examiner unable to tell Macintosh HD from Preboot or Recovery
            // (LIVE-018). Same shape as the geo-point fix above.
            //
            // The recursive step is constrained to this case so a cross-case
            // `parent_id` cannot pull another case's region into the walk.
            // The walk is not depth-capped. It used to stop at 3 parent links,
            // which silently dropped a filesystem nested deeper than that -- an
            // LVM/RAID volume inside a partition, a container inside a
            // container -- from the disk map with nothing to say a region was
            // missing. `UNION` (not `UNION ALL`) is what makes an unbounded walk
            // terminate on a cyclic `parent_id`.
            "WITH RECURSIVE descendants(id) AS ( \
                 SELECT id FROM artifacts WHERE case_id = ? AND id = ? \
                 UNION \
                 SELECT a.id FROM descendants d CROSS JOIN artifacts a ON a.parent_id = d.id WHERE a.case_id = ? \
             ) \
             SELECT a.id, a.artifact_type, a.parent_id, \
                    json_extract(a.metadata_json, '$.offset_bytes') AS offset_bytes, \
                    json_extract(a.metadata_json, '$.size_bytes') AS size_bytes, \
                    COALESCE(NULLIF(a.name, ''), \
                             CAST(json_extract(a.metadata_json, '$.volume_name') AS TEXT), \
                             CAST(json_extract(a.metadata_json, '$.volume_label') AS TEXT), \
                             CAST(json_extract(a.metadata_json, '$.label') AS TEXT), \
                             CAST(json_extract(a.metadata_json, '$.name') AS TEXT)) AS name, \
                    json_extract(a.metadata_json, '$.partition_scheme') AS scheme, \
                    json_extract(a.metadata_json, '$.filesystem_type') AS fs_type \
             FROM artifacts a JOIN descendants d ON a.id = d.id \
             WHERE a.id <> ? \
               AND a.artifact_type IN ('Partition', 'UnallocatedSpace', 'FileSystem') \
             ORDER BY offset_bytes ASC, a.id ASC",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(root_artifact_id.as_bytes().to_vec())
        .bind(case_id.as_bytes().to_vec())
        .bind(root_artifact_id.as_bytes().to_vec())
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch disk regions")?;

        let mut regions = Vec::with_capacity(rows.len());
        for row in rows {
            regions.push(DiskRegion {
                artifact_id: Uuid::from_slice(&row.id).context("Invalid UUID for artifact ID")?,
                artifact_type: row.artifact_type,
                parent_id: row
                    .parent_id
                    .map(|bytes| Uuid::from_slice(&bytes).context("Invalid UUID for parent ID"))
                    .transpose()?,
                offset_bytes: row.offset_bytes,
                size_bytes: row.size_bytes,
                name: row.name,
                scheme: row.scheme,
                fs_type: row.fs_type,
            });
        }

        Ok(regions)
    }

    /// Aggregated sizes of the immediate children of `prefix` within a source
    /// filesystem, for a drill-down size treemap. Each returned row is either a
    /// subdirectory (its `total_size` is the sum of every descendant file) or a
    /// file that lives directly in `prefix`.
    ///
    /// `prefix` is the parent directory path with no trailing slash; "" is the
    /// filesystem root. The hierarchy is read from the `path` column (files are
    /// stored flat under the FileSystem), so this works regardless of parent_id
    /// nesting. Rows are ordered largest-first.
    pub async fn get_dir_children_sizes(
        &self,
        case_id: Uuid,
        source_id: Uuid,
        prefix: &str,
    ) -> Result<Vec<DirChildSize>> {
        // Normalise: drop any trailing slash so the "prefix/" join is exact.
        let prefix = prefix.trim_end_matches('/');
        // Descendants of `prefix`: paths beginning "<prefix>/", compared with a
        // case-sensitive substr equality (SQLite's LIKE folds ASCII case, which
        // would add `/users` into the `/Users` treemap). `substr` is
        // character-indexed, so both the compared length and the start of `rest`
        // are CHARACTER counts; byte length would corrupt segment names under any
        // multi-byte (non-ASCII) directory name.
        let prefix_slash = format!("{prefix}/");
        let prefix_len = (prefix.chars().count() + 1) as i64;
        let rest_start = prefix_len + 1;

        // Group by the first segment of `rest`; a segment with anything after a
        // '/' is a directory whose size is the sum of its descendant files.
        let rows = sqlx::query(
            // Cycle-safe, uncapped descendant walk -- same shape and reasoning
            // as `subtree_cte`, spelled out here because this query uses
            // numbered parameters and chains further CTEs after it. A depth cap
            // here would have under-reported the size of any deeply nested
            // directory in the treemap while the browse list showed the files.
            "WITH RECURSIVE subtree(id) AS ( \
                 SELECT id FROM artifacts WHERE case_id = ?1 AND id = ?2 \
                 UNION \
                 SELECT a.id FROM subtree s CROSS JOIN artifacts a ON a.parent_id = s.id WHERE a.case_id = ?1 \
             ), \
             rels AS ( \
                 SELECT substr(a.path, ?4) AS rest, COALESCE(a.size, 0) AS size \
                 FROM artifacts a JOIN subtree s ON a.id = s.id AND a.id <> ?2 \
                 WHERE a.artifact_type = 'FileEntry' AND a.path IS NOT NULL \
                   AND a.is_directory IS NOT 1 \
                   AND substr(a.path, 1, ?5) = ?3 \
             ), \
             segs AS ( \
                 SELECT CASE WHEN instr(rest, '/') > 0 THEN substr(rest, 1, instr(rest, '/') - 1) ELSE rest END AS seg, \
                        CASE WHEN instr(rest, '/') > 0 THEN 1 ELSE 0 END AS deeper, \
                        size \
                 FROM rels \
             ) \
             SELECT seg AS name, SUM(size) AS total_size, COUNT(*) AS file_count, MAX(deeper) AS is_dir \
             FROM segs WHERE seg <> '' \
             GROUP BY seg ORDER BY total_size DESC, seg ASC",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(source_id.as_bytes().to_vec())
        .bind(prefix_slash)
        .bind(rest_start)
        .bind(prefix_len)
        .fetch_all(&self.pool)
        .await
        .context("Failed to aggregate directory sizes")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let name: String = row.try_get("name")?;
            let path = format!("{}/{}", prefix, name);
            out.push(DirChildSize {
                path,
                name,
                total_size: row.try_get::<i64, _>("total_size")?,
                file_count: row.try_get::<i64, _>("file_count")?,
                is_dir: row.try_get::<i64, _>("is_dir")? != 0,
            });
        }
        Ok(out)
    }

    /// Geolocation points for a case: parsed records carrying `gps_lat`/`gps_lon`
    /// (EXIF photos, and any other record type that resolves a location).
    /// Returns `(label, path, latitude, longitude, altitude, timestamp)` per
    /// point, bounded to keep a report/export from unbounded growth.
    ///
    /// An EXIF record qualifies only with an explicit `has_gps` true, the same
    /// rule [`Self::get_geo_map_points`] and the geolocation count apply, so the
    /// export, the map and the count agree. Other record types qualify on
    /// coordinates alone.
    ///
    /// A returned length equal to [`GEO_POINT_EXPORT_CAP`] means the answer was
    /// bounded and the caller MUST disclose the export as truncated.
    pub async fn get_geo_points(
        &self,
        case_id: Uuid,
    ) -> Result<
        Vec<(
            String,
            Option<String>,
            f64,
            f64,
            Option<f64>,
            Option<String>,
        )>,
    > {
        // The only evidence the caller has that this answer was bounded is the
        // returned length reaching the ceiling — the report layer compares
        // against exactly this number. That comparison is only sound if every
        // fetched row becomes a returned point, so the coordinate-usability
        // test lives in SQL rather than in a silent Rust-side `continue`:
        // dropping rows after the LIMIT shrinks the result below the ceiling
        // and makes a capped, incomplete export read as a complete one.
        // The time arms are ordered by usefulness, not merely by nullness. A
        // numeric `$.timestamp` is non-NULL, so a plain COALESCE selected it and
        // it then decoded to None against `Option<String>` — silently defeating
        // the human-readable `datetime_original` sitting one arm away, which is
        // the very fallback this query was changed to add. A text `$.timestamp`
        // wins, then the EXIF date strings, and a numeric epoch is kept last as
        // text rather than dropped.
        //
        // A point that cannot be attributed to a file, at a time, is not
        // evidence — and the parsers that produce most of them do not use the
        // field names this query originally asked for. The EXIF parser writes
        // `source_name` and `datetime_original`; only some writers record a
        // `source_path` or a normalised `timestamp`. Each column therefore
        // falls back through the names that actually carry the answer, most
        // specific first, so an explicit path still wins over a bare file name
        // (LIVE-015). The WHERE clause is untouched, so the partial index that
        // serves this query still does.
        let rows = sqlx::query(
            "SELECT COALESCE(NULLIF(a.name, ''), \
                             json_extract(a.metadata_json, '$.source_name')) AS name, \
                    COALESCE(json_extract(a.metadata_json, '$.source_path'), \
                             json_extract(a.metadata_json, '$.path'), \
                             json_extract(a.metadata_json, '$.source_name')) AS path, \
                    json_extract(a.metadata_json, '$.gps_lat') AS lat, \
                    json_extract(a.metadata_json, '$.gps_lon') AS lon, \
                    json_extract(a.metadata_json, '$.gps_altitude') AS alt, \
                    COALESCE(CASE WHEN typeof(json_extract(a.metadata_json, '$.timestamp')) = 'text' \
                                  THEN json_extract(a.metadata_json, '$.timestamp') END, \
                             CAST(json_extract(a.metadata_json, '$.datetime_original') AS TEXT), \
                             CAST(json_extract(a.metadata_json, '$.modify_date') AS TEXT), \
                             CAST(json_extract(a.metadata_json, '$.timestamp') AS TEXT)) AS ts \
             FROM artifacts a \
             WHERE a.case_id = ? \
               AND json_extract(a.metadata_json, '$.gps_lat') IS NOT NULL \
               AND json_extract(a.metadata_json, '$.gps_lon') IS NOT NULL \
               AND typeof(json_extract(a.metadata_json, '$.gps_lat')) IN ('real','integer') \
               AND typeof(json_extract(a.metadata_json, '$.gps_lon')) IN ('real','integer') \
               AND (COALESCE(json_extract(a.metadata_json, '$.type'), '') <> 'exif' \
                    OR json_extract(a.metadata_json, '$.has_gps') = 1) \
             LIMIT ?",
        )
        .bind(case_id.as_bytes().to_vec())
        .bind(GEO_POINT_EXPORT_CAP as i64)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch geo points")?;

        let fetched = rows.len();
        let mut unusable = 0usize;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // json_extract yields REAL/INTEGER for numbers; read as f64.
            let lat: Option<f64> = row.try_get("lat").ok();
            let lon: Option<f64> = row.try_get("lon").ok();
            let (Some(lat), Some(lon)) = (lat, lon) else {
                unusable += 1;
                continue;
            };
            if !lat.is_finite() || !lon.is_finite() {
                unusable += 1;
                continue;
            }
            let label: Option<String> = row.try_get("name").ok();
            out.push((
                label.unwrap_or_else(|| "GPS point".to_string()),
                row.try_get::<Option<String>, _>("path").ok().flatten(),
                lat,
                lon,
                row.try_get::<Option<f64>, _>("alt").ok().flatten(),
                row.try_get::<Option<String>, _>("ts").ok().flatten(),
            ));
        }
        if unusable > 0 {
            warn!(
                "case {}: {} GPS row(s) passed the SQL type filter but produced no usable \
                 coordinate; the export ceiling check under-counts by that much",
                case_id, unusable
            );
        }
        if fetched >= GEO_POINT_EXPORT_CAP {
            warn!(
                "case {}: geolocation export hit its {} point ceiling; the caller must disclose \
                 the export as truncated",
                case_id, GEO_POINT_EXPORT_CAP
            );
        }
        Ok(out)
    }

    /// The statement [`Self::get_geo_map_points`] runs. Bind the case id, then
    /// the row ceiling.
    ///
    /// Named, and public, so the query-plan regression test can EXPLAIN what
    /// ships instead of a retyping of it. The retyping it used to plan had
    /// already drifted from this statement in three ways, any of which could
    /// have hidden a change of plan.
    pub const GEO_MAP_POINTS_SQL: &'static str =
        "SELECT a.id AS id, a.parent_id AS parent_id, a.metadata_json AS meta \
         FROM artifacts a \
         WHERE a.case_id = ? \
           AND json_extract(a.metadata_json, '$.gps_lat') IS NOT NULL \
           AND json_extract(a.metadata_json, '$.gps_lon') IS NOT NULL \
         LIMIT ?";

    /// Every GPS point in the case for the interactive map. Selects only records
    /// carrying `gps_lat`/`gps_lon` (a small subset) and parses each one's
    /// metadata in Rust, applying the same rules the frontend used to apply
    /// client-side: EXIF records require an explicit `has_gps`; camera falls back
    /// to `make`+`model`; timestamp prefers `datetime_original`. This replaces
    /// the frontend's per-record-type scan (which silently capped at 500/type).
    ///
    /// # Errors
    ///
    /// Returns an error when the case holds more than [`GEO_MAP_POINT_CAP`]
    /// GPS-tagged records. The response carries a bare point list with no
    /// truncation channel, so the only alternatives are to load every row (a
    /// photo-heavy case can exhaust memory and hang the request) or to quietly
    /// draw a subset of a suspect's movements as if it were all of them. An
    /// explicit error naming the count is the only one of the three an examiner
    /// can act on.
    ///
    /// Under the ceiling, rows that carry a GPS fix the loop cannot use are
    /// returned as [`BoundedList::undecodable`] rather than only logged: a map
    /// missing fixes must not look like a map of every fix.
    ///
    /// [`BoundedList::has_more`] is therefore always false here, deliberately.
    /// This call does not truncate — it refuses. A map has no page order and no
    /// scrollback, so a `has_more` map would be an arbitrary, unreproducible
    /// subset of a suspect's movements, and an exhibit that cannot be
    /// reproduced is worse than one that was never drawn. The bound is still
    /// reported in [`BoundedList::limit`] so a caller can name it.
    pub async fn get_geo_map_points(
        &self,
        case_id: Uuid,
    ) -> Result<BoundedList<seance_core::models::GeoMapPoint>> {
        // Fetch one past the ceiling so "exactly at the ceiling" is still a
        // complete answer rather than a false alarm.
        let rows = sqlx::query(Self::GEO_MAP_POINTS_SQL)
            .bind(case_id.as_bytes().to_vec())
            .bind(GEO_MAP_POINT_CAP as i64 + 1)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch geo map points")?;

        if rows.len() > GEO_MAP_POINT_CAP {
            return Err(anyhow::anyhow!(
                "case {} holds more than {} GPS-tagged records; the interactive map cannot \
                 show them all and will not show a silent subset. Narrow the case view or use \
                 the KML/GeoJSON export, which discloses its own ceiling.",
                case_id,
                GEO_MAP_POINT_CAP
            ));
        }

        // Coordinate from a JSON number or a numeric string; None otherwise.
        let coord = |v: Option<&serde_json::Value>| -> Option<f64> {
            match v {
                Some(serde_json::Value::Number(n)) => n.as_f64(),
                Some(serde_json::Value::String(s)) => s.trim().parse::<f64>().ok(),
                _ => None,
            }
        };
        let string_field = |m: &serde_json::Value, key: &str| -> Option<String> {
            m.get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        };

        // Rows the SQL said carry a GPS fix but that this loop cannot turn into
        // a point are counted, never dropped in silence: the map is a bare list
        // with no truncation channel, so "this case has no further fixes" and
        // "some fixes would not decode" are otherwise the same picture. The
        // EXIF `has_gps` rule below is a qualification, not a failure, so it is
        // deliberately not counted here.
        let mut unusable = 0usize;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // Dashed UUID string so it matches the jump-to-artifact route.
            let id_bytes: Vec<u8> = row.try_get("id").unwrap_or_default();
            let Ok(id) = Uuid::from_slice(&id_bytes).map(|u| u.to_string()) else {
                unusable += 1;
                continue;
            };
            let meta_str: String = row.try_get("meta").unwrap_or_default();
            let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str) else {
                unusable += 1;
                continue;
            };

            let (Some(lat), Some(lon)) = (coord(meta.get("gps_lat")), coord(meta.get("gps_lon")))
            else {
                unusable += 1;
                continue;
            };
            if !lat.is_finite() || !lon.is_finite() {
                unusable += 1;
                continue;
            }

            let record_type = string_field(&meta, "type").unwrap_or_default();
            // EXIF requires the explicit has_gps flag; other types qualify on
            // finite coordinates alone.
            if record_type == "exif" && meta.get("has_gps") != Some(&serde_json::Value::Bool(true))
            {
                continue;
            }

            // For a photo point, the image lives on the parent FileEntry, so a
            // thumbnail preview targets the parent, not this EXIF record.
            let image_id = if record_type == "exif" {
                let pid: Option<Vec<u8>> = row.try_get("parent_id").ok();
                pid.and_then(|b| Uuid::from_slice(&b).ok())
                    .map(|u| u.to_string())
            } else {
                None
            };

            let camera = string_field(&meta, "camera").or_else(|| {
                let parts: Vec<String> = ["make", "model"]
                    .iter()
                    .filter_map(|k| string_field(&meta, k))
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(" "))
                }
            });

            out.push(seance_core::models::GeoMapPoint {
                id,
                record_type,
                lat,
                lon,
                camera,
                timestamp: string_field(&meta, "datetime_original")
                    .or_else(|| string_field(&meta, "timestamp")),
                source_name: string_field(&meta, "source_name"),
                image_id,
            });
        }
        if unusable > 0 {
            warn!(
                "case {}: {} GPS-tagged record(s) could not be turned into a map point \
                 (undecodable id, undecodable metadata, or an unusable coordinate); the map \
                 shows fewer fixes than the case holds",
                case_id, unusable
            );
        }
        Ok(BoundedList {
            items: out,
            limit: GEO_MAP_POINT_CAP,
            offset: 0,
            // Never truncated: past the ceiling this call returned Err above.
            has_more: false,
            undecodable: unusable,
        })
    }

    /// Resolve backup-relative file paths (a Manifest `relativePath`, e.g.
    /// `Library/SMS/Attachments/ab/12/GUID/IMG_0001.JPG`) to the artifact ids
    /// holding those files. Used to attach chat media to its bytes.
    ///
    /// Matching goes through the indexed generated `name` column (the file's
    /// basename) and then confirms the full relative path in memory, so a case
    /// with hundreds of thousands of artifacts stays fast — a direct
    /// `json_extract(...) = ?` on `relative_path` has no index and scans.
    pub async fn resolve_files_by_relative_path(
        &self,
        case_id: Uuid,
        paths: &[String],
    ) -> Result<std::collections::HashMap<String, Uuid>> {
        use std::collections::{HashMap, HashSet};

        // Basename -> the requested full paths ending in it.
        let mut wanted: HashMap<&str, Vec<&String>> = HashMap::new();
        for p in paths {
            let base = p.rsplit('/').next().unwrap_or(p.as_str());
            if !base.is_empty() {
                wanted.entry(base).or_default().push(p);
            }
        }
        let mut out: HashMap<String, Uuid> = HashMap::new();
        if wanted.is_empty() {
            return Ok(out);
        }

        // Chunked so the IN list stays well inside SQLite's variable limit.
        let names: Vec<&str> = wanted.keys().copied().collect();
        for chunk in names.chunks(200) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT id, metadata_json FROM artifacts \
                 WHERE case_id = ? AND artifact_type = 'FileEntry' AND name IN ({placeholders})"
            );
            let mut q = sqlx::query(&sql).bind(case_id.as_bytes().to_vec());
            for name in chunk {
                q = q.bind(*name);
            }
            let rows = q
                .fetch_all(&self.pool)
                .await
                .context("Failed to resolve files by relative path")?;

            let chunk_set: HashSet<&str> = chunk.iter().copied().collect();
            for row in rows {
                let meta_str: String = row.try_get("metadata_json").unwrap_or_default();
                let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str) else {
                    continue;
                };
                let Some(rel) = meta.get("relative_path").and_then(|v| v.as_str()) else {
                    continue;
                };
                let base = rel.rsplit('/').next().unwrap_or(rel);
                if !chunk_set.contains(base) {
                    continue;
                }
                let id_bytes: Vec<u8> = row.try_get("id").unwrap_or_default();
                let Ok(id) = Uuid::from_slice(&id_bytes) else {
                    continue;
                };
                // A directory record shares the path but carries no content.
                if meta.get("is_directory").and_then(|v| v.as_bool()) == Some(true) {
                    continue;
                }
                for requested in wanted.get(base).into_iter().flatten() {
                    // Apps record a path relative to their own container
                    // (WhatsApp stores "Media/..." for a file the backup holds
                    // at "Message/Media/..."), so accept the stored path when
                    // the request is a suffix of it at a path boundary. The
                    // boundary check keeps "b/f.jpg" from matching "ab/f.jpg".
                    let req = requested.as_str();
                    let matches = rel == req
                        || (rel.len() > req.len()
                            && rel.ends_with(req)
                            && rel.as_bytes()[rel.len() - req.len() - 1] == b'/');
                    if matches {
                        out.insert((*requested).clone(), id);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Count all descendant artifacts under each root (parent_id IS NULL)
    /// artifact of the case, excluding the root itself.
    ///
    /// The walk is not depth-capped. It used to stop at 32 parent links, which
    /// under-reported the artifact count of any deeply nested source (an
    /// archive inside an archive) with nothing to say it had. `UNION` (not
    /// `UNION ALL`) is what makes an unbounded walk terminate on a cyclic
    /// `parent_id`: an id already in the result is never re-added.
    /// The statement [`Self::get_artifact_counts_by_source`] runs, exposed so the
    /// query-plan test can EXPLAIN the shipped SQL rather than a copy of it.
    ///
    /// The recursive step is constrained to this case so a cross-case
    /// `parent_id` pointing into this tree cannot inflate a root's count, and it
    /// is written queue-first with `CROSS JOIN` for the reason set out on
    /// [`subtree_cte`] — without that this walk does not finish on a real case.
    pub fn counts_by_source_sql() -> &'static str {
        "WITH RECURSIVE tree(root_id, id) AS ( \
             SELECT id, id FROM artifacts WHERE case_id = ? AND parent_id IS NULL \
             UNION \
             SELECT t.root_id, a.id FROM tree t CROSS JOIN artifacts a ON a.parent_id = t.id WHERE a.case_id = ? \
         ) \
         SELECT root_id, COUNT(*) - 1 AS count FROM tree GROUP BY root_id"
    }

    pub async fn get_artifact_counts_by_source(&self, case_id: Uuid) -> Result<Vec<(Uuid, i64)>> {
        let rows = sqlx::query(Self::counts_by_source_sql())
            .bind(case_id.as_bytes().to_vec())
            .bind(case_id.as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await
            .context("Failed to count artifacts by source")?;

        let mut counts = Vec::with_capacity(rows.len());
        for row in rows {
            let root_id: Vec<u8> = row.try_get("root_id")?;
            counts.push((
                Uuid::from_slice(&root_id).context("Invalid UUID for root artifact ID")?,
                row.try_get::<i64, _>("count")?,
            ));
        }
        Ok(counts)
    }

    /// Histogram of file sizes in powers-of-2 buckets: bucket p counts
    /// FileEntry artifacts with size in [2^p, 2^(p+1)); bucket 0 covers [0, 2).
    /// Directories and entries without a size are excluded.
    pub async fn get_file_size_histogram(&self, case_id: Uuid) -> Result<Vec<(u32, i64)>> {
        let rows = sqlx::query(Self::file_size_histogram_sql())
            .bind(case_id.as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await
            .context("Failed to compute file size histogram")?;

        let mut histogram = Vec::with_capacity(rows.len());
        for row in rows {
            histogram.push((
                row.try_get::<i64, _>("bucket")? as u32,
                row.try_get::<i64, _>("count")?,
            ));
        }
        Ok(histogram)
    }

    /// The histogram statement, built once.
    ///
    /// `size` is a VIRTUAL generated column — a `json_extract` over
    /// `metadata_json` that SQLite re-evaluates at every reference — and the
    /// bucket expression references it up to 62 times per row. Materialising
    /// the filtered sizes first evaluates the column once per row and runs the
    /// `CASE` chain over a plain integer: 200,000 files went from 1.0 s to
    /// 0.27 s a call (release, this host, 2026-09-19). Portable
    /// floor(log2(size)) without SQLite math functions: hardcoded power-of-2
    /// thresholds, no user input.
    fn file_size_histogram_sql() -> &'static str {
        static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
            let mut bucket_expr = String::from("CASE");
            for p in (1..=62u32).rev() {
                bucket_expr.push_str(&format!(" WHEN s >= {} THEN {}", 1i64 << p, p));
            }
            bucket_expr.push_str(" ELSE 0 END");
            format!(
                "WITH sizes AS MATERIALIZED (\
                    SELECT size AS s FROM artifacts \
                    WHERE case_id = ? AND artifact_type = 'FileEntry' \
                      AND size IS NOT NULL AND size >= 0 AND is_directory IS NOT 1) \
                 SELECT {bucket_expr} AS bucket, COUNT(*) AS count FROM sizes \
                 GROUP BY bucket ORDER BY bucket ASC"
            )
        });
        &SQL
    }

    // ── Timeline histogram / extent ──────────────────────────────

    /// Event counts bucketed by (day-of-week, hour) in UTC, for a pattern-of-life
    /// activity heatmap. Day-of-week is 0=Sunday..6=Saturday, hour is 0..23.
    /// Returns only non-empty cells; the caller fills the 7x24 grid.
    ///
    /// Events at or before the epoch (`timestamp <= 0`) are NOT in the cells:
    /// epoch 0 is overwhelmingly a "no date recorded" sentinel and would pile
    /// into the Thursday 00:00 UTC cell. They are not discarded unannounced —
    /// [`Self::count_timeline_activity_excluded`] counts them so the caller can
    /// disclose that the cells do not sum to the case's timeline.
    pub async fn get_timeline_activity(&self, case_id: Uuid) -> Result<Vec<(i64, i64, i64)>> {
        let rows = sqlx::query(
            "SELECT CAST(strftime('%w', timestamp, 'unixepoch') AS INTEGER) AS dow, \
                    CAST(strftime('%H', timestamp, 'unixepoch') AS INTEGER) AS hour, \
                    COUNT(*) AS n \
             FROM timeline_events \
             WHERE case_id = ? AND timestamp IS NOT NULL AND timestamp > 0 \
             GROUP BY dow, hour",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_all(&self.pool)
        .await
        .context("Failed to aggregate timeline activity")?;

        let mut cells = Vec::with_capacity(rows.len());
        for row in rows {
            cells.push((
                row.try_get::<i64, _>("dow")?,
                row.try_get::<i64, _>("hour")?,
                row.try_get::<i64, _>("n")?,
            ));
        }
        Ok(cells)
    }

    /// Timeline events [`Self::get_timeline_activity`] leaves out of the heatmap:
    /// those with a timestamp at or before the epoch.
    pub async fn count_timeline_activity_excluded(&self, case_id: Uuid) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM timeline_events \
             WHERE case_id = ? AND timestamp IS NOT NULL AND timestamp <= 0",
        )
        .bind(case_id.as_bytes().to_vec())
        .fetch_one(&self.pool)
        .await
        .context("Failed to count timeline events excluded from the activity heatmap")
    }

    /// Event counts per fixed-width time bucket, honoring the same filters as
    /// get_timeline_events_count. Buckets are floor-aligned multiples of
    /// `bucket_seconds` (correct for negative timestamps too), ordered
    /// ascending; empty buckets are omitted.
    pub async fn get_timeline_histogram(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<&[String]>,
        search_text: Option<&str>,
        filename_filter: Option<&str>,
        event_type_filter: Option<&str>,
        event_ids: Option<&[Vec<u8>]>,
        bucket_seconds: i64,
    ) -> Result<Vec<(i64, i64)>> {
        anyhow::ensure!(
            bucket_seconds > 0,
            "bucket_seconds must be positive, got {}",
            bucket_seconds
        );

        let (where_suffix, binds) = build_timeline_where(
            "",
            from_ts,
            to_ts,
            source_modules,
            search_text,
            filename_filter,
            event_type_filter,
            event_ids,
        );

        // Floor division: SQLite integer division/modulo truncate toward zero,
        // which would shift negative timestamps into the wrong bucket.
        // t - ((t % b) + b) % b == floor(t / b) * b for b > 0.
        // SECURITY: bucket_seconds is a validated i64 formatted as an integer.
        let b = bucket_seconds;
        let query = format!(
            "SELECT (timestamp - ((timestamp % {b}) + {b}) % {b}) AS bucket_start, COUNT(*) AS count \
             FROM timeline_events WHERE case_id = ?{where_suffix} \
             GROUP BY bucket_start ORDER BY bucket_start ASC"
        );

        let case_id_bytes = case_id.as_bytes().to_vec();
        let mut q = sqlx::query(&query).bind(&case_id_bytes);
        for bind in &binds {
            q = match bind {
                TimelineBind::I64(v) => q.bind(*v),
                TimelineBind::Text(s) => q.bind(s),
                TimelineBind::Blob(bytes) => q.bind(bytes),
            };
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to compute timeline histogram")?;

        let mut histogram = Vec::with_capacity(rows.len());
        for row in rows {
            histogram.push((
                row.try_get::<i64, _>("bucket_start")?,
                row.try_get::<i64, _>("count")?,
            ));
        }
        Ok(histogram)
    }

    /// Timeline histogram split by source module: one (source, bucket_start,
    /// count) row per non-empty (module, time-bucket) cell. Powers the
    /// swimlane view, which shows which sources were active when.
    pub async fn get_timeline_histogram_by_source(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<&[String]>,
        search_text: Option<&str>,
        filename_filter: Option<&str>,
        event_type_filter: Option<&str>,
        event_ids: Option<&[Vec<u8>]>,
        bucket_seconds: i64,
    ) -> Result<Vec<(String, i64, i64)>> {
        anyhow::ensure!(
            bucket_seconds > 0,
            "bucket_seconds must be positive, got {}",
            bucket_seconds
        );

        let (where_suffix, binds) = build_timeline_where(
            "",
            from_ts,
            to_ts,
            source_modules,
            search_text,
            filename_filter,
            event_type_filter,
            event_ids,
        );

        // Same floor-division bucketing as get_timeline_histogram; b is a
        // validated i64 rendered as an integer literal.
        let b = bucket_seconds;
        let query = format!(
            "SELECT source_module AS src, \
                    (timestamp - ((timestamp % {b}) + {b}) % {b}) AS bucket_start, \
                    COUNT(*) AS count \
             FROM timeline_events WHERE case_id = ?{where_suffix} \
             GROUP BY src, bucket_start ORDER BY src ASC, bucket_start ASC"
        );

        let case_id_bytes = case_id.as_bytes().to_vec();
        let mut q = sqlx::query(&query).bind(&case_id_bytes);
        for bind in &binds {
            q = match bind {
                TimelineBind::I64(v) => q.bind(*v),
                TimelineBind::Text(s) => q.bind(s),
                TimelineBind::Blob(bytes) => q.bind(bytes),
            };
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to compute timeline histogram by source")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push((
                row.try_get::<String, _>("src")?,
                row.try_get::<i64, _>("bucket_start")?,
                row.try_get::<i64, _>("count")?,
            ));
        }
        Ok(out)
    }

    /// (min, max) timestamp of matching timeline events, or None when no
    /// events match. Same filter params as get_timeline_events_count; lets
    /// callers choose a histogram bucket size.
    pub async fn get_timeline_extent(
        &self,
        case_id: Uuid,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
        source_modules: Option<&[String]>,
        search_text: Option<&str>,
        filename_filter: Option<&str>,
        event_type_filter: Option<&str>,
        event_ids: Option<&[Vec<u8>]>,
    ) -> Result<Option<(i64, i64)>> {
        let (where_suffix, binds) = build_timeline_where(
            "",
            from_ts,
            to_ts,
            source_modules,
            search_text,
            filename_filter,
            event_type_filter,
            event_ids,
        );

        let query = format!(
            "SELECT MIN(timestamp) AS min_ts, MAX(timestamp) AS max_ts \
             FROM timeline_events WHERE case_id = ?{where_suffix}"
        );

        let case_id_bytes = case_id.as_bytes().to_vec();
        let mut q = sqlx::query(&query).bind(&case_id_bytes);
        for bind in &binds {
            q = match bind {
                TimelineBind::I64(v) => q.bind(*v),
                TimelineBind::Text(s) => q.bind(s),
                TimelineBind::Blob(bytes) => q.bind(bytes),
            };
        }

        let row = q
            .fetch_one(&self.pool)
            .await
            .context("Failed to compute timeline extent")?;

        let min_ts: Option<i64> = row.try_get("min_ts")?;
        let max_ts: Option<i64> = row.try_get("max_ts")?;
        Ok(min_ts.zip(max_ts))
    }

    // ── Audit log filtering ──────────────────────────────────────

    /// get_audit_log with optional server-side filters. All filters are exact
    /// matches except the timestamp bounds, which compare RFC3339 strings
    /// (lexicographic order == chronological order for the stored format).
    /// Ordered newest first (id DESC), like get_audit_log.
    pub async fn get_audit_log_filtered(
        &self,
        case_id: Uuid,
        user_id: Option<&str>,
        action: Option<&str>,
        resource_type: Option<&str>,
        from_ts: Option<&str>,
        to_ts: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let (where_suffix, binds) =
            build_audit_where(user_id, action, resource_type, from_ts, to_ts);

        let query = format!(
            "SELECT id, case_id, timestamp, user_id, action, resource_type, resource_id, details \
             FROM audit_log WHERE case_id = ?{where_suffix} ORDER BY id DESC LIMIT ? OFFSET ?"
        );

        let mut q = sqlx::query(&query).bind(case_id);
        for bind in &binds {
            q = q.bind(bind);
        }
        let rows = q
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch audit log")?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let resource_id: Option<Vec<u8>> = row.try_get("resource_id")?;
            // A resource id that is not a UUID is corruption (or tampering), and
            // `verify_audit_chain` treats it as an error. Here the row stays
            // visible — failing the call would hide the whole log — but under a
            // marker, never as "" which would read as "no resource".
            let resource_id_str = resource_id.map(|bytes| {
                Uuid::from_slice(&bytes)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|_| format!("<undecodable resource_id: {} bytes>", bytes.len()))
            });

            events.push(serde_json::json!({
                "id": row.try_get::<i64, _>("id")?,
                "timestamp": row.try_get::<String, _>("timestamp")?,
                "user_id": row.try_get::<String, _>("user_id")?,
                "action": row.try_get::<String, _>("action")?,
                "resource_type": row.try_get::<Option<String>, _>("resource_type")?,
                "resource_id": resource_id_str,
                "details": row.try_get::<Option<String>, _>("details")?,
            }));
        }

        Ok(events)
    }

    /// Count of audit log entries matching the same filters as
    /// get_audit_log_filtered.
    pub async fn get_audit_log_count_filtered(
        &self,
        case_id: Uuid,
        user_id: Option<&str>,
        action: Option<&str>,
        resource_type: Option<&str>,
        from_ts: Option<&str>,
        to_ts: Option<&str>,
    ) -> Result<i64> {
        let (where_suffix, binds) =
            build_audit_where(user_id, action, resource_type, from_ts, to_ts);

        let query =
            format!("SELECT COUNT(*) AS count FROM audit_log WHERE case_id = ?{where_suffix}");

        let mut q = sqlx::query(&query).bind(case_id);
        for bind in &binds {
            q = q.bind(bind);
        }
        let row = q
            .fetch_one(&self.pool)
            .await
            .context("Failed to count audit log entries")?;
        Ok(row.try_get::<i64, _>("count")?)
    }
}

/// Bind value for dynamically built timeline WHERE clauses.
enum TimelineBind {
    I64(i64),
    Text(String),
    Blob(Vec<u8>),
}

/// Escape SQLite LIKE metacharacters so a bound value matches literally under an
/// `ESCAPE '\'` clause: `\`, `%`, and `_` become `\\`, `\%`, `\_`. Every LIKE
/// that binds an escaped value MUST carry `ESCAPE '\'` in its SQL, matching the
/// paths that already escape (e.g. conversation search, path children).
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Build the shared WHERE-clause suffix (and its bind values, in placeholder
/// order) for timeline event filters. The ONE place these predicates are
/// written: the page, the count, the export, the histograms and the extent all
/// call it, so they cannot disagree about which events a filter matches (BUG-231
/// had to be applied to four copies before they were merged). The caller
/// prepends "WHERE <prefix>case_id = ?" and binds case_id first.
///
/// `prefix` is the table alias the columns are qualified with (`"te"` where the
/// query joins `timeline_tags`), or `""` for an unaliased `timeline_events`.
fn build_timeline_where(
    prefix: &str,
    from_ts: Option<i64>,
    to_ts: Option<i64>,
    source_modules: Option<&[String]>,
    search_text: Option<&str>,
    filename_filter: Option<&str>,
    event_type_filter: Option<&str>,
    event_ids: Option<&[Vec<u8>]>,
) -> (String, Vec<TimelineBind>) {
    let mut sql = String::new();
    let mut binds = Vec::new();
    let q = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}.")
    };

    // Date range. Each bound is applied independently so an open-ended range
    // (only `from` or only `to`) still constrains the result.
    if let Some(from) = from_ts {
        sql.push_str(&format!(" AND {q}timestamp >= ?"));
        binds.push(TimelineBind::I64(from));
    }
    if let Some(to) = to_ts {
        sql.push_str(&format!(" AND {q}timestamp <= ?"));
        binds.push(TimelineBind::I64(to));
    }

    // Source module IN clause
    if let Some(modules) = source_modules {
        if !modules.is_empty() {
            let placeholders = modules.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            sql.push_str(&format!(" AND {q}source_module IN ({placeholders})"));
            for module in modules {
                binds.push(TimelineBind::Text(module.clone()));
            }
        }
    }

    // Text search - advanced parser when special syntax is present
    let use_advanced_search = search_text
        .is_some_and(|s| s.contains('+') || s.contains('-') || s.contains('"') || s.contains(':'));

    let simple_search = |sql: &mut String, binds: &mut Vec<TimelineBind>, s: &str| {
        sql.push_str(&format!(
            " AND ({q}short_desc LIKE ? ESCAPE '\\' OR {q}full_details LIKE ? ESCAPE '\\' OR {q}timestamp_desc LIKE ? ESCAPE '\\')"
        ));
        let pattern = format!("%{}%", escape_like(s));
        binds.push(TimelineBind::Text(pattern.clone()));
        binds.push(TimelineBind::Text(pattern.clone()));
        binds.push(TimelineBind::Text(pattern));
    };

    if use_advanced_search {
        if let Some(search_str) = search_text {
            // The parse can FAIL, or succeed yet yield an EMPTY predicate (a
            // query that is all separators, like "-"). Either way fall back to
            // the simple LIKE so a request that named a search is never answered
            // unfiltered.
            match seance_core::search::SearchQuery::parse(search_str) {
                Ok(parsed) => {
                    let (where_clause, params) =
                        parsed.to_sql_with_prefix((!prefix.is_empty()).then_some(prefix));
                    if !where_clause.is_empty() {
                        sql.push_str(&format!(" AND ({where_clause})"));
                        for param in params {
                            binds.push(TimelineBind::Text(param));
                        }
                    } else {
                        simple_search(&mut sql, &mut binds, search_str);
                    }
                }
                Err(_) => simple_search(&mut sql, &mut binds, search_str),
            }
        }
    } else if let Some(search_str) = search_text {
        simple_search(&mut sql, &mut binds, search_str);
    }

    // Filename filter (searches in JSON full_details)
    if let Some(filename) = filename_filter {
        sql.push_str(&format!(
            " AND json_extract({q}full_details, '$.filename') LIKE ? ESCAPE '\\'"
        ));
        binds.push(TimelineBind::Text(format!("%{}%", escape_like(filename))));
    }

    // Event type filter (timestamp_desc column)
    if let Some(event_type) = event_type_filter {
        sql.push_str(&format!(" AND {q}timestamp_desc LIKE ? ESCAPE '\\'"));
        binds.push(TimelineBind::Text(format!("%{}%", escape_like(event_type))));
    }

    // Event IDs filter (for tagged-only filtering). Empty set = tagged only with
    // nothing tagged: match nothing, so every read agrees instead of one of them
    // dropping the predicate and answering with the whole timeline (BUG-231).
    if let Some(ids) = event_ids {
        if ids.is_empty() {
            sql.push_str(" AND 0");
        } else {
            let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            sql.push_str(&format!(" AND {q}artifact_id IN ({placeholders})"));
            for id in ids {
                binds.push(TimelineBind::Blob(id.clone()));
            }
        }
    }

    (sql, binds)
}

/// Build the optional-filter WHERE suffix (and its bind values, in placeholder
/// order) for audit log queries. The caller prepends "WHERE case_id = ?".
fn build_audit_where(
    user_id: Option<&str>,
    action: Option<&str>,
    resource_type: Option<&str>,
    from_ts: Option<&str>,
    to_ts: Option<&str>,
) -> (String, Vec<String>) {
    let mut sql = String::new();
    let mut binds = Vec::new();

    if let Some(user) = user_id {
        sql.push_str(" AND user_id = ?");
        binds.push(user.to_string());
    }
    if let Some(action) = action {
        sql.push_str(" AND action = ?");
        binds.push(action.to_string());
    }
    if let Some(resource_type) = resource_type {
        sql.push_str(" AND resource_type = ?");
        binds.push(resource_type.to_string());
    }
    // Timestamps are stored as RFC3339 TEXT; string compare is chronological.
    if let Some(from) = from_ts {
        sql.push_str(" AND timestamp >= ?");
        binds.push(from.to_string());
    }
    if let Some(to) = to_ts {
        sql.push_str(" AND timestamp <= ?");
        binds.push(to.to_string());
    }

    (sql, binds)
}

/// Normalize a messaging handle or email address into a stable node id:
/// lower-cased, with common URI prefixes and surrounding whitespace stripped,
/// so the same participant collapses to one node across records.
fn normalize_handle(s: &str) -> String {
    s.trim()
        .trim_start_matches("mailto:")
        .trim_start_matches("tel:")
        .trim()
        .to_lowercase()
}

/// One artifact within a duplicate-hash group.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateMember {
    pub id: Uuid,
    pub name: Option<String>,
    pub path: Option<String>,
    pub artifact_type: String,
}

/// A `PerceptualHash` record with the image it was computed from.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PerceptualHashRow {
    /// The PerceptualHash ParsedRecord's own id.
    pub record_id: Uuid,
    /// The image artifact the hash was computed from, if the lineage is present.
    pub parent_id: Option<Uuid>,
    /// The 64-char PDQ hex.
    pub pdq_hex: String,
}

/// A set of artifacts sharing a SHA-256 (duplicate content across the evidence).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateGroup {
    /// The shared SHA-256 (hex).
    pub hash: String,
    /// True number of artifacts with this hash (may exceed `members.len()`).
    pub count: usize,
    /// A bounded sample of the members.
    pub members: Vec<DuplicateMember>,
}

/// One message matching a chat search, tagged with its conversation so the UI
/// can open that thread at this message.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversationSearchHit {
    /// The matching message's artifact id.
    pub id: Uuid,
    /// Conversation this message belongs to (the thread key).
    pub thread_key: String,
    /// The matched message text.
    pub text: String,
    /// Epoch seconds of the message.
    pub date: i64,
}

/// Which end of a record listing a caller wants first.
///
/// This is INGEST order (`artifacts.created_at`), not the order the recorded
/// events happened in. A chat parser writes its rows in whatever order it walked
/// the source database, so "newest ingested" is emphatically NOT "most recent
/// message" and no caller may present it as one — a record's own timestamp lives
/// in its metadata, is per-parser (`date`, `timestamp`, or a formatted string),
/// and is not indexed. What this does decide is which end of the case a caller
/// that can only afford a bounded prefix reads from, which on a case far larger
/// than the prefix is the difference between seeing the first import and the
/// last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOrder {
    /// `created_at ASC, id ASC` — the long-standing default. Required by callers
    /// that page to the end of the match set.
    OldestIngestedFirst,
    /// `created_at DESC, id DESC` — for callers that truncate and would
    /// otherwise show only the earliest-ingested slice of the case.
    NewestIngestedFirst,
}

impl RecordOrder {
    /// The literal interpolated into `ORDER BY`. A closed enum, never client
    /// input, so nothing unvalidated reaches the statement.
    fn sql_direction(self) -> &'static str {
        match self {
            RecordOrder::OldestIngestedFirst => "ASC",
            RecordOrder::NewestIngestedFirst => "DESC",
        }
    }
}

/// ParsedRecord types the communications view correlates, and therefore the
/// exact population [`SqliteConnection::comms_contact_ranking`] ranks over.
///
/// Kept in sync with `COMMS_TYPES` in `frontend/src/pages/comms/normalize.ts`.
/// A messenger present there and absent here is silently missing from every
/// server-side comms total; a messenger present here and absent there makes the
/// server's totals exceed anything the page can show. Add to both or neither.
///
/// Public so the API layer can validate a client's `channel` against the same
/// list rather than inventing a second one.
pub const COMMS_RECORD_TYPES: &[&str] = &[
    "iMessage",
    "WhatsApp",
    "Signal",
    "AndroidSms",
    "CallLog",
    "EmailMessage",
    "Viber",
    "Kik",
    "Skype",
    "LINE",
    "TelegramMessage",
    "FacebookMessenger",
    "WeChat",
    "Instagram",
    "Snapchat",
    "TwitterDM",
];

/// The metadata keys the comms timestamp procedure reads, IN ORDER, and the
/// order is a claim: the first key that YIELDS AN INSTANT decides the record.
///
/// The same list `frontend/src/lib/epoch.ts` reads and the same list
/// `seance_core::timestamp` is given for a comms record. A key present here and
/// absent there puts one record at two instants on one screen.
pub const COMMS_TIME_KEYS: &[&str] = &["date", "timestamp"];

/// The SQL of the two statements the comms volume histogram runs, as built by
/// [`SqliteConnection::comms_histogram_sql`].
///
/// Returned as a pair rather than built at each call site because both share
/// one CTE chain and both are read on the same page load. The query-plan test
/// EXPLAINs these strings, which is the only way it can be testing what runs.
pub struct CommsHistogramSql {
    /// The ordered census and the extent, in one pass. Bind one record-type
    /// name per VALUES row, then the case id, then the LIKE pattern and the
    /// exact contact when the caller asked for them.
    pub census: String,
    /// One row per non-empty time bucket. Same binds, same order.
    pub buckets: String,
}

/// One bar: a claim that `count` communications happened in the span that
/// STARTS at `bucket_start_secs` and runs for the bucket width.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CommsHistogramBucket {
    /// Whole Unix SECONDS, floor-aligned on the epoch — not calendar-aligned,
    /// because `FRIENDLY_BUCKET_SECONDS` uses 30.4375 days for a "month". The
    /// unit is in the name because the chart works in milliseconds and a 1000x
    /// mix renders 2024 as 1970-01-20.
    pub bucket_start_secs: i64,
    /// Records placed inside this bucket. Both confidences, because a bar that
    /// drew only the contract readings would understate the volume.
    pub count: i64,
    /// How many of `count` were placed only by assuming which unit the parser
    /// used. The evidence supports those instants UNDER THAT ASSUMPTION, and a
    /// bar that cannot say so is a bar that overstates its own footing.
    pub rescued_count: i64,
}

/// The ordered census behind the comms volume histogram, and the extent of the
/// records it could place.
///
/// Two populations, never conflated. `total_records` describes the case
/// narrowed by CHANNEL ALONE; every other count here describes the MATCHED
/// population — channel, search term and contact together — which is the
/// population the bars sum to. One identity cannot hold across both while a
/// search term narrows the bars, so there are two totals and each says which
/// question it answers.
///
/// The five classes are assigned by an ORDERED chain, so each record lands in
/// exactly one and the invariant is an equation rather than an aspiration:
///
/// ```text
/// matched_records == unreadable_metadata + not_a_message + unplaceable_absent
///                    + unplaceable_value + placed_by_rescue + placed_as_written
/// sum(bucket.count)         == placed_by_rescue + placed_as_written
/// sum(bucket.rescued_count) == placed_by_rescue
/// sum(by_type_unplaceable_value)  == unplaceable_value
/// sum(by_type_unplaceable_absent) == unplaceable_absent
/// ```
///
/// The last two hold because the breakdowns are the very rows their totals were
/// summed from — one pass, one grouping — and not a second query's opinion
/// about the same population.
///
/// NOT `Copy`: the two breakdowns are owned lists. Everything else here is an
/// integer and stays cheap to clone.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CommsVolumeCensus {
    /// Every comms record in the case, narrowed by `channel` and by NOTHING
    /// ELSE. LIVE-024: a tile that shrank while an examiner typed would read as
    /// evidence disappearing, so this number does not move with the search.
    pub total_records: i64,
    /// Records matching channel, search term AND contact. THE BARS SUM TO THE
    /// PLACED PART OF THIS, and the class invariant holds over this population.
    pub matched_records: i64,
    /// Records whose `metadata_json` does not parse, so nothing about them
    /// could be read — not their time, not their counterparty. Distinct from
    /// every other class because "unreadable" is not "silent". Reachable only
    /// through corruption after write; see `comms_histogram_sql` for the exact
    /// reach of the guard that counts them.
    pub unreadable_metadata: i64,
    /// Parser tally rows (`$.subtype = "summary"`) and parser STATUS STUBS —
    /// records whose `$.type` is a comms type but which carry a `$.status` and
    /// no `$.subtype`. A `ParseFailed` stub stands for an entire unread
    /// database; counting it as one unplaced message would understate the
    /// shortfall by an unbounded amount.
    pub not_a_message: i64,
    /// Messages that never claimed a time: every listed key absent, or written
    /// as JSON null. Never 1970-01-01, and never counted as a value that failed
    /// to read.
    pub unplaceable_absent: i64,
    /// Messages that claimed a time no reading of which is admissible — a zero,
    /// a magnitude below the reader's band, text the shape check refuses. The
    /// record DID claim a time and the report must not say it was silent.
    pub unplaceable_value: i64,
    /// Messages placed only by assuming which unit the parser wrote
    /// (milliseconds, microseconds, FILETIME ticks). Drawn on the chart, and
    /// counted here so the size of the assumption is on the page beside it.
    pub placed_by_rescue: i64,
    /// Messages read in the unit the record's contract states, or parsed from a
    /// written date-time carrying its own UTC offset. The strongest footing.
    pub placed_as_written: i64,
    /// Earliest placed instant in the matched population, whole Unix SECONDS.
    /// `None` where nothing could be placed — which is a DIFFERENT empty state
    /// from a case with no communications, and the classes above are what tell
    /// them apart.
    pub min_ts_secs: Option<i64>,
    /// Latest placed instant in the matched population, whole Unix SECONDS.
    pub max_ts_secs: Option<i64>,
    /// `unplaceable_value` BROKEN DOWN BY RECORD TYPE — and that class alone:
    /// the records that DID claim a time no reading of which is admissible,
    /// which is a finding about the parsers that wrote them. Sums to
    /// `unplaceable_value` exactly, because these are the rows that total was
    /// summed from.
    ///
    /// Ordered count descending, then type name ascending in byte order — the
    /// comparator `comms_contact_ranking` sorts its own `by_type` with, so a
    /// quoted sentence does not reshuffle between two reads of one case. A type
    /// with nothing in this class is ABSENT rather than present with a zero.
    ///
    /// Kept apart from `by_type_unplaceable_absent`, as the two classes are
    /// kept apart everywhere else in this feature: one list of both would
    /// report a parser as having lost times it never wrote.
    ///
    /// NOT SERIALISED. `CommsHistogramResponse` flattens this census beside its
    /// own contract field for the breakdown, and one payload carrying the same
    /// array under two names is the two-exact-figures confusion this feature
    /// exists to prevent. The API names the population it serves.
    #[serde(skip)]
    pub by_type_unplaceable_value: Vec<(String, i64)>,
    /// `unplaceable_absent` BROKEN DOWN BY RECORD TYPE — the records that never
    /// claimed a time at all. Same order, same identity, same reason for being
    /// a separate list, and not serialised for the same reason.
    #[serde(skip)]
    pub by_type_unplaceable_absent: Vec<(String, i64)>,
}

impl CommsVolumeCensus {
    /// The classes, summed. Equal to `matched_records` by construction of the
    /// ordered chain; asserted rather than assumed, because v1's census was
    /// arithmetically false and nothing caught it.
    pub fn class_sum(&self) -> i64 {
        self.unreadable_metadata
            + self.not_a_message
            + self.unplaceable_absent
            + self.unplaceable_value
            + self.placed_by_rescue
            + self.placed_as_written
    }

    /// Records the chart draws: both placed classes, and only those.
    pub fn placed_records(&self) -> i64 {
        self.placed_as_written + self.placed_by_rescue
    }
}

/// One correspondent and the number of comms records exchanged with them.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactCount {
    /// The counterparty exactly as the viewer's chain reads it — a name where
    /// the evidence carried one, otherwise a handle, JID, address or number.
    /// Never normalised or prettified: two spellings of one person stay two
    /// rows, because merging them would be an inference, not a fact.
    pub contact: String,
    /// Records naming this counterparty. Exact, over the whole case.
    pub count: i64,
}

/// The SQL of the statements a record listing runs, as built by
/// [`SqliteConnection::record_listing_sql`].
pub struct RecordListingSql {
    /// One page of records, in the requested ingest direction.
    pub page: String,
    /// The exact size of the whole match set. Only read when the page could not
    /// carry the count itself; see [`SqliteConnection::list_records_by_type_ordered`].
    pub count: String,
}

/// The SQL of the two statements the comms ranking runs, as built by
/// [`SqliteConnection::comms_ranking_sql`].
///
/// Returned as a pair rather than built at each call site because both
/// statements share one CTE and both are read on every comms page load, so a
/// plan regression in either is a regression in the page. The query-plan test
/// EXPLAINs both of these strings, which is the only way it can be testing what
/// actually runs.
pub struct CommsRankingSql {
    /// Counts every comms record in the case by type and bucket. Bind one
    /// record-type name per VALUES row, then the case id.
    pub census: String,
    /// The league table itself. Bind one record-type name per VALUES row, then
    /// the case id, then the LIKE pattern when the caller asked for one.
    pub ranking: String,
}

/// The comms counterparty league table, computed in SQL over every matching
/// record in the case.
///
/// This type exists because a ranking is not a list — its ORDER is its claim,
/// and an order computed over a sample is wrong rather than incomplete. Every
/// field here says which population it describes, so a reader can never take a
/// capped table for the whole correspondent list, or a search result for the
/// size of the case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommsContactRanking {
    /// The top correspondents, highest count first, ties broken by contact
    /// ascending so the order is deterministic between runs. At most `limit`
    /// rows, filtered by the caller's search term when one was given.
    pub contacts: Vec<ContactCount>,
    /// The cap actually applied to `contacts`.
    pub limit: usize,
    /// True when at least one further correspondent exists below the last row,
    /// decided by a `LIMIT + 1` probe rather than by the list being full. A
    /// top-8 that reports `has_more` is explicitly NOT the correspondent list.
    pub has_more: bool,
    /// Distinct correspondents matching the search term, exact and unaffected by
    /// `limit`. With no search term this is the true size of the correspondent
    /// list, which is what makes a capped `contacts` readable as a sample of a
    /// known whole.
    pub distinct_contacts: i64,
    /// Rankable, non-summary records per ParsedRecord type — the census behind
    /// the channel tiles. Counts only the records that carry a counterparty, so
    /// it matches what the viewer's normalised event list contains.
    ///
    /// Deliberately NOT narrowed by the search term: the tiles describe the
    /// case, and a tile that shrank while an examiner typed would read as
    /// evidence disappearing.
    pub by_type: Vec<(String, i64)>,
    /// Every record the query read, across all four buckets:
    /// `sum(by_type) + summary_records + unrankable_records +
    /// records_without_counterparty`. Narrowed by `channel`, never by the search
    /// term.
    pub total_records: i64,
    /// Parser-emitted tally rows (`subtype = "summary"`), which are counts OF
    /// messages rather than messages. The viewer skips them
    /// (`frontend/src/pages/comms/normalize.ts:81`) and so does the ranking;
    /// they are reported here so the total still adds up.
    pub summary_records: i64,
    /// Records carrying none of the counterparty keys the viewer reads, so
    /// there is nothing in the evidence to rank them under.
    ///
    /// Separate from the ranking on purpose: "this case has no more
    /// correspondents" and "these records carried none we could read" are
    /// different facts about the evidence and must never be the same number.
    pub unrankable_records: i64,
    /// Records whose counterparty is a parser placeholder rather than a party —
    /// today only `CallLog` rows the device recorded with no number at all
    /// (`seance_plugin_call_history/src/lib.rs:194`).
    ///
    /// Held apart from `unrankable_records` because the two say different
    /// things: this one is the device positively recording an unidentified
    /// call, that one is a record we could not read a counterparty out of.
    pub records_without_counterparty: i64,
}

/// One correspondent/thread in a messaging database, aggregated in SQL so the
/// full list is available without shipping the messages to the client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversationSummary {
    /// Stable thread identifier, used to fetch this conversation's messages.
    pub key: String,
    /// Display name where the data carries one, else the key.
    pub label: String,
    pub count: i64,
    /// Epoch seconds of the most recent message, 0 when undated.
    pub last_time: i64,
    pub last_preview: Option<String>,
    pub is_group: bool,
    /// Platform/service tag (e.g. "iMessage", "SMS", "iOS").
    pub tag: Option<String>,
}

/// Scrollback position in a conversation: a point in the total order
/// `(ord DESC, id DESC)` that [`SqliteConnection::conversation_messages`] pages
/// by.
///
/// `ord` alone is NOT a position. Messages sharing a second, and undated
/// recovered bodies (which all collapse to the same sentinel), give many rows
/// the same `ord`; a cursor that carries only `ord` resumes strictly below it
/// and every tied row left on the far side of the page boundary is skipped with
/// nothing to show it ever existed. `id` is unique, so `(ord, id)` is total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationCursor {
    /// Ordering value of the last message on the previous page.
    pub ord: i64,
    /// That message's artifact id, which breaks ties on `ord`.
    ///
    /// Required, deliberately. An older client's request carries only `ord`,
    /// and an optional field here would let that request be answered: it would
    /// resume strictly below the tie and drop every message sharing that `ord`,
    /// silently, which is the exact defect this type exists to end. A caller
    /// holding only an `ord` has no position in this order, and must be told so
    /// where the request is parsed rather than handed a thread with messages
    /// missing from it. Always send back the id from
    /// [`ConversationPage::next_cursor`].
    pub id: Uuid,
}

/// One page of a conversation plus everything the caller needs to know that it
/// is one page of a conversation.
#[derive(Debug, Clone, Default)]
pub struct ConversationPage {
    /// The messages, newest first.
    pub records: Vec<seance_core::artifact::Artifact>,
    /// True when at least one further message exists beyond this page, decided
    /// by a `LIMIT + 1` probe rather than by the page being full. A caller must
    /// use this — not `records.len()` — to decide the thread has ended.
    pub has_more: bool,
    /// Position to resume from, valid only while `has_more` is true.
    pub next_cursor: Option<ConversationCursor>,
    /// Rows this page fetched but could not decode. Non-zero means the page is
    /// short by that many messages that DO exist in the evidence, which must
    /// never be presented as a gap in the conversation.
    pub undecodable: usize,
}

/// Attachments for the messages on screen, with both ways the list can be less
/// than the whole set.
#[derive(Debug, Clone, Default)]
pub struct AttachmentFetch {
    pub items: Vec<seance_core::artifact::Artifact>,
    /// True when the fetch hit its row cap, so further attachments exist.
    pub truncated: bool,
    /// Rows that matched but could not be decoded. Separate from `truncated`:
    /// a capped list and a lossy one are different failures, and neither may
    /// read as "this message had no media".
    pub undecodable: usize,
}

/// A participant in the communication network.
/// File/media category counts for the logical navigator (see `media_counts`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MediaCounts {
    pub pictures: i64,
    pub videos: i64,
    pub audio: i64,
    pub documents: i64,
    pub geolocation: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CommNode {
    pub id: String,
    pub label: String,
    /// "self" (device owner), "contact" (messaging peer), or "email".
    pub kind: String,
    /// Total messages/emails this participant is involved in.
    pub weight: i64,
}

/// A weighted, undirected communication link between two participants.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommEdge {
    pub source: String,
    pub target: String,
    pub weight: i64,
}

/// Aggregated communication network for a case (see `communication_graph`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommunicationGraph {
    pub nodes: Vec<CommNode>,
    pub edges: Vec<CommEdge>,
    /// True when participants beyond the node cap were dropped, or when email
    /// rows beyond the row cap were never read.
    pub truncated: bool,
    pub total_participants: i64,
    /// Email records that were read but contributed no edge (absent metadata,
    /// undecodable JSON, no sender). Reported separately from `truncated`
    /// because they are a different failure: every email row in a case can be
    /// unusable while `truncated` is false, and the resulting messaging-only
    /// graph would otherwise be presented as the suspect's whole contact
    /// network.
    pub unusable_email_records: i64,
    /// Call-log records that recorded no number. They are real evidence but
    /// name no counterparty, so they are not drawn as a node; this is how many
    /// the graph left out for that reason (mirrors
    /// [`CommsContactRanking::records_without_counterparty`]).
    pub records_without_counterparty: i64,
}

/// One recorded reason that a result in a case is less than everything, with
/// how many artifacts carry it.
///
/// `reason` is `None` when a plugin set `content_incomplete` without a
/// `content_incomplete_reason`. That is NOT the same as "no artifacts were
/// incomplete", and consumers must render it as an unexplained shortfall rather
/// than drop it: a 512 MiB hive cap and a corrupt mid-file record are different
/// stories, and "reason not recorded" is a third.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IncompleteReason {
    pub reason: Option<String>,
    pub count: i64,
}

/// Incompleteness attributable to one timeline `source_module`, i.e. to one
/// section of the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ModuleIncompleteness {
    /// Distinct artifacts behind this module's records marked incomplete in
    /// EITHER sense — `content_incomplete` (the bytes could not be read or
    /// decoded whole) or `inventory_incomplete` (the listing is short of what
    /// the container holds). An artifact marked on both axes counts once.
    ///
    /// Counting only the content axis made a section built entirely from short
    /// listings report "0 incomplete records" while the case-level census
    /// counted every one of them.
    pub artifacts: i64,
    /// The reasons those artifacts recorded, most frequent first. Inventory
    /// reasons are prefixed `inventory: ` so a reader can tell a short listing
    /// from an unreadable file.
    pub reasons: Vec<IncompleteReason>,
}

/// Case-wide census of plugin-recorded incompleteness
/// (see [`SqliteConnection::get_case_incompleteness`]).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CaseIncompleteness {
    /// Artifacts whose CONTENT could not be read or decoded whole.
    pub content_incomplete: i64,
    /// Artifacts whose LISTING is short of what the container holds.
    pub inventory_incomplete: i64,
    /// CONTENT reasons recorded case-wide, most frequent first, capped at
    /// [`SqliteConnection::INCOMPLETE_REASON_CAP`].
    pub reasons: Vec<IncompleteReason>,
    /// Distinct content reasons the case actually holds. Greater than
    /// `reasons.len()` means the reason list itself is truncated and must say so.
    pub distinct_reasons: i64,
    /// LISTING (inventory) reasons recorded case-wide, most frequent first,
    /// capped the same way. Kept separate from `reasons` because "we could not
    /// read this file whole" and "this listing is short of what the container
    /// holds" are different claims with different follow-up, and merging them
    /// would attribute a content reason to a missing-item question.
    pub inventory_reasons: Vec<IncompleteReason>,
    /// Distinct inventory reasons the case actually holds; see
    /// `distinct_reasons`.
    pub distinct_inventory_reasons: i64,
    /// Per-report-section attribution, keyed by timeline `source_module`.
    pub by_source_module: std::collections::HashMap<String, ModuleIncompleteness>,
    /// Records a later run superseded, and which are therefore excluded from
    /// every figure above. Carried so the exclusion can be stated rather than
    /// silently applied.
    pub superseded: i64,
    /// `TimelineEvent` artifacts recorded without a timeline row because their
    /// timestamp was missing or unparseable (`metadata.timeline_omitted`).
    /// Superseded records are excluded. The timeline is a subset of the events
    /// the evidence contains by exactly this many.
    pub timeline_omitted: i64,
}

impl CaseIncompleteness {
    /// True when any artifact in the case is marked incomplete in either sense,
    /// or any timeline event is missing from the timeline.
    pub fn any(&self) -> bool {
        self.content_incomplete > 0 || self.inventory_incomplete > 0 || self.timeline_omitted > 0
    }
}

/// One aggregated processing-log group: everything one module did in one status
/// across the whole case.
///
/// Defined on the trait side (`seance_core::db`) because
/// [`seance_core::db::DatabaseConnection::get_processing_log_for_case`] returns
/// it; re-exported here so `seance_db::CaseProcessingLogEntry` keeps resolving
/// for the report and API layers.
pub use seance_core::db::CaseProcessingLogEntry;

/// Rows read per batch during a case-wide filter apply.
const FILTER_SCAN_BATCH: u32 = 2_000;

/// Ceiling on artifacts examined by one case-wide filter apply. A filter
/// predicate is arbitrary metadata logic, so every candidate row must be
/// decoded and evaluated; this bounds the work a single request can do.
/// Hitting it clears `scan_complete` rather than silently reporting a short
/// total as the whole truth.
const MAX_FILTER_SCAN_ROWS: u64 = 500_000;

// ── Record-listing query types ───────────────────────────────────

/// The most metadata keys one `q` may be OR-matched across.
///
/// Each key adds a guarded `json_extract` and a LIKE to the predicate, so an
/// unbounded key list is an unbounded per-row cost over the whole type. A caller
/// that sends more is refused rather than silently having its list trimmed: a
/// trimmed list searches fewer places than the screen says it searched.
pub const RECORD_SEARCH_MAX_KEYS: usize = 16;

/// A case-insensitive substring search, OR-matched across named metadata keys.
///
/// The keys are named by the caller rather than inferred. The alternative —
/// searching every key in the document — would make the population a term
/// matches depend on which keys a parser happened to write, so two records that
/// look identical on screen could match differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordTextFilter<'a> {
    /// The term. Matched as a substring; LIKE metacharacters in it are escaped
    /// and match literally.
    pub needle: &'a str,
    /// Metadata keys to match against. Bare key names only — they are
    /// interpolated into a JSON path, so they are shape-checked by
    /// [`RecordListingRefinement::validate`] and must never be free text from a
    /// request without passing it.
    pub keys: &'a [String],
}

impl RecordTextFilter<'_> {
    /// The SQL predicate, with one `?` per key.
    ///
    /// `json_valid` guards the whole disjunction: without it a single record
    /// whose `metadata_json` no longer parses aborts the entire statement, and
    /// the table shows nothing at all rather than losing one row.
    fn sql_predicate(&self) -> String {
        let ors: Vec<String> = self
            .keys
            .iter()
            .map(|k| format!("json_extract(a.metadata_json, '$.{k}') LIKE ? ESCAPE '\\'"))
            .collect();
        format!(
            "(json_valid(a.metadata_json) AND ({}))",
            if ors.is_empty() {
                // No keys is not "match everything": it is "match nothing",
                // because nothing was searched. The API refuses the request
                // before it gets here; this is the fail-closed floor.
                "0".to_string()
            } else {
                ors.join(" OR ")
            }
        )
    }
}

/// Which metadata key a listing is ordered by, and in which direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSort<'a> {
    /// Bare metadata key name; shape-checked before it reaches the SQL.
    pub key: &'a str,
    pub descending: bool,
}

/// The optional refinements [`SqliteConnection::record_listing_sql`] applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordListingRefinement<'a> {
    pub search: Option<RecordTextFilter<'a>>,
    pub sort_key: Option<&'a str>,
    pub sort_descending: bool,
    /// Leave out records a later run of the same module answered (`HUNT-107`).
    pub exclude_superseded: bool,
}

impl RecordListingRefinement<'_> {
    /// No search and no sort: the listing exactly as it was before either
    /// existed. Every statement it builds is byte-identical to the old one.
    pub fn none() -> Self {
        Self::default()
    }

    /// Refuse anything that must not reach a JSON path or an unbounded
    /// predicate.
    ///
    /// Key names are interpolated (a JSON path cannot be a bound parameter), so
    /// this is the boundary that keeps client text out of the SQL. It refuses
    /// rather than sanitising: a key quietly stripped of its dots searches a
    /// different place from the one the caller named.
    pub fn validate(&self) -> Result<()> {
        if let Some(search) = &self.search {
            anyhow::ensure!(
                !search.keys.is_empty(),
                "a search term needs at least one key to search; with none, \
                 nothing would be searched and every record would be reported as \
                 a non-match"
            );
            anyhow::ensure!(
                search.keys.len() <= RECORD_SEARCH_MAX_KEYS,
                "a search may name at most {} keys, got {}",
                RECORD_SEARCH_MAX_KEYS,
                search.keys.len()
            );
            for key in search.keys {
                ensure_bare_metadata_key(key)?;
            }
        }
        if let Some(key) = self.sort_key {
            ensure_bare_metadata_key(key)?;
        }
        Ok(())
    }
}

/// Everything one call to [`SqliteConnection::list_records_filtered`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordListingQuery<'a> {
    pub record_type: &'a str,
    /// Restrict to records under this source artifact's subtree.
    pub source_id: Option<Uuid>,
    pub search: Option<RecordTextFilter<'a>>,
    /// Order by a metadata key. When `None` the listing is in INGEST order,
    /// which is not the records' own event time and must not be presented as
    /// such.
    pub sort: Option<RecordSort<'a>>,
    /// Ingest direction, used only when `sort` is `None`.
    pub order: RecordOrder,
    pub page: u32,
    pub page_size: u32,
    /// Whether records a later run of the same module answered are listed.
    ///
    /// `false` is the examining default: a superseded record is the *previous*
    /// answer to a question this case has since answered, and listing it beside
    /// the current one makes every number on the screen the sum of two runs
    /// (`HUNT-107`). `true` is the deliberate "show me what the earlier run
    /// said".
    pub include_superseded: bool,
}

/// One page of records, and the three populations a screen needs to describe it.
#[derive(Debug, Clone)]
pub struct RecordListingPage {
    pub records: Vec<seance_core::artifact::Artifact>,
    /// Records matching type + scope + search. The denominator for "N of T".
    pub total: i64,
    /// Records matching type + scope, IGNORING the search. Equal to `total`
    /// when nothing was searched.
    pub type_total: i64,
    /// Records in the type + scope population whose `metadata_json` will not
    /// parse, and which therefore could not be tested against the search term.
    /// They are neither matches nor established non-matches.
    ///
    /// `None` means the question was not asked — no search term was given, so
    /// nothing read the JSON — and must never be rendered as zero.
    pub unfilterable_metadata: Option<i64>,
    /// Records of this type and scope that a later run answered, and which this
    /// listing therefore left out.
    ///
    /// `None` means the question was not asked — the caller asked for them to be
    /// listed, so nothing was excluded — and must never be rendered as zero.
    pub superseded_total: Option<i64>,
}

/// Which of the two record-listing statements is being bound. They take the same
/// values in different orders; see [`SqliteConnection::bind_record_listing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordStatement {
    Page,
    Count,
}

/// Refuse anything that is not a bare metadata key name.
///
/// Key names reach the SQL by interpolation into a JSON path — `'$.' || key`
/// cannot be a bound parameter in an expression the planner has to see whole —
/// so this is the only thing standing between a query parameter and the
/// statement text. ASCII alphanumerics and `_` only; no dots, no brackets, no
/// quotes, and a length bound so a pathological key cannot be used to build a
/// megabyte of SQL.
fn ensure_bare_metadata_key(key: &str) -> Result<()> {
    anyhow::ensure!(!key.is_empty(), "a metadata key name cannot be empty");
    anyhow::ensure!(
        key.len() <= 64,
        "'{key}' is longer than a metadata key name may be (64 bytes)"
    );
    anyhow::ensure!(
        key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "'{key}' is not a bare metadata key name (letters, digits and underscore only)"
    );
    Ok(())
}

// ── Review-ledger types ──────────────────────────────────────────

/// What a single entry in a review batch asserts.
///
/// Three marks, not two booleans, because the three transitions are the three
/// things an examiner can actually do, and because `Unreviewed` must be
/// expressible WITHOUT also un-asserting the opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMark {
    /// "I have this artifact on screen." Records the first opening; a repeat
    /// changes nothing.
    Opened,
    /// "I have examined this artifact." Implies an opening, recorded at the
    /// instant the review was, never backdated.
    Reviewed,
    /// "Withdraw my review." Leaves the opening standing and appends the
    /// withdrawal to the history rather than erasing the review.
    Unreviewed,
}

/// What a review batch actually changed.
///
/// Every field is a count of TRANSITIONS, not of marks received, so a client
/// that re-sends the same openings on every scroll can tell that nothing
/// happened. `rejected` names the ids that were refused rather than reporting a
/// smaller success count and leaving the caller to work out which.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewBatchOutcome {
    /// Ledger rows created (an artifact this examiner had not opened before).
    pub openings_recorded: u64,
    /// Rows whose `reviewed_at` this call set.
    pub reviews_recorded: u64,
    /// Rows whose `reviewed_at` this call cleared.
    pub reviews_withdrawn: u64,
    /// Marks that found the ledger already in the state they asked for.
    pub unchanged: u64,
    /// Artifact ids that are not in this case and were therefore not filed.
    pub rejected: Vec<Uuid>,
}

/// Which of the ledger's two independent assertions an id listing is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewIdState {
    /// Artifacts with a ledger row: somebody had them on screen.
    Opened,
    /// Artifacts with a review stamp: somebody asserted they examined them.
    Reviewed,
}

/// One examiner's ledger row for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewRow {
    pub artifact_id: Uuid,
    pub examiner: String,
    /// When this examiner FIRST opened it.
    pub opened_at: i64,
    /// When this examiner marked it reviewed, or `None` for opened-but-not-
    /// cleared. `None` is "no review recorded", never "reviewed at epoch 0".
    pub reviewed_at: Option<i64>,
}

/// A capped list of ledger ids, with the exact size of the set it was cut from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewIdPage {
    pub ids: Vec<Uuid>,
    /// Exact count of DISTINCT artifacts in this state. Always the full set,
    /// even when `ids` is capped.
    pub total: i64,
    /// True when more ids exist than `ids` carries.
    pub capped: bool,
    /// The cap that was applied, so a client compares against the number the
    /// server used rather than the one it asked for.
    pub cap: usize,
}

/// One examiner's roll-up over a case's ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExaminerReviewCounts {
    pub examiner: String,
    /// Artifacts this examiner opened. Every reviewed artifact is also an
    /// opened one, so this is a SUPERSET of `reviewed` and the two must never
    /// be added together.
    pub opened: i64,
    /// Artifacts this examiner marked reviewed.
    pub reviewed: i64,
    pub first_opened_at: i64,
    pub last_activity_at: i64,
}

/// The review ledger's case-wide state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewStats {
    pub per_examiner: Vec<ExaminerReviewCounts>,
    /// Distinct artifacts opened by ANYBODY. Not the sum of the per-examiner
    /// figures: two examiners opening one artifact is one artifact opened.
    pub distinct_opened: i64,
    /// Distinct artifacts reviewed by ANYBODY.
    pub distinct_reviewed: i64,
    /// Every artifact row in the case, of every type — the denominator.
    pub case_artifact_total: i64,
}

/// One appended transition in the review ledger's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewEvent {
    pub artifact_id: Uuid,
    pub examiner: String,
    /// `opened` | `reviewed` | `review_withdrawn`.
    pub action: String,
    pub at: i64,
}

/// Largest population [`SqliteConnection::filtered_artifact_ids`] will hand to
/// the file grid.
///
/// The grid lists a filter's population by restricting its SQL to the resolved
/// id set, so the set has to fit in a bound parameter and in an ephemeral index
/// the planner builds per statement. 50,000 is a deliberate compromise: it is
/// far past what anyone reads row by row, and small enough that the restriction
/// costs a couple of megabytes rather than a couple of hundred. A filter with a
/// larger population is not refused — it is served, capped, and the response
/// says how big the population really was.
pub const FILTER_POPULATION_MAX_IDS: usize = 50_000;

/// One row of the batched filter scan.
///
/// Module-level rather than local to the scan so the shared scan can hand a
/// borrowed row to its callers; see
/// [`SqliteConnection::scan_filter_matches`].
#[derive(sqlx::FromRow)]
struct FilterScanRow {
    rowid: i64,
    id: Vec<u8>,
    parent_id: Option<Vec<u8>>,
    artifact_type: String,
    metadata_json: String,
}

/// What one bounded filter scan established, independent of what the caller did
/// with the matches.
struct FilterScanSummary {
    /// Matches found. A lower bound when `scan_complete` is false.
    total: u64,
    scan_complete: bool,
    undecodable: u64,
}

/// A filter's population, resolved to artifact ids for the file grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredIdSet {
    /// The matched ids, at most `id_cap` of them.
    pub ids: Vec<Uuid>,
    /// Every match the scan found, whether or not its id is in `ids`. A lower
    /// bound when `scan_complete` is false.
    pub total: u64,
    /// False when the scan stopped at [`MAX_FILTER_SCAN_ROWS`]: matches beyond
    /// that point were never examined.
    pub scan_complete: bool,
    /// Rows the scan reached and could not evaluate. Neither matches nor
    /// established non-matches.
    pub undecodable: u64,
    /// The ceiling applied to `ids`.
    pub id_cap: usize,
    /// True when the population is larger than `ids` carries, so a grid opened
    /// on it is showing part of the filter's matches.
    pub id_cap_reached: bool,
}

/// One page of a filter apply (see `get_filtered_artifacts`).
#[derive(Debug)]
pub struct FilteredArtifactPage {
    /// The requested window of matching artifacts.
    pub items: Vec<Artifact>,
    /// Total matches found. A lower bound when `scan_complete` is false.
    pub total: u64,
    /// False when the scan stopped at [`MAX_FILTER_SCAN_ROWS`]: matches beyond
    /// that point were never examined.
    pub scan_complete: bool,
    /// Rows the scan reached but could not evaluate (undecodable
    /// `metadata_json`, or an `artifact_type` this build does not know). They
    /// are neither matches nor established non-matches, so a non-zero count
    /// qualifies the result even when `scan_complete` is true.
    pub undecodable: u64,
}

/// Scope for list_file_entries: one folder level, or a whole source subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileListScope {
    /// Every FileEntry in the case, regardless of source. Lets a case-wide
    /// view (the picture gallery) page through the server rather than
    /// fanning out one query per source and paging in the browser.
    CaseWide,
    /// FileEntry artifacts whose parent_id is exactly this artifact
    /// (tree/folder navigation).
    DirectChildren(Uuid),
    /// All FileEntry artifacts anywhere under this artifact (recursive over
    /// parent_id, to any depth -- see `subtree_cte`).
    Subtree(Uuid),
    /// Immediate children of a directory identified by its `path`, within the
    /// given source subtree. The hierarchy is read from the `path` column, not
    /// parent_id, so it reconstructs the true filesystem tree even when a
    /// parser stores every file as a flat child of the FileSystem artifact.
    /// The prefix is the parent directory path with no trailing slash; an
    /// empty prefix lists the filesystem root's own entries.
    PathChildren(Uuid, String),
}

/// Optional filters for list_file_entries. Default matches everything.
#[derive(Debug, Clone, Default)]
pub struct FileEntryFilters {
    /// Case-insensitive substring match on name.
    pub name_contains: Option<String>,
    /// Case-insensitive extension suffix match on name (leading dot optional).
    pub extension: Option<String>,
    /// Match any of these extensions (leading dot optional). Empty means no
    /// constraint. Lets one query cover a whole media class (every picture
    /// type) instead of one request per extension.
    pub extensions: Vec<String>,
    /// Only entries whose metadata marks them deleted.
    pub deleted_only: bool,
    /// How the listing treats duplicate identity (§2.8).
    pub unique: UniqueFilter,
    /// Some(true) = directories only, Some(false) = exclude directories,
    /// None = both.
    pub directories: Option<bool>,
    /// Filter by hash-set match status: "notable", "known", "unknown", or
    /// "any" (matched by at least one set). Any other value (or None) applies
    /// no known-status filter.
    pub known: Option<String>,
    /// Restrict the listing to exactly these artifact ids, on top of every other
    /// filter and the scope. This is how a saved compound filter's population is
    /// opened in the grid: [`SqliteConnection::filtered_artifact_ids`] resolves
    /// the population, and the grid lists that set.
    ///
    /// `None` applies no restriction. `Some(empty)` matches NOTHING — never
    /// everything. The difference is load-bearing: a filter that matched no
    /// files must not open a grid showing the entire case.
    ///
    /// The ids do not widen the listing. They are ANDed with the case scope, so
    /// an id belonging to another case cannot pull that case's file into this
    /// case's grid.
    pub restrict_to_ids: Option<Vec<Uuid>>,
}

/// One artifact a recoverable problem is blocking (`ROADMAP.md` §2.11).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockedArtifact {
    /// The status record that reports the problem.
    pub artifact_id: Uuid,
    /// The artifact a module would be re-run on: the reported record's parent
    /// where it has one, else the record itself. A status record has no bytes,
    /// so re-running a decryptor on it would do nothing.
    pub target_id: Uuid,
    pub name: Option<String>,
    /// The parser's own sentence about what was not read, verbatim.
    pub detail: Option<String>,
}

/// A group of artifacts blocked by the same problem.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockedGroup {
    /// The record type that reports it.
    pub record_type: String,
    /// The `IncompleteReason` token.
    pub reason: String,
    /// A per-scheme discriminator where the record carries one (`LUKS`,
    /// `BitLocker`): two schemes report through one record type and need
    /// different answers.
    pub scheme: Option<String>,
    /// Artifacts in this group, case-wide.
    pub count: i64,
    /// Up to the caller's cap of them.
    pub examples: Vec<BlockedArtifact>,
    /// More exist than are listed, so `examples` is a subset.
    pub examples_truncated: bool,
}

/// A pivot result the examiner pinned to the case (`ROADMAP.md` §5.13).
///
/// Carries the snapshot as it was when pinned. Whether the same value still
/// answers the same way is a separate question the report asks at render time,
/// and a difference between the two is itself on the record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinnedPivot {
    pub id: Uuid,
    pub case_id: Uuid,
    /// The value that was pivoted on.
    pub value: String,
    /// Why the examiner pinned it. Absent rather than empty.
    pub note: Option<String>,
    pub examiner: String,
    /// Unix seconds.
    pub pinned_at: i64,
    /// Artifacts the index held for the value when it was pinned.
    pub total_matches: i64,
    /// How many of those were grouped: fewer than `total_matches` when the
    /// pivot's cap bit.
    pub grouped: i64,
    /// The per-kind counts are a sample, not a total.
    pub truncated: bool,
    /// The grouped result verbatim, as the pivot endpoint returned it.
    pub groups: serde_json::Value,
}

/// One file entry recovered for a requested name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNameHit {
    /// The file entry's artifact id, so a finding can open it.
    pub artifact_id: Uuid,
    /// The name as the evidence stored it, which may differ in case from the
    /// name that was asked for.
    pub name: String,
    /// The entry's path, when it has one.
    pub path: Option<String>,
    /// Whether the entry is a deleted one. `false` covers both "the parser
    /// said not deleted" and "the parser said nothing", which for a live
    /// filesystem entry is the same answer.
    pub deleted: bool,
    /// The MFT record number, for an entry read from an NTFS MFT.
    pub record_number: Option<u64>,
    /// The record's sequence number. Both halves of the file reference are
    /// needed to say whether a reference still names this file: NTFS frees a
    /// record on delete and increments the sequence when it is reused.
    pub sequence_number: Option<u64>,
}

/// What the case holds for one requested file name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileNameMatches {
    /// Up to the caller's cap of the matching entries.
    pub hits: Vec<FileNameHit>,
    /// How many matched in total, including those past the cap.
    pub seen: usize,
    /// More entries carried this name than the cap allowed, so `hits` is a
    /// subset. Without this a capped answer would be indistinguishable from a
    /// complete one, and "every entry for this program is deleted" would be
    /// claimed from a sample.
    pub truncated: bool,
}

impl FileNameMatches {
    /// Whether every entry recovered for this name is a deleted one.
    ///
    /// `false` when the answer was capped: the claim is about all of them and
    /// only some were read.
    pub fn all_deleted(&self) -> bool {
        !self.truncated && !self.hits.is_empty() && self.hits.iter().all(|h| h.deleted)
    }
}

/// How a file listing treats duplicate identity (§2.8).
///
/// Uniqueness is decided by SHA-256, so the three states are not two: a file
/// can be shown to be one of a kind, shown to have a twin, or carry no hash
/// and be neither. A bare `unique_only: bool` could not express the third, and
/// the third is the one that must not be silently folded into either answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UniqueFilter {
    /// No constraint: every file, duplicate or not.
    #[default]
    Off,
    /// Only files whose SHA-256 is carried by nothing else in the case.
    OnlyUnique,
    /// Only files carrying no SHA-256 — the population `OnlyUnique` had to set
    /// aside, counted so a grid can say what it could not assess.
    Unassessable,
}

/// One row from list_file_entries. Field values come from the generated
/// columns of migration 0018 (metadata_json JSON paths).
#[derive(Debug, Clone)]
pub struct FileEntryRow {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub size: Option<i64>,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub modified: Option<String>,
    pub created: Option<String>,
    pub accessed: Option<String>,
    /// Hash-set match status: "notable", "known", or None when no case hash
    /// set matches the entry's recorded md5/sha1/sha256.
    pub known_status: Option<String>,
    /// Full metadata document; None when the lean payload was requested.
    pub metadata_json: Option<String>,
}

/// One hash-set hit from list_hash_hits: an artifact whose recorded hash
/// matches a hash-set entry.
#[derive(Debug, Clone)]
pub struct HashHitRow {
    pub artifact_id: Uuid,
    pub name: Option<String>,
    pub path: Option<String>,
    pub hash_set_id: Uuid,
    pub hash_set_name: String,
    pub matched_hash: String,
    /// Which artifact hash matched: "md5", "sha1", or "sha256".
    pub algorithm: String,
}

/// A disk layout region (partition, unallocated gap, or filesystem) from
/// get_disk_regions.
#[derive(Debug, Clone)]
pub struct DiskRegion {
    pub artifact_id: Uuid,
    pub artifact_type: String,
    pub parent_id: Option<Uuid>,
    pub offset_bytes: Option<i64>,
    pub size_bytes: Option<i64>,
    pub name: Option<String>,
    /// Partition scheme (metadata key partition_scheme, e.g. "MBR", "GPT").
    pub scheme: Option<String>,
    /// Filesystem type (metadata key filesystem_type, e.g. "NTFS").
    pub fs_type: Option<String>,
}

/// One immediate child of a directory in the size treemap: a subdirectory
/// (aggregated size of everything beneath it) or a file directly in the path.
#[derive(Debug, Clone)]
pub struct DirChildSize {
    /// Path segment name (the child directory or file name).
    pub name: String,
    /// Full path of this child (prefix + '/' + name).
    pub path: String,
    /// Total size in bytes: for a directory, the sum of all descendant files.
    pub total_size: i64,
    /// Number of files at or beneath this child.
    pub file_count: i64,
    /// True when this child is a directory (has anything beneath it).
    pub is_dir: bool,
}

/// Result of walking the audit-log hash chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditChainStatus {
    /// True when every chained row's hash recomputes correctly.
    pub valid: bool,
    /// Number of chained rows verified (legacy NULL-hash rows are skipped).
    pub checked: i64,
    /// id of the first row that failed verification, if any.
    pub broken_at: Option<i64>,
    /// Whether a passing verification is evidence of no tampering.
    ///
    /// True only when the chain is keyed (`SEANCE_AUDIT_HMAC_KEY` set), because
    /// then the digest depends on a secret the database does not hold. An
    /// unkeyed chain is a plain SHA-256 over fields that all live in the same
    /// database, so anyone who can write to it can rewrite a row, recompute
    /// every hash after it and produce a chain that verifies. `valid` on such a
    /// chain means "internally consistent", NOT "unaltered" -- and a verdict
    /// that cannot tell those apart is the one an examiner would quote in court.
    /// Callers must carry this alongside `valid`; it is never a detail.
    ///
    /// Since migration 0032 this is true only when a key is configured AND
    /// every checked row was written keyed (`unkeyed_rows == 0`). A chain that
    /// was keyed part-way through is NOT tamper-evident as a whole -- its
    /// unkeyed prefix could have been rewritten before the key existed -- and
    /// `tamper_evident_from` says where the evidence-grade part begins.
    pub tamper_evident: bool,
    /// Rows that recomputed under a server-held key (current or retired).
    pub keyed_rows: i64,
    /// Rows that recomputed only as a plain SHA-256 digest. Every one of these
    /// is a row a database writer could have rewritten; a court reading needs
    /// this count beside `checked`, or "N entries verified" reads as N entries
    /// proven unaltered.
    pub unkeyed_rows: i64,
    /// id of the first row of the run of keyed rows that reaches the head of
    /// the chain -- the point from which a passing verification is evidence of
    /// no alteration. `None` when no row is keyed. Equal to the first chained
    /// row's id on a fully keyed chain. Rows before it verified as internally
    /// consistent only.
    pub tamper_evident_from: Option<i64>,
    /// Why verification stopped at `broken_at`, in words a reader can act on:
    /// a hash mismatch, an unkeyed row following keyed ones, or a fingerprint
    /// naming a key the server does not hold (and which variable to put it in).
    /// `None` when `valid`.
    pub break_reason: Option<String>,
    /// id and `entry_hash` of the last chained row — the chain HEAD — on a
    /// chain that verified. `None` when the chain is empty or broken.
    ///
    /// A hash chain proves the entries it still holds are unaltered and in
    /// order; it cannot prove none were removed from the END, because deleting
    /// the last N rows leaves no gap and the shortened chain still verifies
    /// (the one attacker keying defends against — a database writer — is
    /// exactly who can do this). The head is published so it can be anchored
    /// OUTSIDE the database — logged to a SIEM, written to write-once media,
    /// handed to the client — and compared on a later verification: a head that
    /// moved backwards, or a `checked` count below the anchored one, is the
    /// truncation the chain alone cannot show. See
    /// [`AuditChainStatus::truncation_note`].
    pub head_id: Option<i64>,
    /// See [`AuditChainStatus::head_id`].
    pub head_hash: Option<String>,
    /// Whether the server that ran this verification holds an audit key
    /// (`SEANCE_AUDIT_HMAC_KEY`).
    ///
    /// Carried because the rows alone cannot say what an all-unkeyed chain on a
    /// keyed server is (SEC-009). A deployment that ran unkeyed before the key
    /// was set and a log that a database writer deleted and rewrote from
    /// scratch, unkeyed, on a server that HAS a key look identical from the
    /// rows — every row takes the unkeyed branch, `keyed_rows` stays 0, and the
    /// verdict is `valid: true`. The disclosure that accompanies the verdict has
    /// to say so, and must not advise setting a key that is already set; this
    /// flag is what lets it tell the two servers apart.
    pub key_configured: bool,
}

impl AuditChainStatus {
    /// The sentence a verdict must carry about what a hash chain does NOT
    /// prove: that no trailing entries were deleted. Kept beside the verdict so
    /// "the log has not been altered" is never read as "the log is complete".
    pub fn truncation_note(&self) -> &'static str {
        "A hash chain attests that the entries it HOLDS are unaltered and in order; it cannot \
         attest that none were deleted from the end, because removing the most recent entries \
         leaves no gap and the shortened chain still verifies. Detecting that requires the chain \
         head (its length and last hash) to have been recorded outside this database and compared \
         here. Pass the recorded head to this check to have that comparison made."
    }
}

/// The retired audit keys named by `SEANCE_AUDIT_HMAC_KEY_PREVIOUS`.
///
/// Colon-separated, and ALSO taken whole. `SEANCE_AUDIT_HMAC_KEY` is read
/// verbatim, so a current key that contains a colon is legal — and after a
/// rotation the only place it can go is this variable, where splitting on `:`
/// turned it into fragments that matched nothing and the whole pre-rotation
/// history verified `false` (CR-033 #10). Every row names its key by
/// fingerprint and the verifier picks the match, so a candidate that matches
/// no row costs nothing: the whole value is added as one more candidate
/// whenever it differs from its fragments.
fn parse_retired_audit_keys(value: &str) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = value
        .split(':')
        .filter(|k| !k.is_empty())
        .map(|k| k.as_bytes().to_vec())
        .collect();
    if value.contains(':') && value.chars().any(|c| c != ':') {
        let whole = value.as_bytes().to_vec();
        if !keys.contains(&whole) {
            keys.push(whole);
        }
    }
    keys
}

/// Short, non-reversible identifier for an audit key: the first 16 hex chars
/// of SHA-256 over a domain-separated prefix and the key bytes.
///
/// Stored on every audit row so the verifier knows which key to recompute
/// under after a rotation. The prefix keeps this digest distinct from any
/// other use of the same key material; the truncation means the value
/// identifies the key without offering a useful target for recovering it. The
/// key itself is never stored or logged.
pub fn audit_key_fingerprint(key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"seance-audit-hmac-key-fingerprint\0");
    hasher.update(key);
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Compute the tamper-evident hash for one audit-log row.
///
/// Over length-prefixed fields (prev_hash, timestamp, user_id, action,
/// resource_type, resource_id, details); absent fields hash as empty strings.
/// Length prefixes prevent adjacent fields from being ambiguously re-split.
///
/// When `key` is `Some`, the digest is HMAC-SHA256 keyed by the server secret,
/// so the chain cannot be recomputed by someone with only database access.
/// When `None`, it is a plain SHA-256 chain (backward compatible).
fn compute_audit_entry_hash(
    key: Option<&[u8]>,
    prev_hash: Option<&str>,
    timestamp: &str,
    user_id: &str,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    details: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};

    let fields = [
        prev_hash.unwrap_or(""),
        timestamp,
        user_id,
        action,
        resource_type.unwrap_or(""),
        resource_id.unwrap_or(""),
        details.unwrap_or(""),
    ];

    match key {
        Some(k) => {
            use hmac::{Hmac, Mac};
            let mut mac =
                <Hmac<Sha256>>::new_from_slice(k).expect("HMAC accepts a key of any length");
            for field in fields {
                mac.update(&(field.len() as u64).to_le_bytes());
                mac.update(field.as_bytes());
            }
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect()
        }
        None => {
            let mut hasher = Sha256::new();
            for field in fields {
                hasher.update((field.len() as u64).to_le_bytes());
                hasher.update(field.as_bytes());
            }
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect()
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FilterRow {
    pub id: Uuid,
    pub case_id: Option<Uuid>,
    pub name: String,
    pub description: String,
    pub filter_json: String,
    pub is_predefined: bool,
    pub created_at: String,
    pub updated_at: String,
}
#[cfg(test)]
mod tests {
    use super::parse_timeline_timestamp;
    use super::*;
    use serde_json::json;

    async fn test_db() -> SqliteConnection {
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db
    }

    #[test]
    fn hmac_keying_changes_audit_hash() {
        let unkeyed = compute_audit_entry_hash(None, None, "t", "u", "a", None, None, None);
        let keyed =
            compute_audit_entry_hash(Some(b"secret"), None, "t", "u", "a", None, None, None);
        let keyed_again =
            compute_audit_entry_hash(Some(b"secret"), None, "t", "u", "a", None, None, None);
        let keyed_other =
            compute_audit_entry_hash(Some(b"other"), None, "t", "u", "a", None, None, None);
        assert_ne!(
            unkeyed, keyed,
            "keyed HMAC must differ from unkeyed SHA-256"
        );
        assert_eq!(
            keyed, keyed_again,
            "same key + inputs must be deterministic"
        );
        assert_ne!(
            keyed, keyed_other,
            "a different key must produce a different hash"
        );
    }

    #[tokio::test]
    async fn interior_null_entry_hash_breaks_chain() {
        let db = test_db().await;
        let case_id = db.create_case("c", "e").await.unwrap();
        for a in ["one", "two", "three"] {
            db.record_audit_event(Some(case_id), "alice", a, None, None, None)
                .await
                .unwrap();
        }
        // A healthy chain verifies.
        assert!(db.verify_audit_chain(None).await.unwrap().valid);

        // Excluding a row by nulling its entry_hash (the old silent-skip bug)
        // must now be detected as a chain break, not skipped.
        let middle: i64 =
            sqlx::query_scalar("SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 1")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        sqlx::query("UPDATE audit_log SET entry_hash = NULL WHERE id = ?")
            .bind(middle)
            .execute(&db.pool)
            .await
            .unwrap();

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(
            !status.valid,
            "an interior NULL entry_hash must break verification"
        );
        assert_eq!(status.broken_at, Some(middle));
    }

    fn timeline_artifact(case_id: Uuid, ts: i64, desc: &str) -> Artifact {
        Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": ts,
                "timestamp_desc": "Created",
                "source_module": "test_module",
                "short_desc": desc,
                "full_details": "{}",
            }),
        )
    }

    async fn count_for_case(db: &SqliteConnection, table: &str, case_id: Uuid) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {} WHERE case_id = ?", table);
        sqlx::query_scalar::<_, i64>(&sql)
            .bind(case_id)
            .fetch_one(&db.pool)
            .await
            .unwrap()
    }

    // --- H2: foreign key enforcement on pooled connections ---

    #[tokio::test]
    async fn foreign_keys_cascade_on_pooled_connections() {
        let db = test_db().await;
        let case_id = db.create_case("FK Case", "examiner").await.unwrap();

        // timeline_tags declares FOREIGN KEY (case_id) ... ON DELETE CASCADE
        db.create_timeline_tag(case_id, Uuid::new_v4(), Some("ex"), Some("note"))
            .await
            .unwrap();
        assert_eq!(count_for_case(&db, "timeline_tags", case_id).await, 1);

        // Raw parent delete: the cascade itself must fire (no app-level cleanup)
        sqlx::query("DELETE FROM cases WHERE id = ?")
            .bind(case_id)
            .execute(&db.pool)
            .await
            .unwrap();

        assert_eq!(
            count_for_case(&db, "timeline_tags", case_id).await,
            0,
            "ON DELETE CASCADE must be enforced on pooled connections"
        );
    }

    // --- H3: delete_case removes all child data, retains audit log ---

    /// A single hash set can legitimately hold digests of more than one
    /// algorithm (a VICS import stores each medium's MD5 and SHA-1 under one set
    /// whose label names only one of them). lookup_hash must match on the value
    /// regardless of the set's `hash_algorithm` label; a label filter would drop
    /// the differing-algorithm entries and un-flag known-CSAM. This test pins
    /// that behaviour so the "optimisation" the doc warns against cannot slip in.
    #[tokio::test]
    async fn lookup_hash_matches_mixed_algorithm_entries_in_one_set() {
        let db = test_db().await;
        let case_id = db.create_case("VICS", "examiner").await.unwrap();
        // The set's declared algorithm is md5, but it holds a SHA-1 too.
        let set_id = db
            .create_hash_set(case_id, "vics", None, "known", "md5")
            .await
            .unwrap();
        let md5 = "d41d8cd98f00b204e9800998ecf8427e"; // 32 hex
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 hex
        db.import_hash_set_entries(set_id, &[(md5.to_string(), None), (sha1.to_string(), None)])
            .await
            .unwrap();

        assert_eq!(
            db.lookup_hash(case_id, sha1).await.unwrap().len(),
            1,
            "a SHA-1 in an md5-labelled set must still be found"
        );
        assert_eq!(
            db.lookup_hash(case_id, md5).await.unwrap().len(),
            1,
            "the MD5 must be found too"
        );
    }

    /// P1 pivot: a set of artifact ids groups by record `type` where one is
    /// set, and by coarse `artifact_type` where it is not, so the pivot can
    /// say "2 network flows, 1 file" rather than "3 records".
    #[tokio::test]
    async fn record_kinds_group_by_type_then_fall_back_to_artifact_type() {
        let db = test_db().await;
        let case_id = db.create_case("Pivot", "examiner").await.unwrap();

        let flow_a = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "NetworkFlow", "name": "tcp 10.0.0.1 -> 203.0.113.9"}),
        );
        let flow_b = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "NetworkFlow", "name": "tcp 10.0.0.2 -> 203.0.113.9"}),
        );
        let dns = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "DnsResolution", "name": "evil.example -> 203.0.113.9"}),
        );
        let file = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "notes.txt"}),
        );
        for a in [&flow_a, &flow_b, &dns, &file] {
            db.record_artifact(a).await.unwrap();
        }

        let kinds = db
            .record_kinds_for_ids(case_id, &[flow_a.id, flow_b.id, dns.id, file.id])
            .await
            .unwrap();
        assert_eq!(
            kinds.get(&flow_a.id).map(String::as_str),
            Some("NetworkFlow")
        );
        assert_eq!(
            kinds.get(&flow_b.id).map(String::as_str),
            Some("NetworkFlow")
        );
        assert_eq!(
            kinds.get(&dns.id).map(String::as_str),
            Some("DnsResolution")
        );
        // No $.type: the coarse artifact_type stands in.
        assert_eq!(kinds.get(&file.id).map(String::as_str), Some("FileEntry"));

        // An id from another case is simply absent, never guessed at.
        assert!(!kinds.contains_key(&Uuid::new_v4()));

        // Empty input is an empty map, not an error or a full-table scan.
        assert!(db
            .record_kinds_for_ids(case_id, &[])
            .await
            .unwrap()
            .is_empty());
    }

    /// HUNT-078: `get_case` notes the access with a write. When that write
    /// cannot land — here a read-only connection, in production a writer
    /// held by a running ingest for the whole busy timeout — the read must
    /// still answer. Before this the read failed with the note, and the UI
    /// told the examiner the case may have been deleted.
    #[tokio::test]
    async fn a_case_still_reads_when_the_access_note_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cases.sqlite");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let writable = SqliteConnection::new(&url).await.unwrap();
        writable.initialize().await.unwrap();
        let case_id = writable.create_case("Read me", "examiner").await.unwrap();
        let before = writable.get_case(case_id).await.unwrap().last_accessed_at;

        let read_only = SqliteConnection::new(&format!("sqlite://{}?mode=ro", path.display()))
            .await
            .unwrap();
        let fetched = read_only
            .get_case(case_id)
            .await
            .expect("a read must not depend on the access note landing");
        assert_eq!(fetched.id, case_id);
        assert_eq!(fetched.name, "Read me");
        // The note did not land, and that is all that differs.
        assert_eq!(fetched.last_accessed_at, before);
    }

    /// HUNT-072: a case marked for deletion is gone from every listing and
    /// answers its status as `deleting`, so the window between the request
    /// and the last row's removal never shows a half-deleted case as live.
    #[tokio::test]
    async fn a_case_marked_deleting_leaves_the_listings_and_says_so() {
        let db = test_db().await;
        let keep = db.create_case("Keep", "examiner").await.unwrap();
        let going = db.create_case("Going", "examiner").await.unwrap();

        db.mark_case_deleting(going).await.unwrap();

        assert_eq!(
            db.case_status(going).await.unwrap().as_deref(),
            Some("deleting")
        );
        assert_eq!(
            db.case_status(keep).await.unwrap().as_deref(),
            Some("active")
        );
        assert_eq!(db.case_status(Uuid::new_v4()).await.unwrap(), None);

        let listed: Vec<Uuid> = db
            .list_cases()
            .await
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(listed, vec![keep]);
        let searched: Vec<Uuid> = db
            .search_cases(None, None, None)
            .await
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(searched, vec![keep]);
        assert_eq!(db.cases_pending_deletion().await.unwrap(), vec![going]);

        assert!(
            db.mark_case_deleting(Uuid::new_v4()).await.is_err(),
            "marking a case that does not exist is an error, not a silent no-op"
        );
    }

    /// HUNT-072: the delete runs in bounded batches rather than one
    /// transaction over every row, so a case larger than the batch is still
    /// removed whole — and the batch boundary is exercised, not assumed.
    #[tokio::test]
    async fn a_case_larger_than_one_delete_batch_is_removed_whole() {
        let db = test_db().await;
        let case_id = db.create_case("Big", "examiner").await.unwrap();
        let other = db.create_case("Other", "examiner").await.unwrap();

        let n = DELETE_BATCH_ROWS * 2 + 7;
        let mut batch = Vec::with_capacity(n);
        for i in 0..n {
            batch.push(Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({"name": format!("f{i}")}),
            ));
        }
        db.record_artifacts_batch(&batch).await.unwrap();
        for a in batch.iter().take(DELETE_BATCH_ROWS + 3) {
            db.record_processing_log(case_id, a.id, "mod.id", "complete", 0, None, 1)
                .await
                .unwrap();
        }
        let event = timeline_artifact(case_id, 1_700_000_000, "event");
        db.record_artifact(&event).await.unwrap();
        let keep = Artifact::new(other, ArtifactType::FileEntry, None, json!({"name": "k"}));
        db.record_artifact(&keep).await.unwrap();

        db.delete_case(case_id).await.unwrap();

        for table in ["artifacts", "timeline_events", "processing_log"] {
            assert_eq!(count_for_case(&db, table, case_id).await, 0, "{table}");
        }
        assert_eq!(db.case_status(case_id).await.unwrap(), None);
        assert_eq!(count_for_case(&db, "artifacts", other).await, 1);
        assert_eq!(
            db.case_status(other).await.unwrap().as_deref(),
            Some("active")
        );
        assert!(db.cases_pending_deletion().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_case_removes_children_and_retains_audit() {
        let db = test_db().await;
        let case_id = db.create_case("Delete Me", "examiner").await.unwrap();

        // Populate child tables
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "file.txt"}),
        );
        db.record_artifact(&artifact).await.unwrap();

        let event = timeline_artifact(case_id, 1_700_000_000, "event");
        db.record_artifact(&event).await.unwrap();
        db.create_timeline_tag(case_id, event.id, Some("ex"), Some("tagged"))
            .await
            .unwrap();

        let profile = seance_core::profile::IngestionProfile {
            id: Uuid::new_v4(),
            case_id,
            name: "profile".to_string(),
            description: "d".to_string(),
            enabled_modules: vec![],
            disabled_modules: vec![],
            is_active: false,
            created_at: Utc::now().timestamp(),
        };
        db.create_profile(&profile).await.unwrap();

        db.create_hash_set(case_id, "hs", None, "known", "md5")
            .await
            .unwrap();

        db.record_integrity_check(
            case_id,
            artifact.id,
            Some("aa"),
            None,
            None,
            Some("aa"),
            None,
            None,
            "verified",
            None,
        )
        .await
        .unwrap();

        db.save_filter(Uuid::new_v4(), Some(case_id), "f", "d", "{}", false)
            .await
            .unwrap();

        db.record_processing_log(case_id, artifact.id, "mod.id", "complete", 1, None, 5)
            .await
            .unwrap();

        db.record_audit_event(
            Some(case_id),
            "examiner",
            "case_created",
            Some("case"),
            Some(case_id),
            None,
        )
        .await
        .unwrap();
        db.record_audit_event(
            Some(case_id),
            "examiner",
            "evidence_ingested",
            Some("artifact"),
            Some(artifact.id),
            None,
        )
        .await
        .unwrap();

        db.delete_case(case_id).await.unwrap();

        for table in [
            "artifacts",
            "timeline_events",
            "timeline_tags",
            "ingestion_profiles",
            "hash_sets",
            "integrity_checks",
            "filters",
            "processing_log",
        ] {
            assert_eq!(
                count_for_case(&db, table, case_id).await,
                0,
                "{} rows must be removed with the case",
                table
            );
        }

        // Audit rows are forensic evidence: retained, with case_id nulled
        let total_audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(total_audit, 2, "audit_log rows must survive case deletion");
        let nulled: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE case_id IS NULL")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(nulled, 2);
    }

    #[tokio::test]
    async fn delete_artifact_recursive_cleans_tags_and_processing_log() {
        let db = test_db().await;
        let case_id = db.create_case("Case", "examiner").await.unwrap();

        let event = timeline_artifact(case_id, 1_700_000_000, "event");
        db.record_artifact(&event).await.unwrap();
        db.create_timeline_tag(case_id, event.id, None, Some("keep?"))
            .await
            .unwrap();
        db.record_processing_log(case_id, event.id, "mod.id", "complete", 0, None, 1)
            .await
            .unwrap();

        let (artifacts, events) = db
            .delete_artifact_recursive(case_id, event.id)
            .await
            .unwrap();
        assert_eq!(artifacts, 1);
        assert_eq!(events, 1);

        let tags: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM timeline_tags WHERE event_id = ?")
            .bind(event.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(tags, 0, "timeline_tags must not orphan");

        let logs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM processing_log WHERE artifact_id = ?")
                .bind(event.id)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(logs, 0, "processing_log must not orphan");
    }

    // --- H4: tamper-evident audit hash chain ---

    #[tokio::test]
    async fn audit_chain_links_across_events() {
        let db = test_db().await;
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();

        db.record_audit_event(
            Some(case_id),
            "alice",
            "case_created",
            Some("case"),
            Some(case_id),
            None,
        )
        .await
        .unwrap();
        db.record_audit_event(
            Some(case_id),
            "alice",
            "evidence_ingested",
            Some("artifact"),
            Some(Uuid::new_v4()),
            Some("/tmp/x"),
        )
        .await
        .unwrap();
        db.record_audit_event(None, "bob", "search_executed", None, None, Some("query"))
            .await
            .unwrap();

        let rows = sqlx::query("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id ASC")
            .fetch_all(&db.pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);

        let prev0: Option<String> = rows[0].try_get("prev_hash").unwrap();
        let entry0: Option<String> = rows[0].try_get("entry_hash").unwrap();
        let prev1: Option<String> = rows[1].try_get("prev_hash").unwrap();
        let entry1: Option<String> = rows[1].try_get("entry_hash").unwrap();
        let prev2: Option<String> = rows[2].try_get("prev_hash").unwrap();

        assert!(prev0.is_none(), "genesis row has no prev_hash");
        assert!(entry0.is_some());
        assert_eq!(prev1, entry0, "row 2 chains from row 1");
        assert_eq!(prev2, entry1, "row 3 chains from row 2");

        let status = db.verify_audit_chain(None).await.unwrap();
        assert_eq!(
            status,
            AuditChainStatus {
                valid: true,
                checked: 3,
                broken_at: None,
                tamper_evident: db.audit_hmac_key.is_some(),
                keyed_rows: if db.audit_hmac_key.is_some() { 3 } else { 0 },
                unkeyed_rows: if db.audit_hmac_key.is_some() { 0 } else { 3 },
                tamper_evident_from: db.audit_hmac_key.as_ref().map(|_| 1),
                break_reason: None,
                // The head is the third (last) chained row; its hash is
                // content-dependent, so assert its shape below rather than
                // pinning a literal.
                head_id: Some(3),
                head_hash: status.head_hash.clone(),
                key_configured: db.audit_hmac_key.is_some(),
            }
        );
        assert!(
            status.head_hash.as_deref().is_some_and(|h| h.len() == 64),
            "a verified chain publishes its head hash so it can be anchored externally"
        );
    }

    #[tokio::test]
    async fn audit_chain_detects_tampered_row() {
        let db = test_db().await;
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();

        for i in 0..3 {
            db.record_audit_event(
                Some(case_id),
                "alice",
                "action",
                None,
                None,
                Some(&format!("event {}", i)),
            )
            .await
            .unwrap();
        }

        // Tamper with the middle row's details
        let mid_id: i64 =
            sqlx::query_scalar("SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 1")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        sqlx::query("UPDATE audit_log SET details = 'tampered' WHERE id = ?")
            .bind(mid_id)
            .execute(&db.pool)
            .await
            .unwrap();

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid);
        assert_eq!(status.broken_at, Some(mid_id));
    }

    #[tokio::test]
    async fn audit_chain_skips_legacy_unchained_rows() {
        let db = test_db().await;

        // Simulate a pre-migration row: no entry_hash
        sqlx::query(
            "INSERT INTO audit_log (case_id, timestamp, user_id, action) VALUES (NULL, ?, 'legacy', 'old_action')",
        )
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();

        db.record_audit_event(None, "alice", "new_action", None, None, None)
            .await
            .unwrap();
        db.record_audit_event(None, "alice", "newer_action", None, None, None)
            .await
            .unwrap();

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid);
        assert_eq!(status.checked, 2, "legacy rows are skipped, not counted");
    }

    /// Rewrite the whole chain the way a database writer with no server secret
    /// can: change a row, then recompute every hash from the same fields the
    /// verifier reads. Returns nothing; the chain is left internally consistent.
    async fn recompute_unkeyed_chain(db: &SqliteConnection) {
        let rows = sqlx::query(
            "SELECT id, timestamp, user_id, action, details FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        let mut prev: Option<String> = None;
        for row in rows {
            let id: i64 = row.try_get("id").unwrap();
            let timestamp: String = row.try_get("timestamp").unwrap();
            let user_id: String = row.try_get("user_id").unwrap();
            let action: String = row.try_get("action").unwrap();
            let details: Option<String> = row.try_get("details").unwrap();
            // resource_type / resource_id are NULL on every row these tests write.
            let entry = compute_audit_entry_hash(
                None,
                prev.as_deref(),
                &timestamp,
                &user_id,
                &action,
                None,
                None,
                details.as_deref(),
            );
            sqlx::query("UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?")
                .bind(&prev)
                .bind(&entry)
                .bind(id)
                .execute(&db.pool)
                .await
                .unwrap();
            prev = Some(entry);
        }
    }

    #[tokio::test]
    async fn a_rewritten_unkeyed_chain_verifies_and_reports_itself_not_tamper_evident() {
        let mut db = test_db().await;
        // The default deployment: no SEANCE_AUDIT_HMAC_KEY. Set explicitly so
        // the test states the condition rather than inheriting the environment.
        db.audit_hmac_key = None;
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();

        for i in 0..3 {
            db.record_audit_event(
                Some(case_id),
                "alice",
                "evidence_exported",
                None,
                None,
                Some(&format!("event {}", i)),
            )
            .await
            .unwrap();
        }
        assert!(db.verify_audit_chain(None).await.unwrap().valid);

        sqlx::query(
            "UPDATE audit_log SET details = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_log)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        recompute_unkeyed_chain(&db).await;

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(
            status.valid,
            "an unkeyed chain recomputes from database contents alone, so a rewrite verifies"
        );
        assert!(
            !status.tamper_evident,
            "a 'valid' verdict that a database writer can manufacture must not be reported as \
             evidence the audit trail is unaltered"
        );
    }

    #[tokio::test]
    async fn a_keyed_chain_reports_itself_tamper_evident_and_rejects_a_rewrite() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();

        for i in 0..3 {
            db.record_audit_event(
                Some(case_id),
                "alice",
                "evidence_exported",
                None,
                None,
                Some(&format!("event {}", i)),
            )
            .await
            .unwrap();
        }

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid);
        assert!(
            status.tamper_evident,
            "a keyed HMAC chain cannot be recomputed from the database alone"
        );

        // The same rewrite an unkeyed chain absorbs silently.
        sqlx::query(
            "UPDATE audit_log SET details = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_log)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        recompute_unkeyed_chain(&db).await;

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(
            !status.valid,
            "the key is what makes the rewrite detectable"
        );
        assert!(status.tamper_evident);
    }

    /// Write `n` audit rows through `db` as they are keyed right now.
    async fn write_audit_rows(db: &SqliteConnection, case_id: Uuid, n: usize, label: &str) {
        for i in 0..n {
            db.record_audit_event(
                Some(case_id),
                "alice",
                "evidence_exported",
                None,
                None,
                Some(&format!("{label} {i}")),
            )
            .await
            .unwrap();
        }
    }

    // --- DEPLOY-001: keying introduced or rotated on a live chain ---

    #[tokio::test]
    async fn a_chain_keyed_part_way_through_says_from_which_row_it_is_tamper_evident() {
        // The migration path every existing deployment takes: rows written
        // before SEANCE_AUDIT_HMAC_KEY was set, then rows written under it. The
        // old rows must not become a "broken chain", and they must not be
        // credited with a tamper-evidence they never had.
        let mut db = test_db().await;
        db.audit_hmac_key = None;
        db.audit_hmac_previous_keys = Vec::new();
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 3, "unkeyed").await;

        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        write_audit_rows(&db, case_id, 2, "keyed").await;

        let first_keyed: i64 =
            sqlx::query_scalar("SELECT MIN(id) FROM audit_log WHERE key_fingerprint IS NOT NULL")
                .fetch_one(&db.pool)
                .await
                .unwrap();

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid, "{status:?}");
        assert_eq!(status.checked, 5);
        assert_eq!(status.unkeyed_rows, 3);
        assert_eq!(status.keyed_rows, 2);
        assert_eq!(status.tamper_evident_from, Some(first_keyed));
        assert!(
            !status.tamper_evident,
            "a chain with an unkeyed prefix is not tamper-evident as a whole: {status:?}"
        );
        assert!(status.break_reason.is_none());
    }

    /// A chain whose rows were all written under a key that has since been
    /// RETIRED is still fully keyed, and must be reported as tamper-evident.
    ///
    /// Requiring the *current* key made an archived database verified on a
    /// workstation holding only `SEANCE_AUDIT_HMAC_KEY_PREVIOUS` report
    /// `tamper_evident: false` with `unkeyed_rows == 0` — and the report then
    /// rendered the PARTIALLY-keyed disclosure, "rows before entry 1 were
    /// written unkeyed", when no row precedes the first and none was unkeyed.
    /// That is a false statement about the custody record in a court-facing
    /// document.
    #[tokio::test]
    async fn a_chain_verified_under_a_retired_key_alone_is_still_tamper_evident() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"the-key-of-the-day".to_vec());
        db.audit_hmac_previous_keys = Vec::new();
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 4, "keyed").await;

        // The archive is later read on a machine that holds the key only as a
        // retired one, with no current key configured at all.
        db.audit_hmac_key = None;
        db.audit_hmac_previous_keys = vec![b"the-key-of-the-day".to_vec()];

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(
            status.valid,
            "every row still recomputes under the retired key"
        );
        assert_eq!(status.unkeyed_rows, 0, "no row was written unkeyed");
        assert_eq!(status.keyed_rows, 4);
        assert!(
            status.tamper_evident,
            "every row recomputed under a server-held secret, so a passing \
             verification IS evidence of no alteration — whether that secret is \
             the current key or a retired one"
        );
    }

    #[tokio::test]
    async fn a_fully_keyed_chain_is_tamper_evident_from_its_first_row() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        db.audit_hmac_previous_keys = Vec::new();
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 3, "keyed").await;

        let first: i64 = sqlx::query_scalar("SELECT MIN(id) FROM audit_log")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid);
        assert!(status.tamper_evident);
        assert_eq!(status.keyed_rows, 3);
        assert_eq!(status.unkeyed_rows, 0);
        assert_eq!(status.tamper_evident_from, Some(first));
    }

    /// A deleted tail is the one tampering a hash chain cannot show on its own,
    /// and it is exactly what a database-write attacker (the actor keying
    /// defends against) can do to erase their own tracks. The chain still
    /// verifies afterwards, so the only honest defence is an external anchor:
    /// the head published on one verification, compared on the next. This pins
    /// both halves — that a truncated chain still returns `valid`, and that the
    /// published head moves so the truncation is detectable against a record of
    /// the earlier head.
    #[tokio::test]
    async fn a_truncated_chain_still_verifies_but_its_head_reveals_the_deletion() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        db.audit_hmac_previous_keys = Vec::new();
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 6, "keyed").await;

        // The operator records the head of the intact chain out of band.
        let anchor = db.verify_audit_chain(None).await.unwrap();
        assert!(anchor.valid && anchor.tamper_evident);
        assert_eq!(anchor.checked, 6);
        let anchored_count = anchor.checked;
        let anchored_head = anchor
            .head_hash
            .clone()
            .expect("a verified chain has a head");

        // The attacker deletes the last two rows — their own tracks. No gap is
        // left, so the shortened chain is internally continuous.
        sqlx::query(
            "DELETE FROM audit_log WHERE id IN \
             (SELECT id FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 2)",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        let after = db.verify_audit_chain(None).await.unwrap();
        // The chain ALONE cannot show the deletion: it still verifies.
        assert!(
            after.valid && after.tamper_evident,
            "a truncated chain is internally consistent and still verifies — which is the whole \
             danger, and why the verdict must never equate 'verifies' with 'complete'"
        );
        // The head, compared against the anchor, is what reveals it.
        assert!(
            after.checked < anchored_count,
            "the chain is now shorter than the anchored length"
        );
        assert_ne!(
            after.head_hash.as_deref(),
            Some(anchored_head.as_str()),
            "the head moved: an operator holding the anchored head can prove the tail was deleted"
        );
    }

    #[tokio::test]
    async fn a_rewritten_keyed_row_breaks_the_chain_with_a_reason() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 3, "keyed").await;

        sqlx::query(
            "UPDATE audit_log SET details = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_log)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        recompute_unkeyed_chain(&db).await;

        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid);
        let reason = status
            .break_reason
            .as_deref()
            .expect("a break names its reason");
        assert!(
            reason.contains("does not recompute under the current key"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn an_unkeyed_tail_after_keyed_rows_is_a_break_not_a_downgrade() {
        // The attack a keyed chain exists to catch: someone with database
        // access replaces everything after row N with rows they hashed
        // themselves. They have no key, so the rows they write are unkeyed and
        // carry no fingerprint -- exactly what a legacy pre-key row looks like.
        // The difference is position: legacy rows precede the first keyed row,
        // a replaced tail follows one.
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 2, "keyed").await;

        db.audit_hmac_key = None;
        write_audit_rows(&db, case_id, 2, "forged").await;
        let first_forged: i64 =
            sqlx::query_scalar("SELECT MIN(id) FROM audit_log WHERE key_fingerprint IS NULL")
                .fetch_one(&db.pool)
                .await
                .unwrap();

        db.audit_hmac_key = Some(b"server-held-secret".to_vec());
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid, "{status:?}");
        assert_eq!(status.broken_at, Some(first_forged));
        assert_eq!(status.keyed_rows, 2);
        assert!(
            status
                .break_reason
                .as_deref()
                .unwrap_or_default()
                .contains("follows keyed rows"),
            "{status:?}"
        );
    }

    #[tokio::test]
    async fn a_retired_key_in_previous_keeps_its_segment_verifying() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"key-2025".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 2, "old key").await;

        // The rotation: new key current, old key retired.
        db.audit_hmac_key = Some(b"key-2026".to_vec());
        db.audit_hmac_previous_keys = vec![b"key-2025".to_vec()];
        write_audit_rows(&db, case_id, 2, "new key").await;

        let first: i64 = sqlx::query_scalar("SELECT MIN(id) FROM audit_log")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid, "{status:?}");
        assert_eq!(status.keyed_rows, 4);
        assert_eq!(status.unkeyed_rows, 0);
        assert!(
            status.tamper_evident,
            "every row was written under a key the server holds: {status:?}"
        );
        assert_eq!(status.tamper_evident_from, Some(first));

        // And the rows under the retired key are still checked, not waved
        // through: rewrite one and the retired key catches it.
        sqlx::query(
            "UPDATE audit_log SET details = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_log)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid);
        assert_eq!(status.broken_at, Some(first));
        assert!(
            status
                .break_reason
                .as_deref()
                .unwrap_or_default()
                .contains("retired key"),
            "{status:?}"
        );
    }

    /// A retired key that contains a colon is still one key (CR-033 #10).
    ///
    /// `SEANCE_AUDIT_HMAC_KEY` is taken verbatim, so `with:colon` is a legal
    /// current key. Retiring it into the colon-separated
    /// `SEANCE_AUDIT_HMAC_KEY_PREVIOUS` split it into `with` and `colon`, neither
    /// of which any row was written under, and the whole pre-rotation history
    /// verified as a break.
    #[test]
    fn a_retired_key_containing_a_colon_is_offered_whole_as_well_as_split() {
        assert_eq!(
            parse_retired_audit_keys("with:colon"),
            vec![b"with".to_vec(), b"colon".to_vec(), b"with:colon".to_vec()]
        );
        assert_eq!(parse_retired_audit_keys("plain"), vec![b"plain".to_vec()]);
        assert!(parse_retired_audit_keys("").is_empty());
        assert!(parse_retired_audit_keys(":").is_empty());
        // Two ordinary keys are still two keys, with nothing invented.
        assert_eq!(
            parse_retired_audit_keys("k1:k2"),
            vec![b"k1".to_vec(), b"k2".to_vec(), b"k1:k2".to_vec()]
        );
    }

    #[tokio::test]
    async fn rows_written_under_a_key_with_a_colon_verify_after_it_is_retired() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"with:colon".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 3, "keyed").await;

        // Rotated: the old key is expressed the only way the variable allows.
        db.audit_hmac_key = Some(b"next-key".to_vec());
        db.audit_hmac_previous_keys = parse_retired_audit_keys("with:colon");
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(status.valid, "{status:?}");
        assert_eq!(status.keyed_rows, 3);
    }

    /// Two connections that share nothing but the database file — two
    /// processes, in effect — appending to the audit log at once must produce
    /// one chain, not a fork (HUNT-038). Each `SqliteConnection::new` has its
    /// own `audit_lock`, so only the transaction's write lock can keep the
    /// second writer from reading a head the first is about to replace.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writers_from_separate_connections_do_not_fork_the_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("audit.db").display()
        );
        let a = SqliteConnection::new(&url).await.expect("open a");
        a.initialize().await.expect("migrate");
        let b = SqliteConnection::new(&url).await.expect("open b");
        let case_id = a.create_case("Race Case", "examiner").await.unwrap();

        let writer = |db: SqliteConnection, tag: &'static str| async move {
            for i in 0..60 {
                db.record_audit_event(
                    Some(case_id),
                    tag,
                    "race",
                    Some("case"),
                    Some(case_id),
                    Some(&format!("{tag} {i}")),
                )
                .await
                .expect("write");
                tokio::task::yield_now().await;
            }
        };
        let (ra, rb) = tokio::join!(
            tokio::spawn(writer(a.clone(), "alpha")),
            tokio::spawn(writer(b.clone(), "beta"))
        );
        ra.unwrap();
        rb.unwrap();

        let status = a.verify_audit_chain(None).await.unwrap();
        assert!(status.valid, "two writers must leave one chain: {status:?}");
        assert!(status.checked >= 120, "{status:?}");
    }

    #[tokio::test]
    async fn a_fingerprint_the_server_does_not_hold_breaks_with_the_variable_named() {
        let mut db = test_db().await;
        db.audit_hmac_key = Some(b"key-2025".to_vec());
        let case_id = db.create_case("Audit Case", "examiner").await.unwrap();
        write_audit_rows(&db, case_id, 2, "old key").await;
        let old_fp = audit_key_fingerprint(b"key-2025");

        // Rotated without retiring the old key anywhere.
        db.audit_hmac_key = Some(b"key-2026".to_vec());
        db.audit_hmac_previous_keys = Vec::new();
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid);
        let reason = status.break_reason.as_deref().expect("reason");
        assert!(
            reason.contains(&old_fp),
            "the reason names the fingerprint: {reason}"
        );
        assert!(
            reason.contains("SEANCE_AUDIT_HMAC_KEY_PREVIOUS"),
            "the reason names where the retired key goes: {reason}"
        );

        // And with no key configured at all, the same rows are a chain this
        // server cannot vouch for -- not a silently unkeyed pass.
        db.audit_hmac_key = None;
        let status = db.verify_audit_chain(None).await.unwrap();
        assert!(!status.valid, "{status:?}");
        assert!(
            status
                .break_reason
                .as_deref()
                .unwrap_or_default()
                .contains("no audit key is configured"),
            "{status:?}"
        );
    }

    #[test]
    fn a_key_fingerprint_identifies_a_key_without_being_the_key() {
        let fp = audit_key_fingerprint(b"server-held-secret");
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, audit_key_fingerprint(b"server-held-secret"));
        assert_ne!(fp, audit_key_fingerprint(b"server-held-secret2"));
        // Domain-separated: not a truncation of the raw SHA-256 of the key.
        use sha2::{Digest, Sha256};
        let raw: String = Sha256::digest(b"server-held-secret")
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_ne!(fp, raw);
    }

    // --- M3: stable timeline pagination with duplicate timestamps ---

    #[tokio::test]
    async fn timeline_pagination_stable_with_duplicate_timestamps() {
        let db = test_db().await;
        let case_id = db.create_case("Paging Case", "examiner").await.unwrap();

        let a = timeline_artifact(case_id, 1_700_000_000, "event a");
        let b = timeline_artifact(case_id, 1_700_000_000, "event b");
        db.record_artifact(&a).await.unwrap();
        db.record_artifact(&b).await.unwrap();

        let page = |offset: usize| {
            db.get_timeline_events_filtered(
                case_id,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(1),
                Some(offset),
                Some("timestamp"),
                Some("desc"),
                None,
                None,
            )
        };

        let first = page(0).await.unwrap();
        let second = page(1).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].id, second[0].id, "pages must not repeat an event");

        let mut seen: Vec<Uuid> = vec![first[0].id, second[0].id];
        seen.sort();
        let mut expected = vec![a.id, b.id];
        expected.sort();
        assert_eq!(
            seen, expected,
            "both events appear exactly once across pages"
        );

        // Deterministic: re-querying the same page returns the same event
        let first_again = page(0).await.unwrap();
        assert_eq!(first_again[0].id, first[0].id);
    }

    #[tokio::test]
    async fn record_type_counts_tolerates_non_string_discriminator() {
        // Regression: a ParsedRecord whose discriminator is a non-string JSON
        // value (a numeric `subtype`, seen in real evidence) must not poison the
        // whole count — it used to fail the sqlx decode into `String` and error
        // the entire /record_types endpoint.
        let db = test_db().await;
        let case_id = db.create_case("Types", "e").await.unwrap();

        let string_typed = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "exif" }),
        );
        let numeric_typed = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "subtype": 1 }),
        );
        db.record_artifact(&string_typed).await.unwrap();
        db.record_artifact(&numeric_typed).await.unwrap();

        let counts = db.record_type_counts(case_id, None).await.unwrap();
        let map: std::collections::HashMap<String, i64> = counts.into_iter().collect();
        assert_eq!(map.get("exif"), Some(&1));
        assert_eq!(
            map.get("1"),
            Some(&1),
            "numeric subtype must be coerced to the text '1', not dropped"
        );
    }

    #[tokio::test]
    async fn record_type_counts_scopes_to_source_subtree() {
        // Provenance parity: the Logical navigator must be able to ask "what did
        // THIS acquisition yield?" and get counts that match the rows the source
        // filter then lists. The scoped count walks the source's subtree; the
        // unscoped count spans the whole case.
        let db = test_db().await;
        let case_id = db.create_case("Provenance", "e").await.unwrap();

        // Two independent acquisitions.
        let source_a = Artifact::new(case_id, ArtifactType::RawEvidence, None, json!({}));
        let source_b = Artifact::new(case_id, ArtifactType::RawEvidence, None, json!({}));
        db.record_artifact(&source_a).await.unwrap();
        db.record_artifact(&source_b).await.unwrap();

        // A intermediate node, so we also prove records nested below the source
        // (not just direct children) are attributed to it.
        let fs_a = Artifact::new(case_id, ArtifactType::FileSystem, None, json!({}))
            .with_parent(source_a.id);
        db.record_artifact(&fs_a).await.unwrap();

        let mk = |parent: Uuid, ty: &str| {
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({ "type": ty }),
            )
            .with_parent(parent)
        };
        // A: iMessage directly under the source, iMessage nested under its
        // filesystem, and one Contact. B: a single iMessage.
        for rec in [
            mk(source_a.id, "iMessage"),
            mk(fs_a.id, "iMessage"),
            mk(source_a.id, "Contact"),
            mk(source_b.id, "iMessage"),
        ] {
            db.record_artifact(&rec).await.unwrap();
        }

        let counts = |src| {
            let db = &db;
            async move {
                let rows = db.record_type_counts(case_id, src).await.unwrap();
                rows.into_iter()
                    .collect::<std::collections::HashMap<String, i64>>()
            }
        };

        let all = counts(None).await;
        assert_eq!(all.get("iMessage"), Some(&3), "case-wide iMessage count");
        assert_eq!(all.get("Contact"), Some(&1));

        let a = counts(Some(source_a.id)).await;
        assert_eq!(
            a.get("iMessage"),
            Some(&2),
            "source A's iMessages include the one nested under its filesystem"
        );
        assert_eq!(a.get("Contact"), Some(&1));

        let b = counts(Some(source_b.id)).await;
        assert_eq!(b.get("iMessage"), Some(&1));
        assert_eq!(
            b.get("Contact"),
            None,
            "source B has no contacts; it must not inherit A's"
        );
    }

    #[tokio::test]
    async fn search_conversation_messages_matches_text_and_groups_by_thread() {
        let db = test_db().await;
        let case_id = db.create_case("Chat", "e").await.unwrap();

        // Two WhatsApp threads; only some messages mention "coffee". WhatsApp
        // groups a conversation on the contact JID.
        let mk = |thread: &str, text: &str, date: i64| {
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "WhatsApp",
                    "contact_jid": thread,
                    "text": text,
                    "date": date,
                }),
            )
        };
        for a in [
            mk("alice", "want a coffee later?", 1_000),
            mk("alice", "sure, see you then", 1_010),
            mk("bob", "the COFFEE machine broke", 2_000),
            mk("bob", "unrelated message", 2_010),
            // A different record type must never leak into WhatsApp results.
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({ "type": "Instagram", "chat_identifier": "x", "text": "coffee", "date": 3_000 }),
            ),
        ] {
            db.record_artifact(&a).await.unwrap();
        }

        let hits = db
            .search_conversation_messages(case_id, "WhatsApp", "coffee", 100)
            .await
            .unwrap();
        // Case-insensitive LIKE, WhatsApp only (Instagram excluded), newest first.
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].thread_key, "bob"); // date 2000 > 1000
        assert_eq!(hits[0].text, "the COFFEE machine broke");
        assert_eq!(hits[1].thread_key, "alice");

        // A wildcard character in the term is matched literally, not as LIKE `%`.
        let none = db
            .search_conversation_messages(case_id, "WhatsApp", "%", 100)
            .await
            .unwrap();
        assert!(none.is_empty(), "'%' must be escaped, not match everything");

        // An unknown record type has no thread grouping: that is an error, not
        // an empty result that reads as "no such messages".
        assert!(db
            .search_conversation_messages(case_id, "NotAThing", "coffee", 100)
            .await
            .is_err());
    }

    #[test]
    fn escape_like_escapes_all_metacharacters() {
        // Backslash first, so an escaped `%`/`_` is not double-escaped.
        assert_eq!(escape_like("report_final"), "report\\_final");
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(escape_like("plain"), "plain");
    }

    #[tokio::test]
    async fn timeline_filters_escape_like_metacharacters() {
        // BUG-189: `_` and `%` are LIKE wildcards. Unescaped, a search for
        // "report_final" also matches "reportXfinal" and a bare "%" matches
        // every event. The page query, the count and the extent/histogram
        // builder must all agree.
        let db = test_db().await;
        let case_id = db.create_case("Escape", "examiner").await.unwrap();

        let ev = |ts: i64, desc: &str, filename: &str, kind: &str| {
            Artifact::new(
                case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": ts,
                    "timestamp_desc": kind,
                    "source_module": "test_module",
                    "short_desc": desc,
                    "full_details": json!({ "filename": filename }).to_string(),
                }),
            )
        };
        for a in [
            ev(
                1_700_000_001,
                "report_final",
                "report_final.docx",
                "File_Created",
            ),
            ev(
                1_700_000_002,
                "reportXfinal",
                "reportXfinal.docx",
                "FileXCreated",
            ),
        ] {
            db.record_artifact(&a).await.unwrap();
        }

        let list = |search: Option<&'static str>,
                    filename: Option<&'static str>,
                    kind: Option<&'static str>| {
            db.get_timeline_events_filtered(
                case_id, None, None, None, search, filename, kind, None, None, None, None, None,
                None,
            )
        };
        let count = |search: Option<&'static str>,
                     filename: Option<&'static str>,
                     kind: Option<&'static str>| {
            db.get_timeline_events_count(case_id, None, None, None, search, filename, kind, None)
        };

        // Text search: `_` is literal.
        let rows = list(Some("report_final"), None, None).await.unwrap();
        assert_eq!(rows.len(), 1, "`_` must not match an arbitrary character");
        assert_eq!(rows[0].short_desc, "report_final");
        assert_eq!(count(Some("report_final"), None, None).await.unwrap(), 1);

        // Text search: `%` is literal, so it matches nothing here.
        assert!(list(Some("%"), None, None).await.unwrap().is_empty());
        assert_eq!(count(Some("%"), None, None).await.unwrap(), 0);

        // Filename filter.
        let rows = list(None, Some("report_final.docx"), None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            count(None, Some("report_final.docx"), None).await.unwrap(),
            1
        );
        assert!(list(None, Some("%"), None).await.unwrap().is_empty());

        // Event-type filter (timestamp_desc).
        let rows = list(None, None, Some("File_Created")).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp_desc, "File_Created");
        assert_eq!(count(None, None, Some("File_Created")).await.unwrap(), 1);

        // build_timeline_where (extent / histogram) uses the same escaping, so
        // the chart range covers exactly the matching event.
        let extent = db
            .get_timeline_extent(
                case_id,
                None,
                None,
                None,
                Some("report_final"),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(extent, Some((1_700_000_001, 1_700_000_001)));
    }

    /// §2.8. "Show unique only" answers with the files this case can
    /// *demonstrate* are one of a kind. A file carrying no hash is neither
    /// unique nor a duplicate — it is unassessed — and folding it into either
    /// answer would turn an unknown into a finding. The three states are
    /// therefore three, and `UniqueFilter::Unassessable` counts the population
    /// the grid had to set aside so a screen can say so.
    #[tokio::test]
    async fn unique_only_lists_what_can_be_shown_unique_and_counts_what_cannot() {
        let db = test_db().await;
        let case_id = db.create_case("Dupes", "examiner").await.unwrap();

        // Two copies of one file, one genuinely unique file, and two files
        // that were never hashed.
        let rows: Vec<(&str, Option<&str>)> = vec![
            ("copy-a.jpg", Some("aaaa1111")),
            ("copy-b.jpg", Some("aaaa1111")),
            ("only-one.jpg", Some("bbbb2222")),
            ("nohash-1.bin", None),
            ("nohash-2.bin", None),
        ];
        for (name, sha) in rows {
            let mut meta = json!({ "name": name, "path": format!("/{name}"), "size": 10 });
            if let Some(sha) = sha {
                meta["sha256"] = json!(sha);
            }
            let a = Artifact::new(case_id, ArtifactType::FileEntry, None, meta);
            db.record_artifact(&a).await.unwrap();
        }

        let list = |unique: UniqueFilter| {
            let db = &db;
            async move {
                db.list_file_entries(
                    case_id,
                    FileListScope::CaseWide,
                    &FileEntryFilters {
                        unique,
                        ..Default::default()
                    },
                    None,
                    None,
                    1,
                    50,
                    false,
                )
                .await
                .unwrap()
            }
        };

        // Off: every file, duplicates and unhashed included.
        let (all, all_total) = list(UniqueFilter::Off).await;
        assert_eq!(all_total, 5);
        assert_eq!(all.len(), 5);

        // OnlyUnique: the one file with a hash nothing else carries. NOT the
        // two copies, and NOT the unhashed pair — those are unknown.
        let (unique_rows, unique_total) = list(UniqueFilter::OnlyUnique).await;
        assert_eq!(unique_total, 1, "only the file shown to be one of a kind");
        assert_eq!(unique_rows[0].name.as_deref(), Some("only-one.jpg"));

        // Unassessable: exactly the files whose uniqueness cannot be decided.
        let (unassessed, unassessed_total) = list(UniqueFilter::Unassessable).await;
        assert_eq!(unassessed_total, 2, "the two files carrying no hash");
        let mut names: Vec<&str> = unassessed
            .iter()
            .filter_map(|r| r.name.as_deref())
            .collect();
        names.sort();
        assert_eq!(names, ["nohash-1.bin", "nohash-2.bin"]);

        // The three populations account for the whole scope with nothing
        // double-counted: 1 unique + 2 unassessed + 2 duplicate copies = 5.
        assert_eq!(unique_total + unassessed_total + 2, all_total);
    }

    #[tokio::test]
    async fn list_file_entries_name_filter_escapes_like_metacharacters() {
        // BUG-189: `report_final.docx` must not also match `reportXfinal.docx`.
        let db = test_db().await;
        let case_id = db.create_case("Files", "examiner").await.unwrap();

        for name in ["report_final.docx", "reportXfinal.docx", "notes.txt"] {
            let a = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": name, "path": format!("/{name}"), "size": 10 }),
            );
            db.record_artifact(&a).await.unwrap();
        }

        let by_name = |needle: &str| FileEntryFilters {
            name_contains: Some(needle.to_string()),
            ..Default::default()
        };

        let (rows, total) = db
            .list_file_entries(
                case_id,
                FileListScope::CaseWide,
                &by_name("report_final"),
                None,
                None,
                1,
                50,
                false,
            )
            .await
            .unwrap();
        assert_eq!(total, 1, "`_` must be matched literally");
        assert_eq!(rows[0].name.as_deref(), Some("report_final.docx"));

        // A bare `%` matches nothing rather than every file.
        let (_, total) = db
            .list_file_entries(
                case_id,
                FileListScope::CaseWide,
                &by_name("%"),
                None,
                None,
                1,
                50,
                false,
            )
            .await
            .unwrap();
        assert_eq!(total, 0, "`%` must not act as a wildcard");
    }

    #[tokio::test]
    async fn search_cases_escapes_like_metacharacters() {
        // BUG-189: case search over name/reference/examiner escapes too.
        let db = test_db().await;
        db.create_case("Op_Nightfall", "examiner").await.unwrap();
        db.create_case("OpXNightfall", "examiner").await.unwrap();

        let hits = db
            .search_cases(Some("Op_Nightfall"), None, None)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Op_Nightfall");

        let none = db.search_cases(Some("%"), None, None).await.unwrap();
        assert!(none.is_empty(), "`%` must not match every case");
    }

    #[test]
    fn parse_timestamp_accepts_i64_unix_seconds() {
        // A bare integer is whole-second UTC with no recoverable offset.
        assert_eq!(
            parse_timeline_timestamp(&json!(1234567890i64)),
            Some(ParsedTimestamp {
                secs: 1234567890,
                subsec_nanos: 0,
                offset_seconds: None,
            })
        );
        assert_eq!(
            parse_timeline_timestamp(&json!(0)),
            Some(ParsedTimestamp {
                secs: 0,
                subsec_nanos: 0,
                offset_seconds: None,
            })
        );
        assert_eq!(
            parse_timeline_timestamp(&json!(-86400)),
            Some(ParsedTimestamp {
                secs: -86400,
                subsec_nanos: 0,
                offset_seconds: None,
            })
        );
    }

    #[test]
    fn parse_timestamp_accepts_rfc3339_strings() {
        // Zulu: UTC instant, offset known to be 0.
        assert_eq!(
            parse_timeline_timestamp(&json!("2009-02-13T23:31:30Z")),
            Some(ParsedTimestamp {
                secs: 1234567890,
                subsec_nanos: 0,
                offset_seconds: Some(0),
            })
        );
        // Offset form: same UTC instant, but the +01:00 source offset is retained (D6).
        assert_eq!(
            parse_timeline_timestamp(&json!("2009-02-14T00:31:30+01:00")),
            Some(ParsedTimestamp {
                secs: 1234567890,
                subsec_nanos: 0,
                offset_seconds: Some(3600),
            })
        );
        // Fractional seconds are preserved to nanoseconds (D5).
        assert_eq!(
            parse_timeline_timestamp(&json!("2009-02-13T23:31:30.123456789Z")),
            Some(ParsedTimestamp {
                secs: 1234567890,
                subsec_nanos: 123456789,
                offset_seconds: Some(0),
            })
        );
    }

    #[test]
    fn parse_timestamp_rejects_garbage() {
        assert_eq!(parse_timeline_timestamp(&json!("not a timestamp")), None);
        assert_eq!(parse_timeline_timestamp(&json!("2009-13-45")), None);
        assert_eq!(parse_timeline_timestamp(&json!(null)), None);
        assert_eq!(parse_timeline_timestamp(&json!({"nested": true})), None);
    }

    // --- B2-088: chat rows keep the sub-second precision the parser recovered ---

    fn chat_artifact(metadata: serde_json::Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata)
    }

    #[test]
    fn chat_rows_take_sub_second_precision_from_date_ns() {
        // iMessage stores a nanosecond clock; `date` is only whole seconds. With
        // the nanoseconds dropped, every message inside one second collapsed to
        // the same instant and the unified timeline could order a reply before
        // the message it answered.
        let art = chat_artifact(json!({
            "subtype": "chat_message",
            "type": "iMessage",
            "date": 1_672_531_200i64,
            "date_ns": 1_672_531_200i64 * 1_000_000_000 + 123_456_789,
            "text": "later",
        }));
        let row = chat_timeline_row(&art, "{}").expect("a dated chat message is a timeline row");
        assert_eq!(row.3, 1_672_531_200, "whole seconds are unchanged");
        assert_eq!(row.4, 123_456_789, "nanoseconds must reach the timeline");
    }

    #[test]
    fn chat_rows_ignore_a_date_ns_that_contradicts_date() {
        // Disagreement means one of the two is wrong; picking either would
        // invent an ordering. Keep the seconds we were given, claim no
        // sub-second precision.
        let art = chat_artifact(json!({
            "subtype": "chat_message",
            "type": "iMessage",
            "date": 1_672_531_200i64,
            "date_ns": 999i64,
            "text": "mismatched",
        }));
        let row = chat_timeline_row(&art, "{}").expect("a dated chat message is a timeline row");
        assert_eq!(row.3, 1_672_531_200);
        assert_eq!(row.4, 0, "no invented sub-second component");
    }

    #[test]
    fn chat_rows_without_nanoseconds_are_unaffected() {
        let art = chat_artifact(json!({
            "subtype": "chat_message",
            "type": "WhatsApp",
            "date": 1_600_000_000i64,
            "text": "plain",
        }));
        let row = chat_timeline_row(&art, "{}").expect("a dated chat message is a timeline row");
        assert_eq!((row.3, row.4), (1_600_000_000, 0));
    }

    // --- B2-013 / B2-114: every parsed messaging platform can be threaded ---

    #[test]
    fn every_messaging_platform_the_tree_parses_has_a_thread_key() {
        // A platform with no thread key made conversation_summaries,
        // conversation_messages and search all return an EMPTY list: the
        // messages were in the case, but the Conversations view reported the
        // phone had no chats at all.
        // Derived from the comms list, not retyped, so a platform added there
        // without a thread key fails here. CallLog is a call register, not a chat.
        for record_type in COMMS_RECORD_TYPES.iter().filter(|t| **t != "CallLog") {
            assert!(
                SqliteConnection::thread_key_expr(record_type).is_some(),
                "{record_type} messages would fail every conversation query"
            );
        }
    }

    #[tokio::test]
    async fn conversation_queries_refuse_an_unthreadable_record_type() {
        let db = test_db().await;
        let case_id = db.create_case("Chats", "e").await.unwrap();
        let t = "PrefetchEntry";
        assert!(db.conversation_summaries(case_id, t).await.is_err());
        assert!(db.unthreadable_record_count(case_id, t).await.is_err());
        assert!(db
            .conversation_messages(case_id, t, "k", None, 10)
            .await
            .is_err());
        assert!(db
            .search_conversation_messages(case_id, t, "x", 10)
            .await
            .is_err());
    }

    #[test]
    fn a_non_messaging_record_type_has_no_thread_key() {
        assert!(SqliteConnection::thread_key_expr("PrefetchEntry").is_none());
        assert!(SqliteConnection::thread_key_expr("").is_none());
    }
}

// ---------------------------------------------------------------------------
// Incompleteness census, case-scoped processing log, sub-second ordering
// ---------------------------------------------------------------------------
#[cfg(test)]
mod completeness_tests {
    use super::*;
    use serde_json::json;

    async fn test_db() -> SqliteConnection {
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db
    }

    /// Record a ParsedRecord carrying the incompleteness pair, plus a timeline
    /// event for the same artifact id so it is attributable to a report section.
    async fn incomplete_record(
        db: &SqliteConnection,
        case_id: Uuid,
        module: &str,
        reason: Option<&str>,
    ) -> Uuid {
        let mut md = json!({
            "type": "TestRecord",
            "content_incomplete": true,
        });
        if let Some(r) = reason {
            md.as_object_mut()
                .unwrap()
                .insert("content_incomplete_reason".into(), json!(r));
        }
        let a = Artifact::new(case_id, ArtifactType::ParsedRecord, None, md);
        db.record_artifact(&a).await.unwrap();
        let ev = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000i64,
                "timestamp_desc": "Created",
                "source_module": module,
                "short_desc": "row",
                "full_details": "{}",
            }),
        );
        db.record_artifact(&ev).await.unwrap();
        // Point the timeline row at the incomplete artifact, which is what the
        // per-section attribution join follows.
        sqlx::query("UPDATE timeline_events SET artifact_id = ? WHERE artifact_id = ?")
            .bind(a.id)
            .bind(ev.id)
            .execute(&db.pool)
            .await
            .unwrap();
        a.id
    }

    /// The census is what makes 809 plugin-written stamps reach a reader. Before
    /// it existed nothing in the tree read `content_incomplete`, so a truncated
    /// result and a complete one were indistinguishable in the report.
    #[tokio::test]
    async fn census_counts_content_and_inventory_incompleteness() {
        let db = test_db().await;
        let case_id = db.create_case("Census", "e").await.unwrap();

        incomplete_record(&db, case_id, "registry", Some("hive exceeded 512 MiB cap")).await;
        incomplete_record(&db, case_id, "registry", Some("hive exceeded 512 MiB cap")).await;
        incomplete_record(&db, case_id, "evtx", Some("corrupt record at offset 4096")).await;

        // A complete artifact must not be counted.
        let ok = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "TestRecord", "content_incomplete": false}),
        );
        db.record_artifact(&ok).await.unwrap();

        // A short listing is a different axis and counted separately -- with
        // its OWN recorded reason key.
        let short = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({
                "name": "vol",
                "inventory_incomplete": true,
                "inventory_incomplete_reason": "archive structure could not be resolved",
            }),
        );
        db.record_artifact(&short).await.unwrap();

        let census = db.get_case_incompleteness(case_id).await.unwrap();
        assert!(census.any());
        assert_eq!(census.content_incomplete, 3);
        assert_eq!(census.inventory_incomplete, 1);
        assert_eq!(census.distinct_reasons, 2);
        assert_eq!(
            census.reasons[0],
            IncompleteReason {
                reason: Some("hive exceeded 512 MiB cap".into()),
                count: 2
            },
            "the most frequent reason must lead: {:?}",
            census.reasons
        );

        // Per-section attribution: each report section can state its own share.
        let registry = census.by_source_module.get("registry").unwrap();
        assert_eq!(registry.artifacts, 2);
        let evtx = census.by_source_module.get("evtx").unwrap();
        assert_eq!(evtx.artifacts, 1);
        assert_eq!(
            evtx.reasons[0].reason.as_deref(),
            Some("corrupt record at offset 4096")
        );

        // `inventory_incomplete_reason` is written at 43 sites across the
        // plugin tree. The first census read only the content reason, so a
        // short listing reached the report as a bare count and the reader could
        // not tell an unresolved container from a decode failure -- in the one
        // disclosure that exists to say a missing item may still be there.
        assert_eq!(census.distinct_inventory_reasons, 1);
        assert_eq!(
            census.inventory_reasons,
            vec![IncompleteReason {
                reason: Some("archive structure could not be resolved".into()),
                count: 1
            }],
            "the recorded reason for a short listing must survive the census"
        );
        // The two axes must not be merged: a content reason must never be
        // offered as the explanation for a short listing.
        assert!(census
            .inventory_reasons
            .iter()
            .all(|r| r.reason.as_deref() != Some("hive exceeded 512 MiB cap")));
    }

    /// B4-034: the per-section attribution joined only `content_incomplete`, so
    /// a report section built entirely from SHORT LISTINGS printed
    /// "0 incomplete records" while the case-level census counted every one of
    /// them. The section is where an examiner reads the evidence; that is where
    /// it has to say the listing is short.
    #[tokio::test]
    async fn per_section_attribution_covers_short_listings_too() {
        let db = test_db().await;
        let case_id = db.create_case("SectionCensus", "e").await.unwrap();

        // A record from the `archive` module whose LISTING is short, attributed
        // to a report section through its timeline event.
        let a = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({
                "name": "backup.zip",
                "inventory_incomplete": true,
                "inventory_incomplete_reason": "central directory ended early",
            }),
        );
        db.record_artifact(&a).await.unwrap();
        let ev = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000i64,
                "timestamp_desc": "Created",
                "source_module": "archive",
                "short_desc": "entry",
                "full_details": "{}",
            }),
        );
        db.record_artifact(&ev).await.unwrap();
        sqlx::query("UPDATE timeline_events SET artifact_id = ? WHERE artifact_id = ?")
            .bind(a.id)
            .bind(ev.id)
            .execute(&db.pool)
            .await
            .unwrap();

        let census = db.get_case_incompleteness(case_id).await.unwrap();
        let archive = census
            .by_source_module
            .get("archive")
            .expect("a short listing must be attributable to its report section");
        assert_eq!(
            archive.artifacts, 1,
            "a section whose only artifact carries a short listing must not report zero"
        );
        assert!(
            archive
                .reasons
                .iter()
                .any(|r| r.reason.as_deref() == Some("inventory: central directory ended early")),
            "the listing reason must reach the section, labelled as a listing: {:?}",
            archive.reasons
        );
    }

    /// An artifact marked on BOTH axes is one incomplete record in its section,
    /// not two.
    #[tokio::test]
    async fn an_artifact_incomplete_on_both_axes_is_counted_once_per_section() {
        let db = test_db().await;
        let case_id = db.create_case("BothAxes", "e").await.unwrap();

        let a = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({
                "name": "vol",
                "content_incomplete": true,
                "content_incomplete_reason": "short_read",
                "inventory_incomplete": true,
                "inventory_incomplete_reason": "walk stopped",
            }),
        );
        db.record_artifact(&a).await.unwrap();
        let ev = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000i64,
                "timestamp_desc": "Created",
                "source_module": "fs",
                "short_desc": "vol",
                "full_details": "{}",
            }),
        );
        db.record_artifact(&ev).await.unwrap();
        sqlx::query("UPDATE timeline_events SET artifact_id = ? WHERE artifact_id = ?")
            .bind(a.id)
            .bind(ev.id)
            .execute(&db.pool)
            .await
            .unwrap();

        let census = db.get_case_incompleteness(case_id).await.unwrap();
        let fs = census.by_source_module.get("fs").expect("section present");
        assert_eq!(fs.artifacts, 1, "one artifact is one incomplete record");
        assert_eq!(fs.reasons.len(), 2, "but both reasons are disclosed");
    }

    /// The report's File Overview printed "not determined" for carved files on
    /// every case, on the stated grounds that the case store could not answer
    /// it. It can: `seance_plugin_carver` writes `metadata.carved = true` and
    /// nothing else writes that key. Telling a court "not determined" about a
    /// figure the store holds is the same defect as telling it nothing at all.
    #[tokio::test]
    async fn carved_files_are_counted_not_reported_as_undetermined() {
        let db = test_db().await;
        let case_id = db.create_case("Carved", "e").await.unwrap();
        for name in ["carved_00000000.jpg", "carved_00001000.png"] {
            db.record_artifact(&Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({"name": name, "carved": true}),
            ))
            .await
            .unwrap();
        }
        // A file read from a filesystem record is not carved and must not be
        // counted: an inflated recovery figure is as impeachable as a missing one.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "notes.txt"}),
        ))
        .await
        .unwrap();

        // A non-file artifact carrying the same key is NOT a carved file. The
        // figure is printed against `FileOverview::total_files`, which counts
        // FileEntry rows only, so counting this would put a row in the numerator
        // that the denominator excludes.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"name": "carving summary", "carved": true}),
        ))
        .await
        .unwrap();

        assert_eq!(db.count_carved_files(case_id).await.unwrap(), 2);

        // Stated as the invariant it exists to protect: the numerator can never
        // exceed the denominator the report prints beside it.
        let (_rows, total_files) = db
            .list_file_entries(
                case_id,
                FileListScope::CaseWide,
                &FileEntryFilters::default(),
                None,
                None,
                1,
                1,
                false,
            )
            .await
            .unwrap();
        assert!(
            db.count_carved_files(case_id).await.unwrap() <= total_files,
            "carved files cannot outnumber the files they are counted against"
        );

        // A case with no carving reports a real zero, from a real count.
        let other = db.create_case("NoCarving", "e").await.unwrap();
        assert_eq!(db.count_carved_files(other).await.unwrap(), 0);
    }

    /// The encrypted-file figure has to reconcile two independent conventions:
    /// `encrypted` on the file itself (filesystem readers) and `is_encrypted` on
    /// a separate assessment record (file-analysis, iOS backup). This pins the
    /// three ways a naive query gets it wrong:
    ///
    /// * counting the assessment records directly double-counts a file that a
    ///   filesystem already flagged AND content analysis then fingerprinted;
    /// * counting only `encrypted` returns 0 for a raw-image case, where no
    ///   filesystem reader ever sets the flag and every finding is a detection;
    /// * testing for the PRESENCE of `encrypted` counts APFS's explicit
    ///   `"encrypted": false`, which says the opposite.
    ///
    /// And a fourth: counting a marker that is not on a file at all. The figure
    /// is printed beside `FileOverview::total_files`, which counts FileEntry
    /// rows only, so every branch has to land on a FileEntry of this case or the
    /// report can print more encrypted files than files.
    #[tokio::test]
    async fn encrypted_files_are_counted_once_per_file() {
        let db = test_db().await;
        let case_id = db.create_case("Encrypted", "e").await.unwrap();

        // A: flagged by the filesystem reader.
        let a = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "vault.dmg", "encrypted": true}),
        );
        db.record_artifact(&a).await.unwrap();

        // ...and ALSO fingerprinted by content analysis. Still one file.
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "analysis_type": "encryption_detection",
                    "encryption_type": "FileVault 2",
                    "is_encrypted": true,
                }),
            )
            .with_parent(a.id),
        )
        .await
        .unwrap();

        // B: no filesystem flag at all; known encrypted only by detection.
        let b = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "secrets.zip"}),
        );
        db.record_artifact(&b).await.unwrap();
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "analysis_type": "encryption_detection",
                    "encryption_type": "Encrypted ZIP",
                    "is_encrypted": true,
                }),
            )
            .with_parent(b.id),
        )
        .await
        .unwrap();

        // C: APFS writes an explicit false. Not encrypted.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "notes.txt", "encrypted": false}),
        ))
        .await
        .unwrap();

        // D: an iOS backup directory holding an encrypted backup the reader
        // could not open. The `is_encrypted` record is ABOUT ITSELF, not about
        // its parent directory, and it is a ParsedRecord, not a file: it is one
        // encrypted OBJECT but not one encrypted FILE, so it is not counted into
        // a figure whose denominator is the file count. It still reaches the
        // examiner through the incompleteness census, which is what the pair it
        // carries is for. Neither is the directory counted: nothing says the
        // directory itself is encrypted.
        let d = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "Backup"}),
        );
        db.record_artifact(&d).await.unwrap();
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "IosBackupInfo",
                    "subtype": "ios_backup_incomplete",
                    "is_encrypted": true,
                    "content_incomplete": true,
                    "content_incomplete_reason": "encrypted",
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": "encrypted",
                }),
            )
            .with_parent(d.id),
        )
        .await
        .unwrap();

        // E: a detection whose subject is not a file entry -- here a ParsedRecord
        // produced by another parser. Folding it onto that parent would put a
        // non-file in the numerator, so it is excluded.
        let e = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"name": "registry value"}),
        );
        db.record_artifact(&e).await.unwrap();
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "analysis_type": "encryption_detection",
                    "encryption_type": "Unknown",
                    "is_encrypted": true,
                }),
            )
            .with_parent(e.id),
        )
        .await
        .unwrap();

        // F: a parentless detection. There is no file to attribute it to, so it
        // cannot be counted as one; guessing a subject would be worse than the
        // shortfall.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "analysis_type": "encryption_detection",
                "encryption_type": "Unknown",
                "is_encrypted": true,
            }),
        ))
        .await
        .unwrap();

        // A and B, each once. Not C (explicitly not encrypted), not D (the
        // record is not a file and the directory is not marked), not E (the
        // subject is not a file), not F (there is no subject).
        assert_eq!(db.count_encrypted_files(case_id).await.unwrap(), 2);

        // The invariant behind the artifact_type filter, stated: the encrypted
        // count is a subset of the file count the report prints beside it. The
        // case holds four FileEntry rows (A, B, C, D) and four non-file markers.
        let (_rows, total_files) = db
            .list_file_entries(
                case_id,
                FileListScope::CaseWide,
                &FileEntryFilters::default(),
                None,
                None,
                1,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(total_files, 4, "the denominator counts file entries only");
        assert!(
            db.count_encrypted_files(case_id).await.unwrap() <= total_files,
            "encrypted files cannot outnumber the files they are counted against"
        );

        // A case with nothing encrypted reports a real zero, from a real count.
        let other = db.create_case("NoEncryption", "e").await.unwrap();
        assert_eq!(db.count_encrypted_files(other).await.unwrap(), 0);
    }

    /// Is this the artifact type that `FileOverview::total_files` counts?
    ///
    /// Exhaustive on purpose: adding a variant to [`ArtifactType`] stops this
    /// compiling until someone decides which side of the file denominator it
    /// falls on, so a new type cannot quietly escape the sweep below.
    fn is_the_file_overview_denominator(t: &ArtifactType) -> bool {
        match t {
            ArtifactType::FileEntry => true,
            ArtifactType::Container
            | ArtifactType::RawEvidence
            | ArtifactType::Partition
            | ArtifactType::FileSystem
            | ArtifactType::FileContent
            | ArtifactType::SystemArtifact
            | ArtifactType::ParsedRecord
            | ArtifactType::TimelineEvent
            | ArtifactType::UnallocatedSpace
            | ArtifactType::SlackSpace => false,
        }
    }

    const EVERY_ARTIFACT_TYPE: [ArtifactType; 11] = [
        ArtifactType::Container,
        ArtifactType::RawEvidence,
        ArtifactType::Partition,
        ArtifactType::FileSystem,
        ArtifactType::FileEntry,
        ArtifactType::FileContent,
        ArtifactType::SystemArtifact,
        ArtifactType::ParsedRecord,
        ArtifactType::TimelineEvent,
        ArtifactType::UnallocatedSpace,
        ArtifactType::SlackSpace,
    ];

    /// The class, not the two instances that were found.
    ///
    /// Every figure the File Overview prints is a fraction of
    /// `FileOverview::total_files`, and that denominator is a `FileEntry`-only
    /// count (`list_file_entries` scopes every query to
    /// `artifact_type = 'FileEntry'`). So every numerator beside it must be
    /// scoped the same way, for EVERY artifact type that could come to carry
    /// its marker keys — not merely for the `ParsedRecord` that happened to be
    /// the observed case. `count_carved_files` and `count_encrypted_files` both
    /// tested only the metadata key, so a carving summary or an encryption
    /// assessment landed in a numerator whose denominator excluded it and the
    /// report could print "3 of 2 files encrypted", which is not a figure that
    /// survives cross-examination.
    ///
    /// This stamps every marker key on one artifact of every non-file type at
    /// once, so a count that forgets the scope for any of them fails here.
    #[tokio::test]
    async fn file_scoped_counts_stay_inside_the_file_count_for_every_artifact_type() {
        let db = test_db().await;
        let case_id = db.create_case("Denominator", "e").await.unwrap();

        // The one real file, legitimately both carved and encrypted. Both
        // numerators must be exactly 1: a scope that excluded too much would
        // pass a "<= total" assertion by under-counting.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "carved_00000000.jpg", "carved": true, "encrypted": true}),
        ))
        .await
        .unwrap();

        for artifact_type in EVERY_ARTIFACT_TYPE {
            if is_the_file_overview_denominator(&artifact_type) {
                continue;
            }
            // Every marker key the file-scoped counts read, on one artifact of
            // a type the denominator does not count.
            let marked = Artifact::new(
                case_id,
                artifact_type.clone(),
                None,
                json!({
                    "name": format!("{artifact_type:?} summary"),
                    "carved": true,
                    "encrypted": true,
                    "is_encrypted": true,
                    // A TimelineEvent is refused outright without a parseable
                    // timestamp, which is correct — an event with no time is
                    // not an event. The marker keys above are what this test is
                    // about; these three are the price of writing one artifact
                    // of EVERY type, and they are inert on the others.
                    "timestamp": 1_700_000_000_i64,
                    "timestamp_desc": "Created",
                    "source_module": "completeness_test",
                }),
            );
            db.record_artifact(&marked).await.unwrap();

            // And the other convention: an assessment record whose SUBJECT is
            // that non-file artifact. Folding it onto its parent must not put
            // the parent in the numerator either.
            db.record_artifact(
                &Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "analysis_type": "encryption_detection",
                        "encryption_type": "Unknown",
                        "is_encrypted": true,
                    }),
                )
                .with_parent(marked.id),
            )
            .await
            .unwrap();
        }

        let (_rows, total_files) = db
            .list_file_entries(
                case_id,
                FileListScope::CaseWide,
                &FileEntryFilters::default(),
                None,
                None,
                1,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(total_files, 1, "one file entry is the whole denominator");

        let carved = db.count_carved_files(case_id).await.unwrap();
        let encrypted = db.count_encrypted_files(case_id).await.unwrap();
        for (label, counted) in [("carved", carved), ("encrypted", encrypted)] {
            assert_eq!(
                counted, 1,
                "{label}: the one real file must be counted, and nothing else"
            );
            assert!(
                counted <= total_files,
                "{label}: {counted} of {total_files} files is not a defensible figure"
            );
        }
    }

    /// `get_processing_log_for_case` must be reachable through
    /// `DatabaseConnection`, not only on the concrete SQLite type: tool
    /// provenance is part of what a case store owes the court, so the interface
    /// has to require it. Before it moved onto the trait this call did not
    /// resolve on a trait object at all.
    ///
    /// The default trait body deliberately returns `Err`, never an empty log —
    /// an empty tool-provenance section reads as "no module ran", which is a
    /// claim about the evidence. This asserts the SQLite backend overrides it
    /// with the real aggregation rather than inheriting the refusal.
    #[tokio::test]
    async fn processing_log_for_case_is_reachable_through_the_trait() {
        let db = test_db().await;
        let case_id = db.create_case("Trait", "e").await.unwrap();
        let a = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
        db.record_artifact(&a).await.unwrap();
        db.record_processing_log(case_id, a.id, "mod_a", "completed", 3, None, 12)
            .await
            .unwrap();

        let conn: &dyn DatabaseConnection = &db;
        let (groups, total) = conn
            .get_processing_log_for_case(case_id, 100)
            .await
            .expect("the SQLite backend must aggregate, not inherit the refusing default");
        assert_eq!(total, 1);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].module_id, "mod_a");
        assert_eq!(groups[0].artifacts_produced, 3);
    }

    /// A flag set with no reason must survive the census as an unexplained
    /// shortfall. Dropping it would let a report show "0 incomplete" reasons
    /// beside a non-zero count.
    #[tokio::test]
    async fn incompleteness_without_a_reason_is_still_reported() {
        let db = test_db().await;
        let case_id = db.create_case("NoReason", "e").await.unwrap();
        incomplete_record(&db, case_id, "carver", None).await;

        let census = db.get_case_incompleteness(case_id).await.unwrap();
        assert_eq!(census.content_incomplete, 1);
        assert_eq!(census.reasons.len(), 1);
        assert_eq!(census.reasons[0].reason, None);
        assert_eq!(census.reasons[0].count, 1);
    }

    /// A clean case must report a clean census, never a false alarm.
    #[tokio::test]
    async fn a_complete_case_reports_no_incompleteness() {
        let db = test_db().await;
        let case_id = db.create_case("Clean", "e").await.unwrap();
        let a = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "TestRecord"}),
        );
        db.record_artifact(&a).await.unwrap();

        let census = db.get_case_incompleteness(case_id).await.unwrap();
        assert!(!census.any());
        assert!(census.reasons.is_empty());
        assert_eq!(census.distinct_reasons, 0);
        // Neither axis may invent a shortfall. A completeness notice that fires
        // on an ordinary case trains an examiner to ignore it.
        assert!(census.inventory_reasons.is_empty());
        assert_eq!(census.distinct_inventory_reasons, 0);
    }

    /// B3-063. The report's Processing Log section was hard-coded empty because
    /// only a per-artifact accessor existed, and listing one artifact's subset
    /// would show a fraction of the tool provenance as the whole. The
    /// case-scoped accessor aggregates instead, so the section is complete.
    #[tokio::test]
    async fn case_processing_log_aggregates_every_run_of_a_module() {
        let db = test_db().await;
        let case_id = db.create_case("Provenance", "e").await.unwrap();
        let a = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
        db.record_artifact(&a).await.unwrap();
        let b = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "g"}));
        db.record_artifact(&b).await.unwrap();

        db.record_processing_log(case_id, a.id, "plugin.mft", "complete", 400, None, 10)
            .await
            .unwrap();
        db.record_processing_log(case_id, b.id, "plugin.mft", "complete", 600, None, 20)
            .await
            .unwrap();
        db.record_processing_log(
            case_id,
            b.id,
            "plugin.evtx",
            "failed",
            0,
            Some("short read"),
            5,
        )
        .await
        .unwrap();

        let (groups, total) = db.get_processing_log_for_case(case_id, 100).await.unwrap();
        assert_eq!(total, 2, "two (module, status) groups exist");
        assert_eq!(groups.len(), 2);
        let mft = groups.iter().find(|g| g.module_id == "plugin.mft").unwrap();
        assert_eq!(mft.runs, 2);
        assert_eq!(
            mft.artifacts_produced, 1000,
            "the section must state every artifact the module produced, not one run's"
        );
        assert_eq!(mft.duration_ms, Some(30));
        let evtx = groups
            .iter()
            .find(|g| g.module_id == "plugin.evtx")
            .unwrap();
        assert_eq!(evtx.status, "failed");
        assert_eq!(evtx.error_count, 1);
        assert_eq!(evtx.error_message.as_deref(), Some("short read"));
    }

    /// A capped group listing must report the true group count so the caller
    /// can disclose the shortfall rather than present a subset as the whole.
    #[tokio::test]
    async fn capped_processing_log_reports_the_true_group_count() {
        let db = test_db().await;
        let case_id = db.create_case("Capped", "e").await.unwrap();
        let a = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "f"}));
        db.record_artifact(&a).await.unwrap();
        for i in 0..5 {
            db.record_processing_log(
                case_id,
                a.id,
                &format!("plugin.m{i}"),
                "complete",
                1,
                None,
                1,
            )
            .await
            .unwrap();
        }
        let (groups, total) = db.get_processing_log_for_case(case_id, 2).await.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(total, 5);
    }

    fn subsec_event(case_id: Uuid, rfc3339: &str, desc: &str) -> Artifact {
        Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": rfc3339,
                "timestamp_desc": "Created",
                "source_module": "evtx",
                "short_desc": desc,
                "full_details": "{}",
            }),
        )
    }

    /// B3-082. EVTX writes real nanoseconds, but every timeline query sorted by
    /// whole seconds and then artifact id, so same-second events were presented
    /// in an arbitrary order. Within one second that ordering IS the intrusion
    /// sequence.
    #[tokio::test]
    async fn same_second_events_order_by_sub_second_not_by_id() {
        let db = test_db().await;
        let case_id = db.create_case("Subsec", "e").await.unwrap();

        // Insert oldest-sub-second FIRST so a stable id tiebreak would put it
        // first in a DESC listing -- the exact wrong answer.
        for (ts, desc) in [
            ("2026-07-01T00:00:00.100000000Z", "first"),
            ("2026-07-01T00:00:00.500000000Z", "second"),
            ("2026-07-01T00:00:00.900000000Z", "third"),
        ] {
            db.record_artifact(&subsec_event(case_id, ts, desc))
                .await
                .unwrap();
        }

        let newest_first = db
            .get_timeline_events(case_id, Some(10), Some(0))
            .await
            .unwrap();
        let order: Vec<&str> = newest_first.iter().map(|e| e.short_desc.as_str()).collect();
        assert_eq!(
            order,
            vec!["third", "second", "first"],
            "same-second events must be presented in sub-second order"
        );

        // The filtered/paginated path the UI and the report use must agree.
        let asc = db
            .get_timeline_events_filtered(
                case_id,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(10),
                Some(0),
                Some("timestamp"),
                Some("asc"),
                None,
                None,
            )
            .await
            .unwrap();
        let asc_order: Vec<&str> = asc.iter().map(|e| e.short_desc.as_str()).collect();
        assert_eq!(asc_order, vec!["first", "second", "third"]);
    }

    /// Events written before the sub-second column existed hold 0. They must
    /// land at the top of their second, beside any other 0-nanosecond event,
    /// rather than being flung to an arbitrary extreme of the listing.
    #[tokio::test]
    async fn zero_sub_second_events_sort_at_the_top_of_their_second() {
        let db = test_db().await;
        let case_id = db.create_case("Legacy", "e").await.unwrap();
        db.record_artifact(&subsec_event(
            case_id,
            "2026-07-01T00:00:00.750000000Z",
            "late_in_second",
        ))
        .await
        .unwrap();
        // A bare integer timestamp carries no fraction: subsec 0.
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_782_864_000i64, // 2026-07-01T00:00:00Z
                "timestamp_desc": "Created",
                "source_module": "legacy",
                "short_desc": "legacy_row",
                "full_details": "{}",
            }),
        ))
        .await
        .unwrap();
        db.record_artifact(&subsec_event(
            case_id,
            "2026-07-01T00:00:01.000000000Z",
            "next_second",
        ))
        .await
        .unwrap();

        let events = db
            .get_timeline_events(case_id, Some(10), Some(0))
            .await
            .unwrap();
        let order: Vec<&str> = events.iter().map(|e| e.short_desc.as_str()).collect();
        assert_eq!(
            order,
            vec!["next_second", "late_in_second", "legacy_row"],
            "a 0-nanosecond row belongs at the start of its second, not outside it"
        );
    }
}

// ---------------------------------------------------------------------------
// Bookmark custody: a repeat create must not rewrite provenance
// ---------------------------------------------------------------------------
#[cfg(test)]
mod bookmark_custody_tests {
    use super::*;
    use seance_core::artifact::{Artifact, ArtifactType};
    use serde_json::json;

    async fn test_db() -> SqliteConnection {
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db
    }

    /// B6-029: `INSERT OR REPLACE` on `UNIQUE(case_id, artifact_id)` deletes the
    /// existing row and inserts a new one. A second create therefore minted a
    /// new bookmark id, reset `created_at` to now, and overwrote the examiner —
    /// so "when was this first bookmarked, and by whom?" silently became "just
    /// now, by whoever clicked last", and any export citing the old id stopped
    /// resolving.
    #[tokio::test]
    async fn a_repeat_bookmark_keeps_its_id_creation_time_and_examiner() {
        let db = test_db().await;
        let case_id = db.create_case("Bookmarks", "e").await.unwrap();
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "evidence.jpg" }),
        );
        db.record_artifact(&art).await.unwrap();

        let first = db
            .create_artifact_bookmark(case_id, art.id, None, Some("first look"), Some("alice"))
            .await
            .unwrap();
        let original = db
            .get_artifact_bookmark(case_id, art.id)
            .await
            .unwrap()
            .expect("bookmark exists");

        // Second create with a different note and a different examiner.
        let second = db
            .create_artifact_bookmark(case_id, art.id, None, Some("second look"), Some("bob"))
            .await
            .unwrap();

        assert_eq!(
            first, second,
            "the bookmark id must be stable so exports and citations keep resolving"
        );

        let after = db
            .get_artifact_bookmark(case_id, art.id)
            .await
            .unwrap()
            .expect("bookmark still exists");
        assert_eq!(after.id, original.id);
        assert_eq!(
            after.created_at, original.created_at,
            "'when was this first bookmarked' must not be rewritten"
        );
        assert_eq!(
            after.examiner.as_deref(),
            Some("alice"),
            "the examiner who first bookmarked it must survive a later create"
        );
        assert_eq!(
            after.note.as_deref(),
            Some("second look"),
            "the mutable note is what a repeat create updates"
        );
        assert!(
            after.updated_at >= original.updated_at,
            "updated_at must move forward"
        );

        // Exactly one row: the unique constraint is still honoured.
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_bookmarks WHERE case_id = ? AND artifact_id = ?",
        )
        .bind(case_id)
        .bind(art.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(n, 1);
    }

    /// A create that supplies no note must not erase the examiner's finding.
    #[tokio::test]
    async fn a_repeat_bookmark_without_a_note_leaves_the_existing_one_alone() {
        let db = test_db().await;
        let case_id = db.create_case("Bookmarks", "e").await.unwrap();
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "evidence.jpg" }),
        );
        db.record_artifact(&art).await.unwrap();

        db.create_artifact_bookmark(case_id, art.id, None, Some("contraband"), Some("alice"))
            .await
            .unwrap();
        db.create_artifact_bookmark(case_id, art.id, None, None, Some("alice"))
            .await
            .unwrap();

        let after = db
            .get_artifact_bookmark(case_id, art.id)
            .await
            .unwrap()
            .expect("bookmark exists");
        assert_eq!(after.note.as_deref(), Some("contraband"));
    }
}

// ---------------------------------------------------------------------------
// Bounded answers and total cursors
//
// Every test here fails against the code as it was: each one covers a query
// that returned less than the evidence held while looking like it had returned
// all of it.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod bounded_answer_tests {
    use super::*;
    use serde_json::json;

    async fn test_db() -> SqliteConnection {
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db
    }

    /// A WhatsApp message in `thread`. `date` of `None` is an undated recovered
    /// body — the shape that collapses every such row onto one ordering value.
    fn message(case_id: Uuid, thread: &str, text: &str, date: Option<i64>) -> Artifact {
        let mut meta = json!({
            "type": "WhatsApp",
            "contact_jid": thread,
            "text": text,
        });
        if let Some(d) = date {
            meta["date"] = json!(d);
        }
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta)
    }

    /// Walk the whole thread the way a scrollback client does, one page at a
    /// time, and return the ids in the order they were served.
    async fn walk_thread(db: &SqliteConnection, case_id: Uuid, page: u32) -> Vec<Uuid> {
        let mut seen: Vec<Uuid> = Vec::new();
        let mut cursor: Option<ConversationCursor> = None;
        for _ in 0..100 {
            let p = db
                .conversation_messages(case_id, "WhatsApp", "alice", cursor, page)
                .await
                .unwrap();
            seen.extend(p.records.iter().map(|r| r.id));
            if !p.has_more {
                return seen;
            }
            cursor = p.next_cursor;
            assert!(cursor.is_some(), "has_more with no cursor strands the rest");
        }
        panic!("scrollback did not terminate");
    }

    #[tokio::test]
    async fn scrollback_reaches_undated_messages_past_the_first_page() {
        let db = test_db().await;
        let case_id = db.create_case("Chat", "e").await.unwrap();

        // Recovered bodies with no date and no recovery_index: every one of
        // them orders at the same sentinel. An ord-only cursor asked for
        // "older than the sentinel" and never saw the rest of them again.
        let mut ids = Vec::new();
        for i in 0..5 {
            let m = message(case_id, "alice", &format!("carved {i}"), None);
            ids.push(m.id);
            db.record_artifact(&m).await.unwrap();
        }

        let seen = walk_thread(&db, case_id, 2).await;
        assert_eq!(
            seen.len(),
            5,
            "every undated message must be reachable by paging"
        );
        let unique: std::collections::HashSet<Uuid> = seen.iter().copied().collect();
        assert_eq!(unique.len(), 5, "no message may be served twice");
        for id in ids {
            assert!(
                unique.contains(&id),
                "message {id} was skipped by the cursor"
            );
        }
    }

    #[tokio::test]
    async fn scrollback_reaches_messages_sharing_one_second() {
        let db = test_db().await;
        let case_id = db.create_case("Chat", "e").await.unwrap();

        // An SMS/group-chat burst: four messages stamped the same second, then
        // one older. A page boundary inside the burst used to drop its tail.
        let mut ids = Vec::new();
        for i in 0..4 {
            let m = message(case_id, "alice", &format!("burst {i}"), Some(1_700_000_000));
            ids.push(m.id);
            db.record_artifact(&m).await.unwrap();
        }
        let older = message(case_id, "alice", "earlier", Some(1_699_999_000));
        ids.push(older.id);
        db.record_artifact(&older).await.unwrap();

        let seen = walk_thread(&db, case_id, 2).await;
        let unique: std::collections::HashSet<Uuid> = seen.iter().copied().collect();
        assert_eq!(unique.len(), 5, "same-second messages must not be skipped");
        for id in ids {
            assert!(
                unique.contains(&id),
                "message {id} was skipped by the cursor"
            );
        }
    }

    /// Give `id` a blob that is not a UUID, so decoding the row fails.
    async fn corrupt_artifact_id(db: &SqliteConnection, id: Uuid) {
        sqlx::query("UPDATE artifacts SET id = X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' WHERE id = ?")
            .bind(id)
            .execute(&db.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_undecodable_message_row_does_not_end_the_thread() {
        let db = test_db().await;
        let case_id = db.create_case("Chat", "e").await.unwrap();

        for i in 0..3 {
            let m = message(case_id, "alice", &format!("m{i}"), None);
            db.record_artifact(&m).await.unwrap();
            if i == 0 {
                corrupt_artifact_id(&db, m.id).await;
            }
        }

        // The corrupted id sorts first, so it lands on page one.
        let page = db
            .conversation_messages(case_id, "WhatsApp", "alice", None, 2)
            .await
            .unwrap();
        assert_eq!(page.undecodable, 1, "the dropped row must be counted");
        assert_eq!(
            page.records.len(),
            1,
            "the page is short by the dropped row"
        );
        assert!(
            page.has_more,
            "a page shortened by a decode failure must not read as end-of-thread"
        );
        assert!(page.next_cursor.is_some());

        // And the rest of the thread is still reachable.
        let seen = walk_thread(&db, case_id, 2).await;
        assert_eq!(seen.len(), 2, "both decodable messages must be served");
    }

    #[tokio::test]
    async fn attachment_fetch_reports_rows_it_could_not_decode() {
        let db = test_db().await;
        let case_id = db.create_case("Chat", "e").await.unwrap();

        for i in 0..2 {
            let a = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "iMessageAttachment",
                    "message_rowid": 7,
                    "filename": format!("IMG_000{i}.JPG"),
                }),
            );
            db.record_artifact(&a).await.unwrap();
            if i == 0 {
                corrupt_artifact_id(&db, a.id).await;
            }
        }

        let fetch = db
            .attachments_for_messages(case_id, "iMessageAttachment", &[7], &[])
            .await
            .unwrap();
        assert_eq!(fetch.items.len(), 1);
        assert!(!fetch.truncated, "the cap did not bite");
        assert_eq!(
            fetch.undecodable, 1,
            "a media row that vanished must be counted, not read as 'no media'"
        );
    }

    /// Bulk-insert `n` TimelineEvent artifacts under `parent`, each with a
    /// timeline row at `base_ts + row`. Raw SQL: the point of these tests is
    /// volume, and going through the artifact writer for thousands of rows
    /// would make them slow without testing anything more.
    async fn bulk_timeline_events(
        db: &SqliteConnection,
        case_id: Uuid,
        parent: Option<Uuid>,
        n: i64,
        base_ts: i64,
    ) {
        sqlx::query(
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?) \
             INSERT INTO artifacts (id, case_id, parent_id, artifact_type, metadata_json, created_at) \
             SELECT randomblob(16), ?, ?, 'TimelineEvent', '{}', '2026-01-01T00:00:00Z' FROM seq",
        )
        .bind(n)
        .bind(case_id)
        .bind(parent.map(|p| p.as_bytes().to_vec()))
        .execute(&db.pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO timeline_events (id, case_id, artifact_id, timestamp, \
                 timestamp_subsec_nanos, source_utc_offset_seconds, timestamp_desc, \
                 source_module, short_desc, full_details) \
             SELECT a.id, a.case_id, a.id, ? + a.rowid, 0, NULL, 'Created', 'bulk', 'bulk', '{}' \
             FROM artifacts a \
             WHERE a.case_id = ? AND a.artifact_type = 'TimelineEvent' \
               AND a.id NOT IN (SELECT artifact_id FROM timeline_events WHERE case_id = ?)",
        )
        .bind(base_ts)
        .bind(case_id)
        .bind(case_id)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn related_events_stay_bounded_and_keep_the_artifacts_own_history() {
        let db = test_db().await;
        let case_id = db.create_case("Volume", "e").await.unwrap();

        // A directory holding one file of interest and a great many others.
        let parent = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({ "name": "vol" }),
        );
        db.record_artifact(&parent).await.unwrap();

        // The artifact the examiner asked about: an OLD event, so a single
        // newest-first query capped at N would push it out entirely.
        let target = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_000,
                "timestamp_desc": "Created",
                "source_module": "test",
                "short_desc": "the file of interest",
                "full_details": "{}",
            }),
        )
        .with_parent(parent.id);
        db.record_artifact(&target).await.unwrap();

        // Every other file on the volume, all newer than the target.
        bulk_timeline_events(
            &db,
            case_id,
            Some(parent.id),
            RELATED_TIMELINE_CAP as i64 + 1,
            5_000_000,
        )
        .await;

        let page = db
            .get_related_timeline_events(case_id, target.id)
            .await
            .unwrap();

        assert_eq!(
            page.events.len(),
            RELATED_TIMELINE_CAP,
            "the sibling tree must not be loaded unbounded"
        );
        assert!(page.truncated, "a bounded answer must say it is bounded");
        assert_eq!(page.cap, RELATED_TIMELINE_CAP);
        assert!(
            page.events.iter().any(|e| e.artifact_id == target.id),
            "the artifact's own event must never be crowded out by its siblings"
        );
        // Still chronological, newest first.
        let mut sorted = page.events.clone();
        sorted.sort_by_key(|row| std::cmp::Reverse(row.timestamp));
        assert_eq!(
            sorted.first().map(|e| e.timestamp),
            page.events.first().map(|e| e.timestamp)
        );
    }

    #[tokio::test]
    async fn related_events_say_truncated_when_the_core_half_fills_the_cap() {
        let db = test_db().await;
        let case_id = db.create_case("Container", "e").await.unwrap();

        let parent = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({ "name": "vol" }),
        );
        db.record_artifact(&parent).await.unwrap();

        // A container whose OWN history — its children — is exactly the cap.
        // No `timestamp` in its metadata, so it carries no event itself.
        let target = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "archive.zip" }),
        )
        .with_parent(parent.id);
        db.record_artifact(&target).await.unwrap();
        bulk_timeline_events(
            &db,
            case_id,
            Some(target.id),
            RELATED_TIMELINE_CAP as i64,
            5_000_000,
        )
        .await;

        // One sibling, with an event of its own, that the answer has no room
        // for. Skipping the sibling query when the budget was spent reported
        // this as a complete relation.
        bulk_timeline_events(&db, case_id, Some(parent.id), 1, 6_000_000).await;

        let page = db
            .get_related_timeline_events(case_id, target.id)
            .await
            .unwrap();

        assert_eq!(page.events.len(), RELATED_TIMELINE_CAP);
        assert!(
            page.truncated,
            "sibling events exist and none of them are in this answer; reporting it as \
             complete tells the examiner nothing else happened around this artifact"
        );
    }

    #[tokio::test]
    async fn filter_apply_counts_rows_it_could_not_evaluate() {
        let db = test_db().await;
        let case_id = db.create_case("Filter", "e").await.unwrap();

        let jpg = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "a.jpg", "extension": "jpg" }),
        );
        db.record_artifact(&jpg).await.unwrap();

        // A row this build cannot classify: written by a newer version, or
        // damaged. It is neither a match nor an established non-match.
        sqlx::query(
            "INSERT INTO artifacts (id, case_id, parent_id, artifact_type, metadata_json, created_at) \
             VALUES (?, ?, NULL, 'FutureArtifactType', '{\"extension\":\"jpg\"}', '2026-01-01T00:00:00Z')",
        )
        .bind(Uuid::new_v4())
        .bind(case_id)
        .execute(&db.pool)
        .await
        .unwrap();

        let filter = seance_core::filter::FilterCondition::Simple {
            field: "extension".to_string(),
            operator: seance_core::filter::FilterOp::Eq,
            value: json!("jpg"),
        };
        let page = db
            .get_filtered_artifacts(case_id, None, &filter, 100, 0)
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert!(page.scan_complete, "the scan did reach the end of the case");
        assert_eq!(
            page.undecodable, 1,
            "a row that was never evaluated must qualify the result"
        );
    }

    #[tokio::test]
    async fn geo_map_reports_gps_rows_it_could_not_use() {
        let db = test_db().await;
        let case_id = db.create_case("Map", "e").await.unwrap();

        let good = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "gps", "gps_lat": 51.5, "gps_lon": -0.12 }),
        );
        db.record_artifact(&good).await.unwrap();
        // Carries a fix the SQL filter accepts but that is not a coordinate.
        let bad = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "gps", "gps_lat": "not a number", "gps_lon": "??" }),
        );
        db.record_artifact(&bad).await.unwrap();

        let set = db.get_geo_map_points(case_id).await.unwrap();
        assert_eq!(set.items.len(), 1);
        assert_eq!(
            set.undecodable, 1,
            "a fix the map cannot draw must be reported, not just logged"
        );
        assert!(
            !set.has_more,
            "the map refuses past its ceiling, it never truncates"
        );
        assert!(
            !set.is_complete(),
            "a map missing a fix must not report itself complete"
        );
    }

    #[test]
    fn page_size_is_clamped_into_one_through_max() {
        assert_eq!(clamp_page_size(None, 100), 100, "None means the maximum");
        assert_eq!(
            clamp_page_size(Some(0), 100),
            1,
            "a zero page discloses nothing"
        );
        assert_eq!(clamp_page_size(Some(50), 100), 50);
        assert_eq!(
            clamp_page_size(Some(usize::MAX), 100),
            100,
            "a caller cannot lift its own ceiling"
        );
    }

    #[test]
    fn probe_limit_asks_for_one_row_past_the_page() {
        assert_eq!(probe_limit(0), 1);
        assert_eq!(probe_limit(100), 101);
        assert_eq!(
            probe_limit(usize::MAX),
            i64::MAX,
            "an absurd limit must not wrap into a negative LIMIT"
        );
    }

    /// A case holding one FileSystem artifact with `n` FileEntry children.
    /// Returns `(case_id, parent_id)`.
    async fn tree_case(db: &SqliteConnection, n: usize) -> (Uuid, Uuid) {
        let case_id = db.create_case("Tree", "e").await.unwrap();
        let parent = Artifact::new(
            case_id,
            ArtifactType::FileSystem,
            None,
            json!({ "name": "volume" }),
        );
        db.record_artifact(&parent).await.unwrap();
        for i in 0..n {
            let child = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("file{i}") }),
            )
            .with_parent(parent.id);
            db.record_artifact(&child).await.unwrap();
        }
        (case_id, parent.id)
    }

    #[tokio::test]
    async fn a_child_page_shortened_by_a_decode_loss_is_not_the_last_page() {
        let db = test_db().await;
        let (case_id, parent_id) = tree_case(&db, 5).await;

        // Break the id of a row that lands inside the first page — the exact
        // damage B8-006/007 describes. On the wire the shortened page used to
        // be indistinguishable from "the listing ended here".
        let victim: Vec<u8> =
            sqlx::query_scalar("SELECT id FROM artifacts WHERE parent_id = ? LIMIT 1")
                .bind(parent_id.as_bytes().to_vec())
                .fetch_one(&db.pool)
                .await
                .unwrap();
        // Pinned first in the page order so it is certainly inside page one.
        sqlx::query(
            "UPDATE artifacts SET id = X'0102', created_at = '1970-01-01T00:00:00Z' WHERE id = ?",
        )
        .bind(&victim)
        .execute(&db.pool)
        .await
        .unwrap();

        let page = db
            .get_child_artifacts(case_id, Some(parent_id), Some(2), 0)
            .await
            .unwrap();

        assert_eq!(
            page.items.len(),
            1,
            "the undecodable row must not be invented back into the page"
        );
        assert!(
            page.has_more,
            "a page shortened by a decode loss must still say more rows exist; \
             a caller that stops on a short page loses the rest of the tree"
        );
        assert_eq!(
            page.undecodable, 1,
            "the dropped row is the second fact and paging further will never find it"
        );
        assert!(!page.is_complete());
    }

    #[tokio::test]
    async fn one_unreadable_child_no_longer_fails_the_whole_listing() {
        let db = test_db().await;
        let (case_id, parent_id) = tree_case(&db, 3).await;
        sqlx::query(
            "UPDATE artifacts SET artifact_type = 'NotAKnownType' \
             WHERE id = (SELECT id FROM artifacts WHERE parent_id = ? LIMIT 1)",
        )
        .bind(parent_id.as_bytes().to_vec())
        .execute(&db.pool)
        .await
        .unwrap();

        let page = db
            .get_child_artifacts(case_id, Some(parent_id), None, 0)
            .await
            .expect("one unknown artifact type must not 500 the entire tree");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.undecodable, 1);
    }

    #[tokio::test]
    async fn paging_children_reaches_every_child_exactly_once() {
        let db = test_db().await;
        let (case_id, parent_id) = tree_case(&db, 7).await;

        let mut seen = std::collections::HashSet::new();
        let mut offset = 0usize;
        let mut pages = 0;
        loop {
            let page = db
                .get_child_artifacts(case_id, Some(parent_id), Some(2), offset)
                .await
                .unwrap();
            for a in &page.items {
                assert!(
                    seen.insert(a.id),
                    "a page boundary repeated artifact {}",
                    a.id
                );
            }
            pages += 1;
            assert!(pages < 10, "paging did not terminate");
            if !page.has_more {
                break;
            }
            offset += page.limit;
        }
        assert_eq!(
            seen.len(),
            7,
            "every child must be reachable; a bare cap would have stranded the rest"
        );
    }

    #[tokio::test]
    async fn tree_page_carries_each_row_child_count() {
        let db = test_db().await;
        let (case_id, parent_id) = tree_case(&db, 2).await;

        // Give the first child two children of its own.
        let expandable: Vec<u8> = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE parent_id = ? ORDER BY created_at ASC, id ASC LIMIT 1",
        )
        .bind(parent_id.as_bytes().to_vec())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let expandable_id = Uuid::from_slice(&expandable).unwrap();
        for i in 0..2 {
            let g = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("grand{i}") }),
            )
            .with_parent(expandable_id);
            db.record_artifact(&g).await.unwrap();
        }

        let page = db
            .get_child_artifacts_filtered(case_id, Some(parent_id), false, None, 0)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        let with_children = page
            .items
            .iter()
            .find(|c| c.artifact.id == expandable_id)
            .expect("the expandable child must be on the page");
        assert_eq!(
            with_children.child_count, 2,
            "the child count must come back with the row, not from a query per row"
        );
        assert!(page
            .items
            .iter()
            .any(|c| c.artifact.id != expandable_id && c.child_count == 0));
    }

    #[tokio::test]
    async fn a_record_past_the_first_page_of_children_is_still_findable() {
        let db = test_db().await;
        let (case_id, parent_id) = tree_case(&db, 3).await;

        let map = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "allocation_map", "blocks": [] }),
        )
        .with_parent(parent_id);
        db.record_artifact(&map).await.unwrap();
        // Pin it last in the page order so "page one" definitely excludes it.
        sqlx::query("UPDATE artifacts SET created_at = '2099-01-01T00:00:00Z' WHERE id = ?")
            .bind(map.id.as_bytes().to_vec())
            .execute(&db.pool)
            .await
            .unwrap();

        let first_page = db
            .get_child_artifacts(case_id, Some(parent_id), Some(2), 0)
            .await
            .unwrap();
        assert!(
            first_page.items.iter().all(|a| a.id != map.id),
            "test precondition: the record must not be on the first page"
        );

        let found = db
            .find_child_artifact_by_record_type(case_id, parent_id, "allocation_map")
            .await
            .unwrap();
        assert_eq!(
            found.map(|a| a.id),
            Some(map.id),
            "a targeted lookup must not depend on the record landing in page one"
        );
        assert!(db
            .find_child_artifact_by_record_type(case_id, parent_id, "no_such_record")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_bookmark_page_says_more_bookmarks_exist() {
        let db = test_db().await;
        let case_id = db.create_case("Marks", "e").await.unwrap();
        for i in 0..3 {
            let a = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("f{i}") }),
            );
            db.record_artifact(&a).await.unwrap();
            db.create_artifact_bookmark(case_id, a.id, None, Some("note"), Some("ex"))
                .await
                .unwrap();
        }

        let page = db
            .list_artifact_bookmarks(case_id, None, Some(2), 0)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(
            page.has_more,
            "an export that stopped here would omit a finding the examiner recorded"
        );

        let rest = db
            .list_artifact_bookmarks(case_id, None, Some(2), 2)
            .await
            .unwrap();
        assert_eq!(rest.items.len(), 1);
        assert!(!rest.has_more);
        assert!(rest.is_complete());

        let mut ids: Vec<Uuid> = page.items.iter().map(|b| b.bookmark.id).collect();
        ids.extend(rest.items.iter().map(|b| b.bookmark.id));
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "paging must not repeat or skip a bookmark");
    }

    /// Review finding: `json_extract` yields whatever type the JSON held, so a
    /// numeric `volume_name` made the derived `FromRow` decode of `Option<String>`
    /// fail and `?` took the WHOLE disk map down with it — one odd label on one
    /// region 500s the panel for every region. `get_geo_points` reads each
    /// column with `.ok()` for exactly this reason.
    #[tokio::test]
    async fn a_non_text_volume_label_leaves_one_region_unnamed_not_the_map_broken() {
        let db = test_db().await;
        let case_id = db.create_case("Odd label", "e").await.unwrap();
        let root = Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({ "size_bytes": 1_000_000 }),
        );
        db.record_artifact(&root).await.unwrap();

        // A numeric label: a numeric FAT volume label, or any third-party parser.
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::FileSystem,
                None,
                json!({ "filesystem_type": "fat", "offset_bytes": 1000, "size_bytes": 500,
                        "volume_name": 12345 }),
            )
            .with_parent(root.id),
        )
        .await
        .unwrap();
        db.record_artifact(
            &Artifact::new(
                case_id,
                ArtifactType::FileSystem,
                None,
                json!({ "filesystem_type": "apfs", "offset_bytes": 2000, "size_bytes": 500,
                        "volume_name": "Macintosh HD" }),
            )
            .with_parent(root.id),
        )
        .await
        .unwrap();

        let regions = db
            .get_disk_regions(case_id, root.id)
            .await
            .expect("one odd label must not fail the whole query");
        assert_eq!(regions.len(), 2, "both regions must still be returned");
        assert!(
            regions
                .iter()
                .any(|r| r.name.as_deref() == Some("Macintosh HD")),
            "the well-formed neighbour keeps its name: {regions:?}"
        );
    }

    /// LIVE-018: an APFS container holds a dozen volumes, and the disk map
    /// labelled every one of them "APFS" because it read only the artifact's
    /// `name` column — which the filesystem parser leaves null. The volume's
    /// own name was in its metadata the whole time, so an examiner could not
    /// tell Macintosh HD from Preboot, Recovery or VM.
    #[tokio::test]
    async fn a_filesystem_region_is_named_by_its_volume_when_the_column_is_null() {
        let db = test_db().await;
        let case_id = db.create_case("APFS", "e").await.unwrap();

        let root = Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({ "size_bytes": 1_000_000 }),
        );
        db.record_artifact(&root).await.unwrap();

        for (index, volume) in ["Macintosh HD", "Preboot", "Recovery"].iter().enumerate() {
            let fs = Artifact::new(
                case_id,
                ArtifactType::FileSystem,
                None,
                json!({
                    "filesystem_type": "apfs",
                    "offset_bytes": 1000 * (index as i64 + 1),
                    "size_bytes": 500,
                    "volume_name": volume,
                }),
            )
            .with_parent(root.id);
            db.record_artifact(&fs).await.unwrap();
        }

        let regions = db.get_disk_regions(case_id, root.id).await.unwrap();
        let names: Vec<String> = regions
            .iter()
            .map(|r| r.name.clone().unwrap_or_default())
            .collect();

        assert_eq!(names.len(), 3);
        for volume in ["Macintosh HD", "Preboot", "Recovery"] {
            assert!(
                names.iter().any(|n| n == volume),
                "volume {volume:?} unnamed; got {names:?}"
            );
        }
    }

    /// LIVE-015: an EXIF point must carry the file it came from and when it was
    /// taken. The report's Geolocation table has a File, a Path and a Timestamp
    /// column, and the exif parser writes `source_name` and `datetime_original`
    /// — not `source_path` and `timestamp`, which is all this query asked for.
    /// A coordinate with no source file and no time cannot be attributed to
    /// anything, which is the whole evidential point of the section.
    #[tokio::test]
    async fn a_gps_point_carries_the_file_it_came_from_and_when_it_was_taken() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "exif",
                "has_gps": true,
                "gps_lat": 54.579706,
                "gps_lon": -5.951100,
                "gps_altitude": 14.9,
                "source_name": "FullSizeRender.jpg",
                "datetime_original": "2020:02:19 13:21:13",
            }),
        ))
        .await
        .unwrap();

        let points = db.get_geo_points(case_id).await.unwrap();
        assert_eq!(points.len(), 1);
        let (label, path, lat, _lon, _alt, timestamp) = &points[0];

        assert!(
            label.contains("FullSizeRender.jpg") || path.as_deref() == Some("FullSizeRender.jpg"),
            "the point must name its source file, got label={label:?} path={path:?}"
        );
        assert_eq!(
            timestamp.as_deref(),
            Some("2020:02:19 13:21:13"),
            "the capture time is in datetime_original"
        );
        assert!((*lat - 54.579706).abs() < 1e-9);
    }

    /// Review finding: a numeric `$.timestamp` is non-NULL, so a plain COALESCE
    /// picked it and then decoded to None — the point exported with no time at
    /// all, while the readable capture date sat one arm away.
    #[tokio::test]
    async fn a_numeric_timestamp_does_not_shadow_the_readable_capture_date() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "exif",
                "has_gps": true,
                "gps_lat": 1.0,
                "gps_lon": 2.0,
                "timestamp": 1_582_118_473_i64,
                "datetime_original": "2020:02:19 13:21:13",
            }),
        ))
        .await
        .unwrap();

        let points = db.get_geo_points(case_id).await.unwrap();
        let (_l, _p, _lat, _lon, _alt, timestamp) = &points[0];
        assert_eq!(timestamp.as_deref(), Some("2020:02:19 13:21:13"));
    }

    /// And a numeric time with nothing readable beside it is still reported,
    /// as text, rather than silently becoming "no time recorded".
    #[tokio::test]
    async fn a_numeric_timestamp_alone_is_still_reported() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "exif", "has_gps": true, "gps_lat": 1.0, "gps_lon": 2.0,
                    "timestamp": 1_582_118_473_i64 }),
        ))
        .await
        .unwrap();

        let points = db.get_geo_points(case_id).await.unwrap();
        assert_eq!(points[0].5.as_deref(), Some("1582118473"));
    }

    /// The export must apply the same EXIF qualification as the map and the
    /// count: an EXIF record with coordinates but `has_gps` false (a 0,0
    /// placeholder) is not a fix, while a typeless record with coordinates is.
    #[tokio::test]
    async fn geo_export_excludes_exif_without_has_gps_but_keeps_typeless() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        for meta in [
            json!({ "type": "exif", "has_gps": false, "gps_lat": 0.0, "gps_lon": 0.0,
                    "source_name": "nofix.jpg" }),
            json!({ "gps_lat": 1.0, "gps_lon": 2.0, "source_name": "typeless.db" }),
        ] {
            db.record_artifact(&Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                meta,
            ))
            .await
            .unwrap();
        }

        let points = db.get_geo_points(case_id).await.unwrap();
        assert_eq!(points.len(), 1, "got {points:?}");
        assert_eq!(points[0].0, "typeless.db");
        assert_eq!(db.media_counts(case_id).await.unwrap().geolocation, 1);
    }

    /// The navigator count and the map must agree: a GPS-bearing record with no
    /// `type` key is a valid non-exif point, and `NULL <> 'exif'` is NULL, which
    /// would have excluded it from the count.
    #[tokio::test]
    async fn a_typeless_gps_record_is_counted_as_geolocation() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "gps_lat": 1.0, "gps_lon": 2.0 }),
        ))
        .await
        .unwrap();

        assert_eq!(db.media_counts(case_id).await.unwrap().geolocation, 1);
    }

    /// A job row whose status or count is not one this code wrote must be an
    /// error, not a `Failed` job (an outcome no module reported) or a wrapped
    /// `usize`.
    #[tokio::test]
    async fn a_job_row_that_will_not_decode_is_an_error_not_a_failed_job() {
        let db = test_db().await;
        let case_id = db.create_case("Jobs", "e").await.unwrap();
        let target = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "a"}));
        db.record_artifact(&target).await.unwrap();
        for (status, produced) in [("quiesced", 0_i64), ("complete", -1_i64)] {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO ad_hoc_jobs (id, case_id, module_id, target_artifact_id, status, \
                 artifacts_produced, created_at) VALUES (?, ?, 'm', ?, ?, ?, 1)",
            )
            .bind(id)
            .bind(case_id)
            .bind(target.id)
            .bind(status)
            .bind(produced)
            .execute(&db.pool)
            .await
            .unwrap();
            assert!(db.get_job(id).await.is_err(), "{status}/{produced}");
            assert!(db.list_jobs(case_id).await.is_err());
            assert!(db.list_jobs_for_artifact(target.id).await.is_err());
            let page = db.list_jobs_page(case_id, None, 0).await.unwrap();
            assert_eq!((page.items.len(), page.undecodable), (0, 1));
            sqlx::query("DELETE FROM ad_hoc_jobs")
                .execute(&db.pool)
                .await
                .unwrap();
        }
    }

    /// A pin whose id will not decode is an error, not a pin that quietly
    /// vanishes from the report's pinned-pivot section.
    #[tokio::test]
    async fn a_pinned_pivot_that_will_not_decode_is_an_error_not_a_missing_pin() {
        let db = test_db().await;
        let case_id = db.create_case("Pins", "e").await.unwrap();
        sqlx::query(
            "INSERT INTO pinned_pivots (id, case_id, value, examiner, pinned_at, total_matches, \
             grouped, truncated, groups_json) VALUES (X'0102', ?, 'v', 'ex', 1, 0, 0, 0, '{}')",
        )
        .bind(case_id)
        .execute(&db.pool)
        .await
        .unwrap();
        assert!(db.list_pinned_pivots(case_id).await.is_err());
    }

    /// A bookmark on an artifact whose metadata will not parse is kept, listed
    /// under a marker that is not the "Unknown" of a parsed-but-nameless one.
    #[tokio::test]
    async fn a_bookmark_with_unreadable_artifact_metadata_is_marked_not_unknown() {
        let db = test_db().await;
        let case_id = db.create_case("Bm", "e").await.unwrap();
        let art = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "a"}));
        db.record_artifact(&art).await.unwrap();
        db.create_artifact_bookmark(case_id, art.id, None, Some("n"), Some("ex"))
            .await
            .unwrap();
        // SQLite's JSON accepts JSON5 (unquoted keys, trailing commas), so
        // this passes its own validity checks while `serde_json` refuses it.
        sqlx::query("UPDATE artifacts SET metadata_json = ? WHERE id = ?")
            .bind("{name: 'a', }")
            .bind(art.id)
            .execute(&db.pool)
            .await
            .unwrap();

        let listed = db
            .list_artifact_bookmarks(case_id, None, None, 0)
            .await
            .unwrap();
        assert_eq!(listed.items.len(), 1, "the bookmark is not dropped");
        assert_eq!(listed.items[0].artifact_name, UNREADABLE_METADATA_NAME);
    }

    /// An explicit `source_path` still wins: it is the fuller answer, and a
    /// parser that records one must not be overridden by the bare file name.
    #[tokio::test]
    async fn an_explicit_source_path_is_preferred_over_the_bare_name() {
        let db = test_db().await;
        let case_id = db.create_case("Geo", "e").await.unwrap();
        db.record_artifact(&Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "exif",
                "has_gps": true,
                "gps_lat": 1.0,
                "gps_lon": 2.0,
                "source_name": "IMG.JPG",
                "source_path": "/DCIM/100APPLE/IMG.JPG",
                "timestamp": "2021-01-01T00:00:00Z",
                "datetime_original": "2021:01:01 00:00:00",
            }),
        ))
        .await
        .unwrap();

        let points = db.get_geo_points(case_id).await.unwrap();
        let (_label, path, _lat, _lon, _alt, timestamp) = &points[0];
        assert_eq!(path.as_deref(), Some("/DCIM/100APPLE/IMG.JPG"));
        assert_eq!(timestamp.as_deref(), Some("2021-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn a_case_is_walked_by_id_a_page_at_a_time_with_no_row_seen_twice() {
        // The sweep `LIVE-028` needs: every artifact exactly once, in a total
        // order, without OFFSET — which on a 580,394-artifact case would make a
        // full pass cost the square of the case.
        let db = test_db().await;
        let case_id = db.create_case("Walk", "e").await.unwrap();
        let other = db.create_case("Other", "e").await.unwrap();
        let mut expected = Vec::new();
        for i in 0..25 {
            let a = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("f{i}") }),
            );
            expected.push(a.id);
            db.record_artifact(&a).await.unwrap();
        }
        // A neighbouring case must not appear in the walk.
        db.record_artifact(&Artifact::new(
            other,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "not mine" }),
        ))
        .await
        .unwrap();

        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = db.artifacts_page_after(case_id, after, 7).await.unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 7, "the page size is honoured");
            after = page.last().map(|a| a.id);
            for a in page {
                assert_eq!(a.case_id, case_id);
                seen.push(a.id);
            }
        }
        expected.sort();
        assert_eq!(seen.len(), 25, "every artifact once");
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 25, "and no row twice");
        assert_eq!(sorted, expected);
        // The order is by id, which is what makes `after` a resumable cursor.
        let mut ascending = seen.clone();
        ascending.sort();
        assert_eq!(seen, ascending);
    }

    /// HUNT-113. An ingest a stopped process never finished left a case that
    /// read as complete. The run is now a row: opened when the root is queued,
    /// closed when its case goes idle, and — when the next start finds it
    /// still open — marked interrupted with what the walk had recorded.
    #[tokio::test]
    async fn an_ingest_run_left_running_by_a_stopped_process_is_marked_interrupted_with_its_count()
    {
        use seance_core::profile::IngestRun;
        let db = test_db().await;
        let case_id = db.create_case("Runs", "e").await.unwrap();

        // A root with three children, two of them under one child: the count
        // an interrupted run reports is the whole subtree, not one level.
        let root = Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"name": "img"}),
        );
        db.record_artifact(&root).await.unwrap();
        let dir = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "d"}))
            .with_parent(root.id);
        db.record_artifact(&dir).await.unwrap();
        for n in ["a", "b"] {
            db.record_artifact(
                &Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": n}))
                    .with_parent(dir.id),
            )
            .await
            .unwrap();
        }
        // An unrelated root in the same case, with its own finished run.
        let other = Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"name": "o"}),
        );
        db.record_artifact(&other).await.unwrap();

        let run = |source: Uuid, label: &str, started_at: i64| IngestRun {
            id: Uuid::new_v4(),
            case_id,
            source_artifact_id: source,
            source_label: label.to_string(),
            started_at,
            finished_at: None,
            status: IngestRun::RUNNING.to_string(),
            artifacts_recorded: None,
            detail: None,
        };
        db.start_ingest_run(&run(other.id, "o", 1_000))
            .await
            .unwrap();
        let closed = db
            .finish_ingest_runs_for_case(case_id, IngestRun::COMPLETED, 1_500)
            .await
            .unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].status, "completed");
        assert_eq!(
            closed[0].artifacts_recorded, None,
            "counted at read time, not here"
        );

        db.start_ingest_run(&run(root.id, "/evidence/img.E01", 2_000))
            .await
            .unwrap();
        // A run queued AFTER the sweeping process started is that process's
        // own and is not swept.
        db.start_ingest_run(&run(other.id, "o-again", 9_000))
            .await
            .unwrap();

        let swept = db
            .mark_interrupted_ingest_runs(5_000, "stopped")
            .await
            .unwrap();
        assert_eq!(swept.len(), 1, "only the run the stopped process left");
        assert_eq!(swept[0].source_artifact_id, root.id);
        assert_eq!(swept[0].status, "interrupted");
        assert_eq!(swept[0].artifacts_recorded, Some(3), "the whole subtree");
        assert_eq!(swept[0].detail.as_deref(), Some("stopped"));
        assert!(swept[0].finished_at.is_some());

        // Idempotent, and the listing shows every run newest first with the
        // one still running untouched.
        let again = db
            .mark_interrupted_ingest_runs(5_000, "stopped")
            .await
            .unwrap();
        assert!(again.is_empty());
        let all = db.list_ingest_runs(case_id).await.unwrap();
        let statuses: Vec<(&str, &str, Option<i64>)> = all
            .iter()
            .map(|r| {
                (
                    r.source_label.as_str(),
                    r.status.as_str(),
                    r.artifacts_recorded,
                )
            })
            .collect();
        assert_eq!(
            statuses,
            [
                ("o-again", "running", None),
                ("/evidence/img.E01", "interrupted", Some(3)),
                ("o", "completed", Some(0)),
            ]
        );
    }

    #[tokio::test]
    async fn jobs_left_pending_or_running_by_a_stopped_process_are_failed_and_named() {
        use seance_core::profile::{AdHocJob, JobStatus};
        let db = test_db().await;
        let case_id = db.create_case("Jobs", "e").await.unwrap();
        let target = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "t" }),
        );
        db.record_artifact(&target).await.unwrap();

        let job = |status: JobStatus, created_at: i64| AdHocJob {
            id: Uuid::new_v4(),
            case_id,
            module_id: "mod".to_string(),
            target_artifact_id: target.id,
            status,
            artifacts_produced: 0,
            error_message: None,
            created_at,
            completed_at: None,
        };
        let pending = job(JobStatus::Pending, 1_000);
        let running = job(JobStatus::Running, 1_001);
        let complete = job(JobStatus::Complete, 1_002);
        let failed = AdHocJob {
            error_message: Some("its own reason".to_string()),
            ..job(JobStatus::Failed, 1_003)
        };
        // Accepted by the process doing the sweep: created after it started.
        let later = job(JobStatus::Pending, 2_001);
        for j in [&pending, &running, &complete, &failed, &later] {
            db.create_job(j).await.unwrap();
        }

        let swept = db.fail_interrupted_jobs(2_000, "stopped").await.unwrap();
        let swept_ids: Vec<Uuid> = swept.iter().map(|j| j.id).collect();
        assert_eq!(
            swept_ids,
            vec![pending.id, running.id],
            "exactly the pending and running jobs from before the cutoff, oldest first"
        );
        for j in &swept {
            assert_eq!(j.status, JobStatus::Failed);
            assert_eq!(j.error_message.as_deref(), Some("stopped"));
            assert!(j.completed_at.is_some(), "the sweep records when it ran");
        }

        let untouched = db.get_job(complete.id).await.unwrap().unwrap();
        assert_eq!(untouched.status, JobStatus::Complete);
        let untouched = db.get_job(failed.id).await.unwrap().unwrap();
        assert_eq!(untouched.error_message.as_deref(), Some("its own reason"));
        let untouched = db.get_job(later.id).await.unwrap().unwrap();
        assert_eq!(
            untouched.status,
            JobStatus::Pending,
            "a job created after the cutoff belongs to a live process"
        );

        let again = db.fail_interrupted_jobs(2_000, "stopped").await.unwrap();
        assert!(again.is_empty(), "a second sweep finds nothing to do");
    }

    #[tokio::test]
    async fn a_job_page_says_more_jobs_exist_and_never_invents_a_failure() {
        let db = test_db().await;
        let case_id = db.create_case("Jobs", "e").await.unwrap();
        let target = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "t" }),
        );
        db.record_artifact(&target).await.unwrap();

        for i in 0..3i64 {
            let job = seance_core::profile::AdHocJob {
                id: Uuid::new_v4(),
                case_id,
                module_id: format!("mod{i}"),
                target_artifact_id: target.id,
                status: seance_core::profile::JobStatus::Complete,
                artifacts_produced: 1,
                error_message: None,
                created_at: 1_000 + i,
                completed_at: Some(1_010 + i),
            };
            db.create_job(&job).await.unwrap();
        }

        let page = db.list_jobs_page(case_id, Some(2), 0).await.unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(
            page.has_more,
            "list_jobs had no LIMIT at all; a bounded one must say it is bounded"
        );

        // A status this build cannot read used to be reported as a failed job.
        sqlx::query("UPDATE ad_hoc_jobs SET status = 'quiesced' WHERE created_at = 1000")
            .execute(&db.pool)
            .await
            .unwrap();
        let all = db.list_jobs_page(case_id, None, 0).await.unwrap();
        assert_eq!(all.items.len(), 2);
        assert_eq!(
            all.undecodable, 1,
            "an unreadable status is a decode loss, not an outcome the module reported"
        );
        assert!(all
            .items
            .iter()
            .all(|j| j.status != seance_core::profile::JobStatus::Failed));
        assert!(!all.has_more, "two of three rows fit, so nothing is beyond");
    }

    #[tokio::test]
    async fn a_processing_history_page_says_the_history_is_short() {
        let db = test_db().await;
        let case_id = db.create_case("Hist", "e").await.unwrap();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "t" }),
        );
        db.record_artifact(&artifact).await.unwrap();
        for i in 0..3 {
            db.record_processing_log(
                case_id,
                artifact.id,
                &format!("mod{i}"),
                "complete",
                1,
                None,
                5,
            )
            .await
            .unwrap();
        }

        let page = db
            .get_processing_log_for_artifact_page(artifact.id, Some(2), 0)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(
            page.has_more,
            "clamping the limit without this channel silently shortens the module history"
        );
        assert_eq!(page.limit, 2);

        let rest = db
            .get_processing_log_for_artifact_page(artifact.id, Some(2), 2)
            .await
            .unwrap();
        assert_eq!(rest.items.len(), 1);
        assert!(rest.is_complete());

        let clamped = db
            .get_processing_log_for_artifact_page(artifact.id, Some(usize::MAX), 0)
            .await
            .unwrap();
        assert_eq!(
            clamped.limit, PROCESSING_LOG_PAGE_MAX,
            "the applied ceiling must be reported, not the one that was asked for"
        );
    }

    #[tokio::test]
    async fn communication_graph_reports_unusable_email_rows() {
        let db = test_db().await;
        let case_id = db.create_case("Graph", "e").await.unwrap();

        let usable = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "EmailMessage", "from": "a@example.com", "to": ["b@example.com"] }),
        );
        db.record_artifact(&usable).await.unwrap();
        // No sender: this record can carry no edge.
        let unusable = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "EmailMessage", "to": ["c@example.com"] }),
        );
        db.record_artifact(&unusable).await.unwrap();

        let graph = db.communication_graph(case_id).await.unwrap();
        assert_eq!(
            graph.unusable_email_records, 1,
            "an email row that contributed nothing must be disclosed, not only warned about"
        );
        assert!(
            !graph.truncated,
            "unusable rows are a different failure from a cap"
        );
    }

    /// HUNT-192: links of equal weight came back in `HashMap` order, which
    /// differs between calls, so `/graph/communications` answered the same
    /// question two ways. The order is (weight desc, source, target).
    #[tokio::test]
    async fn communication_graph_orders_equal_weight_links_the_same_every_call() {
        let db = test_db().await;
        let case_id = db.create_case("Graph order", "e").await.unwrap();
        // One mail from a sender to nine recipients: nine links of weight 1,
        // plus a reply that makes one link weight 2.
        let recipients: Vec<String> = (1..=9).map(|i| format!("r{i}@example.org")).collect();
        let mut arts = vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "EmailMessage", "from": "boss@example.org", "to": recipients }),
        )];
        arts.push(Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "EmailMessage", "from": "boss@example.org", "to": ["r5@example.org"] }),
        ));
        db.record_artifacts_batch(&arts).await.unwrap();

        let order = |g: &CommunicationGraph| {
            g.edges
                .iter()
                .map(|e| (e.weight, e.source.clone(), e.target.clone()))
                .collect::<Vec<_>>()
        };
        let first = order(&db.communication_graph(case_id).await.unwrap());
        assert_eq!(first.len(), 9);
        let mut expected = first.clone();
        expected.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        assert_eq!(
            first, expected,
            "links are ordered by weight, then source, then target"
        );
        for _ in 0..20 {
            assert_eq!(
                order(&db.communication_graph(case_id).await.unwrap()),
                first
            );
        }
    }

    #[tokio::test]
    async fn duplicate_group_count_is_the_whole_group_not_the_sample() {
        let db = test_db().await;
        let case_id = db.create_case("Dedup", "e").await.unwrap();

        const SHA: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        let mut arts = Vec::new();
        for i in 0..50 {
            arts.push(Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("copy_{i}.bin"), "sha256": SHA }),
            ));
        }
        db.record_artifacts_batch(&arts).await.unwrap();

        let groups = db.duplicate_hash_groups(case_id, 10, 3).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].members.len(),
            3,
            "the member list is capped in SQL, not after loading all 50"
        );
        assert_eq!(
            groups[0].count, 50,
            "the true group size must survive the member cap"
        );
    }

    #[test]
    fn nested_and_indexed_virtual_column_paths_resolve() {
        let doc = json!({
            "items": [ { "name": "first" }, { "name": "second" } ],
            "flat": "top",
        });
        assert_eq!(
            resolve_json_path(&doc, "$.items[0].name"),
            Some(&json!("first")),
            "a nested path stored by the column editor must actually resolve"
        );
        assert_eq!(
            resolve_json_path(&doc, "$.items[1].name"),
            Some(&json!("second"))
        );
        assert_eq!(resolve_json_path(&doc, "$.flat"), Some(&json!("top")));
        assert_eq!(resolve_json_path(&doc, "$.items[9].name"), None);
        assert_eq!(resolve_json_path(&doc, "$.missing.name"), None);
        assert_eq!(resolve_json_path(&doc, "$."), None);
    }

    #[tokio::test]
    async fn timeline_dynamic_columns_resolve_nested_paths() {
        let db = test_db().await;
        let case_id = db.create_case("Timeline", "e").await.unwrap();

        let event = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000,
                "timestamp_desc": "Created",
                "source_module": "test",
                "short_desc": "nested details",
                "full_details": "{\"items\":[{\"name\":\"payload.exe\"}]}",
            }),
        );
        db.record_artifact(&event).await.unwrap();

        let cols = vec!["$.items[0].name".to_string()];
        let events = db
            .get_timeline_events_filtered(
                case_id,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(10),
                None,
                None,
                None,
                Some(&cols),
                None,
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let fields = events[0]
            .dynamic_fields
            .as_ref()
            .expect("dynamic fields requested");
        assert_eq!(
            fields.get("items[0].name"),
            Some(&json!("payload.exe")),
            "a configured nested column must show the value that is in the evidence"
        );
    }
}

#[cfg(test)]
mod wal_hint_tests {
    use super::wal_bytes_beside;

    #[test]
    fn a_memory_database_has_no_wal_to_report() {
        assert_eq!(wal_bytes_beside("sqlite::memory:"), None);
    }

    #[test]
    fn the_wal_is_found_beside_the_database_the_url_names() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("seance.sqlite");
        std::fs::write(format!("{}-wal", db.display()), vec![0u8; 4096]).unwrap();

        // The query string is part of the URL Séance uses, not of the path.
        assert_eq!(
            wal_bytes_beside(&format!("sqlite:{}?mode=rwc", db.display())),
            Some(4096)
        );
        assert_eq!(
            wal_bytes_beside(&format!("sqlite://{}", db.display())),
            Some(4096)
        );
    }
}

/// The processing log as one row per (artifact, module), whatever shape the
/// rows are stored in.
///
/// Most of the log is the same sentence — "this module ran over this artifact
/// and produced nothing" — and it is stored folded, one row per artifact per
/// status, with the modules and their durations in `zero_yield_modules`
/// (HUNT-074). Every read goes through this so a folded row and the
/// row-per-module rows earlier builds wrote are indistinguishable to the caller:
/// the per-artifact history still lists each module, and the case summary still
/// groups by module.
///
/// `seq` is the module's position inside a folded row (0 for a stored row), so
/// `(created_at, id, seq)` is a total order: every module expanded from one
/// folded row shares its `id` and `created_at`, and without `seq` a page
/// boundary inside that group would repeat some modules and skip others.
///
/// `predicate` is inlined into BOTH branches so the case or artifact filter is
/// applied before the expansion rather than after it — a union of the whole
/// table filtered afterwards would scan every case. It is a literal from this
/// file, never caller input, and its parameter must therefore be bound twice.
fn expanded_processing_log(predicate: &str) -> String {
    format!(
        "SELECT id, case_id, artifact_id, module_id, status, artifacts_produced, \
                error_message, duration_ms, created_at, 0 AS seq \
           FROM processing_log WHERE {predicate} AND zero_yield_modules IS NULL \
         UNION ALL \
         SELECT p.id, p.case_id, p.artifact_id, \
                json_extract(j.value, '$.module_id') AS module_id, p.status, 0, NULL, \
                json_extract(j.value, '$.duration_ms'), p.created_at, j.key AS seq \
           FROM processing_log p, json_each(p.zero_yield_modules) j \
          WHERE p.{predicate} AND p.zero_yield_modules IS NOT NULL"
    )
}
