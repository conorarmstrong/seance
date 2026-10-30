#![forbid(unsafe_code)]
//! Twitter / X parser (Android per-account database).
//!
//! [`TwitterParser`] self-selects Twitter's Android databases under
//! `com.twitter.android/databases/`:
//!
//! - the per-account main DB `<userId>-<NN>.db` (the `<NN>` is an app-version
//!   schema revision that drifts, so it is matched by pattern, never a fixed
//!   number). Its `conversation_entries` table holds Direct Messages; a `users`
//!   table maps numeric ids to `@screen_name`. Its own `search_queries` table
//!   is the account's search history on every real store held (HUNT-191).
//! - `<userId>-search.db` → the `search_queries` table (search history), where
//!   a build keeps it in a database of its own; no real one has been observed.
//!
//! # Schema drift
//!
//! Twitter renames DM/table columns between app versions (a documented
//! schema-drift offender), so nothing is hard-coded: tables are discovered via
//! `sqlite_master`, every column is resolved through a field map of the names
//! seen on real stores, and message direction is *computed* from the account
//! owner id vs the sender (there is no stored direction flag). The main
//! database's `PRAGMA user_version` is checked against the window those real
//! stores span (`SUPPORTED_MAIN_SCHEMA`); a store outside it, or one whose
//! columns no candidate name matches, still parses and carries a
//! `ParserStaleWarning` record naming the version or the unresolved fields. A
//! non-Twitter file, a missing table, or a corrupt row never panics.

use rusqlite::Connection;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::inline_marker::{user_version_marker, TableFields as Fields};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_catalogue, probe_table, query_failed_marker,
    unix_seconds_from_magnitude, unreadable_store_marker, ChatMessage, Presence, RowDrops,
    SupportedRange,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

/// Record type for every marker that qualifies this plugin's DM records.
///
/// Deliberately NOT `TwitterDM`, the type the records themselves carry:
/// `seance_db` groups conversations by `metadata.$.type`, so a marker sharing
/// the walk's type would join the grouping as a phantom one-message thread.
const INCOMPLETE_TYPE: &str = "TwitterIncomplete";

/// The same rule for the search-history walk, whose records are `TwitterSearch`.
const SEARCH_INCOMPLETE_TYPE: &str = "TwitterSearchIncomplete";

/// The parser identity the per-account main database's schema warnings are
/// filed under.
const MAIN_SCHEMA_APP: &str = "twitter-android";

/// The parser identity for the `<userId>-search.db` walk. No version window is
/// declared for it: no real `-search.db` has been observed (both real
/// per-account stores keep `search_queries` inside the main database), and a
/// range nobody observed would be a fabrication. Drift there is caught by the
/// column map alone.
const SEARCH_SCHEMA_APP: &str = "twitter-android-search";

/// The `PRAGMA user_version` window the main-database walk was validated
/// against, on real stores only — never widened by guesswork. Observed: 7 in
/// plaso's `test_data/twitter_android.db`, 59 in both Magnet 2022 CTF Pixel 3
/// stores (`com.twitter.android/databases/0-61.db` and
/// `1489429766507835392-61.db`). A store outside it still parses; it also
/// carries a `ParserStaleWarning`.
const SUPPORTED_MAIN_SCHEMA: SupportedRange = SupportedRange {
    min: 7,
    max: Some(59),
};

/// The real stores each endpoint of [`SUPPORTED_MAIN_SCHEMA`] was read out of,
/// written on every schema record as `validated_against`.
const MAIN_SCHEMA_EVIDENCE: &str = "plaso test_data/twitter_android.db (user_version 7); Magnet \
     2022 CTF Pixel 3 com.twitter.android/databases/0-61.db and 1489429766507835392-61.db \
     (user_version 59)";

/// The logical fields each table is read through, with the physical column
/// names that have carried them. Candidate order is preference order. A rename
/// in a newer app build is then one more candidate here, not a code path — and
/// until it is added, the field is reported as unresolved rather than read as
/// empty. Both real stores (user_version 7 and 59) carry exactly the first
/// candidate of every entry below.
const ENTRY_FIELDS: &[(&str, &[&str])] = &[
    ("entry_id", &["entry_id"]),
    ("conversation_id", &["conversation_id"]),
    ("sender_id", &["user_id", "sender_id"]),
    (
        "created",
        &["created", "created_at", "timestamp", "sort_timestamp"],
    ),
    ("entry_type", &["entry_type", "type"]),
];
/// The message body lives in the serialized `data` protobuf on every real
/// store observed, and in a plain `text` column on some builds. Either carries
/// it, so drift is reported only when neither resolves.
const ENTRY_BODY_FIELDS: &[(&str, &[&str])] = &[
    ("text", &["text"]),
    ("data", &["data", "request_body", "attachment"]),
];
const USER_FIELDS: &[(&str, &[&str])] = &[
    ("user_id", &["user_id", "_id", "id"]),
    ("screen_name", &["username", "screen_name", "handle"]),
];
const SEARCH_FIELDS: &[(&str, &[&str])] = &[("time", &["time"]), ("query", &["query", "name"])];

/// The marker for the main store's `PRAGMA user_version` against the validated
/// window, if any.
fn schema_version_marker(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Option<Artifact> {
    user_version_marker(
        conn,
        case_id,
        parent_id,
        MAIN_SCHEMA_APP,
        &SUPPORTED_MAIN_SCHEMA,
        MAIN_SCHEMA_EVIDENCE,
    )
}

/// Resolve a table's columns, or the marker for a column list that would not
/// read — which is a store this tool did not examine, never one with no such
/// columns.
fn resolve_or_report(
    conn: &Connection,
    app: &'static str,
    table: &'static str,
    specs: &[(&str, &[&str])],
    kind: Kind,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<Fields, Vec<Artifact>> {
    Fields::resolve(conn, app, table, specs).map_err(|unreadable| {
        vec![unreadable_store_marker(
            case_id,
            parent_id,
            kind.incomplete_type(),
            format!(
                "the Twitter `{table}` column list would not read: {}",
                unreadable.why
            ),
        )]
    })
}

pub struct TwitterParser;

impl ForensicsModule for TwitterParser {
    fn id(&self) -> &str {
        "plugin.messaging.twitter"
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
        let base = name.to_ascii_lowercase();
        let base = base.rsplit('/').next().unwrap_or("");
        let kind = match classify(base) {
            Some(k) => k,
            None => return Ok(Vec::new()),
        };

        debug!("TwitterParser inspecting {name}");
        // Direction is computed from the account-owner id, which lives in the
        // ORIGINAL filename (`<ownerId>-<NN>.db`) — never the random temp path
        // the DB is copied to. Parse it from `base` here and pass it through.
        let owner = owner_id_from_base(base);
        // The shared gate skips directories and artifacts with no reachable
        // content, probes the SQLite magic with a LOOPING read (a windowed or
        // container-backed source may answer a 16-byte request with 4, and a
        // single `read_at` would file a real Twitter database as "not SQLite"),
        // stages the database with its `-wal` sibling, stamps whatever the
        // parse produced with how much of the file was actually read, and — the
        // arm this plugin was missing — reports a store that carried the SQLite
        // header and would not stage instead of returning an empty list.
        //
        // `<userId>-<NN>.db` / `<userId>-search.db` is Twitter's own naming and
        // nothing else uses it, so silence there reads exactly like a phone
        // that never had the app. Every sibling plugin whose filename
        // identifies its app already emitted that record; Twitter was the copy
        // of the contract that had drifted, which is what happens to a rule
        // written out ten times. It is now written out once.
        Ok(seance_sqlite_util::process_named_sqlite_db(
            artifact,
            "twitter",
            kind.incomplete_type(),
            "Twitter",
            |path, case_id, parent_id| match kind {
                Kind::Main => parse_main(path, owner, case_id, parent_id),
                Kind::Search => parse_search(path, case_id, parent_id),
            },
        ))
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Main,
    Search,
}

impl Kind {
    /// The marker record type for this walk. The two walks emit different
    /// record types (`TwitterDM` vs `TwitterSearch`), so their markers must
    /// differ too or a search-history failure joins the DM conversation
    /// grouping.
    fn incomplete_type(self) -> &'static str {
        match self {
            Kind::Main => INCOMPLETE_TYPE,
            Kind::Search => SEARCH_INCOMPLETE_TYPE,
        }
    }
}

/// `<digits>-search.db` is the search history; `<digits>-<digits>.db` is the
/// per-account main DB. Anything else is not ours.
fn classify(base: &str) -> Option<Kind> {
    let stem = base.strip_suffix(".db")?;
    if let Some(uid) = stem.strip_suffix("-search") {
        return uid
            .chars()
            .all(|c| c.is_ascii_digit())
            .then_some(Kind::Search);
    }
    let (uid, nn) = stem.split_once('-')?;
    if !uid.is_empty()
        && uid.chars().all(|c| c.is_ascii_digit())
        && !nn.is_empty()
        && nn.chars().all(|c| c.is_ascii_digit())
    {
        Some(Kind::Main)
    } else {
        None
    }
}

/// Open the staged copy, or say why this identified store could not be read.
///
/// The caller has already established that the file carried the SQLite header
/// and is named the way Twitter names its per-account databases, so a copy that
/// will not open is a store this tool did not examine — never an account with
/// no DMs. Returning `Err` here hands the caller the marker to emit.
fn open_or_report(
    path: &Path,
    kind: Kind,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<Connection, Vec<Artifact>> {
    let conn = open_readonly(path).map_err(|e| {
        vec![unreadable_store_marker(
            case_id,
            parent_id,
            kind.incomplete_type(),
            format!("the staged Twitter database would not open: {e}"),
        )]
    })?;
    // A corrupt or partially carved store answers every catalogue query with
    // SQLITE_CORRUPT. Read that as "no conversation_entries table" and the case
    // file says this account had no Direct Messages — a positive claim about a
    // device manufactured out of a read error (B8-015).
    probe_catalogue(&conn).map_err(|e| {
        vec![unreadable_store_marker(
            case_id,
            parent_id,
            kind.incomplete_type(),
            format!("the Twitter schema catalogue would not read: {e}"),
        )]
    })?;
    Ok(conn)
}

/// Three answers about a table, never two.
///
/// `Absent` is a finding about the evidence and means this file is not the
/// Twitter schema we are looking for, so the parser is silent. `Undetermined`
/// is a fact about this tool and must be reported: it was collapsed into
/// `false` here by an `unwrap_or(false)`-shaped helper, which made a damaged
/// store and a foreign one render identically.
fn require_table(
    conn: &Connection,
    table: &str,
    kind: Kind,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<bool, Vec<Artifact>> {
    // `probe_table` counts views as present: a schema that exposes its rows
    // through a compatibility view answered `type='table'` with "no such
    // table", and the walk that depends on it produced nothing while the case
    // read as a device with no records of this kind.
    match probe_table(conn, table) {
        Presence::Present => Ok(true),
        Presence::Absent => Ok(false),
        Presence::Undetermined(why) => Err(vec![unreadable_store_marker(
            case_id,
            parent_id,
            kind.incomplete_type(),
            format!("whether the Twitter `{table}` table exists could not be established: {why}"),
        )]),
    }
}

/// Best-effort text from a serialized `data` BLOB. Twitter DM bodies are a
/// protobuf whose text is a length-delimited string field; the shared
/// [`recover_protobuf_text`](seance_core::blob_text::recover_protobuf_text)
/// helper recovers it cleanly (correct UTF-8, no framing) and is labelled a
/// best-effort recovery on the record.
fn text_from_blob(blob: &[u8]) -> Option<String> {
    seance_core::blob_text::recover_protobuf_text(blob)
}

fn parse_main(path: &Path, owner: Option<i64>, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    let conn = match open_or_report(path, Kind::Main, case_id, parent_id) {
        Ok(c) => c,
        Err(marker) => return marker,
    };
    // The DM table is conversation_entries; some versions also carry a `messages`
    // table. Require conversation_entries to treat this as a Twitter main DB.
    match require_table(
        &conn,
        "conversation_entries",
        Kind::Main,
        case_id,
        parent_id,
    ) {
        // Genuinely not the Twitter DM schema: silence. Filing an incompleteness
        // finding against every database this parser does not recognise teaches
        // the examiner to skip the findings that matter.
        Ok(false) => return Vec::new(),
        Ok(true) => {}
        Err(marker) => return marker,
    }

    // Schema-drift defence: the store's version against the validated window,
    // then each table's columns against the names the parser knows. Findings,
    // filed beside the records; never a reason to stop the walk. A renamed
    // `created` or `conversation_id` used to end the walk with an empty list —
    // silence indistinguishable from an account with no DMs.
    let mut markers = Vec::new();
    markers.extend(schema_version_marker(&conn, case_id, parent_id));
    let entries = match resolve_or_report(
        &conn,
        MAIN_SCHEMA_APP,
        "conversation_entries",
        ENTRY_FIELDS,
        Kind::Main,
        case_id,
        parent_id,
    ) {
        Ok(f) => f,
        Err(marker) => return marker,
    };
    let body = match resolve_or_report(
        &conn,
        MAIN_SCHEMA_APP,
        "conversation_entries",
        ENTRY_BODY_FIELDS,
        Kind::Main,
        case_id,
        parent_id,
    ) {
        Ok(f) => f,
        Err(marker) => return marker,
    };
    let convo = entries.col("conversation_id");
    let sender = entries.col("sender_id");
    let created = entries.col("created");
    let entry_id = entries.col_or("entry_id", "rowid");
    let entry_type = entries.col("entry_type");
    // Text is usually inside a serialized `data`/`request_body` blob; a plain
    // `text` column exists on some versions.
    let text_col = body.col("text");
    let data_col = body.col("data");

    let sql = format!(
        "SELECT {entry_id}, {convo}, {sender}, {created}, {entry_type}, {text_col}, {data_col} \
         FROM conversation_entries ORDER BY {convo}, {created}"
    );
    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an account
    // with no DMs (HUNT-189). The schema findings already made travel with it.
    let query_failed = |e: rusqlite::Error, markers: Vec<Artifact>| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            INCOMPLETE_TYPE,
            "conversation_entries",
            &e.to_string(),
        )];
        out.extend(entries.drift_marker(case_id, parent_id, 0));
        out.extend(markers);
        out
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e, markers),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<i64>>(0).unwrap_or(None),
            r.get::<_, Option<String>>(1).unwrap_or(None),
            r.get::<_, Option<i64>>(2).unwrap_or(None),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
            r.get::<_, Option<i64>>(4).unwrap_or(None),
            r.get::<_, Option<String>>(5).unwrap_or(None),
            r.get::<_, Option<Vec<u8>>>(6).unwrap_or(None),
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e, markers),
    };

    let (names, name_drops, name_drift) = user_names(&conn, case_id, parent_id);
    markers.extend(name_drift);
    let mut out = Vec::new();
    // Rows the query returned that could not be decoded. `flatten()` used to
    // swallow these, so the DM count read as exact (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (eid, conversation_id, sender_id, created_ts, etype, text, data_blob) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Twitter: skipping undecodable conversation_entries row: {}",
                    e
                );
                drops.record(&e);
                continue;
            }
        };
        let date = created_ts.and_then(unix_seconds_from_magnitude);
        // A plain `text` column is authoritative; otherwise the body is a
        // best-effort recovery from the serialized protobuf `data` blob and is
        // flagged as such so an analyst never mistakes it for a verbatim field.
        let (body, text_recovered) = match text {
            Some(t) if !t.is_empty() => (Some(t), false),
            _ => (data_blob.as_deref().and_then(text_from_blob), true),
        };
        // A genuine `false` — the body came from a real `text` column — is a
        // finding and survives the shell's null-dropping.
        let text_recovered = text_recovered && body.is_some();
        // There is no stored direction flag: it is computed from the account
        // owner id in the filename against the row's sender. Without either,
        // it was never established, and the shared shell then omits both
        // `is_from_me` and `direction` rather than writing a null.
        let is_from_me = match (sender_id, owner) {
            (Some(s), Some(o)) => Some(s == o),
            _ => None,
        };
        let screen = sender_id.and_then(|s| {
            names
                .iter()
                .find(|(id, _)| *id == s)
                .map(|(_, n)| n.clone())
        });

        // "(dm)" rather than the derived "(no text)": on this store an entry
        // with no body is usually a non-message conversation entry, and the
        // label should not imply a message that said nothing.
        let preview = body
            .as_deref()
            .unwrap_or("(dm)")
            .chars()
            .take(60)
            .collect::<String>();
        let msg = ChatMessage::new("TwitterDM", "Twitter/X DM", "Android")
            .text(body)
            .date_secs(date)
            .from_me(is_from_me)
            .chat_identifier(conversation_id.clone())
            .contact(screen.clone())
            .extras([
                ("source_table", json!("conversation_entries")),
                ("entry_id", json!(eid)),
                ("conversation_id", json!(conversation_id)),
                ("sender_id", json!(sender_id.map(|s| s.to_string()))),
                ("sender_screen_name", json!(screen)),
                ("entry_type", json!(etype)),
                ("text_recovered", json!(text_recovered)),
            ]);
        let display = format!("{}: {preview}", msg.direction().unwrap_or("dm"));
        out.push(msg.display(display).into_artifact(case_id, parent_id));
    }
    // Counted before either marker joins the list, so a marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        "conversation_entries",
        recovered,
    ));
    out.extend(name_drops.marker(
        case_id,
        parent_id,
        "TwitterUserIncomplete",
        "users",
        names.len(),
    ));
    out.extend(entries.drift_marker(case_id, parent_id, recovered));
    if body.map.column("text").is_none() && body.map.column("data").is_none() {
        out.extend(body.drift_marker(case_id, parent_id, recovered));
    }
    // The search history this account's main store keeps (HUNT-191).
    out.extend(main_store_searches(&conn, case_id, parent_id));
    out.extend(markers);
    out
}

/// The `search_queries` table inside the per-account main store.
///
/// Both real per-account stores held — plaso's `twitter_android.db`
/// (user_version 7, one search) and the Magnet 2022 CTF Pixel 3
/// `1489429766507835392-61.db` (user_version 59, two) — keep the search history
/// here, and no `<uid>-search.db` exists in any corpus held; reading only the
/// latter left every real search unextracted (HUNT-191). The columns read are
/// the ones the `-search.db` walk reads (`time`, `query`), which both real main
/// stores carry, so the records are the same `TwitterSearch` shape. The table's
/// version is the main store's, so its drift is filed under the main schema.
///
/// Absent is a finding (this build of the app kept no search table) and owes
/// nothing; every could-not-look is a `TwitterSearchIncomplete` marker naming
/// SQLite's error, never an empty search history.
fn main_store_searches(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    match probe_table(conn, "search_queries") {
        Presence::Present => {}
        Presence::Absent => return Vec::new(),
        Presence::Undetermined(why) => {
            return vec![unreadable_store_marker(
                case_id,
                parent_id,
                SEARCH_INCOMPLETE_TYPE,
                format!(
                    "whether the main Twitter store holds a `search_queries` table could not \
                     be established: {why}"
                ),
            )]
        }
    }
    let fields = match resolve_or_report(
        conn,
        MAIN_SCHEMA_APP,
        "search_queries",
        SEARCH_FIELDS,
        Kind::Search,
        case_id,
        parent_id,
    ) {
        Ok(f) => f,
        Err(marker) => return marker,
    };
    let unread = |what: &str, e: rusqlite::Error| {
        vec![unreadable_store_marker(
            case_id,
            parent_id,
            SEARCH_INCOMPLETE_TYPE,
            format!("the main Twitter store's `search_queries` {what}: {e}"),
        )]
    };
    let time = fields.col("time");
    let query = fields.col("query");
    let sql = format!("SELECT {time}, {query} FROM search_queries ORDER BY {time} DESC");
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return unread("query would not prepare", e),
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?))
    }) {
        Ok(rows) => rows,
        Err(e) => return unread("query would not run", e),
    };
    let mut out = Vec::new();
    // A row that would not decode is a search this device performed and the
    // case would no longer show; it is counted (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        match row {
            Ok((t, Some(q))) => out.push(search_record(case_id, parent_id, t, q)),
            Ok((_, None)) => {}
            Err(e) => {
                debug!("Twitter: skipping undecodable main-store search_queries row: {e}");
                drops.record(&e);
            }
        }
    }
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        SEARCH_INCOMPLETE_TYPE,
        "search_queries",
        recovered,
    ));
    out.extend(fields.drift_marker(case_id, parent_id, recovered));
    out
}

/// One `TwitterSearch` record, whichever store the row came from.
fn search_record(case_id: Uuid, parent_id: Uuid, time: Option<i64>, query: String) -> Artifact {
    let metadata = json!({
        "type": "TwitterSearch",
        "subtype": "search",
        "platform": "Android",
        "source_table": "search_queries",
        "service": "Twitter/X",
        "query": query,
        "date": time.and_then(unix_seconds_from_magnitude),
        "name": format!("search: {}", query.chars().take(60).collect::<String>()),
    });
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(parent_id)
        .with_subtype("search")
}

/// (user_id, @screen_name) from the `users` table, for sender resolution.
///
/// Returns the pairs alongside the `users` rows that would not decode. A lost
/// row is a lost identity: the DMs that account sent are then attributed to a
/// bare numeric id with nothing to say the handle was on the device but
/// unreadable (B3-023).
///
/// The third element is the one record about the lookup itself — schema drift
/// in `users`, or a table, column list or query that would not read: the DMs
/// are then attributed by numeric id, and the marker says why.
fn user_names(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> (Vec<(i64, String)>, RowDrops, Option<Artifact>) {
    // An absent `users` table is a store shape: the DMs are attributed by
    // numeric id and nothing is owed. A `users` table that could not be looked
    // for, or whose column list would not read, is "could not look" — the DMs
    // still walk by numeric id, and a `TwitterUserIncomplete` record says the
    // handles were not looked up, never that there were none (HUNT-224).
    let could_not_look = |detail: String| {
        (
            Vec::new(),
            RowDrops::new(),
            Some(unreadable_store_marker(
                case_id,
                parent_id,
                "TwitterUserIncomplete",
                detail,
            )),
        )
    };
    match probe_table(conn, "users") {
        Presence::Present => {}
        Presence::Absent => return (Vec::new(), RowDrops::new(), None),
        Presence::Undetermined(why) => {
            return could_not_look(format!(
                "whether the main Twitter store holds a `users` table could not be established, \
                 so DM senders are shown by numeric id: {why}"
            ))
        }
    }
    let users = match Fields::resolve(conn, MAIN_SCHEMA_APP, "users", USER_FIELDS) {
        Ok(users) => users,
        Err(why) => {
            return could_not_look(format!(
                "the Twitter `users` table is present and its column list would not read, so \
                 DM senders are shown by numeric id and no handle was looked up: {why}"
            ))
        }
    };
    let drift = users.drift_marker(case_id, parent_id, 0);
    if !users.map.all_resolved() {
        return (Vec::new(), RowDrops::new(), drift);
    }
    let id = users.col("user_id");
    let screen = users.col("screen_name");
    let sql = format!("SELECT {id}, {screen} FROM users WHERE {screen} IS NOT NULL");
    // `users` and both its columns are there, so a statement that will not
    // prepare or run leaves every DM attributed by bare numeric id; the record
    // says the handles were on the device and unread (HUNT-189).
    let query_failed = |e: rusqlite::Error| {
        Some(query_failed_marker(
            case_id,
            parent_id,
            "TwitterUserIncomplete",
            "users",
            &e.to_string(),
        ))
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return (Vec::new(), RowDrops::new(), query_failed(e)),
    };
    // Errors propagate out of the closure instead of being flattened to `None`
    // by `unwrap_or(None)`: a handle stored with an unexpected column type is a
    // row that could not be decoded, and collapsing it into a NULL would make it
    // indistinguishable from a row that genuinely had no handle — the drop would
    // then be uncountable (B3-023).
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return (Vec::new(), RowDrops::new(), query_failed(e)),
    };
    let mut out = Vec::new();
    let mut drops = RowDrops::new();
    for row in rows {
        match row {
            // A NULL id or handle is a genuinely empty row, not a decode
            // failure: skip it without counting it as dropped.
            Ok((Some(a), Some(b))) => out.push((a, b)),
            Ok(_) => {}
            Err(e) => {
                debug!("Twitter: skipping undecodable users row: {}", e);
                drops.record(&e);
            }
        }
    }
    (out, drops, None)
}

/// The account owner id is the numeric prefix of the DB filename. We recover it
/// from a `users`/owner marker when possible; otherwise direction stays unknown.
/// Account-owner id from the original DB basename (`<ownerId>-<NN>.db`). Taken
/// from the evidence filename, not the temp path the bytes are copied to.
fn owner_id_from_base(base: &str) -> Option<i64> {
    let stem = base.strip_suffix(".db").unwrap_or(base);
    let uid = stem.split('-').next()?;
    uid.parse::<i64>().ok()
}

fn parse_search(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    let conn = match open_or_report(path, Kind::Search, case_id, parent_id) {
        Ok(c) => c,
        Err(marker) => return marker,
    };
    match require_table(&conn, "search_queries", Kind::Search, case_id, parent_id) {
        Ok(false) => return Vec::new(),
        Ok(true) => {}
        Err(marker) => return marker,
    }
    // No version window for the search store (none has been observed), so the
    // column map is the whole defence here.
    let fields = match resolve_or_report(
        &conn,
        SEARCH_SCHEMA_APP,
        "search_queries",
        SEARCH_FIELDS,
        Kind::Search,
        case_id,
        parent_id,
    ) {
        Ok(f) => f,
        Err(marker) => return marker,
    };
    let time = fields.col("time");
    let query = fields.col("query");
    let sql = format!("SELECT {time}, {query} FROM search_queries ORDER BY {time} DESC");
    // The table and its columns are established, so a statement that will not
    // prepare or run is a search history this tool could not read — never an
    // empty one (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            SEARCH_INCOMPLETE_TYPE,
            "search_queries",
            &e.to_string(),
        )];
        out.extend(fields.drift_marker(case_id, parent_id, 0));
        out
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<i64>>(0).unwrap_or(None),
            r.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };
    let mut out = Vec::new();
    // Same tally for the search history: a dropped row is a search this device
    // performed and the case no longer shows (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (t, q) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Twitter: skipping undecodable search_queries row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        let Some(q) = q else { continue };
        out.push(search_record(case_id, parent_id, t, q));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        SEARCH_INCOMPLETE_TYPE,
        "search_queries",
        recovered,
    ));
    out.extend(fields.drift_marker(case_id, parent_id, recovered));
    out
}

#[cfg(test)]
mod tests {
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
    use super::*;
    // `process()` reaches SQLite through the shared entry gate, so the parser
    // itself no longer names `TempDb`. These tests drive `parse_main` /
    // `parse_search` directly off a staged copy, so they still do.
    use seance_sqlite_util::TempDb;
    use std::fs;

    #[test]
    fn classifies_db_filenames() {
        assert!(matches!(
            classify("921137666602819584-66.db"),
            Some(Kind::Main)
        ));
        assert!(matches!(
            classify("921137666602819584-search.db"),
            Some(Kind::Search)
        ));
        assert!(classify("msgstore.db").is_none());
        assert!(classify("cache4.db").is_none());
        assert!(classify("direct.db").is_none());
    }

    /// A protobuf-ish `data` blob like the real one: a timestamp run, then the
    /// message text in a length-delimited field. The parser must recover the
    /// text, not the digits.
    fn dm_blob(text: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x0d); // non-printable separator
        v.extend_from_slice(b"172029765556800"); // embedded timestamp (digits)
        v.push(0x00);
        v.push(0x6a); // protobuf tag for the text field
        v.push(text.len() as u8);
        v.extend_from_slice(text.as_bytes());
        v.push(0x00);
        v
    }

    #[test]
    fn parses_dm_and_search_via_discovery() {
        let dir = std::env::temp_dir().join(format!("twtest_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        // Main DB: real conversation_entries schema (text lives in `data`) + users.
        let main = dir.join("100-66.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 59;
             CREATE TABLE users(user_id INTEGER, username TEXT, name TEXT);
             INSERT INTO users VALUES (100,'me_owner','Me'),(200,'friend_x','Friend');
             CREATE TABLE conversation_entries(
               _id INTEGER, entry_id INTEGER, sort_entry_id INTEGER,
               conversation_id TEXT, user_id INTEGER, created INTEGER,
               entry_type INTEGER, data BLOB, request_id TEXT, linked_entry_id INTEGER);",
        )
        .unwrap();
        c.execute(
            "INSERT INTO conversation_entries(entry_id,conversation_id,user_id,created,entry_type,data) \
             VALUES (1,'100-200',100,1720000000000,0,?1)",
            rusqlite::params![dm_blob("What's up?!")],
        )
        .unwrap();
        c.execute(
            "INSERT INTO conversation_entries(entry_id,conversation_id,user_id,created,entry_type,data) \
             VALUES (2,'100-200',200,1720000005000,0,?1)",
            rusqlite::params![dm_blob("Not much, you?")],
        )
        .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        // The owner id comes from the original filename (`100-66.db`); the parser
        // is handed it explicitly rather than re-deriving it from the temp path.
        assert_eq!(owner_id_from_base("100-66.db"), Some(100));
        let tmp = TempDb::write(&content, "twitter").unwrap();
        let msgs = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(msgs.len(), 2);
        // Text recovered from the protobuf blob, not the timestamp digits.
        assert_eq!(msgs[0].metadata["text"], "What's up?!");
        assert_eq!(msgs[0].metadata["date"], 1_720_000_000); // ms -> s
        assert_eq!(msgs[0].metadata["is_from_me"], true); // sender 100 == owner
        assert_eq!(msgs[0].metadata["sender_screen_name"], "me_owner");
        assert_eq!(msgs[1].metadata["text"], "Not much, you?");
        assert_eq!(msgs[1].metadata["is_from_me"], false);
        assert_eq!(msgs[1].metadata["sender_screen_name"], "friend_x");

        // Search DB.
        let search = dir.join("100-search.db");
        let c = Connection::open(&search).unwrap();
        c.execute_batch(
            "CREATE TABLE search_queries(time INTEGER, query TEXT);
             INSERT INTO search_queries VALUES (1720000000000,'dfir'),(1720000009000,'forensics');",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&search).unwrap();
        let tmp = TempDb::write(&content, "twitter").unwrap();
        let searches = parse_search(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(searches.len(), 2);
        assert_eq!(searches[0].metadata["query"], "forensics"); // DESC by time

        let _ = fs::remove_dir_all(&dir);
    }

    /// An unset (0) timestamp is an absent key, never 1970-01-01.
    #[test]
    fn zero_timestamps_are_absent_not_1970() {
        assert_eq!(unix_seconds_from_magnitude(0), None);
        assert_eq!(unix_seconds_from_magnitude(-1), None);
        assert_eq!(
            unix_seconds_from_magnitude(1_720_000_000_000),
            Some(1_720_000_000)
        );

        let dir = std::env::temp_dir().join(format!("twzero_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("100-66.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,0,0,'undated dm');
             CREATE TABLE search_queries(time INTEGER, query TEXT);
             INSERT INTO search_queries VALUES (0,'undated search');",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        let tmp = TempDb::write(&content, "twitter").unwrap();
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        // The main store's own `search_queries` is read too (HUNT-191), so the
        // DM and the search are told apart by type.
        let msgs: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0].metadata["date"].is_null(),
            "unset date stays absent"
        );
        let main_searches: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterSearch"))
            .collect();
        assert_eq!(main_searches.len(), 1);
        assert!(main_searches[0].metadata["date"].is_null());

        let searches = parse_search(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(searches.len(), 1);
        assert!(searches[0].metadata["date"].is_null());

        let _ = fs::remove_dir_all(&dir);
    }
    /// One-DM main database, as bytes.
    fn dm_db_bytes() -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("twshort_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("100-66.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 59;
             CREATE TABLE users(user_id INTEGER, username TEXT, name TEXT);
             INSERT INTO users VALUES (100,'me_owner','Me'),(200,'friend_x','Friend');
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, data BLOB);",
        )
        .unwrap();
        c.execute(
            "INSERT INTO conversation_entries(entry_id,conversation_id,user_id,created,entry_type,data) \
             VALUES (1,'100-200',200,1720000000000,0,?1)",
            rusqlite::params![dm_blob("only surviving dm")],
        )
        .unwrap();
        drop(c);
        let bytes = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        bytes
    }

    fn run_source(ds: std::sync::Arc<dyn seance_core::data_source::DataSource>) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "100-66.db" }),
        );
        TwitterParser.process(&art).unwrap()
    }

    /// B2-124: the database was staged without comparing what came back against
    /// what the source declared, so a truncated DM store parsed as a complete
    /// one. What an examiner learns: whether the DMs on screen are the whole
    /// conversation, or the part that happened to be readable.
    #[test]
    fn a_short_read_marks_every_record_it_produced() {
        let out = run_source(std::sync::Arc::new(truncated(dm_db_bytes())));
        let dm = out
            .iter()
            .find(|a| a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("chat_message"))
            .expect("the readable prefix still parses");
        assert_eq!(dm.metadata["content_incomplete"], true);
        assert_eq!(dm.metadata["content_incomplete_reason"], "short_read");
        assert!(
            out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("DatabaseNotStagedInFull")),
            "a partial spill must be reported in its own right"
        );
    }

    /// The counterpart: a database read whole must stay unmarked, and a source
    /// that answers in small chunks is a whole database, not a non-SQLite file.
    #[test]
    fn a_chunked_but_complete_source_is_parsed_without_marks() {
        let out = run_source(std::sync::Arc::new(DribbleSource::new(dm_db_bytes(), 4)));
        assert_eq!(out.len(), 1, "a chunked source is not a non-SQLite file");
        assert!(out[0].metadata.get("content_incomplete").is_none());
    }

    /// `<userId>-<NN>.db` is Twitter's own naming, so a file with that name and
    /// the SQLite header is a Twitter store. One whose pages will not read is a
    /// store this tool did not examine — not an account with no Direct
    /// Messages.
    ///
    /// Twitter was the copy of this contract that had drifted: `has_table`
    /// collapsed `Presence::Undetermined` into `false`, so a corrupt store took
    /// the "not a Twitter schema" exit and produced nothing at all (B8-015).
    #[test]
    fn a_corrupt_main_db_is_reported_rather_than_returning_nothing() {
        let mut bytes = dm_db_bytes();
        // Keep the header so the pre-spill probe still admits the file, then
        // destroy the pages behind it.
        for b in bytes.iter_mut().skip(16) {
            *b = 0xFF;
        }
        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(bytes),
        ));
        assert!(
            !out.is_empty(),
            "an unreadable Twitter store must not render as an account with no DMs"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!(INCOMPLETE_TYPE))
            .expect("a store that would not read must be declared");
        assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        // Never the walk's own record type: `seance_db` groups conversations by
        // `metadata.$.type`, so `TwitterDM` here would be a phantom thread.
        assert_ne!(marker.metadata["type"], json!("TwitterDM"));
    }

    /// The same rule for the search-history database, under its own marker
    /// type. Sharing `TwitterIncomplete` would file a search-history failure
    /// into the DM conversation grouping.
    #[test]
    fn a_corrupt_search_db_is_reported_under_its_own_record_type() {
        let dir = std::env::temp_dir().join(format!("twsearchbad_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("100-search.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE search_queries(time INTEGER, query TEXT);
             INSERT INTO search_queries VALUES (1720000000000,'dfir');",
        )
        .unwrap();
        drop(c);
        let mut bytes = fs::read(&path).unwrap();
        let _ = fs::remove_dir_all(&dir);
        for b in bytes.iter_mut().skip(16) {
            *b = 0xFF;
        }

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(std::sync::Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(bytes),
            )),
            json!({ "name": "100-search.db" }),
        );
        let out = TwitterParser.process(&art).unwrap();
        assert!(
            out.iter()
                .any(|a| a.metadata["type"] == json!(SEARCH_INCOMPLETE_TYPE)),
            "an unreadable search store must be declared under its own type"
        );
    }

    /// The counterpart to both: a perfectly readable SQLite file that simply is
    /// not a Twitter schema must still produce nothing. A module that files an
    /// incompleteness finding against every database it does not recognise
    /// teaches the examiner to skip the findings that matter.
    #[test]
    fn a_readable_non_twitter_database_reports_nothing() {
        let dir = std::env::temp_dir().join(format!("twother_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("100-66.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE unrelated(id INTEGER PRIMARY KEY, v TEXT); \
             INSERT INTO unrelated VALUES (1,'x');",
        )
        .unwrap();
        drop(c);
        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_dir_all(&dir);

        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(bytes),
        ));
        assert!(
            out.is_empty(),
            "an unrecognised schema is not an incompleteness finding"
        );
    }

    /// The record shell is the shared one, so an unestablished direction is
    /// omitted rather than written as JSON `null`. This plugin wrote null,
    /// because a `json!` literal cannot leave a field out — and a consumer that
    /// reads `is_from_me` with a boolean default turns that into "received".
    #[test]
    fn an_unestablished_direction_is_omitted_from_the_record() {
        let bytes = dm_db_bytes();
        let tmp = TempDb::write(&bytes, "twitter").unwrap();
        // No owner id: direction cannot be computed from sender alone.
        let msgs = parse_main(tmp.path(), None, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].metadata.get("is_from_me").is_none());
        assert!(msgs[0].metadata.get("direction").is_none());
        // A genuine `false` still survives: the body came from a real column or
        // it did not, and that is a finding.
        assert_eq!(msgs[0].metadata["text_recovered"], json!(true));
    }

    // --- Schema-drift defence (ROADMAP §1.4a) -------------------------------

    /// The marker records this parse emitted about the schema itself.
    fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
        result
            .iter()
            .filter(|a| a.metadata["type"] == "ParserStaleWarning")
            .collect()
    }

    /// A main database from `sql`, staged the way `process` stages one.
    fn staged(sql: &str) -> TempDb {
        let dir = std::env::temp_dir().join(format!("twdrift_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("100-66.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        let bytes = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        TempDb::write(&bytes, "twitter").unwrap()
    }

    /// The `DatabaseUnreadable` records of type `ty` in `out`.
    fn query_unreadable<'a>(out: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
        out.iter()
            .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
            .filter(|a| a.metadata["type"] == json!(ty))
            .collect()
    }

    /// Android declares its own collations (`LOCALIZED`) through the framework,
    /// not stock SQLite, so a table whose sort column carries one lists its
    /// columns and then refuses any statement that sorts on it. SQLite will not
    /// CREATE such a table, so the catalogue is edited after the real rows go in.
    fn with_localized(table: &str, column_decl: &str) -> String {
        format!(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_master SET sql = replace(sql, '{column_decl}', '{column_decl} COLLATE LOCALIZED')
               WHERE name = '{table}';
             PRAGMA writable_schema = OFF;"
        )
    }

    /// HUNT-189: `conversation_entries` found and its columns resolved, and a
    /// statement that would not prepare returned an empty list — an account
    /// with no DMs, as far as the case file could tell.
    #[test]
    fn a_conversation_entries_query_that_will_not_run_is_reported_unreadable_not_empty() {
        let tmp = staged(&format!(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, data BLOB);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,NULL);
             {}",
            with_localized("conversation_entries", "created INTEGER")
        ));
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        assert!(!out.iter().any(|a| a.metadata["type"] == json!("TwitterDM")));
        let v = query_unreadable(&out, INCOMPLETE_TYPE);
        assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
        assert_eq!(v[0].metadata["source_table"], json!("conversation_entries"));
        assert!(v[0].metadata["sqlite_error"]
            .as_str()
            .unwrap()
            .contains("LOCALIZED"));
    }

    /// HUNT-189, the secondary lookup: a `users` table present with both its
    /// columns, whose query will not run (here a view that sorts under the
    /// framework-only collation), left every DM attributed by bare numeric id
    /// with nothing to say the handles were on the device and unread.
    #[test]
    fn a_users_query_that_will_not_run_is_reported_not_silently_unresolved() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'hi');
             CREATE TABLE users_store(user_id INTEGER, username TEXT, name TEXT);
             INSERT INTO users_store VALUES (200, 'alice', 'Alice');
             CREATE VIEW users AS SELECT user_id, username, name FROM users_store
               ORDER BY username COLLATE LOCALIZED;",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1, "the DMs still walk: {out:?}");
        let v = query_unreadable(&out, "TwitterUserIncomplete");
        assert_eq!(
            v.len(),
            1,
            "no DatabaseUnreadable record for `users`: {out:?}"
        );
        assert_eq!(v[0].metadata["source_table"], json!("users"));
    }

    /// HUNT-224: a `users` view whose base table is gone is listed in the
    /// catalogue and will not answer `PRAGMA table_info`, so `Fields::resolve`
    /// failed and the lookup returned empty: every DM attributed by numeric id
    /// with nothing to say the handles could not be looked for.
    #[test]
    fn a_users_column_list_that_will_not_read_is_reported_not_silently_unresolved() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'hi');
             CREATE TABLE users_store(user_id INTEGER, username TEXT, name TEXT);
             CREATE VIEW users AS SELECT user_id, username, name FROM users_store;
             DROP TABLE users_store;",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1, "the DMs still walk: {out:?}");
        let v: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterUserIncomplete"))
            .collect();
        assert_eq!(v.len(), 1, "no TwitterUserIncomplete record: {out:?}");
        assert_eq!(v[0].metadata["status"], json!("StoreUnreadable"));
        assert!(v[0].metadata["detail"].as_str().unwrap().contains("users"));
    }

    /// The control: a main store with no `users` table is a store shape, and
    /// carries no `users` marker.
    #[test]
    fn a_main_store_without_a_users_table_carries_no_users_marker() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'hi');",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        assert!(
            !out.iter()
                .any(|a| a.metadata["type"] == json!("TwitterUserIncomplete")),
            "{out:?}"
        );
    }

    /// HUNT-189: `search_queries` found and its columns resolved, and a
    /// statement that would not prepare returned an empty list.
    #[test]
    fn a_search_queries_query_that_will_not_run_is_reported_unreadable_not_empty() {
        let tmp = staged(&format!(
            "CREATE TABLE search_queries(time INTEGER, query TEXT);
             INSERT INTO search_queries VALUES (1720000000000, 'forensics');
             {}",
            with_localized("search_queries", "time INTEGER")
        ));
        let out = parse_search(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        assert!(!out
            .iter()
            .any(|a| a.metadata["type"] == json!("TwitterSearch")));
        let v = query_unreadable(&out, SEARCH_INCOMPLETE_TYPE);
        assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
        assert_eq!(v[0].metadata["source_table"], json!("search_queries"));
    }

    /// A per-account database whose `PRAGMA user_version` is newer than any
    /// this parser was validated against says so beside the DMs it still
    /// recovers.
    #[test]
    fn a_main_db_schema_version_outside_the_validated_range_is_declared_and_dms_still_parse() {
        let tmp = staged(
            "PRAGMA user_version = 99;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'still parsed');",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        let m = markers[0];
        assert_eq!(m.metadata["app"], MAIN_SCHEMA_APP);
        assert_eq!(m.metadata["seen_schema_version"], 99);
        assert_eq!(
            m.metadata["supported_range"],
            SUPPORTED_MAIN_SCHEMA.describe()
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
        // HUNT-204: the range names the real stores its endpoints came from.
        let evidence = m.metadata["validated_against"].as_str().unwrap_or_default();
        assert!(
            evidence.contains("twitter_android.db") && evidence.contains("-61.db"),
            "the range carries no evidence-file name: {}",
            m.metadata
        );
        assert_ne!(
            m.metadata["type"],
            json!("TwitterDM"),
            "never the walk's own type"
        );
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1);
        assert_eq!(dms[0].metadata["text"], "still parsed");
    }

    /// Inside the window, at both ends, no marker: the control that gives the
    /// marker its meaning.
    #[test]
    fn a_main_db_schema_version_inside_the_validated_range_carries_no_stale_marker() {
        for v in [
            SUPPORTED_MAIN_SCHEMA.min,
            SUPPORTED_MAIN_SCHEMA.max.unwrap(),
        ] {
            let tmp = staged(&format!(
                "PRAGMA user_version = {v};
                 CREATE TABLE conversation_entries(
                   entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
                   created INTEGER, entry_type INTEGER, data BLOB);"
            ));
            let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
            assert!(stale_markers(&out).is_empty(), "user_version {v}: {out:?}");
        }
    }

    /// `PRAGMA user_version` of 0 is SQLite's default for a store that never
    /// set one — the absence of a version, not "version 0". The parse is
    /// declared unranked, with nothing called incomplete.
    #[test]
    fn a_main_db_with_no_recorded_version_is_declared_unranked_not_older() {
        let tmp = staged(
            "CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, data BLOB);",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        assert_eq!(markers[0].metadata["status"], "SchemaVersionNotRecorded");
        assert!(markers[0].metadata.get("content_incomplete").is_none());
        // The range it states is one the evidence set, and says which.
        assert!(markers[0].metadata["validated_against"].is_string());
    }

    /// A renamed `conversation_entries` column is named by the logical field it
    /// carried, and the DMs still walk with that field absent. The old code
    /// returned an empty list here — silence indistinguishable from an account
    /// with no DMs.
    #[test]
    fn a_renamed_conversation_entries_column_is_declared_and_the_dms_still_walk() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               when_created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'undated dm');",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        let m = markers[0];
        assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(m.metadata["source_table"], "conversation_entries");
        assert_eq!(m.metadata["unresolved_fields"], json!(["created"]));
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1, "the DM is still walked");
        assert_eq!(dms[0].metadata["text"], "undated dm");
        assert!(dms[0].metadata.get("date").is_none_or(|d| d.is_null()));
        assert_eq!(dms[0].metadata["is_from_me"], false);
    }

    /// The body may sit in `text` or in the `data` protobuf, so one of them
    /// missing is a finding about the build, not drift. Both missing is drift,
    /// and both are named.
    #[test]
    fn a_store_with_neither_body_column_names_both_and_still_walks_the_entries() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, payload BLOB);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,x'00');",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        assert_eq!(
            markers[0].metadata["unresolved_fields"],
            json!(["text", "data"])
        );
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1, "the entry is still walked, bodiless");
        assert!(dms[0].metadata.get("text").is_none_or(|t| t.is_null()));
    }

    /// The `users` lookup has its own column set and its own marker: a renamed
    /// handle column leaves the DMs attributed by numeric id, and says so.
    #[test]
    fn a_renamed_users_column_is_declared_under_the_users_table() {
        let tmp = staged(
            "PRAGMA user_version = 59;
             CREATE TABLE users(user_id INTEGER, screen TEXT, name TEXT);
             INSERT INTO users VALUES (200,'friend_x','Friend');
             CREATE TABLE conversation_entries(
               entry_id INTEGER, conversation_id TEXT, user_id INTEGER,
               created INTEGER, entry_type INTEGER, text TEXT);
             INSERT INTO conversation_entries VALUES (1,'100-200',200,1720000000000,0,'hi');",
        );
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        assert_eq!(markers[0].metadata["source_table"], "users");
        assert_eq!(
            markers[0].metadata["unresolved_fields"],
            json!(["screen_name"])
        );
        let dms: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("TwitterDM"))
            .collect();
        assert_eq!(dms.len(), 1);
        assert_eq!(dms[0].metadata["sender_id"], "200");
        assert!(dms[0].metadata["sender_screen_name"].is_null());
    }

    /// No real `<userId>-search.db` has been observed, so no version window is
    /// declared for it and no version marker is filed; a renamed column is
    /// still named. (The two real per-account stores carry `search_queries`
    /// inside the main database instead.)
    #[test]
    fn the_search_db_declares_no_range_and_still_names_a_renamed_column() {
        let dir = std::env::temp_dir().join(format!("twsearchdrift_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("100-search.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE search_queries(time INTEGER, q TEXT);
             INSERT INTO search_queries VALUES (1720000000000,'dfir');",
        )
        .unwrap();
        drop(c);
        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let tmp = TempDb::write(&bytes, "twitter").unwrap();

        let out = parse_search(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        let markers = stale_markers(&out);
        assert_eq!(markers.len(), 1, "{out:?}");
        assert_eq!(markers[0].metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(markers[0].metadata["source_table"], "search_queries");
        assert_eq!(markers[0].metadata["unresolved_fields"], json!(["query"]));
        assert!(
            !out.iter()
                .any(|a| a.metadata["type"] == json!("TwitterSearch")),
            "a search with no query column is not a search record"
        );
    }

    /// `search_queries` exactly as both real per-account main stores declare it
    /// (the Magnet 2022 CTF Pixel 3 `1489429766507835392-61.db`, user_version
    /// 59; plaso's `twitter_android.db`, user_version 7, has the same columns
    /// up to `pc` and `cluster_titles` in place of the two suggestion blobs).
    const MAIN_STORE_SEARCH_SQL: &str = "CREATE TABLE search_queries (
            _id INTEGER PRIMARY KEY, type INTEGER, name TEXT NOT NULL, query TEXT NOT NULL,
            query_id INTEGER, time INTEGER, latitude REAL, longitude REAL, radius REAL,
            location TEXT, pc BLOB, priority INTEGER, user_search_suggestion BLOB,
            topic_search_suggestion BLOB, score REAL DEFAULT 0);
         INSERT INTO search_queries (_id, type, name, query, query_id, time, priority, score)
            VALUES (1, 0, 'illusions', 'illusions', -1033998862, 1644737085919, 3, 0.0),
                   (2, 0, 'minecraft', 'minecraft', 695073197, 1644737097459, 3, 0.0);";

    fn main_store_with(extra: &str) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("twmainsearch_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("100-61.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(&format!(
            "PRAGMA user_version = 59;
             CREATE TABLE users(user_id INTEGER, username TEXT, name TEXT);
             CREATE TABLE conversation_entries(
               _id INTEGER, entry_id INTEGER, sort_entry_id INTEGER,
               conversation_id TEXT, user_id INTEGER, created INTEGER,
               entry_type INTEGER, data BLOB, request_id TEXT, linked_entry_id INTEGER);
             {extra}"
        ))
        .unwrap();
        drop(c);
        let bytes = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        bytes
    }

    fn searches(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == json!("TwitterSearch"))
            .collect()
    }

    /// HUNT-191. Both real per-account stores keep `search_queries` inside the
    /// main `<uid>-<NN>.db`; no `<uid>-search.db` exists in any corpus held, so
    /// the search history was never extracted from real evidence.
    #[test]
    fn search_history_inside_the_main_store_is_extracted() {
        let tmp = TempDb::write(&main_store_with(MAIN_STORE_SEARCH_SQL), "twitter").unwrap();
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let s = searches(&out);
        assert_eq!(s.len(), 2, "{out:?}");
        // Newest first, as the `-search.db` walk orders them.
        assert_eq!(s[0].metadata["query"], "minecraft");
        assert_eq!(s[0].metadata["date"], 1_644_737_097);
        assert_eq!(s[1].metadata["query"], "illusions");
        assert_eq!(s[0].metadata["source_table"], "search_queries");
        assert!(stale_markers(&out).is_empty(), "{:?}", stale_markers(&out));
    }

    /// A main store without `search_queries` owes no search record and no
    /// marker: the catalogue answered.
    #[test]
    fn a_main_store_without_search_queries_owes_no_search_marker() {
        let tmp = TempDb::write(&main_store_with(""), "twitter").unwrap();
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        assert!(searches(&out).is_empty());
        assert!(!out
            .iter()
            .any(|a| a.metadata["type"] == json!(SEARCH_INCOMPLETE_TYPE)));
    }

    /// A main-store `search_queries` that is listed and cannot be queried is
    /// the search history unread — declared under the search marker type, with
    /// the DM walk unaffected.
    #[test]
    fn a_main_store_search_table_that_cannot_be_queried_is_declared() {
        let bytes = main_store_with(
            "CREATE TABLE sq (time INTEGER, query TEXT);
             CREATE VIEW search_queries AS SELECT time, query FROM sq;
             DROP TABLE sq;",
        );
        let tmp = TempDb::write(&bytes, "twitter").unwrap();
        let out = parse_main(tmp.path(), Some(100), Uuid::new_v4(), Uuid::new_v4());
        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!(SEARCH_INCOMPLETE_TYPE))
            .unwrap_or_else(|| panic!("the unread search history is declared: {out:?}"));
        assert_eq!(marker.metadata["content_incomplete"], true);
        assert!(marker.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("search_queries"));
    }

    /// The grade: the real stores' own search history. plaso's
    /// `twitter_android.db` (user_version 7) holds one search, "rosegold"; the
    /// Magnet 2022 CTF Pixel 3 `1489429766507835392-61.db` (user_version 59)
    /// holds two, "minecraft" then "illusions" newest first. Each file is
    /// skipped when absent, as the harness below does.
    #[test]
    fn real_main_stores_yield_their_search_history() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let corpus = std::env::var_os("SEANCE_APP_SCHEMA_CORPUS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| workspace.join("test_data").join("app_schema_corpus"));
        let cases: [(std::path::PathBuf, &[&str]); 2] = [
            (
                workspace.join("reference/plaso/test_data/twitter_android.db"),
                &["rosegold"],
            ),
            (
                corpus.join("android2022_tw_1489429766507835392-61.db"),
                &["minecraft", "illusions"],
            ),
        ];
        for (path, expected) in cases {
            if !path.exists() {
                assert!(
                    std::env::var_os("SEANCE_APP_SCHEMA_CORPUS_REQUIRED").is_none(),
                    "{} not found and SEANCE_APP_SCHEMA_CORPUS_REQUIRED is set",
                    path.display()
                );
                eprintln!("skipping {}: not found", path.display());
                continue;
            }
            let tmp = TempDb::write(&fs::read(&path).unwrap(), "twitter").unwrap();
            let out = parse_main(tmp.path(), None, Uuid::new_v4(), Uuid::new_v4());
            let got: Vec<&str> = searches(&out)
                .iter()
                .map(|a| a.metadata["query"].as_str().unwrap())
                .collect();
            assert_eq!(got, expected, "{}", path.display());
            // HUNT-224's control on real data: a readable `users` lookup is
            // never reported as one that could not be looked up.
            assert!(
                !out.iter()
                    .any(|a| a.metadata["type"] == json!("TwitterUserIncomplete")),
                "{}: a readable `users` table must carry no lookup marker",
                path.display()
            );
        }
    }

    /// The corpus-diff harness: every real per-account store this parser was
    /// validated against parses with no schema marker. Files outside the tree
    /// are skipped when absent; `SEANCE_APP_SCHEMA_CORPUS` names the directory
    /// holding the CTF-derived copies.
    #[test]
    fn real_twitter_stores_in_the_validated_range_carry_no_stale_marker() {
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
                workspace.join("reference/plaso/test_data/twitter_android.db"),
                None,
                7,
                expect("plaso test_data/twitter_android.db DMs (user_version 7)", 1),
            ),
            (
                corpus.join("android2022_tw_1489429766507835392-61.db"),
                Some(1489429766507835392),
                59,
                expect(
                    "Magnet 2022 CTF Pixel 3 1489429766507835392-61.db DMs (user_version 59)",
                    0,
                ),
            ),
            (
                corpus.join("android2022_tw_0-61.db"),
                Some(0),
                59,
                expect("Magnet 2022 CTF Pixel 3 0-61.db DMs (user_version 59)", 0),
            ),
        ];
        let mut checked = 0;
        for (path, owner, version, expect) in expectations {
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
                SUPPORTED_MAIN_SCHEMA.contains(version),
                "the declared range must include the observed version {version}"
            );
            let tmp = TempDb::write(&fs::read(&path).unwrap(), "twitter").unwrap();
            let out = parse_main(tmp.path(), owner, Uuid::new_v4(), Uuid::new_v4());
            assert!(
                stale_markers(&out).is_empty(),
                "{}: a real store in range must not warn: {:?}",
                expect.label,
                stale_markers(&out)
            );
            let dms = out
                .iter()
                .filter(|a| a.metadata["type"] == json!("TwitterDM"))
                .count();
            seance_sqlite_util::check_corpus(&expect, dms).unwrap();
            eprintln!("{}: {dms} DMs", expect.label);
            checked += 1;
        }
        eprintln!("checked {checked} real Twitter store(s)");
    }

    /// ROADMAP §5.11, owner decision (b) of 2026-09-26: this parser's schema
    /// records speak the vocabulary every schema record shares — the same status
    /// names, subtype `parser_stale` and `warning_class: "ParserStaleWarning"`.
    #[test]
    fn schema_records_speak_the_shared_vocabulary() {
        use seance_sqlite_util::adopt::inline_marker::{
            field_drift_marker, stale_marker, version_not_recorded_marker,
            version_undetermined_marker,
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
}
