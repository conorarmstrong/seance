//! `plum.sqlite` — the UWP Sticky Notes app's store.
//!
//! Lives under
//! `…\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState`.
//!
//! # What the real store does (`PLUM-1`, lab-made, 6.1.4.0)
//!
//! Compared on 2026-09-27 against a database the real app wrote on the
//! project's own Windows 11 lab VM (`documentation/VALIDATION.md` `PLUM-1`):
//!
//! * **The whole database can live in the `-wal`.** The app never
//!   checkpointed, not even on a clean close: `plum.sqlite` was 4,096 bytes
//!   (page 1 only) and the schema and every row were in `plum.sqlite-wal`. The
//!   module stages the `-wal` beside the spill (`TempDb::spill`), so the reader
//!   sees what SQLite would; without it there are no tables at all.
//! * **Times are .NET ticks** (100 ns since 0001-01-01) in `bigint` columns,
//!   in UTC as the writing machine's clock understood it. They are converted
//!   and the raw ticks kept, and never "corrected" for a clock that was wrong.
//! * **`Text` holds one paragraph per line, each prefixed `\id=<guid> `.**
//!   `text` is the note with those prefixes removed; `text_raw` is the column
//!   as stored.
//! * **A deleted note leaves no tombstone.** `DeletedAt` is never set; the row
//!   is removed. Its older images survive in superseded WAL frames, and
//!   [`recover_deleted_from_wal`] surfaces them as recovered records whose
//!   deletion is inferred from the row's absence, not read from the file.
//!
//! # Three states, not two
//!
//! The schema this build knows is a `Note` table. Whether it is there is a
//! three-state question and the difference matters:
//!
//! * **present** — read it;
//! * **absent** — the database exists and holds no such table, which is a
//!   finding: this is not the store this build knows, and saying so is not the
//!   same as saying there are no notes;
//! * **undetermined** — the database would not answer the question at all,
//!   which is damage rather than an absence.
//!
//! An unrecognised schema therefore emits a `StickyNotesParseStatus` record
//! naming the tables that ARE there, rather than silence — because silence
//! reads as "this machine had no notes".

use std::collections::{BTreeMap, HashSet};

use rusqlite::types::ValueRef;
use rusqlite::Connection;
use seance_core::data_source::DataSource;
use seance_plugin_sqlite::sqlite_forensic::{btree, reader::PageReader, record, wal};
use serde_json::{json, Map, Value};

use crate::unvalidated::stamp_plum;

/// Notes read before the reader stops.
pub const MAX_NOTES: usize = 100_000;

/// The table the documented schema holds the notes in.
pub const NOTE_TABLE: &str = "Note";

/// The columns this build reads when they are there. Each is optional: a
/// schema that has some and not others is read for what it has, and the record
/// says which columns answered.
const WANTED: &[&str] = &[
    "Id",
    "Text",
    "WindowPosition",
    "IsOpen",
    "CreatedAt",
    "UpdatedAt",
    "DeletedAt",
    "Theme",
];

/// .NET ticks between 0001-01-01 and 1601-01-01, the FILETIME epoch. A .NET
/// `DateTime` tick and a FILETIME tick are the same 100 ns, so ticks minus this
/// is a FILETIME, converted by the one shared FILETIME converter.
const DOTNET_TICKS_AT_FILETIME_EPOCH: i64 = 504_911_232_000_000_000;

/// The size of a WAL header and of each frame's header, fixed by the format.
const WAL_HEADER_BYTES: u64 = 32;
const WAL_FRAME_HEADER_BYTES: u64 = 24;

/// What `time_basis` says on every note.
const TIME_BASIS: &str =
    "CreatedAt/UpdatedAt/DeletedAt are stored as .NET DateTime ticks (100 ns since \
     0001-01-01) in UTC as the writing machine's clock understood it; `created`/`modified`/\
     `deleted` are those ticks converted, and the `_ticks` fields are the stored values. They \
     are reported as the file holds them and are not corrected for any error in that machine's \
     clock. A value stored as text is reported as stored.";

/// A time column's value: converted when it is ticks, as stored when it is text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoteTime {
    /// RFC 3339, or the text as stored.
    pub display: Option<String>,
    /// The stored integer, when the column held one.
    pub ticks: Option<i64>,
}

impl NoteTime {
    fn from_ticks(ticks: i64) -> Self {
        NoteTime {
            display: dotnet_ticks_to_rfc3339(ticks),
            ticks: Some(ticks),
        }
    }

    fn from_text(text: String) -> Self {
        NoteTime {
            display: Some(text),
            ticks: None,
        }
    }
}

/// .NET ticks → RFC 3339 UTC. `None` for a value before 1970 or past year 9999,
/// which is reported raw rather than turned into an invented date.
pub fn dotnet_ticks_to_rfc3339(ticks: i64) -> Option<String> {
    let filetime = ticks.checked_sub(DOTNET_TICKS_AT_FILETIME_EPOCH)?;
    if filetime <= 0 {
        return None;
    }
    seance_core::time::filetime_to_rfc3339(filetime as u64)
}

/// Whether `s` is a bare 36-character GUID (8-4-4-4-12 hex digits).
fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Remove each paragraph's `\id=<guid> ` prefix. Returns the text and how many
/// prefixes were removed. A line without the exact prefix is left alone.
pub fn strip_paragraph_ids(stored: &str) -> (String, usize) {
    const PREFIX: &str = "\\id=";
    let mut stripped = 0;
    let lines: Vec<&str> = stored
        .split('\n')
        .map(|line| {
            if let Some(rest) = line.strip_prefix(PREFIX) {
                if rest.len() > 36
                    && rest.is_char_boundary(36)
                    && is_guid(&rest[..36])
                    && rest[36..].starts_with(' ')
                {
                    stripped += 1;
                    return &rest[37..];
                }
            }
            line
        })
        .collect();
    (lines.join("\n"), stripped)
}

/// One note from the UWP store.
#[derive(Clone, Debug, Default)]
pub struct PlumNote {
    pub id: Option<String>,
    /// SQLite's rowid for the row, when the `Note` object has one.
    pub rowid: Option<i64>,
    /// The text for reading: RTF extracted when it is RTF, and each paragraph's
    /// `\id=<guid> ` prefix removed.
    pub text: Option<String>,
    /// The `Text` column exactly as stored.
    pub text_raw: Option<String>,
    pub raw_is_rtf: bool,
    pub paragraph_ids_stripped: usize,
    pub created_at: NoteTime,
    pub updated_at: NoteTime,
    pub deleted_at: NoteTime,
    pub is_open: Option<bool>,
    pub theme: Option<String>,
    /// Which of the wanted columns this schema actually had.
    pub columns_present: Vec<String>,
    /// The store's `PRAGMA user_version`, when it recorded one.
    pub user_version: Option<i64>,
}

impl PlumNote {
    /// Fill the text fields from the stored `Text`.
    fn set_text(&mut self, raw: Option<String>) {
        self.text_raw = raw.clone();
        let (text, raw_is_rtf) = match raw {
            Some(t) if crate::rtf::is_rtf(t.as_bytes()) => {
                (Some(crate::rtf::extract(t.as_bytes()).text), true)
            }
            other => (other, false),
        };
        self.raw_is_rtf = raw_is_rtf;
        self.text = text.map(|t| {
            let (t, n) = strip_paragraph_ids(&t);
            self.paragraph_ids_stripped = n;
            t
        });
    }

    /// The fields a live note and a recovered one share.
    fn common_fields(&self, m: &mut Map<String, Value>, source_file: &str) {
        m.insert(
            "name".into(),
            json!(match self.text.as_deref().map(str::trim) {
                Some(t) if !t.is_empty() => t.lines().next().unwrap_or(t).to_string(),
                _ => format!(
                    "Sticky note {}",
                    self.id.clone().unwrap_or_else(|| "(unnamed)".into())
                ),
            }),
        );
        m.insert("source_file".into(), json!(source_file));
        m.insert("source_format".into(), json!("plum_sqlite"));
        m.insert("note_id".into(), json!(self.id));
        m.insert("rowid".into(), json!(self.rowid));
        m.insert("text".into(), json!(self.text));
        m.insert("text_raw".into(), json!(self.text_raw));
        m.insert("text_was_rtf".into(), json!(self.raw_is_rtf));
        m.insert(
            "paragraph_ids_stripped".into(),
            json!(self.paragraph_ids_stripped),
        );
        m.insert(
            "text_basis".into(),
            json!(
                "The stored text is sniffed for the RTF magic and extracted when it is RTF, and \
                 taken as stored when it is not. Each line's `\\id=<paragraph guid> ` prefix, \
                 which the app writes before every paragraph, is removed from `text`; \
                 `text_raw` is the column exactly as stored."
            ),
        );
        m.insert("created".into(), json!(self.created_at.display));
        m.insert("created_ticks".into(), json!(self.created_at.ticks));
        m.insert("modified".into(), json!(self.updated_at.display));
        m.insert("modified_ticks".into(), json!(self.updated_at.ticks));
        m.insert("deleted".into(), json!(self.deleted_at.display));
        m.insert("deleted_ticks".into(), json!(self.deleted_at.ticks));
        m.insert("time_basis".into(), json!(TIME_BASIS));
        m.insert("is_open".into(), json!(self.is_open));
        m.insert("theme".into(), json!(self.theme));
        m.insert("user_version".into(), json!(self.user_version));
    }

    pub fn to_json(&self, source_file: &str) -> Value {
        let mut m = Map::new();
        m.insert("type".into(), json!("StickyNote"));
        self.common_fields(&mut m, source_file);
        if self.deleted_at.display.is_some() || self.deleted_at.ticks.is_some() {
            m.insert(
                "deleted_note".into(),
                json!(
                    "This row carries a deletion time, so the app recorded the note as deleted \
                     and the row survived. The note's text above is what the row still holds."
                ),
            );
        }
        // Which columns answered, so a null above is distinguishable from a
        // column this schema does not have.
        m.insert("columns_present".into(), json!(self.columns_present));
        m.insert(
            "columns_basis".into(),
            json!(
                "A null field above may be a row with no value OR a column this database's \
                 schema does not have. `columns_present` is which of the columns this build \
                 looks for were actually there."
            ),
        );
        stamp_plum(&mut m, self.user_version);
        Value::Object(m)
    }
}

/// The status record for a database whose schema this build does not know.
///
/// `user_version` is the store's `PRAGMA user_version` when a database was
/// opened, and decides the stamp.
pub fn parse_status(
    source_file: &str,
    status: &str,
    detail: String,
    tables: Vec<String>,
    user_version: Option<i64>,
) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!("StickyNotesParseStatus"));
    m.insert("name".into(), json!(format!("{source_file} — {status}")));
    m.insert("source_file".into(), json!(source_file));
    m.insert("status".into(), json!(status));
    m.insert("detail".into(), json!(detail));
    // The tables that ARE there. Without them "an unrecognised schema" is a
    // dead end; with them the next reader knows what to write against.
    m.insert("tables_present".into(), json!(tables));
    m.insert("notes_recovered".into(), json!(0));
    m.insert("content_incomplete".into(), json!(true));
    m.insert(
        "content_incomplete_reason".into(),
        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
    );
    m.insert("user_version".into(), json!(user_version));
    stamp_plum(&mut m, user_version);
    Value::Object(m)
}

/// Every table name in the database, so a status record can name them.
pub fn table_names(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            out = rows.flatten().collect();
        }
    }
    out
}

/// The store's `PRAGMA user_version`, when it recorded one.
pub fn user_version(conn: &Connection) -> Option<i64> {
    match seance_sqlite_util::read_user_version(conn) {
        seance_sqlite_util::StoreSchemaVersion::Found(v) => Some(v),
        _ => None,
    }
}

/// A time column's value, whichever storage class it has.
fn note_time(v: ValueRef<'_>) -> NoteTime {
    match v {
        ValueRef::Integer(i) => NoteTime::from_ticks(i),
        ValueRef::Text(t) => NoteTime::from_text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Real(f) => NoteTime::from_text(f.to_string()),
        ValueRef::Null | ValueRef::Blob(_) => NoteTime::default(),
    }
}

/// Read the notes, or a status record saying why there are none.
pub fn read(conn: &Connection, source_file: &str) -> Vec<Value> {
    use seance_sqlite_util::{probe_table, Presence};

    let version = user_version(conn);
    match probe_table(conn, NOTE_TABLE) {
        Presence::Present => {}
        Presence::Absent => {
            return vec![parse_status(
                source_file,
                "SchemaNotRecognised",
                format!(
                    "This database opened and holds no `{NOTE_TABLE}` table, which is the table \
                     this build reads the UWP Sticky Notes store from. That is an absence of the \
                     schema this build knows, NOT an absence of notes: the tables it does hold \
                     are named below, and a store this build cannot read may still hold notes."
                ),
                table_names(conn),
                version,
            )];
        }
        Presence::Undetermined(e) => {
            return vec![parse_status(
                source_file,
                "SchemaUndetermined",
                format!(
                    "This database would not answer whether it holds a `{NOTE_TABLE}` table \
                     ({e}). That is damage rather than an absence, and nothing about the notes \
                     it may hold is established either way."
                ),
                table_names(conn),
                version,
            )];
        }
    }

    // Which of the columns this build reads the schema actually has. Read what
    // is there rather than refusing the table: a schema that gained or lost a
    // column is still a store of notes, and the record says which columns
    // answered so a null field is distinguishable from a missing column.
    // `table_columns` lower-cases what it returns, and SQLite matches a column
    // name case-insensitively, so the canonical spelling is reported rather
    // than whichever casing this database happened to declare.
    let have = seance_sqlite_util::table_columns(conn, NOTE_TABLE);
    let present: Vec<String> = WANTED
        .iter()
        .filter(|w| have.iter().any(|c| c.eq_ignore_ascii_case(w)))
        .map(|w| (*w).to_string())
        .collect();
    if present.is_empty() {
        return vec![parse_status(
            source_file,
            "SchemaNotRecognised",
            format!(
                "This database holds a `{NOTE_TABLE}` table and none of the columns this build \
                 reads. Its columns are not named here because the table exists; what it holds \
                 was not read."
            ),
            table_names(conn),
            version,
        )];
    }

    let quoted: Vec<String> = present.iter().map(|c| format!("\"{c}\"")).collect();
    // The rowid is asked for first, and the query is asked again without it
    // when the object has none (a view, or a WITHOUT ROWID table): a note
    // without a rowid is still a note.
    let with_rowid = format!(
        "SELECT rowid, {} FROM \"{NOTE_TABLE}\" LIMIT {MAX_NOTES}",
        quoted.join(", ")
    );
    let without_rowid = format!(
        "SELECT NULL, {} FROM \"{NOTE_TABLE}\" LIMIT {MAX_NOTES}",
        quoted.join(", ")
    );
    let prepared = conn
        .prepare(&with_rowid)
        .or_else(|_| conn.prepare(&without_rowid));
    let mut stmt = match prepared {
        Ok(s) => s,
        Err(e) => {
            return vec![parse_status(
                source_file,
                "TableUnreadable",
                format!(
                    "This database's `{NOTE_TABLE}` table could not be read ({e}). Nothing about \
                     the notes it holds is established either way."
                ),
                table_names(conn),
                version,
            )]
        }
    };
    // Column 0 is the rowid; the wanted columns follow.
    let idx = |name: &str| {
        present
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name))
            .map(|i| i + 1)
    };
    let rows = stmt.query_map([], |row| {
        let get = |name: &str| -> Option<String> {
            idx(name).and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
        };
        let time = |name: &str| -> NoteTime {
            idx(name)
                .and_then(|i| row.get_ref(i).ok())
                .map(note_time)
                .unwrap_or_default()
        };
        let mut note = PlumNote {
            id: get("Id"),
            rowid: row.get::<_, Option<i64>>(0).ok().flatten(),
            created_at: time("CreatedAt"),
            updated_at: time("UpdatedAt"),
            deleted_at: time("DeletedAt"),
            is_open: idx("IsOpen")
                .and_then(|i| row.get::<_, Option<i64>>(i).ok().flatten())
                .map(|v| v != 0),
            theme: get("Theme"),
            columns_present: present.clone(),
            user_version: version,
            ..PlumNote::default()
        };
        note.set_text(get("Text"));
        Ok(note)
    });
    match rows {
        Ok(rows) => {
            let notes: Vec<Value> = rows.flatten().map(|n| n.to_json(source_file)).collect();
            if notes.is_empty() {
                // An empty table is an answer, and it is not the same answer as
                // a database this build could not read.
                return vec![parse_status(
                    source_file,
                    "NoNotesStored",
                    format!(
                        "This database holds a `{NOTE_TABLE}` table with no rows. The app's store \
                         exists and records no notes -- which is not the same as this build \
                         having failed to read it."
                    ),
                    table_names(conn),
                    version,
                )];
            }
            notes
        }
        Err(e) => vec![parse_status(
            source_file,
            "TableUnreadable",
            format!("This database's `{NOTE_TABLE}` rows could not be read ({e})."),
            table_names(conn),
            version,
        )],
    }
}

/// One image of a `Note` row found in a WAL frame.
struct FrameRow {
    frame_index: usize,
    page_number: u32,
    rowid: Option<i64>,
    values: Vec<record::Value>,
    decode_notes: Vec<String>,
    committed: bool,
    current_generation: bool,
}

fn text_of(v: Option<&record::Value>) -> Option<String> {
    match v {
        Some(record::Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn time_of(v: Option<&record::Value>) -> NoteTime {
    match v {
        Some(record::Value::Int(i)) => NoteTime::from_ticks(*i),
        Some(record::Value::Text(s)) => NoteTime::from_text(s.clone()),
        _ => NoteTime::default(),
    }
}

/// **Notes deleted from the store, recovered from superseded WAL frames.**
///
/// Sticky Notes 6.1.4.0 removes a deleted note's row and sets no tombstone
/// (`PLUM-1`), so the live table cannot say a note was deleted. The WAL can: a
/// frame written before the delete still holds the page image with the row in
/// it. This decodes every `Note`-shaped row in every frame — a leaf-table cell
/// whose record has exactly as many values as the live `Note` table has
/// columns, and whose `Id` is text — and emits one `StickyNoteRecovered`
/// record for each `Id` that is **absent from the live table**, from the
/// newest frame that holds it.
///
/// The frame decoder is the forensic SQLite parser's
/// (`seance_plugin_sqlite::sqlite_forensic`), not a second one. `main` is the
/// main database file, read only for overflow pages; a row whose payload
/// overflowed into a page the main file does not hold is decoded short and
/// says so. Earlier images of notes that are still live are edit history and
/// are not reported here.
pub fn recover_deleted_from_wal(
    conn: &Connection,
    wal_bytes: &[u8],
    main: &dyn DataSource,
    source_file: &str,
) -> Vec<Value> {
    // The live table's columns in declaration order: a record's values are in
    // that order.
    let columns: Vec<String> = match conn.prepare(&format!(
        "SELECT name FROM pragma_table_info('{NOTE_TABLE}') ORDER BY cid"
    )) {
        Ok(mut stmt) => stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let col = |name: &str| columns.iter().position(|c| c.eq_ignore_ascii_case(name));
    let (Some(id_col), false) = (col("Id"), columns.is_empty()) else {
        return Vec::new();
    };
    let live_ids: HashSet<String> =
        match conn.prepare(&format!("SELECT \"Id\" FROM \"{NOTE_TABLE}\"")) {
            Ok(mut stmt) => match stmt.query_map([], |r| r.get::<_, Option<String>>(0)) {
                Ok(rows) => rows.flatten().flatten().collect(),
                // The live set is what the inference rests on; without it nothing
                // can be called deleted.
                Err(_) => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        };
    let version = user_version(conn);

    let mut head = [0u8; 100];
    let n = seance_core::io::read_full(main, 0, &mut head);
    let Some(header) = seance_plugin_sqlite::sqlite_forensic::header::parse(&head[..n]) else {
        return Vec::new();
    };
    let parsed = wal::parse(wal_bytes, header.page_size);
    if parsed.frames.is_empty() || parsed.page_size == 0 {
        return Vec::new();
    }
    let page_size = parsed.page_size;
    let reader = PageReader::new(main, 0, page_size, header.reserved_space);
    // Frames after the last commit frame of the current generation belong to
    // a transaction SQLite would not replay.
    let last_commit = parsed
        .frames
        .iter()
        .filter(|f| f.is_commit && f.current_generation)
        .map(|f| f.frame_index)
        .max();

    // Every image of every Note-shaped row, and which rows each frame's page
    // image held (for "the first later image of the page without the row").
    let mut by_id: BTreeMap<String, Vec<FrameRow>> = BTreeMap::new();
    let mut page_images: Vec<(usize, u32, HashSet<String>)> = Vec::new();
    for frame in &parsed.frames {
        let content_offset = if frame.page_number == 1 { 100 } else { 0 };
        let rows = btree::parse_leaf_page_rows(
            &reader,
            &frame.page_data,
            content_offset,
            frame.page_number.saturating_sub(1) as usize,
        );
        let mut ids_here = HashSet::new();
        for row in rows {
            if row.values.len() != columns.len() {
                continue;
            }
            let Some(id) = text_of(row.values.get(id_col)) else {
                continue;
            };
            ids_here.insert(id.clone());
            by_id.entry(id).or_default().push(FrameRow {
                frame_index: frame.frame_index,
                page_number: frame.page_number,
                rowid: row.rowid,
                values: row.values,
                decode_notes: row.notes,
                committed: last_commit.is_some_and(|c| frame.frame_index <= c),
                current_generation: frame.current_generation,
            });
        }
        page_images.push((frame.frame_index, frame.page_number, ids_here));
    }

    let mut out = Vec::new();
    for (id, images) in by_id {
        if live_ids.contains(&id) {
            continue;
        }
        let Some(newest) = images.iter().max_by_key(|r| r.frame_index) else {
            continue;
        };
        let frames_holding: Vec<usize> = images.iter().map(|r| r.frame_index).collect();
        let first_without = page_images
            .iter()
            .find(|(fi, pn, ids)| {
                *fi > newest.frame_index && *pn == newest.page_number && !ids.contains(&id)
            })
            .map(|(fi, _, _)| *fi);

        let get = |name: &str| col(name).and_then(|i| newest.values.get(i));
        let mut note = PlumNote {
            id: Some(id.clone()),
            rowid: newest.rowid,
            created_at: time_of(get("CreatedAt")),
            updated_at: time_of(get("UpdatedAt")),
            deleted_at: time_of(get("DeletedAt")),
            is_open: match get("IsOpen") {
                Some(record::Value::Int(i)) => Some(*i != 0),
                _ => None,
            },
            theme: text_of(get("Theme")),
            user_version: version,
            ..PlumNote::default()
        };
        note.set_text(text_of(get("Text")));

        let mut m = Map::new();
        m.insert("type".into(), json!("StickyNoteRecovered"));
        note.common_fields(&mut m, source_file);
        m.insert("recovered".into(), json!(true));
        m.insert("recovery_source".into(), json!("wal_superseded_frame"));
        m.insert("wal_frame".into(), json!(newest.frame_index));
        m.insert(
            "wal_frame_offset".into(),
            json!(
                WAL_HEADER_BYTES
                    + newest.frame_index as u64 * (WAL_FRAME_HEADER_BYTES + page_size as u64)
            ),
        );
        m.insert("wal_page_number".into(), json!(newest.page_number));
        m.insert("wal_frames_holding_row".into(), json!(frames_holding));
        m.insert("first_wal_frame_without_row".into(), json!(first_without));
        m.insert("wal_frame_committed".into(), json!(newest.committed));
        m.insert(
            "wal_frame_current_generation".into(),
            json!(newest.current_generation),
        );
        m.insert("deleted_inferred".into(), json!(true));
        let tombstone = if note.deleted_at.ticks.is_some() || note.deleted_at.display.is_some() {
            "This image of the row does carry a DeletedAt value, shown above."
        } else {
            "The app sets no tombstone: Sticky Notes 6.1.4.0 was observed (PLUM-1) to remove a \
             deleted note's row without ever setting DeletedAt, and no image of this row has one, \
             so there is no deletion time to report."
        };
        m.insert(
            "deletion_basis".into(),
            json!(format!(
                "Deletion is INFERRED, not recorded. A row with this Id is absent from the latest \
                 committed state of the database (the live Note table read with the WAL \
                 applied), and frame {} of the WAL still holds an image of it. {tombstone} The \
                 same absence would follow if the row had been removed by anything other than \
                 the app's delete.",
                newest.frame_index
            )),
        );
        m.insert(
            "recovery_basis".into(),
            json!(format!(
                "Decoded from WAL frame {} (0-based; byte offset of the frame header shown), an \
                 image of database page {} written before the row was removed. The values are \
                 that image's, which is the newest the WAL holds; the frames listed hold this \
                 row's earlier images too.",
                newest.frame_index, newest.page_number
            )),
        );
        if !newest.committed {
            m.insert(
                "wal_frame_note".into(),
                json!(
                    "This frame is after the WAL's last commit frame, so SQLite would not replay \
                     it: the row may never have been committed."
                ),
            );
        }
        if !newest.decode_notes.is_empty() {
            m.insert("decode_notes".into(), json!(newest.decode_notes));
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
            );
        }
        stamp_plum(&mut m, version);
        out.push(Value::Object(m));
    }
    out
}
