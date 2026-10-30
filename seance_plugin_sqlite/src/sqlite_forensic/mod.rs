//! Forensic SQLite parser: raw b-tree parsing, deleted-record recovery, WAL and
//! rollback-journal recovery, and corruption-tolerant extraction.
//!
//! This module parses SQLite databases without a driver, walking b-trees
//! directly from a [`DataSource`] and recovering deleted rows from freeblocks,
//! freelist pages, and unallocated/slack space. It degrades gracefully on
//! corruption rather than failing the whole file.

pub mod btree;
pub mod carving;
pub mod freelist;
pub mod header;
pub mod journal;
pub mod reader;
pub mod record;
pub mod recovered_chat;
pub mod schema;
pub mod wal;

use reader::PageReader;
use record::Value;
use schema::SchemaEntry;
use seance_core::data_source::DataSource;
use std::collections::HashMap;

/// Where a recovered record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySource {
    /// Intra-page deleted cell recovered from a freeblock chain.
    Freeblock,
    /// A page on the freelist (trunk or leaf) reparsed for records.
    Freelist,
    /// Record-shaped bytes carved from a live page's unallocated region.
    Unallocated,
    /// Printable text salvaged from slack space.
    Slack,
    /// A page version recovered from the write-ahead log.
    Wal,
    /// A pre-image page recovered from a rollback journal.
    Journal,
}

impl RecoverySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoverySource::Freeblock => "freeblock",
            RecoverySource::Freelist => "freelist",
            RecoverySource::Unallocated => "unallocated",
            RecoverySource::Slack => "slack",
            RecoverySource::Wal => "wal",
            RecoverySource::Journal => "journal",
        }
    }
}

/// A single extracted or recovered record.
#[derive(Debug, Clone)]
pub struct ForensicRecord {
    pub table: Option<String>,
    pub rowid: Option<i64>,
    pub page_number: usize,
    pub deleted: bool,
    pub recovery_source: Option<RecoverySource>,
    pub confidence: u8,
    pub columns: Vec<String>,
    pub values: Vec<Value>,
    pub notes: Vec<String>,
}

/// Database-level metadata for the summary artifact.
#[derive(Debug, Clone)]
pub struct DbSummary {
    pub page_size: usize,
    pub page_count: usize,
    pub encoding: &'static str,
    pub magic_ok: bool,
    pub base_offset: u64,
    pub tables: Vec<String>,
    pub schema_objects: usize,
    pub live_rows: usize,
    pub deleted_rows: usize,
    pub carved_rows: usize,
    pub wal_present: bool,
    pub journal_present: bool,
    pub wal_frames: usize,
    pub journal_frames: usize,
    pub freelist_pages: usize,
    pub warnings: Vec<String>,
}

/// The full result of a forensic extraction.
#[derive(Debug)]
pub struct ExtractionResult {
    pub summary: DbSummary,
    pub schema: Vec<SchemaEntry>,
    pub records: Vec<ForensicRecord>,
    pub records_truncated: bool,
}

/// Options controlling extraction.
pub struct ForensicOptions {
    pub enable_carving: bool,
    pub max_records: usize,
    pub wal_bytes: Option<Vec<u8>>,
    pub journal_bytes: Option<Vec<u8>>,
}

impl Default for ForensicOptions {
    fn default() -> Self {
        Self {
            enable_carving: true,
            max_records: 100_000,
            wal_bytes: None,
            journal_bytes: None,
        }
    }
}

fn encoding_str(enc: header::TextEncoding) -> &'static str {
    match enc {
        header::TextEncoding::Utf8 => "UTF-8",
        header::TextEncoding::Utf16Le => "UTF-16LE",
        header::TextEncoding::Utf16Be => "UTF-16BE",
    }
}

/// Confidence score (0-100) from recovery source, corruption notes, and null
/// ratio. Ported from the reference `CalculateConfidence`.
fn confidence(source: Option<RecoverySource>, notes: &[String], values: &[Value]) -> u8 {
    let mut score: i32 = 100;
    score -= (notes.len() as i32) * 15;
    if !values.is_empty() {
        let nulls = values.iter().filter(|v| matches!(v, Value::Null)).count();
        let ratio = nulls as f64 / values.len() as f64;
        if ratio > 0.5 {
            score -= 20;
        } else if ratio > 0.25 {
            score -= 10;
        }
    }
    score -= match source {
        None => 0,
        Some(RecoverySource::Freeblock) => 15,
        Some(RecoverySource::Freelist) => 20,
        Some(RecoverySource::Unallocated) => 30,
        Some(RecoverySource::Slack) => 35,
        Some(RecoverySource::Wal) => 10,
        Some(RecoverySource::Journal) => 15,
    };
    score.clamp(0, 100) as u8
}

/// Aligns column names to a value list, padding/truncating as needed.
fn align_columns(columns: &[String], value_count: usize) -> Vec<String> {
    let mut out: Vec<String> = columns.iter().take(value_count).cloned().collect();
    while out.len() < value_count {
        out.push(format!("c{}", out.len()));
    }
    out
}

/// Marker note set by the freeblock header-realignment reconstructor.
const REALIGNED_NOTE: &str = "reconstructed from freeblock (header realigned)";

/// Aligns column names to a freeblock-reconstructed value list from the **right**.
/// Reconstruction recovers the surviving *tail* of a record whose leading columns
/// (the rowid-alias and any columns before the clobbered header boundary) were
/// lost, so the recovered values correspond to the table's trailing columns.
/// Right-aligning maps `[sender, body]` onto `[..., sender, body]` instead of
/// mislabelling them as the first columns.
fn align_columns_right(columns: &[String], value_count: usize) -> Vec<String> {
    if columns.len() >= value_count {
        columns[columns.len() - value_count..].to_vec()
    } else {
        align_columns(columns, value_count)
    }
}

/// Whether the schema declares a table by (case-insensitive) name.
fn has_table(schema: &[SchemaEntry], name: &str) -> bool {
    schema
        .iter()
        .any(|e| e.obj_type.eq_ignore_ascii_case("table") && e.name.eq_ignore_ascii_case(name))
}

/// Scan raw bytes for iMessage `attributedBody` typedstream blobs and return the
/// distinct message texts, in file order. Each `streamtyped` signature is decoded
/// with the shared typedstream extractor over a bounded window (a single
/// attributedBody, even with attribute runs, is small). Recovers message bodies
/// straight from deleted space, independent of whether the surrounding record was
/// carved cleanly.
fn scan_attributed_bodies(raw: &[u8]) -> Vec<String> {
    const SIG: &[u8] = b"streamtyped";
    const WINDOW: usize = 8192;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0usize;
    while i + SIG.len() <= raw.len() {
        let Some(rel) = raw[i..].windows(SIG.len()).position(|w| w == SIG) else {
            break;
        };
        let start = i + rel;
        let end = (start + WINDOW).min(raw.len());
        if let Some(text) = seance_core::typedstream::extract_message_text(&raw[start..end]) {
            let t = text.trim().to_string();
            if t.chars().count() >= 2 && seen.insert(t.clone()) {
                out.push(t);
            }
        }
        i = start + SIG.len();
    }
    out
}

/// Reads up to `max` bytes from a source starting at `offset`.
fn read_prefix(src: &dyn DataSource, offset: u64, max: usize) -> Vec<u8> {
    let size = src.size();
    if offset >= size {
        return Vec::new();
    }
    let want = ((size - offset) as usize).min(max);
    let mut buf = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        match src.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    buf.truncate(filled);
    buf
}

/// Detects whether a data source looks like a SQLite database (magic at 0, at a
/// scan offset, or a recoverable/zeroed header with valid structure).
pub fn looks_like_sqlite_source(src: &dyn DataSource) -> bool {
    let prefix = read_prefix(src, 0, 65536);
    if prefix.is_empty() {
        return false;
    }
    let base = header::detect_offset(&prefix).unwrap_or(0);
    header::parse(&prefix[base..]).is_some()
}

/// Extracts all live rows, recovered/deleted rows, schema, and metadata from a
/// SQLite database exposed via `src`. Returns `None` only when the bytes cannot
/// be recognised as SQLite at all.
pub fn extract(src: &dyn DataSource, opts: &ForensicOptions) -> Option<ExtractionResult> {
    let prefix = read_prefix(src, 0, 65536);
    if prefix.is_empty() {
        return None;
    }
    let base_offset = header::detect_offset(&prefix).unwrap_or(0) as u64;
    let header_bytes = read_prefix(src, base_offset, 4096);
    let hdr = header::parse(&header_bytes)?;

    let mut warnings = hdr.warnings.clone();
    let reader = PageReader::new(src, base_offset, hdr.page_size, hdr.reserved_space);
    let total_pages = reader.total_pages();
    let scan_pages = reader.page_count_including_partial();

    // --- Schema from sqlite_master (page 1 b-tree). ---
    let mut schema: Vec<SchemaEntry> = Vec::new();
    let (master_rows, _master_pages) = btree::walk_table(&reader, 1);
    for row in &master_rows {
        if let Some(entry) = schema::entry_from_master_row(&row.values) {
            schema.push(entry);
        }
    }

    // Map root page -> (table name, columns), table name -> columns, and page
    // index -> table name.
    let mut root_to_table: HashMap<i64, (String, Vec<String>)> = HashMap::new();
    let mut table_columns: HashMap<String, Vec<String>> = HashMap::new();
    for e in &schema {
        if e.obj_type.eq_ignore_ascii_case("table") && e.root_page > 0 {
            root_to_table.insert(e.root_page, (e.name.clone(), e.columns.clone()));
            table_columns.insert(e.name.clone(), e.columns.clone());
        }
    }

    let mut page_to_table: HashMap<usize, String> = HashMap::new();
    let mut records: Vec<ForensicRecord> = Vec::new();
    let mut live_rows = 0usize;

    // --- Live extraction: walk every table b-tree. ---
    let mut roots: Vec<i64> = root_to_table.keys().copied().collect();
    roots.sort_unstable();
    for root in roots {
        let (name, columns) = root_to_table.get(&root).cloned().unwrap();
        let (rows, visited) = btree::walk_table(&reader, root);
        for p in &visited {
            page_to_table.entry(*p).or_insert_with(|| name.clone());
        }
        for row in rows {
            let cols = align_columns(&columns, row.values.len());
            let conf = confidence(None, &row.notes, &row.values);
            records.push(ForensicRecord {
                table: Some(name.clone()),
                rowid: row.rowid,
                page_number: row.page_index + 1,
                deleted: false,
                recovery_source: None,
                confidence: conf,
                columns: cols,
                values: row.values,
                notes: row.notes,
            });
            live_rows += 1;
        }
    }

    let mut deleted_rows = 0usize;
    let mut carved_rows = 0usize;
    let mut freelist_page_count = 0usize;

    if opts.enable_carving {
        // --- Carve deleted records from live pages (freeblocks + slack). ---
        for page_index in 0..scan_pages {
            let page = reader.read_page(page_index);
            if page.is_empty() {
                continue;
            }
            let content_offset = reader.content_offset(page_index);
            let carved = carving::carve_page(
                &reader,
                &page,
                content_offset,
                page_index,
                RecoverySource::Unallocated,
            );
            for c in carved {
                let table = page_to_table.get(&page_index).cloned();
                let base_cols = table
                    .as_ref()
                    .and_then(|t| table_columns.get(t))
                    .cloned()
                    .unwrap_or_default();
                // A freeblock-reconstructed row recovered only the record's tail;
                // align its values to the trailing schema columns.
                let realigned = c.notes.iter().any(|n| n == REALIGNED_NOTE);
                let cols = if realigned {
                    align_columns_right(&base_cols, c.values.len())
                } else {
                    align_columns(&base_cols, c.values.len())
                };
                let conf = confidence(Some(c.source), &c.notes, &c.values);
                records.push(ForensicRecord {
                    table,
                    rowid: c.rowid,
                    page_number: page_index + 1,
                    deleted: true,
                    recovery_source: Some(c.source),
                    confidence: conf,
                    columns: cols,
                    values: c.values,
                    notes: c.notes,
                });
                deleted_rows += 1;
                carved_rows += 1;
            }
        }

        // --- Freelist pages: reparse former leaf-table cells + carve. ---
        let freelist_pages = freelist::collect_freelist_pages(
            &reader,
            hdr.first_freelist_trunk,
            hdr.total_freelist_pages,
        );
        freelist_page_count = freelist_pages.len();
        for fp in freelist_pages {
            let page = reader.read_page(fp.page_index);
            if page.is_empty() {
                continue;
            }
            let content_offset = reader.content_offset(fp.page_index);
            // A freed leaf-table page usually still holds intact cells (SQLite
            // does not zero freed pages absent `secure_delete`). Prefer clean
            // structured decoding of those; fall back to carving/salvage only
            // when the page is not an intact leaf page.
            let rows = btree::parse_leaf_page_rows(&reader, &page, content_offset, fp.page_index);
            if !rows.is_empty() {
                // Infer a placeholder schema for these orphaned records.
                let value_lists: Vec<Vec<Value>> = rows.iter().map(|r| r.values.clone()).collect();
                let (inferred, conf_ratio) = schema::infer_column_count(&value_lists);
                let placeholder = schema::placeholder_columns(inferred);
                for row in rows {
                    let cols = align_columns(&placeholder, row.values.len());
                    let mut notes = row.notes;
                    notes.push(format!(
                        "orphaned freelist record; inferred {} columns ({:.0}% confidence)",
                        inferred,
                        conf_ratio * 100.0
                    ));
                    let conf = confidence(Some(RecoverySource::Freelist), &notes, &row.values);
                    records.push(ForensicRecord {
                        table: None,
                        rowid: row.rowid,
                        page_number: fp.page_index + 1,
                        deleted: true,
                        recovery_source: Some(RecoverySource::Freelist),
                        confidence: conf,
                        columns: cols,
                        values: row.values,
                        notes,
                    });
                    deleted_rows += 1;
                }
            } else {
                // Not an intact leaf page: carve slack/freeblocks instead.
                let carved = carving::carve_page(
                    &reader,
                    &page,
                    content_offset,
                    fp.page_index,
                    RecoverySource::Freelist,
                );
                for c in carved {
                    let cols = align_columns(&[], c.values.len());
                    let conf = confidence(Some(c.source), &c.notes, &c.values);
                    records.push(ForensicRecord {
                        table: None,
                        rowid: c.rowid,
                        page_number: fp.page_index + 1,
                        deleted: true,
                        recovery_source: Some(c.source),
                        confidence: conf,
                        columns: cols,
                        values: c.values,
                        notes: c.notes,
                    });
                    deleted_rows += 1;
                    carved_rows += 1;
                }
            }
        }
    }

    // --- WAL recovery. ---
    let wal_present = opts.wal_bytes.is_some();
    let mut wal_frames = 0usize;
    if let Some(bytes) = &opts.wal_bytes {
        let parsed = wal::parse(bytes, hdr.page_size);
        wal_frames = parsed.frames.len();
        warnings.extend(parsed.warnings);
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for frame in parsed.frames {
            let content_offset = if frame.page_number == 1 { 100 } else { 0 };
            let rows = btree::parse_leaf_page_rows(
                &reader,
                &frame.page_data,
                content_offset,
                frame.page_number.saturating_sub(1) as usize,
            );
            for row in rows {
                // Dedup identical page versions across frames.
                let key = format!("{:?}", row.values).into_bytes();
                if !seen.insert(key) {
                    continue;
                }
                let table = page_to_table
                    .get(&((frame.page_number.saturating_sub(1)) as usize))
                    .cloned();
                let base_cols = table
                    .as_ref()
                    .and_then(|t| table_columns.get(t))
                    .cloned()
                    .unwrap_or_default();
                let cols = align_columns(&base_cols, row.values.len());
                let mut notes = row.notes;
                if !frame.current_generation {
                    notes.push(
                        "this WAL frame's salts differ from the log header's, so it was written \
                         before the last checkpoint or reset: the row is older than the live \
                         database"
                            .to_string(),
                    );
                }
                let conf = confidence(Some(RecoverySource::Wal), &notes, &row.values);
                records.push(ForensicRecord {
                    table,
                    rowid: row.rowid,
                    page_number: frame.page_number as usize,
                    deleted: false,
                    recovery_source: Some(RecoverySource::Wal),
                    confidence: conf,
                    columns: cols,
                    values: row.values,
                    notes,
                });
            }
        }
    }

    // --- Rollback journal recovery. ---
    let journal_present = opts.journal_bytes.is_some();
    let mut journal_frames = 0usize;
    if let Some(bytes) = &opts.journal_bytes {
        let parsed = journal::parse(bytes, hdr.page_size);
        journal_frames = parsed.frames.len();
        warnings.extend(parsed.warnings);
        for frame in parsed.frames {
            let content_offset = if frame.page_number == 1 { 100 } else { 0 };
            let rows = btree::parse_leaf_page_rows(
                &reader,
                &frame.page_data,
                content_offset,
                frame.page_number.saturating_sub(1) as usize,
            );
            for row in rows {
                // Which table this page belongs to, from the same page-to-table
                // map the WAL path uses. Every journal row used to be published
                // with `table: None`, and the recovered-conversation reader
                // threads only rows whose table matches the schema it is
                // rebuilding — so a rolled-back deletion of a chat table could
                // never reach the conversation view.
                //
                // The map is the database as it is NOW, and a journal holds a
                // page as it was BEFORE the transaction, so the attribution is
                // an inference: a page freed and reused for another table since
                // would be misattributed. It is labelled on the record, never
                // presented as read from the journal itself.
                let table = page_to_table
                    .get(&((frame.page_number.saturating_sub(1)) as usize))
                    .cloned();
                let base_cols = table
                    .as_ref()
                    .and_then(|t| table_columns.get(t))
                    .cloned()
                    .unwrap_or_default();
                let cols = align_columns(&base_cols, row.values.len());
                let mut notes = row.notes;
                if let Some(name) = &table {
                    notes.push(format!(
                        concat!(
                            "table `{}` inferred from the page-to-table map of the database ",
                            "as it is now; the journal holds this page as it was before the ",
                            "transaction, so a page reused since would be misattributed"
                        ),
                        name
                    ));
                }
                let conf = confidence(Some(RecoverySource::Journal), &notes, &row.values);
                records.push(ForensicRecord {
                    table,
                    rowid: row.rowid,
                    page_number: frame.page_number as usize,
                    deleted: true,
                    recovery_source: Some(RecoverySource::Journal),
                    confidence: conf,
                    columns: cols,
                    values: row.values,
                    notes,
                });
                deleted_rows += 1;
            }
        }
    }

    // --- Recover deleted iMessage bodies from raw attributedBody typedstream
    // blobs. The per-row carve loses the body when a message cell's ~40 columns
    // are shifted/truncated, but the intact `streamtyped` blobs still sit in
    // deleted space. Scanning the raw bytes for them directly recovers far more
    // messages than the carved rows do (a cleared chat.db can hold hundreds of
    // decodable bodies the record carver never cleanly reconstructs). Gated to
    // iMessage schemas so it never runs on unrelated databases.
    if opts.enable_carving && has_table(&schema, "message") && has_table(&schema, "handle") {
        // Bodies already visible on live rows are not "recovered"; dedup on text.
        let mut seen: std::collections::HashSet<String> = records
            .iter()
            .filter(|r| !r.deleted)
            .flat_map(|r| r.values.iter())
            .filter_map(|v| match v {
                Value::Text(s) => Some(s.trim().to_string()),
                _ => None,
            })
            .collect();
        const ATTRIBUTED_SCAN_CAP: usize = 512 * 1024 * 1024;
        let raw = read_prefix(src, base_offset, ATTRIBUTED_SCAN_CAP);
        // These bodies carry no recovered timestamp (that column lives elsewhere
        // in the smashed cell), so the order they are found in the file is the
        // only ordering signal we have. Stamp a monotonic recovery index so the
        // chat viewer can present them deterministically instead of at random.
        let mut recovery_index: i64 = 0;
        for text in scan_attributed_bodies(&raw) {
            if seen.insert(text.clone()) {
                records.push(ForensicRecord {
                    table: Some("message".to_string()),
                    rowid: None,
                    page_number: 0,
                    deleted: true,
                    recovery_source: Some(RecoverySource::Slack),
                    confidence: 50,
                    columns: vec!["text".to_string(), "recovery_index".to_string()],
                    values: vec![Value::Text(text), Value::Int(recovery_index)],
                    notes: vec!["recovered from attributedBody typedstream".to_string()],
                });
                recovery_index += 1;
                deleted_rows += 1;
                carved_rows += 1;
            }
        }
    }

    // --- Cap emitted records honestly. ---
    let records_truncated = records.len() > opts.max_records;
    if records_truncated {
        // Recovered (deleted) rows are the forensic payload and must survive the
        // cap; a large live table must not crowd them out. Stable-sort deleted
        // rows to the front (order preserved), then truncate, so every recovered
        // row is kept and live rows take only the remaining budget.
        records.sort_by_key(|r| !r.deleted);
        records.truncate(opts.max_records);
    }

    let tables: Vec<String> = schema
        .iter()
        .filter(|e| e.obj_type.eq_ignore_ascii_case("table"))
        .map(|e| e.name.clone())
        .collect();

    let summary = DbSummary {
        page_size: hdr.page_size,
        page_count: total_pages,
        encoding: encoding_str(hdr.encoding()),
        magic_ok: hdr.magic_ok,
        base_offset,
        tables,
        schema_objects: schema.len(),
        live_rows,
        deleted_rows,
        carved_rows,
        wal_present,
        journal_present,
        wal_frames,
        journal_frames,
        freelist_pages: freelist_page_count,
        warnings,
    };

    Some(ExtractionResult {
        summary,
        schema,
        records,
        records_truncated,
    })
}
