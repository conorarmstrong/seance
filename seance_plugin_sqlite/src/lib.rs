#![forbid(unsafe_code)]
//! Forensic SQLite database parser module.
//!
//! Parses SQLite databases as raw b-trees (no driver, no temp copy), recovering
//! deleted rows from freeblocks, freelist pages, and unallocated/slack space,
//! and pulling additional page versions from `-wal`/`-journal` sidecars. Degrades
//! gracefully on corruption (zeroed/fuzzy magic, bad page size, truncation,
//! per-page damage) rather than failing the whole file.
//!
//! See [`sqlite_forensic`] for the parser internals.

pub mod sqlite_forensic;

use anyhow::Context;
use base64::Engine;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{detect_file_type, DetectedFileType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value as JsonValue};
use sqlite_forensic::record::Value;
use sqlite_forensic::{extract, ForensicOptions, ForensicRecord};
use std::path::PathBuf;
use tracing::info;

/// Maximum number of row artifacts emitted per database (truncation recorded
/// honestly in the summary).
const MAX_RECORDS_EMITTED: usize = 50_000;

/// Blob bytes at or below this size are emitted as full base64; larger blobs get
/// a bounded hex preview plus the true size.
const BLOB_INLINE_LIMIT: usize = 256;

pub struct SqliteParser;

/// A `-wal` / `-journal` sidecar as staged for the parser, with the fact of a
/// short staging kept beside the bytes.
///
/// A sidecar read that stopped at the cap or ran out early yields FEWER page
/// versions, and the rows only that sidecar held then look like rows that never
/// existed. The bytes alone cannot say that, so the flag travels with them.
#[derive(Debug, Default)]
struct Sidecar {
    bytes: Option<Vec<u8>>,
    /// Why the sidecar was not staged whole, when it was not: `cap_reached`
    /// when it is larger than `MAX_SIDECAR_BYTES`, `short_read` when the file or
    /// sibling could not deliver the bytes it declared. `None` means it was
    /// staged whole, or there was no sidecar at all — the two are told apart by
    /// `bytes`.
    incomplete: Option<IncompleteReason>,
}

impl SqliteParser {
    /// Locates the `-wal`/`-journal` sidecars for a database and returns their
    /// bytes.
    ///
    /// Two discovery routes are tried, in order:
    /// 1. **Local filesystem** — a file named `<db>-wal` / `<db>-journal` beside
    ///    the database, via the artifact's `source_path` metadata or the data
    ///    source's underlying path. This is the common on-disk case.
    /// 2. **Sibling through the data source** — a `-wal`/`-journal` entry inside
    ///    the *same container* as the database (e.g. a ZIP), reached via
    ///    [`DataSource::open_sibling`]. The path-based lookup above cannot see
    ///    these because a containerized database has no local path.
    ///
    /// A caller may still override both by supplying sidecar bytes directly via
    /// [`ForensicOptions`].
    ///
    /// Each route is capped at `MAX_SIDECAR_BYTES`, and a sidecar that could not
    /// be staged whole is returned with [`Sidecar::incomplete`] set: the page
    /// versions past the cap are not recovered, and without the flag the rows
    /// they held are indistinguishable from rows that never existed.
    fn discover_sidecars(artifact: &Artifact) -> (Sidecar, Sidecar) {
        // Cap sidecar reads: a WAL/journal is normally small, and reading an
        // arbitrarily large file whole into RAM is an OOM vector on hostile or
        // corrupt evidence. 512 MiB is far beyond any legitimate WAL.
        const MAX_SIDECAR_BYTES: u64 = 512 * 1024 * 1024;

        let base_path = artifact
            .metadata
            .get("source_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .or_else(|| artifact.data.as_ref().and_then(|d| d.get_underlying_path()));

        // Route 1: a sidecar file on the local filesystem beside the database.
        let read_fs_sidecar = |suffix: &str| -> Option<Sidecar> {
            use std::io::Read;
            let base = base_path.as_ref()?;
            let path = PathBuf::from(format!("{}{}", base.to_string_lossy(), suffix));
            let declared = std::fs::metadata(&path).ok()?.len();
            let file = std::fs::File::open(&path).ok()?;
            let mut buf = Vec::new();
            file.take(MAX_SIDECAR_BYTES).read_to_end(&mut buf).ok()?;
            Some(Sidecar {
                incomplete: shortfall(buf.len() as u64, declared, MAX_SIDECAR_BYTES),
                bytes: Some(buf),
            })
        };

        // Route 2: a sibling reachable through the data source itself (e.g. a
        // `-wal` entry inside the same container as the database).
        let read_source_sibling = |suffix: &str| -> Option<Sidecar> {
            let sib = artifact.data.as_ref()?.open_sibling(suffix)?;
            let declared = sib.size();
            let size = declared.min(MAX_SIDECAR_BYTES);
            let mut buf = vec![0u8; size as usize];
            let mut off = 0usize;
            while off < buf.len() {
                match sib.read_at(off as u64, &mut buf[off..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n,
                }
            }
            buf.truncate(off);
            if buf.is_empty() {
                return None;
            }
            Some(Sidecar {
                incomplete: shortfall(buf.len() as u64, declared, MAX_SIDECAR_BYTES),
                bytes: Some(buf),
            })
        };

        let discover = |suffix: &str| {
            read_fs_sidecar(suffix)
                .or_else(|| read_source_sibling(suffix))
                .unwrap_or_default()
        };
        (discover("-wal"), discover("-journal"))
    }
}

/// Why `got` bytes is less than the `declared` size, if it is.
///
/// `cap_reached` when the object is bigger than the caller's ceiling,
/// `short_read` when it simply could not deliver what it declared. `None` means
/// nothing is missing — which is the only state in which a result may be
/// presented as complete.
fn shortfall(got: u64, declared: u64, cap: u64) -> Option<IncompleteReason> {
    if got >= declared {
        None
    } else if declared > cap {
        Some(IncompleteReason::CapReached)
    } else {
        Some(IncompleteReason::ShortRead)
    }
}

/// Whether `ds` can deliver the last byte of the size it declares.
///
/// This parser deliberately never loads the database into RAM — it walks pages
/// through `read_at` — so it never holds a byte count to compare against
/// `size()` the way the spill-based plugins do. Without this probe a truncated
/// image, a container entry whose backing extents run out, or a carved fragment
/// simply yields the pages it can reach: fewer tables, fewer rows, and a
/// recovery indistinguishable from a complete one.
///
/// One byte is read at `size() - 1`. A source that answers it can reach its own
/// end; a source that returns nothing there cannot, and every page past that
/// point is unread. An empty source declares nothing and is therefore not short.
///
/// What an examiner learns: whether the rows recovered from this database are
/// all of the ones it holds. A wrong answer here is an absence conclusion drawn
/// from a truncated read.
fn source_reaches_its_declared_end(ds: &dyn seance_core::data_source::DataSource) -> bool {
    let size = ds.size();
    if size == 0 {
        return true;
    }
    let mut last = [0u8; 1];
    seance_core::io::read_full(ds, size - 1, &mut last) == 1
}

impl ForensicsModule for SqliteParser {
    fn id(&self) -> &str {
        "plugin.generic.sqlite_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // A `ParsedRecord` is read only when it is a shadow-copy prior version
        // (HUNT-274); every other parsed record returns before its data is
        // touched.
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        // We read via `read_at` on the artifact's data source directly; Stream
        // is the capability the orchestrator already provides for that. (No temp
        // spill, no whole-file load.)
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_database(a))
    }
}

impl SqliteParser {
    fn parse_database(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds.clone(),
            None => return Ok(Vec::new()),
        };

        // Content-based gate: fire on a clean SQLite magic OR on a structurally
        // recoverable database whose header magic is damaged. Never gate on the
        // filename.
        let detected = detect_file_type(data_source.as_ref());
        let is_sqlite = detected == DetectedFileType::SqliteDatabase
            || sqlite_forensic::looks_like_sqlite_source(data_source.as_ref());
        if !is_sqlite {
            return Ok(Vec::new());
        }

        info!(
            "SQLite forensic parser engaged (artifact ID: {})",
            artifact.id
        );

        let (wal, journal) = Self::discover_sidecars(artifact);
        let sidecar_incomplete = wal.incomplete.or(journal.incomplete);
        // The database itself: pages past the last byte the source can deliver
        // were never walked, so the tables and rows recovered are a subset.
        let source_short = !source_reaches_its_declared_end(data_source.as_ref());
        let opts = ForensicOptions {
            enable_carving: true,
            max_records: MAX_RECORDS_EMITTED,
            wal_bytes: wal.bytes,
            journal_bytes: journal.bytes,
        };

        let result = extract(data_source.as_ref(), &opts)
            .context("data source did not parse as a SQLite database")
            .map_err(|e| ModuleError::ParsingError(e.to_string()))?;

        let mut artifacts = Vec::with_capacity(result.records.len() + 1);

        // Which database a row came from. Without it every recovered row in the
        // case looks alike and the examiner cannot tell whose "message" table
        // they are reading.
        let db_name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown database")
            .to_string();
        let db_path = artifact
            .metadata
            .get("relative_path")
            .or_else(|| artifact.metadata.get("path"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Per-row artifacts.
        for record in &result.records {
            let mut metadata = record_to_metadata(record);
            if let Some(map) = metadata.as_object_mut() {
                map.insert("database".to_string(), json!(db_name));
                map.insert("database_artifact".to_string(), json!(artifact.id));
                if let Some(ref p) = db_path {
                    map.insert("database_path".to_string(), json!(p));
                }
            }
            artifacts.push(
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(artifact.id),
            );
        }

        // Recovered-conversation reconstruction: if the recovered rows belong to a
        // known chat app (iMessage/WhatsApp/SMS), thread them into chat_message
        // records the conversation viewer renders, each flagged recovered. This
        // turns a "cleared history" database — whose live tables are empty — into a
        // readable deleted conversation instead of loose rows.
        let conversations = sqlite_forensic::recovered_chat::reconstruct(&result);
        let reconstructed = conversations.len();
        for mut convo in conversations {
            if let Some(map) = convo.as_object_mut() {
                map.insert("database".to_string(), json!(db_name));
                map.insert("database_artifact".to_string(), json!(artifact.id));
                if let Some(ref p) = db_path {
                    map.insert("database_path".to_string(), json!(p));
                }
            }
            artifacts.push(
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, convo)
                    .with_parent(artifact.id),
            );
        }

        // Database summary artifact. Carry the same database identity the rows
        // do, so a viewer can enumerate every database from the (few, never
        // truncated) summaries rather than from a bounded page of rows.
        let mut summary = summary_to_metadata(&result);
        if let Some(map) = summary.as_object_mut() {
            map.insert("database".to_string(), json!(db_name));
            map.insert("database_artifact".to_string(), json!(artifact.id));
            if let Some(ref p) = db_path {
                map.insert("database_path".to_string(), json!(p));
            }
            // A database whose source cannot reach its own declared end was
            // walked over a prefix: the pages past that point hold tables and
            // rows this result does not have. Stated first because it is the
            // coarsest loss on the record.
            if source_short {
                map.insert("source_short_read".to_string(), json!(true));
                map.insert("content_incomplete".to_string(), json!(true));
                map.insert(
                    "content_incomplete_reason".to_string(),
                    json!(IncompleteReason::ShortRead.as_str()),
                );
                map.insert(
                    "incomplete_detail".to_string(),
                    json!(format!(
                        "the source could not deliver the {} bytes it declares for this \
                         database; pages past the readable end were never walked, so tables \
                         and rows missing here are not missing from the database",
                        data_source.size()
                    )),
                );
            }
            // A sidecar staged short means page versions — and the rows only
            // those versions hold — were never seen. That is content missing
            // from the recovery, so it uses the same pair every consumer reads.
            if let Some(reason) = sidecar_incomplete {
                map.insert("sidecar_truncated".to_string(), json!(true));
                map.insert(
                    "sidecar_incomplete_reason".to_string(),
                    json!(reason.as_str()),
                );
                map.insert("content_incomplete".to_string(), json!(true));
                if !source_short {
                    map.insert(
                        "content_incomplete_reason".to_string(),
                        json!(reason.as_str()),
                    );
                    map.insert(
                        "incomplete_detail".to_string(),
                        json!(
                            "a -wal / -journal sidecar could not be staged in full; the page \
                             versions it holds were not searched for recoverable rows, so rows \
                             that lived only there look like rows that never existed"
                        ),
                    );
                }
            }
        }
        artifacts.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, summary)
                .with_parent(artifact.id),
        );

        info!(
            "SQLite forensic parser produced {} artifacts ({} live, {} deleted, {} carved, {} recovered messages)",
            artifacts.len(),
            result.summary.live_rows,
            result.summary.deleted_rows,
            result.summary.carved_rows,
            reconstructed
        );

        Ok(artifacts)
    }
}

/// Converts a decoded value into JSON. Blobs become base64 (small) or a bounded
/// hex preview plus the true size (large) rather than `<blob N>`.
fn value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(n) => json!(n),
        Value::Float(f) => json!(f),
        Value::Text(s) => json!(s),
        Value::Blob(bytes) => {
            if bytes.len() <= BLOB_INLINE_LIMIT {
                json!({
                    "blob": true,
                    "size": bytes.len(),
                    "base64": base64::engine::general_purpose::STANDARD.encode(bytes),
                })
            } else {
                let preview: String = bytes[..64].iter().map(|b| format!("{:02x}", b)).collect();
                json!({
                    "blob": true,
                    "size": bytes.len(),
                    "hex_preview": preview,
                    "truncated": true,
                })
            }
        }
    }
}

fn record_to_metadata(record: &ForensicRecord) -> JsonValue {
    let mut columns = serde_json::Map::new();
    for (name, value) in record.columns.iter().zip(record.values.iter()) {
        columns.insert(name.clone(), value_to_json(value));
    }
    json!({
        "type": "SqliteRow",
        "table": record.table,
        "rowid": record.rowid,
        "page": record.page_number,
        "deleted": record.deleted,
        "recovery_source": record.recovery_source.map(|s| s.as_str()),
        "confidence": record.confidence,
        "columns": columns,
        "corruption_notes": record.notes,
        "source": "SqliteForensicParser",
    })
}

fn summary_to_metadata(result: &sqlite_forensic::ExtractionResult) -> JsonValue {
    let s = &result.summary;
    let schema: Vec<JsonValue> = result
        .schema
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "type": e.obj_type,
                "tbl_name": e.tbl_name,
                "root_page": e.root_page,
                "columns": e.columns,
                "sql": e.sql,
            })
        })
        .collect();

    let mut meta = json!({
        "type": "SqliteDatabaseForensics",
        "page_size": s.page_size,
        "page_count": s.page_count,
        "encoding": s.encoding,
        "magic_ok": s.magic_ok,
        "base_offset": s.base_offset,
        "tables": s.tables,
        "schema_objects": s.schema_objects,
        "schema": schema,
        "live_rows": s.live_rows,
        "deleted_rows": s.deleted_rows,
        "carved_rows": s.carved_rows,
        "freelist_pages": s.freelist_pages,
        "wal_present": s.wal_present,
        "wal_frames": s.wal_frames,
        "journal_present": s.journal_present,
        "journal_frames": s.journal_frames,
        "records_emitted": result.records.len(),
        "records_truncated": result.records_truncated,
        "warnings": s.warnings,
        "source": "SqliteForensicParser",
    });

    // `records_truncated` is this parser's own key and predates the shared
    // vocabulary; the API and the export honesty paths key on
    // `content_incomplete` / `content_incomplete_reason`, and on
    // `inventory_incomplete` for a listing that stopped short. Stamping only the
    // bespoke key left a capped recovery presenting as the whole set of rows the
    // database held (B3-015). Both are written; nothing that reads the old key
    // breaks.
    if result.records_truncated {
        if let Some(map) = meta.as_object_mut() {
            map.insert("inventory_incomplete".to_string(), json!(true));
            map.insert("content_incomplete".to_string(), json!(true));
            map.insert(
                "content_incomplete_reason".to_string(),
                json!(IncompleteReason::CapReached.as_str()),
            );
            map.insert("max_records".to_string(), json!(MAX_RECORDS_EMITTED));
            map.insert(
                "incomplete_detail".to_string(),
                json!(format!(
                    "row emission stopped at the {MAX_RECORDS_EMITTED}-record cap; recovered \
                     (deleted) rows were kept first, and the rows not emitted are absent from \
                     this result — they are not absent from the database"
                )),
            );
        }
    }

    meta
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    fn artifact_with_source(bytes: Vec<u8>) -> Artifact {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "test.db" }),
        )
    }

    #[test]
    fn module_identity_and_gate() {
        let p = SqliteParser;
        assert_eq!(p.id(), "plugin.generic.sqlite_parser");
        assert!(!p.version().is_empty());
        let subs = p.subscribes_to();
        assert!(subs.contains(&ArtifactType::FileEntry));
        assert!(subs.contains(&ArtifactType::SystemArtifact));
    }

    #[test]
    fn missing_data_source_returns_empty() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "no_data.db" }),
        );
        assert!(SqliteParser.process(&art).unwrap().is_empty());
    }

    #[test]
    fn non_sqlite_content_is_skipped() {
        let art = artifact_with_source(b"this is definitely not a sqlite file".to_vec());
        assert!(SqliteParser.process(&art).unwrap().is_empty());
    }

    #[test]
    fn blob_small_is_base64() {
        let j = value_to_json(&Value::Blob(vec![0, 1, 2, 3, 4]));
        assert_eq!(j["blob"], json!(true));
        assert_eq!(j["size"], json!(5));
        assert!(j["base64"].as_str().is_some());
    }

    #[test]
    fn blob_large_is_hex_preview() {
        let j = value_to_json(&Value::Blob(vec![0xAB; 1000]));
        assert_eq!(j["size"], json!(1000));
        assert_eq!(j["truncated"], json!(true));
        assert!(j["hex_preview"].as_str().unwrap().len() == 128);
    }

    fn extraction(records_truncated: bool) -> sqlite_forensic::ExtractionResult {
        sqlite_forensic::ExtractionResult {
            summary: sqlite_forensic::DbSummary {
                page_size: 4096,
                page_count: 1,
                encoding: "UTF-8",
                magic_ok: true,
                base_offset: 0,
                tables: vec!["message".to_string()],
                schema_objects: 1,
                live_rows: 1,
                deleted_rows: 0,
                carved_rows: 0,
                wal_present: false,
                journal_present: false,
                wal_frames: 0,
                journal_frames: 0,
                freelist_pages: 0,
                warnings: vec![],
            },
            schema: vec![],
            records: vec![],
            records_truncated,
        }
    }

    /// B3-015: the record cap was recorded as `records_truncated` alone, a key
    /// the API and export honesty paths never read, so a capped recovery
    /// presented as the complete set of rows the database held. What an examiner
    /// learns: whether the rows listed are all the parser found. A wrong answer
    /// here is an absence conclusion drawn from a cap.
    #[test]
    fn a_capped_recovery_carries_the_standard_incompleteness_pair() {
        let meta = summary_to_metadata(&extraction(true));
        // The bespoke key stays: other code may already read it.
        assert_eq!(meta["records_truncated"], json!(true));
        // ...alongside the vocabulary the consumers actually key on.
        assert_eq!(meta["content_incomplete"], json!(true));
        assert_eq!(meta["content_incomplete_reason"], "cap_reached");
        assert_eq!(meta["inventory_incomplete"], json!(true));
        assert_eq!(meta["max_records"], json!(MAX_RECORDS_EMITTED));
        assert!(meta["incomplete_detail"]
            .as_str()
            .expect("the detail says what is missing")
            .contains("not absent from the database"));
    }

    /// The counterpart: an uncapped recovery must stay unmarked, or the marker
    /// means nothing.
    #[test]
    fn a_complete_recovery_carries_no_incompleteness_pair() {
        let meta = summary_to_metadata(&extraction(false));
        assert_eq!(meta["records_truncated"], json!(false));
        assert!(meta.get("content_incomplete").is_none());
        assert!(meta.get("inventory_incomplete").is_none());
    }

    /// A source whose `-wal` sibling declares more bytes than it can deliver —
    /// a container entry whose backing extents run out mid-log.
    #[derive(Debug)]
    struct SourceWithShortWal {
        db: Vec<u8>,
        wal: Vec<u8>,
    }

    fn copy_from(data: &[u8], offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    impl DataSource for SourceWithShortWal {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            copy_from(&self.db, offset, buf)
        }
        fn size(&self) -> u64 {
            self.db.len() as u64
        }
        fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
            (suffix == "-wal")
                .then(|| Arc::new(TruncatedSource::halved(self.wal.clone())) as Arc<dyn DataSource>)
        }
    }

    /// A `-wal` sidecar that could not be staged whole hides page versions, and
    /// the rows only those versions held look like rows that never existed.
    /// Before the fix the short read was silently kept and the summary said
    /// nothing.
    #[test]
    fn a_sidecar_staged_short_is_reported_rather_than_silently_kept() {
        let src: Arc<dyn DataSource> = Arc::new(SourceWithShortWal {
            db: b"SQLite format 3\0".to_vec(),
            wal: vec![0xAAu8; 64],
        });
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "test.db" }),
        );
        let (wal, journal) = SqliteParser::discover_sidecars(&art);
        assert!(wal.bytes.is_some(), "the readable prefix is still used");
        assert_eq!(
            wal.incomplete,
            Some(IncompleteReason::ShortRead),
            "a -wal that delivered less than it declared is short, not capped: \
             the reason an examiner is given must be the one that happened"
        );
        assert!(journal.bytes.is_none());
        assert!(
            journal.incomplete.is_none(),
            "an absent sidecar is not a short one"
        );
    }

    fn small_database() -> Vec<u8> {
        let path = std::env::temp_dir().join(format!("seance_sqlite_vss_{}.db", Uuid::new_v4()));
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT);
                 INSERT INTO message (body) VALUES ('hello');",
            )
            .unwrap();
        }
        let db = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        db
    }

    /// HUNT-274: a database inside a shadow copy was listed and never opened.
    /// A `VssPriorVersion` record is now read, and every row recovered from it
    /// repeats the snapshot label, so it cannot be mistaken for the live
    /// database; a `ParsedRecord` that is not a prior version is not read.
    #[test]
    fn a_shadow_copy_prior_version_is_parsed_and_every_row_says_so() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(small_database()));
        let prior = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(src.clone()),
            json!({
                "type": "VssPriorVersion",
                "name": "snapshot.db [shadow copy 2015-03-23]",
                "is_snapshot_version": true,
                "snapshot_label": "SHADOW COPY VERSION, not the live volume",
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
                "vss_stack_position": 0,
            }),
        );
        let out = SqliteParser.process(&prior).unwrap();
        assert!(!out.is_empty(), "the prior version's database is parsed");
        for a in &out {
            assert_eq!(
                a.metadata["is_snapshot_version"],
                json!(true),
                "{}",
                a.metadata
            );
            assert_eq!(a.metadata["vss_snapshot_id"], json!("snap-1"));
            assert_eq!(a.parent_id, Some(prior.id));
        }

        let other = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(src),
            json!({ "type": "SomethingElse" }),
        );
        assert!(SqliteParser.process(&other).unwrap().is_empty());
    }

    /// Same class as the sidecar shortfall, on the database itself. This parser
    /// never buffers the file, so nothing compared what the source can deliver
    /// against what it declares: a truncated image or a container entry whose
    /// extents run out yielded the pages it could reach and a summary that said
    /// the recovery was whole.
    ///
    /// What an examiner learns: whether the rows recovered are all the database
    /// holds. A wrong answer here is an absence conclusion drawn from a cut read.
    #[test]
    fn a_database_whose_source_cannot_reach_its_declared_end_is_reported_short() {
        // A real database, behind a source that claims twice its length.
        let path = std::env::temp_dir().join(format!("seance_sqlite_short_{}.db", Uuid::new_v4()));
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT);
                 INSERT INTO message (body) VALUES ('hello');",
            )
            .unwrap();
        }
        let db = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(
            !source_reaches_its_declared_end(&TruncatedSource::halved(db.clone())),
            "a source that cannot answer at size()-1 is short"
        );
        assert!(
            source_reaches_its_declared_end(&ByteSliceDataSource::new(db.clone())),
            "a source that delivers what it declares is not short"
        );

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(TruncatedSource::halved(db)) as Arc<dyn DataSource>),
            json!({ "name": "short.db" }),
        );
        let out = SqliteParser.process(&art).unwrap();
        let summary = out
            .iter()
            .find(|a| a.metadata["type"] == "SqliteDatabaseForensics")
            .expect("the readable prefix still parses into a summary");
        assert_eq!(summary.metadata["source_short_read"], json!(true));
        assert_eq!(summary.metadata["content_incomplete"], json!(true));
        assert_eq!(summary.metadata["content_incomplete_reason"], "short_read");
    }
}
