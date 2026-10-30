//! Integration tests for the forensic SQLite parser.
//!
//! Proves, with assertions:
//! - deleted rows are recovered from a database with known-deleted content
//!   (vendored `base.db`, where user "Charlie" was deleted, and a purpose-built
//!   fixture);
//! - a truncated / zeroed-header / bad-page-size database yields partial
//!   extraction rather than a hard error, and no fixture panics;
//! - WAL and rollback-journal pages contribute rows tagged with their source;
//! - the full row count (not a 5-row sample) is returned;
//! - dropped tables are recovered from the freelist with inferred columns;
//! - BLOBs are returned as real bytes.

use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_sqlite::sqlite_forensic::record::Value;
use seance_plugin_sqlite::sqlite_forensic::{extract, ForensicOptions, RecoverySource};
use seance_plugin_sqlite::SqliteParser;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/sqlite_extract_go/testdata/corrupted")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// True (with a logged skip) when the vendored reference fixtures are absent,
/// e.g. on a fresh checkout or in CI where `reference/` is gitignored. Callers
/// `if fixtures_missing() { return; }` to skip gracefully instead of panicking.
fn fixtures_missing() -> bool {
    if !fixtures_dir().exists() {
        eprintln!("skipping: reference sqlite fixtures absent (gitignored, absent in CI)");
        return true;
    }
    false
}

/// Builds a database from a setup closure and returns its raw bytes.
fn build_db<F: FnOnce(&Connection)>(setup: F) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_forensic_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        setup(&conn);
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

fn text_values(rec: &seance_plugin_sqlite::sqlite_forensic::ForensicRecord) -> String {
    rec.values
        .iter()
        .filter_map(|v| match v {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("|")
}

// ---------------------------------------------------------------------------
// 1. Deleted-record recovery (headline) on a known fixture.
// ---------------------------------------------------------------------------

#[test]
fn base_db_recovers_known_deleted_row() {
    if fixtures_missing() {
        return;
    }
    // base.db has a users table where id=3 ("Charlie" / charlie@example.com) was
    // deleted, plus a messages table. Live users are Alice, Bob, Diana, Eve.
    let r = extract(
        &ByteSliceDataSource::new(read_fixture("base.db")),
        &ForensicOptions::default(),
    )
    .expect("base.db must parse");

    assert_eq!(r.summary.page_size, 4096);
    assert_eq!(r.summary.page_count, 3);
    assert!(r.summary.tables.contains(&"users".to_string()));
    assert!(r.summary.tables.contains(&"messages".to_string()));

    // 4 live users + 3 live messages.
    assert_eq!(r.summary.live_rows, 7);

    // The deleted row must be recovered and tagged.
    let deleted: Vec<_> = r.records.iter().filter(|x| x.deleted).collect();
    assert!(
        !deleted.is_empty(),
        "expected at least one recovered deleted row"
    );
    let charlie = deleted
        .iter()
        .find(|x| text_values(x).contains("charlie@example.com"));
    let charlie = charlie.expect("deleted user 'charlie@example.com' must be recovered");
    assert!(charlie.deleted);
    assert!(charlie.recovery_source.is_some());
    assert!(
        charlie.confidence < 100,
        "recovered rows should have reduced confidence"
    );

    // No live row should carry the deleted email.
    for rec in r.records.iter().filter(|x| !x.deleted) {
        assert!(!text_values(rec).contains("charlie@example.com"));
    }
}

#[test]
fn own_fixture_recovers_deleted_body() {
    let db = build_db(|conn| {
        conn.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)",
            [],
        )
        .unwrap();
        for i in 0..8 {
            conn.execute(
                "INSERT INTO notes (title, body) VALUES (?1, ?2)",
                [format!("title_{i}"), format!("secret_body_{i}")],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM notes WHERE id = 4", []).unwrap();
    });

    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    assert_eq!(r.summary.live_rows, 7);
    let recovered = r
        .records
        .iter()
        .filter(|x| x.deleted)
        .any(|x| text_values(x).contains("secret_body_3"));
    assert!(
        recovered,
        "deleted row body 'secret_body_3' must be recovered"
    );
}

// ---------------------------------------------------------------------------
// 2. Corruption resilience.
// ---------------------------------------------------------------------------

#[test]
fn zeroed_header_still_extracts_and_recovers() {
    if fixtures_missing() {
        return;
    }
    // First 100 bytes zeroed. The page-1 b-tree header (offset 100) survives, so
    // full extraction plus deleted-row recovery must still work.
    let r = extract(
        &ByteSliceDataSource::new(read_fixture("zeroed_header.db")),
        &ForensicOptions::default(),
    )
    .expect("zeroed header must be recovered, not rejected");
    assert!(r.summary.warnings.iter().any(|w| w.contains("zeroed")));
    assert_eq!(r.summary.live_rows, 7);
    assert!(r.records.iter().any(|x| x.deleted));
}

#[test]
fn truncated_and_bad_pagesize_degrade_gracefully() {
    if fixtures_missing() {
        return;
    }
    // Each of these must return partial results (Some) without a hard error.
    for name in [
        "truncated_header.db",
        "truncated_midpage.db",
        "corrupt_pagesize.db",
        "odd_pagesize.db",
        "brute_force_db.db",
        "corrupt_page_header.db",
    ] {
        let r = extract(
            &ByteSliceDataSource::new(read_fixture(name)),
            &ForensicOptions::default(),
        );
        assert!(r.is_some(), "{name} should degrade to partial extraction");
    }

    // corrupt_page_header.db has page 2 clobbered; page 3 (messages) still parses.
    let r = extract(
        &ByteSliceDataSource::new(read_fixture("corrupt_page_header.db")),
        &ForensicOptions::default(),
    )
    .unwrap();
    assert!(
        r.summary.live_rows > 0 && r.summary.live_rows < 7,
        "expected partial extraction, got {} rows",
        r.summary.live_rows
    );
}

#[test]
fn every_corrupted_fixture_never_panics() {
    if fixtures_missing() {
        return;
    }
    let dir = fixtures_dir();
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|x| x == "db").unwrap_or(false) {
            // Must not panic; result may be Some (partial) or None (unreadable).
            let _ = extract(
                &ByteSliceDataSource::new(std::fs::read(&path).unwrap()),
                &ForensicOptions::default(),
            );
            count += 1;
        }
    }
    assert!(count >= 10, "expected the vendored corrupted corpus");
}

#[test]
fn random_bytes_are_rejected() {
    let junk = vec![0x42u8; 5000];
    assert!(extract(&ByteSliceDataSource::new(junk), &ForensicOptions::default()).is_none());
}

// ---------------------------------------------------------------------------
// 3. WAL + rollback journal recovery.
// ---------------------------------------------------------------------------

#[test]
fn wal_pages_contribute_rows() {
    let tmp = std::env::temp_dir().join(format!("seance_wal_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&tmp).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0i64)
        .unwrap();
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT)", [])
        .unwrap();
    for i in 0..8 {
        conn.execute("INSERT INTO t (note) VALUES (?1)", [format!("wal_row_{i}")])
            .unwrap();
    }
    let db_bytes = std::fs::read(&tmp).unwrap();
    let wal_bytes = std::fs::read(format!("{}-wal", tmp.display())).ok();
    assert!(wal_bytes.is_some(), "WAL sidecar should exist");

    let opts = ForensicOptions {
        wal_bytes,
        ..Default::default()
    };
    let r = extract(&ByteSliceDataSource::new(db_bytes), &opts).unwrap();
    assert!(r.summary.wal_present);
    assert!(r.summary.wal_frames > 0);
    let wal_rows: Vec<_> = r
        .records
        .iter()
        .filter(|x| x.recovery_source == Some(RecoverySource::Wal))
        .collect();
    assert!(
        wal_rows
            .iter()
            .any(|x| text_values(x).contains("wal_row_0")),
        "WAL frames must contribute the inserted rows"
    );

    drop(conn);
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}-wal", tmp.display()));
    let _ = std::fs::remove_file(format!("{}-shm", tmp.display()));
}

/// A rollback-journal row must carry the table it came from, and its column
/// names with it.
///
/// Every journal record was published with `table: None`, while the recovered
/// -conversation reader threads only rows whose `table` matches the schema it
/// is rebuilding — so a rolled-back deletion of a chat table could never reach
/// the conversation view, though the module's own documentation said freelist
/// and journal rows were joined back into it. The WAL path had always used the
/// page-to-table map; the journal path is the same shape and did not.
#[test]
fn a_journal_row_is_attributed_to_the_table_its_page_belongs_to() {
    let tmp = std::env::temp_dir().join(format!("seance_jrn_tbl_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&tmp).unwrap();
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)", [])
        .unwrap();
    for i in 0..30 {
        conn.execute(
            "INSERT INTO notes (body) VALUES (?1)",
            [format!("body_{i}")],
        )
        .unwrap();
    }
    conn.execute_batch("BEGIN; UPDATE notes SET body='wiped';")
        .unwrap();
    let journal_bytes = std::fs::read(format!("{}-journal", tmp.display())).ok();
    conn.execute_batch("ROLLBACK;").unwrap();
    let db_bytes = std::fs::read(&tmp).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&tmp);

    let opts = ForensicOptions {
        journal_bytes,
        ..Default::default()
    };
    let r = extract(&ByteSliceDataSource::new(db_bytes), &opts).unwrap();
    let attributed: Vec<_> = r
        .records
        .iter()
        .filter(|x| {
            x.recovery_source == Some(RecoverySource::Journal)
                && x.table.as_deref() == Some("notes")
        })
        .collect();
    assert!(
        !attributed.is_empty(),
        "a journal page that belongs to `notes` must say so; got tables {:?}",
        r.records
            .iter()
            .filter(|x| x.recovery_source == Some(RecoverySource::Journal))
            .map(|x| x.table.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        attributed
            .iter()
            .any(|x| x.columns.contains(&"body".to_string())),
        "and must carry that table's column names"
    );
    // The inference is labelled: the page-to-table map is the database as it is
    // now, and a page reused since the journal was written would be misread.
    assert!(
        attributed
            .iter()
            .any(|x| x.notes.iter().any(|n| n.contains("inferred"))),
        "the attribution is an inference and must say so: {:?}",
        attributed
            .iter()
            .map(|x| x.notes.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_file(format!("{}-journal", tmp.display()));
}

#[test]
fn journal_pages_contribute_rows() {
    // Commit rows, then open a transaction that overwrites them so their
    // pre-images land in the rollback journal, then feed the journal.
    let tmp = std::env::temp_dir().join(format!("seance_jrn_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&tmp).unwrap();
    conn.execute("CREATE TABLE j (id INTEGER PRIMARY KEY, tag TEXT)", [])
        .unwrap();
    for i in 0..30 {
        conn.execute(
            "INSERT INTO j (tag) VALUES (?1)",
            [format!("journal_tag_{i}")],
        )
        .unwrap();
    }
    conn.execute_batch("BEGIN; UPDATE j SET tag='wiped';")
        .unwrap();
    let journal_bytes = std::fs::read(format!("{}-journal", tmp.display())).ok();
    assert!(journal_bytes.is_some(), "journal sidecar should exist");
    conn.execute_batch("ROLLBACK;").unwrap();
    let db_bytes = std::fs::read(&tmp).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&tmp);

    let opts = ForensicOptions {
        journal_bytes,
        ..Default::default()
    };
    let r = extract(&ByteSliceDataSource::new(db_bytes), &opts).unwrap();
    assert!(r.summary.journal_present);
    assert!(r.summary.journal_frames > 0);
    let jrn_rows: Vec<_> = r
        .records
        .iter()
        .filter(|x| x.recovery_source == Some(RecoverySource::Journal))
        .collect();
    assert!(
        jrn_rows
            .iter()
            .any(|x| text_values(x).contains("journal_tag_0")),
        "journal pre-image pages must contribute the original rows"
    );
}

#[test]
fn vendored_journal_parses_without_error() {
    if fixtures_missing() {
        return;
    }
    // valid.journal's page-2 pre-image is an empty table (rolled back before any
    // inserts committed), so it contributes 0 rows, but must parse cleanly.
    let opts = ForensicOptions {
        journal_bytes: Some(read_fixture("valid.journal")),
        ..Default::default()
    };
    let r = extract(
        &ByteSliceDataSource::new(read_fixture("with_journal.db")),
        &opts,
    )
    .unwrap();
    assert!(r.summary.journal_present);
    assert_eq!(r.summary.journal_frames, 1);
}

// ---------------------------------------------------------------------------
// 4. Full extraction (not a 5-row sample), dropped tables, blobs.
// ---------------------------------------------------------------------------

#[test]
fn full_row_count_is_returned_not_sampled() {
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE big (id INTEGER PRIMARY KEY, v TEXT)", [])
            .unwrap();
        for i in 0..500 {
            conn.execute("INSERT INTO big (v) VALUES (?1)", [format!("row_{i}")])
                .unwrap();
        }
    });
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    assert_eq!(
        r.summary.live_rows, 500,
        "all rows must be returned (old parser sampled only 5)"
    );
}

#[test]
fn dropped_table_recovered_from_freelist_with_inferred_columns() {
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE keep (id INTEGER PRIMARY KEY, x TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO keep (x) VALUES ('keepme')", [])
            .unwrap();
        conn.execute(
            "CREATE TABLE gone (id INTEGER PRIMARY KEY, payload TEXT)",
            [],
        )
        .unwrap();
        for i in 0..250 {
            conn.execute(
                "INSERT INTO gone (payload) VALUES (?1)",
                [format!("dropped_row_{i:04}")],
            )
            .unwrap();
        }
        conn.execute("DROP TABLE gone", []).unwrap();
    });
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    assert!(!r.summary.tables.contains(&"gone".to_string()));
    assert!(
        r.summary.freelist_pages > 0,
        "dropped pages should be on the freelist"
    );
    let freelist_rows: Vec<_> = r
        .records
        .iter()
        .filter(|x| x.recovery_source == Some(RecoverySource::Freelist))
        .collect();
    assert!(
        freelist_rows
            .iter()
            .any(|x| text_values(x).contains("dropped_row_")),
        "dropped-table rows must be recovered from the freelist"
    );
    // Orphaned records get inferred placeholder column names.
    let orphan = freelist_rows
        .iter()
        .find(|x| !x.columns.is_empty())
        .expect("freelist rows should have inferred columns");
    assert!(orphan.columns.iter().all(|c| c.starts_with('c')));
    assert!(orphan.table.is_none());
}

#[test]
fn blobs_are_returned_as_real_bytes() {
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE b (id INTEGER PRIMARY KEY, data BLOB)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO b (data) VALUES (?1)",
            [&[0xDE_u8, 0xAD, 0xBE, 0xEF, 0x00, 0x01] as &[u8]],
        )
        .unwrap();
    });
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    let row = r
        .records
        .iter()
        .find(|x| x.table.as_deref() == Some("b"))
        .expect("blob table row");
    let blob = row
        .values
        .iter()
        .find_map(|v| match v {
            Value::Blob(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("row should contain a BLOB value");
    assert_eq!(blob, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
}

// ---------------------------------------------------------------------------
// 5. ForensicsModule integration.
// ---------------------------------------------------------------------------

fn artifact_with(bytes: Vec<u8>, metadata: serde_json::Value) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, Some(src), metadata)
}

#[test]
fn module_emits_summary_and_row_artifacts_with_schema() {
    if fixtures_missing() {
        return;
    }
    let art = artifact_with(read_fixture("base.db"), json!({ "name": "anything" }));
    let out = SqliteParser.process(&art).unwrap();
    assert!(out.len() > 7, "expected row artifacts plus a summary");

    // Summary artifact carries db metadata.
    let summary = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteDatabaseForensics")
        })
        .expect("summary artifact");
    assert_eq!(summary.metadata["page_size"], json!(4096));
    assert_eq!(summary.metadata["encoding"], json!("UTF-8"));
    assert!(summary.metadata["tables"].as_array().unwrap().len() >= 2);
    assert!(summary.metadata["deleted_rows"].as_u64().unwrap() >= 1);
    assert!(summary.metadata["schema"].as_array().unwrap().len() >= 2);

    // A recovered row artifact carries the required forensic fields.
    let deleted_row = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteRow")
                && a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true)
        })
        .expect("deleted row artifact");
    assert!(deleted_row.metadata.get("recovery_source").is_some());
    assert!(deleted_row.metadata.get("confidence").is_some());
    assert!(deleted_row.metadata.get("columns").is_some());
    assert_eq!(deleted_row.parent_id, Some(art.id));
    assert_eq!(deleted_row.artifact_type, ArtifactType::ParsedRecord);
}

#[test]
fn module_autofires_on_content_not_filename() {
    if fixtures_missing() {
        return;
    }
    // Non-database-looking name, but SQLite content => must fire.
    let art = artifact_with(read_fixture("base.db"), json!({ "name": "photo.jpg" }));
    let out = SqliteParser.process(&art).unwrap();
    assert!(
        !out.is_empty(),
        "content detection must trigger regardless of name"
    );
}

#[test]
fn module_skips_non_sqlite() {
    let art = artifact_with(b"not a database at all, just text".to_vec(), json!({}));
    assert!(SqliteParser.process(&art).unwrap().is_empty());
}

#[test]
fn module_discovers_wal_sidecar_from_source_path() {
    // Write a real db + -wal to disk; point the artifact at it via source_path.
    let tmp = std::env::temp_dir().join(format!("seance_sidecar_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&tmp).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0i64)
        .unwrap();
    conn.execute("CREATE TABLE s (id INTEGER PRIMARY KEY, note TEXT)", [])
        .unwrap();
    for i in 0..6 {
        conn.execute(
            "INSERT INTO s (note) VALUES (?1)",
            [format!("sidecar_row_{i}")],
        )
        .unwrap();
    }
    let db_bytes = std::fs::read(&tmp).unwrap();

    let art = artifact_with(
        db_bytes,
        json!({ "name": "s.db", "source_path": tmp.to_string_lossy() }),
    );
    let out = SqliteParser.process(&art).unwrap();

    // Summary should report the WAL was discovered and parsed.
    let summary = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteDatabaseForensics")
        })
        .unwrap();
    assert_eq!(summary.metadata["wal_present"], json!(true));
    assert!(summary.metadata["wal_frames"].as_u64().unwrap() > 0);

    // A WAL-sourced row artifact should carry the inserted text.
    let has_wal_row = out.iter().any(|a| {
        a.metadata.get("recovery_source").and_then(|v| v.as_str()) == Some("wal")
            && serde_json::to_string(&a.metadata)
                .unwrap()
                .contains("sidecar_row_0")
    });
    assert!(
        has_wal_row,
        "sidecar WAL rows must be discovered and emitted"
    );

    drop(conn);
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}-wal", tmp.display()));
    let _ = std::fs::remove_file(format!("{}-shm", tmp.display()));
}

/// A data source that yields the database bytes and, like a container entry,
/// hands back its `-wal` sibling through `open_sibling`. There is no local path,
/// so the parser must use that route rather than a filesystem lookup.
#[derive(Debug)]
struct ContainerDbSource {
    db: Vec<u8>,
    wal: Vec<u8>,
}
impl DataSource for ContainerDbSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= self.db.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.db.len() - off);
        buf[..n].copy_from_slice(&self.db[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.db.len() as u64
    }
    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        (suffix == "-wal")
            .then(|| Arc::new(ByteSliceDataSource::new(self.wal.clone())) as Arc<dyn DataSource>)
    }
}

#[test]
fn module_discovers_wal_sibling_through_container_data_source() {
    // Build a real db + -wal on disk, read both, then delete the files so the
    // WAL can ONLY be reached in-memory via the data source's open_sibling — the
    // container case (e.g. a db and its -wal inside the same ZIP).
    let tmp = std::env::temp_dir().join(format!("seance_container_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&tmp).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0i64)
        .unwrap();
    conn.execute("CREATE TABLE s (id INTEGER PRIMARY KEY, note TEXT)", [])
        .unwrap();
    for i in 0..6 {
        conn.execute(
            "INSERT INTO s (note) VALUES (?1)",
            [format!("container_row_{i}")],
        )
        .unwrap();
    }
    let db_bytes = std::fs::read(&tmp).unwrap();
    let wal_bytes = std::fs::read(format!("{}-wal", tmp.display())).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}-wal", tmp.display()));
    let _ = std::fs::remove_file(format!("{}-shm", tmp.display()));
    assert!(!wal_bytes.is_empty(), "the test WAL must hold frames");

    // No source_path and no on-disk file: the only route to the WAL is the
    // data source's open_sibling.
    let src: Arc<dyn DataSource> = Arc::new(ContainerDbSource {
        db: db_bytes,
        wal: wal_bytes,
    });
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        json!({ "name": "s.db" }),
    );
    let out = SqliteParser.process(&art).unwrap();

    let summary = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteDatabaseForensics")
        })
        .expect("summary record");
    assert_eq!(
        summary.metadata["wal_present"],
        json!(true),
        "WAL must be reached via the container sibling route"
    );
    assert!(summary.metadata["wal_frames"].as_u64().unwrap() > 0);

    let has_wal_row = out.iter().any(|a| {
        a.metadata.get("recovery_source").and_then(|v| v.as_str()) == Some("wal")
            && serde_json::to_string(&a.metadata)
                .unwrap()
                .contains("container_row_0")
    });
    assert!(
        has_wal_row,
        "container WAL rows must be discovered and emitted"
    );
}

// ---------------------------------------------------------------------------
// 6. Freeblock/slack/unallocated recovery asserted BY SOURCE LABEL, plus the
//    column-realignment fix, overflow reassembly, and recovered conversations.
//    (These paths do most of the real-world recovery work but were previously
//    only exercised indirectly.)
// ---------------------------------------------------------------------------

/// Deleting rows from a live page turns them into freeblocks whose leading
/// varints are clobbered. Recovery must (a) tag them Freeblock and (b) split
/// them back into their real columns rather than mashing sender+body into one
/// field. This is the regression guard for the header-realignment fix.
#[test]
fn freeblock_recovery_splits_columns_and_labels_source() {
    let db = build_db(|conn| {
        conn.execute(
            "CREATE TABLE msg (id INTEGER PRIMARY KEY, sender TEXT, body TEXT)",
            [],
        )
        .unwrap();
        // Keep some, delete others, so the page stays live (in-page freeblocks).
        let rows = [
            ("alice", "KEEP lunch at noon"),
            ("bob", "DELETEME the password is hunter2"),
            ("carol", "KEEP see you tomorrow"),
            ("dave", "DELETEME meet at the pier at midnight"),
            ("erin", "DELETEME transfer 5000 to account 9981"),
        ];
        for (s, b) in rows {
            conn.execute("INSERT INTO msg (sender, body) VALUES (?1, ?2)", [s, b])
                .unwrap();
        }
        conn.execute("DELETE FROM msg WHERE body LIKE 'DELETEME%'", [])
            .unwrap();
    });
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();

    let freeblocks: Vec<_> = r
        .records
        .iter()
        .filter(|x| x.deleted && x.recovery_source == Some(RecoverySource::Freeblock))
        .collect();
    assert!(
        !freeblocks.is_empty(),
        "in-page deletes must be recovered and labelled Freeblock"
    );

    // The recovered "bob/hunter2" row must have sender and body as SEPARATE
    // columns, not one mashed field.
    let hunter = r
        .records
        .iter()
        .find(|x| x.deleted && text_values(x).contains("hunter2"))
        .expect("deleted 'hunter2' row must be recovered");
    let sender_col = hunter
        .columns
        .iter()
        .zip(hunter.values.iter())
        .find(|(_, v)| matches!(v, Value::Text(s) if s == "bob"));
    assert!(
        sender_col.is_some(),
        "sender 'bob' must be recovered as its own column, got columns={:?} values={:?}",
        hunter.columns,
        hunter.values
    );
    // And the body must be a distinct value (not concatenated with the sender).
    let has_clean_body = hunter
        .values
        .iter()
        .any(|v| matches!(v, Value::Text(s) if s.contains("hunter2") && !s.contains("bob")));
    assert!(
        has_clean_body,
        "body must be split from sender, got values={:?}",
        hunter.values
    );
}

/// A cell whose payload exceeds the page's usable space spills onto overflow
/// pages; live extraction must follow the chain and reassemble the full value.
#[test]
fn overflow_chain_reassembles_large_value() {
    let big = "OVERFLOW_".repeat(2000); // ~18 KB, far past a 4 KB page's local payload
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE o (id INTEGER PRIMARY KEY, v TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO o (v) VALUES (?1)", [&big])
            .unwrap();
    });
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    let row = r
        .records
        .iter()
        .find(|x| x.table.as_deref() == Some("o"))
        .expect("overflow table row");
    let v = row
        .values
        .iter()
        .find_map(|v| match v {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        })
        .expect("text value");
    assert_eq!(v.len(), big.len(), "overflow chain must reassemble fully");
    assert_eq!(v, big);
}

/// End-to-end: a "cleared" iMessage chat.db (messages deleted) must reconstruct
/// into threaded, recovered iMessage chat_message artifacts with the correspondent
/// resolved through the recovered `handle` table.
#[test]
fn recovered_imessage_conversation_is_threaded() {
    let db = build_db(|conn| {
        conn.execute(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO chat (guid) VALUES ('chat-1')", [])
            .unwrap();
        conn.execute(
            "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, handle_id INTEGER, is_from_me INTEGER, date INTEGER)",
            [],
        )
        .unwrap();
        for (t, from_me) in [
            ("SECRET meet me at the docks", 0),
            ("bring the documents", 1),
            ("delete this after reading", 0),
        ] {
            conn.execute(
                "INSERT INTO message (text, handle_id, is_from_me, date) VALUES (?1, 1, ?2, 700000000)",
                rusqlite::params![t, from_me],
            )
            .unwrap();
        }
        // Clear the history: the app now shows an empty conversation list.
        conn.execute("DELETE FROM message", []).unwrap();
    });

    let art = artifact_with(db, json!({ "name": "chat.db" }));
    let out = SqliteParser.process(&art).unwrap();

    let recovered_msgs: Vec<_> = out
        .iter()
        .filter(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("iMessage")
                && a.metadata.get("recovered").and_then(|v| v.as_bool()) == Some(true)
        })
        .collect();
    assert!(
        !recovered_msgs.is_empty(),
        "cleared iMessage history must reconstruct into recovered messages"
    );
    // At least one recovered message keeps its text and resolves the contact.
    let docks = recovered_msgs.iter().find(|a| {
        a.metadata
            .get("text")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("docks"))
            .unwrap_or(false)
    });
    let docks = docks.expect("recovered message text must survive");
    assert_eq!(
        docks
            .metadata
            .get("chat_identifier")
            .and_then(|v| v.as_str()),
        Some("+15551234567"),
        "handle join must resolve the correspondent phone number"
    );
    assert_eq!(
        docks.metadata.get("direction").and_then(|v| v.as_str()),
        Some("received")
    );
}

// ---------------------------------------------------------------------------
// 7. Self-contained (always-run) equivalents of the fixture-gated tests, so the
//    corruption-resilience and module-emission paths are covered in CI where the
//    vendored reference/ fixtures are absent.
// ---------------------------------------------------------------------------

#[test]
fn self_contained_zeroed_header_still_recovers() {
    let mut db = build_db(|conn| {
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", [])
            .unwrap();
        for i in 0..20 {
            conn.execute("INSERT INTO t (v) VALUES (?1)", [format!("val_{i}")])
                .unwrap();
        }
        conn.execute("DELETE FROM t WHERE id = 5", []).unwrap();
    });
    // Zero the first 100 bytes (the file header). The page-1 b-tree header at
    // offset 100 survives, so extraction + deleted-row recovery must still work.
    for b in db.iter_mut().take(100) {
        *b = 0;
    }
    let r = extract(&ByteSliceDataSource::new(db), &ForensicOptions::default()).unwrap();
    assert!(
        r.summary.live_rows >= 18,
        "live rows recovered past a zeroed header"
    );
    assert!(
        r.records
            .iter()
            .any(|x| x.deleted && text_values(x).contains("val_4")),
        "deleted 'val_4' recovered despite the zeroed header"
    );
}

#[test]
fn self_contained_module_emits_summary_and_deleted_row_artifacts() {
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE u (id INTEGER PRIMARY KEY, email TEXT)", [])
            .unwrap();
        for i in 0..6 {
            conn.execute(
                "INSERT INTO u (email) VALUES (?1)",
                [format!("user{i}@ex.com")],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM u WHERE id = 3", []).unwrap();
    });
    let art = artifact_with(db, json!({ "name": "store.db" }));
    let out = SqliteParser.process(&art).unwrap();

    let summary = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteDatabaseForensics")
        })
        .expect("summary artifact");
    assert!(summary.metadata["deleted_rows"].as_u64().unwrap() >= 1);

    let deleted_row = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteRow")
                && a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true)
        })
        .expect("a recovered deleted row artifact");
    assert!(deleted_row.metadata.get("recovery_source").is_some());
    assert!(deleted_row.metadata.get("confidence").is_some());
    assert_eq!(deleted_row.parent_id, Some(art.id));
}

/// On a database with far more live rows than the emit cap, recovered (deleted)
/// rows must still survive the cap — they are the forensic payload and must not
/// be crowded out by live rows (regression for the large-DB truncation bug).
#[test]
fn recovered_rows_survive_the_record_cap() {
    let db = build_db(|conn| {
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT)", [])
            .unwrap();
        for i in 0..300 {
            conn.execute(
                "INSERT INTO t (note) VALUES (?1)",
                [format!("live row number {i} padding padding")],
            )
            .unwrap();
        }
        // A contiguous block of deletions leaves plenty of recoverable freed cells.
        for i in 0..60 {
            conn.execute(
                "INSERT INTO t (note) VALUES (?1)",
                [format!("DELETED SECRET message {i} to recover")],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM t WHERE note LIKE 'DELETED SECRET%'", [])
            .unwrap();
    });
    // Cap well below the 300 live rows: a naive truncate keeps only live rows and
    // drops every recovered row.
    let opts = ForensicOptions {
        max_records: 50,
        ..Default::default()
    };
    let r = extract(&ByteSliceDataSource::new(db), &opts).unwrap();
    assert!(r.records_truncated, "the cap should have triggered");
    assert_eq!(r.records.len(), 50);
    // With the fix, the capped set is filled with recovered (deleted) rows first;
    // a naive truncate would have kept only live rows (0 deleted). There are far
    // more than 50 recovered rows here, so effectively all 50 kept must be deleted.
    let deleted_kept = r.records.iter().filter(|x| x.deleted).count();
    assert!(
        deleted_kept >= 40,
        "recovered rows must dominate the capped set (kept {deleted_kept}/50), \
         not be crowded out by live rows"
    );
}
