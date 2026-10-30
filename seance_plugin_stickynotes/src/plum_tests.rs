//! `plum.sqlite` — stated before it was read.
//!
//! Every fixture here is a database built in memory or in a temporary
//! directory, so these run on every machine. The first group is about the
//! three-state answer the reader gives — present, absent, undetermined —
//! because that is the part a parser gets wrong in a way an examiner cannot
//! see. The second pins, without the corpus, what the lab-made 6.1.4.0
//! database (`PLUM-1`, `plum_real_tests.rs`) showed the real store does.

use super::plum::*;
use rusqlite::Connection;

fn db(setup: &[&str]) -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    for sql in setup {
        conn.execute_batch(sql).expect("setup sql");
    }
    conn
}

const SCHEMA: &str = "CREATE TABLE Note (
    Id TEXT, Text TEXT, WindowPosition TEXT, IsOpen INTEGER,
    CreatedAt TEXT, UpdatedAt TEXT, DeletedAt TEXT, Theme TEXT
);";

#[test]
fn the_notes_come_out_with_their_times_and_their_text() {
    let conn = db(&[
        SCHEMA,
        "INSERT INTO Note VALUES ('n1', 'Buy milk', '0,0', 1,
            '2019-04-02T09:15:00Z', '2019-04-02T09:20:00Z', NULL, 'Yellow');",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    let n = &out[0];
    assert_eq!(n["type"], "StickyNote");
    assert_eq!(n["note_id"], "n1");
    assert_eq!(n["text"], "Buy milk");
    assert_eq!(n["name"], "Buy milk");
    assert_eq!(n["created"], "2019-04-02T09:15:00Z");
    assert_eq!(n["modified"], "2019-04-02T09:20:00Z");
    assert!(n["deleted"].is_null());
    assert_eq!(n["is_open"], serde_json::json!(true));
    assert_eq!(n["source_format"], "plum_sqlite");
    assert_eq!(n["text_was_rtf"], serde_json::json!(false));
}

/// **RTF in the column is extracted; plain text is taken as stored.** Which
/// one a given build of the app writes is not assumed.
#[test]
fn an_rtf_column_is_extracted_and_a_plain_one_is_not_mangled() {
    let conn = db(&[
        SCHEMA,
        r"INSERT INTO Note (Id, Text) VALUES ('r1', '{\rtf1\ansi Dentist\par 3pm}');",
        "INSERT INTO Note (Id, Text) VALUES ('p1', 'Plain {braces} and a \\backslash');",
    ]);
    let out = read(&conn, "plum.sqlite");
    let rtf = out.iter().find(|n| n["note_id"] == "r1").expect("r1");
    assert_eq!(rtf["text"], "Dentist\n3pm");
    assert_eq!(rtf["text_was_rtf"], serde_json::json!(true));
    let plain = out.iter().find(|n| n["note_id"] == "p1").expect("p1");
    assert_eq!(plain["text"], "Plain {braces} and a \\backslash");
    assert_eq!(plain["text_was_rtf"], serde_json::json!(false));
}

/// A row with a deletion time is a note the app recorded as deleted, and the
/// row survived. That is worth saying rather than filtering out.
#[test]
fn a_deleted_note_is_reported_as_deleted_and_not_dropped() {
    let conn = db(&[
        SCHEMA,
        "INSERT INTO Note (Id, Text, DeletedAt) VALUES ('d1', 'Meet at 8', '2019-05-01T10:00:00Z');",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["deleted"], "2019-05-01T10:00:00Z");
    assert!(out[0]["deleted_note"]
        .as_str()
        .unwrap_or("")
        .contains("recorded the note as deleted"));
    assert_eq!(out[0]["text"], "Meet at 8");
}

/// **A schema this build does not know is a status record naming the tables
/// that ARE there** — not silence, which reads as "this machine had no notes".
#[test]
fn an_unrecognised_schema_names_the_tables_it_found() {
    let conn = db(&[
        "CREATE TABLE NoteV2 (id TEXT, body TEXT);",
        "CREATE TABLE Migrations (v INTEGER);",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    let s = &out[0];
    assert_eq!(s["type"], "StickyNotesParseStatus");
    assert_eq!(s["status"], "SchemaNotRecognised");
    assert_eq!(s["notes_recovered"], serde_json::json!(0));
    assert_eq!(s["content_incomplete_reason"], "unresolved_structure");
    let tables: Vec<&str> = s["tables_present"]
        .as_array()
        .expect("the tables it found")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(tables, vec!["Migrations", "NoteV2"]);
    assert!(
        s["detail"]
            .as_str()
            .unwrap_or("")
            .contains("NOT an absence of notes"),
        "got {:?}",
        s["detail"]
    );
}

/// An empty `Note` table is an answer of its own, and not the same answer as a
/// database this build could not read.
#[test]
fn an_empty_note_table_is_reported_as_no_notes_stored() {
    let conn = db(&[SCHEMA]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["status"], "NoNotesStored");
    assert!(out[0]["detail"]
        .as_str()
        .unwrap_or("")
        .contains("not the same as this build having failed to read it"));
}

/// **A schema with some of the columns is read for what it has**, and the
/// record says which columns answered — so a null field is distinguishable
/// from a column the schema does not have.
#[test]
fn a_schema_missing_some_columns_is_read_for_what_it_has() {
    let conn = db(&[
        "CREATE TABLE Note (Id TEXT, Text TEXT);",
        "INSERT INTO Note VALUES ('n1', 'Just a note');",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["text"], "Just a note");
    assert!(out[0]["created"].is_null());
    let cols: Vec<&str> = out[0]["columns_present"]
        .as_array()
        .expect("which columns answered")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(cols, vec!["Id", "Text"]);
    assert!(out[0]["columns_basis"]
        .as_str()
        .unwrap_or("")
        .contains("a column this database's schema does not have"));
}

/// A `Note` table with none of the columns this build reads.
#[test]
fn a_note_table_with_no_familiar_column_is_a_status_record() {
    let conn = db(&["CREATE TABLE Note (entirely TEXT, different TEXT);"]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out[0]["type"], "StickyNotesParseStatus");
    assert_eq!(out[0]["status"], "SchemaNotRecognised");
}

/// **Every record from a store that recorded no schema version carries the
/// never-validated stamp**, the status records included. (PLUM-1 validated
/// `user_version` 13 only; see
/// `only_user_version_13_carries_the_lab_made_validation_stamp`.)
#[test]
fn every_record_says_it_has_never_been_validated() {
    for conn in [
        db(&[SCHEMA, "INSERT INTO Note (Id, Text) VALUES ('n1', 'x');"]),
        db(&[SCHEMA]),
        db(&["CREATE TABLE Other (x TEXT);"]),
    ] {
        for r in read(&conn, "plum.sqlite") {
            assert_eq!(
                r["validation_state"], "never_validated_against_real_notes",
                "got {r:?}"
            );
            assert_eq!(r["validated_against_real_notes"], serde_json::json!(false));
            assert!(r["validation_notice"]
                .as_str()
                .unwrap_or("")
                .contains("this store's schema has NEVER been run against a known answer"));
        }
    }
}

/// A view named `Note` is read like a table, because that is what the probe
/// already accepts and a store could be shaped either way.
#[test]
fn a_view_named_note_is_read_like_a_table() {
    let conn = db(&[
        "CREATE TABLE Raw (Id TEXT, Text TEXT);",
        "INSERT INTO Raw VALUES ('v1', 'From a view');",
        "CREATE VIEW Note AS SELECT Id, Text FROM Raw;",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["text"], "From a view");
}

// ---------------------------------------------------------------------------
// HUNT-128: what the lab-made 6.1.4.0 database (PLUM-1) showed the real store
// does, pinned here without the corpus so the behaviour is held on every run.
// ---------------------------------------------------------------------------

/// The 6.1.4.0 schema's shape: `Id` a varchar primary key (so the table keeps
/// an implicit rowid), times as `bigint` .NET ticks.
const SCHEMA_6_1: &str = r#"CREATE TABLE "Note" (
    "Text" varchar, "WindowPosition" varchar, "IsOpen" integer, "IsAlwaysOnTop" integer,
    "Theme" varchar, "Type" varchar, "Id" varchar primary key not null, "ParentId" varchar,
    "CreatedAt" bigint, "DeletedAt" bigint, "UpdatedAt" bigint
);"#;

/// **Integer times are .NET ticks, converted and kept.** Before PLUM-1 the
/// reader asked SQLite for every time as text, an integer column answered
/// with an error, and the error was spent as "no value": every real note came
/// out with `created` and `modified` null.
#[test]
fn integer_times_are_dotnet_ticks_and_are_converted_not_dropped() {
    let conn = db(&[
        SCHEMA_6_1,
        r"INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt)
          VALUES ('n1', 'x', 639261413931443023, 639261414398948277);",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert_eq!(out[0]["created"], "2026-09-27T21:29:53.144302300+00:00");
    assert_eq!(out[0]["created_ticks"], 639_261_413_931_443_023_i64);
    assert_eq!(out[0]["modified"], "2026-09-27T21:30:39.894827700+00:00");
    assert_eq!(out[0]["modified_ticks"], 639_261_414_398_948_277_i64);
    assert!(out[0]["deleted"].is_null());
    assert!(out[0]["time_basis"]
        .as_str()
        .unwrap_or("")
        .contains("not corrected"));
}

/// A ticks value outside what a date can be is reported raw, not invented.
#[test]
fn an_impossible_ticks_value_is_kept_raw_and_not_converted() {
    let conn = db(&[
        SCHEMA_6_1,
        "INSERT INTO Note (Id, Text, CreatedAt) VALUES ('n1', 'x', 5);",
    ]);
    let out = read(&conn, "plum.sqlite");
    assert!(out[0]["created"].is_null(), "{}", out[0]);
    assert_eq!(out[0]["created_ticks"], 5);
}

/// **Each paragraph's `\id=<guid> ` prefix is stripped from `text`, and the
/// stored text is kept whole in `text_raw`.** A line that does not carry the
/// exact prefix is left alone.
#[test]
fn paragraph_ids_are_stripped_from_the_text_and_the_raw_text_is_kept() {
    let stored = "\\id=cb205a0c-c266-4683-add3-55a1d748b5d0 Evidence checklist\n\
                  \\id=44a83ad6-6548-4e5d-baeb-06bd05c25f8f 1. Seize laptop\n\
                  \\id=not-a-guid keep me\n\
                  plain line";
    let conn = db(&[SCHEMA_6_1]);
    conn.execute(
        "INSERT INTO Note (Id, Text) VALUES ('n1', ?1)",
        rusqlite::params![stored],
    )
    .unwrap();
    let out = read(&conn, "plum.sqlite");
    assert_eq!(
        out[0]["text"],
        "Evidence checklist\n1. Seize laptop\n\\id=not-a-guid keep me\nplain line"
    );
    assert_eq!(out[0]["text_raw"], stored);
    assert_eq!(out[0]["name"], "Evidence checklist");
    assert_eq!(out[0]["paragraph_ids_stripped"], 2);
}

/// Every note carries its SQLite rowid, so a recovered copy of the same row
/// can be matched to it.
#[test]
fn every_note_carries_its_rowid_and_the_stores_user_version() {
    let conn = db(&[
        SCHEMA_6_1,
        "PRAGMA user_version = 13;",
        "INSERT INTO Note (Id, Text) VALUES ('a', 'one');",
        "INSERT INTO Note (Id, Text) VALUES ('b', 'two');",
    ]);
    let out = read(&conn, "plum.sqlite");
    let b = out.iter().find(|n| n["note_id"] == "b").unwrap();
    assert_eq!(b["rowid"], 2);
    assert_eq!(b["user_version"], 13);
}

/// **The stamp is decided by the schema version.** `user_version` 13 is what
/// PLUM-1 validated; any other version, or none, keeps the never-validated
/// stamp, because the reader has not met it.
#[test]
fn only_user_version_13_carries_the_lab_made_validation_stamp() {
    for (version, state, validated) in [
        (13, "plum_validated_against_one_lab_made_database", true),
        (12, "never_validated_against_real_notes", false),
        (14, "never_validated_against_real_notes", false),
        (0, "never_validated_against_real_notes", false),
    ] {
        for conn in [
            db(&[SCHEMA_6_1, "INSERT INTO Note (Id, Text) VALUES ('n', 'x');"]),
            db(&[SCHEMA_6_1]),
            db(&["CREATE TABLE Other (x TEXT);"]),
        ] {
            conn.execute_batch(&format!("PRAGMA user_version = {version};"))
                .unwrap();
            for r in read(&conn, "plum.sqlite") {
                assert_eq!(r["validation_state"], state, "v{version}: {r}");
                assert_eq!(r["validated_against_real_notes"], validated, "v{version}");
                let notice = r["validation_notice"].as_str().unwrap_or("");
                if validated {
                    assert!(notice.contains("lab-made") && notice.contains("6.1.4.0"));
                } else {
                    assert!(notice.contains("user_version 13"), "{notice}");
                }
            }
        }
    }
}

/// A live WAL-mode database with a note deleted and not checkpointed, in the
/// shape PLUM-1 showed: no tombstone, the row simply gone. Returns the
/// directory, the main file path and the still-open writer (closing it would
/// checkpoint the WAL).
fn wal_store_with_a_hard_deleted_note() -> (std::path::PathBuf, std::path::PathBuf, Connection) {
    let dir = std::env::temp_dir().join(format!(
        "seance_stickynotes_wal_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plum.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    conn.execute_batch(SCHEMA_6_1).unwrap();
    conn.execute_batch("PRAGMA user_version = 13;").unwrap();
    conn.execute_batch(
        r"INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt) VALUES
            ('keep', '\id=11111111-1111-1111-1111-111111111111 Kept note', 639261413931443023, 639261413931443023);
          INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt) VALUES
            ('gone', '\id=22222222-2222-2222-2222-222222222222 Short-lived', 639261415366713590, 639261415493657630);",
    )
    .unwrap();
    conn.execute_batch("DELETE FROM Note WHERE Id = 'gone';")
        .unwrap();
    (dir, path, conn)
}

/// **A hard-deleted note is recovered from the WAL frame that last held it**,
/// labelled as recovered, with its frame and offset, and the deletion stated
/// as an inference from the row's absence — the app sets no tombstone.
#[test]
fn a_hard_deleted_note_is_recovered_from_its_superseded_wal_frame() {
    let (dir, path, _writer) = wal_store_with_a_hard_deleted_note();
    let wal = std::fs::read(format!("{}-wal", path.display())).unwrap();
    let main = std::fs::read(&path).unwrap();
    let reader =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let live = read(&reader, "plum.sqlite");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0]["note_id"], "keep");

    let main_src = seance_core::data_source::ByteSliceDataSource::new(main);
    let rec = recover_deleted_from_wal(&reader, &wal, &main_src, "plum.sqlite");
    assert_eq!(rec.len(), 1, "{rec:#?}");
    let r = &rec[0];
    assert_eq!(r["type"], "StickyNoteRecovered");
    assert_eq!(r["note_id"], "gone");
    assert_eq!(r["text"], "Short-lived");
    assert_eq!(r["created"], "2026-09-27T21:32:16.671359+00:00");
    assert_eq!(r["rowid"], 2);
    assert_eq!(r["recovery_source"], "wal_superseded_frame");
    assert_eq!(r["deleted_inferred"], true);
    let frame = r["wal_frame"].as_u64().expect("a frame number");
    let page_size = u64::from(u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]));
    assert_eq!(r["wal_frame_offset"], 32 + frame * (24 + page_size));
    assert!(r["first_wal_frame_without_row"].as_u64().unwrap() > frame);
    assert!(r["deletion_basis"]
        .as_str()
        .unwrap()
        .contains("no tombstone"));
    assert_eq!(r["validated_against_real_notes"], true);
    drop(reader);
    drop(_writer);
    let _ = std::fs::remove_dir_all(dir);
}

/// A note that is live is never also reported as recovered, however many
/// older images of it the WAL holds.
#[test]
fn a_live_notes_older_wal_images_are_not_reported_as_recovered() {
    let (dir, path, writer) = wal_store_with_a_hard_deleted_note();
    writer
        .execute_batch("UPDATE Note SET Text = 'edited' WHERE Id = 'keep';")
        .unwrap();
    let wal = std::fs::read(format!("{}-wal", path.display())).unwrap();
    let main = std::fs::read(&path).unwrap();
    let reader =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let main_src = seance_core::data_source::ByteSliceDataSource::new(main);
    let rec = recover_deleted_from_wal(&reader, &wal, &main_src, "plum.sqlite");
    assert!(rec.iter().all(|r| r["note_id"] != "keep"), "{rec:#?}");
    drop(reader);
    drop(writer);
    let _ = std::fs::remove_dir_all(dir);
}
