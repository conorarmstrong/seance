use super::*;
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

use rusqlite::Connection;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// Build a SQLite DB from `ddl`, return its raw bytes.
fn make_db(ddl: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_ios_test_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(ddl).unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

fn run(module: &dyn ForensicsModule, name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

#[test]
fn cocoa_epoch_conversion() {
    // Cocoa 700000000 -> Unix 700000000 + 978307200 = 1678307200 (2023-03-08).
    assert_eq!(
        cocoa_secs_to_unix_nanos(700_000_000.0),
        Some((1_678_307_200, 0))
    );
    // These columns are REAL: the fraction is decoded, not truncated.
    assert_eq!(
        cocoa_secs_to_unix_nanos(700_000_000.5),
        Some((1_678_307_200, 500_000_000))
    );
    assert_eq!(cocoa_secs_to_unix_nanos(0.0), None);
    assert_eq!(cocoa_secs_to_unix_nanos(-5.0), None);
}

#[test]
fn calendar_note_and_photo_records_keep_their_sub_second_part() {
    // Every one of these columns is REAL. Two events inside the same second are
    // ordered by the fraction alone, and the records used to publish whole
    // seconds only — so an examiner could not tell which came first.
    let db = make_db(
        "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO Calendar VALUES (1, 'Work');
         CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER, \
           due_date REAL, completion_date REAL, priority INTEGER);
         INSERT INTO CalendarItem (summary, description, start_date, end_date, all_day, calendar_id) \
           VALUES ('Standup', 'daily', 700000000.25, 700003600.75, 0, 1);
         INSERT INTO CalendarItem (summary, start_date, calendar_id, due_date, completion_date) \
           VALUES ('Buy milk', NULL, 1, 700100000.25, 700200000.75);",
    );
    let arts = run(&CalendarDbParser, "Calendar.sqlitedb", db);

    let event = arts
        .iter()
        .find(|a| a.metadata["type"] == "CalendarEvent")
        .expect("the timed event");
    let base = 700_000_000 + 978_307_200;
    assert_eq!(event.metadata["date"].as_i64(), Some(base));
    assert_eq!(
        event.metadata["date_ns"].as_i64(),
        Some(base * 1_000_000_000 + 250_000_000)
    );
    // The string the viewer renders must agree with the nanos beside it.
    assert!(event.metadata["dtstart"].as_str().unwrap().contains(".25"));
    assert!(event.metadata["dtend"].as_str().unwrap().contains(".75"));

    let reminder = arts
        .iter()
        .find(|a| a.metadata["type"] == "Reminder")
        .expect("the reminder");
    assert_eq!(
        reminder.metadata["due_ns"].as_i64(),
        Some((700_100_000 + 978_307_200) * 1_000_000_000 + 250_000_000)
    );
    assert_eq!(
        reminder.metadata["completed_date_ns"].as_i64(),
        Some((700_200_000 + 978_307_200) * 1_000_000_000 + 750_000_000)
    );

    // Notes: ZCREATIONDATE / ZMODIFICATIONDATE are the same REAL Cocoa column.
    let notes = make_db(
        "CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 TEXT, \
           ZSNIPPET TEXT, ZCREATIONDATE REAL, ZMODIFICATIONDATE REAL);
         INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (1, 'Note', 'body', 700000000.25, 700000000.75);",
    );
    let arts = run(&NotesParser, "NoteStore.sqlite", notes);
    let note = arts
        .iter()
        .find(|a| a.metadata["type"] == "Note")
        .expect("the note");
    assert_eq!(
        note.metadata["created_ns"].as_i64(),
        Some(base * 1_000_000_000 + 250_000_000)
    );
    assert_eq!(
        note.metadata["modified_ns"].as_i64(),
        Some(base * 1_000_000_000 + 750_000_000)
    );

    // Photos: two burst frames a quarter-second apart share a whole second.
    let photos = make_db(
        "CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME TEXT, ZDATECREATED REAL, \
           ZLATITUDE REAL, ZLONGITUDE REAL, ZWIDTH INTEGER, ZHEIGHT INTEGER, ZKIND INTEGER, \
           ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         CREATE TABLE ZADDITIONALASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZASSET INTEGER, \
           ZORIGINALFILENAME TEXT);
         INSERT INTO ZASSET VALUES (1, 'IMG_0001.HEIC', 700000000.25, -180.0, -180.0, 4032, 3024, 0, 0, 0);
         INSERT INTO ZASSET VALUES (2, 'IMG_0002.HEIC', 700000000.75, -180.0, -180.0, 4032, 3024, 0, 0, 0);",
    );
    let arts = run(&PhotosParser, "Photos.sqlite", photos);
    let assets: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["type"] == "PhotoAsset")
        .collect();
    assert_eq!(assets.len(), 2);
    let first = assets
        .iter()
        .find(|a| a.metadata["filename"] == "IMG_0001.HEIC")
        .unwrap();
    let second = assets
        .iter()
        .find(|a| a.metadata["filename"] == "IMG_0002.HEIC")
        .unwrap();
    assert_eq!(
        first.metadata["date"].as_i64(),
        second.metadata["date"].as_i64()
    );
    assert!(
        first.metadata["date_ns"].as_i64() < second.metadata["date_ns"].as_i64(),
        "the capture order of two frames in one second must survive"
    );
}

#[test]
fn powerlog_torch_event_keeps_its_sub_second_part() {
    // A flashlight switched on and off inside one second is two events; the
    // fraction is the only thing that orders them. PowerLog writes Unix seconds
    // here, and the Core Data branch of the same column is covered by
    // `cocoa_epoch_conversion` above.
    let db = make_db(
        "CREATE TABLE PLCameraAgent_EventForward_Torch (timestamp REAL, state INTEGER);
         INSERT INTO PLCameraAgent_EventForward_Torch VALUES (1673000000.25, 1);
         INSERT INTO PLCameraAgent_EventForward_Torch VALUES (1673000000.75, 0);",
    );
    let arts = run(&PowerLogParser, "CurrentPowerlog.PLSQL", db);
    let torch: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["category"] == json!("torch"))
        .collect();
    assert_eq!(torch.len(), 2);
    assert_eq!(torch[0].metadata["date"].as_i64(), Some(1673000000));
    assert_eq!(torch[1].metadata["date"].as_i64(), Some(1673000000));
    assert_eq!(
        torch[0].metadata["date_ns"].as_i64(),
        Some(1673000000 * 1_000_000_000 + 250_000_000)
    );
    assert_eq!(
        torch[1].metadata["date_ns"].as_i64(),
        Some(1673000000 * 1_000_000_000 + 750_000_000)
    );
}

#[test]
fn parses_voicemail() {
    let db = make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, remote_uid INTEGER, date INTEGER, \
           token TEXT, sender TEXT, callback_num TEXT, duration INTEGER, expiration INTEGER, \
           trashed_date INTEGER, flags INTEGER, receiver TEXT);
         INSERT INTO voicemail (date, sender, callback_num, duration, trashed_date) \
           VALUES (1673000000, '+420777050540', '+420777050540', 42, 0);
         INSERT INTO voicemail (date, sender, duration, trashed_date) \
           VALUES (1673100000, '+15551234567', 7, 1673200000);",
    );
    let arts = run(&VoicemailParser, "voicemail.db", db);
    // Two voicemails and the store's summary (HUNT-215).
    assert_eq!(arts.len(), 3);
    assert_eq!(arts[2].metadata["type"], "VoicemailSummary");
    assert_eq!(arts[2].metadata["voicemails"], 2);
    assert_eq!(arts[2].metadata["trashed"], 1);
    assert_eq!(arts[0].metadata["type"], "Voicemail");
    assert_eq!(arts[0].metadata["sender"], "+420777050540");
    assert_eq!(arts[0].metadata["date"].as_i64(), Some(1673000000));
    assert_eq!(arts[0].metadata["duration_seconds"].as_i64(), Some(42));
    assert_eq!(arts[0].metadata["deleted"], false);
    assert_eq!(arts[1].metadata["deleted"], true); // trashed_date > 0
    assert!(run(&VoicemailParser, "other.db", make_db("CREATE TABLE x(a);")).is_empty());
}

#[test]
fn parses_calendar_db() {
    let db = make_db(
        "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO Calendar VALUES (1, 'Work');
         CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER, \
           priority INTEGER, due_date REAL, completion_date REAL);
         INSERT INTO CalendarItem (summary, description, start_date, end_date, all_day, calendar_id) \
           VALUES ('Standup', 'daily', 700000000.0, 700003600.0, 0, 1);",
    );
    let arts = run(&CalendarDbParser, "Calendar.sqlitedb", db);
    // The event and the store's summary (HUNT-215).
    assert_eq!(arts.len(), 2);
    assert_eq!(arts[1].metadata["type"], "CalendarSummary");
    assert_eq!(arts[1].metadata["events"], 1);
    assert_eq!(arts[1].metadata["reminders"], 0);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "CalendarEvent");
    assert_eq!(m["summary"], "Standup");
    assert_eq!(m["calendar_name"], "Work");
    assert_eq!(m["date"].as_i64(), Some(1_678_307_200));
    // dtstart is an ISO string so the existing CalendarEvent viewer renders it.
    assert!(m["dtstart"].as_str().unwrap().starts_with("2023-03-08"));
}

#[test]
fn parses_calendar_reminders() {
    // Reminders share Calendar.sqlitedb: NULL-start CalendarItem rows carrying
    // due_date/completion_date/priority (the real iOS 15 names). One event is present too, to prove the
    // event output is unchanged and reminders never leak in as events.
    let db = make_db(
        "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO Calendar VALUES (1, 'Work');
         INSERT INTO Calendar VALUES (2, 'Reminders');
         CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER, \
           due_date REAL, completion_date REAL, priority INTEGER);
         INSERT INTO CalendarItem (summary, description, start_date, end_date, all_day, calendar_id) \
           VALUES ('Standup', 'daily', 700000000.0, 700003600.0, 0, 1);
         INSERT INTO CalendarItem (summary, start_date, calendar_id, due_date, completion_date, priority) \
           VALUES ('Buy milk', NULL, 2, 700100000.0, 700200000.0, 1);
         INSERT INTO CalendarItem (summary, start_date, calendar_id, due_date) \
           VALUES ('Call dentist', NULL, 2, 700300000.0);
         INSERT INTO CalendarItem (summary, start_date, calendar_id) \
           VALUES ('Someday task', NULL, 2);",
    );
    let arts = run(&CalendarDbParser, "Calendar.sqlitedb", db);

    // Event output unchanged: exactly the one timed event, no reminder leakage.
    let events: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["type"] == "CalendarEvent")
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["summary"], "Standup");
    assert_eq!(events[0].metadata["date"].as_i64(), Some(1_678_307_200));

    let reminders: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["type"] == "Reminder")
        .collect();
    assert_eq!(reminders.len(), 3);
    let rem = |t: &str| {
        reminders
            .iter()
            .copied()
            .find(|a| a.metadata["title"] == t)
            .unwrap()
    };

    // Completed reminder with a due date and priority.
    let milk = rem("Buy milk");
    assert_eq!(milk.metadata["completed"], true);
    assert_eq!(milk.metadata["due"].as_i64(), Some(1_678_407_200));
    assert_eq!(
        milk.metadata["completed_date"].as_i64(),
        Some(1_678_507_200)
    );
    assert_eq!(milk.metadata["priority"].as_i64(), Some(1));
    assert_eq!(milk.metadata["calendar_name"], "Reminders");
    assert_eq!(milk.metadata["name"], "Buy milk");

    // Open reminder with a due date, no completion, no priority.
    let dentist = rem("Call dentist");
    assert_eq!(dentist.metadata["completed"], false);
    assert_eq!(dentist.metadata["due"].as_i64(), Some(1_678_607_200));
    assert_eq!(dentist.metadata.get("completed_date"), None);
    assert_eq!(dentist.metadata.get("priority"), None);

    // Open reminder with no due date: `due` omitted, not fabricated as 2001.
    let someday = rem("Someday task");
    assert_eq!(someday.metadata["completed"], false);
    assert_eq!(someday.metadata.get("due"), None);
}

#[test]
fn parses_notes() {
    let db = make_db(
        "CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 VARCHAR, \
           ZSNIPPET VARCHAR, ZCREATIONDATE TIMESTAMP, ZMODIFICATIONDATE TIMESTAMP);
         INSERT INTO ZICCLOUDSYNCINGOBJECT (ZTITLE1, ZSNIPPET, ZCREATIONDATE, ZMODIFICATIONDATE) \
           VALUES ('Shopping list', 'milk, eggs, bread', 700000000.0, 700010000.0);
         INSERT INTO ZICCLOUDSYNCINGOBJECT (ZTITLE1) VALUES (NULL);",
    );
    let arts = run(&NotesParser, "NoteStore.sqlite", db);
    // The NULL-title row (a folder/account) is skipped: this synthetic store
    // has no Z_PRIMARYKEY, so the title heuristic selects notes and the
    // summary says so.
    let notes: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["type"] == "Note")
        .collect();
    assert_eq!(notes.len(), 1);
    let m = &notes[0].metadata;
    assert_eq!(m["title"], "Shopping list");
    assert_eq!(m["snippet"], "milk, eggs, bread");
    assert_eq!(m["created"].as_i64(), Some(1_678_307_200));
    assert_eq!(m["body_present"], false);
    assert_eq!(m["body_table_absent"], true);
    let summary = arts
        .iter()
        .find(|a| a.metadata["type"] == "NotesSummary")
        .expect("summary");
    assert_eq!(summary.metadata["notes"], 1);
    assert_eq!(summary.metadata["deleted_notes"], 0);
    assert_eq!(summary.metadata["entity_resolution"], "title_heuristic");
    assert_eq!(summary.metadata["attachment_entity_unresolved"], true);
}

#[test]
fn parses_photos() {
    let db = make_db(
        "CREATE TABLE ZGENERICASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, \
           ZDATECREATED TIMESTAMP, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZWIDTH INTEGER, \
           ZHEIGHT INTEGER, ZKIND INTEGER, ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         CREATE TABLE ZADDITIONALASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZASSET INTEGER, \
           ZORIGINALFILENAME VARCHAR);
         INSERT INTO ZGENERICASSET VALUES (1, 'IMG_0001.HEIC', 700000000.0, 50.08, 14.42, 4032, 3024, 0, 1, 0);
         INSERT INTO ZADDITIONALASSETATTRIBUTES VALUES (1, 1, 'IMG_0001.HEIC');
         INSERT INTO ZGENERICASSET VALUES (2, 'IMG_0002.MOV', 700001000.0, -180.0, -180.0, 1920, 1080, 1, 0, 1);",
    );
    let arts = run(&PhotosParser, "Photos.sqlite", db);
    let assets: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["type"] == "PhotoAsset")
        .collect();
    assert_eq!(assets.len(), 2);
    let a = &assets[0].metadata;
    assert_eq!(a["type"], "PhotoAsset");
    assert_eq!(a["filename"], "IMG_0001.HEIC");
    assert_eq!(a["original_filename"], "IMG_0001.HEIC");
    assert_eq!(a["media_kind"], "photo");
    assert_eq!(a["favorite"], true);
    assert_eq!(a["has_gps"], true);
    assert_eq!(a["date"].as_i64(), Some(1_678_307_200));
    // Second asset: video, -180 location dropped, trashed.
    let b = &assets[1].metadata;
    assert_eq!(b["media_kind"], "video");
    assert_eq!(b["deleted"], true);
    assert_eq!(b.get("has_gps"), None);
    // No album table and no Z_PRIMARYKEY: membership is unresolved, not 0.
    let summary = arts
        .iter()
        .find(|a| a.metadata["type"] == "PhotosSummary")
        .expect("summary");
    assert_eq!(summary.metadata["album_table_present"], false);
    assert_eq!(summary.metadata["album_membership_present"], false);
    assert_eq!(summary.metadata["face_rows_table_absent"], true);
}

#[test]
fn photos_media_kind_maps_known_and_unknown() {
    assert_eq!(photos_media_kind(Some(0)), "photo");
    assert_eq!(photos_media_kind(Some(1)), "video");
    // An unrecognised or missing ZKIND must not be silently labelled a photo.
    assert_eq!(photos_media_kind(Some(2)), "unknown");
    assert_eq!(photos_media_kind(Some(99)), "unknown");
    assert_eq!(photos_media_kind(None), "unknown");
}

#[test]
fn parses_powerlog_torch_and_inventory() {
    let db = make_db(
        "CREATE TABLE PLCameraAgent_EventForward_Torch (ID INTEGER PRIMARY KEY, timestamp REAL, state INTEGER);
         INSERT INTO PLCameraAgent_EventForward_Torch (timestamp, state) VALUES (1673000000, 1);
         INSERT INTO PLCameraAgent_EventForward_Torch (timestamp, state) VALUES (1673000030, 0);
         CREATE TABLE PLBatteryAgent_EventBackward_Battery (ID INTEGER, timestamp REAL, Level INTEGER);
         CREATE TABLE PLApplicationAgent_EventForward_Application (ID INTEGER, timestamp REAL);",
    );
    let arts = run(&PowerLogParser, "CurrentPowerlog.PLSQL", db);
    let torch: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["category"] == json!("torch"))
        .collect();
    assert_eq!(torch.len(), 2);
    assert_eq!(torch[0].metadata["event"], "flashlight on");
    assert_eq!(torch[0].metadata["date"].as_i64(), Some(1673000000));
    assert_eq!(torch[1].metadata["event"], "flashlight off");
    // Inventory summary lists the three PL* tables.
    let summary = arts
        .iter()
        .find(|a| a.metadata["type"] == json!("PowerLogSummary"))
        .expect("summary");
    assert_eq!(summary.metadata["table_count"].as_u64(), Some(3));
}

/// The shared `table_columns` probe lower-cases every name. PowerLog schemas
/// use mixed case (`Timestamp`, `State`), so the resolved column must still
/// name the real column — SQLite matches identifiers case-insensitively.
#[test]
fn powerlog_torch_resolves_mixed_case_columns() {
    let db = make_db(
        "CREATE TABLE PLCameraAgent_EventForward_Torch (ID INTEGER PRIMARY KEY, Timestamp REAL, State INTEGER);
         INSERT INTO PLCameraAgent_EventForward_Torch (Timestamp, State) VALUES (1673000000, 1);
         INSERT INTO PLCameraAgent_EventForward_Torch (Timestamp, State) VALUES (1673000030, 0);",
    );
    let arts = run(&PowerLogParser, "CurrentPowerlog.PLSQL", db);
    let torch: Vec<_> = arts
        .iter()
        .filter(|a| a.metadata["category"] == json!("torch"))
        .collect();
    assert_eq!(torch.len(), 2);
    assert_eq!(torch[0].metadata["event"], "flashlight on");
    assert_eq!(torch[0].metadata["date"].as_i64(), Some(1673000000));
    assert_eq!(torch[1].metadata["event"], "flashlight off");
}

#[test]
fn module_ids_stable() {
    assert_eq!(VoicemailParser.id(), "plugin.ios.voicemail");
    assert_eq!(CalendarDbParser.id(), "plugin.ios.calendar_db");
    assert_eq!(NotesParser.id(), "plugin.ios.notes");
    assert_eq!(RoutinedLocationParser.id(), "plugin.ios.routined_locations");
    assert_eq!(PhotosParser.id(), "plugin.ios.photos");
    assert_eq!(PowerLogParser.id(), "plugin.ios.powerlog");
    assert_eq!(SafariBookmarksParser.id(), "plugin.ios.safari_bookmarks");
    assert_eq!(SafariTabsParser.id(), "plugin.ios.safari_tabs");
    assert_eq!(SafariSearchesParser.id(), "plugin.ios.safari_searches");
    assert_eq!(HealthKitParser.id(), "plugin.ios.healthkit");
}

/// Real gold-backup DBs, gated on SEANCE_IOS_SAMPLES=/dir/with/the/db/files.
#[test]
fn real_gold_samples() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_IOS_SAMPLES") else {
        return;
    };
    let dir = dir.display().to_string();
    let read = |f: &str| std::fs::read(format!("{dir}/{f}")).ok();
    if let Some(b) = read("Calendar.sqlitedb") {
        let n = run(&CalendarDbParser, "Calendar.sqlitedb", b).len();
        assert!(n > 100, "expected >100 calendar events, got {n}");
    }
    if let Some(b) = read("NoteStore.sqlite") {
        let n = run(&NotesParser, "NoteStore.sqlite", b).len();
        assert!(n > 50, "expected >50 notes, got {n}");
    }
    if let Some(b) = read("Photos.sqlite") {
        let n = run(&PhotosParser, "Photos.sqlite", b).len();
        assert!(n > 1000, "expected >1000 photo assets, got {n}");
    }
}
fn run_source(module: &dyn ForensicsModule, name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

const VOICEMAIL_DDL: &str = "\
    CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, remote_uid INTEGER, date INTEGER, \
      token TEXT, sender TEXT, callback_num TEXT, duration INTEGER, expiration INTEGER, \
      trashed_date INTEGER, flags INTEGER, receiver TEXT);\
    INSERT INTO voicemail (date, sender, duration, trashed_date) \
      VALUES (1673000000, '+420777050540', 42, 0);";

/// B3-012: the database was staged without comparing what the source returned
/// against what it declared, so a partial iOS database parsed as a complete
/// recovery. What an examiner learns: whether the voicemails listed are all of
/// them. A wrong answer reads as "no such message ever existed".
#[test]
fn a_short_read_marks_every_record_it_produced() {
    let out = run_source(
        &VoicemailParser,
        "voicemail.db",
        Arc::new(truncated(make_db(VOICEMAIL_DDL))),
    );
    let rec = out
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("Voicemail"))
        .expect("the readable prefix still parses");
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(rec.metadata["content_incomplete_reason"], "short_read");
    assert!(
        out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                == Some("DatabaseNotStagedInFull")),
        "a partial spill must be reported in its own right, so a truncation \
         deep enough to yield no rows is not an empty mailbox"
    );
}

/// The counterpart: a database staged whole must stay unmarked, or the marker
/// means nothing.
#[test]
fn a_complete_ios_database_carries_no_incompleteness_marks() {
    let out = run(&VoicemailParser, "voicemail.db", make_db(VOICEMAIL_DDL));
    assert!(!out.is_empty());
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// The magic probe loops over short reads: a chunked source holds a perfectly
/// good database and must not be filed as "not SQLite".
#[test]
fn a_source_that_answers_in_small_chunks_is_still_parsed() {
    let out = run_source(
        &VoicemailParser,
        "voicemail.db",
        Arc::new(DribbleSource::new(make_db(VOICEMAIL_DDL), 4)),
    );
    // The voicemail and the store's summary (HUNT-215).
    assert_eq!(out.len(), 2, "a chunked source is not a non-SQLite file");
    assert_eq!(out[0].metadata["type"], "Voicemail");
    assert_eq!(out[1].metadata["type"], "VoicemailSummary");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// A sound database must not acquire a drop marker.
///
/// The counterpart to the marker test below: counting losses must not invent
/// one where there was none (B4-012).
#[test]
fn a_sound_voicemail_walk_leaves_no_row_drop_marker() {
    let db = make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, date INTEGER, sender TEXT, \
           callback_num TEXT, duration INTEGER, trashed_date INTEGER, receiver TEXT);
         INSERT INTO voicemail (ROWID, date, sender, duration, trashed_date) \
           VALUES (1, 1673000000, '+420777050540', 42, 0);",
    );
    let arts = run(&VoicemailParser, "voicemail.db", db);
    assert_eq!(
        of_type(&arts, "Voicemail").len(),
        1,
        "the sound row is still recovered: {arts:?}"
    );
    assert!(
        !arts
            .iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str()) == Some("RowsUndecodable")),
        "a sound database must not be flagged"
    );
}

/// The drop marker carries the standard incompleteness pair and does not group
/// as one of the records it qualifies.
#[test]
fn the_row_drop_marker_carries_the_standard_pair() {
    let mut drops = RowDrops::default();
    assert!(
        drops
            .marker(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "VoicemailIncomplete",
                "voicemail",
                5
            )
            .is_none(),
        "a walk that dropped nothing emits nothing"
    );

    drops.record("column 1 is a blob, expected integer");
    drops.record("column 1 is a blob, expected integer");
    let marker = drops
        .marker(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "VoicemailIncomplete",
            "voicemail",
            5,
        )
        .expect("dropped rows must be declared");

    assert_eq!(marker.metadata["rows_dropped"], json!(2));
    assert_eq!(marker.metadata["records_recovered"], json!(5));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(marker.metadata["type"], "VoicemailIncomplete");
    assert_ne!(
        marker.metadata["type"], "Voicemail",
        "the marker must not group as a voicemail"
    );
    assert!(marker.metadata["first_error"]
        .as_str()
        .is_some_and(|e| e.contains("blob")));

    // The key the examiner actually sees. `frontend/src/lib/incompleteness.ts`
    // reads the parser's sentence from `content_incomplete_detail` and knows
    // nothing named `detail`. The local RowDrops this crate carried until
    // 2026-07-31 emitted only the bare `detail`, so a dropped-row marker
    // reached the screen as "unresolved structure" with no count, no table and
    // no decoder reason — the stamp arrived and its explanation did not.
    for key in ["content_incomplete_detail", "inventory_incomplete_detail"] {
        let detail = marker.metadata[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} must carry the sentence the UI renders"));
        assert!(detail.contains("2 row(s)"), "{key}: {detail}");
        assert!(detail.contains("voicemail"), "{key}: {detail}");
        assert!(detail.contains("blob"), "{key}: {detail}");
    }
}

// ---------------------------------------------------------------------------
// Cached locations (com.apple.routined)
// ---------------------------------------------------------------------------

/// `ZRTCLLOCATIONMO` as iOS 15 writes it, with the two rows that matter: the
/// last fix the phone recorded, and one whose accuracy says the fix is invalid.
fn routined_db() -> Vec<u8> {
    make_db(
        "CREATE TABLE ZRTCLLOCATIONMO (
            Z_PK INTEGER PRIMARY KEY, ZTYPE INTEGER, ZALTITUDE FLOAT, ZCOURSE FLOAT,
            ZHORIZONTALACCURACY FLOAT, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZSPEED FLOAT,
            ZTIMESTAMP TIMESTAMP, ZVERTICALACCURACY FLOAT);
         INSERT INTO ZRTCLLOCATIONMO VALUES
            (1, 0, 12.5, 88.0, 35.0, 38.8428235057189, -77.2776775592395, 1.5, 666555669.230695, 3.0),
            (2, 0, 0.0, -1.0, 1414.0, 38.84412765, -77.28686523, -1.0, 666555963.105048, -1.0),
            (3, 0, 0.0, -1.0, -1.0, 0.0, 0.0, -1.0, 666555000.0, -1.0);",
    )
}

/// The Magnet 2022 iOS CTF asks for the last position of the phone. It is in
/// `com.apple.routined`'s `Cache.sqlite`, and Séance listed the database as a
/// file and its rows as untyped SQLite rows: the question could only be
/// answered by writing SQL by hand (HUNT-099).
#[test]
fn cached_locations_become_located_records() {
    let out = run(&RoutinedLocationParser, "Cache.sqlite", routined_db());
    let fixes: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "CachedLocation")
        .collect();
    assert_eq!(fixes.len(), 2, "the invalid fix is not a location");

    // Newest first: "where was this phone last" is the question being asked.
    let last = fixes[0];
    assert_eq!(last.metadata["gps_lat"], 38.84412765);
    assert_eq!(last.metadata["gps_lon"], -77.28686523);
    // Core Data counts from 2001; read as Unix it is 31 years early. The
    // sub-second part is kept for the same reason this crate keeps it on a
    // PowerLog event: two fixes inside one second are two positions, and
    // truncating collapses them onto one instant with no order between them.
    assert_eq!(
        last.metadata["timestamp"],
        "2022-02-14T18:26:03.105047941+00:00"
    );
    assert_eq!(last.metadata["horizontal_accuracy_m"], 1414.0);
    assert_eq!(last.metadata["source"], "com.apple.routined");
}

/// CoreLocation writes -1 for "not measured". A speed of -1 m/s and a course of
/// -1 degrees are not findings about the phone's movement; they are the absence
/// of one, and a map that drew them would be drawing an invention.
#[test]
fn unmeasured_speed_and_course_are_absent_not_minus_one() {
    let out = run(&RoutinedLocationParser, "Cache.sqlite", routined_db());
    let fixes: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "CachedLocation")
        .collect();

    let unmeasured = fixes[0];
    assert!(unmeasured.metadata.get("speed_mps").is_none());
    assert!(unmeasured.metadata.get("course_deg").is_none());

    let measured = fixes[1];
    assert_eq!(measured.metadata["speed_mps"], 1.5);
    assert_eq!(measured.metadata["course_deg"], 88.0);
    assert_eq!(measured.metadata["altitude_m"], 12.5);
}

/// A negative horizontal accuracy is CoreLocation's own way of saying the fix
/// is invalid. Putting it on the map at 0,0 — the Gulf of Guinea — would place
/// the phone somewhere it has never been.
#[test]
fn an_invalid_fix_is_not_a_location() {
    let out = run(&RoutinedLocationParser, "Cache.sqlite", routined_db());
    assert!(
        !out.iter().any(|a| a.metadata["gps_lat"] == 0.0),
        "a fix CoreLocation marked invalid must not reach the map"
    );
    // And it is counted, not silently dropped.
    let status = out
        .iter()
        .find(|a| a.metadata["type"] == "CachedLocationSummary")
        .expect("the walk summarises itself");
    assert_eq!(status.metadata["fixes"], 2);
    assert_eq!(status.metadata["invalid_fixes"], 1);
}

#[test]
fn another_databases_cache_sqlite_is_not_claimed() {
    let out = run(
        &RoutinedLocationParser,
        "Cache.sqlite",
        make_db("CREATE TABLE Something (a TEXT);"),
    );
    assert!(out.is_empty());
}

// ---------------------------------------------------------------------------
// A store the parser recognised but could not query.
//
// Each of the four new parsers is built on one fixed-column SELECT. On a
// generation that lacks any one of those columns the statement does not
// prepare, and the walk used to return whatever it had — no records, no
// summary, no marker — so the case read as a device with no bookmarks, no
// tabs or no health samples. "Could not look" must never render as "not
// there" (the B8-038 class the crate's own `with_db` comment describes).
// ---------------------------------------------------------------------------

fn unreadable_status(out: &[Artifact]) -> &Artifact {
    let v: Vec<_> = out
        .iter()
        .filter(|a| {
            a.metadata["type"] == "IosArtifactParseStatus"
                && a.metadata["status"] == "DatabaseUnreadable"
        })
        .collect();
    assert_eq!(
        v.len(),
        1,
        "expected exactly one DatabaseUnreadable status, got {}: {:?}",
        v.len(),
        out.iter()
            .map(|a| a.metadata["type"].clone())
            .collect::<Vec<_>>()
    );
    v[0]
}

#[test]
fn a_bookmarks_store_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    // The table is there, so the file is recognised; the columns the walk
    // reads are not, so the walk cannot run.
    let db = make_db(
        "CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO bookmarks VALUES (1, 'Root');",
    );
    let out = run(&SafariBookmarksParser, "Bookmarks.db", db);
    assert!(
        !out.iter().any(|a| a.metadata["type"] == "SafariBookmark"),
        "no bookmark can be read from columns that are not there"
    );
    let status = unreadable_status(&out);
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(status.metadata["records_recovered"], 0);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("bookmarks") && detail.contains("no such column"),
        "the detail names the query and SQLite's own reason: {detail}"
    );
}

#[test]
fn an_open_tabs_store_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    let db = make_db(
        "CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, title TEXT);
         CREATE TABLE windows (id INTEGER PRIMARY KEY);
         INSERT INTO bookmarks VALUES (1, 'Root');",
    );
    let out = run(&SafariTabsParser, "SafariTabs.db", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "SafariOpenTab"));
    let status = unreadable_status(&out);
    assert_eq!(status.metadata["content_incomplete"], true);
    assert!(status.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("bookmarks"));
}

#[test]
fn an_open_tabs_store_whose_windows_cannot_be_queried_is_reported_unreadable_not_empty() {
    // The bookmarks walk runs; the windows walk — which decides whether a
    // tab is private — does not. A tab published without that answer is a
    // tab published as not private, so the store is unreadable as a whole.
    let db = make_db(
        "CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, special_id INTEGER, parent INTEGER, \
           type INTEGER, title TEXT, url TEXT, num_children INTEGER, hidden INTEGER, \
           deleted INTEGER, read INTEGER, last_modified REAL, order_index INTEGER, \
           external_uuid TEXT, date_closed REAL, extra_attributes BLOB, \
           local_attributes BLOB, sync_data BLOB);
         CREATE TABLE windows (id INTEGER PRIMARY KEY);
         INSERT INTO bookmarks (id, special_id, parent, type, title, url) VALUES (1, 0, NULL, 1, 'Root', NULL);",
    );
    let out = run(&SafariTabsParser, "SafariTabs.db", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "SafariOpenTab"));
    let status = unreadable_status(&out);
    assert!(status.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("windows"));
}

#[test]
fn a_browserstate_store_whose_tab_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    let db = make_db(
        "CREATE TABLE tabs (id INTEGER PRIMARY KEY, title TEXT);
         CREATE TABLE browser_windows (id INTEGER PRIMARY KEY);
         INSERT INTO tabs VALUES (1, 'A tab');",
    );
    let out = run(&SafariTabsParser, "BrowserState.db", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "SafariOpenTab"));
    let status = unreadable_status(&out);
    assert!(status.metadata["detail"].as_str().unwrap().contains("tabs"));
}

#[test]
fn a_health_store_whose_sample_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    let db = make_db(
        "CREATE TABLE samples (data_id INTEGER PRIMARY KEY);
         CREATE TABLE objects (data_id INTEGER PRIMARY KEY);
         INSERT INTO samples VALUES (1);
         INSERT INTO objects VALUES (1);",
    );
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "HealthSample"));
    let status = unreadable_status(&out);
    assert!(status.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("samples"));
}

// ---------------------------------------------------------------------------
// HealthKit summary honesty.
// ---------------------------------------------------------------------------

/// The smallest `healthdb_secure.sqlite` the samples walk can run over.
fn health_db(extra: &str) -> Vec<u8> {
    make_db(&format!(
        "CREATE TABLE samples (data_id INTEGER PRIMARY KEY, data_type INTEGER, start_date REAL, end_date REAL);
         CREATE TABLE objects (data_id INTEGER PRIMARY KEY, type INTEGER, creation_date REAL, uuid BLOB, provenance INTEGER);
         CREATE TABLE data_provenances (ROWID INTEGER PRIMARY KEY, origin_product_type TEXT, origin_build TEXT, \
           source_version TEXT, tz_name TEXT, source_id INTEGER, device_id INTEGER, local_product_type TEXT, local_build TEXT);
         CREATE TABLE quantity_samples (data_id INTEGER PRIMARY KEY, quantity REAL, original_quantity REAL, original_unit INTEGER);
         CREATE TABLE category_samples (data_id INTEGER PRIMARY KEY, value INTEGER);
         CREATE TABLE unit_strings (ROWID INTEGER PRIMARY KEY, unit_string TEXT);
         INSERT INTO samples VALUES (1, 7, 600000000.0, 600000001.0);
         INSERT INTO objects VALUES (1, 1, 600000000.0, X'01', NULL);
         INSERT INTO quantity_samples VALUES (1, 72.0, 72.0, NULL);
         {extra}"
    ))
}

#[test]
fn a_health_store_without_a_workouts_table_is_labelled_absent_not_zero() {
    // The structured field already said `workout_rows_table_absent`; the
    // display label said "0 workout row(s) unread" — a could-not-look shown
    // as a count of nothing.
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", health_db(""));
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .expect("summary");
    assert_eq!(summary.metadata["workout_rows_table_absent"], true);
    let name = summary.metadata["name"].as_str().unwrap();
    assert!(
        !name.contains("0 workout"),
        "an absent table is not zero rows: {name}"
    );
    assert!(
        name.contains("workouts table absent"),
        "the label says the table could not be looked at: {name}"
    );
}

#[test]
fn deleted_objects_and_deleted_samples_are_counted_apart() {
    // `objects.type = 2` marks any deleted object — a workout or a
    // correlation as much as a sample. The field named `deleted_samples`
    // counted all of them. Here: one deleted sample, and one deleted object
    // that is not a sample at all.
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        health_db(
            "INSERT INTO samples VALUES (2, 7, 600000002.0, 600000003.0);
             INSERT INTO objects VALUES (2, 2, 600000002.0, X'02', NULL);
             INSERT INTO objects VALUES (3, 2, 600000004.0, X'03', NULL);",
        ),
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .expect("summary");
    assert_eq!(summary.metadata["samples"], 2);
    assert_eq!(summary.metadata["deleted_samples"], 1);
    assert_eq!(summary.metadata["deleted_objects"], 2);
    let name = summary.metadata["name"].as_str().unwrap();
    assert!(name.contains("1 deleted"), "{name}");
}

// ---------------------------------------------------------------------------
// Photos: album subclasses inherit the root album's join table.
// ---------------------------------------------------------------------------

#[test]
fn an_album_subclass_inherits_the_root_album_join_table_and_a_folder_says_which_entity_it_is() {
    // Core Data keeps one `Z_27ASSETS` for `Album` (27) and every entity
    // that descends from it (`CloudSharedAlbum` 28 on the real iOS 15
    // store). `Folder` (34) descends from `GenericAlbum` (26), not from
    // `Album`, and has no membership table of its own.
    let db = make_db(
        "CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
         INSERT INTO Z_PRIMARYKEY VALUES (3, 'Asset', 0, 2);
         INSERT INTO Z_PRIMARYKEY VALUES (26, 'GenericAlbum', 0, 3);
         INSERT INTO Z_PRIMARYKEY VALUES (27, 'Album', 26, 0);
         INSERT INTO Z_PRIMARYKEY VALUES (28, 'CloudSharedAlbum', 27, 0);
         INSERT INTO Z_PRIMARYKEY VALUES (34, 'Folder', 26, 0);
         CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, ZDATECREATED TIMESTAMP, \
           ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZWIDTH INTEGER, ZHEIGHT INTEGER, ZKIND INTEGER, \
           ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         CREATE TABLE ZADDITIONALASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZASSET INTEGER, ZORIGINALFILENAME VARCHAR);
         INSERT INTO ZASSET VALUES (1, 'IMG_0001.HEIC', 700000000.0, -180.0, -180.0, 100, 100, 0, 0, 0);
         INSERT INTO ZASSET VALUES (2, 'IMG_0002.HEIC', 700000001.0, -180.0, -180.0, 100, 100, 0, 0, 0);
         CREATE TABLE ZGENERICALBUM (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZKIND INTEGER, ZTITLE VARCHAR);
         INSERT INTO ZGENERICALBUM VALUES (1, 27, 2, 'Mine');
         INSERT INTO ZGENERICALBUM VALUES (2, 28, 1505, 'Shared with me');
         INSERT INTO ZGENERICALBUM VALUES (3, 34, 4000, 'A folder');
         CREATE TABLE Z_27ASSETS (Z_27ALBUMS INTEGER, Z_3ASSETS INTEGER);
         INSERT INTO Z_27ASSETS VALUES (1, 1);
         INSERT INTO Z_27ASSETS VALUES (2, 1);
         INSERT INTO Z_27ASSETS VALUES (2, 2);",
    );
    let out = run(&PhotosParser, "Photos.sqlite", db);
    let album = |title: &str| {
        out.iter()
            .find(|a| a.metadata["type"] == "PhotoAlbum" && a.metadata["title"] == title)
            .unwrap_or_else(|| panic!("album {title}"))
    };
    assert_eq!(album("Mine").metadata["asset_count"], 1);
    let shared = album("Shared with me");
    assert_eq!(
        shared.metadata["asset_count"], 2,
        "a CloudSharedAlbum's memberships are in Album's join table: {:?}",
        shared.metadata
    );
    assert_eq!(shared.metadata.get("asset_count_unresolved"), None);
    let folder = album("A folder");
    assert_eq!(folder.metadata["asset_count_unresolved"], true);
    let reason = folder.metadata["asset_count_unresolved_reason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("Folder") && reason.contains("Album") && reason.contains("Z_27ASSETS"),
        "the reason names the entity, the root it does not descend from and the one table found: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Safari recent searches: the plist's own limits, and where a value came from.
// ---------------------------------------------------------------------------

fn searches_plist(with_udid: bool) -> Vec<u8> {
    let mut d = plist::Dictionary::new();
    let mut e = plist::Dictionary::new();
    e.insert("SearchString".into(), plist::Value::String("seance".into()));
    e.insert(
        "Date".into(),
        plist::Value::Date(plist::Date::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        )),
    );
    d.insert(
        "RecentWebSearches".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(e)]),
    );
    if with_udid {
        d.insert(
            "DidPromptSearchEngineAlertUDID".into(),
            plist::Value::String("00008010-000000000000001E".into()),
        );
    }
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(d)).unwrap();
    bytes
}

#[test]
fn the_search_summary_names_the_plist_key_its_device_udid_came_from() {
    let out = run(
        &SafariSearchesParser,
        "com.apple.mobilesafari.plist",
        searches_plist(true),
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "SafariSearchesSummary")
        .expect("summary");
    assert_eq!(summary.metadata["device_udid"], "00008010-000000000000001E");
    assert_eq!(
        summary.metadata["device_udid_source"], "DidPromptSearchEngineAlertUDID",
        "the value is an interpretation of one key; the record says which"
    );
    let without = run(
        &SafariSearchesParser,
        "com.apple.mobilesafari.plist",
        searches_plist(false),
    );
    let summary = without
        .iter()
        .find(|a| a.metadata["type"] == "SafariSearchesSummary")
        .expect("summary");
    assert_eq!(summary.metadata.get("device_udid"), None);
    assert_eq!(summary.metadata.get("device_udid_source"), None);
}

#[test]
fn a_short_read_of_the_searches_plist_is_reported_unreadable_with_the_byte_counts() {
    let bytes = searches_plist(true);
    let declared = (bytes.len() as u64) * 2;
    let out = run_source(
        &SafariSearchesParser,
        "com.apple.mobilesafari.plist",
        Arc::new(truncated(bytes.clone())),
    );
    assert!(!out.iter().any(|a| a.metadata["type"] == "WebSearchQuery"));
    assert_eq!(out.len(), 1);
    let status = &out[0].metadata;
    assert_eq!(status["type"], "IosArtifactParseStatus");
    assert_eq!(status["status"], "PlistUnreadable");
    assert_eq!(status["content_incomplete"], true);
    assert_eq!(
        status["content_incomplete_reason"],
        IncompleteReason::ShortRead.as_str()
    );
    assert_eq!(
        status["detail"],
        format!(
            "{} of {declared} declared bytes were delivered",
            bytes.len()
        )
    );
}

#[test]
fn a_searches_plist_over_the_ceiling_is_refused_with_the_ceiling_stated() {
    let declared = 16 * 1024 * 1024 + 1;
    let out = run_source(
        &SafariSearchesParser,
        "com.apple.mobilesafari.plist",
        Arc::new(seance_core::test_support::UnreadableSource::new(declared)),
    );
    assert_eq!(out.len(), 1);
    let status = &out[0].metadata;
    assert_eq!(status["status"], "PlistUnreadable");
    assert_eq!(
        status["content_incomplete_reason"],
        IncompleteReason::CapReached.as_str()
    );
    assert_eq!(
        status["detail"],
        format!(
            "{declared} bytes exceeds the {}-byte ceiling",
            16 * 1024 * 1024
        )
    );
}

// ---------------------------------------------------------------------------
// The same class in the five older parsers: the one fixed-column SELECT each
// is built on does not prepare on a generation that lacks a column, and the
// walk used to return nothing — no records, no summary, no marker — so the
// case read as a device with no voicemails, events, fixes, notes or photos.
// ---------------------------------------------------------------------------

#[test]
fn a_voicemail_store_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    let db = make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, date INTEGER);
         INSERT INTO voicemail VALUES (1, 1700000000);",
    );
    let out = run(&VoicemailParser, "voicemail.db", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "Voicemail"));
    let status = unreadable_status(&out);
    assert_eq!(status.metadata["records_recovered"], 0);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("voicemail") && detail.contains("no such column"),
        "the detail names the query and SQLite's own reason: {detail}"
    );
}

#[test]
fn a_calendar_store_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    // `CalendarItem` is there, so the file is recognised; the `Calendar`
    // table the walk joins is not.
    let db = make_db(
        "CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER);
         INSERT INTO CalendarItem VALUES (1, 'Standup', NULL, 700000000.0, 700003600.0, 0, 1);",
    );
    let out = run(&CalendarDbParser, "Calendar.sqlitedb", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "CalendarEvent"));
    let status = unreadable_status(&out);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("CalendarItem") && detail.contains("no such table"),
        "{detail}"
    );
}

#[test]
fn a_routined_cache_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    let db = make_db(
        "CREATE TABLE ZRTCLLOCATIONMO (Z_PK INTEGER PRIMARY KEY, ZLATITUDE FLOAT, ZLONGITUDE FLOAT);
         INSERT INTO ZRTCLLOCATIONMO VALUES (1, 50.0, 14.0);",
    );
    let out = run(&RoutinedLocationParser, "Cache.sqlite", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "LocationFix"));
    assert!(!out
        .iter()
        .any(|a| a.metadata["type"] == "RoutinedLocationSummary"));
    let status = unreadable_status(&out);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("ZRTCLLOCATIONMO") && detail.contains("no such column"),
        "{detail}"
    );
}

#[test]
fn a_notes_store_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    // `ZSNIPPET` is one of the columns the note walk names outright.
    let db = make_db(
        "CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 VARCHAR);
         INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (1, 'Shopping list');",
    );
    let out = run(&NotesParser, "NoteStore.sqlite", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "Note"));
    assert!(!out.iter().any(|a| a.metadata["type"] == "NotesSummary"));
    let status = unreadable_status(&out);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("ZICCLOUDSYNCINGOBJECT") && detail.contains("no such column"),
        "{detail}"
    );
}

#[test]
fn a_photos_catalog_whose_columns_cannot_be_queried_is_reported_unreadable_not_empty() {
    // The asset table is there; `ZADDITIONALASSETATTRIBUTES`, which the
    // walk joins for the original file name, is not.
    let db = make_db(
        "CREATE TABLE ZGENERICASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, \
           ZDATECREATED TIMESTAMP, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZWIDTH INTEGER, \
           ZHEIGHT INTEGER, ZKIND INTEGER, ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         INSERT INTO ZGENERICASSET VALUES (1, 'IMG_0001.HEIC', 700000000.0, -180.0, -180.0, 100, 100, 0, 0, 0);",
    );
    let out = run(&PhotosParser, "Photos.sqlite", db);
    assert!(!out.iter().any(|a| a.metadata["type"] == "PhotoAsset"));
    assert!(!out.iter().any(|a| a.metadata["type"] == "PhotosSummary"));
    let status = unreadable_status(&out);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert!(
        detail.contains("ZGENERICASSET") && detail.contains("no such table"),
        "{detail}"
    );
}

// ---------------------------------------------------------------------------
// Secondary queries: a lookup that does not prepare is a could-not-look, and
// the record it would have filled says so instead of reading as not-there.
// ---------------------------------------------------------------------------

/// A `healthdb_secure.sqlite` with a `healthdb.sqlite` beside it on disk,
/// opened through a source that can look at its neighbours.
fn health_store_with_sibling(secure: &[u8], sibling_ddl: &str) -> Vec<Artifact> {
    let dir = std::env::temp_dir().join(format!("seance_ios_health_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("healthdb_secure.sqlite"), secure).unwrap();
    std::fs::write(dir.join("healthdb.sqlite"), make_db(sibling_ddl)).unwrap();
    let ds: Arc<dyn DataSource> = Arc::new(
        seance_core::data_source::FileDataSource::new(dir.join("healthdb_secure.sqlite"))
            .expect("the staged store opens"),
    );
    let out = run_source(&HealthKitParser, "healthdb_secure.sqlite", ds);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn health_sample(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == "HealthSample")
        .expect("the one sample")
}

fn health_summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .expect("summary")
}

#[test]
fn a_sources_table_that_cannot_be_queried_is_not_a_source_id_that_is_not_there() {
    // The sibling has a `sources` table, so the resolution used to stay
    // "resolved" with the table unread, and every sample read as one whose
    // source id is missing from a table that was in fact never looked at.
    let out = health_store_with_sibling(
        &health_db(
            "INSERT INTO data_provenances VALUES (1, 'iPhone', '19A404', '15.0.2', 'UTC', 7, NULL, NULL, NULL);
             UPDATE objects SET provenance = 1 WHERE data_id = 1;",
        ),
        "CREATE TABLE sources (ROWID INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO sources VALUES (7, 'Health');",
    );
    let sample = health_sample(&out);
    assert_eq!(sample.metadata["source_id"], 7);
    assert_eq!(sample.metadata["source_name_unresolved"], true);
    assert_eq!(
        sample.metadata["source_name_unresolved_reason"],
        "sibling_sources_query_did_not_run"
    );
    let summary = health_summary(&out);
    assert_eq!(
        summary.metadata["source_name_resolution"],
        "sibling_sources_query_did_not_run"
    );
    assert_eq!(summary.metadata.get("sources_rows"), None);
    let err = summary.metadata["sources_query_error"].as_str().unwrap();
    assert!(err.contains("no such column"), "{err}");
}

#[test]
fn a_source_devices_table_that_cannot_be_queried_is_named_not_left_blank() {
    let out = health_store_with_sibling(
        &health_db(
            "INSERT INTO data_provenances VALUES (1, 'iPhone', '19A404', '15.0.2', 'UTC', 7, 3, NULL, NULL);
             UPDATE objects SET provenance = 1 WHERE data_id = 1;",
        ),
        "CREATE TABLE sources (ROWID INTEGER PRIMARY KEY, name TEXT, bundle_id TEXT, product_type TEXT);
         INSERT INTO sources VALUES (7, 'Health', 'com.apple.Health', 'iPhone13,2');
         CREATE TABLE source_devices (ROWID INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO source_devices VALUES (3, 'iPhone');",
    );
    let sample = health_sample(&out);
    assert_eq!(sample.metadata["source_name"], "Health");
    assert_eq!(sample.metadata["device_id"], 3);
    assert_eq!(sample.metadata.get("source_device"), None);
    assert_eq!(
        sample.metadata["source_device_unresolved_reason"],
        "sibling_source_devices_query_did_not_run"
    );
    let summary = health_summary(&out);
    assert_eq!(summary.metadata["sources_rows"], 1);
    assert_eq!(summary.metadata.get("source_device_rows"), None);
    assert_eq!(
        summary.metadata["source_device_resolution"],
        "sibling_source_devices_query_did_not_run"
    );
    assert!(summary.metadata["source_devices_query_error"]
        .as_str()
        .unwrap()
        .contains("no such column"));
}

#[test]
fn a_device_id_the_devices_table_does_not_hold_is_told_apart_from_a_table_not_read() {
    let out = health_store_with_sibling(
        &health_db(
            "INSERT INTO data_provenances VALUES (1, 'iPhone', '19A404', '15.0.2', 'UTC', 7, 3, NULL, NULL);
             UPDATE objects SET provenance = 1 WHERE data_id = 1;",
        ),
        "CREATE TABLE sources (ROWID INTEGER PRIMARY KEY, name TEXT, bundle_id TEXT, product_type TEXT);
         INSERT INTO sources VALUES (7, 'Health', 'com.apple.Health', 'iPhone13,2');
         CREATE TABLE source_devices (ROWID INTEGER PRIMARY KEY, name TEXT, manufacturer TEXT, model TEXT, \
           hardware TEXT, firmware TEXT, software TEXT, localIdentifier TEXT);",
    );
    let sample = health_sample(&out);
    assert_eq!(
        sample.metadata["source_device_unresolved_reason"],
        "device_id_not_in_source_devices"
    );
    let summary = health_summary(&out);
    assert_eq!(summary.metadata["source_device_resolution"], "resolved");
    assert_eq!(summary.metadata["source_device_rows"], 0);
}

#[test]
fn a_metadata_join_that_cannot_be_queried_is_reported_unread_not_as_zero_rows() {
    // Both metadata tables are there, so the reader used to try the join,
    // fail to prepare it, and report `metadata_rows: 0` with no `metadata`
    // on any sample — the same figures a store with no metadata gives.
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        health_db(
            "CREATE TABLE metadata_keys (ROWID INTEGER PRIMARY KEY);
             CREATE TABLE metadata_values (ROWID INTEGER PRIMARY KEY, object_id INTEGER, key_id INTEGER);
             INSERT INTO metadata_keys VALUES (1);
             INSERT INTO metadata_values VALUES (1, 1, 1);",
        ),
    );
    let summary = health_summary(&out);
    assert_eq!(summary.metadata["metadata_status"], "query_did_not_run");
    assert_eq!(summary.metadata.get("metadata_rows"), None);
    let err = summary.metadata["metadata_query_error"].as_str().unwrap();
    assert!(err.contains("no such column"), "{err}");
    let sample = health_sample(&out);
    assert_eq!(sample.metadata.get("metadata"), None);
    assert_eq!(sample.metadata["metadata_unread"], true);
    assert_eq!(
        sample.metadata["metadata_unread_reason"],
        "metadata_values join did not run"
    );
}

#[test]
fn a_metadata_join_that_runs_and_finds_nothing_says_read_and_zero() {
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        health_db(
            "CREATE TABLE metadata_keys (ROWID INTEGER PRIMARY KEY, key TEXT);
             CREATE TABLE metadata_values (ROWID INTEGER PRIMARY KEY, object_id INTEGER, key_id INTEGER, \
               value_type INTEGER, string_value TEXT, numerical_value REAL, date_value REAL, data_value BLOB);",
        ),
    );
    let summary = health_summary(&out);
    assert_eq!(summary.metadata["metadata_status"], "read");
    assert_eq!(summary.metadata["metadata_rows"], 0);
    assert_eq!(summary.metadata["data_type_histogram_status"], "counted");
    assert_eq!(summary.metadata["data_type_histogram"]["7"], 1);
    let sample = health_sample(&out);
    assert_eq!(sample.metadata.get("metadata_unread"), None);
}

#[test]
fn a_metadata_table_the_store_lacks_is_labelled_absent() {
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", health_db(""));
    let summary = health_summary(&out);
    assert_eq!(summary.metadata["metadata_status"], "tables_absent");
    assert_eq!(summary.metadata.get("metadata_rows"), None);
}

#[test]
fn a_tab_sessions_table_that_cannot_be_queried_leaves_no_tab_marked_as_having_no_session() {
    // `tab_sessions` is there, so the lookup used to be tried, fail to
    // prepare, and every tab was published `session_state_present: false`
    // — the same as a tab with no session row.
    let db = make_db(
        "CREATE TABLE tabs (id INTEGER PRIMARY KEY, uuid TEXT, title TEXT, url TEXT, \
           user_visible_url TEXT, order_index INTEGER, last_viewed_time REAL, \
           private_browsing INTEGER, opened_from_link INTEGER, showing_reader INTEGER, \
           browser_window_uuid TEXT, browser_window_id INTEGER, readinglist_bookmark_id INTEGER);
         CREATE TABLE browser_windows (id INTEGER PRIMARY KEY);
         CREATE TABLE tab_sessions (tab_uuid TEXT);
         INSERT INTO tabs VALUES (1, 'T-1', 'A tab', 'https://example.test/', NULL, 0, 700000000.0, 0, 0, 0, 'W-1', 1, 0);
         INSERT INTO tab_sessions VALUES ('T-1');",
    );
    let out = run(&SafariTabsParser, "BrowserState.db", db);
    let tab = out
        .iter()
        .find(|a| a.metadata["type"] == "SafariOpenTab")
        .expect("the tab");
    assert_eq!(tab.metadata.get("session_state_present"), None);
    assert_eq!(tab.metadata["session_state_unknown"], true);
    assert_eq!(
        tab.metadata["session_state_unknown_reason"],
        "tab_sessions query did not run"
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "SafariTabsSummary")
        .expect("summary");
    assert_eq!(summary.metadata.get("session_rows"), None);
    assert_eq!(summary.metadata["session_rows_query_did_not_run"], true);
    assert!(summary.metadata["session_rows_query_error"]
        .as_str()
        .unwrap()
        .contains("no such column"));
    // The store is still read: nothing here made the tabs unreadable.
    assert!(!out
        .iter()
        .any(|a| a.metadata["status"] == "DatabaseUnreadable"));
}

#[test]
fn a_note_body_table_that_cannot_be_queried_leaves_no_note_marked_as_having_no_body() {
    // `ZICNOTEDATA` is there, so the body lookup used to be tried, fail to
    // prepare, and every note was published `body_present: false` — the
    // same as a note whose body row is missing.
    let db = make_db(
        "CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE1 VARCHAR, \
           ZSNIPPET VARCHAR, ZCREATIONDATE TIMESTAMP, ZMODIFICATIONDATE TIMESTAMP);
         INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (1, 'Shopping list', 'milk', 700000000.0, 700010000.0);
         CREATE TABLE ZICNOTEDATA (Z_PK INTEGER PRIMARY KEY, ZNOTE INTEGER);
         INSERT INTO ZICNOTEDATA VALUES (1, 1);",
    );
    let out = run(&NotesParser, "NoteStore.sqlite", db);
    let note = out
        .iter()
        .find(|a| a.metadata["type"] == "Note")
        .expect("the note");
    assert_eq!(note.metadata.get("body_present"), None);
    assert_eq!(note.metadata["body_unread"], true);
    assert_eq!(
        note.metadata["body_unread_reason"],
        "ZICNOTEDATA query did not run"
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "NotesSummary")
        .expect("summary");
    assert_eq!(summary.metadata["bodies_absent"], 0);
    assert_eq!(summary.metadata["bodies_unread"], 1);
    assert_eq!(summary.metadata["body_query_did_not_run"], true);
    assert!(summary.metadata["body_query_error"]
        .as_str()
        .unwrap()
        .contains("no such column"));
}

// ---------------------------------------------------------------------------
// HUNT-190, the remainder: an expected table absent from a readable catalogue,
// a catalogue that will not read, a NULL read as `false`, and a torch query
// that fails. Each used to be silence or an assertion the column never made.
// ---------------------------------------------------------------------------

fn run_at(module: &dyn ForensicsModule, name: &str, path: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name, "path": path }),
    );
    module.process(&art).unwrap()
}

/// Page 1's b-tree cell count set past what the page can hold: the header
/// still reads as SQLite and the catalogue query fails with SQLITE_CORRUPT.
fn corrupt_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

fn table_absent_status(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["status"] == "ExpectedTableAbsent")
        .unwrap_or_else(|| panic!("the absent table must be stated, not silent: {out:?}"))
}

/// A readable `voicemail.db` with no `voicemail` table answered nothing, which
/// renders as a device with no voicemail — when what the catalogue said is
/// that this is not a schema this reader knows.
#[test]
fn a_voicemail_store_without_its_table_says_so() {
    let out = run(
        &VoicemailParser,
        "voicemail.db",
        make_db("CREATE TABLE voicemail_v2 (ROWID INTEGER PRIMARY KEY, date INTEGER);"),
    );
    let s = table_absent_status(&out);
    assert_eq!(s.metadata["type"], "IosArtifactParseStatus");
    assert_eq!(s.metadata["expected_tables"], json!(["voicemail"]));
    assert_eq!(s.metadata["inventory_incomplete"], true);
    assert_eq!(s.metadata["records_recovered"], 0);
}

#[test]
fn a_calendar_store_without_its_table_says_so() {
    let out = run(
        &CalendarDbParser,
        "Calendar.sqlitedb",
        make_db("CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);"),
    );
    assert_eq!(
        table_absent_status(&out).metadata["expected_tables"],
        json!(["CalendarItem"])
    );
}

#[test]
fn a_notes_store_without_its_table_says_so() {
    // The pre-iOS 9 `notes.sqlite` keeps notes in `ZNOTE`; this reader knows
    // only the modern table, and must say so rather than report no notes.
    let out = run(
        &NotesParser,
        "notes.sqlite",
        make_db("CREATE TABLE ZNOTE (Z_PK INTEGER PRIMARY KEY, ZTITLE VARCHAR);"),
    );
    assert_eq!(
        table_absent_status(&out).metadata["expected_tables"],
        json!(["ZICCLOUDSYNCINGOBJECT"])
    );
}

#[test]
fn a_photos_store_without_an_asset_table_says_so() {
    let out = run(
        &PhotosParser,
        "Photos.sqlite",
        make_db("CREATE TABLE ZGENERICALBUM (Z_PK INTEGER PRIMARY KEY, ZTITLE VARCHAR);"),
    );
    assert_eq!(
        table_absent_status(&out).metadata["expected_tables"],
        json!(["ZGENERICASSET", "ZASSET"])
    );
}

/// `has_table` collapsed "the catalogue would not read" into "absent", so a
/// damaged `voicemail.db` or `Photos.sqlite` answered nothing at all.
#[test]
fn a_voicemail_store_whose_catalogue_will_not_read_is_unreadable_not_empty() {
    let db = corrupt_catalogue(make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, date INTEGER, sender TEXT, \
           callback_num TEXT, duration INTEGER, trashed_date INTEGER, receiver TEXT);",
    ));
    let out = run(&VoicemailParser, "voicemail.db", db);
    let s = unreadable_status(&out);
    assert!(
        s.metadata["detail"].as_str().unwrap().contains("voicemail"),
        "{:?}",
        s.metadata
    );
}

#[test]
fn a_photos_store_whose_catalogue_will_not_read_is_unreadable_not_empty() {
    let db = corrupt_catalogue(make_db(
        "CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR);",
    ));
    let out = run(&PhotosParser, "Photos.sqlite", db);
    let _ = unreadable_status(&out);
}

/// `Cache.sqlite` is a name many apps use, so a readable one without the
/// location table stays unclaimed (`another_databases_cache_sqlite_is_not_claimed`).
/// But one at `com.apple.routined`'s own path whose catalogue will not read
/// is the location history unread — and says so.
#[test]
fn a_routined_cache_whose_catalogue_will_not_read_is_unreadable_at_its_own_path() {
    let at_routined = run_at(
        &RoutinedLocationParser,
        "Cache.sqlite",
        "/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite",
        corrupt_catalogue(routined_db()),
    );
    let _ = unreadable_status(&at_routined);

    let elsewhere = run_at(
        &RoutinedLocationParser,
        "Cache.sqlite",
        "/private/var/mobile/Containers/Data/Application/X/Library/Caches/Cache.sqlite",
        corrupt_catalogue(routined_db()),
    );
    assert!(
        !elsewhere
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseUnreadable"),
        "another app's damaged Cache.sqlite is not claimed as a location cache"
    );
}

/// `trashed_date` NULL was written `deleted: false` — an assertion of "not
/// trashed" from a column that recorded nothing. 0 is "not trashed"; NULL is
/// unknown.
#[test]
fn a_null_voicemail_trashed_date_is_null_not_false() {
    let db = make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, remote_uid INTEGER, date INTEGER, \
           token TEXT, sender TEXT, callback_num TEXT, duration INTEGER, expiration INTEGER, \
           trashed_date INTEGER, flags INTEGER, receiver TEXT);
         INSERT INTO voicemail (date, sender, trashed_date) VALUES (1673000000, '+1', 0);
         INSERT INTO voicemail (date, sender, trashed_date) VALUES (1673100000, '+2', NULL);
         INSERT INTO voicemail (date, sender, trashed_date) VALUES (1673200000, '+3', 1673300000);",
    );
    let out = run(&VoicemailParser, "voicemail.db", db);
    let by = |s: &str| {
        &out.iter()
            .find(|a| a.metadata["sender"] == s)
            .unwrap()
            .metadata
    };
    assert_eq!(by("+1")["deleted"], false);
    assert_eq!(by("+2")["deleted"], Value::Null, "{:?}", by("+2"));
    assert_eq!(by("+3")["deleted"], true);
}

/// The same in Photos: `ZFAVORITE` / `ZTRASHEDSTATE` NULL is not "not a
/// favourite" / "not deleted".
#[test]
fn a_null_photos_favorite_or_trashed_state_is_null_not_false() {
    let db = make_db(
        "CREATE TABLE ZGENERICASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, \
           ZDATECREATED TIMESTAMP, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZWIDTH INTEGER, \
           ZHEIGHT INTEGER, ZKIND INTEGER, ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         CREATE TABLE ZADDITIONALASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZASSET INTEGER, \
           ZORIGINALFILENAME VARCHAR);
         INSERT INTO ZGENERICASSET VALUES (1, 'A.HEIC', 700000000.0, NULL, NULL, 1, 1, 0, NULL, NULL);
         INSERT INTO ZGENERICASSET VALUES (2, 'B.HEIC', 700000001.0, NULL, NULL, 1, 1, 0, 0, 0);",
    );
    let out = run(&PhotosParser, "Photos.sqlite", db);
    let asset = |f: &str| {
        &out.iter()
            .find(|a| a.metadata["filename"] == f)
            .unwrap()
            .metadata
    };
    assert_eq!(
        asset("A.HEIC")["favorite"],
        Value::Null,
        "{:?}",
        asset("A.HEIC")
    );
    assert_eq!(asset("A.HEIC")["deleted"], Value::Null);
    assert_eq!(asset("B.HEIC")["favorite"], false);
    assert_eq!(asset("B.HEIC")["deleted"], false);
}

/// The same once more in Calendar: `all_day` NULL is not "timed".
#[test]
fn a_null_calendar_all_day_is_null_not_false() {
    let db = make_db(
        "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);
         CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER);
         INSERT INTO CalendarItem (summary, start_date, all_day) VALUES ('Unknown', 700000000.0, NULL);
         INSERT INTO CalendarItem (summary, start_date, all_day) VALUES ('Timed', 700000001.0, 0);",
    );
    let out = run(&CalendarDbParser, "Calendar.sqlitedb", db);
    let ev = |s: &str| {
        &out.iter()
            .find(|a| a.metadata["summary"] == s)
            .unwrap()
            .metadata
    };
    assert_eq!(ev("Unknown")["all_day"], Value::Null);
    assert_eq!(ev("Timed")["all_day"], false);
}

fn powerlog_summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == "PowerLogSummary")
        .unwrap_or_else(|| panic!("a PowerLog summary: {out:?}"))
}

/// A torch table whose columns cannot be listed — a view over a table that has
/// since gone — made `powerlog_torch` return `None`: no events, and
/// `torch_rows_dropped 0` on a summary that said nothing had failed.
#[test]
fn a_torch_query_that_cannot_run_is_stated_on_the_summary() {
    let db = make_db(
        "CREATE TABLE PLBatteryAgent_EventBackward_Battery (ID INTEGER, timestamp REAL, Level INTEGER);
         CREATE TABLE PL_t (ID INTEGER PRIMARY KEY, timestamp REAL, state INTEGER);
         CREATE VIEW PLCameraAgent_EventForward_Torch AS SELECT timestamp, state FROM PL_t;
         DROP TABLE PL_t;",
    );
    let out = run(&PowerLogParser, "CurrentPowerlog.PLSQL", db);
    let m = &powerlog_summary(&out).metadata;
    assert_eq!(m["torch_status"], "query_did_not_run", "{m:?}");
    assert!(m["torch_query_error"].as_str().unwrap().contains("PL_t"));
    assert_eq!(m["content_incomplete"], true);
}

/// A torch table with no column this reader recognises as a time was the
/// same silence by another door (`?` on the column search).
#[test]
fn a_torch_table_with_no_time_column_is_stated_on_the_summary() {
    let db = make_db(
        "CREATE TABLE PLCameraAgent_EventForward_Torch (ID INTEGER PRIMARY KEY, when_utc REAL, state INTEGER);
         INSERT INTO PLCameraAgent_EventForward_Torch (when_utc, state) VALUES (1673000000, 1);",
    );
    let out = run(&PowerLogParser, "CurrentPowerlog.PLSQL", db);
    let m = &powerlog_summary(&out).metadata;
    assert_eq!(m["torch_status"], "time_column_unresolved", "{m:?}");
    assert_eq!(m["content_incomplete"], true);
}

/// The controls: a torch table read whole says `read`, and a PowerLog with no
/// torch table says `table_absent` — a finding, not a shortfall.
#[test]
fn a_read_or_absent_torch_table_says_which() {
    let read = run(
        &PowerLogParser,
        "CurrentPowerlog.PLSQL",
        make_db(
            "CREATE TABLE PLCameraAgent_EventForward_Torch (ID INTEGER PRIMARY KEY, timestamp REAL, state INTEGER);
             INSERT INTO PLCameraAgent_EventForward_Torch (timestamp, state) VALUES (1673000000, 1);",
        ),
    );
    let m = &powerlog_summary(&read).metadata;
    assert_eq!(m["torch_status"], "read");
    assert!(m.get("content_incomplete").is_none(), "{m:?}");

    let absent = run(
        &PowerLogParser,
        "CurrentPowerlog.PLSQL",
        make_db("CREATE TABLE PLBatteryAgent_EventBackward_Battery (ID INTEGER, timestamp REAL);"),
    );
    let m = &powerlog_summary(&absent).metadata;
    assert_eq!(m["torch_status"], "table_absent");
    assert!(m.get("content_incomplete").is_none(), "{m:?}");
}

// ---------------------------------------------------------------------------
// HUNT-213 / HUNT-214 / HUNT-215: the reminders query, the Photos album
// lookups, and an empty voicemail or calendar store. Each was silence.
// ---------------------------------------------------------------------------

/// `Calendar` and the columns of `CalendarItem` this reader selects, as they
/// are named on the Magnet 2022 iPhone 8 (iOS 15) `Calendar.sqlitedb`: the
/// completion column is `completion_date`, not `completed_date`.
const REAL_CALENDAR_DDL: &str =
    "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);
     CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, summary TEXT, \
       location_id INTEGER, description TEXT, start_date REAL, start_tz TEXT, end_date REAL, \
       end_tz TEXT, all_day INTEGER, calendar_id INTEGER, priority INTEGER, due_date REAL, \
       due_tz TEXT, due_all_day INTEGER, completion_date REAL, creation_date REAL);";

/// The tables of the Magnet 2022 iPhone 8's top-level
/// `Library/Voicemail/voicemail.db`, as `sqlite_master` has them: `voicemail`
/// and `deleted` share twelve columns, and both are empty. (The per-account
/// store beside it has `voicemail` only; see the fixture tests.)
const REAL_VOICEMAIL_DDL: &str =
    "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, \
       remote_uid INTEGER, date INTEGER, token TEXT, sender TEXT, callback_num TEXT, \
       duration INTEGER, expiration INTEGER, trashed_date INTEGER, flags INTEGER, \
       receiver TEXT, label TEXT);
     CREATE INDEX date_index on voicemail(date);
     CREATE INDEX remote_uid_index on voicemail(remote_uid);
     CREATE TABLE deleted (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, \
       remote_uid INTEGER, date INTEGER, token TEXT, sender TEXT, callback_num TEXT, \
       duration INTEGER, expiration INTEGER, trashed_date INTEGER, flags INTEGER, \
       receiver TEXT, label TEXT);
     CREATE TABLE map (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT, label TEXT);";

fn of_type<'a>(out: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == ty).collect()
}

/// Set the page-type byte of `table`'s root b-tree page to an invalid value:
/// the catalogue and `PRAGMA table_info` still read (they never touch that
/// page), and any statement that walks the table fails with SQLITE_CORRUPT —
/// the shape of a store with one damaged page.
fn corrupt_table(bytes: Vec<u8>, table: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_ios_corrupt_{}.db", Uuid::new_v4()));
    std::fs::write(&path, &bytes).unwrap();
    let (root, page_size): (i64, i64) = {
        let c = Connection::open(&path).unwrap();
        let root = c
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = ?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        let ps = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        (root, ps)
    };
    let _ = std::fs::remove_file(&path);
    assert!(root > 1, "the table's root must not be page 1");
    let mut bytes = bytes;
    bytes[((root - 1) * page_size) as usize] = 0x01;
    bytes
}

/// HUNT-213 (and what grading it on the real store found): the reminders
/// query named `completed_date`, a column the real iOS 15 `CalendarItem` does
/// not have, so it never prepared and every reminder on a real device was
/// dropped without a word.
#[test]
fn reminders_are_read_from_the_real_completion_date_column() {
    let db = make_db(&format!(
        "{REAL_CALENDAR_DDL}
         INSERT INTO Calendar (ROWID, title) VALUES (2, 'Reminders');
         INSERT INTO CalendarItem (summary, start_date, calendar_id, due_date, completion_date, priority) \
           VALUES ('Buy milk', NULL, 2, 700100000.0, 700200000.0, 1);"
    ));
    let out = run(&CalendarDbParser, "Calendar.sqlitedb", db);
    let reminders = of_type(&out, "Reminder");
    assert_eq!(reminders.len(), 1, "{out:?}");
    assert_eq!(reminders[0].metadata["completed"], true);
    assert_eq!(
        reminders[0].metadata["completed_date"].as_i64(),
        Some(1_678_507_200)
    );
}

/// HUNT-213: a reminders query that will not prepare (here a `CalendarItem`
/// generation without the reminder columns) returned nothing and left no
/// marker, so "no reminders" and "could not look" read alike.
#[test]
fn a_reminders_query_that_will_not_run_is_reported_not_silent() {
    let db = make_db(
        "CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT);
         CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT, \
           start_date REAL, end_date REAL, all_day INTEGER, calendar_id INTEGER);
         INSERT INTO CalendarItem (summary, start_date) VALUES ('Standup', 700000000.0);",
    );
    let out = run(&CalendarDbParser, "Calendar.sqlitedb", db);
    assert_eq!(of_type(&out, "CalendarEvent").len(), 1, "events still read");
    let m: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "ReminderIncomplete")
        .filter(|a| a.metadata["status"] == "DatabaseUnreadable")
        .collect();
    assert_eq!(
        m.len(),
        1,
        "no DatabaseUnreadable reminders record: {out:?}"
    );
    assert_eq!(m[0].metadata["source_table"], "CalendarItem");
    assert!(m[0].metadata["sqlite_error"]
        .as_str()
        .unwrap()
        .contains("due_date"));
}

/// HUNT-215: a `Calendar.sqlitedb` whose `CalendarItem` is present and empty
/// produced no record at all. It now states zero events and zero reminders.
#[test]
fn an_empty_calendar_store_states_zero_events_and_zero_reminders() {
    let out = run(
        &CalendarDbParser,
        "Calendar.sqlitedb",
        make_db(REAL_CALENDAR_DDL),
    );
    let s = of_type(&out, "CalendarSummary");
    assert_eq!(
        s.len(),
        1,
        "no summary for an empty calendar store: {out:?}"
    );
    assert_eq!(s[0].metadata["events"], 0);
    assert_eq!(s[0].metadata["reminders"], 0);
    assert!(s[0].metadata.get("content_incomplete").is_none());
}

/// HUNT-215: the same for `voicemail.db`, on the real table shape. Both
/// voicemail stores on the Magnet 2022 iPhone 8 are this: present and empty.
#[test]
fn an_empty_voicemail_store_states_zero_voicemails() {
    let out = run(
        &VoicemailParser,
        "voicemail.db",
        make_db(REAL_VOICEMAIL_DDL),
    );
    let s = of_type(&out, "VoicemailSummary");
    assert_eq!(
        s.len(),
        1,
        "no summary for an empty voicemail store: {out:?}"
    );
    assert_eq!(s[0].metadata["voicemails"], 0);
    assert!(s[0].metadata.get("content_incomplete").is_none());
}

/// A photo library with two albums in `Album`'s join table, on the iOS 15
/// entity numbering.
fn album_library() -> Vec<u8> {
    make_db(
        "CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
         INSERT INTO Z_PRIMARYKEY VALUES (3, 'Asset', 0, 2);
         INSERT INTO Z_PRIMARYKEY VALUES (26, 'GenericAlbum', 0, 2);
         INSERT INTO Z_PRIMARYKEY VALUES (27, 'Album', 26, 0);
         CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, ZDATECREATED TIMESTAMP, \
           ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZWIDTH INTEGER, ZHEIGHT INTEGER, ZKIND INTEGER, \
           ZFAVORITE INTEGER, ZTRASHEDSTATE INTEGER);
         CREATE TABLE ZADDITIONALASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZASSET INTEGER, ZORIGINALFILENAME VARCHAR);
         INSERT INTO ZASSET VALUES (1, 'IMG_0001.HEIC', 700000000.0, -180.0, -180.0, 100, 100, 0, 0, 0);
         INSERT INTO ZASSET VALUES (2, 'IMG_0002.HEIC', 700000001.0, -180.0, -180.0, 100, 100, 0, 0, 0);
         CREATE TABLE ZGENERICALBUM (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZKIND INTEGER, ZTITLE VARCHAR);
         INSERT INTO ZGENERICALBUM VALUES (1, 27, 2, 'Mine');
         INSERT INTO ZGENERICALBUM VALUES (2, 27, 2, 'Holiday');
         CREATE TABLE Z_27ASSETS (Z_27ALBUMS INTEGER, Z_3ASSETS INTEGER);
         INSERT INTO Z_27ASSETS VALUES (1, 1);
         INSERT INTO Z_27ASSETS VALUES (2, 1);
         INSERT INTO Z_27ASSETS VALUES (2, 2);",
    )
}

fn photos_summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == "PhotosSummary")
        .unwrap_or_else(|| panic!("a Photos summary: {out:?}"))
}

/// HUNT-214: the album-membership rows would not read (one damaged page), the
/// failure was flattened away, and every album said `asset_count: 0` on a
/// summary that said nothing had failed.
#[test]
fn an_album_membership_table_that_will_not_read_is_not_zero_members() {
    let out = run(
        &PhotosParser,
        "Photos.sqlite",
        corrupt_table(album_library(), "Z_27ASSETS"),
    );
    for album in of_type(&out, "PhotoAlbum") {
        assert_eq!(
            album.metadata.get("asset_count"),
            None,
            "a count the membership query never produced: {:?}",
            album.metadata
        );
        assert_eq!(album.metadata["asset_count_unresolved"], true);
    }
    let s = &photos_summary(&out).metadata;
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    let failures = s["lookup_failures"].to_string();
    assert!(failures.contains("Z_27ASSETS"), "{failures}");
}

/// HUNT-214: `Z_PRIMARYKEY` would not read, so no entity numbers, no join
/// table, and the albums' counts were "unresolved" for a reason that blamed
/// the store ("no album-asset join table was found") on a summary that said
/// nothing had failed.
#[test]
fn a_core_data_entity_table_that_will_not_read_is_stated_on_the_summary() {
    let out = run(
        &PhotosParser,
        "Photos.sqlite",
        corrupt_table(album_library(), "Z_PRIMARYKEY"),
    );
    let s = &photos_summary(&out).metadata;
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("Z_PRIMARYKEY"),
        "{s:?}"
    );
}

/// HUNT-214: the album table itself would not read, and the summary said
/// `albums: 0` as though the library had none.
#[test]
fn an_album_table_that_will_not_read_is_not_zero_albums() {
    let out = run(
        &PhotosParser,
        "Photos.sqlite",
        corrupt_table(album_library(), "ZGENERICALBUM"),
    );
    let s = &photos_summary(&out).metadata;
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("ZGENERICALBUM"),
        "{s:?}"
    );
}

/// The control for all three: a library whose lookups all read carries no
/// failure and the counts it found.
#[test]
fn a_sound_album_library_carries_no_lookup_failure() {
    let out = run(&PhotosParser, "Photos.sqlite", album_library());
    let s = &photos_summary(&out).metadata;
    assert!(s.get("content_incomplete").is_none(), "{s:?}");
    assert!(s.get("lookup_failures").is_none(), "{s:?}");
    assert_eq!(s["albums"], 2);
    assert_eq!(s["album_memberships"], 3);
}

/// A NoteStore on the iOS 15 entity numbering (ICAccount 5, ICFolder 9,
/// ICNote 11, as the Magnet 2022 iPhone 8's `Z_PRIMARYKEY` has them): one
/// account, one ordinary folder, one Recently Deleted folder and a note in
/// each folder. `folder_title` and `account_ident` are the trash folder's
/// `ZTITLE2` and the account's `ZIDENTIFIER`, so a test can make either long
/// enough to spill onto overflow pages.
fn notestore_with_folders(folder_title: &str, account_ident: &str) -> Vec<u8> {
    make_db(&format!(
        "PRAGMA page_size = 4096;
         CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
         INSERT INTO Z_PRIMARYKEY VALUES (5, 'ICAccount', 0, 1);
         INSERT INTO Z_PRIMARYKEY VALUES (9, 'ICFolder', 0, 3);
         INSERT INTO Z_PRIMARYKEY VALUES (11, 'ICNote', 0, 5);
         CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, \
           ZMARKEDFORDELETION INTEGER, ZFOLDERTYPE INTEGER, ZACCOUNT4 INTEGER, ZACCOUNT5 INTEGER, \
           ZFOLDER INTEGER, ZCREATIONDATE TIMESTAMP, ZMODIFICATIONDATE TIMESTAMP, \
           ZSNIPPET VARCHAR, ZTITLE1 VARCHAR, ZIDENTIFIER VARCHAR, ZTITLE2 VARCHAR);
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZIDENTIFIER) VALUES (1, 5, '{account_ident}');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZFOLDERTYPE, ZACCOUNT5, ZIDENTIFIER, ZTITLE2) \
           VALUES (2, 9, 0, 1, 'F-NOTES', 'Notes');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZFOLDERTYPE, ZACCOUNT5, ZIDENTIFIER, ZTITLE2) \
           VALUES (3, 9, 1, 1, 'F-TRASH', '{folder_title}');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZACCOUNT4, ZFOLDER, \
           ZCREATIONDATE, ZMODIFICATIONDATE, ZSNIPPET, ZTITLE1, ZIDENTIFIER) \
           VALUES (4, 11, 0, 1, 2, 700000000.0, 700000100.0, 'milk', 'Groceries', 'N-1');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZACCOUNT4, ZFOLDER, \
           ZCREATIONDATE, ZMODIFICATIONDATE, ZSNIPPET, ZTITLE1, ZIDENTIFIER) \
           VALUES (5, 11, 0, 1, 3, 700000000.0, 700000200.0, 'meet at 6', 'Plan', 'N-2');"
    ))
}

/// Break the overflow chain of the value filled with `fill`: its first
/// overflow page is made to claim it is the last, so SQLite reports the
/// record corrupt when — and only when — a statement reads that column. The
/// shape a damaged page gives a real store: one lookup fails, the rest read.
fn break_overflow_chain(mut bytes: Vec<u8>, fill: u8) -> Vec<u8> {
    const PAGE: usize = 4096;
    let first = (0..bytes.len() / PAGE)
        .map(|p| p * PAGE)
        .find(|&at| {
            bytes[at + 4..at + 64].iter().all(|&b| b == fill) && bytes[at..at + 4] != [0, 0, 0, 0]
        })
        .expect("an overflow page of the long value, with a successor");
    bytes[first..first + 4].copy_from_slice(&[0, 0, 0, 0]);
    bytes
}

fn notes_summary(out: &[Artifact]) -> &serde_json::Value {
    &out.iter()
        .find(|a| a.metadata["type"] == "NotesSummary")
        .unwrap_or_else(|| panic!("a Notes summary: {out:?}"))
        .metadata
}

/// HUNT-232: the folder query failed (a damaged page under the Recently
/// Deleted folder's row), `if let Ok` / `.flatten()` swallowed it, and the
/// note in that folder was published `deleted: false`, with no folder and
/// nothing to say the folder had not been looked up.
#[test]
fn a_folder_query_that_will_not_read_is_stated_not_passed_off_as_no_folder() {
    let long = "Q".repeat(12_000);
    let db = break_overflow_chain(notestore_with_folders(&long, "LocalAccount"), b'Q');
    let out = run(&NotesParser, "NoteStore.sqlite", db);
    let notes = of_type(&out, "Note");
    assert_eq!(notes.len(), 2, "the notes themselves still read: {out:?}");
    // The folder read before the damaged row is real and still resolves.
    let groceries = notes
        .iter()
        .find(|n| n.metadata["title"] == "Groceries")
        .unwrap();
    assert_eq!(groceries.metadata["folder"], "Notes");
    assert_eq!(groceries.metadata["deleted"], false);
    assert!(groceries.metadata.get("folder_unresolved").is_none());
    // The note in the folder the failure cut off is not "not deleted".
    let plan = notes
        .iter()
        .find(|n| n.metadata["title"] == "Plan")
        .unwrap();
    assert_eq!(
        plan.metadata["folder_unresolved"], true,
        "{:?}",
        plan.metadata
    );
    assert_eq!(
        plan.metadata.get("in_recently_deleted"),
        Some(&serde_json::Value::Null),
        "a trash membership nobody could look up: {:?}",
        plan.metadata
    );
    assert_eq!(plan.metadata.get("deleted"), Some(&serde_json::Value::Null));
    let s = notes_summary(&out);
    assert_eq!(s["deleted_notes_unresolved"], 1);
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("folders"),
        "{s:?}"
    );
}

/// HUNT-232: the account query failed and every note lost its account with
/// no marker.
#[test]
fn an_account_query_that_will_not_read_is_stated_not_passed_off_as_no_account() {
    let long = "R".repeat(12_000);
    let db = break_overflow_chain(notestore_with_folders("Recently Deleted", &long), b'R');
    let out = run(&NotesParser, "NoteStore.sqlite", db);
    let notes = of_type(&out, "Note");
    assert_eq!(notes.len(), 2, "{out:?}");
    for note in &notes {
        assert_eq!(
            note.metadata["account_unresolved"], true,
            "{:?}",
            note.metadata
        );
    }
    let s = notes_summary(&out);
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("accounts"),
        "{s:?}"
    );
}

/// The control: the same store, sound, resolves both and states no failure.
#[test]
fn a_sound_notestore_resolves_folder_and_account_with_no_lookup_failure() {
    let out = run(
        &NotesParser,
        "NoteStore.sqlite",
        notestore_with_folders("Recently Deleted", "LocalAccount"),
    );
    let plan = of_type(&out, "Note")
        .into_iter()
        .find(|n| n.metadata["title"] == "Plan")
        .expect("the note in the trash");
    assert_eq!(plan.metadata["folder"], "Recently Deleted");
    assert_eq!(plan.metadata["in_recently_deleted"], true);
    assert_eq!(plan.metadata["account"], "LocalAccount");
    let s = notes_summary(&out);
    assert!(s.get("lookup_failures").is_none(), "{s:?}");
    assert!(s.get("content_incomplete").is_none(), "{s:?}");
    assert_eq!(s["deleted_notes"], 1);
}

/// HUNT-233: the real iOS 15 `voicemail.db` (the Magnet 2022 iPhone 8's
/// top-level store) carries a `deleted` table with the `voicemail` table's
/// twelve columns, which the parser never read. Its rows are read, labelled
/// by the table they came from, and — no device held has a row in it — said
/// to be unvalidated.
#[test]
fn rows_of_the_voicemail_deleted_table_are_read_and_labelled_unvalidated() {
    let db = make_db(&format!(
        "{REAL_VOICEMAIL_DDL}
         INSERT INTO deleted (remote_uid, date, sender, callback_num, duration, trashed_date, \
           flags, receiver) VALUES (41, 1641830000, '+15555550100', '+15555550100', 12, 0, 0, \
           '+15555550199');"
    ));
    let out = run(&VoicemailParser, "voicemail.db", db);
    let from_deleted: Vec<_> = of_type(&out, "Voicemail")
        .into_iter()
        .filter(|v| v.metadata["source_table"] == "deleted")
        .collect();
    assert_eq!(from_deleted.len(), 1, "{out:?}");
    let v = &from_deleted[0].metadata;
    assert_eq!(v["sender"], "+15555550100");
    assert_eq!(v["date"], 1641830000);
    assert_eq!(v["duration_seconds"], 12);
    assert_eq!(v["row_semantics_validated"], false);
    let s = &of_type(&out, "VoicemailSummary")[0].metadata;
    assert_eq!(s["voicemails"], 0);
    assert_eq!(s["deleted_table_rows"], 1);
    assert_eq!(s["deleted_table_semantics_validated"], false);
}

/// A store with no `deleted` table (the per-account store beside it on the
/// same device) says the table is absent, not that it held nothing.
#[test]
fn a_voicemail_store_without_a_deleted_table_says_so() {
    let db = make_db(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, \
           remote_uid INTEGER, date INTEGER, token TEXT, sender TEXT, callback_num TEXT, \
           duration INTEGER, expiration INTEGER, trashed_date INTEGER, flags INTEGER, \
           receiver TEXT, label TEXT);",
    );
    let out = run(&VoicemailParser, "voicemail.db", db);
    let s = &of_type(&out, "VoicemailSummary")[0].metadata;
    assert_eq!(s["deleted_table_present"], false);
    assert!(s.get("deleted_table_rows").is_none());
}

/// HUNT-236. Both deleted censuses are answered from the partial index the
/// real iOS 15 `healthdb_secure.sqlite` carries (`CREATE INDEX objects_deleted
/// ON objects (type) WHERE (objects.type = 2)`, and `EXPLAIN QUERY PLAN` on
/// the Magnet 2022 store shows both censuses searching it), while the sample
/// walk reaches `objects` by its primary key. A damaged index page fails the
/// censuses and not the walk: `deleted_samples` then fell back to the walked
/// count with nothing to say so, and `deleted_objects` vanished.
#[test]
fn a_deleted_census_that_will_not_run_is_flagged_not_passed_off_as_whole_table() {
    let db = make_db(
        "CREATE TABLE samples (data_id INTEGER PRIMARY KEY, start_date REAL, end_date REAL, data_type INTEGER);
         CREATE TABLE objects (data_id INTEGER PRIMARY KEY AUTOINCREMENT, uuid BLOB UNIQUE, \
           provenance INTEGER NOT NULL, type INTEGER, creation_date REAL);
         CREATE INDEX objects_deleted ON objects (type) WHERE (objects.type = 2);
         CREATE TABLE data_provenances (ROWID INTEGER PRIMARY KEY, origin_product_type TEXT, origin_build TEXT, \
           source_version TEXT, tz_name TEXT, source_id INTEGER, device_id INTEGER, local_product_type TEXT, local_build TEXT);
         CREATE TABLE quantity_samples (data_id INTEGER PRIMARY KEY, quantity REAL, original_quantity REAL, original_unit INTEGER);
         CREATE TABLE category_samples (data_id INTEGER PRIMARY KEY, value INTEGER);
         CREATE TABLE unit_strings (ROWID INTEGER PRIMARY KEY, unit_string TEXT);
         INSERT INTO samples VALUES (1, 600000000.0, 600000001.0, 7);
         INSERT INTO samples VALUES (2, 600000002.0, 600000003.0, 7);
         INSERT INTO objects VALUES (1, X'01', 0, 1, 600000000.0);
         INSERT INTO objects VALUES (2, X'02', 0, 2, 600000002.0);
         INSERT INTO objects VALUES (3, X'03', 0, 2, 600000004.0);",
    );
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        corrupt_table(db, "objects_deleted"),
    );
    let s = &out
        .iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .unwrap_or_else(|| panic!("summary: {out:?}"))
        .metadata;
    assert_eq!(s["samples"], 2, "the walk still reads: {s:?}");
    // The walked count is published, and said to be the walked count.
    assert_eq!(s["deleted_samples"], 1);
    assert_eq!(s["deleted_samples_basis"], "walked_samples", "{s:?}");
    assert!(s["deleted_samples_census_error"].is_string(), "{s:?}");
    assert_eq!(s["deleted_samples_is_lower_bound"], false);
    // The object census has no stand-in: absent, and said to be.
    assert!(s.get("deleted_objects").is_none());
    assert!(s["deleted_objects_census_error"].is_string(), "{s:?}");
}

/// The control: on a sound store both counts are over the whole table.
#[test]
fn a_sound_health_store_counts_deleted_over_the_whole_table() {
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", health_db(""));
    let s = &out
        .iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .unwrap()
        .metadata;
    assert_eq!(s["deleted_samples_basis"], "whole_table");
    assert!(s.get("deleted_samples_census_error").is_none());
}

/// Damage the right-most leaf of `index`'s b-tree, so a scan in index order
/// reads every leaf before it and then fails — the shape of a damaged page
/// part-way through a real index, not one that fails before the first row.
fn corrupt_last_index_leaf(bytes: Vec<u8>, index: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_ios_leaf_{}.db", Uuid::new_v4()));
    std::fs::write(&path, &bytes).unwrap();
    let (root, page_size): (usize, usize) = {
        let c = Connection::open(&path).unwrap();
        let root: i64 = c
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = ?1",
                [index],
                |r| r.get(0),
            )
            .unwrap();
        let ps: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        (root as usize, ps as usize)
    };
    let _ = std::fs::remove_file(&path);
    let mut bytes = bytes;
    let mut page = root;
    // 0x02 is an index interior page; its right-most child follows the
    // eight-byte header prefix.
    assert_eq!(bytes[(page - 1) * page_size], 0x02, "the index spans pages");
    while bytes[(page - 1) * page_size] == 0x02 {
        let at = (page - 1) * page_size + 8;
        page = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    }
    assert_eq!(bytes[(page - 1) * page_size], 0x0a, "an index leaf");
    bytes[(page - 1) * page_size] = 0x01;
    bytes
}

/// A `healthdb_secure.sqlite` with the real iOS 15 `samples` indexes and
/// enough samples, over five data types, that `samples_type_anchor` — which
/// `EXPLAIN QUERY PLAN` on the Magnet 2022 store shows the histogram scanning
/// as a covering index — spans several leaves.
fn health_db_with_real_sample_indexes() -> Vec<u8> {
    make_db(
        "CREATE TABLE samples (data_id INTEGER PRIMARY KEY, start_date REAL, end_date REAL, data_type INTEGER);
         CREATE INDEX samples_type_dates ON samples (data_type, start_date, end_date);
         CREATE INDEX samples_type_end ON samples (data_type, end_date);
         CREATE INDEX samples_type_anchor ON samples (data_type, data_id);
         CREATE TABLE objects (data_id INTEGER PRIMARY KEY AUTOINCREMENT, uuid BLOB UNIQUE, \
           provenance INTEGER NOT NULL, type INTEGER, creation_date REAL);
         CREATE TABLE data_provenances (ROWID INTEGER PRIMARY KEY, origin_product_type TEXT, origin_build TEXT, \
           source_version TEXT, tz_name TEXT, source_id INTEGER, device_id INTEGER, local_product_type TEXT, local_build TEXT);
         CREATE TABLE quantity_samples (data_id INTEGER PRIMARY KEY, quantity REAL, original_quantity REAL, original_unit INTEGER);
         CREATE TABLE category_samples (data_id INTEGER PRIMARY KEY, value INTEGER);
         CREATE TABLE unit_strings (ROWID INTEGER PRIMARY KEY, unit_string TEXT);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
           INSERT INTO samples SELECT i, 600000000.0 + i, 600000001.0 + i, 5 + (i - 1) / 600 FROM n;
         INSERT INTO objects SELECT data_id, randomblob(16), 0, 1, start_date FROM samples;",
    )
}

fn health_summary_of(out: &[Artifact]) -> &serde_json::Value {
    &out.iter()
        .find(|a| a.metadata["type"] == "HealthKitSummary")
        .unwrap_or_else(|| panic!("a HealthKit summary: {out:?}"))
        .metadata
}

/// HUNT-237: the data-type histogram was read with `iter.flatten()`, so a
/// row that failed part-way through the census ended it early and the
/// summary still said `data_type_histogram_status: counted` over a histogram
/// short of the table's.
#[test]
fn a_histogram_census_that_fails_part_way_keeps_its_rows_and_says_it_is_partial() {
    let db = corrupt_last_index_leaf(health_db_with_real_sample_indexes(), "samples_type_anchor");
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", db);
    let s = health_summary_of(&out);
    assert_ne!(s["data_type_histogram_status"], "counted", "{s:?}");
    assert_eq!(s["data_type_histogram_status"], "partial", "{s:?}");
    // The rows before the damaged leaf are real and kept.
    let histogram = s["data_type_histogram"].as_object().expect("histogram");
    assert_eq!(histogram.get("5"), Some(&json!(600)), "{s:?}");
    assert!(histogram.get("9").is_none(), "{s:?}");
    assert!(s["data_type_histogram_query_error"].is_string(), "{s:?}");
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"]
            .to_string()
            .contains("data_type_histogram"),
        "{s:?}"
    );
    // On the real store `count(*)` scans the same index, so the row count
    // fails with it: said, not silently left out.
    assert!(s.get("sample_rows").is_none(), "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("sample_rows"),
        "{s:?}"
    );
}

/// HUNT-240: the sample walk sorts, so a failure mid-scan loses every row;
/// the summary said "HealthKit: 0 sample(s)" as if the store were empty.
#[test]
fn a_sample_walk_that_fails_is_named_as_failed_not_as_an_empty_store() {
    let db = corrupt_last_index_leaf(health_db_with_real_sample_indexes(), "samples_type_anchor");
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", db);
    let s = health_summary_of(&out);
    let name = s["name"].as_str().expect("name");
    assert!(
        name.contains("sample walk failed"),
        "a failed walk must not read as an empty store: {name}"
    );
    assert_eq!(s["samples_walk_failed"], true, "{s:?}");
    assert!(
        s["inventory_incomplete_detail"]
            .as_str()
            .is_some_and(|d| d.contains("sample walk")),
        "{s:?}"
    );
}

/// The control: the same store, sound, is counted whole with no failure.
#[test]
fn a_sound_histogram_census_is_counted_whole() {
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        health_db_with_real_sample_indexes(),
    );
    let s = health_summary_of(&out);
    assert_eq!(s["data_type_histogram_status"], "counted");
    assert_eq!(s["data_type_histogram"].as_object().unwrap().len(), 5);
    assert_eq!(s["data_type_histogram"]["9"], 600);
    assert_eq!(s["sample_rows"], 3000);
    assert!(s.get("lookup_failures").is_none(), "{s:?}");
    assert!(s.get("content_incomplete").is_none(), "{s:?}");
}

/// HUNT-238: `table_count` answered `None` both for a table that is not
/// there and for one whose count would not read, and the summary published
/// the second as `workout_rows_table_absent: true` — and named it "workouts
/// table absent" — so a damaged table read as an absent one.
#[test]
fn a_table_count_that_fails_is_stated_not_passed_off_as_an_absent_table() {
    let db = health_db(
        "CREATE TABLE workouts (data_id INTEGER PRIMARY KEY, duration REAL, total_energy_burned REAL, \
           total_basal_energy_burned REAL, total_distance REAL, activity_type INTEGER, goal_type INTEGER, \
           goal REAL, total_w_steps REAL, total_flights_climbed REAL, condenser_version INTEGER, condenser_date REAL);
         INSERT INTO workouts (data_id, duration, activity_type) VALUES (1, 1800.0, 37);",
    );
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        corrupt_table(db, "workouts"),
    );
    let s = health_summary_of(&out);
    assert!(s.get("workout_rows_table_absent").is_none(), "{s:?}");
    assert!(s.get("workout_rows").is_none(), "{s:?}");
    let name = s["name"].as_str().unwrap();
    assert!(!name.contains("workouts table absent"), "{name}");
    assert!(name.contains("workouts not counted"), "{name}");
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    assert!(
        s["lookup_failures"].to_string().contains("workout_rows"),
        "{s:?}"
    );
    // A table that is genuinely absent still says so.
    assert_eq!(s["ecg_sample_rows_table_absent"], true, "{s:?}");
}

/// `BrowserState.db` with the real iOS 15 `tabs` and `browser_windows`
/// tables (the Magnet 2022 iPhone 8's), one tab in one of two windows.
fn browser_state_with_real_windows() -> Vec<u8> {
    make_db(
        "CREATE TABLE tabs (id INTEGER PRIMARY KEY, uuid TEXT, title TEXT, url TEXT, \
           user_visible_url TEXT, order_index INTEGER, last_viewed_time REAL, \
           private_browsing INTEGER, opened_from_link INTEGER, showing_reader INTEGER, \
           browser_window_uuid TEXT, browser_window_id INTEGER, readinglist_bookmark_id INTEGER);
         INSERT INTO tabs VALUES (1, 'T-1', 'A tab', 'https://example.test/', NULL, 0, 700000000.0, 0, 0, 0, 'W-1', 1, 0);
         CREATE TABLE browser_windows (id INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT NOT NULL,\
           type INTEGER DEFAULT 0,active_document_index INTEGER DEFAULT 0,\
           active_private_document_index INTEGER DEFAULT 0,active_document_is_valid BOOL DEFAULT 1,\
           tab_state_successfully_loaded BOOL DEFAULT 0,legacy_plist_file_version INTEGER DEFAULT 0,\
           scene_ID TEXT,CONSTRAINT uuid_type_index UNIQUE(uuid, type));
         INSERT INTO browser_windows (uuid, type) VALUES ('W-1', 0);
         INSERT INTO browser_windows (uuid, type) VALUES ('W-2', 0);",
    )
}

fn safari_tabs_summary(out: &[Artifact]) -> &serde_json::Value {
    &out.iter()
        .find(|a| a.metadata["type"] == "SafariTabsSummary")
        .unwrap_or_else(|| panic!("a Safari tabs summary: {out:?}"))
        .metadata
}

/// HUNT-238, the same shape in Safari: `table_count(..).unwrap_or(0)` said
/// "0 window(s)" both for a `browser_windows` table whose count would not
/// read (on the real store `count(*)` scans its unique-constraint index) and
/// for one that is not there.
#[test]
fn a_window_count_that_fails_is_stated_not_published_as_zero_windows() {
    let db = corrupt_table(
        browser_state_with_real_windows(),
        "sqlite_autoindex_browser_windows_1",
    );
    let out = run(&SafariTabsParser, "BrowserState.db", db);
    let s = safari_tabs_summary(&out);
    assert_eq!(s["tabs"], 1, "the tabs still read: {s:?}");
    assert!(s.get("windows").is_none(), "{s:?}");
    assert!(s["windows_count_error"].is_string(), "{s:?}");
    assert_eq!(s["content_incomplete"], true, "{s:?}");
    let name = s["name"].as_str().unwrap();
    assert!(!name.contains("0 window"), "{name}");
    assert!(name.contains("windows not counted"), "{name}");
}

#[test]
fn a_sound_window_table_is_counted() {
    let out = run(
        &SafariTabsParser,
        "BrowserState.db",
        browser_state_with_real_windows(),
    );
    let s = safari_tabs_summary(&out);
    assert_eq!(s["windows"], 2, "{s:?}");
    assert!(s.get("content_incomplete").is_none(), "{s:?}");
}
