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
    let path = std::env::temp_dir().join(format!("seance_wintl_test_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(ddl).unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    ActivitiesCacheParser.process(&art).unwrap()
}

/// The canonical Timeline schema (superset the parser probes). Callers append
/// their own INSERTs.
const SCHEMA: &str = "\
    CREATE TABLE Activity (\
        Id TEXT, AppId TEXT, ActivityType INTEGER, ActivityStatus INTEGER, \
        [Group] TEXT, Payload BLOB, ClipboardPayload BLOB, StartTime INTEGER, \
        EndTime INTEGER, LastModifiedTime INTEGER, ExpirationTime INTEGER, \
        LastModifiedOnClient INTEGER, CreatedInCloud INTEGER, IsLocalOnly INTEGER, \
        PlatformDeviceId TEXT);\
    CREATE TABLE Activity_PackageId (\
        ActivityId TEXT, Platform TEXT, PackageName TEXT, ExpirationTime INTEGER);";

fn records(arts: &[Artifact]) -> Vec<&Artifact> {
    arts.iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect()
}

fn timeline_events(arts: &[Artifact]) -> Vec<&Artifact> {
    arts.iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect()
}

#[test]
fn parses_focus_activity_with_join() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, AppId, ActivityType, ActivityStatus, Payload, StartTime, EndTime, LastModifiedTime, IsLocalOnly, PlatformDeviceId) VALUES (\
           'guid-focus-1', \
           {appid}, \
           6, 1, {payload}, 1546300800, 1546300845, 1546300900, 1, 'device-A');\
         INSERT INTO Activity_PackageId (ActivityId, Platform, PackageName) VALUES \
           ('guid-focus-1', 'windows_win32', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE');",
        appid = r#"'[{"application":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","platform":"windows_win32"}]'"#,
        payload = r#"'{"displayText":"pshashes.txt","appDisplayName":"Microsoft Word","description":"C:\\Users\\bob\\Desktop","contentUri":"file:///C:/Users/bob/Desktop/pshashes.txt","activeDurationSeconds":40,"userTimezone":"America/New_York"}'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let recs = records(&arts);
    assert_eq!(recs.len(), 1);
    let m = &recs[0].metadata;

    assert_eq!(m["type"], "WindowsTimelineActivity");
    assert_eq!(m["subtype"], "windows_timeline_activity");
    assert_eq!(m["platform"], "Windows");
    assert_eq!(m["source_table"], "Activity");
    assert_eq!(m["activity_id"], "guid-focus-1");
    assert_eq!(
        m["executable"],
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    );
    assert_eq!(m["app_display_name"], "Microsoft Word");
    assert_eq!(m["activity_type"].as_i64(), Some(6));
    assert_eq!(m["activity_type_label"], "App in focus");
    assert_eq!(m["display_text"], "pshashes.txt");
    assert_eq!(
        m["content_uri"],
        "file:///C:/Users/bob/Desktop/pshashes.txt"
    );
    assert_eq!(m["date"].as_i64(), Some(1546300800));
    assert_eq!(m["start_time"].as_i64(), Some(1546300800));
    assert!(m["start_time_iso"]
        .as_str()
        .unwrap()
        .starts_with("2019-01-01"));
    assert_eq!(m["end_time"].as_i64(), Some(1546300845));
    assert_eq!(m["duration_seconds"].as_i64(), Some(45));
    assert_eq!(m["active_duration_seconds"].as_i64(), Some(40));
    assert_eq!(m["user_timezone"], "America/New_York");
    assert_eq!(m["payload_binary"], false);
    assert_eq!(m["is_local_only"].as_i64(), Some(1));
    assert_eq!(m["name"], "pshashes.txt");
    assert_eq!(m["short_desc"], "Microsoft Word — pshashes.txt (focus 40s)");

    // Activity_PackageId cross-reference.
    let pkgs = m["packages"].as_array().unwrap();
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0]["platform"], "windows_win32");

    // Exactly one TimelineEvent keyed on StartTime.
    let evs = timeline_events(&arts);
    assert_eq!(evs.len(), 1);
    let ev = &evs[0].metadata;
    assert_eq!(ev["timestamp"].as_i64(), Some(1546300800));
    assert_eq!(ev["timestamp_desc"], "Windows Timeline Activity");
    assert_eq!(ev["source_module"], "plugin.windows.timeline_activity");
    assert_eq!(ev["filename"], "file:///C:/Users/bob/Desktop/pshashes.txt");
    // full_details is a STRINGIFIED JSON object.
    let fd: Value = serde_json::from_str(ev["full_details"].as_str().unwrap()).unwrap();
    assert_eq!(fd["activity_type_label"], "App in focus");
    assert_eq!(fd["duration_seconds"].as_i64(), Some(45));
    assert_eq!(fd["display_text"], "pshashes.txt");
}

#[test]
fn decodes_clipboard_text() {
    // "aHVudGVyMg==" is base64 for "hunter2".
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, Payload, ClipboardPayload, StartTime) VALUES (\
           'guid-clip-1', 10, {payload}, {clip}, 1546300800);",
        payload = r#"'{"displayText":"(copied text)"}'"#,
        clip = r#"'[{"content":"aHVudGVyMg==","format":"Text"}]'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let recs = records(&arts);
    assert_eq!(recs.len(), 1);
    let m = &recs[0].metadata;
    assert_eq!(m["activity_type_label"], "Clipboard");
    assert_eq!(m["has_clipboard"], true);
    assert_eq!(m["clipboard_text"], "hunter2");
    assert_eq!(m["clipboard_format"], "Text");

    // Clipboard text rides in the TimelineEvent full_details.
    let evs = timeline_events(&arts);
    assert_eq!(evs.len(), 1);
    let fd: Value =
        serde_json::from_str(evs[0].metadata["full_details"].as_str().unwrap()).unwrap();
    assert_eq!(fd["clipboard_text"], "hunter2");
}

#[test]
fn non_text_clipboard_records_bytes_not_text() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, ClipboardPayload, StartTime) VALUES (\
           'guid-clip-2', 16, {clip}, 1546300800);",
        clip = r#"'[{"content":"aHVudGVyMg==","format":"Bitmap"}]'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(m["has_clipboard"], false);
    assert_eq!(m.get("clipboard_text"), None);
    assert_eq!(m["clipboard_format"], "Bitmap");
    assert!(m["clipboard_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn resolves_known_folder_guid_prefix() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, AppId, ActivityType, StartTime) VALUES (\
           'guid-kf-1', {appid}, 5, 1546300800);",
        appid = r#"'[{"application":"{6D809377-6AF0-444B-8957-A3773F02200E}\\Microsoft Office\\WINWORD.EXE","platform":"x_exe_path"}]'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(
        m["executable"],
        "%ProgramFiles%\\Microsoft Office\\WINWORD.EXE"
    );
    assert_eq!(m["activity_type_label"], "Open app / file / webpage");
}

#[test]
fn unknown_guid_prefix_left_verbatim() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, AppId, ActivityType, StartTime) VALUES (\
           'guid-kf-2', {appid}, 5, 1546300800);",
        appid = r#"'[{"application":"{00000000-0000-0000-0000-000000000000}\\some.exe","platform":"x_exe_path"}]'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(
        m["executable"],
        "{00000000-0000-0000-0000-000000000000}\\some.exe"
    );
}

#[test]
fn parses_activity_operation_table() {
    let ddl = format!(
        "{SCHEMA}\
         ALTER TABLE Activity RENAME TO Activity_orig;\
         CREATE TABLE Activity (\
            Id TEXT, AppId TEXT, ActivityType INTEGER, Payload BLOB, StartTime INTEGER);\
         CREATE TABLE ActivityOperation (\
            Id TEXT, AppId TEXT, ActivityType INTEGER, Payload BLOB, StartTime INTEGER, \
            OperationType INTEGER, OperationOrder INTEGER);\
         INSERT INTO ActivityOperation (Id, ActivityType, Payload, StartTime, OperationType, OperationOrder) VALUES (\
           'guid-op-1', 5, {payload}, 1546300800, 3, 7);",
        payload = r#"'{"displayText":"pending.docx"}'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let recs = records(&arts);
    assert_eq!(recs.len(), 1);
    let m = &recs[0].metadata;
    assert_eq!(m["source_table"], "ActivityOperation");
    assert_eq!(m["operation_type"].as_i64(), Some(3));
    assert_eq!(m["operation_order"].as_i64(), Some(7));
    assert_eq!(m["display_text"], "pending.docx");
}

#[test]
fn binary_payload_flagged_not_fabricated() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, Payload, StartTime) VALUES (\
           'guid-bin-1', 5, {payload}, 1546300800);",
        payload = r#"'not-json-at-all'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(m["payload_binary"], true);
    assert_eq!(m.get("display_text"), None);
    assert_eq!(m.get("content_uri"), None);
}

#[test]
fn zero_timestamps_omitted_and_no_timeline_event() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, Payload, StartTime, EndTime, LastModifiedTime) VALUES (\
           'guid-zero-1', 5, {payload}, 0, 0, 0);",
        payload = r#"'{"displayText":"x.txt"}'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let recs = records(&arts);
    // The record still emits (fail-closed omission of times, not the row).
    assert_eq!(recs.len(), 1);
    let m = &recs[0].metadata;
    assert_eq!(m.get("start_time"), None);
    assert_eq!(m.get("date"), None);
    assert_eq!(m.get("end_time"), None);
    assert_eq!(m.get("last_modified_time"), None);
    // No fabricated 1970 epoch anywhere.
    assert!(m.get("start_time_iso").is_none());
    // No TimelineEvent without a valid StartTime.
    assert_eq!(timeline_events(&arts).len(), 0);
}

#[test]
fn end_before_start_never_panics_no_negative_duration() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, Payload, StartTime, EndTime) VALUES (\
           'guid-rev-1', 5, {payload}, 1546300845, 1546300800);",
        payload = r#"'{"displayText":"x.txt"}'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(m["start_time"].as_i64(), Some(1546300845));
    assert_eq!(m["end_time"].as_i64(), Some(1546300800));
    // end < start yields no duration rather than a negative one.
    assert_eq!(m.get("duration_seconds"), None);
}

#[test]
fn degrades_when_optional_columns_missing() {
    // A build variant lacking ClipboardPayload / CreatedInCloud must still parse.
    let ddl = format!(
        "CREATE TABLE Activity (\
            Id TEXT, AppId TEXT, ActivityType INTEGER, Payload BLOB, StartTime INTEGER, \
            EndTime INTEGER);\
         CREATE TABLE Activity_PackageId (ActivityId TEXT, Platform TEXT, PackageName TEXT);\
         INSERT INTO Activity (Id, ActivityType, Payload, StartTime, EndTime) VALUES (\
           'guid-min-1', 6, {payload}, 1546300800, 1546300860);",
        payload = r#"'{"displayText":"minimal.txt","appDisplayName":"App"}'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let recs = records(&arts);
    assert_eq!(recs.len(), 1);
    let m = &recs[0].metadata;
    assert_eq!(m["display_text"], "minimal.txt");
    assert_eq!(m["duration_seconds"].as_i64(), Some(60));
    assert_eq!(m.get("clipboard_text"), None);
    assert_eq!(m.get("created_in_cloud"), None);
}

#[test]
fn wrong_schema_named_activitiescache_is_rejected() {
    // A SQLite DB named activitiescache.db but with an unrelated schema.
    let db =
        make_db("CREATE TABLE notes (id INTEGER, body TEXT); INSERT INTO notes VALUES (1,'x');");
    assert!(run("ActivitiesCache.db", db).is_empty());
}

#[test]
fn missing_package_table_is_rejected() {
    // Activity present but Activity_PackageId absent → not a Timeline cache.
    let db = make_db(
        "CREATE TABLE Activity (Id TEXT, ActivityType INTEGER, Payload BLOB, StartTime INTEGER);\
         INSERT INTO Activity VALUES ('a', 5, '{}', 1546300800);",
    );
    assert!(run("ActivitiesCache.db", db).is_empty());
}

#[test]
fn non_sqlite_and_wrong_name_skipped() {
    // Not SQLite at all.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello world".to_vec()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "ActivitiesCache.db" }),
    );
    assert!(ActivitiesCacheParser.process(&art).unwrap().is_empty());

    // Right content, wrong basename → pre-filter skip.
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES ('a', 5, 1546300800);"
    );
    assert!(run("something_else.db", make_db(&ddl)).is_empty());
}

#[test]
fn directory_entry_skipped() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(Vec::new()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "ActivitiesCache.db", "is_directory": true }),
    );
    assert!(ActivitiesCacheParser.process(&art).unwrap().is_empty());
}

#[test]
fn blob_guid_id_formatted_dotnet_layout() {
    // 16 raw bytes 00..0F render as the .NET Guid string layout. The formatter
    // is now shared with the VSS catalog parser (seance_core::guid).
    let bytes: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    assert_eq!(format_guid(&bytes), "03020100-0504-0706-0809-0a0b0c0d0e0f");
}

#[test]
fn percent_decoded_content_uri() {
    assert_eq!(
        percent_decode("file:///C:/Users/bob/My%20Documents/a%2Bb.txt"),
        "file:///C:/Users/bob/My Documents/a+b.txt"
    );
    // Malformed escape is left intact.
    assert_eq!(percent_decode("100%done"), "100%done");
}

#[test]
fn module_id_stable() {
    assert_eq!(
        ActivitiesCacheParser.id(),
        "plugin.windows.timeline_activity"
    );
    assert_eq!(ActivitiesCacheParser.version(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn activity_type_labels() {
    assert_eq!(activity_type_label(Some(6)), "App in focus");
    assert_eq!(activity_type_label(Some(10)), "Clipboard");
    assert_eq!(activity_type_label(Some(5)), "Open app / file / webpage");
    assert_eq!(activity_type_label(Some(99)), "Type 99");
    assert_eq!(activity_type_label(None), "Unknown");
}

#[test]
fn uncheckpointed_wal_activities_are_parsed() {
    // A live ActivitiesCache keeps its newest rows in an uncheckpointed WAL.
    // Spilling the main database alone silently drops them (BUG-256).
    use seance_core::data_source::SiblingBundleSource;
    use std::collections::HashMap;

    let path = std::env::temp_dir().join(format!("seance_wintl_wal_{}.db", Uuid::new_v4()));
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(&format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
           ('guid-checkpointed', 6, 1546300800);"
    ))
    .unwrap();
    // Everything from here on lives only in the WAL.
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0i64)
        .unwrap();
    conn.execute_batch(
        "INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
           ('guid-in-wal', 6, 1546300900);",
    )
    .unwrap();
    let db_bytes = std::fs::read(&path).unwrap();
    let wal_bytes = std::fs::read(format!("{}-wal", path.display())).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    assert!(!wal_bytes.is_empty(), "the fixture WAL must hold frames");

    let ids = |arts: &[Artifact]| -> Vec<String> {
        records(arts)
            .iter()
            .filter_map(|a| a.metadata.get("activity_id").and_then(|v| v.as_str()))
            .map(str::to_string)
            .collect()
    };

    // Without the sibling only the checkpointed row is visible.
    let without = run("ActivitiesCache.db", db_bytes.clone());
    assert_eq!(ids(&without), vec!["guid-checkpointed".to_string()]);

    // With the `-wal` reachable through the data source, both are parsed.
    let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db_bytes));
    let wal: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(wal_bytes));
    let mut siblings = HashMap::new();
    siblings.insert("-wal".to_string(), wal);
    let bundled: Arc<dyn DataSource> = Arc::new(SiblingBundleSource::new(inner, siblings));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bundled),
        json!({ "name": "ActivitiesCache.db" }),
    );
    let with = ActivitiesCacheParser.process(&art).unwrap();
    let mut got = ids(&with);
    got.sort();
    assert_eq!(
        got,
        vec!["guid-checkpointed".to_string(), "guid-in-wal".to_string()],
        "the uncheckpointed activity must be recovered"
    );
}

/// Real ActivitiesCache.db samples, gated on
/// `SEANCE_WIN_TIMELINE_SAMPLES=/dir/with/ActivitiesCache.db`.
#[test]
fn real_samples() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_WIN_TIMELINE_SAMPLES") else {
        return;
    };
    let dir = dir.display().to_string();
    if let Ok(bytes) = std::fs::read(format!("{dir}/ActivitiesCache.db")) {
        let arts = run("ActivitiesCache.db", bytes);
        let recs = records(&arts);
        assert!(!recs.is_empty(), "expected activities from a real DB");
        // Every emitted timestamp must be a real post-2000 instant.
        for r in &recs {
            if let Some(s) = r.metadata.get("start_time").and_then(|v| v.as_i64()) {
                assert!(s > 946_684_800, "start_time before 2000: {s}");
            }
        }
    }
}

#[test]
fn clipboard_text_over_the_cap_is_marked_truncated_rather_than_shown_as_the_whole_clip() {
    // 10 KiB of text: past the 8 KiB storage cap.
    let long = "A".repeat(10 * 1024);
    let b64 = base64::engine::general_purpose::STANDARD.encode(long.as_bytes());
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, ClipboardPayload, StartTime) VALUES (\
           'guid-clip-long', 10, '[{{\"content\":\"{b64}\",\"format\":\"Text\"}}]', 1546300800);",
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;

    assert_eq!(m["clipboard_text_truncated"], true);
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["content_incomplete_reason"], "clipboard_text_capped");
    assert_eq!(
        m["clipboard_bytes"].as_u64(),
        Some(10 * 1024),
        "the true clipboard length must survive even when the text does not"
    );
    assert_eq!(m["clipboard_text"].as_str().unwrap().len(), 8 * 1024);
}

#[test]
fn clipboard_text_within_the_cap_is_explicitly_marked_complete() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, ClipboardPayload, StartTime) VALUES (\
           'guid-clip-short', 10, {clip}, 1546300800);",
        clip = r#"'[{"content":"aHVudGVyMg==","format":"Text"}]'"#,
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(m["clipboard_text_truncated"], false);
    assert!(m.get("content_incomplete").is_none());
}

/// Same class as the clipboard cap, and worse: the raw `AppId` was cut with a
/// bare `String::truncate`, which PANICS when the cap lands inside a multi-byte
/// character. The orchestrator catches the panic, so one oversized AppId took
/// the whole `ActivitiesCache.db` with it and the machine read as having no
/// Timeline at all. The cut was also silent, so a kept prefix looked like the
/// whole AppId.
///
/// What an examiner learns: the application an activity belongs to, and whether
/// the AppId shown is the whole of it.
#[test]
fn an_oversized_app_id_is_cut_on_a_character_boundary_and_says_it_was_cut() {
    // 65_535 ASCII bytes then a two-byte character, so the 65_536-byte cap
    // falls mid-code-point.
    let huge = format!("{}\u{e9}tail", "a".repeat(APPID_RAW_CAP - 1));
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, AppId, ActivityType, StartTime) VALUES (\
           'guid-appid-huge', '{huge}', 6, 1546300800);"
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    let kept = m["app_id_raw"].as_str().expect("the prefix is kept");
    assert_eq!(kept.len(), APPID_RAW_CAP - 1, "cut back to a char boundary");
    assert_eq!(m["app_id_raw_truncated"], true);
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["content_incomplete_reason"], "app_id_raw_capped");
}

/// The counterpart: an AppId within the cap is explicitly marked whole, or the
/// marker above means nothing.
#[test]
fn an_app_id_within_the_cap_is_explicitly_marked_complete() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, AppId, ActivityType, StartTime) VALUES (\
           'guid-appid-small', 'notepad.exe', 6, 1546300800);"
    );
    let arts = run("ActivitiesCache.db", make_db(&ddl));
    let m = &records(&arts)[0].metadata;
    assert_eq!(m["app_id_raw_truncated"], false);
    assert!(m.get("content_incomplete").is_none());
}
fn run_source(ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "ActivitiesCache.db" }),
    );
    ActivitiesCacheParser.process(&art).unwrap()
}

/// B3-011: the database was staged without comparing what the source returned
/// against what it declared, so a partial ActivitiesCache parsed as a complete
/// activity history. What an examiner learns: whether the activities listed are
/// all of them. A wrong answer reads as "the user never opened that document".
#[test]
fn a_short_read_marks_every_activity_it_produced() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
           ('guid-short', 6, 1546300800);"
    );
    let out = run_source(Arc::new(truncated(make_db(&ddl))));
    let rec = records(&out)
        .into_iter()
        .find(|a| a.metadata.get("activity_id").and_then(|v| v.as_str()) == Some("guid-short"))
        .expect("the readable prefix still parses");
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(rec.metadata["content_incomplete_reason"], "short_read");
    assert!(
        out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                == Some("DatabaseNotStagedInFull")),
        "a partial spill must be reported in its own right, so that a \
         truncation deep enough to yield no rows is not an empty timeline"
    );
}

/// The counterpart: a database staged whole must stay unmarked, or the marker
/// means nothing.
#[test]
fn a_complete_timeline_database_carries_no_incompleteness_marks() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
           ('guid-whole', 6, 1546300800);"
    );
    let out = run("ActivitiesCache.db", make_db(&ddl));
    assert!(!out.is_empty());
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// The magic probe loops over short reads: a chunked source holds a perfectly
/// good database and must not be filed as "not SQLite".
#[test]
fn a_source_that_answers_in_small_chunks_is_still_parsed() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
           ('guid-dribble', 6, 1546300800);"
    );
    let out = run_source(Arc::new(DribbleSource::new(make_db(&ddl), 4)));
    assert!(
        !records(&out).is_empty(),
        "a chunked source is not a non-SQLite file"
    );
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// B4-013: the application-name map is built from `Activity_PackageId`. When
/// that query cannot run, every activity loses its app attribution — and the
/// records used to come back looking like a complete, fully-attributed history.
#[test]
fn an_unreadable_package_map_marks_the_activities_it_weakened() {
    let ddl = "\
        CREATE TABLE Activity (\
            Id TEXT, AppId TEXT, ActivityType INTEGER, ActivityStatus INTEGER, \
            [Group] TEXT, Payload BLOB, ClipboardPayload BLOB, StartTime INTEGER, \
            EndTime INTEGER, LastModifiedTime INTEGER, ExpirationTime INTEGER, \
            LastModifiedOnClient INTEGER, CreatedInCloud INTEGER, IsLocalOnly INTEGER, \
            PlatformDeviceId TEXT);\
        CREATE TABLE Activity_PackageId (ActivityId TEXT);\
        INSERT INTO Activity (Id, ActivityType, StartTime) VALUES \
            ('guid-nopkg', 6, 1546300800);"
        .to_string();
    let out = run("ActivitiesCache.db", make_db(&ddl));

    let rec = records(&out)
        .into_iter()
        .find(|a| a.metadata.get("activity_id").and_then(|v| v.as_str()) == Some("guid-nopkg"))
        .expect("the activity itself still parses");
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(
        rec.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(
        out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str()) == Some("RowsNotDecoded")),
        "a walk that lost rows must say so in its own record"
    );
}

/// B6-015: a Timeline database that matched by name and by SQLite magic but
/// could not be staged or opened must not return an empty activity list.
#[test]
fn an_unusable_database_reports_itself_rather_than_looking_empty() {
    let case = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let a = db_unusable_artifact(
        case,
        parent,
        "ActivitiesCache.db",
        "database could not be staged for reading",
        "disk full",
    );
    assert_eq!(a.metadata["type"], "WindowsTimelineParseStatus");
    assert_eq!(a.metadata["status"], "DatabaseUnreadable");
    assert_eq!(a.metadata["content_incomplete"], true);
    assert_eq!(
        a.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(a.metadata["inventory_incomplete"], true);
    assert_eq!(a.parent_id, Some(parent));
}

/// A record can be short for two reasons at once: its clipboard text was cut at
/// the decode cap, and the table walk around it lost rows. The walk stamp used
/// to overwrite the cap reason, so the examiner was told the row was
/// structurally damaged and never told the clipboard text was truncated.
#[test]
fn the_walk_stamp_does_not_erase_a_reason_the_record_already_carried() {
    let case = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let mut out = vec![Artifact::new(
        case,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "WindowsTimelineActivity",
            "content_incomplete": true,
            "content_incomplete_reason": "cap_reached",
            "clipboard_text_truncated": true,
        }),
    )];

    let gaps = WalkGaps {
        activity_row_errors: 2,
        ..WalkGaps::default()
    };
    gaps.stamp(case, parent, &mut out);

    let reason = out[0].metadata["content_incomplete_reason"]
        .as_str()
        .unwrap();
    assert!(
        reason.split('+').any(|r| r == "cap_reached"),
        "the clipboard cap must survive the walk stamp: {reason}"
    );
    assert!(
        reason.split('+').any(|r| r == "unresolved_structure"),
        "the walk's own reason must still be stated: {reason}"
    );
    assert_eq!(out[0].metadata["inventory_incomplete"], true);
    // The marker record is appended after the stamped records.
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].metadata["status"], "RowsNotDecoded");
}

/// A schema that exposes its rows through a view is not a schema with no rows.
///
/// Every local `has_table` / `table_exists` in this tree asked
/// `sqlite_master WHERE type='table'`, which answers "absent" for a view. Real
/// schemas do this: recent WhatsApp `msgstore.db` generations keep `messages`
/// as a compatibility view over the `message` table, and the same pattern shows
/// up wherever a vendor renames a table and leaves the old name behind. The
/// walk that depends on the check then produced nothing, and the case read as a
/// device that simply held no records of that kind.
///
/// `probe_table` counts views as present because every caller means "can I
/// SELECT from this name", and a view answers a SELECT exactly as a table does.
#[test]
fn a_table_behind_a_compatibility_view_is_found() {
    let conn = Connection::open_in_memory().expect("an in-memory database");
    conn.execute_batch(
        "CREATE TABLE activity_real (id INTEGER PRIMARY KEY, payload TEXT);
         CREATE VIEW Activity AS SELECT * FROM activity_real;",
    )
    .expect("a table and a view over it");

    assert!(
        has_table(&conn, "activity_real"),
        "the plain table must still be found"
    );
    assert!(
        has_table(&conn, "Activity"),
        "a view answers SELECT exactly as a table does, so it must count as present"
    );
    assert!(
        !has_table(&conn, "no_such_name"),
        "a name that is neither must still be absent"
    );
}

/// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page whose
/// cell count exceeds `(page_size - 8) / 6`, so the file still opens and the
/// schema catalogue will not read.
fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[103] = 0xFF;
    bytes[104] = 0xFF;
    bytes
}

/// B8-039/B8-048. `has_table` folded `Presence::Undetermined` — the catalogue
/// would not answer — into `false`, and the stage-2 gate then returned a bare
/// empty vec. Nothing at all is what a machine with no Timeline history
/// produces, so an `ActivitiesCache.db` this tool could not read was reported as
/// a custodian with no recorded activity. That is a claim about a person, made
/// from a damaged page.
///
/// Against the unfixed code this returns an empty vector.
#[test]
fn an_uncataloguable_store_is_not_reported_as_a_user_with_no_activity() {
    let ddl = SCHEMA.to_string();
    let out = run("ActivitiesCache.db", corrupt_the_catalogue(make_db(&ddl)));

    assert!(
        !out.is_empty(),
        "an unreadable ActivitiesCache.db must not render as a user with no activity history"
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
        .expect("the store was identified and not examined; that must be stated");
    assert_eq!(marker.metadata["type"], json!("WindowsTimelineParseStatus"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert_eq!(marker.metadata["records_recovered"], json!(0));
}

/// HUNT-277. A shadow-copy prior version of `ActivitiesCache.db` is read under
/// its own file name and everything it yields repeats the snapshot identity; a
/// `ParsedRecord` that is not a prior version is not read. SYNTHETIC database.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let ddl = format!(
        "{SCHEMA}\
         INSERT INTO Activity (Id, ActivityType, StartTime) VALUES ('guid-1', 6, 1546300800);"
    );
    let bytes = make_db(&ddl);
    let source = || -> Arc<dyn DataSource> { Arc::new(ByteSliceDataSource::new(bytes.clone())) };
    assert!(ActivitiesCacheParser
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source()),
        json!({
            "type": "VssPriorVersion",
            "name": "ActivitiesCache.db [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "ActivitiesCache.db",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = ActivitiesCacheParser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version's database is read");
    assert!(
        out.iter()
            .all(|a| a.metadata["is_snapshot_version"] == json!(true)
                && a.metadata["vss_snapshot_id"] == json!("snap-1")),
        "{out:#?}"
    );

    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source()),
        json!({ "type": "SomethingElse", "name": "ActivitiesCache.db" }),
    );
    assert!(ActivitiesCacheParser.process(&plain).unwrap().is_empty());
}
