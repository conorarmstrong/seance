use super::*;
use seance_core::test_support::TruncatedSource;

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

use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

/// Build a synthetic iOS `CallHistory.storedata` (`ZCALLRECORD` table) with an
/// outgoing call, an answered incoming call, and a missed call. `ZADDRESS` is a
/// BLOB to exercise the blob-decoding path.
fn create_ios_call_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ios_calls_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZCALLRECORD (
                Z_PK INTEGER PRIMARY KEY,
                ZADDRESS BLOB,
                ZDATE REAL,
                ZDURATION REAL,
                ZORIGINATED INTEGER,
                ZANSWERED INTEGER,
                ZCALLTYPE INTEGER
            );
            -- ZDATE is cocoa seconds since 2001-01-01. 700000000 -> 2023-03-08.
            -- Outgoing call.
            INSERT INTO ZCALLRECORD VALUES (1, CAST('+15551234567' AS BLOB), 700000000.0, 65.0, 1, 1, 1);
            -- Answered incoming call.
            INSERT INTO ZCALLRECORD VALUES (2, CAST('+15559998888' AS BLOB), 700000100.0, 42.0, 0, 1, 1);
            -- Missed incoming call (not answered, zero duration).
            INSERT INTO ZCALLRECORD VALUES (3, CAST('+15550001111' AS BLOB), 700000200.0, 0.0, 0, 0, 1);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Build a synthetic Android call-log (`calls` table inside a `contacts2.db`).
fn create_android_call_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_android_calls_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 1;
            CREATE TABLE calls (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                date INTEGER,
                duration INTEGER,
                type INTEGER,
                name TEXT
            );
            -- date in millis. type 1=incoming, 2=outgoing, 3=missed.
            INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, 30, 1, 'Alice');
            INSERT INTO calls VALUES (2, '+15559998888', 1600000100000, 120, 2, 'Bob');
            INSERT INTO calls VALUES (3, '+15550001111', 1600000200000, 0, 3, NULL);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Build a synthetic iOS `CallHistory.storedata` holding two calls placed
/// inside the *same* second — 250 ms and 750 ms in. Nothing but the fraction
/// tells them apart, which is what makes this the fixture for the sub-second
/// contract.
fn create_ios_subsecond_call_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ios_subsec_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZCALLRECORD (
                Z_PK INTEGER PRIMARY KEY,
                ZADDRESS BLOB,
                ZDATE REAL,
                ZDURATION REAL,
                ZORIGINATED INTEGER,
                ZANSWERED INTEGER,
                ZCALLTYPE INTEGER
            );
            INSERT INTO ZCALLRECORD VALUES (1, CAST('+15551234567' AS BLOB), 700000000.25, 65.0, 1, 1, 1);
            INSERT INTO ZCALLRECORD VALUES (2, CAST('+15559998888' AS BLOB), 700000000.75, 42.0, 0, 1, 1);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Android call log whose `date` millis carry a 750 ms remainder.
fn create_android_subsecond_call_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_android_subsec_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 1;
            CREATE TABLE calls (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                date INTEGER,
                duration INTEGER,
                type INTEGER,
                name TEXT
            );
            INSERT INTO calls VALUES (1, '+15551234567', 1600000000750, 30, 1, 'Alice');",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Build a SQLite db that is NOT a call log (only a `foo` table).
fn create_non_call_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_non_call_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE foo (id INTEGER PRIMARY KEY, bar TEXT); INSERT INTO foo VALUES (1, 'x');",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn calls(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["subtype"] == "call")
        .collect()
}

fn summary(result: &[Artifact]) -> &Artifact {
    result
        .iter()
        .find(|a| a.metadata["subtype"] == "summary")
        .expect("summary record present")
}

#[test]
fn test_module_metadata() {
    let parser = CallHistoryParser;
    assert_eq!(parser.id(), "plugin.mobile.call_history");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_filename_prefilter() {
    assert!(identify_call_history_db("CallHistory.storedata"));
    assert!(identify_call_history_db(
        "/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"
    ));
    assert!(identify_call_history_db("contacts2.db"));
    assert!(identify_call_history_db("calllog.db"));
    assert!(!identify_call_history_db("chat.db"));
    assert!(!identify_call_history_db("mmssms.db"));
    assert!(!identify_call_history_db("random.txt"));
}

#[test]
fn test_epoch_normalization() {
    // Android millis -> seconds
    assert_eq!(
        normalize_epoch_parts(1_600_000_000_000),
        Some((1_600_000_000, 0))
    );
    // already seconds -> unchanged
    assert_eq!(
        normalize_epoch_parts(1_600_000_000),
        Some((1_600_000_000, 0))
    );
    // The millisecond part is what orders two calls inside one second, so it
    // survives as nanos instead of being divided away.
    assert_eq!(
        normalize_epoch_parts(1_600_000_000_750),
        Some((1_600_000_000, 750_000_000))
    );
    // micros -> seconds, keeping all six fractional digits. This is the case
    // the old two-branch rule got wrong: it divided a 16-digit value by a
    // thousand and dated the call to the year 52671.
    assert_eq!(
        normalize_epoch_parts(1_600_000_000_750_123),
        Some((1_600_000_000, 750_123_000))
    );
    // An unset column is absent, not midnight on 1970-01-01.
    assert_eq!(normalize_epoch_parts(0), None);
    assert_eq!(normalize_epoch_parts(-1_600_000_000_000), None);
}

#[test]
fn ios_call_record_keeps_the_sub_second_that_orders_two_calls_in_one_second() {
    let parser = CallHistoryParser;
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_ios_subsecond_call_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = calls(&result);
    assert_eq!(recs.len(), 2);
    let first = recs.iter().find(|a| a.metadata["rowid"] == 1).unwrap();
    let second = recs.iter().find(|a| a.metadata["rowid"] == 2).unwrap();

    // Both calls land on the same whole second, so the seconds field alone
    // cannot say which came first.
    let base = 700_000_000 + 978_307_200;
    assert_eq!(first.metadata["timestamp"].as_i64().unwrap(), base);
    assert_eq!(second.metadata["timestamp"].as_i64().unwrap(), base);

    let first_ns = first.metadata["timestamp_ns"].as_i64().unwrap();
    let second_ns = second.metadata["timestamp_ns"].as_i64().unwrap();
    assert_eq!(first_ns, base * 1_000_000_000 + 250_000_000);
    assert_eq!(second_ns, base * 1_000_000_000 + 750_000_000);
    assert!(
        first_ns < second_ns,
        "the ZDATE fraction must still order the two calls"
    );

    // The string an examiner reads must not contradict the nanos beside it.
    assert!(first.metadata["timestamp_rfc3339"]
        .as_str()
        .unwrap()
        .contains(".25"));
}

#[test]
fn android_call_record_keeps_its_millisecond_part() {
    let parser = CallHistoryParser;
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_android_subsecond_call_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "calllog.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    let call = recs[0];
    assert_eq!(call.metadata["timestamp"].as_i64(), Some(1_600_000_000));
    // The 750 ms the device recorded was previously divided away.
    assert_eq!(
        call.metadata["timestamp_ns"].as_i64(),
        Some(1_600_000_000 * 1_000_000_000 + 750_000_000)
    );
}

#[test]
fn test_skips_non_matching_file() {
    let parser = CallHistoryParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "random_file.txt"}),
    );
    assert_eq!(parser.process(&artifact).unwrap().len(), 0);
}

#[test]
fn test_identification_only_no_data() {
    let parser = CallHistoryParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "CallHistory.storedata"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "CallLog");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_ios_parsing_and_direction() {
    let parser = CallHistoryParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_call_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = calls(&result);
    assert_eq!(recs.len(), 3, "expected 3 calls, got {}", recs.len());

    let outgoing = recs.iter().find(|a| a.metadata["rowid"] == 1).unwrap();
    assert_eq!(outgoing.metadata["direction"], "outgoing");
    assert_eq!(outgoing.metadata["type"], "CallLog");
    assert_eq!(outgoing.metadata["platform"], "iOS");
    assert_eq!(outgoing.metadata["number"], "+15551234567");
    assert_eq!(outgoing.metadata["contact"], "+15551234567");
    assert_eq!(outgoing.metadata["duration_seconds"], 65);
    // Cocoa 700000000 -> unix 700000000 + 978307200
    assert_eq!(
        outgoing.metadata["timestamp"].as_i64().unwrap(),
        700_000_000 + 978_307_200
    );
    assert!(outgoing.metadata["timestamp_rfc3339"].is_string());

    let incoming = recs.iter().find(|a| a.metadata["rowid"] == 2).unwrap();
    assert_eq!(incoming.metadata["direction"], "incoming");
    assert_eq!(incoming.metadata["answered"], true);

    let missed = recs.iter().find(|a| a.metadata["rowid"] == 3).unwrap();
    assert_eq!(missed.metadata["direction"], "missed");
    assert_eq!(missed.metadata["answered"], false);
    assert_eq!(missed.metadata["duration_seconds"], 0);

    let s = summary(&result);
    assert_eq!(s.metadata["type"], "CallLog");
    assert_eq!(s.metadata["platform"], "iOS");
    assert_eq!(s.metadata["call_count"], 3);
    assert_eq!(s.metadata["outgoing_count"], 1);
    assert_eq!(s.metadata["incoming_count"], 1);
    assert_eq!(s.metadata["missed_count"], 1);
}

#[test]
fn test_android_parsing_and_direction() {
    let parser = CallHistoryParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_android_call_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "contacts2.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = calls(&result);
    assert_eq!(recs.len(), 3, "expected 3 calls, got {}", recs.len());

    let incoming = recs.iter().find(|a| a.metadata["rowid"] == 1).unwrap();
    assert_eq!(incoming.metadata["direction"], "incoming");
    assert_eq!(incoming.metadata["platform"], "Android");
    assert_eq!(incoming.metadata["number"], "+15551234567");
    assert_eq!(incoming.metadata["duration_seconds"], 30);
    // Android date is millis; normalized to seconds.
    assert_eq!(
        incoming.metadata["timestamp"].as_i64().unwrap(),
        1_600_000_000
    );

    let outgoing = recs.iter().find(|a| a.metadata["rowid"] == 2).unwrap();
    assert_eq!(outgoing.metadata["direction"], "outgoing");

    let missed = recs.iter().find(|a| a.metadata["rowid"] == 3).unwrap();
    assert_eq!(missed.metadata["direction"], "missed");

    let s = summary(&result);
    assert_eq!(s.metadata["platform"], "Android");
    assert_eq!(s.metadata["call_count"], 3);
    assert_eq!(s.metadata["incoming_count"], 1);
    assert_eq!(s.metadata["outgoing_count"], 1);
    assert_eq!(s.metadata["missed_count"], 1);
}

#[test]
fn test_parent_and_case_chain() {
    let parser = CallHistoryParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_call_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );
    let parent_id = artifact.id;
    let result = parser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    for rec in &result {
        assert_eq!(rec.parent_id, Some(parent_id));
        assert_eq!(rec.case_id, case_id);
        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
    }
}

#[test]
fn test_negative_non_call_schema_rejected() {
    let parser = CallHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_non_call_db()));
    // Name passes the pre-filter, so only the schema check can reject it.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "contacts2.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0, "non-call schema must yield zero artifacts");
}

#[test]
fn test_garbage_no_panic() {
    let parser = CallHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 2048]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        0,
        "garbage must yield zero artifacts, no panic"
    );
}

/// iOS `ZDATE` of 0 is "unset"; the record must be honestly undated rather than
/// carrying a fabricated 2001-01-01 timestamp.
#[test]
fn test_ios_zero_zdate_is_undated_not_2001() {
    let db = {
        let temp = std::env::temp_dir().join(format!("test_ios_zero_{}.db", Uuid::new_v4()));
        {
            let conn = Connection::open(&temp).unwrap();
            conn.execute_batch(
                "CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS BLOB, ZDATE REAL, \
                   ZDURATION REAL, ZORIGINATED INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER);
                 INSERT INTO ZCALLRECORD VALUES (1, CAST('+15551234567' AS BLOB), 0.0, 10.0, 1, 1, 1);",
            )
            .unwrap();
        }
        let data = std::fs::read(&temp).unwrap();
        let _ = std::fs::remove_file(&temp);
        data
    };
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );
    let result = parser_process(&artifact);
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert!(
        recs[0].metadata.get("timestamp").is_none(),
        "a 0 ZDATE must be omitted, not stored as 2001-01-01"
    );
    assert!(recs[0].metadata.get("timestamp_rfc3339").is_none());
}

/// Android `date` of 0 is "unset"; must be omitted, not stored as 1970-01-01.
#[test]
fn test_android_zero_date_is_undated_not_1970() {
    let db = {
        let temp = std::env::temp_dir().join(format!("test_android_zero_{}.db", Uuid::new_v4()));
        {
            let conn = Connection::open(&temp).unwrap();
            conn.execute_batch(
                "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, \
                   duration INTEGER, type INTEGER, name TEXT);
                 INSERT INTO calls VALUES (1, '+15551234567', 0, 30, 1, 'Alice');",
            )
            .unwrap();
        }
        let data = std::fs::read(&temp).unwrap();
        let _ = std::fs::remove_file(&temp);
        data
    };
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "contacts2.db"}),
    );
    let result = parser_process(&artifact);
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert!(
        recs[0].metadata.get("timestamp").is_none(),
        "a 0 date must be omitted, not stored as 1970-01-01"
    );
}

/// Small helper to run the parser and unwrap.
fn parser_process(artifact: &Artifact) -> Vec<Artifact> {
    CallHistoryParser.process(artifact).unwrap()
}

// --- Cap honesty (B2-079) ----------------------------------------------------

/// A walk that read every row must not claim the log was cut short.
#[test]
fn a_complete_call_log_summary_carries_no_truncation_flag() {
    let summary = build_call_summary(&[], "Android", "calllog.db", 3, false, 0);
    assert_eq!(summary["call_count"], json!(3));
    assert!(summary.get("truncated").is_none());
    assert!(summary.get("content_incomplete").is_none());
}

/// Hitting the cap must be stated on the summary. Both platforms order
/// newest-first, so the dropped rows are the oldest calls; a summary that only
/// reports the capped count would present them as never having happened.
#[test]
fn a_call_log_stopped_by_the_cap_is_marked_incomplete() {
    let summary = build_call_summary(
        &[],
        "iOS",
        "CallHistory.storedata",
        MAX_CALL_ENTRIES,
        true,
        0,
    );
    assert_eq!(summary["truncated"], json!(true));
    assert_eq!(summary["content_incomplete"], json!(true));
    assert_eq!(summary["content_incomplete_reason"], "cap_reached");
    assert_eq!(summary["max_entries"], json!(MAX_CALL_ENTRIES));
    assert_eq!(summary["call_count"], json!(MAX_CALL_ENTRIES));
}
/// B2-123: the parser cap was reported, but the *other* truncation — a database
/// the spill could not stage in full — was not. SQLite opens a short file and
/// answers from the pages it reaches, so the calls recovered read as the whole
/// log with nothing to say otherwise.
#[test]
fn a_short_read_call_log_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(create_ios_call_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );
    let result = CallHistoryParser.process(&artifact).unwrap();

    let call = result
        .iter()
        .find(|a| a.metadata["subtype"] == "call")
        .expect("the readable prefix still parses");
    assert_eq!(call.metadata["content_incomplete"], true);
    assert_eq!(call.metadata["content_incomplete_reason"], "short_read");
    assert!(
        result
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: a log read whole stays unmarked.
#[test]
fn a_complete_call_log_carries_no_incompleteness_marks() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_call_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "CallHistory.storedata"}),
    );
    let result = CallHistoryParser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

// --- Direction honesty (B4-006) ----------------------------------------------

/// Build a database from a literal schema+rows script.
fn db_from_sql(sql: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_calls_sql_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn process_db(db: Vec<u8>, name: &str) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    CallHistoryParser.process(&artifact).unwrap()
}

const IOS_SCHEMA: &str = "CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS BLOB, \
     ZDATE REAL, ZDURATION REAL, ZORIGINATED INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER);";

/// A Core Data row that never recorded `ZORIGINATED`/`ZANSWERED` must not be
/// classified. Before the fix both NULLs became `direction: "missed"` with
/// `answered: false` — an affirmative claim that a call came in and was not
/// picked up, invented from two absent columns.
#[test]
fn ios_null_direction_flags_are_unknown_not_missed() {
    let db = db_from_sql(&format!(
        "{IOS_SCHEMA} INSERT INTO ZCALLRECORD VALUES \
         (1, CAST('+15551234567' AS BLOB), 700000000.0, 12.0, NULL, NULL, 1);"
    ));
    let result = process_db(db, "CallHistory.storedata");
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].metadata["direction"], "unknown");
    assert!(
        recs[0].metadata["answered"].is_null(),
        "a NULL ZANSWERED must not become `answered: false`"
    );
    assert!(
        recs[0].metadata["originated"].is_null(),
        "a NULL ZORIGINATED must not become `originated: false`"
    );

    let s = summary(&result);
    assert_eq!(s.metadata["unknown_direction_count"], json!(1));
    assert_eq!(
        s.metadata["missed_count"],
        json!(0),
        "an undetermined direction must not be tallied as a missed call"
    );
    assert_eq!(
        s.metadata["incoming_count"],
        json!(0),
        "an undetermined direction must not be tallied as incoming either"
    );
}

/// `ZORIGINATED = 0` is a recorded fact (inbound); only the answered refinement
/// is missing, so the call stays "incoming" rather than becoming "missed".
#[test]
fn ios_inbound_with_null_answered_is_incoming_not_missed() {
    let db = db_from_sql(&format!(
        "{IOS_SCHEMA} INSERT INTO ZCALLRECORD VALUES \
         (1, CAST('+15551234567' AS BLOB), 700000000.0, 12.0, 0, NULL, 1);"
    ));
    let recs = process_db(db, "CallHistory.storedata");
    let recs = calls(&recs);
    assert_eq!(recs[0].metadata["direction"], "incoming");
    assert!(recs[0].metadata["answered"].is_null());
}

/// A NULL `ZDURATION` is "not recorded", not "the call lasted no time".
#[test]
fn ios_null_duration_is_null_not_zero() {
    let db = db_from_sql(&format!(
        "{IOS_SCHEMA} INSERT INTO ZCALLRECORD VALUES \
         (1, CAST('+15551234567' AS BLOB), 700000000.0, NULL, 1, 1, 1);"
    ));
    let result = process_db(db, "CallHistory.storedata");
    let recs = calls(&result);
    assert!(recs[0].metadata["duration_seconds"].is_null());
    assert!(recs[0].metadata["name"]
        .as_str()
        .unwrap()
        .contains("duration unknown"));
}

const ANDROID_SCHEMA: &str = "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, \
     date INTEGER, duration INTEGER, type INTEGER);";

/// A NULL `calls.type` never recorded the direction: it must not be written back
/// out as `call_type: 0`, a value Android never stores.
#[test]
fn android_null_type_is_unknown_with_no_fabricated_call_type() {
    let db = db_from_sql(&format!(
        "{ANDROID_SCHEMA} INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, NULL, NULL);"
    ));
    let result = process_db(db, "calllog.db");
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].metadata["direction"], "unknown");
    assert!(
        recs[0].metadata["call_type"].is_null(),
        "a NULL type column must not be recorded as 0"
    );
    assert!(
        recs[0].metadata["duration_seconds"].is_null(),
        "a NULL duration must not be recorded as 0 seconds"
    );
    assert_eq!(
        summary(&result).metadata["unknown_direction_count"],
        json!(1)
    );
}

/// Voicemail/rejected/blocked are directions in their own right and must not be
/// folded into the incoming tally.
#[test]
fn android_other_direction_codes_are_tallied_separately() {
    let db = db_from_sql(&format!(
        "{ANDROID_SCHEMA} INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, 0, 4);"
    ));
    let result = process_db(db, "calllog.db");
    assert_eq!(calls(&result)[0].metadata["direction"], "voicemail");
    let s = summary(&result);
    assert_eq!(s.metadata["other_direction_count"], json!(1));
    assert_eq!(s.metadata["incoming_count"], json!(0));
}

// --- Dropped-row honesty (B4-009) --------------------------------------------

/// A row whose `type` will not decode as an integer is skipped. The count that
/// survives must not present as the exact number of calls the device made.
#[test]
fn android_undecodable_rows_are_counted_on_the_summary() {
    let db = db_from_sql(&format!(
        "{ANDROID_SCHEMA} \
         INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, 30, 1); \
         INSERT INTO calls VALUES (2, '+15559998888', 1600000100000, 30, 'not-an-integer');"
    ));
    let result = process_db(db, "calllog.db");
    assert_eq!(calls(&result).len(), 1);
    let s = summary(&result);
    assert_eq!(s.metadata["call_count"], json!(1));
    assert_eq!(s.metadata["rows_dropped"], json!(1));
    assert_eq!(s.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        s.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(s.metadata["content_incomplete"], json!(true));
    assert_eq!(
        s.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

/// The iOS walk carries the same tally.
#[test]
fn ios_undecodable_rows_are_counted_on_the_summary() {
    let db = db_from_sql(&format!(
        "{IOS_SCHEMA} \
         INSERT INTO ZCALLRECORD VALUES (1, CAST('+1555' AS BLOB), 700000000.0, 12.0, 1, 1, 1); \
         INSERT INTO ZCALLRECORD VALUES (2, CAST('+1556' AS BLOB), 700000100.0, 'nope', 1, 1, 1);"
    ));
    let result = process_db(db, "CallHistory.storedata");
    assert_eq!(calls(&result).len(), 1);
    let s = summary(&result);
    assert_eq!(s.metadata["rows_dropped"], json!(1));
    assert_eq!(s.metadata["content_incomplete"], json!(true));
}

/// A cap is the coarser statement and must survive alongside the row tally.
#[test]
fn a_capped_and_lossy_call_log_reports_the_cap_reason() {
    let summary = build_call_summary(&[], "iOS", "CallHistory.storedata", 10, true, 4);
    assert_eq!(summary["content_incomplete_reason"], "cap_reached");
    assert_eq!(summary["rows_dropped"], json!(4));
    assert_eq!(summary["inventory_incomplete"], json!(true));
}

// --- Unreadable databases (B7-023 class) -------------------------------------

/// A file that carries the SQLite magic and cannot be read is a call log this
/// tool failed on, not a device with no call history. Before the fix the schema
/// probe swallowed the error (`unwrap_or(false)`) and the parser returned zero
/// artifacts, which renders identically to an empty log.
#[test]
fn a_corrupt_call_log_reports_a_parse_failure_not_an_empty_log() {
    let mut db = create_ios_call_db();
    // Keep the header, destroy the page content: SQLite opens it and then fails
    // every query against the catalogue.
    for b in db.iter_mut().skip(16) {
        *b = 0xFF;
    }
    let result = process_db(db, "CallHistory.storedata");
    assert_eq!(result.len(), 1, "the failure must be reported as a record");
    let m = &result[0].metadata;
    assert_eq!(m["status"], "ParseFailed");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(m["inventory_incomplete"], json!(true));
}

/// The counterpart: a file that is not a database at all stays silent.
#[test]
fn a_non_sqlite_file_still_yields_nothing() {
    let result = process_db(vec![0xABu8; 2048], "CallHistory.storedata");
    assert!(result.is_empty());
}

// --- Schema-drift defence (ROADMAP §1.4a) -----------------------------------

/// The marker records this parse emitted about the schema itself.
fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// An Android `calllog.db` whose `PRAGMA user_version` is outside the window
/// this parser was validated against must say so, and still parse the rows.
#[test]
fn an_android_call_log_outside_the_validated_range_is_declared_and_still_parsed() {
    let db = db_from_sql(&format!(
        "PRAGMA user_version = 42; {ANDROID_SCHEMA} INSERT INTO calls VALUES \
         (1, '+15551234567', 1600000000000, 30, 1);"
    ));
    let result = process_db(db, "calllog.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["app"], AndroidStore::CallLog.app());
    assert_eq!(m.metadata["seen_schema_version"], 42);
    assert_eq!(
        m.metadata["supported_range"],
        AndroidStore::CallLog.supported().describe()
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
    // HUNT-204: the range names the real store it was read from.
    let evidence = m.metadata["validated_against"].as_str().unwrap_or_default();
    assert!(
        evidence.contains("calllog.db") && evidence.contains("Pixel 3"),
        "the range carries no evidence-file name: {}",
        m.metadata
    );
    assert_ne!(m.metadata["type"], "CallLog", "never the walk's own type");
    assert_eq!(calls(&result).len(), 1, "the call is still parsed");
}

/// `PRAGMA user_version` of 0 is SQLite's default for a store that never set
/// one — the absence of a version, not "version 0". Comparing it to the window
/// would manufacture an "older than supported" finding out of an unset field,
/// so the parse is declared unranked instead, with nothing called incomplete.
#[test]
fn a_store_with_no_recorded_version_is_declared_unranked_not_older() {
    let db = db_from_sql(&format!(
        "{ANDROID_SCHEMA} INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, 30, 1);"
    ));
    let result = process_db(db, "calllog.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaVersionNotRecorded");
    assert!(m.metadata.get("content_incomplete").is_none());
    assert_eq!(calls(&result).len(), 1);
}

/// `contacts2.db` is a different provider with its own version counter, so its
/// `calls` table is judged against the window observed on real `contacts2.db`
/// files — not the `calllog.db` one.
#[test]
fn a_contacts2_calls_table_is_judged_against_its_own_validated_range() {
    let inside = db_from_sql(&format!(
        "PRAGMA user_version = 1; {ANDROID_SCHEMA} INSERT INTO calls VALUES \
         (1, '+15551234567', 1600000000000, 30, 1);"
    ));
    let result = process_db(inside, "contacts2.db");
    assert!(stale_markers(&result).is_empty(), "{result:?}");

    let outside = db_from_sql(&format!(
        "PRAGMA user_version = 1300; {ANDROID_SCHEMA} INSERT INTO calls VALUES \
         (1, '+15551234567', 1600000000000, 30, 1);"
    ));
    let result = process_db(outside, "contacts2.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].metadata["app"], AndroidStore::Contacts2.app());
    assert_eq!(
        markers[0].metadata["supported_range"],
        AndroidStore::Contacts2.supported().describe()
    );
    assert_eq!(calls(&result).len(), 1);
}

/// A renamed `calls` column is named by the logical field it carried, and the
/// rows still walk with that field absent — never with a substituted value.
#[test]
fn a_renamed_android_calls_column_is_declared_by_logical_field_and_the_rows_still_walk() {
    let db = db_from_sql(
        "PRAGMA user_version = 5;
         CREATE TABLE calls (_id INTEGER PRIMARY KEY, phone_number TEXT, date INTEGER, \
         duration INTEGER, type INTEGER);
         INSERT INTO calls VALUES (1, '+15551234567', 1600000000000, 30, 2);",
    );
    let result = process_db(db, "calllog.db");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    let m = markers[0];
    assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(m.metadata["source_table"], "calls");
    assert_eq!(m.metadata["unresolved_fields"], json!(["number"]));
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].metadata["direction"], "outgoing");
    assert!(recs[0].metadata["number"].is_null());
}

/// The same defence on the Core Data walk, which has no numeric version to
/// check and so relies on the column map alone.
#[test]
fn a_renamed_zcallrecord_column_is_declared_by_logical_field_and_the_rows_still_walk() {
    let db = db_from_sql(
        "CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS BLOB, ZDATE REAL, \
         ZDURATION REAL, ZDIRECTION INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER);
         INSERT INTO ZCALLRECORD VALUES (1, CAST('+15551234567' AS BLOB), 700000000.0, 12.0, 1, 1, 1);",
    );
    let result = process_db(db, "CallHistory.storedata");
    let markers = stale_markers(&result);
    assert_eq!(markers.len(), 1, "{result:?}");
    assert_eq!(markers[0].metadata["source_table"], "ZCALLRECORD");
    assert_eq!(
        markers[0].metadata["unresolved_fields"],
        json!(["originated"])
    );
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert_eq!(
        recs[0].metadata["direction"], DIRECTION_UNKNOWN,
        "with the direction column unresolved, no direction is invented"
    );
}

/// A Core Data store carries no numeric schema version, so no range is
/// declared for it and a healthy one carries no version marker. Declaring a
/// `0..=0` window on `PRAGMA user_version` would warn on nothing Apple ever
/// changes.
#[test]
fn an_ios_call_history_makes_no_version_range_claim() {
    let result = process_db(create_ios_call_db(), "CallHistory.storedata");
    assert!(stale_markers(&result).is_empty(), "{result:?}");
    assert_eq!(calls(&result).len(), 3);
}

/// The Magnet 2019 Android CTF ships a `contacts2.db` written by the
/// acquisition agent, whose `calls` table keys on `id` rather than `_id`
/// (`id name number date type duration`). It is a real file, so `id` is a
/// candidate and the table resolves in full.
#[test]
fn an_agent_written_calls_table_keyed_on_id_resolves_without_a_drift_marker() {
    let db = db_from_sql(
        "PRAGMA user_version = 1;
         CREATE TABLE calls (id INTEGER, name TEXT, number TEXT, date INTEGER, type INTEGER, \
         duration INTEGER);
         INSERT INTO calls VALUES (1, 'Alice', '+15551234567', 1544470800000, 1, 30);",
    );
    let result = process_db(db, "contacts2.db");
    assert!(stale_markers(&result).is_empty(), "{result:?}");
    let recs = calls(&result);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].metadata["rowid"], 1);
    assert_eq!(recs[0].metadata["number"], "+15551234567");
}

/// The corpus-diff harness for this parser: every real call log it was
/// validated against parses without a schema marker and yields at least the
/// records observed when the range was declared. Files outside the tree are
/// skipped when absent; `SEANCE_APP_SCHEMA_CORPUS` names the directory holding
/// the CTF-derived copies.
#[test]
fn real_call_logs_in_the_validated_range_carry_no_stale_marker() {
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
    // The third element is the version the real file records: `None` where it
    // records none (`PRAGMA user_version` 0), which the parse declares as
    // unranked and nothing else.
    let expectations = [
        (
            workspace.join("reference/plaso/test_data/contacts2.db"),
            "contacts2.db",
            None,
            expect("plaso test_data/contacts2.db calls (no user_version)", 3),
        ),
        (
            corpus.join("magnet2019_contacts2.db"),
            "contacts2.db",
            Some(1),
            expect(
                "Magnet 2019 Android CTF agent contacts2.db calls (user_version 1)",
                3,
            ),
        ),
        (
            corpus.join("android2022_calllog.db"),
            "calllog.db",
            Some(5),
            expect("Magnet 2022 CTF Pixel 3 calllog.db (user_version 5)", 0),
        ),
        (
            corpus.join("ios2022_CallHistory.storedata"),
            "CallHistory.storedata",
            None,
            expect("Magnet 2022 CTF iPhone 8 CallHistory.storedata", 1),
        ),
    ];
    let mut checked = 0;
    for (path, name, version, expect) in expectations {
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
        let result = process_db(std::fs::read(&path).unwrap(), name);
        let markers = stale_markers(&result);
        match (version, name) {
            (Some(v), _) => {
                assert!(
                    AndroidStore::classify(name).supported().contains(v),
                    "the declared range must include the observed version {v}"
                );
                assert!(
                    markers.is_empty(),
                    "{}: a real store in range must not warn: {markers:?}",
                    expect.label
                );
            }
            // The Core Data store has no window at all, so no version marker.
            (None, "CallHistory.storedata") => {
                assert!(markers.is_empty(), "{}: {markers:?}", expect.label)
            }
            (None, _) => {
                assert_eq!(markers.len(), 1, "{}: {markers:?}", expect.label);
                assert_eq!(markers[0].metadata["status"], "SchemaVersionNotRecorded");
            }
        }
        assert!(
            !result.iter().any(|a| a.metadata["status"] == "ParseFailed"),
            "{}: {result:?}",
            expect.label
        );
        seance_sqlite_util::check_corpus(&expect, calls(&result).len()).unwrap();
        checked += 1;
    }
    eprintln!("checked {checked} real call log(s)");
}

/// ROADMAP §5.11, owner decision (b) of 2026-09-26: this parser's schema
/// records speak the vocabulary every schema record shares — the same status
/// names, subtype `parser_stale` and `warning_class: "ParserStaleWarning"`.
#[test]
fn schema_records_speak_the_shared_vocabulary() {
    use seance_sqlite_util::adopt::inline_marker::{
        field_drift_marker, stale_marker, version_not_recorded_marker, version_undetermined_marker,
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
