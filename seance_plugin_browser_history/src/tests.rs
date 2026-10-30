use super::*;
use seance_core::data_source::DataSource;
use seance_core::test_support::{DribbleSource, TruncatedSource};
use std::sync::Arc;
use uuid::Uuid;

// The bytes a test built and no more: the shared in-memory source (ROADMAP §5.11),
// not a private copy of it.
use seance_core::data_source::ByteSliceDataSource;

/// Create a valid in-memory Chrome History SQLite database and return its bytes.
fn create_chrome_test_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://test.org/page', 'Test Page', 2, 13300000100000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (2, 1, 13299999000000000, 0, 0);
             INSERT INTO visits VALUES (3, 2, 13300000100000000, 1, 7);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Create a valid in-memory Firefox places.sqlite database and return its bytes.
fn create_firefox_test_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_firefox_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mozilla.org', 'Mozilla', 3, 1700000000000000);
             INSERT INTO moz_places VALUES (2, 'https://rust-lang.org', 'Rust', 1, 1700000100000000);
             INSERT INTO moz_historyvisits VALUES (1, 1, 1700000000000000, 1);
             INSERT INTO moz_historyvisits VALUES (2, 1, 1699999000000000, 2);
             INSERT INTO moz_historyvisits VALUES (3, 2, 1700000100000000, 3);"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Create a valid in-memory Safari History.db database and return its bytes.
fn create_safari_test_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_safari_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 15;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
             INSERT INTO history_items VALUES (1, 'https://apple.com', 4);
             INSERT INTO history_items VALUES (2, 'https://developer.apple.com', 2);
             INSERT INTO history_visits VALUES (1, 1, 720000000.0, 'Apple');
             INSERT INTO history_visits VALUES (2, 1, 719999000.0, 'Apple Inc');
             INSERT INTO history_visits VALUES (3, 2, 720000100.0, 'Apple Developer');"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// Filter helper: timeline events emitted by a parse run.
fn timeline_events(artifacts: &[Artifact]) -> Vec<&Artifact> {
    artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect()
}

#[test]
fn test_chrome_emits_timeline_events() {
    let parser = BrowserHistoryParser;
    let data_source: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_chrome_test_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "History"}),
    );
    let artifacts = parser.process(&artifact).unwrap();
    let events = timeline_events(&artifacts);
    assert!(!events.is_empty(), "chrome should emit timeline events");

    assert!(events
        .iter()
        .all(|e| e.metadata["source_module"] == "plugin.browsers.history_parser"));
    // Chrome visit_time 13300000000000000 (WebKit us) -> 1655526400 Unix seconds.
    assert!(events
        .iter()
        .any(|e| e.metadata["timestamp"].as_i64() == Some(1_655_526_400)));
    let short = events[0].metadata["short_desc"].as_str().unwrap();
    assert!(!short.is_empty());
    assert!(short.starts_with("Web visit:"));
}

#[test]
fn test_chrome_parses_through_short_reading_source() {
    // A source that hands back the DB in small chunks (as a window over a disk
    // image does) must recover the same records as a full-read source; a single
    // read_at would otherwise write a truncated temp DB and lose rows.
    let parser = BrowserHistoryParser;
    let db = create_chrome_test_db();
    let full: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db.clone()));
    let chunked: Arc<dyn DataSource> = Arc::new(DribbleSource::new(db, 512));
    let mk = |ds: Arc<dyn DataSource>| {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({"name": "History"}),
        )
    };
    let full_records = parser.process(&mk(full)).unwrap();
    let chunked_records = parser.process(&mk(chunked)).unwrap();
    assert!(
        !chunked_records.is_empty(),
        "short-read source recovered nothing"
    );
    assert_eq!(
        full_records.len(),
        chunked_records.len(),
        "short-reading source must recover the same records as a full-read source"
    );
}

#[test]
fn test_firefox_and_safari_emit_timeline_events() {
    let parser = BrowserHistoryParser;

    let ff_source: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_firefox_test_db()));
    let ff = parser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ff_source),
            json!({"name": "places.sqlite"}),
        ))
        .unwrap();
    let ff_events = timeline_events(&ff);
    assert!(!ff_events.is_empty(), "firefox should emit timeline events");
    assert_eq!(
        ff_events[0].metadata["source_module"],
        "plugin.browsers.history_parser"
    );
    assert!(ff_events[0].metadata["timestamp"].as_i64().is_some());

    let sf_source: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_safari_test_db()));
    let sf = parser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(sf_source),
            json!({"name": "History.db"}),
        ))
        .unwrap();
    let sf_events = timeline_events(&sf);
    assert!(!sf_events.is_empty(), "safari should emit timeline events");
    assert_eq!(
        sf_events[0].metadata["source_module"],
        "plugin.browsers.history_parser"
    );
    assert!(sf_events[0].metadata["timestamp"].as_i64().is_some());
}

#[test]
fn test_module_metadata() {
    let parser = BrowserHistoryParser;
    assert_eq!(parser.id(), "plugin.browsers.history_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_skips_non_history_file() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "random_file.txt"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_skips_no_name() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({}));
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_identification_only_without_data_source() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "History"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["browser"], "Chrome/Edge");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_chrome_history_parsing() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_chrome_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History"}),
    );

    let result = parser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    // Should have 3 visit records (from visits table)
    assert_eq!(records.len(), 3);

    // Check first record (most recent visit)
    assert_eq!(records[0].metadata["browser"], "Chrome/Edge");
    assert_eq!(records[0].metadata["type"], "BrowserHistory");
    assert!(records[0].metadata["url"]
        .as_str()
        .unwrap()
        .starts_with("https://"));
    assert!(records[0].metadata["visit_time"].as_i64().unwrap() > 0);

    // Verify transition types were parsed
    let transitions: Vec<&str> = records
        .iter()
        .filter_map(|a| a.metadata["transition_type"].as_str())
        .collect();
    assert!(transitions.contains(&"typed")); // transition 1
    assert!(transitions.contains(&"link")); // transition 0
    assert!(transitions.contains(&"form_submit")); // transition 7
}

#[test]
fn test_firefox_history_parsing() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_firefox_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "places.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    // 3 visit records
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].metadata["browser"], "Firefox");

    // Verify firefox-specific transitions
    let transitions: Vec<&str> = records
        .iter()
        .filter_map(|a| a.metadata["transition_type"].as_str())
        .collect();
    assert!(transitions.contains(&"link")); // type 1
    assert!(transitions.contains(&"typed")); // type 2
    assert!(transitions.contains(&"bookmark")); // type 3
}

#[test]
fn test_safari_history_parsing() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_safari_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].metadata["browser"], "Safari");

    // Core Data timestamp 720000000 + 978307200 = 1698307200 (Unix)
    let visit_time = records
        .iter()
        .find(|a| a.metadata["title"] == "Apple Developer")
        .unwrap()
        .metadata["visit_time"]
        .as_i64()
        .unwrap();
    let (expected_secs, _) = cocoa_secs_to_unix_nanos(720000100.0).unwrap();
    assert_eq!(visit_time, expected_secs);
}

/// Two Safari visits inside the same second — a redirect chain, which is how
/// this happens in real history — 250 ms and 750 ms in.
fn create_safari_subsecond_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_safari_subsec_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 15;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
             INSERT INTO history_items VALUES (1, 'https://example.com/start', 1);
             INSERT INTO history_items VALUES (2, 'https://example.com/landed', 1);
             INSERT INTO history_visits VALUES (1, 1, 720000000.25, 'Start');
             INSERT INTO history_visits VALUES (2, 2, 720000000.75, 'Landed');"
        ).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn safari_visit_keeps_the_sub_second_that_orders_a_redirect_chain() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_safari_subsecond_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History.db"}),
    );

    let result = BrowserHistoryParser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    assert_eq!(records.len(), 2);
    let start = records
        .iter()
        .find(|a| a.metadata["title"] == "Start")
        .expect("the first visit");
    let landed = records
        .iter()
        .find(|a| a.metadata["title"] == "Landed")
        .expect("the redirected visit");

    // Both visits share a whole second, so `visit_time` alone cannot say which
    // page was reached first — the fraction is the entire ordering signal.
    let base = 720_000_000 + 978_307_200;
    assert_eq!(start.metadata["visit_time"].as_i64(), Some(base));
    assert_eq!(landed.metadata["visit_time"].as_i64(), Some(base));
    assert_eq!(
        start.metadata["visit_time_us"].as_i64(),
        Some(base * 1_000_000 + 250_000)
    );
    assert_eq!(
        landed.metadata["visit_time_us"].as_i64(),
        Some(base * 1_000_000 + 750_000)
    );
    assert!(
        start.metadata["visit_time_us"].as_i64() < landed.metadata["visit_time_us"].as_i64(),
        "the redirect must still land after the page that issued it"
    );
}

fn create_chrome_cookie_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_ck_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '16');
             CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, \
             path TEXT, creation_utc INTEGER, expires_utc INTEGER, last_access_utc INTEGER, \
             is_secure INTEGER, is_httponly INTEGER);
             INSERT INTO cookies VALUES ('.example.com', 'sid', '', X'DEADBEEF', '/', \
               13300000000000000, 13400000000000000, 13300000005000000, 1, 1);
             INSERT INTO cookies VALUES ('shop.test', 'cart', 'abc123', X'', '/', \
               13300000000000000, 13400000000000000, 13300000005000000, 0, 0);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn create_firefox_cookie_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ff_ck_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 12;
             CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, \
             creationTime INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER);
             INSERT INTO moz_cookies VALUES ('.mozilla.org', 'pref', 'darkmode', '/', \
               1893456000, 1700000000000000, 1700000100000000, 1, 0);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn test_chrome_cookie_parsing() {
    let parser = BrowserHistoryParser;
    let data = create_chrome_cookie_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Cookies" }),
    );

    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 2);
    for r in &records {
        assert_eq!(r.metadata["type"], "BrowserCookie");
        assert_eq!(r.metadata["browser"], "Chrome/Edge");
    }
    // Encrypted cookie: empty value, flagged encrypted, no `value` field.
    let sid = records
        .iter()
        .find(|a| a.metadata["cookie_name"] == "sid")
        .unwrap();
    assert_eq!(sid.metadata["value_encrypted"], true);
    assert!(sid.metadata.get("value").is_none());
    assert_eq!(sid.metadata["is_secure"], true);
    assert!(sid.metadata["creation_time"].as_i64().unwrap() > 0);
    // Plaintext cookie: value present, not encrypted.
    let cart = records
        .iter()
        .find(|a| a.metadata["cookie_name"] == "cart")
        .unwrap();
    assert_eq!(cart.metadata["value_encrypted"], false);
    assert_eq!(cart.metadata["value"], "abc123");
}

#[test]
fn test_firefox_cookie_parsing() {
    let parser = BrowserHistoryParser;
    let data = create_firefox_cookie_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "cookies.sqlite" }),
    );

    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 1);
    let c = &records[0];
    assert_eq!(c.metadata["type"], "BrowserCookie");
    assert_eq!(c.metadata["browser"], "Firefox");
    assert_eq!(c.metadata["value"], "darkmode"); // Firefox values are plaintext
    assert_eq!(c.metadata["value_encrypted"], false);
    assert_eq!(c.metadata["expiry_time"], 1893456000);
    assert!(c.metadata["creation_time"].as_i64().unwrap() > 0);
}

fn create_chrome_webdata_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_webdata_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '98');
             CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER, date_created INTEGER, date_last_used INTEGER);
             INSERT INTO autofill VALUES ('email', 'jane@example.com', 4, 1700000000, 1700500000);
             INSERT INTO autofill VALUES ('search', 'forensics', 2, 1700100000, 1700200000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn create_firefox_formhistory_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ffform_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 5;
             CREATE TABLE moz_formhistory (fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER);
             INSERT INTO moz_formhistory VALUES ('username', 'jdoe', 7, 1700000000000000, 1700500000000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn test_chrome_autofill_parsing() {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_chrome_webdata_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Web Data" }),
    );
    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 2);
    let email = records
        .iter()
        .find(|a| a.metadata["field_name"] == "email")
        .unwrap();
    assert_eq!(email.metadata["type"], "BrowserAutofill");
    assert_eq!(email.metadata["browser"], "Chrome/Edge");
    assert_eq!(email.metadata["value"], "jane@example.com");
    assert_eq!(email.metadata["use_count"], 4);
    assert_eq!(email.metadata["first_used"], 1700000000);
}

#[test]
fn test_firefox_formhistory_parsing() {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(create_firefox_formhistory_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "formhistory.sqlite" }),
    );
    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.metadata["type"], "BrowserAutofill");
    assert_eq!(r.metadata["browser"], "Firefox");
    assert_eq!(r.metadata["field_name"], "username");
    assert_eq!(r.metadata["value"], "jdoe");
    assert_eq!(r.metadata["use_count"], 7);
    assert_eq!(r.metadata["first_used"], 1700000000); // µs -> s
}

fn create_chrome_login_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_login_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '31');
             CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, \
             date_created INTEGER, date_last_used INTEGER, times_used INTEGER);
             INSERT INTO logins VALUES ('https://bank.example/login', 'jdoe', X'DEADBEEF', \
               13300000000000000, 13300000500000000, 9);
             INSERT INTO logins VALUES ('https://mail.test', 'jane@test', X'', \
               13300000000000000, 0, 0);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn test_chrome_logins_parsing() {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_chrome_login_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Login Data" }),
    );
    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 2);

    let bank = records
        .iter()
        .find(|a| a.metadata["username"] == "jdoe")
        .unwrap();
    assert_eq!(bank.metadata["type"], "BrowserLogin");
    assert_eq!(bank.metadata["browser"], "Chrome/Edge");
    assert_eq!(bank.metadata["origin_url"], "https://bank.example/login");
    assert_eq!(bank.metadata["has_saved_password"], true);
    assert_eq!(bank.metadata["password_encrypted"], true);
    assert_eq!(bank.metadata["times_used"], 9);
    // No password field is ever emitted.
    assert!(bank.metadata.get("password").is_none());
    assert!(bank.metadata.get("password_value").is_none());

    let mail = records
        .iter()
        .find(|a| a.metadata["username"] == "jane@test")
        .unwrap();
    assert_eq!(mail.metadata["has_saved_password"], false);
}

#[test]
fn test_firefox_session_parsing() {
    let json = r#"{"windows":[{"tabs":[
        {"entries":[{"url":"https://a.example","title":"A old"},{"url":"https://a.example/now","title":"A now"}],"index":2},
        {"entries":[{"url":"https://b.example","title":"B"}],"index":1}
    ]}]}"#;
    // mozLz4 container: "mozLz40\0" + u32 LE decompressed size + LZ4 block.
    let compressed = lz4_flex::block::compress(json.as_bytes());
    let mut data = b"mozLz40\0".to_vec();
    data.extend_from_slice(&(json.len() as u32).to_le_bytes());
    data.extend_from_slice(&compressed);

    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "sessionstore.jsonlz4" }),
    );
    let records = parser.process(&artifact).unwrap();
    assert_eq!(records.len(), 2);

    // Tab 1's current entry is index 2 -> the "now" URL.
    let a = records
        .iter()
        .find(|r| r.metadata["title"] == "A now")
        .unwrap();
    assert_eq!(a.metadata["type"], "BrowserSession");
    assert_eq!(a.metadata["browser"], "Firefox");
    assert_eq!(a.metadata["url"], "https://a.example/now");
    assert_eq!(a.metadata["window"], 1);

    let b = records
        .iter()
        .find(|r| r.metadata["url"] == "https://b.example")
        .unwrap();
    assert_eq!(b.metadata["title"], "B");
}

#[test]
fn test_firefox_session_bad_magic_is_ignored() {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"not a mozlz4 file".to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "sessionstore.jsonlz4" }),
    );
    assert!(parser.process(&artifact).unwrap().is_empty());
}

#[test]
fn test_invalid_sqlite_graceful_handling() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    // Not a valid SQLite file
    let data = vec![0u8; 1024];
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History"}),
    );

    let result = parser.process(&artifact).unwrap();
    // Should either produce a ParseFailed identification or empty results
    // (rusqlite may open the file but find no tables -> 0 records)
    for a in &result {
        assert_eq!(a.metadata["browser"], "Chrome/Edge");
    }
}

#[test]
fn test_webkit_timestamp_conversion() {
    // WebKit epoch: microseconds since 1601-01-01
    // 13300000000000000 - 11644473600000000 = 1655526400000000 us = 1655526400 unix
    assert_eq!(webkit_us_to_unix_secs(13300000000000000), Some(1655526400));

    // 0 means "unset" and must not become the year 1601/1970
    assert_eq!(webkit_us_to_unix_secs(0), None);

    // Full microsecond precision is preserved by the _us variant
    assert_eq!(
        webkit_us_to_unix_us(13300000000123456),
        Some(1655526400123456)
    );
    assert_eq!(webkit_us_to_unix_us(0), None);
}

#[test]
fn test_webkit_pre_epoch_is_rejected_not_negated() {
    // A stored value below the 1601->1970 gap is before the Unix epoch: it is a
    // corrupt/partially-written field, not a 17th-century browser visit. The
    // shared converter omits it rather than emitting a negative Unix time.
    assert_eq!(webkit_us_to_unix_secs(1_000), None);
    assert_eq!(webkit_us_to_unix_us(1_000), None);
    assert_eq!(webkit_us_to_unix_secs(-1), None);
    // The boundary itself (exactly 1970-01-01) is on the accepted side.
    assert_eq!(webkit_us_to_unix_secs(11_644_473_600_000_000), Some(0));
    assert_eq!(webkit_us_to_unix_us(11_644_473_600_000_000), Some(0));
    // One microsecond below it is not.
    assert_eq!(webkit_us_to_unix_secs(11_644_473_599_999_999), None);
}

#[test]
fn test_prtime_timestamp_conversion() {
    // Firefox PRTime: microseconds since the Unix epoch
    assert_eq!(prtime_to_unix_secs(1700000000123456), Some(1700000000));
    assert_eq!(prtime_to_unix_secs(0), None);
    // Negative PRTime is an unset/corrupt field, not a pre-1970 visit.
    assert_eq!(prtime_to_unix_secs(-1), None);
}

#[test]
fn test_chrome_visit_time_microseconds_preserved() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_chrome_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History"}),
    );

    let result = parser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    // Most recent visit: 13300000100000000 -> unix us 1655526500000000
    assert_eq!(
        records[0].metadata["visit_time_us"].as_i64(),
        Some(1655526500000000)
    );
    assert_eq!(records[0].metadata["visit_time"].as_i64(), Some(1655526500));
}

#[test]
fn test_firefox_visit_time_microseconds_preserved() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_firefox_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "places.sqlite"}),
    );

    let result = parser.process(&artifact).unwrap();
    let records: Vec<&Artifact> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    // Most recent visit: PRTime 1700000100000000 us
    assert_eq!(
        records[0].metadata["visit_time_us"].as_i64(),
        Some(1700000100000000)
    );
    assert_eq!(records[0].metadata["visit_time"].as_i64(), Some(1700000100));
}

#[test]
fn test_truncate_url_multibyte_no_panic() {
    // A raw multibyte (IRI) URL must not panic when the cut lands mid-character.
    let url = "https://例え.テスト/".repeat(10); // multibyte chars around byte 80
    let truncated = truncate_url(&url, 80);
    // Must be a valid str prefix, cut on a char boundary, no panic.
    assert!(url.starts_with(truncated));
    assert!(truncated.len() <= 80);
    // ASCII URLs shorter than the cap are returned unchanged.
    assert_eq!(truncate_url("https://a.com", 80), "https://a.com");
}

#[test]
fn test_coredata_timestamp_conversion() {
    // 0.0 (and negatives) are the unset sentinel — must be None, not surfaced
    // as 2001-01-01.
    assert_eq!(cocoa_secs_to_unix_nanos(0.0), None);
    assert_eq!(cocoa_secs_to_unix_nanos(-5.0), None);
    // A real Core Data timestamp: seconds since 2001 -> Unix +978307200.
    assert_eq!(
        cocoa_secs_to_unix_nanos(700_000_000.0),
        Some((700_000_000 + 978_307_200, 0))
    );
    // Safari's `visit_time` is REAL: the fraction is decoded and carried into
    // the microseconds the record publishes.
    assert_eq!(
        cocoa_secs_to_unix_nanos(700_000_000.25),
        Some((700_000_000 + 978_307_200, 250_000_000))
    );
    assert_eq!(
        safari_visit_us((700_000_000 + 978_307_200, 250_000_000)),
        Some((700_000_000 + 978_307_200) * 1_000_000 + 250_000)
    );
    // A whole second still yields microseconds, so the field is present on
    // every dated visit rather than only on the fractional ones.
    assert_eq!(
        safari_visit_us((700_000_000 + 978_307_200, 0)),
        Some((700_000_000 + 978_307_200) * 1_000_000)
    );
}

#[test]
fn test_firefox_transition_names() {
    assert_eq!(firefox_transition_name(1), "link");
    assert_eq!(firefox_transition_name(2), "typed");
    assert_eq!(firefox_transition_name(7), "download");
    assert_eq!(firefox_transition_name(99), "other");
}

#[test]
fn test_chrome_transition_names() {
    assert_eq!(chrome_transition_name(0), "link");
    assert_eq!(chrome_transition_name(1), "typed");
    assert_eq!(chrome_transition_name(7), "form_submit");
    assert_eq!(chrome_transition_name(999), "other");
}

#[test]
fn test_parent_id_chain() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();
    let data = create_chrome_test_db();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "History"}),
    );

    let parent_id = artifact.id;
    let result = parser.process(&artifact).unwrap();
    // Both parsed records and timeline events chain to the source artifact.
    for record in &result {
        assert_eq!(record.parent_id, Some(parent_id));
        assert_eq!(record.case_id, case_id);
        assert!(matches!(
            record.artifact_type,
            ArtifactType::ParsedRecord | ArtifactType::TimelineEvent
        ));
    }
}

#[test]
fn test_chrome_extensions_from_preferences() {
    let prefs = r#"{
      "extensions": { "settings": {
        "aaaabbbbccccddddeeeeffffgggghhhh": {
          "manifest": { "name": "uBlock Origin", "version": "1.5.0",
            "description": "content blocker", "permissions": ["tabs", "storage"] },
          "state": 1, "from_webstore": true, "path": "aaaabbbb/1.5.0",
          "install_time": "13300000000000000"
        },
        "iiiijjjjkkkkllllmmmmnnnnoooopppp": {
          "manifest": { "name": "Old Toolbar", "version": "0.1" },
          "state": 0, "from_webstore": false
        }
      } }
    }"#;
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(prefs.as_bytes().to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Preferences" }),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 2, "expected two extensions");

    let ublock = result
        .iter()
        .find(|a| a.metadata["extension_name"] == "uBlock Origin")
        .expect("uBlock record");
    assert_eq!(ublock.metadata["enabled"], true);
    assert_eq!(ublock.metadata["from_webstore"], true);
    assert_eq!(ublock.metadata["version"], "1.5.0");
    assert_eq!(
        ublock.metadata["extension_id"],
        "aaaabbbbccccddddeeeeffffgggghhhh"
    );
    // 13300000000000000 WebKit us -> 1655526400 Unix seconds.
    assert_eq!(
        ublock.metadata["install_time"].as_i64(),
        Some(1_655_526_400)
    );
    let perms = ublock.metadata["permissions"].as_array().unwrap();
    assert!(perms.iter().any(|p| p == "tabs"));

    let old = result
        .iter()
        .find(|a| a.metadata["extension_name"] == "Old Toolbar")
        .expect("Old Toolbar record");
    assert_eq!(old.metadata["enabled"], false);
}

#[test]
fn test_preferences_without_extensions_is_ignored() {
    // A file named "Preferences" that isn't a Chrome/Edge profile yields nothing.
    let parser = BrowserHistoryParser;
    for body in [
        r#"{"unrelated":"data"}"#,
        r#"{"extensions":{"other":1}}"#,
        "not json",
    ] {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(body.as_bytes().to_vec()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "Preferences" }),
        );
        assert!(
            parser.process(&artifact).unwrap().is_empty(),
            "non-profile Preferences should be ignored: {body}"
        );
    }
}

// ── BUG-223 / BUG-230: download origin URL and login password honesty ────────

/// Chrome History DB carrying a `downloads` table plus the extra SQL the caller
/// supplies (url-chain table, drift, etc).
fn create_chrome_downloads_db(extra_sql: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_dl_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);",
        )
        .unwrap();
        conn.execute_batch(extra_sql).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn run_history(bytes: Vec<u8>) -> Vec<Artifact> {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "History" }),
    );
    parser.process(&artifact).unwrap()
}

const DOWNLOADS_TABLE: &str = "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, \
     tab_url TEXT, total_bytes INTEGER, start_time INTEGER, end_time INTEGER, \
     danger_type INTEGER, opened INTEGER);
     INSERT INTO downloads VALUES (1, '/Users/x/Downloads/tool.exe', 'https://blog.example/post', \
       1024, 13300000000000000, 13300000010000000, 0, 1);";

#[test]
fn test_chrome_download_source_url_comes_from_url_chain() {
    let records = run_history(create_chrome_downloads_db(&format!(
        "{DOWNLOADS_TABLE}
         CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
         INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.example/redirect');
         INSERT INTO downloads_url_chains VALUES (1, 1, 'https://files.example/tool.exe');"
    )));

    let dl = records
        .iter()
        .find(|a| a.metadata["type"] == "BrowserDownload")
        .expect("download record");
    // The bytes came from the LAST hop, not the initiating tab.
    assert_eq!(dl.metadata["source_url"], "https://files.example/tool.exe");
    assert_eq!(dl.metadata["source_url_origin"], "url_chain_final");
    assert_eq!(
        dl.metadata["url_chain_start"],
        "https://cdn.example/redirect"
    );
    // The initiating tab is still recorded, under its own name.
    assert_eq!(dl.metadata["tab_url"], "https://blog.example/post");
}

#[test]
fn test_chrome_download_falls_back_to_tab_url_without_chain_table() {
    let records = run_history(create_chrome_downloads_db(DOWNLOADS_TABLE));

    let dl = records
        .iter()
        .find(|a| a.metadata["type"] == "BrowserDownload")
        .expect("download record");
    assert_eq!(dl.metadata["source_url"], "https://blog.example/post");
    // The fallback is labelled, so the origin is never mistaken for the real
    // download URL.
    assert_eq!(dl.metadata["source_url_origin"], "tab_url");
}

#[test]
fn test_chrome_login_without_blob_is_not_reported_encrypted() {
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_chrome_login_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Login Data" }),
    );
    let records = parser.process(&artifact).unwrap();

    let mail = records
        .iter()
        .find(|a| a.metadata["username"] == "jane@test")
        .unwrap();
    // No stored blob -> nothing is encrypted; claiming otherwise implied a
    // sealed secret that does not exist (BUG-230).
    assert_eq!(mail.metadata["has_saved_password"], false);
    assert_eq!(mail.metadata["password_encrypted"], false);

    let bank = records
        .iter()
        .find(|a| a.metadata["username"] == "jdoe")
        .unwrap();
    assert_eq!(bank.metadata["password_encrypted"], true);
}

// --- B2-125: caps that report themselves --------------------------------
//
// Every walk in this crate binds `MAX_HISTORY_ENTRIES` as a bare `LIMIT`. A
// query that returns exactly the cap looks identical whether the table held
// that many rows or ten million, and the walks are newest-first, so the rows
// dropped are the OLDEST. An examiner reading such a listing would conclude a
// site was never visited, a cookie never set, a login never saved. These tests
// pin the probe-row detection and the `parse_incomplete` marker that makes the
// truncation visible; against the unfixed code every one of them fails because
// no marker is produced at all.

/// Open database bytes read-only. The returned `TempDb` must be kept alive for
/// as long as the connection is used; dropping it removes the spill.
fn open_db(bytes: &[u8]) -> (TempDb, Connection) {
    let temp = TempDb::write(bytes, "captest").unwrap();
    let conn = temp.open().unwrap();
    (temp, conn)
}

/// The `parse_incomplete` markers in an artifact set.
fn incomplete_markers(artifacts: &[Artifact]) -> Vec<&Artifact> {
    artifacts
        .iter()
        .filter(|a| a.metadata["subtype"] == "parse_incomplete")
        .collect()
}

/// Records carrying the given `subtype`.
fn records_of(artifacts: &[Artifact], subtype: &str) -> usize {
    artifacts
        .iter()
        .filter(|a| a.metadata["subtype"] == subtype)
        .count()
}

/// Assert exactly one marker, naming the right record class and table.
fn assert_single_marker(artifacts: &[Artifact], record_type: &str, source_table: &str, cap: usize) {
    let markers = incomplete_markers(artifacts);
    assert_eq!(
        markers.len(),
        1,
        "a walk that stopped at its cap must emit exactly one marker, got {}",
        markers.len()
    );
    let m = markers[0];
    assert_eq!(m.metadata["type"], record_type);
    assert_eq!(m.metadata["source_table"], source_table);
    assert_eq!(m.metadata["status"], "CapReached");
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(m.metadata["truncated"], true);
    assert_eq!(m.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(m.metadata["max_entries"], cap);
    assert_eq!(m.artifact_type, ArtifactType::ParsedRecord);
}

#[test]
fn chrome_visit_cap_is_flagged_and_an_exact_fit_is_not() {
    let (_spill, conn) = open_db(&create_chrome_test_db());
    let case = Uuid::new_v4();
    let parent = Uuid::new_v4();

    // The fixture holds three visits.
    let capped = parse_chrome(&conn, case, parent, 2).unwrap();
    assert_eq!(records_of(&capped, "browser_visit"), 2);
    assert_single_marker(&capped, "BrowserHistoryIncomplete", "visits", 2);
    assert_eq!(incomplete_markers(&capped)[0].parent_id, Some(parent));
    // The marker must NOT reuse the walk's own record type: seance_db groups
    // ParsedRecords by `metadata.$.type`, so "BrowserHistory" here would file
    // the marker as a browsing record.
    assert_ne!(
        incomplete_markers(&capped)[0].metadata["type"],
        "BrowserHistory"
    );

    // Exactly the cap is not truncation — otherwise the marker means nothing.
    let exact = parse_chrome(&conn, case, parent, 3).unwrap();
    assert_eq!(records_of(&exact, "browser_visit"), 3);
    assert!(incomplete_markers(&exact).is_empty());

    // Room to spare is likewise unmarked.
    let roomy = parse_chrome(&conn, case, parent, 50).unwrap();
    assert!(incomplete_markers(&roomy).is_empty());
}

/// A Chrome profile whose `visits` table is absent, driving the `urls`
/// fallback walk.
fn create_chrome_urls_only_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_urls_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             INSERT INTO urls VALUES (1, 'https://a.example', 'A', 1, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://b.example', 'B', 1, 13300000100000000);
             INSERT INTO urls VALUES (3, 'https://c.example', 'C', 1, 13300000200000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn chrome_urls_fallback_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_chrome_urls_only_db());
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_visit"), 2);
    assert_single_marker(&out, "BrowserHistoryIncomplete", "urls", 2);
}

#[test]
fn chrome_downloads_cap_is_flagged() {
    let bytes = create_chrome_downloads_db(
        "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, \
           total_bytes INTEGER, start_time INTEGER, end_time INTEGER, danger_type INTEGER, \
           opened INTEGER);
         INSERT INTO downloads VALUES (1, '/d/one.exe', 'https://one.example', 1, \
           13300000000000000, 13300000010000000, 0, 0);
         INSERT INTO downloads VALUES (2, '/d/two.exe', 'https://two.example', 2, \
           13300000100000000, 13300000110000000, 0, 0);
         INSERT INTO downloads VALUES (3, '/d/three.exe', 'https://three.example', 3, \
           13300000200000000, 13300000210000000, 0, 0);",
    );
    let (_spill, conn) = open_db(&bytes);
    let sql = "SELECT d.target_path, d.tab_url, d.total_bytes, d.start_time, d.end_time, \
               d.danger_type, d.opened, NULL, NULL, NULL FROM downloads d \
               ORDER BY d.start_time DESC LIMIT ?1";
    let out = download_records(&conn, sql, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_download"), 2);
    assert_single_marker(&out, "BrowserDownloadIncomplete", "downloads", 2);

    // Newest-first, so the oldest download is the one lost.
    let kept: Vec<&str> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "browser_download")
        .map(|a| a.metadata["target_path"].as_str().unwrap())
        .collect();
    assert_eq!(kept, vec!["/d/three.exe", "/d/two.exe"]);
}

#[test]
fn firefox_visit_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_firefox_test_db());
    let out = parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_visit"), 2);
    assert_single_marker(&out, "BrowserHistoryIncomplete", "moz_historyvisits", 2);
}

/// A Firefox profile with no `moz_historyvisits`, driving the places fallback.
fn create_firefox_places_only_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ff_places_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://a.example', 'A', 1, 1700000000000000);
             INSERT INTO moz_places VALUES (2, 'https://b.example', 'B', 1, 1700000100000000);
             INSERT INTO moz_places VALUES (3, 'https://c.example', 'C', 1, 1700000200000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn firefox_places_fallback_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_firefox_places_only_db());
    let out = parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_visit"), 2);
    assert_single_marker(&out, "BrowserHistoryIncomplete", "moz_places", 2);
}

/// A Firefox profile with a bookmark inventory joined to places.
fn create_firefox_bookmarks_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_ff_bm_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://a.example', 'A', 0, 0);
             INSERT INTO moz_places VALUES (2, 'https://b.example', 'B', 0, 0);
             INSERT INTO moz_places VALUES (3, 'https://c.example', 'C', 0, 0);
             INSERT INTO moz_bookmarks VALUES (1, 1, 1, 'A', 1700000000000000, 1700000000000000);
             INSERT INTO moz_bookmarks VALUES (2, 1, 2, 'B', 1700000100000000, 1700000100000000);
             INSERT INTO moz_bookmarks VALUES (3, 1, 3, 'C', 1700000200000000, 1700000200000000);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

/// The resolved plans a direct `bookmark_records` call needs, from a fixture
/// whose columns all resolve.
fn firefox_bookmark_plans(conn: &Connection) -> (ColumnPlan, ColumnPlan) {
    let places = plan_columns(conn, "moz_places", FIREFOX_PLACES, &[]).unwrap();
    let bookmarks = plan_columns(conn, "moz_bookmarks", FIREFOX_BOOKMARKS, &[]).unwrap();
    assert!(places.missing_required().is_empty() && bookmarks.missing_required().is_empty());
    (places, bookmarks)
}

#[test]
fn firefox_bookmark_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_firefox_bookmarks_db());
    let (places, bookmarks) = firefox_bookmark_plans(&conn);
    let out = bookmark_records(
        &conn,
        &places,
        &bookmarks,
        Uuid::new_v4(),
        Uuid::new_v4(),
        2,
    )
    .unwrap();
    assert_eq!(records_of(&out, "browser_bookmark"), 2);
    assert_single_marker(&out, "BrowserBookmarkIncomplete", "moz_bookmarks", 2);
}

#[test]
fn firefox_bookmark_table_that_cannot_be_read_is_reported_not_dropped() {
    // A `moz_bookmarks` whose schema has drifted (no `fk` column) used to be
    // swallowed by `if let Ok(..)` on both the prepare and the query, so a
    // profile with unreadable bookmarks rendered exactly like one with none.
    // It is now declared by field, before any query is written.
    let temp_path = std::env::temp_dir().join(format!("test_ff_bmbad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, title TEXT);
             INSERT INTO moz_places VALUES (1, 'https://a.example', 'A', 1, 1700000000000000);
             INSERT INTO moz_historyvisits VALUES (1, 1, 1700000000000000, 1);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 100).unwrap();
    assert_eq!(
        records_of(&out, "browser_visit"),
        1,
        "history records survive a bookmarks-table failure"
    );
    let declared = out
        .iter()
        .find(|a| a.metadata["type"] == "ParserStaleWarning")
        .expect("a bookmarks table that cannot be read must say so");
    assert_eq!(declared.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(declared.metadata["source_table"], "moz_bookmarks");
    assert_eq!(
        declared.metadata["unresolved_fields"],
        json!(["fk", "type", "dateAdded", "lastModified"])
    );
    assert_eq!(declared.metadata["content_incomplete"], true);
}

#[test]
fn safari_visit_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_safari_test_db());
    let out = parse_safari(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_visit"), 2);
    assert_single_marker(&out, "BrowserHistoryIncomplete", "history_visits", 2);
}

#[test]
fn safari_items_fallback_cap_is_flagged() {
    let temp_path = std::env::temp_dir().join(format!("test_safari_items_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 15;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             INSERT INTO history_items VALUES (1, 'https://a.example', 9);
             INSERT INTO history_items VALUES (2, 'https://b.example', 5);
             INSERT INTO history_items VALUES (3, 'https://c.example', 1);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_safari(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&out, "browser_visit"), 2);
    assert_single_marker(&out, "BrowserHistoryIncomplete", "history_items", 2);
}

#[test]
fn chrome_cookie_cap_is_flagged_and_the_surviving_rows_are_deterministic() {
    // The cookie query had no ORDER BY, so which cookies survived the cap was
    // whatever order SQLite happened to return — two runs over the same
    // evidence could name different sites.
    let bytes = create_chrome_cookie_db();
    let (_spill, conn) = open_db(&bytes);

    let first = parse_chrome_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(records_of(&first, "browser_cookie"), 1);
    assert_single_marker(&first, "BrowserCookieIncomplete", "cookies", 1);

    let host_of = |a: &[Artifact]| -> String {
        a.iter()
            .find(|x| x.metadata["subtype"] == "browser_cookie")
            .unwrap()
            .metadata["host"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // Both fixture rows share a creation_utc, so the host/name/path tiebreak
    // decides — and must decide the same way every run.
    let second = parse_chrome_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(host_of(&first), ".example.com");
    assert_eq!(host_of(&first), host_of(&second));

    let whole = parse_chrome_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 2).unwrap();
    assert_eq!(records_of(&whole, "browser_cookie"), 2);
    assert!(incomplete_markers(&whole).is_empty());
}

#[test]
fn firefox_cookie_cap_is_flagged_and_ordered() {
    let temp_path = std::env::temp_dir().join(format!("test_ff_ck2_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 12;
             CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, \
             creationTime INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER);
             INSERT INTO moz_cookies VALUES ('.old.example', 'a', 'v', '/', 0, 1700000000000000, 0, 0, 0);
             INSERT INTO moz_cookies VALUES ('.new.example', 'b', 'v', '/', 0, 1700000200000000, 0, 0, 0);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_firefox_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(records_of(&out, "browser_cookie"), 1);
    assert_single_marker(&out, "BrowserCookieIncomplete", "moz_cookies", 1);
    // Newest-created-first: the cookie kept is the recent one, deterministically.
    let kept = out
        .iter()
        .find(|a| a.metadata["subtype"] == "browser_cookie")
        .unwrap();
    assert_eq!(kept.metadata["host"], ".new.example");
}

#[test]
fn chrome_login_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_chrome_login_db());
    let out = parse_chrome_logins(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(records_of(&out, "browser_login"), 1);
    assert_single_marker(&out, "BrowserLoginIncomplete", "logins", 1);
}

#[test]
fn chrome_autofill_cap_is_flagged() {
    let (_spill, conn) = open_db(&create_chrome_webdata_db());
    let out = parse_chrome_autofill(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(records_of(&out, "browser_autofill"), 1);
    assert_single_marker(&out, "BrowserAutofillIncomplete", "autofill", 1);
    // Last-used-first, so the value kept is the most recently typed one.
    let kept = out
        .iter()
        .find(|a| a.metadata["subtype"] == "browser_autofill")
        .unwrap();
    assert_eq!(kept.metadata["value"], "jane@example.com");
}

#[test]
fn firefox_formhistory_cap_is_flagged() {
    let temp_path = std::env::temp_dir().join(format!("test_ffform2_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 5;
             CREATE TABLE moz_formhistory (fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER);
             INSERT INTO moz_formhistory VALUES ('username', 'jdoe', 7, 1700000000000000, 1700500000000000);
             INSERT INTO moz_formhistory VALUES ('search', 'old', 1, 1600000000000000, 1600000000000000);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_firefox_formhistory(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(records_of(&out, "browser_autofill"), 1);
    assert_single_marker(&out, "BrowserAutofillIncomplete", "moz_formhistory", 1);
    let kept = out
        .iter()
        .find(|a| a.metadata["subtype"] == "browser_autofill")
        .unwrap();
    assert_eq!(kept.metadata["value"], "jdoe");
}

#[test]
fn a_database_not_staged_in_full_marks_every_record_it_produced() {
    // The spill already knew the file was short; nothing carried that to the
    // records, so a partial profile parsed as a complete browsing history.
    let parser = BrowserHistoryParser;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(create_chrome_test_db()));
    let records = parser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "History" }),
        ))
        .unwrap();

    let visits: Vec<&Artifact> = records
        .iter()
        .filter(|a| a.metadata["subtype"] == "browser_visit")
        .collect();
    assert!(!visits.is_empty(), "the readable pages must still parse");
    for v in &visits {
        assert_eq!(v.metadata["content_incomplete"], true);
        assert_eq!(v.metadata["content_incomplete_reason"], "short_read");
    }
    let marker = records
        .iter()
        .find(|a| a.metadata["type"] == "SqliteSpillIncomplete")
        .expect("a short-staged database must append its own marker");
    assert_eq!(marker.metadata["file_name"], "History");
    assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
}

#[test]
fn a_whole_database_carries_no_incompleteness_at_all() {
    // The counterweight: if a complete parse were marked, the marks would mean
    // nothing on the truncated ones.
    let records = run_history(create_chrome_test_db());
    assert!(!records.is_empty());
    for r in &records {
        assert!(
            r.metadata.get("content_incomplete").is_none(),
            "a complete parse must leave every record unmarked"
        );
    }
    assert!(incomplete_markers(&records).is_empty());
}

// --- B3-010 residual: a capped walk must have a defined winner -----------
//
// The eight history / download / bookmark walks ordered on a timestamp alone
// (`visit_time`, `last_visit_time`, `visit_date`, `start_time`, `dateAdded`).
// Rows sharing a timestamp were then left in whatever order SQLite's sorter
// produced, so which of them survived the cap was undefined: two runs over
// identical evidence could disagree about which rows exist. Reproducibility is
// a baseline property of a forensic tool — an examiner has to be able to re-run
// and get the same listing.
//
// Every fixture below ties three rows on the timestamp and gives the
// URL-ordered winner the MIDDLE rowid, so neither scan direction produces the
// right answer by accident. Against the unfixed queries each of these keeps the
// `mid.example` row and fails.

/// The one URL a capped walk kept.
fn only_url(artifacts: &[Artifact], subtype: &str) -> String {
    let kept: Vec<&Artifact> = artifacts
        .iter()
        .filter(|a| a.metadata["subtype"] == subtype)
        .collect();
    assert_eq!(kept.len(), 1, "expected exactly one surviving record");
    kept[0].metadata["url"].as_str().unwrap().to_string()
}

/// Three Chrome visits at one instant, `aaa` in the middle of the rowid range.
fn create_chrome_tied_visits_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_tie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://mid.example', 'M', 1, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://aaa.example', 'A', 1, 13300000000000000);
             INSERT INTO urls VALUES (3, 'https://zzz.example', 'Z', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (2, 2, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (3, 3, 13300000000000000, 0, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

#[test]
fn chrome_visit_cap_boundary_tie_has_a_defined_winner() {
    let (_spill, conn) = open_db(&create_chrome_tied_visits_db());
    let first = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_url(&first, "browser_visit"), "https://aaa.example");
    let second = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(
        only_url(&first, "browser_visit"),
        only_url(&second, "browser_visit")
    );
}

#[test]
fn chrome_urls_fallback_cap_boundary_tie_has_a_defined_winner() {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_utie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             INSERT INTO urls VALUES (1, 'https://mid.example', 'M', 1, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://aaa.example', 'A', 1, 13300000000000000);
             INSERT INTO urls VALUES (3, 'https://zzz.example', 'Z', 1, 13300000000000000);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_url(&out, "browser_visit"), "https://aaa.example");
}

/// Three downloads started at one instant, `aaa` in the middle of the rowids.
const TIED_DOWNLOADS: &str = "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, \
     tab_url TEXT, total_bytes INTEGER, start_time INTEGER, end_time INTEGER, \
     danger_type INTEGER, opened INTEGER);
     INSERT INTO downloads VALUES (1, '/d/mid.bin', 'https://mid.example', 1, \
       13300000000000000, 13300000010000000, 0, 0);
     INSERT INTO downloads VALUES (2, '/d/aaa.bin', 'https://aaa.example', 1, \
       13300000000000000, 13300000010000000, 0, 0);
     INSERT INTO downloads VALUES (3, '/d/zzz.bin', 'https://zzz.example', 1, \
       13300000000000000, 13300000010000000, 0, 0);";

/// The one download target a capped walk kept.
fn only_download_target(artifacts: &[Artifact]) -> String {
    let kept: Vec<&Artifact> = artifacts
        .iter()
        .filter(|a| a.metadata["subtype"] == "browser_download")
        .collect();
    assert_eq!(kept.len(), 1, "expected exactly one surviving download");
    kept[0].metadata["target_path"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn chrome_download_cap_boundary_tie_has_a_defined_winner() {
    // Both SQL variants — with and without `downloads_url_chains` — carry the
    // same tiebreak, so the answer cannot depend on which schema is present.
    let no_chains = create_chrome_downloads_db(TIED_DOWNLOADS);
    let (_spill, conn) = open_db(&no_chains);
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_download_target(&out), "/d/aaa.bin");

    let with_chains = create_chrome_downloads_db(&format!(
        "{TIED_DOWNLOADS}
         CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
         INSERT INTO downloads_url_chains VALUES (1, 0, 'https://mid.example/f');
         INSERT INTO downloads_url_chains VALUES (2, 0, 'https://aaa.example/f');
         INSERT INTO downloads_url_chains VALUES (3, 0, 'https://zzz.example/f');"
    ));
    let (_spill2, conn2) = open_db(&with_chains);
    let out2 = parse_chrome(&conn2, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_download_target(&out2), "/d/aaa.bin");
}

#[test]
fn firefox_visit_cap_boundary_tie_has_a_defined_winner() {
    let temp_path = std::env::temp_dir().join(format!("test_ff_tie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mid.example', 'M', 1, 1700000000000000);
             INSERT INTO moz_places VALUES (2, 'https://aaa.example', 'A', 1, 1700000000000000);
             INSERT INTO moz_places VALUES (3, 'https://zzz.example', 'Z', 1, 1700000000000000);
             INSERT INTO moz_historyvisits VALUES (1, 1, 1700000000000000, 1);
             INSERT INTO moz_historyvisits VALUES (2, 2, 1700000000000000, 1);
             INSERT INTO moz_historyvisits VALUES (3, 3, 1700000000000000, 1);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_url(&out, "browser_visit"), "https://aaa.example");
}

#[test]
fn firefox_places_fallback_cap_boundary_tie_has_a_defined_winner() {
    let temp_path = std::env::temp_dir().join(format!("test_ff_ptie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mid.example', 'M', 1, 1700000000000000);
             INSERT INTO moz_places VALUES (2, 'https://aaa.example', 'A', 1, 1700000000000000);
             INSERT INTO moz_places VALUES (3, 'https://zzz.example', 'Z', 1, 1700000000000000);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_url(&out, "browser_visit"), "https://aaa.example");
}

#[test]
fn firefox_bookmark_cap_boundary_tie_has_a_defined_winner() {
    let temp_path = std::env::temp_dir().join(format!("test_ff_bmtie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mid.example', 'M', 0, 0);
             INSERT INTO moz_places VALUES (2, 'https://aaa.example', 'A', 0, 0);
             INSERT INTO moz_places VALUES (3, 'https://zzz.example', 'Z', 0, 0);
             INSERT INTO moz_bookmarks VALUES (1, 1, 1, 'M', 1700000000000000, 1700000000000000);
             INSERT INTO moz_bookmarks VALUES (2, 1, 2, 'A', 1700000000000000, 1700000000000000);
             INSERT INTO moz_bookmarks VALUES (3, 1, 3, 'Z', 1700000000000000, 1700000000000000);",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let (places, bookmarks) = firefox_bookmark_plans(&conn);
    let out = bookmark_records(
        &conn,
        &places,
        &bookmarks,
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
    )
    .unwrap();
    assert_eq!(only_url(&out, "browser_bookmark"), "https://aaa.example");
}

#[test]
fn safari_visit_cap_boundary_tie_has_a_defined_winner() {
    let temp_path = std::env::temp_dir().join(format!("test_sf_tie_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 15;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
             INSERT INTO history_items VALUES (1, 'https://mid.example', 1);
             INSERT INTO history_items VALUES (2, 'https://aaa.example', 1);
             INSERT INTO history_items VALUES (3, 'https://zzz.example', 1);
             INSERT INTO history_visits VALUES (1, 1, 720000000.0, 'M');
             INSERT INTO history_visits VALUES (2, 2, 720000000.0, 'A');
             INSERT INTO history_visits VALUES (3, 3, 720000000.0, 'Z');",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);

    let (_spill, conn) = open_db(&bytes);
    let out = parse_safari(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
    assert_eq!(only_url(&out, "browser_visit"), "https://aaa.example");
}

// --- B3-010: the two non-SQLite load sites -------------------------------
//
// `TempDb::spill` compares delivered bytes against declared bytes and
// `stamp_incompleteness` carries the answer onto every record, but the Firefox
// session store and the Chrome/Edge `Preferences` never go through a spill.
// Over the read ceiling, or short of the declared size, both returned an EMPTY
// artifact list — so "no tabs were open" / "no extensions were installed" and
// "we could not read this file" were the same answer. Against the unfixed code
// every test below sees zero records and fails.

/// Run the parser over a named file backed by `ds`.
fn run_named(name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    BrowserHistoryParser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        ))
        .unwrap()
}

/// The single incompleteness marker in an artifact set, with its shared fields
/// checked.
fn assert_file_marker<'a>(
    artifacts: &'a [Artifact],
    record_type: &str,
    file_name: &str,
    reason: &str,
) -> &'a Artifact {
    assert_eq!(
        artifacts.len(),
        1,
        "a file that could not be read must produce exactly its marker"
    );
    let m = &artifacts[0];
    assert_eq!(m.metadata["type"], record_type);
    assert_eq!(m.metadata["subtype"], "parse_incomplete");
    assert_eq!(m.metadata["status"], "FileNotReadInFull");
    assert_eq!(m.metadata["file_name"], file_name);
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(m.metadata["content_incomplete_reason"], reason);
    assert_eq!(m.metadata["inventory_incomplete"], true);
    assert_eq!(m.metadata["inventory_incomplete_reason"], reason);
    assert_eq!(m.artifact_type, ArtifactType::ParsedRecord);
    m
}

/// A valid `mozLz40` session container holding the given JSON.
fn mozlz4(json: &str) -> Vec<u8> {
    let mut data = b"mozLz40\0".to_vec();
    data.extend_from_slice(&(json.len() as u32).to_le_bytes());
    data.extend_from_slice(&lz4_flex::block::compress(json.as_bytes()));
    data
}

#[test]
fn session_file_past_the_read_ceiling_is_not_reported_as_no_open_tabs() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(Vec::new(), MAX_SESSION_BYTES + 1));
    let out = run_named("sessionstore.jsonlz4", ds);
    let m = assert_file_marker(
        &out,
        "BrowserSessionIncomplete",
        "sessionstore.jsonlz4",
        "cap_reached",
    );
    assert_eq!(m.metadata["declared_bytes"], MAX_SESSION_BYTES + 1);
    assert_eq!(m.metadata["bytes_read"], 0u64);
}

#[test]
fn session_file_that_under_delivers_is_not_reported_as_no_open_tabs() {
    // The source declares twice what it holds, so the tail of the LZ4 block is
    // missing. Unfixed, whatever arrived was decompressed and its tabs listed
    // as if the whole session had been recovered.
    let body =
        mozlz4(r#"{"windows":[{"tabs":[{"entries":[{"url":"https://a.example"}],"index":1}]}]}"#);
    let declared = (body.len() * 2) as u64;
    let read = body.len() as u64;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(body));
    let out = run_named("recovery.jsonlz4", ds);
    let m = assert_file_marker(
        &out,
        "BrowserSessionIncomplete",
        "recovery.jsonlz4",
        "short_read",
    );
    assert_eq!(m.metadata["declared_bytes"], declared);
    assert_eq!(m.metadata["bytes_read"], read);
}

#[test]
fn session_container_declaring_an_unusable_size_is_not_reported_as_no_open_tabs() {
    // Valid `mozLz40` magic, so this IS a session file; an empty return would
    // have asserted the profile had no open tabs.
    let mut data = b"mozLz40\0".to_vec();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(b"payload");
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let out = run_named("previous.jsonlz4", ds);
    assert_file_marker(
        &out,
        "BrowserSessionIncomplete",
        "previous.jsonlz4",
        "unresolved_structure",
    );
}

#[test]
fn preferences_past_the_read_ceiling_is_not_reported_as_no_extensions() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(Vec::new(), MAX_PREFS_BYTES + 1));
    let out = run_named("Preferences", ds);
    let m = assert_file_marker(
        &out,
        "BrowserExtensionIncomplete",
        "Preferences",
        "cap_reached",
    );
    assert_eq!(m.metadata["declared_bytes"], MAX_PREFS_BYTES + 1);
    assert_eq!(m.metadata["bytes_read"], 0u64);
}

#[test]
fn preferences_that_under_delivers_is_not_reported_as_no_extensions() {
    // Unfixed, the bytes that did arrive parsed as JSON and their extensions
    // were listed as the complete installed set.
    let prefs = r#"{"extensions":{"settings":{"aaaabbbbccccddddeeeeffffgggghhhh":{
        "manifest":{"name":"uBlock Origin","version":"1.5.0"},"state":1}}}}"#;
    let body = prefs.as_bytes().to_vec();
    let declared = (body.len() * 2) as u64;
    let read = body.len() as u64;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(body));
    let out = run_named("Secure Preferences", ds);
    let m = assert_file_marker(
        &out,
        "BrowserExtensionIncomplete",
        "Secure Preferences",
        "short_read",
    );
    assert_eq!(m.metadata["declared_bytes"], declared);
    assert_eq!(m.metadata["bytes_read"], read);
    assert!(
        m.metadata["detail"].as_str().unwrap().contains("inventory"),
        "the marker must say the extension inventory is what is missing"
    );
}

#[test]
fn a_whole_non_sqlite_browser_file_carries_no_incompleteness() {
    // The counterweight: if a complete read were marked, the marks on the
    // truncated ones would mean nothing.
    let session =
        mozlz4(r#"{"windows":[{"tabs":[{"entries":[{"url":"https://a.example"}],"index":1}]}]}"#);
    let tabs = run_named(
        "sessionstore.jsonlz4",
        Arc::new(ByteSliceDataSource::new(session)) as Arc<dyn DataSource>,
    );
    assert_eq!(tabs.len(), 1);
    assert!(incomplete_markers(&tabs).is_empty());
    assert!(tabs[0].metadata.get("content_incomplete").is_none());

    let prefs = r#"{"extensions":{"settings":{"aaaabbbbccccddddeeeeffffgggghhhh":{
        "manifest":{"name":"uBlock Origin","version":"1.5.0"},"state":1}}}}"#;
    let exts = run_named(
        "Preferences",
        Arc::new(ByteSliceDataSource::new(prefs.as_bytes().to_vec())) as Arc<dyn DataSource>,
    );
    assert_eq!(exts.len(), 1);
    assert!(incomplete_markers(&exts).is_empty());
    assert!(exts[0].metadata.get("content_incomplete").is_none());
}

// --- Adversarial review: the class instances the B3-010 sweep missed ------
//
// The sweep looked for load sites (`read_capped` / `.size()` / `TempDb::`) and
// for timestamp-only `ORDER BY`. It did not look for the third shape of the same
// defect: a READ THAT FAILED being converted into a NEGATIVE FINDING. Two of
// those were left, both of which end with the orchestrator logging a COMPLETED
// run that produced zero records — the strongest possible "this device held
// nothing" an examiner can be handed.

/// The one marker in an artifact set that says a file was never read at all.
fn assert_unread_marker<'a>(
    artifacts: &'a [Artifact],
    record_type: &str,
    file_name: &str,
) -> &'a Artifact {
    let markers = incomplete_markers(artifacts);
    assert_eq!(
        markers.len(),
        1,
        "a file that was never read must produce exactly its marker"
    );
    let m = markers[0];
    assert_eq!(m.metadata["type"], record_type);
    assert_eq!(m.metadata["status"], "FileNotRead");
    assert_eq!(m.metadata["file_name"], file_name);
    assert_eq!(m.metadata["content_incomplete"], true);
    assert_eq!(
        m.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(m.metadata["inventory_incomplete"], true);
    // The sentence has to land where the examiner-facing reader shows it.
    // `frontend/src/lib/incompleteness.ts` takes it from `<flag>_detail` and
    // reads nothing named `detail`, so this marker used to reach the examiner
    // as the bare token "unresolved_structure".
    let detail = m.metadata["detail"]
        .as_str()
        .expect("the marker explains itself");
    assert_eq!(m.metadata["content_incomplete_detail"], json!(detail));
    assert_eq!(m.metadata["inventory_incomplete_detail"], json!(detail));
    // No byte counts: with no data source there was nothing to ask for a size,
    // and a `0` would read as "the file was empty".
    assert!(m.metadata.get("declared_bytes").is_none());
    assert!(m.metadata.get("bytes_read").is_none());
    m
}

/// An artifact with no attached data source, as an ad-hoc re-run loads it from
/// the database (`orchestrator.rs` only stamps a source on when the caller
/// resolved one).
fn run_without_data(name: &str) -> Vec<Artifact> {
    BrowserHistoryParser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": name }),
        ))
        .unwrap()
}

#[test]
fn a_session_file_with_no_data_source_is_not_reported_as_no_open_tabs() {
    // The SQLite branch has always emitted an identification record here. This
    // branch returned `Ok(vec![])`, which is indistinguishable from a profile
    // whose session store held no open tabs.
    let out = run_without_data("recovery.jsonlz4");
    assert_unread_marker(&out, "BrowserSessionIncomplete", "recovery.jsonlz4");
}

#[test]
fn a_preferences_file_with_no_data_source_is_not_reported_as_no_extensions() {
    let out = run_without_data("Secure Preferences");
    assert_unread_marker(&out, "BrowserExtensionIncomplete", "Secure Preferences");
}

/// Bytes that are not a SQLite database at all: a carved fragment, or a file
/// whose first page was overwritten. `sqlite3_open_v2` does not read page 1, so
/// the connection opens and the failure lands on the first statement.
fn not_a_database() -> Vec<u8> {
    vec![0u8; 1024]
}

#[test]
fn a_table_probe_that_cannot_be_answered_is_an_error_not_a_missing_table() {
    // `query_row(..).unwrap_or(false)` turned SQLITE_NOTADB into "the table is
    // not there", and every walk then returned `Ok(vec![])` with a `warn!`.
    let (_spill, conn) = open_db(&not_a_database());
    assert!(
        parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err(),
        "a database SQLite cannot read must not answer 'no urls table'"
    );
    assert!(
        parse_firefox(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err(),
        "a database SQLite cannot read must not answer 'no moz_places table'"
    );
    assert!(
        parse_safari(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err(),
        "a database SQLite cannot read must not answer 'no history_items table'"
    );
    assert!(parse_chrome_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err());
    assert!(parse_firefox_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err());
    assert!(parse_chrome_logins(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err());
    assert!(parse_chrome_autofill(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err());
    assert!(parse_firefox_formhistory(&conn, Uuid::new_v4(), Uuid::new_v4(), 10).is_err());
}

#[test]
fn a_history_file_sqlite_cannot_read_produces_a_record_not_silence() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(not_a_database()));
    let out = run_named("History", ds);
    let failed = out
        .iter()
        .find(|a| a.metadata["status"] == "ParseFailed")
        .expect("an unreadable database must be reported, not answered with zero records");
    assert_eq!(failed.metadata["browser"], "Chrome/Edge");
    assert!(!failed.metadata["error"].as_str().unwrap().is_empty());
}

#[test]
fn a_parse_failure_on_a_database_staged_short_says_the_file_was_short() {
    // Both halves of the same conclusion: the parse failed, AND we only hold
    // part of the file. Reporting the first without the second invites the
    // wrong finding — that the evidence itself is corrupt.
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(not_a_database()));
    let out = run_named("History", ds);
    let failed = out
        .iter()
        .find(|a| a.metadata["status"] == "ParseFailed")
        .expect("an unreadable database must be reported");
    assert_eq!(failed.metadata["content_incomplete"], true);
    // HUNT-186: the stamp no longer overwrites the record's own reason; the
    // short read joins it in `content_incomplete_reasons` and in the sentence
    // the screen shows, beside the spill's own marker below.
    let reasons = failed.metadata["content_incomplete_reasons"]
        .as_array()
        .expect("both reasons listed");
    assert!(reasons.iter().any(|r| r == "short_read"), "{reasons:?}");
    assert!(failed.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap_or_default()
        .contains("short_read"));
    assert!(
        out.iter()
            .any(|a| a.metadata["type"] == "SqliteSpillIncomplete"),
        "the spill's own marker must survive the failure path"
    );
}

/// A row that will not decode must be counted, not just logged.
///
/// What an examiner learns: whether a URL absent from the history listing was
/// never visited. A `visits` row whose `visit_time` is a blob rather than an
/// integer is skipped by the mapper; before this it left a `debug!` line and
/// nothing else, so the listing read as an exact account of the browsing
/// history (B4-008, B4-029).
#[test]
fn undecodable_chrome_visit_rows_are_counted_on_a_marker() {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_bad_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time BLOB, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (2, 1, x'deadbeef', 0, 1);"
        ).unwrap();
    }
    let conn = Connection::open(&temp_path).unwrap();
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1000).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&temp_path);

    let marker = out
        .iter()
        .find(|a| {
            a.metadata.get("status").and_then(|v| v.as_str()) == Some("RowsUndecodable")
                && a.metadata.get("source_table").and_then(|v| v.as_str()) == Some("visits")
        })
        .expect("a dropped visit row must leave a marker");

    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(marker.metadata["first_error"].is_string());
    assert_ne!(
        marker.metadata["type"], "BrowserHistory",
        "the marker must not group as a history record"
    );

    // The sound row is still recovered: counting a loss is not refusing the
    // evidence.
    assert!(out
        .iter()
        .any(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("BrowserHistory")));
}

/// The drop marker has to carry its sentence on the keys the examiner-facing
/// reader displays.
///
/// This crate built its own `RowDrops` rather than using the shared one, and the
/// copy had fallen behind: it stamped a bare `detail`, while
/// `frontend/src/lib/incompleteness.ts` keys the parser's sentence off
/// `<flag>_detail`. So every browser walk that lost a row told the examiner
/// "unresolved structure" and nothing else — not the table, not the count, not
/// the decoder's reason. Against the unfixed crate both assertions here fail.
#[test]
fn a_dropped_browser_row_explains_itself_on_the_keys_the_reader_shows() {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_detail_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time BLOB, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (2, 1, x'deadbeef', 0, 1);"
        ).unwrap();
    }
    let conn = Connection::open(&temp_path).unwrap();
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1000).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&temp_path);

    let marker = out
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a dropped visit row must leave a marker");

    let detail = marker.metadata["detail"]
        .as_str()
        .expect("the marker explains itself");
    assert!(detail.contains("visits"), "{detail}");
    assert_eq!(marker.metadata["content_incomplete_detail"], json!(detail));
    assert_eq!(
        marker.metadata["inventory_incomplete_detail"],
        json!(detail)
    );

    // `records_recovered` counts the records the examiner can see, not the
    // artifacts the walk produced. One visit row survived; it emits a
    // ParsedRecord AND a TimelineEvent for the same visit, and the old count
    // was `artifacts.len()` taken after the cap marker had been pushed — so a
    // one-record walk claimed two.
    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(
        marker.metadata["records_recovered"],
        json!(1),
        "the marker must count browsing records, not timeline events"
    );
    assert_eq!(
        out.iter()
            .filter(|a| a.metadata["type"] == "BrowserHistory")
            .count(),
        1
    );
}

/// The same obligation on a walk that is not the history one, because the
/// scaffolding is now shared and a fix that only reached one walk is exactly
/// what went wrong here before.
#[test]
fn a_dropped_cookie_row_explains_itself_the_same_way() {
    let temp_path = std::env::temp_dir().join(format!("test_ck_detail_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '16');
             CREATE TABLE cookies (host_key BLOB, name TEXT, value TEXT, encrypted_value BLOB, \
             path TEXT, creation_utc INTEGER, expires_utc INTEGER, last_access_utc INTEGER, \
             is_secure INTEGER, is_httponly INTEGER);
             INSERT INTO cookies VALUES ('.example.com', 'sid', 'v', X'', '/', \
               13300000000000000, 13400000000000000, 13300000005000000, 1, 1);
             INSERT INTO cookies VALUES (X'DEADBEEF', 'other', 'v', X'', '/', \
               13200000000000000, 13400000000000000, 13300000005000000, 0, 0);",
        )
        .unwrap();
    }
    let conn = Connection::open(&temp_path).unwrap();
    let out = parse_chrome_cookies(&conn, Uuid::new_v4(), Uuid::new_v4(), 1000).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&temp_path);

    let marker = out
        .iter()
        .find(|a| a.metadata["status"] == "RowsUndecodable")
        .expect("a cookie row that will not decode must leave a marker");
    assert_eq!(marker.metadata["type"], "BrowserCookieIncomplete");
    assert_eq!(marker.metadata["source_table"], "cookies");
    assert_eq!(marker.metadata["rows_dropped"], json!(1));
    assert_eq!(marker.metadata["records_recovered"], json!(1));
    let detail = marker.metadata["detail"].as_str().unwrap();
    assert_eq!(marker.metadata["content_incomplete_detail"], json!(detail));
    assert_eq!(
        marker.metadata["inventory_incomplete_detail"],
        json!(detail)
    );
}

/// A clean database leaves no drop marker at all.
#[test]
fn a_clean_chrome_history_leaves_no_dropped_row_marker() {
    let temp_path = std::env::temp_dir().join(format!("test_chrome_ok_{}.db", Uuid::new_v4()));
    std::fs::write(&temp_path, create_chrome_test_db()).unwrap();
    let conn = Connection::open(&temp_path).unwrap();
    let out = parse_chrome(&conn, Uuid::new_v4(), Uuid::new_v4(), 1000).unwrap();
    drop(conn);
    let _ = std::fs::remove_file(&temp_path);

    assert!(
        !out.iter()
            .any(|a| a.metadata.get("status").and_then(|v| v.as_str()) == Some("RowsUndecodable")),
        "a sound database must not be flagged"
    );
}

/// **A failure must not be counted as a browsing record.** `seance_db` groups
/// `ParsedRecord`s by `metadata.$.type`, which is why `walk.rs` requires its
/// cap and undecodable-row markers to carry a `marker_type` different from the
/// walk's own records. Four records in this crate broke that rule directly:
/// the "no data source" identification record and the history parse failure
/// were typed `BrowserHistory`, and the Chrome-downloads and Firefox-bookmarks
/// failures were typed `BrowserDownload` and `BrowserBookmark`. A case with no
/// downloads and one unreadable downloads table then read as a case with one
/// download.
#[test]
fn a_parse_failure_is_not_typed_as_the_records_it_failed_to_produce() {
    // No data source: the file was identified and not read.
    let out = run_without_data("History");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["status"], "Identified");
    assert_ne!(
        m["type"], "BrowserHistory",
        "an identification record must not be counted among browsing records"
    );
    assert_eq!(m["type"], "BrowserHistoryParseStatus");
    assert_eq!(m["content_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"].is_string());

    // Bytes that are not a SQLite database at all, under a name this parser
    // claims: read whole, and it could not be parsed.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"not a database".to_vec()));
    let out = BrowserHistoryParser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "History" }),
        ))
        .unwrap();
    let failure = out
        .iter()
        .find(|a| a.metadata["status"] == "ParseFailed")
        .expect("a file named as history that will not parse must say so");
    assert_eq!(failure.metadata["type"], "BrowserHistoryParseStatus");
    assert_eq!(failure.metadata["content_incomplete"], json!(true));
    assert!(
        !out.iter().any(|a| a.metadata["type"] == "BrowserHistory"),
        "nothing may be filed as a browsing record here: {:?}",
        out.iter()
            .map(|a| a.metadata["type"].clone())
            .collect::<Vec<_>>()
    );
}

// --- Safari `Cookies.binarycookies` ---
//
// Apple's own binary cookie jar: magic `cook`, never SQLite and never a
// property list. Layout confirmed against the vendored reference parser and
// its field list (`reference/plaso/plaso/parsers/safari_cookies.{py,yaml}`)
// and against the real jar at
// `reference/plaso/test_data/Cookies.binarycookies` — see the doc comments on
// `parse_safari_binarycookies` and its helpers for the citation in full.

/// Write one NUL-terminated string into `strings`, relative to the start of
/// the record its offset table entries will point into, and return that
/// offset. Built independently of `read_binarycookies_cstring`/
/// `parse_binarycookies_record` so this fixture cannot share a bug with the
/// decoder it exercises.
fn push_binarycookies_cstring(strings: &mut Vec<u8>, s: &str) -> u32 {
    let offset = (BC_RECORD_HEADER_LEN + strings.len()) as u32;
    strings.extend_from_slice(s.as_bytes());
    strings.push(0);
    offset
}

/// Hand-build a minimal, well-formed `Cookies.binarycookies` file holding
/// exactly one cookie record: `cook` + one page + one record, byte for byte
/// per the layout `parse_safari_binarycookies` documents.
fn build_binarycookies_fixture(
    host: &str,
    name: &str,
    path: &str,
    value: &str,
    flags: u32,
    creation: f64,
    expiration: f64,
) -> Vec<u8> {
    let mut strings = Vec::new();
    let url_offset = push_binarycookies_cstring(&mut strings, host);
    let name_offset = push_binarycookies_cstring(&mut strings, name);
    let path_offset = push_binarycookies_cstring(&mut strings, path);
    let value_offset = push_binarycookies_cstring(&mut strings, value);

    let size = (BC_RECORD_HEADER_LEN + strings.len()) as u32;
    let mut record = Vec::new();
    record.extend_from_slice(&size.to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes()); // unknown1
    record.extend_from_slice(&flags.to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes()); // unknown2
    record.extend_from_slice(&url_offset.to_le_bytes());
    record.extend_from_slice(&name_offset.to_le_bytes());
    record.extend_from_slice(&path_offset.to_le_bytes());
    record.extend_from_slice(&value_offset.to_le_bytes());
    record.extend_from_slice(&0u64.to_le_bytes()); // unknown3
    record.extend_from_slice(&expiration.to_le_bytes());
    record.extend_from_slice(&creation.to_le_bytes());
    record.extend_from_slice(&strings);
    assert_eq!(record.len(), size as usize);

    let record_offset = (BC_PAGE_HEADER_LEN + 4 + BC_END_OF_PAGE_MARKER_LEN) as u32;
    let mut page = Vec::new();
    page.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page signature (observed, not enforced)
    page.extend_from_slice(&1u32.to_le_bytes()); // record count
    page.extend_from_slice(&record_offset.to_le_bytes()); // offsets[0]
    page.extend_from_slice(&[0, 0, 0, 0]); // end-of-page marker
    page.extend_from_slice(&record);

    let mut file = Vec::new();
    file.extend_from_slice(b"cook");
    file.extend_from_slice(&1u32.to_be_bytes()); // page count
    file.extend_from_slice(&(page.len() as u32).to_be_bytes()); // page size
    file.extend_from_slice(&page);
    file
}

#[test]
fn synthetic_binarycookies_record_decodes_exactly() {
    // Mac absolute time (seconds since 2001-01-01) with a fraction, so the
    // test also pins the sub-second `_us` companion, not just whole seconds.
    let creation = 700_000_000.25_f64;
    let expiration = 800_000_000.75_f64;
    let data = build_binarycookies_fixture(
        "example.com",
        "sid",
        "/",
        "abc123",
        SAFARI_COOKIE_FLAG_SECURE | SAFARI_COOKIE_FLAG_HTTPONLY,
        creation,
        expiration,
    );
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let out = run_named("Cookies.binarycookies", ds);

    assert!(
        incomplete_markers(&out).is_empty(),
        "a well-formed single-cookie jar must not be flagged incomplete: {:?}",
        out
    );
    assert_eq!(records_of(&out, "browser_cookie"), 1);
    let c = &out
        .iter()
        .find(|a| a.metadata["subtype"] == "browser_cookie")
        .unwrap()
        .metadata;

    assert_eq!(c["type"], "BrowserCookie");
    assert_eq!(c["browser"], "Safari");
    assert_eq!(c["host"], "example.com");
    assert_eq!(c["cookie_name"], "sid");
    assert_eq!(c["path"], "/");
    assert_eq!(c["value"], "abc123");
    assert_eq!(c["value_encrypted"], false);
    assert_eq!(c["is_secure"], true);
    assert_eq!(c["is_httponly"], true);
    // 2001-01-01 epoch (978,307,200 s before the Unix epoch) plus the encoded
    // Mac-absolute-time offset, floor/round exactly as
    // `cocoa_secs_to_unix_nanos` documents.
    assert_eq!(c["creation_time"], 1_678_307_200_i64);
    assert_eq!(c["creation_time_us"], 1_678_307_200_250_000_i64);
    assert_eq!(c["expiry_time"], 1_778_307_200_i64);
    assert_eq!(c["expiry_time_us"], 1_778_307_200_750_000_i64);
}

#[test]
fn synthetic_binarycookies_flags_and_absent_value_round_trip() {
    // flags = 0 (neither Secure nor HttpOnly) and an empty value: the offset
    // is non-zero (the string is present, just empty), so `value` is still
    // published — unlike a genuinely absent field (offset 0), which is not
    // covered by this fixture builder but is handled by
    // `read_binarycookies_cstring`'s zero-offset check directly.
    let data = build_binarycookies_fixture(
        ".insecure.example",
        "pref",
        "/app",
        "",
        0,
        1_000_000.0,
        2_000_000.0,
    );
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let out = run_named("Cookies.binarycookies", ds);
    let c = &out
        .iter()
        .find(|a| a.metadata["subtype"] == "browser_cookie")
        .unwrap()
        .metadata;
    assert_eq!(c["is_secure"], false);
    assert_eq!(c["is_httponly"], false);
    assert!(
        c.get("value").is_none(),
        "an empty cookie value must not be published as a value at all"
    );
}

#[test]
fn binarycookies_truncated_file_reports_the_shortfall_not_silently_dropped() {
    // The header and page-size table both survive intact — they declare one
    // 97-byte page — but the file itself is cut short inside that page, the
    // way a source window over a disk image can under-deliver. Silently
    // reading nothing here would read as "this jar held no cookies"; silently
    // returning the fragment would read as a complete record.
    let mut data = build_binarycookies_fixture(
        "example.com",
        "sid",
        "/",
        "abc123",
        SAFARI_COOKIE_FLAG_SECURE,
        700_000_000.0,
        800_000_000.0,
    );
    let declared_total = data.len() as u64;
    data.truncate(data.len() - 30);
    let read_total = data.len() as u64;
    assert!(
        read_total < declared_total,
        "the fixture must actually be shorter than what its own page table declares"
    );

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let out = run_named("Cookies.binarycookies", ds);

    assert_eq!(
        records_of(&out, "browser_cookie"),
        0,
        "a page the file does not fully hold must not yield a partial cookie record"
    );
    let m = assert_file_marker(
        &out,
        "BrowserCookieIncomplete",
        "Cookies.binarycookies",
        "short_read",
    );
    assert_eq!(m.metadata["declared_bytes"], declared_total);
    assert_eq!(m.metadata["bytes_read"], read_total);
}

#[test]
fn binarycookies_with_no_data_source_is_not_reported_as_no_cookies() {
    let out = run_without_data("Cookies.binarycookies");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "BrowserCookieIncomplete");
    assert_eq!(m["status"], "FileNotRead");
    assert_eq!(m["content_incomplete"], true);
}

#[test]
fn binarycookies_bad_magic_is_not_a_truncated_jar() {
    // Not `cook` at all: a genuine determination that this file is not a
    // binarycookies jar, the same convention `parse_firefox_session` uses for
    // its own bad-magic case — not an incompleteness marker.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"not-a-cookie-jar".to_vec()));
    let out = run_named("Cookies.binarycookies", ds);
    assert!(out.is_empty());
}

// --- Schema-drift defence (ROADMAP §1.4a) -------------------------------------

/// Run the parser over `bytes` under the file name it self-selects on.
fn run_bytes(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
    run_named(name, Arc::new(ByteSliceDataSource::new(bytes)))
}

fn sqlite_from(sql: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_stale_{}.db", Uuid::new_v4()));
    {
        let conn = Connection::open(&temp_path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    let data = std::fs::read(&temp_path).unwrap();
    let _ = std::fs::remove_file(&temp_path);
    data
}

fn stale_markers(artifacts: &[Artifact]) -> Vec<&Artifact> {
    artifacts
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// Chromium keeps its schema version in `meta.version`, not `PRAGMA
/// user_version` (0 on every real profile). History was validated against real
/// profiles from meta.version 20 (plaso) to 70 (a current desktop Chrome); a
/// profile past that is still parsed, and the parse says so.
#[test]
fn a_chrome_history_past_the_validated_range_is_parsed_and_declared_stale() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '80');
             INSERT INTO meta VALUES ('last_compatible_version', '16');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);",
        ),
        "History",
    );
    assert_eq!(records_of(&records, "browser_visit"), 1);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["app"], "chrome-history");
    assert_eq!(stale[0].metadata["seen_schema_version"], 80);
    assert_eq!(stale[0].metadata["supported_range"], "20..=70");
    assert_eq!(stale[0].metadata["chromium_last_compatible_version"], 16);
    // §1.4a (decided 2026-09-26): past the validated range is a disclosure.
    // Chromium's own floor (16) is below the validated maximum, so nothing
    // says this parser cannot read the store, and no incompleteness is claimed.
    assert_eq!(stale[0].metadata["status"], "SchemaOutsideValidated");
    assert!(stale[0].metadata.get("content_incomplete").is_none());
    assert!(stale[0].metadata.get("content_incomplete_reason").is_none());
}

/// Chromium's `last_compatible_version` is its own statement that readers
/// older than it cannot read the file. When it is past what this parser was
/// validated to, that is the strongest signal available and the marker says it.
#[test]
fn a_chrome_profile_that_declares_itself_unreadable_by_older_readers_says_so() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '90');
             INSERT INTO meta VALUES ('last_compatible_version', '85');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);",
        ),
        "History",
    );
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert!(stale[0].metadata["message"]
        .as_str()
        .unwrap()
        .contains("last_compatible_version 85"));
    // The one out-of-range case that claims (§1.4a, decided 2026-09-26): the
    // store itself says a reader written for this parser's schemas cannot
    // read it, so a shortfall is expected rather than merely possible.
    assert_eq!(stale[0].metadata["content_incomplete"], true);
    assert_eq!(
        stale[0].metadata["content_incomplete_reason"],
        "unvalidated"
    );
    assert_eq!(
        stale[0].metadata["content_incomplete_detail"],
        stale[0].metadata["message"]
    );
    assert_eq!(stale[0].metadata["detail"], stale[0].metadata["message"]);
    assert!(stale[0].metadata.get("inventory_incomplete").is_none());
}

/// A Chromium store with no `meta` table carries no version where this parser
/// looks; that is stated, and never read as version 0 below the range.
#[test]
fn a_chrome_history_without_a_meta_table_is_stated_not_ranked() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);",
        ),
        "History",
    );
    assert_eq!(records_of(&records, "browser_visit"), 1);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
    assert!(stale[0].metadata.get("content_incomplete").is_none());
}

/// A renamed `visits.visit_time` skips the join it makes meaningless, names the
/// field, and falls back to the `urls` listing so the profile is not silent.
#[test]
fn a_renamed_chrome_visits_column_is_named_and_the_urls_listing_still_parses() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '51');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_ts INTEGER, from_visit INTEGER, transition INTEGER);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 3, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1);
             INSERT INTO visits VALUES (2, 1, 13300000001000000, 0, 1);",
        ),
        "History",
    );
    let visits: Vec<_> = records
        .iter()
        .filter(|a| a.metadata["subtype"] == "browser_visit")
        .collect();
    assert_eq!(
        visits.len(),
        1,
        "one row per url, from the fallback listing"
    );
    assert_eq!(visits[0].metadata["visit_count"], 3);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(
        stale[0].metadata["unresolved_fields"],
        json!(["visit_time"])
    );
    assert_eq!(stale[0].metadata["source_table"], "visits");
    assert_eq!(stale[0].metadata["content_incomplete"], true);
    assert_eq!(
        stale[0].metadata["content_incomplete_reason"],
        "unvalidated"
    );
}

/// A `downloads` table without the columns a download record is meaningless
/// without is declared by field, and history still parses. (This used to be a
/// `ParseFailed` record from a query naming columns that were not there.)
#[test]
fn a_chrome_downloads_table_missing_its_required_columns_is_declared_by_field() {
    let records = run_history(create_chrome_downloads_db(
        "CREATE TABLE downloads (id INTEGER PRIMARY KEY, mystery TEXT);
         INSERT INTO downloads VALUES (1, 'x');",
    ));
    assert!(records
        .iter()
        .any(|a| a.metadata["type"] == "BrowserHistory"));
    assert!(!records
        .iter()
        .any(|a| a.metadata["type"] == "BrowserDownload"));
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["source_table"], "downloads");
    assert_eq!(
        stale[0].metadata["unresolved_fields"],
        json!(["target_path", "start_time", "total_bytes"])
    );
}

/// The plaso reference `History` (meta.version 20, Chrome circa 2010) keeps a
/// download's path in `full_path` and its URL in `url` — no `target_path`, no
/// `tab_url`, no url-chain table. The candidate lists absorb the rename, the
/// download is recovered, and the source URL says which column it came from.
#[test]
fn a_version_20_chrome_downloads_table_is_read_through_its_older_column_names() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '20');
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
             CREATE TABLE downloads (id INTEGER PRIMARY KEY, full_path LONGVARCHAR NOT NULL, url LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state INTEGER NOT NULL);
             INSERT INTO downloads VALUES (1, '/home/x/Downloads/tool.tgz', 'https://files.example/tool.tgz', 12945429317090490, 100, 100, 1);",
        ),
        "History",
    );
    assert!(stale_markers(&records).is_empty(), "{records:?}");
    let dl = records
        .iter()
        .find(|a| a.metadata["type"] == "BrowserDownload")
        .expect("the download is recovered");
    assert_eq!(dl.metadata["target_path"], "/home/x/Downloads/tool.tgz");
    assert_eq!(dl.metadata["source_url"], "https://files.example/tool.tgz");
    assert_eq!(dl.metadata["source_url_origin"], "downloads_url");
    assert!(dl.metadata["end_time"].is_null());
    assert!(dl.metadata.get("danger_type").is_none());
    assert!(dl.metadata.get("was_opened").is_none());
}

/// The plaso reference `cookies.db` (meta.version 5) names its flags `secure`
/// and `httponly` and has no `encrypted_value`. Validated range 5..=24 from
/// real jars; the older names resolve through the candidate lists.
#[test]
fn a_version_5_chrome_cookie_jar_is_read_through_its_older_column_names() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '5');
             CREATE TABLE cookies (creation_utc INTEGER NOT NULL UNIQUE PRIMARY KEY, host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, secure INTEGER NOT NULL, httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, has_expires INTEGER DEFAULT 1, persistent INTEGER DEFAULT 1);
             INSERT INTO cookies VALUES (13300000000000000, '.example.com', 'sid', 'abc', '/', 13400000000000000, 1, 1, 13300000000000000, 1, 1);",
        ),
        "Cookies",
    );
    assert!(stale_markers(&records).is_empty(), "{records:?}");
    let cookie = records
        .iter()
        .find(|a| a.metadata["type"] == "BrowserCookie")
        .expect("the cookie is recovered");
    assert_eq!(cookie.metadata["is_secure"], true);
    assert_eq!(cookie.metadata["is_httponly"], true);
    assert_eq!(cookie.metadata["value_encrypted"], false);
    assert_eq!(cookie.metadata["value"], "abc");
}

/// The chromebook `Login Data` (meta.version 24) predates `date_last_used`;
/// that column is optional and its absence is not drift.
#[test]
fn a_version_24_chrome_login_store_without_date_last_used_owes_no_marker() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
             INSERT INTO meta VALUES ('version', '24');
             CREATE TABLE logins (origin_url TEXT NOT NULL, username_value TEXT, password_value BLOB, date_created INTEGER NOT NULL, times_used INTEGER, id INTEGER PRIMARY KEY);
             INSERT INTO logins VALUES ('https://example.com/login', 'ada', X'01', 13300000000000000, 2, 1);",
        ),
        "Login Data",
    );
    assert!(stale_markers(&records).is_empty(), "{records:?}");
    let login = records
        .iter()
        .find(|a| a.metadata["type"] == "BrowserLogin")
        .expect("the login is recovered");
    assert_eq!(login.metadata["username"], "ada");
    assert!(login.metadata["last_used"].is_null());
}

/// Firefox stamps `PRAGMA user_version`; validated 10..=82 from real profiles
/// (plaso's 10, 23 and 75, and a current Firefox at 82).
#[test]
fn a_firefox_places_past_the_validated_range_is_parsed_and_declared_stale() {
    let records = run_bytes(
        sqlite_from(
            "PRAGMA user_version = 99;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mozilla.org', 'Mozilla', 1, 1700000000000000);
             INSERT INTO moz_historyvisits VALUES (1, 1, 1700000000000000, 1);",
        ),
        "places.sqlite",
    );
    assert_eq!(records_of(&records, "browser_visit"), 1);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["app"], "firefox-places");
    assert_eq!(stale[0].metadata["seen_schema_version"], 99);
    assert_eq!(stale[0].metadata["supported_range"], "10..=82");
}

#[test]
fn a_firefox_places_with_no_recorded_version_is_stated_not_ranked() {
    let records = run_bytes(
        sqlite_from(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mozilla.org', 'Mozilla', 1, 1700000000000000);",
        ),
        "places.sqlite",
    );
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
}

/// A renamed `moz_bookmarks.dateAdded` skips the bookmark walk it makes
/// meaningless, names the field, and leaves the history untouched.
#[test]
fn a_renamed_firefox_bookmark_column_is_named_and_history_still_parses() {
    let records = run_bytes(
        sqlite_from(
            "PRAGMA user_version = 75;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT, date_added INTEGER, lastModified INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://mozilla.org', 'Mozilla', 1, 1700000000000000);
             INSERT INTO moz_bookmarks VALUES (1, 1, 1, 'Mozilla', 1700000000000000, 1700000000000000);",
        ),
        "places.sqlite",
    );
    assert_eq!(records_of(&records, "browser_visit"), 1);
    assert_eq!(records_of(&records, "browser_bookmark"), 0);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["unresolved_fields"], json!(["dateAdded"]));
    assert_eq!(stale[0].metadata["source_table"], "moz_bookmarks");
}

/// Safari stamps `PRAGMA user_version`; validated 13..=16 from real stores
/// (plaso's 13, the macos2021 15, the ios2022ffs 16).
#[test]
fn a_safari_history_past_the_validated_range_is_parsed_and_declared_stale() {
    let records = run_bytes(
        sqlite_from(
            "PRAGMA user_version = 20;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
             INSERT INTO history_items VALUES (1, 'https://apple.com', 1);
             INSERT INTO history_visits VALUES (1, 1, 720000000.0, 'Apple');",
        ),
        "History.db",
    );
    assert_eq!(records_of(&records, "browser_visit"), 1);
    let stale = stale_markers(&records);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["app"], "safari-history");
    assert_eq!(stale[0].metadata["supported_range"], "13..=16");
}

/// Every synthetic fixture in this file carries its store's real version
/// carrier at a validated value, so none of them owes a stale marker — which
/// is what keeps the other tests' record counts honest.
#[test]
fn the_fixtures_at_validated_versions_owe_no_stale_marker() {
    for (bytes, name) in [
        (create_chrome_test_db(), "History"),
        (create_chrome_cookie_db(), "Cookies"),
        (create_chrome_webdata_db(), "Web Data"),
        (create_chrome_login_db(), "Login Data"),
        (create_firefox_test_db(), "places.sqlite"),
        (create_firefox_cookie_db(), "cookies.sqlite"),
        (create_firefox_formhistory_db(), "formhistory.sqlite"),
        (create_safari_test_db(), "History.db"),
    ] {
        let records = run_bytes(bytes, name);
        assert!(
            stale_markers(&records).is_empty(),
            "{name}: {:?}",
            stale_markers(&records)
                .iter()
                .map(|m| &m.metadata["message"])
                .collect::<Vec<_>>()
        );
    }
}

/// HUNT-277: a browser history database inside a shadow copy was listed and never opened. A
/// `VssPriorVersion` record is named `<file> [shadow copy <time>]`, which no browser name test
/// accepts, so the parser decides by the file's original name (`file_name`); every visit, timeline
/// event and status row it yields repeats the snapshot identity, and a `ParsedRecord` that is not a
/// prior version is not read. SYNTHETIC: a Chrome history database built by this suite.
#[test]
fn a_shadow_copy_prior_version_of_a_history_database_is_parsed_and_every_row_says_so() {
    let parser = BrowserHistoryParser;
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_chrome_test_db()));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src.clone()),
        json!({
            "type": "VssPriorVersion",
            "name": "History [shadow copy 2015-03-23]",
            "file_name": "History",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let live = parser
        .process(&Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src.clone()),
            json!({"name": "History"}),
        ))
        .unwrap();
    let out = parser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version's history is parsed");
    assert_eq!(out.len(), live.len(), "the same records as the live file");
    for a in &out {
        assert_eq!(
            a.metadata["is_snapshot_version"],
            json!(true),
            "{}",
            a.metadata
        );
        assert_eq!(a.metadata["vss_snapshot_id"], json!("snap-1"));
    }
    let events: Vec<_> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e.metadata["short_desc"]
        .as_str()
        .unwrap()
        .starts_with("[shadow copy 2015-03-23T00:00:00Z] ")));

    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        json!({ "type": "SomethingElse", "name": "History" }),
    );
    assert!(parser.process(&other).unwrap().is_empty());
}
