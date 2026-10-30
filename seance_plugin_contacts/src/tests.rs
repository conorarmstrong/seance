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

/// A synthetic iOS `AddressBook.sqlitedb` (`ABPerson` + `ABMultiValue`), with
/// the `_SqliteDatabaseProperties._ClientVersion` the real store carries (83 on
/// the ios2022ffs iPhone 8; `PRAGMA user_version` is 0 there). One statement per
/// line, so a test can drop the properties table by filtering lines.
const IOS_CONTACTS_SQL: &str = "
    CREATE TABLE _SqliteDatabaseProperties (key TEXT PRIMARY KEY, value TEXT);
    INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', '83');
    CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Organization TEXT);
    CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, property INTEGER, value TEXT);
    INSERT INTO ABPerson VALUES (1, 'Alice', 'Smith', 'Acme Corp');
    INSERT INTO ABPerson VALUES (2, 'Bob', NULL, NULL);
    -- property 3 = phone, 4 = email
    INSERT INTO ABMultiValue VALUES (10, 1, 3, '+15551234567');
    INSERT INTO ABMultiValue VALUES (11, 1, 4, 'alice@example.com');
    INSERT INTO ABMultiValue VALUES (12, 2, 3, '+15559998888');";

/// Build a synthetic iOS `AddressBook.sqlitedb`.
fn create_ios_contacts_db() -> Vec<u8> {
    db_from_sql(IOS_CONTACTS_SQL)
}

/// A synthetic Android `contacts2.db`, without the `user_version` the provider
/// stamps (1300 on the android2022 Pixel), so a test states it explicitly.
const ANDROID_CONTACTS_SQL: &str = "
    CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT);
    CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
    CREATE TABLE data (
        _id INTEGER PRIMARY KEY, raw_contact_id INTEGER,
        mimetype_id INTEGER, data1 TEXT
    );
    CREATE TABLE calls (
        _id INTEGER PRIMARY KEY, number TEXT, date INTEGER,
        duration INTEGER, type INTEGER
    );

    INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2');
    INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/email_v2');
    INSERT INTO mimetypes VALUES (3, 'vnd.android.cursor.item/organization');
    INSERT INTO mimetypes VALUES (4, 'vnd.android.cursor.item/name');

    INSERT INTO raw_contacts VALUES (1, 'Carol Jones');
    INSERT INTO raw_contacts VALUES (2, 'Dave');

    INSERT INTO data VALUES (100, 1, 1, '+15551112222');
    INSERT INTO data VALUES (101, 1, 2, 'carol@example.com');
    INSERT INTO data VALUES (102, 1, 3, 'Globex');
    INSERT INTO data VALUES (103, 2, 1, '+15553334444');

    -- Unrelated call row that must be ignored by the contacts parser.
    INSERT INTO calls VALUES (1, '+15550000000', 1600000000000, 10, 1);";

/// Build a synthetic Android `contacts2.db` at the validated provider version.
fn create_android_contacts_db() -> Vec<u8> {
    let mut sql = String::from("PRAGMA user_version = 1300;");
    sql.push_str(ANDROID_CONTACTS_SQL);
    db_from_sql(&sql)
}

/// Build a SQLite db that is NOT a contacts store (only a `foo` table).
fn create_non_contacts_db() -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_non_contacts_{}.db", Uuid::new_v4()));
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

fn contacts(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["subtype"] == "contact")
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
    let parser = ContactsParser;
    assert_eq!(parser.id(), "plugin.mobile.contacts");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_filename_prefilter() {
    assert!(identify_contacts_db("AddressBook.sqlitedb"));
    assert!(identify_contacts_db(
        "/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb"
    ));
    assert!(identify_contacts_db("contacts2.db"));
    assert!(!identify_contacts_db("chat.db"));
    assert!(!identify_contacts_db("mmssms.db"));
    assert!(!identify_contacts_db("random.txt"));
}

#[test]
fn test_skips_non_matching_file() {
    let parser = ContactsParser;
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
    let parser = ContactsParser;
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "AddressBook.sqlitedb"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].metadata["type"], "Contact");
    assert_eq!(result[0].metadata["status"], "Identified");
}

#[test]
fn test_ios_parsing() {
    let parser = ContactsParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_contacts_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "AddressBook.sqlitedb"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = contacts(&result);
    assert_eq!(recs.len(), 2, "expected 2 contacts, got {}", recs.len());

    let alice = recs
        .iter()
        .find(|a| a.metadata["display_name"] == "Alice Smith")
        .unwrap();
    assert_eq!(alice.metadata["type"], "Contact");
    assert_eq!(alice.metadata["platform"], "iOS");
    assert_eq!(alice.metadata["organization"], "Acme Corp");
    let phones = alice.metadata["phone_numbers"].as_array().unwrap();
    assert!(phones.iter().any(|v| v == "+15551234567"));
    let emails = alice.metadata["emails"].as_array().unwrap();
    assert!(emails.iter().any(|v| v == "alice@example.com"));

    let bob = recs
        .iter()
        .find(|a| a.metadata["display_name"] == "Bob")
        .unwrap();
    let phones = bob.metadata["phone_numbers"].as_array().unwrap();
    assert!(phones.iter().any(|v| v == "+15559998888"));
    assert!(bob.metadata["emails"].as_array().unwrap().is_empty());

    let s = summary(&result);
    assert_eq!(s.metadata["platform"], "iOS");
    assert_eq!(s.metadata["contact_count"], 2);
    assert_eq!(s.metadata["with_phone_count"], 2);
    assert_eq!(s.metadata["with_email_count"], 1);
}

#[test]
fn test_android_parsing() {
    let parser = ContactsParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_android_contacts_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "contacts2.db"}),
    );

    let result = parser.process(&artifact).unwrap();
    let recs = contacts(&result);
    assert_eq!(recs.len(), 2, "expected 2 contacts, got {}", recs.len());

    let carol = recs
        .iter()
        .find(|a| a.metadata["display_name"] == "Carol Jones")
        .unwrap();
    assert_eq!(carol.metadata["platform"], "Android");
    assert_eq!(carol.metadata["organization"], "Globex");
    let phones = carol.metadata["phone_numbers"].as_array().unwrap();
    assert!(phones.iter().any(|v| v == "+15551112222"));
    let emails = carol.metadata["emails"].as_array().unwrap();
    assert!(emails.iter().any(|v| v == "carol@example.com"));

    let dave = recs
        .iter()
        .find(|a| a.metadata["display_name"] == "Dave")
        .unwrap();
    let phones = dave.metadata["phone_numbers"].as_array().unwrap();
    assert!(phones.iter().any(|v| v == "+15553334444"));

    let s = summary(&result);
    assert_eq!(s.metadata["platform"], "Android");
    assert_eq!(s.metadata["contact_count"], 2);
    assert_eq!(s.metadata["with_phone_count"], 2);
    assert_eq!(s.metadata["with_email_count"], 1);
}

#[test]
fn test_parent_and_case_chain() {
    let parser = ContactsParser;
    let case_id = Uuid::new_v4();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_contacts_db()));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "AddressBook.sqlitedb"}),
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
fn test_negative_non_contacts_schema_rejected() {
    let parser = ContactsParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_non_contacts_db()));
    // Name passes the pre-filter, so only the schema check can reject it.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "contacts2.db"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        0,
        "non-contacts schema must yield zero artifacts"
    );
}

#[test]
fn test_garbage_no_panic() {
    let parser = ContactsParser;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 2048]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "AddressBook.sqlitedb"}),
    );
    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        0,
        "garbage must yield zero artifacts, no panic"
    );
}

// --- Cap honesty (B2-080) ----------------------------------------------------

/// A walk that read every row must not claim the address book was cut short.
#[test]
fn a_complete_contacts_summary_carries_no_truncation_flag() {
    let summary = build_contact_summary(&[], "Android", "contacts2.db", 5, false, 0);
    assert_eq!(summary["contact_count"], json!(5));
    assert!(summary.get("truncated").is_none());
    assert!(summary.get("content_incomplete").is_none());
    assert!(summary.get("rows_dropped").is_none());
}

/// B3-023: rows that would not decode were dropped with only a `debug!` line, so
/// `contact_count` read as the exact number of contacts on the device. What an
/// examiner learns from `rows_dropped`: the count is a floor. A wrong answer
/// looks like "5 contacts" for an address book that held six, the sixth being a
/// corrupt row — and "this number was never in the phone" follows from it.
#[test]
fn undecodable_contact_rows_are_stated_on_the_summary() {
    let summary = build_contact_summary(&[], "iOS", "AddressBook.sqlitedb", 5, false, 2);
    assert_eq!(summary["rows_dropped"], json!(2));
    assert_eq!(summary["inventory_incomplete"], json!(true));
    assert_eq!(summary["content_incomplete"], json!(true));
    assert_eq!(summary["content_incomplete_reason"], "unresolved_structure");
}

/// B3-023: when the walk was BOTH capped and dropped rows, the cap is the
/// coarser statement and must stay as the standard reason; the dropped-row count
/// is reported alongside it rather than overwriting it.
#[test]
fn a_capped_walk_that_also_dropped_rows_keeps_the_cap_reason() {
    let summary = build_contact_summary(
        &[],
        "iOS",
        "AddressBook.sqlitedb",
        MAX_CONTACT_ENTRIES,
        true,
        3,
    );
    assert_eq!(summary["content_incomplete_reason"], "cap_reached");
    assert_eq!(summary["rows_dropped"], json!(3));
    assert_eq!(summary["inventory_incomplete"], json!(true));
}

/// Hitting the cap must be stated on the summary, so a partial address book is
/// never read as proof that a number was not in the phone.
#[test]
fn an_address_book_stopped_by_the_cap_is_marked_incomplete() {
    let summary = build_contact_summary(
        &[],
        "iOS",
        "AddressBook.sqlitedb",
        MAX_CONTACT_ENTRIES,
        true,
        0,
    );
    assert_eq!(summary["truncated"], json!(true));
    assert_eq!(summary["content_incomplete"], json!(true));
    assert_eq!(summary["content_incomplete_reason"], "cap_reached");
    assert_eq!(summary["max_entries"], json!(MAX_CONTACT_ENTRIES));
}
/// B2-123: the parser cap was reported, but a database the spill could not
/// stage in full was not. "This name is not in the address book" is a claim an
/// examiner will rely on; it must not be produced by a partial read.
#[test]
fn a_short_read_address_book_marks_every_record_it_produced() {
    let ds: Arc<dyn DataSource> = Arc::new(truncated(create_ios_contacts_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "AddressBook.sqlitedb"}),
    );
    let result = ContactsParser.process(&artifact).unwrap();

    let contact = result
        .iter()
        .find(|a| a.metadata["subtype"] == "contact")
        .expect("the readable prefix still parses");
    assert_eq!(contact.metadata["content_incomplete"], true);
    assert_eq!(contact.metadata["content_incomplete_reason"], "short_read");
    assert!(
        result
            .iter()
            .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
        "a partial spill must be reported in its own right"
    );
}

/// The counterpart: an address book read whole stays unmarked.
#[test]
fn a_complete_address_book_carries_no_incompleteness_marks() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(create_ios_contacts_db()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "AddressBook.sqlitedb"}),
    );
    let result = ContactsParser.process(&artifact).unwrap();
    assert!(!result.is_empty());
    assert!(
        result
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()),
        "a complete parse must not mark any record incomplete"
    );
}

// --- Unmapped multi-values (B7-034) ------------------------------------------

fn db_from_sql(sql: &str) -> Vec<u8> {
    let temp_path = std::env::temp_dir().join(format!("test_contacts_sql_{}.db", Uuid::new_v4()));
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
    ContactsParser.process(&artifact).unwrap()
}

/// iOS multi-values that are neither phone (3) nor email (4) — addresses, URLs,
/// IM handles — were dropped with no note, so an address book with a home
/// address on file presented as one that held only a number.
#[test]
fn ios_unmapped_multivalues_are_stated_on_the_contact() {
    let db = db_from_sql(
        "CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, \
           Organization TEXT);
         CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, \
           property INTEGER, value TEXT);
         INSERT INTO ABPerson VALUES (1, 'Alice', 'Smith', NULL);
         INSERT INTO ABMultiValue VALUES (10, 1, 3, '+15551234567');
         -- property 5 = street address, 22 = URL: neither is decoded here.
         INSERT INTO ABMultiValue VALUES (11, 1, 5, '1 Main St');
         INSERT INTO ABMultiValue VALUES (12, 1, 22, 'https://example.com');",
    );
    let result = process_db(db, "AddressBook.sqlitedb");
    let c = contacts(&result);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].metadata["unmapped_value_count"], json!(2));
    let kinds = c[0].metadata["unmapped_value_kinds"].as_array().unwrap();
    assert!(kinds.iter().any(|k| k == "property 5"));
    assert!(kinds.iter().any(|k| k == "property 22"));

    // The incompleteness pair is raised once, on the summary — not on every
    // contact, where on a synced Android book it would fire universally and
    // train the examiner to ignore it.
    assert!(
        c[0].metadata.get("inventory_incomplete").is_none(),
        "the per-contact record states counts, not a banner"
    );
    assert!(c[0].metadata.get("content_incomplete").is_none());
    let s = summary(&result);
    assert_eq!(s.metadata["unmapped_value_count"], json!(2));
    assert_eq!(s.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        s.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
}

/// The Android side has the same gap: any mimetype outside phone/email/org/name
/// is passed over, and must be counted.
#[test]
fn android_unmapped_mimetypes_are_stated_on_the_contact() {
    let db = db_from_sql(
        "CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT);
         CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
         CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, \
           mimetype_id INTEGER, data1 TEXT);
         INSERT INTO raw_contacts VALUES (1, 'Alice Smith');
         INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2');
         INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/postal-address_v2');
         INSERT INTO data VALUES (100, 1, 1, '+15551234567');
         INSERT INTO data VALUES (101, 1, 2, '1 Main St');",
    );
    let result = process_db(db, "contacts2.db");
    let c = contacts(&result);
    assert_eq!(c[0].metadata["unmapped_value_count"], json!(1));
    assert_eq!(
        c[0].metadata["unmapped_value_kinds"][0],
        "vnd.android.cursor.item/postal-address_v2"
    );
    let s = summary(&result);
    assert_eq!(s.metadata["unmapped_value_count"], json!(1));
    assert_eq!(s.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        s.metadata["unmapped_value_kinds"][0],
        "vnd.android.cursor.item/postal-address_v2"
    );
}

/// The control: an address book whose every multi-value maps must carry no
/// unmapped note, or the note means nothing.
#[test]
fn a_fully_mapped_address_book_carries_no_unmapped_note() {
    let result = process_db(create_ios_contacts_db(), "AddressBook.sqlitedb");
    assert!(contacts(&result)
        .iter()
        .all(|a| a.metadata.get("unmapped_value_count").is_none()));
    assert!(
        summary(&result)
            .metadata
            .get("unmapped_value_count")
            .is_none(),
        "with nothing passed over the summary must raise no scope note"
    );
    assert!(summary(&result)
        .metadata
        .get("inventory_incomplete")
        .is_none());
}

// --- Unreadable databases (B7-023) -------------------------------------------

/// A corrupt address book is one this tool could not read, not a device with no
/// contacts. Before the fix the schema probe swallowed the error
/// (`unwrap_or(false)`) and the parser returned zero artifacts, which renders
/// identically to an empty address book.
#[test]
fn a_corrupt_address_book_reports_a_parse_failure_not_an_empty_book() {
    let mut db = create_ios_contacts_db();
    for b in db.iter_mut().skip(16) {
        *b = 0xFF;
    }
    let result = process_db(db, "AddressBook.sqlitedb");
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
    assert!(process_db(vec![0xABu8; 2048], "AddressBook.sqlitedb").is_empty());
}

// --- Schema-drift defence (ROADMAP §1.4a) -------------------------------------

/// The stale-warning markers a parse emitted.
fn stale_markers(result: &[Artifact]) -> Vec<&Artifact> {
    result
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// A `contacts2.db` whose `user_version` is the one real store this parser was
/// validated against (1300, android2022) owes no stale marker.
#[test]
fn an_android_store_at_the_validated_version_carries_no_stale_marker() {
    let result = process_db(create_android_contacts_db(), "contacts2.db");
    assert!(stale_markers(&result).is_empty());
    assert_eq!(contacts(&result).len(), 2);
}

/// A newer provider version is still parsed — the contacts it holds are the
/// evidence — and the parse says the version is past what was validated.
#[test]
fn an_android_store_with_a_newer_schema_version_is_parsed_and_declared_stale() {
    let mut sql = String::from("PRAGMA user_version = 1500;");
    sql.push_str(ANDROID_CONTACTS_SQL);
    let result = process_db(db_from_sql(&sql), "contacts2.db");
    assert_eq!(
        contacts(&result).len(),
        2,
        "the contacts are still extracted"
    );
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["seen_schema_version"], 1500);
    assert_eq!(stale[0].metadata["supported_range"], "1300..=1300");
    assert_eq!(stale[0].metadata["app"], "android-contacts");
    // §1.4a (decided 2026-09-26): outside the range is a disclosure.
    assert_eq!(stale[0].metadata["status"], "SchemaOutsideValidated");
    assert!(stale[0].metadata.get("content_incomplete").is_none());
    assert!(stale[0].metadata.get("content_incomplete_reason").is_none());
    assert!(stale[0].metadata["message"]
        .as_str()
        .unwrap()
        .contains("NEWER"));
}

/// The provider always stamps `user_version`; 0 is SQLite's unset default, not
/// a version older than 1300, and is stated as absent rather than ranked.
#[test]
fn an_android_store_with_no_recorded_version_is_stated_not_ranked() {
    let result = process_db(db_from_sql(ANDROID_CONTACTS_SQL), "contacts2.db");
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
    assert!(stale[0].metadata.get("content_incomplete").is_none());
    assert!(!stale[0].metadata["message"]
        .as_str()
        .unwrap()
        .contains("OLDER"));
}

/// A renamed `display_name` would otherwise make every contact nameless with
/// nothing saying why. The marker names the logical field, the table and the
/// columns that were there; the contacts are still emitted from what resolved.
#[test]
fn a_renamed_android_column_is_named_on_the_stale_marker() {
    let result = process_db(
        db_from_sql(
            "PRAGMA user_version = 1300;
             CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, displayname TEXT);
             CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
             CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER,
                                mimetype_id INTEGER, data1 TEXT);
             INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2');
             INSERT INTO raw_contacts VALUES (1, 'Carol Jones');
             INSERT INTO data VALUES (100, 1, 1, '+15551112222');",
        ),
        "contacts2.db",
    );
    let recs = contacts(&result);
    assert_eq!(recs.len(), 1, "what resolved is still parsed");
    assert_eq!(recs[0].metadata["phone_numbers"][0], "+15551112222");
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(
        stale[0].metadata["unresolved_fields"],
        json!(["display_name"])
    );
    assert_eq!(stale[0].metadata["source_table"], "raw_contacts");
    assert_eq!(stale[0].metadata["content_incomplete"], json!(true));
    assert_eq!(
        stale[0].metadata["content_incomplete_reason"],
        "unvalidated"
    );
    assert_eq!(
        stale[0].metadata["present_columns"],
        json!(["_id", "displayname"])
    );
}

/// iOS keeps its version in `_SqliteDatabaseProperties._ClientVersion`, not in
/// `user_version` (which is 0 on the real store). The validated value is 83, the
/// one real `AddressBook.sqlitedb` this project holds (ios2022ffs, iOS 15).
#[test]
fn an_ios_address_book_at_the_validated_client_version_carries_no_stale_marker() {
    let result = process_db(create_ios_contacts_db(), "AddressBook.sqlitedb");
    assert!(stale_markers(&result).is_empty());
}

#[test]
fn an_ios_address_book_with_a_newer_client_version_is_parsed_and_declared_stale() {
    let mut sql = IOS_CONTACTS_SQL.replace("'_ClientVersion', '83'", "'_ClientVersion', '90'");
    sql.push_str("PRAGMA user_version = 0;");
    let result = process_db(db_from_sql(&sql), "AddressBook.sqlitedb");
    assert_eq!(contacts(&result).len(), 2);
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["seen_schema_version"], 90);
    assert_eq!(stale[0].metadata["supported_range"], "83..=83");
    assert_eq!(stale[0].metadata["app"], "ios-addressbook");
}

/// An address book with no `_SqliteDatabaseProperties` at all is stated as
/// carrying no version — never as version 0, older than 83.
#[test]
fn an_ios_address_book_without_the_properties_table_is_stated_not_ranked() {
    let sql = IOS_CONTACTS_SQL
        .lines()
        .filter(|l| !l.contains("_SqliteDatabaseProperties"))
        .collect::<Vec<_>>()
        .join("\n");
    let result = process_db(db_from_sql(&sql), "AddressBook.sqlitedb");
    assert_eq!(contacts(&result).len(), 2);
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
    assert!(stale[0].metadata.get("seen_schema_version").is_none());
}

#[test]
fn a_renamed_ios_multivalue_column_is_named_on_the_stale_marker() {
    let sql =
        IOS_CONTACTS_SQL.replace("property INTEGER, value TEXT", "property INTEGER, val TEXT");
    let result = process_db(db_from_sql(&sql), "AddressBook.sqlitedb");
    // The people are still listed; what hung off them could not be joined.
    assert_eq!(contacts(&result).len(), 2);
    assert!(contacts(&result)
        .iter()
        .all(|c| c.metadata["phone_numbers"].as_array().unwrap().is_empty()));
    let stale = stale_markers(&result);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(stale[0].metadata["unresolved_fields"], json!(["value"]));
    assert_eq!(stale[0].metadata["source_table"], "ABMultiValue");
}

/// The Android provider marks a removed contact with `raw_contacts.deleted = 1`
/// and keeps the row until a sync purges it. The parser published such a row as
/// an ordinary live contact (found grading the NIST HTC Desire S image, where
/// John Bonham is flagged deleted on the handset). Synthetic fixture: it grades
/// nothing about real-world evidence.
#[test]
fn android_deleted_contact_is_flagged() {
    let db = db_from_sql(
        "CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT, deleted INTEGER DEFAULT 0);
         INSERT INTO raw_contacts VALUES (1, 'Live', 0);
         INSERT INTO raw_contacts VALUES (2, 'Gone', 1);",
    );
    let result = process_db(db, "contacts2.db");
    let c = contacts(&result);
    let live = c
        .iter()
        .find(|a| a.metadata["display_name"] == "Live")
        .unwrap();
    let gone = c
        .iter()
        .find(|a| a.metadata["display_name"] == "Gone")
        .unwrap();
    assert_eq!(gone.metadata["deleted"], json!(true));
    assert_eq!(live.metadata["deleted"], json!(false));
    assert_eq!(summary(&result).metadata["deleted_count"], json!(1));
}

/// A schema with no `deleted` column must still parse, and must not claim a
/// contact is live: the flag is absent, not false.
#[test]
fn android_schema_without_deleted_column_states_no_flag() {
    let db = db_from_sql(
        "CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT);
         INSERT INTO raw_contacts VALUES (1, 'Live');",
    );
    let result = process_db(db, "contacts2.db");
    let c = contacts(&result);
    assert!(c[0].metadata.get("deleted").is_none());
    assert!(summary(&result).metadata.get("deleted_count").is_none());
}
