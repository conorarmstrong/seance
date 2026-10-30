//! §1.5 remainder: workouts and sleep, Voice Memos, voicemail audio and
//! transcripts, note attachments and deleted notes, and Photos faces.
//!
//! Every fixture here is synthetic and pins a mechanism only. The shapes are
//! copied from real stores (named on each test); the validation on real
//! evidence is `tests/ios_remainder_corpus_test.rs`, gated on
//! `SEANCE_IOS_CORPORA`.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
use std::path::Path;
use std::sync::Arc;

fn make_db(ddl: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_ios_rem_{}.db", Uuid::new_v4()));
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
    run_ds(module, name, ds)
}

fn run_ds(module: &dyn ForensicsModule, name: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

/// Write `files` into a fresh directory and run `module` over `main` there,
/// through a file-backed source that can open its neighbours.
fn run_in_dir(
    module: &dyn ForensicsModule,
    main: &str,
    files: &[(&str, Vec<u8>)],
) -> Vec<Artifact> {
    let dir = std::env::temp_dir().join(format!("seance_ios_rem_dir_{}", Uuid::new_v4()));
    for (rel, bytes) in files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dir.join(main)).unwrap());
    let base = Path::new(main)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let out = run_ds(module, &base, ds);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn of_type<'a>(out: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == ty).collect()
}

fn one<'a>(out: &'a [Artifact], ty: &str) -> &'a serde_json::Value {
    let v = of_type(out, ty);
    assert_eq!(v.len(), 1, "exactly one {ty}: {out:#?}");
    &v[0].metadata
}

// ---------------------------------------------------------------------------
// HealthKit workouts and sleep
// ---------------------------------------------------------------------------

const HEALTH_BASE: &str = "
    CREATE TABLE samples (data_id INTEGER PRIMARY KEY, data_type INTEGER, start_date REAL, end_date REAL);
    CREATE TABLE objects (data_id INTEGER PRIMARY KEY, type INTEGER, creation_date REAL, uuid BLOB, provenance INTEGER);
    CREATE TABLE data_provenances (ROWID INTEGER PRIMARY KEY, origin_product_type TEXT, origin_build TEXT, \
      source_version TEXT, tz_name TEXT, source_id INTEGER, device_id INTEGER, local_product_type TEXT, local_build TEXT);
    CREATE TABLE quantity_samples (data_id INTEGER PRIMARY KEY, quantity REAL, original_quantity REAL, original_unit INTEGER);
    CREATE TABLE category_samples (data_id INTEGER PRIMARY KEY, value INTEGER);
    CREATE TABLE unit_strings (ROWID INTEGER PRIMARY KEY, unit_string TEXT);
    INSERT INTO data_provenances VALUES (1, 'Watch4,3', '20A', '9', 'America/New_York', NULL, NULL, 'iPhone12,1', '21F');
    CREATE TABLE workout_events (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, date REAL NOT NULL, \
      type INTEGER NOT NULL, duration REAL NOT NULL, metadata BLOB, session_uuid BLOB, error BLOB);
";

/// The iOS 16+ shape: `workouts` keeps the distance, `workout_activities` the
/// activity and its times, `workout_statistics` the totals. Copied from the
/// Hickman iOS 17 store (`user_version` 17012), first run of 2023-07-08.
fn ios16_workout_db() -> Vec<u8> {
    make_db(&format!(
        "{HEALTH_BASE}
         CREATE TABLE workouts (data_id INTEGER PRIMARY KEY, total_distance REAL, goal_type INTEGER, goal REAL, \
           condenser_version INTEGER, condenser_date REAL);
         CREATE TABLE workout_activities (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, uuid BLOB UNIQUE NOT NULL, \
           owner_id INTEGER NOT NULL, is_primary_activity INTEGER NOT NULL, activity_type INTEGER NOT NULL, \
           location_type INTEGER NOT NULL, swimming_location_type INTEGER NOT NULL, lap_length BLOB, \
           start_date REAL NOT NULL, end_date REAL NOT NULL, duration REAL NOT NULL, metadata BLOB);
         CREATE TABLE workout_statistics (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, workout_activity_id INTEGER NOT NULL, \
           data_type INTEGER NOT NULL, quantity REAL NOT NULL, min REAL, max REAL);
         INSERT INTO samples VALUES (142887, 79, 710509639.070725, 710511168.939034);
         INSERT INTO objects VALUES (142887, 1, 710511170.0, X'AA', 1);
         INSERT INTO workouts VALUES (142887, 4.88578759244399, 0, NULL, NULL, NULL);
         INSERT INTO workout_activities VALUES (1, X'01', 142887, 1, 37, 3, 0, NULL, 710509639.070725, 710511168.939034, 1529.868309021, NULL);
         INSERT INTO workout_statistics VALUES (1, 1, 8, 4885.78759244399, NULL, NULL);
         INSERT INTO workout_statistics VALUES (2, 1, 9, 42.6771826207705, NULL, NULL);
         INSERT INTO workout_statistics VALUES (3, 1, 10, 348.129524666862, NULL, NULL);
         INSERT INTO workout_statistics VALUES (4, 1, 5, 2.82665911249245, 1.96666666666667, 3.06666666666667);
         INSERT INTO workout_events VALUES (1, 142887, 710509639.07, 7, 283.7, NULL, NULL, NULL);
         INSERT INTO workout_events VALUES (2, 142887, 710509639.6, 6, 0.0, NULL, NULL, NULL);"
    ))
}

#[test]
fn an_ios16_workout_is_decoded_from_its_activity_and_statistics() {
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        ios16_workout_db(),
    );
    let w = one(&out, "HealthWorkout");
    assert_eq!(w["data_id"], 142887);
    assert_eq!(w["activity_type"], 37);
    assert_eq!(w["activity_type_name"], "running");
    assert_eq!(w["location_type"], 3);
    assert_eq!(w["location_type_name"], "outdoor");
    assert_eq!(w["schema"], "workout_activities");
    // 2023-07-08 11:47:19Z, the 07:47 EDT the creation PDF lists.
    assert_eq!(w["start"], 710_509_639 + 978_307_200);
    assert!((w["duration_seconds"].as_f64().unwrap() - 1529.868309021).abs() < 1e-6);
    assert!((w["total_distance_km"].as_f64().unwrap() - 4.88578759244399).abs() < 1e-9);
    assert!((w["active_energy_kcal"].as_f64().unwrap() - 348.129524666862).abs() < 1e-9);
    // Heart rate is stored per second; the PDF's 169 bpm is 2.8267 x 60.
    assert!((w["heart_rate_avg_bpm"].as_f64().unwrap() - 169.599546749547).abs() < 1e-6);
    assert!((w["heart_rate_min_bpm"].as_f64().unwrap() - 118.0).abs() < 1e-6);
    assert!((w["heart_rate_max_bpm"].as_f64().unwrap() - 184.0).abs() < 1e-6);
    assert_eq!(w["recording_timezone"], "America/New_York");
    assert_eq!(w["origin_product_type"], "Watch4,3");
    assert_eq!(w["event_rows"], 2);
    assert_eq!(w["deleted"], false);
    // Every statistic is kept, the unnamed one by its number.
    let stats = w["statistics"].as_array().unwrap();
    assert_eq!(stats.len(), 4);
    assert!(stats
        .iter()
        .any(|s| s["data_type"] == 9 && s["data_type_name_unknown"] == true));
    let s = one(&out, "HealthKitSummary");
    assert_eq!(s["workouts_decoded"], true);
    assert_eq!(s["workouts"], 1);
    assert_eq!(s["workout_schema"], "workout_activities");
}

/// The pre-iOS 16 shape: one `workouts` row carries the activity, duration,
/// energy and distance. Copied from the Hickman iOS 14.3 store (`user_version`
/// 14201), the run of 2021-01-24 the creation PDF lists at 11:30-11:53 EST.
fn ios14_workout_db(activity: i64) -> Vec<u8> {
    make_db(&format!(
        "{HEALTH_BASE}
         CREATE TABLE workouts (data_id INTEGER PRIMARY KEY, duration REAL, total_energy_burned REAL, \
           total_basal_energy_burned REAL, total_distance REAL, activity_type INTEGER, goal_type INTEGER, goal REAL, \
           total_w_steps REAL, total_flights_climbed REAL, condenser_version INTEGER, condenser_date REAL);
         INSERT INTO samples VALUES (128394, 79, 633112231.0, 633113596.5);
         INSERT INTO objects VALUES (128394, 1, 633113600.0, X'BB', 1);
         INSERT INTO workouts VALUES (128394, 1365.5019569397, 357.637087133051, 38.1536400899544, 4.88944869621473, \
           {activity}, 0, NULL, NULL, NULL, NULL, NULL);"
    ))
}

#[test]
fn a_pre_ios16_workout_is_decoded_from_the_workouts_row() {
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        ios14_workout_db(52),
    );
    let w = one(&out, "HealthWorkout");
    assert_eq!(w["schema"], "workouts");
    assert_eq!(w["activity_type"], 52);
    assert_eq!(w["activity_type_name"], "walking");
    assert!((w["duration_seconds"].as_f64().unwrap() - 1365.5019569397).abs() < 1e-9);
    assert!((w["total_distance_km"].as_f64().unwrap() - 4.88944869621473).abs() < 1e-9);
    // The energy is published with the file's own column name and no unit:
    // no answer key held pins its unit on this generation.
    assert!((w["total_energy_burned"].as_f64().unwrap() - 357.637087133051).abs() < 1e-9);
    assert!(w.get("active_energy_kcal").is_none());
    assert_eq!(w["start"], 633_112_231 + 978_307_200);
    // No location type on this generation: not stated, not guessed.
    assert!(w.get("location_type").is_none());
    let s = one(&out, "HealthKitSummary");
    assert_eq!(s["workout_schema"], "workouts");
}

#[test]
fn a_workout_of_an_unnamed_activity_keeps_its_number_and_says_so() {
    let out = run(
        &HealthKitParser,
        "healthdb_secure.sqlite",
        ios14_workout_db(13),
    );
    let w = one(&out, "HealthWorkout");
    assert_eq!(w["activity_type"], 13);
    assert!(w.get("activity_type_name").is_none());
    assert_eq!(w["activity_type_name_unknown"], true);
}

#[test]
fn sleep_samples_are_named_with_their_stage() {
    let db = make_db(&format!(
        "{HEALTH_BASE}
         INSERT INTO samples VALUES (1, 63, 743400000.0, 743403600.0);
         INSERT INTO objects VALUES (1, 1, 743403600.0, X'01', 1);
         INSERT INTO category_samples VALUES (1, 4);
         INSERT INTO samples VALUES (2, 63, 743403600.0, 743404000.0);
         INSERT INTO objects VALUES (2, 1, 743404000.0, X'02', 1);
         INSERT INTO category_samples VALUES (2, 2);
         INSERT INTO samples VALUES (3, 63, 743404000.0, 743405000.0);
         INSERT INTO objects VALUES (3, 1, 743405000.0, X'03', 1);
         INSERT INTO category_samples VALUES (3, 9);"
    ));
    let out = run(&HealthKitParser, "healthdb_secure.sqlite", db);
    let samples = of_type(&out, "HealthSample");
    assert_eq!(samples.len(), 3);
    let by_id = |id: i64| {
        &samples
            .iter()
            .find(|a| a.metadata["data_id"] == id)
            .unwrap()
            .metadata
    };
    assert_eq!(by_id(1)["data_type_name"], "sleep_analysis");
    assert_eq!(by_id(1)["sleep_stage"], "asleep_deep");
    assert_eq!(by_id(1)["asleep"], true);
    assert_eq!(by_id(2)["sleep_stage"], "awake");
    assert_eq!(by_id(2)["asleep"], false);
    // A value outside the enum is kept and not named.
    assert!(by_id(3).get("sleep_stage").is_none());
    assert_eq!(by_id(3)["sleep_stage_unknown"], true);
    let s = one(&out, "HealthKitSummary");
    assert_eq!(s["sleep_decoded"], true);
    assert_eq!(s["sleep_samples"], 3);
}

// ---------------------------------------------------------------------------
// Voice Memos (CloudRecordings.db)
// ---------------------------------------------------------------------------

/// The iOS 18 shape (MSAB 2026 iPhone 12, iOS 18.7): `ZPATH` is the bare
/// file name beside the database in `AppGroup/<uuid>/Recordings/`.
fn ios18_recordings_db() -> Vec<u8> {
    make_db(
        "CREATE TABLE ZCLOUDRECORDING ( Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZFLAGS INTEGER, \
           ZSHAREDFLAGS INTEGER, ZSILENCEREMOVERENABLED INTEGER, ZFOLDER INTEGER, ZDATE TIMESTAMP, ZDURATION FLOAT, \
           ZEVICTIONDATE TIMESTAMP, ZLOCALDURATION FLOAT, ZMTLAYERMIX FLOAT, ZPLAYBACKPOSITION FLOAT, \
           ZPLAYBACKRATE FLOAT, ZCUSTOMLABEL VARCHAR, ZCUSTOMLABELFORSORTING VARCHAR, ZENCRYPTEDTITLE VARCHAR, \
           ZPATH VARCHAR, ZUNIQUEID VARCHAR, ZAUDIOFUTUREUUIDS BLOB, ZAUDIODIGEST BLOB, ZAUDIOFUTURE BLOB, \
           ZMTAUDIOFUTURE BLOB );
         CREATE TABLE ZFOLDER ( Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZCOUNTOFRECORDINGS INTEGER, \
           ZRANK INTEGER, ZENCRYPTEDNAME VARCHAR, ZUUID VARCHAR );
         INSERT INTO ZFOLDER VALUES (1, 4, 1, 1, 0, 'Huh', 'A7B62C13');
         INSERT INTO ZCLOUDRECORDING (Z_PK, Z_ENT, ZFLAGS, ZDATE, ZDURATION, ZCUSTOMLABEL, ZENCRYPTEDTITLE, ZPATH, ZUNIQUEID) \
           VALUES (1, 1, 4, 787880212.5, 19.7295625, '2025-12-19T23:36:52Z', 'Flour Bakery + Café', \
           '20251219 183652.m4a', '4B176F07-F4E9-4F23-9687-4999E83595A3');
         INSERT INTO ZCLOUDRECORDING (Z_PK, Z_ENT, ZFLAGS, ZDATE, ZDURATION, ZEVICTIONDATE, ZCUSTOMLABEL, ZENCRYPTEDTITLE, ZPATH, ZUNIQUEID, ZFOLDER) \
           VALUES (2, 1, 4, 787880250.0, 15.7, 787880300.0, '2025-12-19T23:37:30Z', 'Flour Bakery + Café 2', \
           '20251219 183730.m4a', 'D02A1ED2-02C8-440E-BE81-BA708BFE6B9C', 1);",
    )
}

#[test]
fn a_voice_memo_is_read_with_its_title_times_and_the_audio_beside_it() {
    let out = run_in_dir(
        &VoiceMemosParser,
        "Recordings/CloudRecordings.db",
        &[
            ("Recordings/CloudRecordings.db", ios18_recordings_db()),
            (
                "Recordings/20251219 183652.m4a",
                b"\0\0\0\x18ftypM4A audio".to_vec(),
            ),
        ],
    );
    let memos = of_type(&out, "VoiceMemo");
    assert_eq!(memos.len(), 2, "{out:#?}");
    let first = &memos
        .iter()
        .find(|a| a.metadata["recording_id"] == 1)
        .unwrap()
        .metadata;
    assert_eq!(first["title"], "Flour Bakery + Café");
    assert_eq!(first["title_source"], "ZENCRYPTEDTITLE");
    assert_eq!(first["date"], 787_880_212 + 978_307_200);
    assert_eq!(
        first["date_ns"],
        (787_880_212_i64 + 978_307_200) * 1_000_000_000 + 500_000_000
    );
    assert!((first["duration_seconds"].as_f64().unwrap() - 19.7295625).abs() < 1e-9);
    assert_eq!(first["file_name"], "20251219 183652.m4a");
    assert_eq!(first["unique_id"], "4B176F07-F4E9-4F23-9687-4999E83595A3");
    assert_eq!(first["audio_present"], true);
    assert_eq!(first["audio_bytes"], 17);
    let second = &memos
        .iter()
        .find(|a| a.metadata["recording_id"] == 2)
        .unwrap()
        .metadata;
    // The audio is not beside the database: said, not guessed.
    assert_eq!(second["audio_present"], false);
    assert_eq!(second["folder"], "Huh");
    // The eviction date is published by its column; what it means is not
    // validated on any device held.
    assert_eq!(second["eviction_date"], 787_880_300 + 978_307_200);
    assert_eq!(second["eviction_date_meaning_validated"], false);
    let s = one(&out, "VoiceMemosSummary");
    assert_eq!(s["recordings"], 2);
    assert_eq!(s["audio_present"], 1);
    assert_eq!(s["audio_absent"], 1);
    assert_eq!(s["with_eviction_date"], 1);
}

#[test]
fn a_voice_memo_audio_path_is_resolved_by_its_file_name_on_ios16() {
    // iOS 16.5 (Cellebrite 2023 "Abe"): ZPATH is absolute, and the title is
    // in ZCUSTOMLABEL and ZENCRYPTEDTITLE both.
    let db = make_db(
        "CREATE TABLE ZCLOUDRECORDING ( Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZFLAGS INTEGER, \
           ZSHAREDFLAGS INTEGER, ZFOLDER INTEGER, ZDATE TIMESTAMP, ZDURATION FLOAT, ZEVICTIONDATE TIMESTAMP, \
           ZLOCALDURATION FLOAT, ZCUSTOMLABEL VARCHAR, ZCUSTOMLABELFORSORTING VARCHAR, ZENCRYPTEDTITLE VARCHAR, \
           ZPATH VARCHAR, ZUNIQUEID VARCHAR, ZAUDIODIGEST BLOB, ZAUDIOFUTURE BLOB );
         INSERT INTO ZCLOUDRECORDING (Z_PK, ZFLAGS, ZDATE, ZDURATION, ZCUSTOMLABEL, ZENCRYPTEDTITLE, ZPATH, ZUNIQUEID) \
           VALUES (13, 4, 700777222.0, 140.642541666667, 'New Recording 3', 'New Recording 3', \
           '/var/mobile/Library/Recordings/20230317 182022.m4a', 'A78EBDC8');",
    );
    let out = run_in_dir(
        &VoiceMemosParser,
        "CloudRecordings.db",
        &[
            ("CloudRecordings.db", db),
            ("20230317 182022.m4a", vec![0u8; 32]),
        ],
    );
    let m = one(&out, "VoiceMemo");
    assert_eq!(m["title"], "New Recording 3");
    assert_eq!(
        m["path"],
        "/var/mobile/Library/Recordings/20230317 182022.m4a"
    );
    assert_eq!(m["file_name"], "20230317 182022.m4a");
    assert_eq!(m["audio_present"], true);
}

#[test]
fn a_voice_memos_store_read_from_a_source_that_cannot_look_beside_it_says_so() {
    let out = run(
        &VoiceMemosParser,
        "CloudRecordings.db",
        ios18_recordings_db(),
    );
    let memos = of_type(&out, "VoiceMemo");
    assert_eq!(memos.len(), 2);
    for m in memos {
        assert!(
            m.metadata.get("audio_present").is_none(),
            "{:?}",
            m.metadata
        );
        assert_eq!(
            m.metadata["audio_unresolved"],
            "source_cannot_open_neighbours"
        );
    }
    let s = one(&out, "VoiceMemosSummary");
    assert_eq!(s["audio_unresolved"], 2);
}

#[test]
fn an_empty_voice_memos_store_is_counted_as_zero_not_silent() {
    // Hickman iOS 13.4.1 / 14.3, Magnet 2020 / 2021: the table, no rows.
    let db = make_db(
        "CREATE TABLE ZCLOUDRECORDING ( Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZFLAGS INTEGER, \
           ZITUNESPERSISTENTID INTEGER, ZDATE TIMESTAMP, ZDURATION FLOAT, ZEVICTIONDATE TIMESTAMP, ZCKRECORDID VARCHAR, \
           ZCUSTOMLABEL VARCHAR, ZPATH VARCHAR, ZUNIQUEID VARCHAR, ZAUDIOFUTURE BLOB, ZCKRECORDSYSTEMFIELDS BLOB );",
    );
    let out = run(&VoiceMemosParser, "CloudRecordings.db", db);
    let s = one(&out, "VoiceMemosSummary");
    assert_eq!(s["recordings"], 0);
}

// ---------------------------------------------------------------------------
// Voicemail audio and transcripts
// ---------------------------------------------------------------------------

/// A `voicemail.db` in the iOS 12 shape (Magnet 2020 iPhone, iOS 12.4).
fn voicemail_db(rows: &str) -> Vec<u8> {
    make_db(&format!(
        "CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, remote_uid INTEGER, date INTEGER, \
           token TEXT, sender TEXT, callback_num TEXT, duration INTEGER, expiration INTEGER, trashed_date INTEGER, \
           flags INTEGER, receiver TEXT);
         {rows}"
    ))
}

/// An `NSKeyedArchiver` transcript in the shape `1.transcript` has on the
/// Magnet 2020 iPhone: a `VMVoicemailTranscript` root with
/// `transcriptionString`, `confidence`, `confidenceRating` and `segments`.
fn transcript_plist(text: &str, confidence: f64) -> Vec<u8> {
    use plist::{Dictionary, Uid, Value as P};
    let mut root = Dictionary::new();
    root.insert("transcriptionString".into(), P::Uid(Uid::new(3)));
    root.insert("confidence".into(), P::Real(confidence));
    root.insert("confidenceRating".into(), P::Integer(2.into()));
    root.insert("segments".into(), P::Uid(Uid::new(2)));
    root.insert("$class".into(), P::Uid(Uid::new(4)));
    let mut seg = Dictionary::new();
    seg.insert("NS.objects".into(), P::Array(vec![]));
    let mut class = Dictionary::new();
    class.insert(
        "$classname".into(),
        P::String("VMVoicemailTranscript".into()),
    );
    class.insert(
        "$classes".into(),
        P::Array(vec![
            P::String("VMVoicemailTranscript".into()),
            P::String("NSObject".into()),
        ]),
    );
    let objects = vec![
        P::String("$null".into()),
        P::Dictionary(root),
        P::Dictionary(seg),
        P::String(text.into()),
        P::Dictionary(class),
    ];
    let mut top = Dictionary::new();
    top.insert("root".into(), P::Uid(Uid::new(1)));
    let mut d = Dictionary::new();
    d.insert("$archiver".into(), P::String("NSKeyedArchiver".into()));
    d.insert("$version".into(), P::Integer(100000.into()));
    d.insert("$top".into(), P::Dictionary(top));
    d.insert("$objects".into(), P::Array(objects));
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &P::Dictionary(d)).unwrap();
    out
}

fn amr(len: usize) -> Vec<u8> {
    let mut v = b"#!AMR\n".to_vec();
    v.resize(len, 0x3c);
    v
}

#[test]
fn a_voicemail_carries_its_audio_and_transcript_from_beside_the_store() {
    let db = voicemail_db(
        "INSERT INTO voicemail VALUES (1, 17, 1583019961, NULL, '+15188577515', NULL, 5, 0, 0, 4363, NULL);
         INSERT INTO voicemail VALUES (2, 70, 1583849459, NULL, '+15188577515', NULL, 9, 0, 0, 4354, NULL);",
    );
    let out = run_in_dir(
        &VoicemailParser,
        "voicemail.db",
        &[
            ("voicemail.db", db),
            ("1.amr", amr(8486)),
            (
                "1.transcript",
                transcript_plist(
                    "Hey it's Paul is Joe going to see if you want to go good day dear",
                    0.5415,
                ),
            ),
        ],
    );
    let vms = of_type(&out, "Voicemail");
    let by = |id: i64| {
        &vms.iter()
            .find(|a| a.metadata["rowid"] == id)
            .unwrap()
            .metadata
    };
    let one_ = by(1);
    assert_eq!(one_["audio_present"], true);
    assert_eq!(one_["audio_file"], "1.amr");
    assert_eq!(one_["audio_bytes"], 8486);
    assert_eq!(one_["audio_format"], "amr");
    assert_eq!(
        one_["transcript"],
        "Hey it's Paul is Joe going to see if you want to go good day dear"
    );
    assert!((one_["transcript_confidence"].as_f64().unwrap() - 0.5415).abs() < 1e-9);
    assert_eq!(one_["transcript_source"], "1.transcript");
    // Row 2 has neither beside it: said, not guessed.
    let two = by(2);
    assert_eq!(two["audio_present"], false);
    assert_eq!(two["transcript_present"], false);
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s["audio_present"], 1);
    assert_eq!(s["transcripts_read"], 1);
}

#[test]
fn a_voicemail_audio_file_with_no_row_is_reported_as_an_orphan() {
    // Magnet 2020: 5.amr sits between rows 4 and 6 of an AUTOINCREMENT table
    // and no row names it.
    let db = voicemail_db(
        "INSERT INTO voicemail VALUES (4, 72, 1584732872, NULL, '+15184246993', NULL, 17, 0, 0, 4354, NULL);
         INSERT INTO voicemail VALUES (6, 73, 1584975804, NULL, '+18003235000', NULL, 154, 0, 0, 4354, NULL);",
    );
    let out = run_in_dir(
        &VoicemailParser,
        "voicemail.db",
        &[
            ("voicemail.db", db),
            ("4.amr", amr(100)),
            ("5.amr", amr(234_789)),
            ("6.amr", amr(200)),
            ("notes.txt", b"x".to_vec()),
        ],
    );
    let orphan = one(&out, "VoicemailAudioOrphan");
    assert_eq!(orphan["audio_file"], "5.amr");
    assert_eq!(orphan["audio_bytes"], 234_789);
    assert_eq!(orphan["implied_rowid"], 5);
    assert_eq!(orphan["deleted_row_inferred"], false);
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s["orphan_audio_files"], 1);
}

#[test]
fn a_voicemail_store_whose_source_cannot_look_beside_it_says_so() {
    let db = voicemail_db(
        "INSERT INTO voicemail VALUES (1, 17, 1583019961, NULL, '+15188577515', NULL, 5, 0, 0, 4363, NULL);",
    );
    let out = run(&VoicemailParser, "voicemail.db", db);
    let vm = one(&out, "Voicemail");
    assert!(vm.get("audio_present").is_none(), "{vm}");
    assert_eq!(vm["audio_unresolved"], "source_cannot_open_neighbours");
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s["orphan_audio_files_unresolved"], true);
}

#[test]
fn a_transcript_that_is_not_a_keyed_archive_is_present_and_unread() {
    let db = voicemail_db(
        "INSERT INTO voicemail VALUES (1, 17, 1583019961, NULL, '+15188577515', NULL, 5, 0, 0, 4363, NULL);",
    );
    let out = run_in_dir(
        &VoicemailParser,
        "voicemail.db",
        &[
            ("voicemail.db", db),
            ("1.transcript", b"not a plist".to_vec()),
        ],
    );
    let vm = one(&out, "Voicemail");
    assert_eq!(vm["transcript_present"], true);
    assert!(vm.get("transcript").is_none());
    assert!(vm["transcript_unread_reason"].is_string(), "{vm}");
}

// ---------------------------------------------------------------------------
// Note attachments and deleted notes
// ---------------------------------------------------------------------------

/// A NoteStore in the iOS 18 shape (MSAB 2026 iPhone 12: ICAttachment 4,
/// ICMedia 10, ICNote 11, ICAccount 13, ICFolder 14): a live note with a PNG
/// whose media sits under `Accounts/<account>/Media/<media>/<generation>/`,
/// and a note marked for deletion in Recently Deleted with a JPEG whose
/// media file is present and empty.
fn notestore_with_attachments() -> Vec<u8> {
    make_db(
        "CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
         INSERT INTO Z_PRIMARYKEY VALUES (4, 'ICAttachment', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (10, 'ICMedia', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (11, 'ICNote', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (13, 'ICAccount', 2, 1);
         INSERT INTO Z_PRIMARYKEY VALUES (14, 'ICFolder', 2, 3);
         CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, \
           ZISPASSWORDPROTECTED INTEGER, ZMARKEDFORDELETION INTEGER, ZFILESIZE INTEGER, ZMEDIA INTEGER, \
           ZNOTE INTEGER, ZACCOUNT2 INTEGER, ZACCOUNT3 INTEGER, ZACCOUNT4 INTEGER, ZACCOUNT7 INTEGER, \
           ZFOLDER INTEGER, ZFOLDERTYPE INTEGER, ZCREATIONDATE TIMESTAMP, ZMODIFICATIONDATE TIMESTAMP, \
           ZSIZEHEIGHT FLOAT, ZSIZEWIDTH FLOAT, ZIDENTIFIER VARCHAR, ZTITLE VARCHAR, ZTYPEUTI VARCHAR, \
           ZFILENAME VARCHAR, ZGENERATION1 VARCHAR, ZSNIPPET VARCHAR, ZTITLE1 VARCHAR, ZTITLE2 VARCHAR);
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZIDENTIFIER) VALUES (1, 13, 'ACCT-1');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZFOLDERTYPE, ZACCOUNT3, ZIDENTIFIER, ZTITLE2) \
           VALUES (2, 14, 0, 1, 'F-1', 'Notes');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZFOLDERTYPE, ZACCOUNT3, ZIDENTIFIER, ZTITLE2) \
           VALUES (3, 14, 1, 1, 'F-2', 'Recently Deleted');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZACCOUNT7, ZFOLDER, ZCREATIONDATE, \
           ZMODIFICATIONDATE, ZTITLE1, ZIDENTIFIER) VALUES (25, 11, 0, 1, 2, 787200000.0, 787200100.0, 'Gear', 'N-25');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZISPASSWORDPROTECTED, ZFILESIZE, ZMEDIA, \
           ZNOTE, ZACCOUNT2, ZCREATIONDATE, ZSIZEHEIGHT, ZSIZEWIDTH, ZIDENTIFIER, ZTITLE, ZTYPEUTI) \
           VALUES (24, 4, 0, 0, 83062, 28, 25, 1, 787200129.0, 205.0, 214.0, 'ATT-24', \
           'Screenshot 2025-12-11 at 4.29.52 PM.png', 'public.png');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZISPASSWORDPROTECTED, ZACCOUNT4, \
           ZIDENTIFIER, ZFILENAME, ZGENERATION1) \
           VALUES (28, 10, 0, 0, 1, 'MEDIA-28', 'Screenshot 2025-12-11 at 4.29.52 PM.png', '1_GEN');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZACCOUNT7, ZFOLDER, ZCREATIONDATE, \
           ZMODIFICATIONDATE, ZIDENTIFIER) VALUES (73, 11, 1, 1, 3, 787880835.0, 787880848.0, 'N-73');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZISPASSWORDPROTECTED, ZFILESIZE, ZMEDIA, \
           ZNOTE, ZACCOUNT2, ZIDENTIFIER, ZTYPEUTI) \
           VALUES (76, 4, 1, 0, 116059, 83, 73, 1, 'ATT-76', 'public.jpeg');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZISPASSWORDPROTECTED, ZACCOUNT4, \
           ZIDENTIFIER, ZFILENAME, ZGENERATION1) VALUES (83, 10, 1, 0, 1, 'MEDIA-83', 'Image.jpeg', '2_GEN');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZMARKEDFORDELETION, ZISPASSWORDPROTECTED, ZTYPEUTI, ZNOTE, \
           ZIDENTIFIER) VALUES (20, 4, 0, 0, 'com.apple.paper', 25, 'ATT-20');",
    )
}

#[test]
fn a_note_attachment_is_read_with_its_media_file_and_its_deletion_state() {
    let out = run_in_dir(
        &NotesParser,
        "NoteStore.sqlite",
        &[
            ("NoteStore.sqlite", notestore_with_attachments()),
            (
                "Accounts/ACCT-1/Media/MEDIA-28/1_GEN/Screenshot 2025-12-11 at 4.29.52 PM.png",
                vec![0x89; 83_062],
            ),
            (
                "Accounts/ACCT-1/Media/MEDIA-83/2_GEN/Image.jpeg",
                Vec::new(),
            ),
        ],
    );
    let atts = of_type(&out, "NoteAttachment");
    assert_eq!(atts.len(), 3, "{out:#?}");
    let by = |id: i64| {
        &atts
            .iter()
            .find(|a| a.metadata["attachment_id"] == id)
            .unwrap()
            .metadata
    };
    let png = by(24);
    assert_eq!(png["note_id"], 25);
    assert_eq!(png["note_title"], "Gear");
    assert_eq!(png["type_uti"], "public.png");
    assert_eq!(png["title"], "Screenshot 2025-12-11 at 4.29.52 PM.png");
    assert_eq!(png["file_size"], 83062);
    assert_eq!(
        png["media_path"],
        "Accounts/ACCT-1/Media/MEDIA-28/1_GEN/Screenshot 2025-12-11 at 4.29.52 PM.png"
    );
    assert_eq!(png["media_present"], true);
    assert_eq!(png["media_bytes"], 83_062);
    assert_eq!(png["deleted"], false);
    let jpeg = by(76);
    assert_eq!(jpeg["deleted"], true);
    assert_eq!(jpeg["marked_for_deletion"], true);
    assert_eq!(jpeg["note_deleted"], true);
    // The file is there and empty: the bytes are gone, and the record says
    // so rather than "present".
    assert_eq!(jpeg["media_present"], true);
    assert_eq!(jpeg["media_bytes"], 0);
    assert_eq!(jpeg["media_empty"], true);
    // A drawing keeps no media file of its own.
    let paper = by(20);
    assert_eq!(paper["type_uti"], "com.apple.paper");
    assert!(paper.get("media_path").is_none());
    assert_eq!(paper["media_not_applicable"], true);
    let s = one(&out, "NotesSummary");
    assert_eq!(s["attachments_decoded"], true);
    assert_eq!(s["attachments"], 3);
    assert_eq!(s["deleted_attachments"], 1);
    assert_eq!(s["attachment_media_present"], 2);
    // The deleted note itself: marked, in Recently Deleted.
    let note = &of_type(&out, "Note")
        .into_iter()
        .find(|a| a.metadata["note_id"] == 73)
        .unwrap()
        .metadata;
    assert_eq!(note["deleted"], true);
    assert_eq!(note["marked_for_deletion"], true);
    assert_eq!(note["in_recently_deleted"], true);
    assert_eq!(note["attachments"], 1);
}

#[test]
fn a_locked_note_attachment_says_its_media_is_ciphertext() {
    // MSAB 2026: a password-protected attachment's media has no ZFILENAME and
    // is stored under the media identifier.
    let db = make_db(
        "CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
         INSERT INTO Z_PRIMARYKEY VALUES (4, 'ICAttachment', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (10, 'ICMedia', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (11, 'ICNote', 2, 90);
         INSERT INTO Z_PRIMARYKEY VALUES (13, 'ICAccount', 2, 1);
         CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZISPASSWORDPROTECTED INTEGER, \
           ZMARKEDFORDELETION INTEGER, ZMEDIA INTEGER, ZNOTE INTEGER, ZACCOUNT4 INTEGER, ZIDENTIFIER VARCHAR, \
           ZTYPEUTI VARCHAR, ZFILENAME VARCHAR, ZGENERATION1 VARCHAR, ZTITLE1 VARCHAR, ZCREATIONDATE TIMESTAMP, \
           ZMODIFICATIONDATE TIMESTAMP, ZSNIPPET VARCHAR);
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZIDENTIFIER) VALUES (1, 13, 'ACCT-1');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZISPASSWORDPROTECTED, ZACCOUNT4, ZTITLE1) VALUES (60, 11, 1, 1, 'Locked');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZISPASSWORDPROTECTED, ZMEDIA, ZNOTE, ZIDENTIFIER, ZTYPEUTI) \
           VALUES (61, 4, 1, 70, 60, 'ATT-61', 'public.jpeg');
         INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, Z_ENT, ZISPASSWORDPROTECTED, ZACCOUNT4, ZIDENTIFIER, ZGENERATION1) \
           VALUES (70, 10, 1, 1, 'MEDIA-70', '1_GEN');",
    );
    let out = run_in_dir(
        &NotesParser,
        "NoteStore.sqlite",
        &[
            ("NoteStore.sqlite", db),
            (
                "Accounts/ACCT-1/Media/MEDIA-70/1_GEN/MEDIA-70",
                vec![0x62; 500],
            ),
        ],
    );
    let a = one(&out, "NoteAttachment");
    assert_eq!(a["password_protected"], true);
    assert_eq!(
        a["media_path"],
        "Accounts/ACCT-1/Media/MEDIA-70/1_GEN/MEDIA-70"
    );
    assert_eq!(a["media_present"], true);
    assert_eq!(a["media_encrypted"], true);
}
