//! A recognised iOS database that cannot be staged must say so, not go quiet.
//!
//! # Why this is its own test binary
//!
//! The only way to make `TempDb::spill` fail is to make the temporary directory
//! unwritable, and it chooses that directory with `std::env::temp_dir()` —
//! which reads `TMPDIR`, a **process-global** variable. Cargo runs the tests in
//! one binary on several threads, so a test that changes it changes it for
//! every test running beside it.
//!
//! That is not theoretical: this test lived in the unit-test module first and
//! broke a neighbour that was staging a database at the same moment. An
//! integration test gets its own process, and being the only test in this file
//! means there is nothing beside it to disturb.
//!
//! # What it covers
//!
//! B8-038's shape, found in a third place. The name matched and the bytes
//! really are SQLite, so returning nothing reads as "this device held no
//! records of this kind" — a claim about the custodian that nothing here
//! established. The PST and Timeline readers were fixed; this one was missed by
//! that class sweep.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// A minimal but genuine SQLite database, so the parser's own magic check
/// passes and the failure under test is the staging and nothing else.
fn voicemail_db() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("seance_unstageable_seed_{}.db", Uuid::new_v4()));
    {
        let conn = rusqlite::Connection::open(&path).expect("seed database");
        conn.execute_batch("CREATE TABLE voicemail (ROWID INTEGER PRIMARY KEY, sender TEXT);")
            .expect("seed schema");
    }
    let bytes = std::fs::read(&path).expect("read the seed back");
    let _ = std::fs::remove_file(&path);
    bytes
}

#[test]
fn an_unstageable_database_produces_a_status_record_rather_than_silence() {
    let bytes = voicemail_db();
    assert_eq!(
        &bytes[..15],
        b"SQLite format 3",
        "the seed must be real SQLite"
    );

    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": "voicemail.db" }),
    );

    // Point the spill at a directory that does not exist. This is the condition
    // an examiner meets when the spill volume fills mid-case.
    let previous = std::env::var("TMPDIR").ok();
    std::env::set_var("TMPDIR", format!("/nonexistent-seance-{}", Uuid::new_v4()));

    let produced = seance_plugin_ios_artifacts::VoicemailParser
        .process(&artifact)
        .expect("the module never errors");

    match previous {
        Some(v) => std::env::set_var("TMPDIR", v),
        None => std::env::remove_var("TMPDIR"),
    }

    assert!(
        !produced.is_empty(),
        "an identified iOS database that could not be staged produced nothing at all, which \
         reads as a device with no voicemails"
    );
    let status = &produced[0].metadata;
    assert_eq!(status["status"], json!("DatabaseUnreadable"));
    assert_eq!(status["content_incomplete"], json!(true));
    assert_eq!(status["records_recovered"], json!(0));
    assert!(
        status["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("could not be staged"),
        "the record must say what failed: {:?}",
        status["detail"]
    );
    assert_eq!(
        status["subtype"],
        json!("parse_incomplete"),
        "it must carry the subtype the Timeline and PST readers use, so a consumer filtering \
         for unreadable databases finds all of them"
    );
}
