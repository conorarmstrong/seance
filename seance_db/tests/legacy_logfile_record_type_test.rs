//! UI-009: a `$LogFile` record ingested before the type fix must still reach
//! the class it belongs to, without its stored metadata being rewritten.
//!
//! NTFS `$LogFile` records carried no `$.type`, so the record-type
//! discriminator fell through onto `$.record_type` — a **numeric** field
//! describing one field of one record — and the largest record class in an NTFS
//! case (73,640 records on the case it was found in) appeared under a card and
//! a viewer heading titled `1`. `seance_plugin_logfile` now writes
//! `"type": "NtfsLogFileRecord"`, which is right for every ingest from that
//! change on and does nothing for a case that was ingested before it.
//!
//! The repair for those cases is made at read time, in
//! `SqliteConnection::RECORD_TYPE_EXPR`, rather than by back-filling `$.type`
//! onto the stored rows: those rows belong to cases that have been examined and
//! may have been reported on, and rewriting stored artifact metadata to improve
//! a label is a mutation of the record that nothing afterwards would show.
//!
//! These tests assert both halves of that decision — the label is corrected,
//! **and** the stored metadata is untouched — because a test for only the first
//! would pass just as happily against the migration the decision rejected.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Legacy LogFile", "Examiner").await?;
    Ok((db, case_id))
}

async fn record(db: &SqliteConnection, case_id: Uuid, metadata: serde_json::Value) -> Result<Uuid> {
    let a = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata,
        data: None,
    };
    db.record_artifact(&a).await?;
    Ok(a.id)
}

/// A `$LogFile` record exactly as the parser wrote it **before** `1a6827e0`:
/// no `$.type`, and the NTFS record-type number under the bare `record_type`
/// key that the analysis grouping reads as a category *name*.
///
/// Taken from `git show 1a6827e0^:seance_plugin_logfile/src/lib.rs` rather than
/// invented, because a fixture for a legacy shape is worth nothing if it is not
/// the shape that is actually in people's cases.
fn legacy_logfile(record_number: i64) -> serde_json::Value {
    json!({
        "record_number": record_number,
        "lsn": format!("0x{:016x}", 0x1001 + record_number),
        "page_number": 1,
        "operation": "InitializeFileRecordSegment",
        "target_attribute": 0,
        "undo_operation": 0,
        "redo_operation": 2,
        "undo_operation_name": "Noop",
        "redo_data_length": 42,
        "undo_data_length": 0,
        "target_vcn": 0,
        "target_lcn": 0,
        "transaction_id": 0,
        "record_type": 1,
        "multi_page": false,
        "source": "$LogFile",
    })
}

/// The same record as the parser writes it now: `$.type` names the class, and
/// the NTFS record-type number moved off the bare `record_type` key onto
/// `ntfs_record_type`, where a number is a value rather than a category name.
fn current_logfile(record_number: i64) -> serde_json::Value {
    let mut v = legacy_logfile(record_number);
    let ntfs_record_type = v["record_type"].take();
    v.as_object_mut()
        .expect("the fixture is an object")
        .remove("record_type");
    v["ntfs_record_type"] = ntfs_record_type;
    v["type"] = json!("NtfsLogFileRecord");
    v
}

#[tokio::test]
async fn a_logfile_record_ingested_before_the_type_fix_is_no_longer_listed_as_1() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..3 {
        record(&db, case_id, legacy_logfile(i)).await?;
    }

    let counts = db.record_type_counts(case_id, None).await?;

    let as_one: i64 = counts
        .iter()
        .filter(|(record_type, _)| record_type == "1")
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(
        as_one, 0,
        "no record class may be titled \"1\"; that number is a field of one record, \
         not the name of a kind of record. Counts were: {counts:?}"
    );

    let as_logfile: i64 = counts
        .iter()
        .filter(|(record_type, _)| record_type == "NtfsLogFileRecord")
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(
        as_logfile, 3,
        "all three legacy records belong to the NtfsLogFileRecord class: {counts:?}"
    );
    Ok(())
}

/// The census is one half; the drill-down is the other. A label corrected only
/// on the card would send the examiner to an empty listing, which is worse than
/// the wrong label — it reads as an absence of evidence.
#[tokio::test]
async fn the_corrected_class_opens_onto_the_records_it_counted() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..4 {
        record(&db, case_id, legacy_logfile(i)).await?;
    }

    let (records, total) = db
        .list_records_by_type(case_id, "NtfsLogFileRecord", None, 1, 100)
        .await?;

    assert_eq!(
        total, 4,
        "the listing must find every record the census counted"
    );
    assert_eq!(records.len(), 4);
    Ok(())
}

/// Old and new records are one class, not two. A case ingested across the fix —
/// or a case re-ingested beside an old one — must not show `NtfsLogFileRecord`
/// twice, or once beside a `1`.
#[tokio::test]
async fn records_from_both_sides_of_the_fix_form_one_class() -> Result<()> {
    let (db, case_id) = setup().await?;
    for i in 0..2 {
        record(&db, case_id, legacy_logfile(i)).await?;
    }
    for i in 2..5 {
        record(&db, case_id, current_logfile(i)).await?;
    }

    let counts = db.record_type_counts(case_id, None).await?;
    let logfile: Vec<_> = counts
        .iter()
        .filter(|(record_type, _)| record_type == "NtfsLogFileRecord")
        .collect();

    assert_eq!(
        logfile.len(),
        1,
        "one class, not one per metadata generation: {counts:?}"
    );
    assert_eq!(logfile[0].1, 5, "all five records: {counts:?}");

    let (_, total) = db
        .list_records_by_type(case_id, "NtfsLogFileRecord", None, 1, 100)
        .await?;
    assert_eq!(total, 5, "and the listing agrees with the census");
    Ok(())
}

/// The half of the decision that a back-fill migration would fail.
///
/// The label is derived at read time; the stored artifact is exactly the bytes
/// the parser wrote, `$.type` still absent and the numeric `record_type` still
/// there. This is the assertion that says the record was not edited to make a
/// screen read better.
#[tokio::test]
async fn the_stored_metadata_is_left_exactly_as_the_parser_wrote_it() -> Result<()> {
    let (db, case_id) = setup().await?;
    let id = record(&db, case_id, legacy_logfile(7)).await?;

    let stored = db.get_artifact_details(case_id, id).await?;

    assert!(
        stored.metadata.get("type").is_none(),
        "deriving the label must not write one: {:?}",
        stored.metadata
    );
    assert_eq!(
        stored.metadata.get("record_type"),
        Some(&json!(1)),
        "the numeric record_type is what the parser found and stays what it found"
    );
    assert_eq!(stored.metadata.get("record_number"), Some(&json!(7)));
    Ok(())
}

/// The arm must not reach past the shape it was written for.
///
/// `$.redo_operation` is emitted only by `seance_plugin_logfile`, and `$.lsn`
/// is required beside it because `seance_plugin_memory_windows`'s MFT scanner
/// emits an `lsn` of its own. A record carrying one without the other, or
/// carrying its own `$.type`, must be untouched by this.
#[tokio::test]
async fn nothing_but_a_legacy_logfile_record_is_relabelled() -> Result<()> {
    let (db, case_id) = setup().await?;

    // An MFT-scan record from memory: an lsn, but no redo operation.
    record(
        &db,
        case_id,
        json!({ "subtype": "MftScanRecord", "lsn": 4242, "record_number": 5 }),
    )
    .await?;
    // A record with a redo operation and no lsn — not the shape either.
    record(
        &db,
        case_id,
        json!({ "record_type": 9, "redo_operation": 2 }),
    )
    .await?;
    // And a record that names its own type, which must always win.
    record(
        &db,
        case_id,
        json!({
            "type": "SomethingElse",
            "lsn": "0x00",
            "redo_operation": 2,
            "record_type": 1,
        }),
    )
    .await?;

    let counts = db.record_type_counts(case_id, None).await?;
    let named: Vec<&str> = counts
        .iter()
        .map(|(record_type, _)| record_type.as_str())
        .collect();

    assert!(
        !named.contains(&"NtfsLogFileRecord"),
        "none of these is a $LogFile record: {counts:?}"
    );
    assert!(named.contains(&"MftScanRecord"), "{counts:?}");
    assert!(named.contains(&"SomethingElse"), "{counts:?}");
    assert!(
        named.contains(&"9"),
        "a record that genuinely has nothing but a numeric record_type still \
         falls through to it: {counts:?}"
    );
    Ok(())
}
