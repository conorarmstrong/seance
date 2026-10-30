//! A file's own filesystem timestamps are timeline evidence.
//!
//! Before this suite, `timeline_events` was populated only by plugins that
//! construct `TimelineEvent` artifacts themselves ($MFT, EVTX, prefetch, LNK,
//! SRUM, ...). Every other `FileEntry` producer — ext4, XFS, APFS, Btrfs,
//! F2FS, FAT/exFAT, HFS+, ISO9660, SquashFS, iOS backups, archive members —
//! recorded real `created`/`modified`/`accessed` values in the artifact's
//! metadata and contributed NOTHING to the timeline. An ext4 image with tens of
//! thousands of dated files produced an EMPTY timeline and a dashboard reading
//! "No dated events", which is the one thing a forensic timeline must never say
//! about evidence that demonstrably carries timestamps.
//!
//! The projection lives on the database write path (as the chat-message
//! projection already does) so that ONE implementation covers every producer,
//! present and future, without a parser change.
//!
//! What these tests pin:
//!   * both write paths (single and batch) project a `FileEntry`'s MAC times;
//!   * timestamps that name the SAME instant coalesce into one row carrying
//!     every kind, mactime-style, instead of N identical rows;
//!   * a producer that emits its own richer file-timeline events (the $MFT
//!     parser, with $SI/$FN provenance and timestomping verdicts) opts out and
//!     is not reported twice;
//!   * a file with no timestamps, or an unparseable one, is never pinned to a
//!     guessed instant — absent stays absent, and the artifact still records;
//!   * sub-second precision and the source UTC offset survive the projection;
//!   * `full_details` is valid JSON carrying `filename`, which migration 0005's
//!     generated column and the filename filter both depend on.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType, FILE_TIMELINE_SELF_EMITTED_KEY};
use seance_core::db::DatabaseConnection;
use seance_db::{SqliteConnection, FILE_TIMELINE_SOURCE_MODULE};
use serde_json::json;
use uuid::Uuid;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

fn file_entry(case_id: Uuid, metadata: serde_json::Value) -> Artifact {
    Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
}

/// Three distinct MAC times on one file produce three timeline rows through the
/// single-artifact write path, each labelled with the kind it came from.
#[tokio::test]
async fn file_entry_mac_times_reach_the_timeline_single_path() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    let artifact = file_entry(
        case_id,
        json!({
            "name": "secrets.docx",
            "path": "/home/suspect/secrets.docx",
            "size": 4096,
            "inode": 12,
            "is_directory": false,
            "created": 1_700_000_000i64,
            "modified": 1_700_000_100i64,
            "accessed": 1_700_000_200i64,
        }),
    );
    let artifact_id = artifact.id;
    db.record_artifact(&artifact).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        3,
        "created/modified/accessed must each earn a timeline row"
    );
    assert!(
        events.iter().all(|e| e.artifact_id == artifact_id),
        "every row points back at the file it describes"
    );
    assert!(
        events
            .iter()
            .all(|e| e.source_module == FILE_TIMELINE_SOURCE_MODULE),
        "filesystem timestamps travel under one source module so they can be filtered as a group"
    );

    // Newest first.
    assert_eq!(events[0].timestamp, 1_700_000_200);
    assert_eq!(events[0].timestamp_desc, "Accessed");
    assert_eq!(events[1].timestamp, 1_700_000_100);
    assert_eq!(events[1].timestamp_desc, "Modified");
    assert_eq!(events[2].timestamp, 1_700_000_000);
    assert_eq!(events[2].timestamp_desc, "Created");

    // The row an examiner reads names the file.
    assert!(
        events[0].short_desc.contains("/home/suspect/secrets.docx"),
        "short_desc must name the file: {}",
        events[0].short_desc
    );
    assert!(
        events[0].short_desc.starts_with("FILE "),
        "a regular file is labelled FILE: {}",
        events[0].short_desc
    );

    // Every row of the same file is distinct in the events table.
    let mut ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3, "each projected row needs its own event id");

    Ok(())
}

/// The batch path (the one the orchestrator's artifact writer actually uses)
/// must project identically to the single path.
#[tokio::test]
async fn file_entry_mac_times_reach_the_timeline_batch_path() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    let a = file_entry(
        case_id,
        json!({
            "name": "a.txt",
            "path": "/a.txt",
            "created": 1_700_000_000i64,
            "modified": 1_700_000_100i64,
        }),
    );
    let b = file_entry(
        case_id,
        json!({
            "name": "b.txt",
            "path": "/b.txt",
            "modified": 1_700_000_300i64,
        }),
    );
    db.record_artifacts_batch(&[a, b]).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        3,
        "two files carrying three timestamps between them make three rows"
    );
    let descs: Vec<&str> = events.iter().map(|e| e.timestamp_desc.as_str()).collect();
    assert!(descs.contains(&"Created"));
    assert!(descs.contains(&"Modified"));

    Ok(())
}

/// A file whose timestamps all name the same instant is ONE event carrying
/// every kind, not four identical rows. This is what keeps the projection
/// proportional to the distinct instants in the evidence rather than to
/// 4x the file count, and it is how `mactime` has presented MACB for decades.
#[tokio::test]
async fn identical_file_times_coalesce_into_one_event() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "copied.bin",
            "path": "/tmp/copied.bin",
            "created": 1_700_000_000i64,
            "modified": 1_700_000_000i64,
            "accessed": 1_700_000_000i64,
            "changed": 1_700_000_000i64,
        }),
    ))
    .await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        1,
        "four timestamps naming one instant are one event"
    );
    assert_eq!(
        events[0].timestamp_desc, "Created, Modified, Accessed, Metadata Changed",
        "the coalesced row must still say which times it stands for"
    );
    assert_eq!(events[0].timestamp, 1_700_000_000);

    Ok(())
}

/// A `FileEntry` that carries no timestamps contributes nothing. Absent stays
/// absent: an undated file must never be pinned to the epoch.
#[tokio::test]
async fn undated_file_entry_stays_off_the_timeline() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Zip", "Examiner").await?;

    let artifact = file_entry(
        case_id,
        json!({"name": "member.bin", "path": "/member.bin"}),
    );
    let id = artifact.id;
    db.record_artifact(&artifact).await?;

    assert_eq!(db.get_timeline_events(case_id, None, None).await?.len(), 0);
    assert!(
        db.get_artifact(id).await?.is_some(),
        "the file itself is still recorded"
    );
    Ok(())
}

/// A producer that emits its OWN timeline events for a file's timestamps (the
/// $MFT parser: $SI and $FN, eight kinds, each carrying SI/FN provenance and
/// the timestomping verdict) declares it on the `FileEntry`. The generic
/// projection must then stay silent, or every NTFS file would be reported
/// twice at every instant.
#[tokio::test]
async fn producer_owned_file_timeline_is_not_reported_twice() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("NTFS", "Examiner").await?;

    let mut metadata = json!({
        "name": "ntuser.dat",
        "path": "/Users/suspect/ntuser.dat",
        "created": "2024-01-15T10:00:00Z",
        "modified": "2024-01-15T10:00:00Z",
        "accessed": "2024-01-15T10:00:00Z",
        "mft_modified": "2024-01-15T10:00:00Z",
    });
    metadata[FILE_TIMELINE_SELF_EMITTED_KEY] = json!(true);
    let file = file_entry(case_id, metadata);
    let own_event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": "2024-01-15T10:00:00Z",
            "timestamp_desc": "Created",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": "FILE ntuser.dat (MFT: 42)",
            "full_details": "{\"filename\":\"ntuser.dat\"}",
        }),
    )
    .with_parent(file.id);

    db.record_artifacts_batch(&[file, own_event]).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        1,
        "the plugin's own event is the only one; the projection must not duplicate it"
    );
    assert_eq!(events[0].source_module, "plugin.ntfs.mft_parser");
    Ok(())
}

/// A timestamp that is present but unreadable is left off the timeline rather
/// than guessed at, and it must not cost the file its artifact row or its other
/// timestamps.
#[tokio::test]
async fn unparseable_file_time_is_skipped_without_losing_the_file() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Fat", "Examiner").await?;

    let artifact = file_entry(
        case_id,
        json!({
            "name": "odd.txt",
            "path": "/odd.txt",
            "created": 1_700_000_000i64,
            "modified": "not a timestamp",
            "accessed": serde_json::Value::Null,
        }),
    );
    let id = artifact.id;
    db.record_artifact(&artifact).await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(
        events.len(),
        1,
        "only the readable timestamp is projected: {:?}",
        events
            .iter()
            .map(|e| e.timestamp_desc.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(events[0].timestamp_desc, "Created");
    assert!(
        db.get_artifact(id).await?.is_some(),
        "an unreadable timestamp must not cost the file its artifact row"
    );
    Ok(())
}

/// D5/D6: the projection carries sub-second precision and the source UTC offset
/// exactly as a plugin-authored event does. Collapsing a filesystem timestamp
/// to whole UTC seconds here would lose the same evidence migration 0021 exists
/// to preserve.
#[tokio::test]
async fn projected_file_time_preserves_subsecond_and_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    // Wall clock 2009-02-13T23:31:30.123456789 at +05:00.
    // UTC instant = 1234567890 - 18000 = 1234549890 s.
    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "p.log",
            "path": "/var/log/p.log",
            "modified": "2009-02-13T23:31:30.123456789+05:00",
        }),
    ))
    .await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 1_234_549_890);
    assert_eq!(events[0].timestamp_subsec_nanos, 123_456_789);
    assert_eq!(events[0].source_utc_offset_seconds, Some(18000));
    Ok(())
}

/// `full_details` must be a JSON object carrying `filename`: migration 0005
/// defines a generated column over `json_extract(full_details, '$.filename')`,
/// and the timeline's filename filter reads it. A projected row that failed
/// this would either break the insert or be invisible to a filename search.
#[tokio::test]
async fn projected_row_is_filterable_by_filename() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "secrets.docx",
            "path": "/home/suspect/secrets.docx",
            "modified": 1_700_000_100i64,
        }),
    ))
    .await?;
    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "boring.txt",
            "path": "/home/suspect/boring.txt",
            "modified": 1_700_000_200i64,
        }),
    ))
    .await?;

    let hits = db
        .get_timeline_events_filtered(
            case_id,
            None,
            None,
            None,
            None,
            Some("secrets"),
            None,
            Some(10),
            Some(0),
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(
        hits.len(),
        1,
        "the filename filter reads full_details.filename on projected rows"
    );
    assert!(hits[0].short_desc.contains("secrets.docx"));
    Ok(())
}

/// Directories are dated evidence too, and a deleted file's deletion time is
/// among the most load-bearing timestamps on a timeline; both must be labelled
/// for what they are.
#[tokio::test]
async fn directories_and_deletion_times_are_labelled() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "Downloads",
            "path": "/home/suspect/Downloads",
            "is_directory": true,
            "modified": 1_700_000_400i64,
        }),
    ))
    .await?;
    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "evidence.zip",
            "path": "/home/suspect/Downloads/evidence.zip",
            "deleted": true,
            "modified": 1_700_000_500i64,
            "deleted_time": 1_700_000_600i64,
        }),
    ))
    .await?;

    let events = db.get_timeline_events(case_id, None, None).await?;
    assert_eq!(events.len(), 3);

    let dir = events
        .iter()
        .find(|e| e.timestamp == 1_700_000_400)
        .expect("the directory's own mtime is on the timeline");
    assert!(
        dir.short_desc.starts_with("DIR "),
        "a directory is labelled DIR: {}",
        dir.short_desc
    );

    let deletion = events
        .iter()
        .find(|e| e.timestamp == 1_700_000_600)
        .expect("the deletion time is on the timeline");
    assert_eq!(deletion.timestamp_desc, "Deleted");
    assert!(
        deletion.short_desc.contains("(deleted)"),
        "a recovered file says so on its timeline rows: {}",
        deletion.short_desc
    );
    Ok(())
}

/// The dashboard's activity views read `timeline_events` through the histogram
/// and source-module census. Both must see the projected filesystem rows, since
/// "No dated events" on an image full of dated files is the defect this whole
/// projection exists to end.
#[tokio::test]
async fn projected_rows_reach_the_dashboard_aggregates() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Ext4", "Examiner").await?;

    db.record_artifact(&file_entry(
        case_id,
        json!({
            "name": "a.txt",
            "path": "/a.txt",
            "created": 1_700_000_000i64,
            "modified": 1_700_000_100i64,
        }),
    ))
    .await?;

    let modules = db.get_timeline_source_module_counts(case_id).await?;
    assert_eq!(
        modules.get(FILE_TIMELINE_SOURCE_MODULE).copied(),
        Some(2),
        "the source-module census counts filesystem timestamps"
    );

    let extent = db
        .get_timeline_extent(case_id, None, None, None, None, None, None, None)
        .await?;
    assert_eq!(
        extent,
        Some((1_700_000_000, 1_700_000_100)),
        "a case whose only dated evidence is file MAC times still has a timeline extent"
    );
    Ok(())
}
