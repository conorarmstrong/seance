//! HELP-002: a bookmarked record with no name must still be recognisable.
//!
//! Bookmarking four `NtfsLogFileRecord` rows produced four bookmarks whose
//! ARTIFACT column all read **Unknown**, distinguished only by the examiner's
//! own note. Nothing was false — a `$LogFile` transaction has no name — but the
//! bookmark list is a curation surface whose whole purpose is returning to a
//! *specific* record, and four identical labels cannot be told apart.
//!
//! These tests go through the real listing rather than a helper, because the
//! defect was in what reached the screen.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Bookmarks", "Examiner").await?;
    Ok((db, case_id))
}

/// Store a parsed record and bookmark it, returning the label the bookmarks
/// list would show for it.
async fn bookmarked_label(
    db: &SqliteConnection,
    case_id: Uuid,
    metadata: serde_json::Value,
) -> Result<String> {
    let a = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata,
        data: None,
    };
    db.record_artifact(&a).await?;
    db.create_artifact_bookmark(case_id, a.id, None, Some("note"), Some("Examiner"))
        .await?;

    let page = db
        .list_artifact_bookmarks(case_id, None, Some(50), 0)
        .await?;
    let row = page
        .items
        .iter()
        .find(|r| r.bookmark.artifact_id == a.id)
        .expect("the bookmark just written is in the listing");
    Ok(row.artifact_name.clone())
}

/// The exact scenario the entry describes: four `$LogFile` records, four
/// bookmarks, and before this fix four identical labels reading "Unknown".
#[tokio::test]
async fn four_logfile_bookmarks_are_told_apart_by_lsn_and_record_number() -> Result<()> {
    let (db, case_id) = setup().await?;

    let mut labels = Vec::new();
    for i in 0..4u64 {
        labels.push(
            bookmarked_label(
                &db,
                case_id,
                json!({
                    "type": "NtfsLogFileRecord",
                    "lsn": format!("0x{:016x}", 0x1001 + i),
                    "record_number": i,
                    "operation": "InitializeFileRecordSegment",
                }),
            )
            .await?,
        );
    }

    assert!(
        !labels.iter().any(|l| l == "Unknown"),
        "a $LogFile record is identified by its LSN and record number, not by \
         having no name: {labels:?}"
    );
    let distinct: std::collections::BTreeSet<&String> = labels.iter().collect();
    assert_eq!(
        distinct.len(),
        4,
        "four bookmarks an examiner made must be four distinguishable rows: {labels:?}"
    );
    assert_eq!(labels[0], "LSN 0x0000000000001001 · record 0", "{labels:?}");
    Ok(())
}

/// A record that *does* have a name is unaffected. This is the behaviour that
/// was already right, and the fix must not reach past the case it was for.
#[tokio::test]
async fn a_named_record_is_still_called_by_its_name() -> Result<()> {
    let (db, case_id) = setup().await?;

    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "FileEntry", "name": "ransom.txt", "path": "/users/a/ransom.txt" }),
    )
    .await?;
    assert_eq!(label, "ransom.txt", "the name wins over the path");
    Ok(())
}

/// The rest of the per-type table, each key taken from the tailored viewer for
/// that type. One case per family so a wrong key is caught here rather than on
/// a screen.
#[tokio::test]
async fn each_named_record_kind_falls_back_to_its_own_identifier() -> Result<()> {
    let (db, case_id) = setup().await?;

    let cases: &[(serde_json::Value, &str)] = &[
        (
            json!({ "type": "YaraMatch", "rule": "Cobalt_Strike_Beacon", "namespace": "apt" }),
            "rule Cobalt_Strike_Beacon · apt",
        ),
        (
            json!({ "type": "UsnJournalEntry", "file_name": "notes.docx", "usn": 4096 }),
            "notes.docx · USN 4096",
        ),
        (
            json!({ "type": "LoginSession", "user": "analyst", "tty": "pts/0" }),
            "analyst · on pts/0",
        ),
        (
            json!({ "type": "BrowserCookie", "host": "example.com", "cookie_name": "SID" }),
            "example.com · SID",
        ),
        (
            json!({ "type": "EvtxLogEntry", "event_id": 4624, "provider_name": "Security-Auditing" }),
            "event 4624 · Security-Auditing",
        ),
    ];

    for (metadata, expected) in cases {
        let label = bookmarked_label(&db, case_id, metadata.clone()).await?;
        assert_eq!(&label, expected, "for {metadata}");
    }
    Ok(())
}

/// A partial record labels itself with what it has, rather than printing an
/// empty half or falling back to Unknown because one field is missing.
#[tokio::test]
async fn a_record_missing_half_its_identifier_uses_the_half_it_has() -> Result<()> {
    let (db, case_id) = setup().await?;

    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "NtfsLogFileRecord", "record_number": 9 }),
    )
    .await?;
    assert_eq!(label, "record 9");
    Ok(())
}

/// And `Unknown` stays for the case it was always right for. A record with
/// nothing identifying in it is not given a synthesised identity — a row
/// number or a truncated UUID would be an identity the evidence does not have.
#[tokio::test]
async fn a_record_with_nothing_identifying_is_still_unknown() -> Result<()> {
    let (db, case_id) = setup().await?;

    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "SomethingWeHaveNoTableFor", "flags": 3, "ok": true }),
    )
    .await?;
    assert_eq!(
        label, "Unknown",
        "inventing a label for a record that carries no identity would be worse \
         than saying it has none"
    );
    Ok(())
}

/// A 4 KB value is returned whole. `CR-039`: this label is printed as the
/// artifact's name in the bookmarks CSV export and in the report, and an
/// exhibit's name is not something a labelling helper gets to shorten. The
/// hostile shape `documentation/UI_TESTING.md` names is bounded where it is
/// *displayed* — the bookmarks screen's cell — not where it is recorded.
#[tokio::test]
async fn a_very_long_value_is_returned_whole() -> Result<()> {
    let (db, case_id) = setup().await?;

    let command = "A".repeat(4096);
    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "ShellHistoryEntry", "command": command }),
    )
    .await?;

    assert_eq!(
        label, command,
        "the export prints this as the artifact's name; it must be the artifact's name"
    );
    Ok(())
}

/// A value carrying newlines is returned as it is. `CR-039`: the helper once
/// collapsed interior whitespace for the table cell's sake, and in doing so
/// rewrote a recovered shell command in the CSV export. The cell is one line
/// because CSS makes it one; the record is what was recovered.
#[tokio::test]
async fn interior_whitespace_is_kept_because_it_is_evidence() -> Result<()> {
    let (db, case_id) = setup().await?;

    let command = "  curl x \n\t | sh  ";
    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "ShellHistoryEntry", "command": command }),
    )
    .await?;

    assert_eq!(label, command);
    Ok(())
}

/// A value that is nothing but whitespace identifies nothing, and must fall
/// through rather than label the row with a blank.
#[tokio::test]
async fn a_whitespace_only_value_is_not_a_label() -> Result<()> {
    let (db, case_id) = setup().await?;

    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "YaraMatch", "rule": "   ", "namespace": "apt" }),
    )
    .await?;

    assert_eq!(label, "apt");
    Ok(())
}

/// A structured value must never be rendered into the cell. A label reading
/// like a serialised object is the same defect class as UI-008's raw-JSON
/// search snippets, one column over.
#[tokio::test]
async fn a_structured_field_is_not_rendered_as_a_label() -> Result<()> {
    let (db, case_id) = setup().await?;

    let label = bookmarked_label(
        &db,
        case_id,
        json!({ "type": "YaraMatch", "rule": { "name": "nested" }, "namespace": "apt" }),
    )
    .await?;
    assert_eq!(
        label, "apt",
        "the object is skipped and the next identifying field used"
    );
    Ok(())
}
