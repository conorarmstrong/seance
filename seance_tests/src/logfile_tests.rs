/// Integration tests for NTFS $LogFile Parser
///
/// Tests the LogFileParser module against real NTFS $LogFile samples
/// from the test_data directory.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_logfile::LogFileParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileSystem artifact from a $LogFile path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_logfile_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
    let file_path = crate::fixtures::resolve(path)?;

    let data_source = Arc::new(
        FileDataSource::new(file_path.clone())
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", file_path.display(), e)),
    );

    let metadata = json!({
        "filesystem_type": "NTFS",
        "volume_name": "Test Volume",
        "size": data_source.size(),
        "artifact_source": "test"
    });

    Some(Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        Some(data_source),
        metadata,
    ))
}

/// Split a `$LogFile` parse into its journal records and its parse-status
/// record.
///
/// The parser emits a `LogFileParseStatus` ParsedRecord FIRST when torn pages,
/// a cap or a short read stopped the walk: a missing rename or delete has to be
/// attributable either to "it did not happen" or to "this part of the journal
/// was never read", never ambiguously to both. It is a statement about the
/// parse, not a journal record, so it carries no LSN and must not be counted or
/// read as one.
fn split_logfile_records(artifacts: &[Artifact]) -> (Option<&Artifact>, Vec<&Artifact>) {
    let mut status = None;
    let mut records = Vec::new();
    for a in artifacts {
        assert_eq!(
            a.artifact_type,
            ArtifactType::ParsedRecord,
            "the $LogFile parser emits ParsedRecords only"
        );
        if a.metadata.get("type").and_then(|v| v.as_str()) == Some("LogFileParseStatus") {
            assert!(
                status.is_none(),
                "one parse, one status record: a second would mean two verdicts on the same walk"
            );
            assert_eq!(
                a.metadata.get("record_type").and_then(|v| v.as_str()),
                Some("logfile_parse_status")
            );
            assert!(
                records.is_empty(),
                "the status record leads the batch, so a reader taking the head of the \
                 listing meets the caveat before the records it qualifies"
            );
            status = Some(a);
        } else {
            records.push(a);
        }
    }
    (status, records)
}

/// The status record is the only channel through which "part of the journal was
/// never read" reaches an examiner, so every field it needs to say that is
/// checked here rather than assumed.
fn assert_logfile_status_record(status: &Artifact, records_parsed: usize) {
    assert_eq!(
        status.metadata.get("source").and_then(|v| v.as_str()),
        Some("$LogFile")
    );
    let incomplete = status
        .metadata
        .get("content_incomplete")
        .and_then(|v| v.as_bool());
    assert_eq!(
        incomplete,
        Some(true),
        "the status record is emitted only when the walk fell short, so it must say so"
    );
    let reason = status
        .metadata
        .get("content_incomplete_reason")
        .and_then(|v| v.as_str())
        .expect("a short parse must name why it stopped");
    assert!(!reason.is_empty(), "the reason must not be blank");
    for key in ["torn_pages", "pages_part_walked", "pages_scanned"] {
        assert!(
            status.metadata.get(key).and_then(|v| v.as_u64()).is_some(),
            "the status record must count `{key}`"
        );
    }
    // `records_parsed` counts every record decoded from the pages that were
    // walked; only the significant ones become artifacts, so it is a ceiling on
    // the batch, never below it.
    let parsed_count = status
        .metadata
        .get("records_parsed")
        .and_then(|v| v.as_u64())
        .expect("the status record must count the records the walk decoded");
    assert!(
        parsed_count >= records_parsed as u64,
        "records_parsed ({parsed_count}) cannot be below the {records_parsed} records emitted"
    );
    let message = status
        .metadata
        .get("message")
        .and_then(|v| v.as_str())
        .expect("a short parse must carry the sentence explaining the reason code");
    assert!(!message.is_empty());
}

/// Every field a `$LogFile` journal record must carry, checked on each record
/// rather than only on the first: a batch where one record lost its LSN is as
/// unusable as a batch where all did.
fn assert_logfile_record_fields(record: &Artifact) {
    let metadata = &record.metadata;
    for key in [
        "record_number",
        "lsn",
        "operation",
        "target_attribute",
        "undo_operation",
        "redo_operation",
        "source",
    ] {
        assert!(
            metadata.get(key).is_some(),
            "a $LogFile record must carry `{key}`"
        );
    }
    assert_eq!(
        metadata.get("source").and_then(|v| v.as_str()),
        Some("$LogFile"),
        "Should be marked as $LogFile"
    );
    let lsn = metadata.get("lsn").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        lsn.starts_with("0x"),
        "LSN should be hex formatted: {}",
        lsn
    );
}

#[test]
fn test_logfile_10_parsing() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_10.bin", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "$LogFile parsing should succeed");

    let artifacts = result.unwrap();
    // LogFile might not have significant records depending on content
    // Just verify it processes without error
    println!("LogFile_10.bin produced {} records", artifacts.len());

    // The parse-status record leads the batch when the walk fell short of the
    // journal; it is not a journal record and carries no LSN.
    let (status, records) = split_logfile_records(&artifacts);
    if let Some(status) = status {
        assert_logfile_status_record(status, records.len());
    }
    for record in &records {
        assert_logfile_record_fields(record);
    }

    // Anti-vacuity, and the point of a test named for parsing: the loop above
    // is satisfied by an empty batch, so a parser that decoded nothing at all
    // would pass every assertion in it. This fixture's measured baseline is one
    // parse-status record leading 124 significant journal records; both halves
    // are pinned so that "the journal held no renames or deletes" can never
    // arrive here as silence.
    assert!(
        status.is_some(),
        "the walk of this fixture falls short of the journal, so it must say so"
    );
    assert_eq!(
        records.len(),
        124,
        "LogFile_10.bin decodes 124 significant journal records"
    );
}

#[test]
fn test_logfile_10_large_parsing() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_10_large.bin", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Large $LogFile parsing should succeed");

    let artifacts = result.unwrap();
    // Larger logfile should have more records
    println!("LogFile_10_large.bin produced {} records", artifacts.len());
}

#[test]
fn test_logfile_7_parsing() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_7.bin", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Windows 7 $LogFile parsing should succeed");

    let artifacts = result.unwrap();
    println!("LogFile_7.bin produced {} records", artifacts.len());
}

#[test]
fn test_logfile_empty() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_empty.bin", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    // Empty logfile might succeed with no records or fail parsing
    if let Ok(artifacts) = result {
        // Empty logfile should have no significant records
        assert_eq!(artifacts.len(), 0, "Empty $LogFile should have no records");
    }
}

#[test]
fn test_non_ntfs_filesystem_ignored() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    // Create artifact with non-NTFS filesystem type
    let artifact = {
        let metadata = json!({
            "filesystem_type": "EXT4",
            "volume_name": "Linux Volume"
        });

        Artifact::new(case_id, ArtifactType::FileSystem, None, metadata)
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Processing non-NTFS should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-NTFS"
    );
}

#[test]
fn test_parent_relationship() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_10.bin", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();

    // Every produced artifact, the parse-status record included: a record whose
    // parent is lost cannot be traced back to the volume it came from.
    for record in &result {
        assert_eq!(
            record.parent_id,
            Some(parent_id),
            "Log record should reference parent"
        );
        assert_eq!(
            record.case_id, case_id,
            "Log record should have same case_id"
        );
    }
}

#[test]
fn test_missing_data_source() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "filesystem_type": "NTFS",
            "volume_name": "Test"
        });

        Artifact::new(case_id, ArtifactType::FileSystem, None, metadata)
    };

    // With no data source, module returns Ok(empty) instead of Err (expected for carved files)
    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Should succeed with empty result when data source is missing"
    );
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_module_metadata() {
    let parser = LogFileParser;

    assert_eq!(parser.id(), "plugin.ntfs.logfile_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(
        parser.subscribes_to(),
        vec![
            ArtifactType::FileSystem,
            ArtifactType::FileEntry,
            ArtifactType::RawEvidence,
            ArtifactType::SystemArtifact
        ]
    );

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::RandomAccess);
}

#[test]
fn test_record_metadata_structure() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/LogFile_10.bin", case_id) else {
        return;
    };

    let result = parser.process(&artifact).unwrap();

    // Every journal record, not just the head of the batch: the parse-status
    // record can lead the listing, and one record short of its LSN is as
    // unusable as all of them.
    let (status, records) = split_logfile_records(&result);
    if let Some(status) = status {
        assert_logfile_status_record(status, records.len());
    }
    for record in &records {
        assert_logfile_record_fields(record);
    }

    // Without this the whole test is vacuous on an empty batch: there would be
    // no record whose metadata structure was ever inspected.
    assert!(
        !records.is_empty(),
        "there must be a journal record for this test to describe the structure of"
    );
}

#[test]
fn test_hd001_logfile() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/HD001_LogFile.dat", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    // This might succeed or fail depending on file format
    if let Ok(artifacts) = result {
        println!("HD001_LogFile.dat produced {} records", artifacts.len());
    } else {
        println!("HD001_LogFile.dat parsing failed (expected for some formats)");
    }
}

#[test]
fn test_hd002_0_logfile() {
    let parser = LogFileParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_logfile_artifact("test_data/HD002.0_LogFile.dat", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    if let Ok(artifacts) = result {
        println!("HD002.0_LogFile.dat produced {} records", artifacts.len());
    }
}
