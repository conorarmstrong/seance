use super::*;
use seance_core::data_source::ByteSliceDataSource;
use std::sync::Arc;

fn file(name: &str, content: Vec<u8>) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(content));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    )
}

#[test]
fn a_windows_11_sqlite_index_is_refused_with_its_reason() {
    let mut bytes = b"SQLite format 3\0".to_vec();
    bytes.resize(4096, 0);
    bytes[16] = 0x10; // page size 4096
    bytes[17] = 0x00;
    let out = WinSearchParser::new()
        .process(&file("Windows.db", bytes))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
    assert!(out[0].metadata["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("Windows 11"));
}

#[test]
fn a_file_that_is_not_ese_is_left_alone() {
    assert!(WinSearchParser::new()
        .process(&file("notes.edb", b"plain text".to_vec()))
        .unwrap()
        .is_empty());
}

#[test]
fn a_file_named_windows_edb_that_is_not_ese_is_refused_not_ignored() {
    // A zero-filled extraction of the index: could not look, not "no items".
    let out = WinSearchParser::new()
        .process(&file("Windows.edb", vec![0u8; 8192]))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["type"], "WindowsSearchIndexIncomplete");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
    assert!(out[0].metadata["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("not an ESE database"));
}

/// A real ESE database that is not a Search index, run through `process` —
/// the chunked staging path — even when it is named like one.
#[test]
fn a_real_non_index_ese_database_staged_through_process_yields_nothing() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ese_other/lonewolf_settingsync_meta.edb"
    ))
    .unwrap();
    let out = WinSearchParser::new()
        .process(&file("meta.edb", bytes))
        .unwrap();
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn column_prefixes_are_stripped_and_plain_names_kept() {
    assert_eq!(
        index::property_name("4428-System_ItemPathDisplay"),
        "System_ItemPathDisplay"
    );
    assert_eq!(
        index::property_name("15F-System_DateModified"),
        "System_DateModified"
    );
    assert_eq!(index::property_name("System_Size"), "System_Size");
    assert_eq!(
        index::property_name("Microsoft_IE_TargetUrl"),
        "Microsoft_IE_TargetUrl"
    );
}

#[test]
fn times_outside_1980_to_2100_are_not_rendered() {
    assert_eq!(index::filetime_rfc3339(0), None);
    assert_eq!(index::filetime_rfc3339(0x2A2A_2A2A_2A2A_2A2A), None);
    assert_eq!(
        index::filetime_rfc3339(0x01D0_64B2_6A8F_EAE8).as_deref(),
        Some("2015-03-22T15:11:04.851735200Z")
    );
}

#[test]
fn an_ese_database_named_windows_edb_without_the_index_table_is_refused() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ese_other/lonewolf_settingsync_meta.edb"
    ))
    .unwrap();
    let out = WinSearchParser::new()
        .process(&file("Windows.edb", bytes))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
    assert!(out[0].metadata["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("property table"));
}

/// HUNT-277. SYNTHETIC: a zero-filled "Windows.edb" stands in for a prior
/// version, the same fixture the live-volume refusal test uses; no real
/// evidence is graded. The prior version's `name` carries the shadow-copy
/// label, so only the original `file_name` identifies it as the Search index.
fn prior_version(file_name: &str, content: Vec<u8>) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(content));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({
            "type": "VssPriorVersion",
            "name": format!("{file_name} [shadow copy 2015-03-23T00:00:00Z]"),
            "file_name": file_name,
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 1,
        }),
    )
}

#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let out = WinSearchParser::new()
        .process(&prior_version("Windows.edb", vec![0u8; 8192]))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    let m = &out[0].metadata;
    assert_eq!(m["type"], "WindowsSearchIndexIncomplete");
    assert_eq!(m["is_snapshot_version"], true);
    assert_eq!(m["vss_snapshot_id"], "snap-1");
    assert!(
        m.get("shadow_copy_sidecars_not_searched").is_some(),
        "{m:#?}"
    );

    // A ParsedRecord that is not a prior version is not this parser's.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 8192]));
    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({ "type": "SomethingElse", "name": "Windows.edb" }),
    );
    assert!(WinSearchParser::new().process(&plain).unwrap().is_empty());

    // The same bytes as a live FileEntry are not stamped.
    let live = WinSearchParser::new()
        .process(&file("Windows.edb", vec![0u8; 8192]))
        .unwrap();
    assert_eq!(live.len(), 1);
    assert!(live[0].metadata.get("is_snapshot_version").is_none());
}

/// CR-047. SYNTHETIC: a source whose every read fails. An unreadable header
/// is "could not look", never "not this format": `process` must return the
/// error, not an empty success a report would read as "no such artefact".
#[test]
fn an_unreadable_header_is_could_not_look_not_not_this_format() {
    use seance_core::test_support::UnreadableSource;
    let ds: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(UnreadableSource::new(4096));
    let art = seance_core::artifact::Artifact::new(
        uuid::Uuid::new_v4(),
        seance_core::artifact::ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "Windows.edb" }),
    );
    let out = WinSearchParser::new().process(&art);
    assert!(
        matches!(out, Err(seance_core::module::ModuleError::IoError(_))),
        "an unreadable header must be an error, got {out:?}"
    );
}
