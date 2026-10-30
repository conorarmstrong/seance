use super::*;
use seance_core::data_source::ByteSliceDataSource;
use std::sync::Arc;

/// A file artifact carrying `content`.
fn artifact_with(content: Vec<u8>) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(content));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Current.mdb" }),
    )
}

/// Bytes that pass ESE content detection: the 0xEF 0xCD 0xAB 0x89 signature at
/// offset 4. Not a valid database — only enough to reach the open attempt.
fn ese_shaped_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 4096];
    bytes[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    bytes
}

#[test]
fn a_file_that_is_not_an_ese_database_is_left_alone() {
    // This plugin sees every file in the case. Anything that is not ESE must
    // produce nothing, and must not be read beyond detection.
    let out = SumParser::new()
        .process(&artifact_with(b"not an ese database at all".to_vec()))
        .expect("a non-ESE file is not an error");
    assert!(out.is_empty());
}

#[test]
fn an_artifact_with_no_data_source_produces_nothing() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "Current.mdb" }),
    );
    assert!(SumParser::new().process(&artifact).unwrap().is_empty());
}

#[test]
fn a_directory_is_never_parsed() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(ese_shaped_bytes()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "SUM", "is_directory": true }),
    );
    assert!(SumParser::new().process(&artifact).unwrap().is_empty());
}

/// An ESE file that is not a UAL database must produce **nothing**, not an
/// empty summary.
///
/// This is the collision test. `SRUDB.dat`, `Windows.edb` and
/// `WebCacheV01.dat` are all ESE databases and all reach this plugin. A summary
/// record saying "User Access Logging: 0 client access records" emitted for
/// each of them would put a UAL finding in a report for a machine that never
/// had the feature enabled.
#[test]
fn an_ese_database_with_no_ual_tables_produces_no_records() {
    // A corrupt/empty ESE file either fails to open or opens with no UAL
    // tables. Both must yield nothing rather than a summary.
    // Failing to open a deliberately malformed database is acceptable; what
    // must not happen is a confident empty result presented as a UAL summary.
    if let Ok(artifacts) = SumParser::new().process(&artifact_with(ese_shaped_bytes())) {
        assert!(
            artifacts.is_empty(),
            "a non-UAL ESE database must not produce a UAL summary; got {artifacts:?}"
        );
    }
}

#[test]
fn a_walk_that_read_everything_emits_no_marker() {
    // The counterweight to the markers below: if a complete walk produced one,
    // its presence on an incomplete walk would carry no information.
    let clean = WalkStatus::default();
    assert!(SumParser::walk_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "ROLE_ACCESS",
        &clean,
        10
    )
    .is_none());
}

#[test]
fn a_table_that_would_not_open_says_so_rather_than_reading_as_empty() {
    // The failure this guards is the important one for an intrusion report:
    // an unreadable client-access table otherwise looks exactly like a role
    // nobody ever accessed.
    let status = WalkStatus::unreadable("records");
    let marker =
        SumParser::walk_status_artifact(Uuid::new_v4(), Uuid::new_v4(), "{role-guid}", &status, 0)
            .expect("an unreadable table must produce a marker");

    assert_eq!(marker.metadata["status"], json!("TableWalkIncomplete"));
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["walk_unreadable"], json!("records"));
    let detail = marker.metadata["content_incomplete_detail"]
        .as_str()
        .expect("the UI renders from this key");
    assert!(
        detail.contains("says nothing about who reached this role"),
        "the marker must state what the absence does NOT mean; got: {detail}"
    );
}

#[test]
fn skipped_rows_are_reported_against_the_rows_that_were_published() {
    let status = WalkStatus {
        rows_skipped: 7,
        ..Default::default()
    };
    let marker =
        SumParser::walk_status_artifact(Uuid::new_v4(), Uuid::new_v4(), "ROLE_ACCESS", &status, 93)
            .expect("a partial walk must produce a marker");
    assert_eq!(marker.metadata["rows_skipped"], json!(7));
    assert_eq!(marker.metadata["rows_emitted"], json!(93));
}

#[test]
fn the_marker_is_not_filed_as_an_access_record() {
    // Downstream grouping is by `metadata.$.type`. Reusing the access type here
    // would file this marker as somebody's access to the role it is warning
    // about.
    let status = WalkStatus::unreadable("columns");
    let marker =
        SumParser::walk_status_artifact(Uuid::new_v4(), Uuid::new_v4(), "T", &status, 0).unwrap();
    assert_ne!(marker.metadata["type"], json!("UalClientAccess"));
    assert_eq!(marker.metadata["type"], json!("UalTableIncomplete"));
}

#[test]
fn a_client_record_names_the_account_the_address_and_the_role() {
    let mut roles = HashMap::new();
    roles.insert(
        "ad495e1e-b84b-4e42-9ae8-9ac9f4c1a2c4".to_string(),
        "File Server".to_string(),
    );
    let row = UalClientAccess {
        authenticated_user: Some("CONTOSO\\administrator".into()),
        client_address: Some("10.0.0.5".into()),
        role_guid: Some("AD495E1E-B84B-4E42-9AE8-9AC9F4C1A2C4".into()),
        tenant_id: None,
        total_accesses: Some(42),
        insert_date: None,
        last_access: None,
        active_days: vec![3, 4, 5],
    };
    let record =
        SumParser::client_record(Uuid::new_v4(), Uuid::new_v4(), &row, "{ad495e1e}", &roles);

    assert_eq!(record.metadata["type"], json!("UalClientAccess"));
    assert_eq!(
        record.metadata["authenticated_user"],
        json!("CONTOSO\\administrator")
    );
    assert_eq!(record.metadata["client_address"], json!("10.0.0.5"));
    assert_eq!(record.metadata["total_accesses"], json!(42));
    // Resolved despite the GUID's case differing from the map's key.
    assert_eq!(record.metadata["role_name"], json!("File Server"));
    assert_eq!(record.metadata["active_day_count"], json!(3));
    assert!(record.metadata["name"]
        .as_str()
        .unwrap()
        .contains("accessed File Server"));
}

#[test]
fn an_unresolved_role_says_why_rather_than_showing_a_bare_guid() {
    // The mapping lives in SystemIdentity.mdb, a different file. Without this
    // the record looks like a parser that failed to decode the role name.
    let row = UalClientAccess {
        authenticated_user: Some("svc_backup".into()),
        client_address: None,
        role_guid: Some("10a9226f-50ee-49d8-a393-9a501d47ce04".into()),
        tenant_id: None,
        total_accesses: None,
        insert_date: None,
        last_access: None,
        active_days: Vec::new(),
    };
    let record = SumParser::client_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &row,
        "{10a9226f}",
        &HashMap::new(),
    );

    assert_eq!(record.metadata["role_name_unresolved"], json!(true));
    assert!(record.metadata["role_name_unresolved_reason"]
        .as_str()
        .unwrap()
        .contains("SystemIdentity.mdb"));
    assert!(record.metadata.get("role_name").is_none());
}

#[test]
fn unknown_fields_are_omitted_rather_than_emitted_as_null_or_empty() {
    // An account name that could not be read is not an account with a blank
    // name, and a report must not render the two identically.
    let row = UalClientAccess {
        authenticated_user: None,
        client_address: None,
        role_guid: None,
        tenant_id: None,
        total_accesses: None,
        insert_date: None,
        last_access: None,
        active_days: Vec::new(),
    };
    let record =
        SumParser::client_record(Uuid::new_v4(), Uuid::new_v4(), &row, "T", &HashMap::new());
    let map = record.metadata.as_object().unwrap();

    for absent in [
        "authenticated_user",
        "client_address",
        "role_guid",
        "total_accesses",
        "insert_date",
        "last_access",
        "active_days",
    ] {
        assert!(
            !map.contains_key(absent),
            "{absent} was not read and must be omitted, not emitted as null"
        );
    }
    assert!(map.contains_key("name"), "a record still needs a label");
}

#[test]
fn stamping_a_complete_walk_leaves_the_record_untouched() {
    let row = UalClientAccess {
        authenticated_user: Some("u".into()),
        client_address: None,
        role_guid: None,
        tenant_id: None,
        total_accesses: Some(1),
        insert_date: None,
        last_access: None,
        active_days: Vec::new(),
    };
    let mut record =
        SumParser::client_record(Uuid::new_v4(), Uuid::new_v4(), &row, "T", &HashMap::new());
    SumParser::stamp_walk(&mut record, &WalkStatus::default());
    assert!(
        record.metadata.get("content_incomplete").is_none(),
        "a complete walk must not mark its records incomplete"
    );
}

#[test]
fn stamping_an_incomplete_walk_marks_every_record_it_produced() {
    let row = UalClientAccess {
        authenticated_user: Some("u".into()),
        client_address: None,
        role_guid: None,
        tenant_id: None,
        total_accesses: Some(1),
        insert_date: None,
        last_access: None,
        active_days: Vec::new(),
    };
    let mut record =
        SumParser::client_record(Uuid::new_v4(), Uuid::new_v4(), &row, "T", &HashMap::new());
    SumParser::stamp_walk(
        &mut record,
        &WalkStatus {
            rows_skipped: 4,
            missing_columns: vec!["LastAccess"],
            ..Default::default()
        },
    );
    // The incompleteness travels with the data wherever it is exported, so no
    // downstream view can quote the row as a complete account of the access.
    assert_eq!(record.metadata["content_incomplete"], json!(true));
    assert_eq!(record.metadata["rows_skipped"], json!(4));
    assert_eq!(record.metadata["missing_columns"], json!(["LastAccess"]));
}

#[test]
fn a_minutes_offset_stored_as_unsigned_16_bit_renders_as_a_signed_utc_offset() {
    // DC01's `OSCurrentTimeZone` is 65116, which is -420 minutes (UTC-7).
    assert_eq!(tables::format_utc_offset(65116u16 as i16), "UTC-07:00");
    assert_eq!(tables::format_utc_offset(0), "UTC+00:00");
    assert_eq!(tables::format_utc_offset(330), "UTC+05:30");
}

/// HUNT-277. A shadow-copy prior version of a UAL database is routed to the
/// parser and a `ParsedRecord` that is not a prior version is not. SYNTHETIC:
/// ESE-shaped bytes that are not a database, so the routed one reaches the open
/// attempt and fails (an `Err`), while the other is never touched (empty `Ok`);
/// libesedb is read-only, so a database cannot be synthesised to stamp.
#[test]
fn a_shadow_copy_prior_version_is_routed_to_the_parser() {
    assert!(SumParser
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(ese_shaped_bytes()));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds.clone()),
        json!({
            "type": "VssPriorVersion",
            "name": "Current.mdb [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "Current.mdb",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    assert!(SumParser.process(&prior).is_err());

    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({ "type": "SomethingElse", "name": "Current.mdb" }),
    );
    assert!(SumParser.process(&plain).unwrap().is_empty());
}
