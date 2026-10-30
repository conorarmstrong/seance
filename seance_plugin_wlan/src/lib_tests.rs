//! The module end to end: what it claims, what it emits, and what it refuses.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use serde_json::Value;

fn evidence(bytes: Vec<u8>, name: &str, path: Option<&str>) -> Artifact {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let mut metadata = json!({ "name": name });
    if let Some(path) = path {
        metadata["path"] = json!(path);
    }
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        metadata,
    )
}

fn document(key_material: &str, protected: bool) -> String {
    // The hex form generated from the text, not typed: see the note in
    // profile_tests.rs.
    let ssid_hex: String = "HomeWiFi"
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>HomeWiFi</name>
	<SSIDConfig>
		<SSID><hex>{ssid_hex}</hex><name>HomeWiFi</name></SSID>
		<nonBroadcast>false</nonBroadcast>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM><security>
		<authEncryption>
			<authentication>WPA2PSK</authentication>
			<encryption>AES</encryption>
			<useOneX>false</useOneX>
		</authEncryption>
		<sharedKey>
			<keyType>passPhrase</keyType>
			<protected>{protected}</protected>
			<keyMaterial>{key_material}</keyMaterial>
		</sharedKey>
	</security></MSM>
</WLANProfile>
"#
    )
}

#[test]
fn the_module_identifies_itself_and_subscribes_to_files() {
    let module = WlanProfiles;
    assert_eq!(module.id(), "plugin.windows.wlan_profiles");
    assert_eq!(
        module.subscribes_to(),
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            ArtifactType::ParsedRecord
        ]
    );
    assert_eq!(module.input_capability(), InputCapability::RandomAccess);
    assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
}

/// **End to end: the network, how it was joined, and the key in the clear.**
/// The record is filed as the same `WifiNetwork` type the macOS known-networks
/// parser emits, so the two platforms' answers to "where has this machine
/// been" sit in one place.
#[test]
fn a_profile_becomes_a_wifi_network_record_under_the_shared_type() {
    let path =
        "/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{6C1B0F1E-1A2B-4C3D-8E5F-0A1B2C3D4E5F}/{11112222-3333-4444-5555-666677778888}.xml";
    let artifact = evidence(
        document("hunter2", false).into_bytes(),
        "{11112222-3333-4444-5555-666677778888}.xml",
        Some(path),
    );
    let out = WlanProfiles.process(&artifact).expect("process");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(out[0].artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(out[0].parent_id, Some(artifact.id));
    assert_eq!(m["type"], "WifiNetwork");
    assert_eq!(m["subtype"], "windows_profile");
    assert_eq!(m["platform"], "windows");
    assert_eq!(m["ssid"], "HomeWiFi");
    assert_eq!(m["name"], "Wi-Fi network: HomeWiFi");
    assert_eq!(m["authentication"], "WPA2PSK");
    assert_eq!(m["encryption"], "AES");
    assert_eq!(m["security_types"], json!(["WPA2PSK", "AES"]));
    assert_eq!(m["connects_automatically"], json!(true));
    assert_eq!(m["key_state"], "in_the_clear");
    assert_eq!(m["key"], "hunter2");
    // Which adapter it was configured on, from the directory above the file.
    assert_eq!(
        m["interface_guid"], "6c1b0f1e-1a2b-4c3d-8e5f-0a1b2c3d4e5f",
        "the interface GUID is how two profiles on two adapters are told apart"
    );
    assert_eq!(m["path"], path);
    assert!(m["statement"]
        .as_str()
        .is_some_and(|s| s.contains("WLAN-AutoConfig")));
    // A cleartext key is not an incompleteness.
    assert!(m["content_incomplete"].is_null(), "{m}");
}

/// A protected key leaves the record incomplete, with the reason and the
/// master key on it.
#[test]
fn a_protected_key_leaves_the_record_incomplete_and_names_the_master_key() {
    let hex: String = crate::dpapi::test_support::blob_for_tests()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let artifact = evidence(document(&hex, true).into_bytes(), "profile.xml", None);
    let out = WlanProfiles.process(&artifact).expect("process");
    let m = &out[0].metadata;
    assert_eq!(m["key_state"], "dpapi_protected");
    assert!(m["key"].is_null());
    assert_eq!(
        m["key_dpapi"]["master_key_guid"],
        crate::dpapi::test_support::MASTER_KEY
    );
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "encrypted");
    assert!(m["content_incomplete_detail"]
        .as_str()
        .is_some_and(|d| d.contains("S-1-5-18")));
    // No interface GUID was knowable from this artifact, and the field is
    // absent rather than guessed.
    assert!(m["interface_guid"].is_null());
}

/// A file that is not a profile is not this module's business, and it says
/// nothing about it.
#[test]
fn a_file_that_is_not_a_profile_produces_nothing() {
    for (bytes, name) in [
        (b"MZ\x90\x00 an executable".to_vec(), "thing.exe"),
        (
            br#"<?xml version="1.0"?><plist version="1.0"><dict/></plist>"#.to_vec(),
            "prefs.plist",
        ),
        (Vec::new(), "empty.xml"),
    ] {
        let artifact = evidence(bytes, name, None);
        assert!(
            WlanProfiles.process(&artifact).expect("process").is_empty(),
            "{name}"
        );
    }
    // An artifact with no bytes at all is skipped rather than refused: there
    // is nothing to say about a file this module never saw.
    let no_data = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "profile.xml" }),
    );
    assert!(WlanProfiles.process(&no_data).expect("process").is_empty());
}

/// **A profile that was not read leaves a record saying so.** "There was no
/// wireless profile here" and "there was one and it was not read" must never
/// render the same.
#[test]
fn a_profile_that_cannot_be_read_leaves_a_refusal_record() {
    // The root element and namespace are there, so it is a profile; there is
    // no name and no SSID in it, so nothing can be filed under a network.
    let bytes = br#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<MSM><security><authEncryption><authentication>WPA2PSK</authentication>
	</authEncryption></security></MSM>
</WLANProfile>"#
        .to_vec();
    let artifact = evidence(bytes, "nameless.xml", None);
    let out = WlanProfiles.process(&artifact).expect("process");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "WifiNetworkIncomplete");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert!(m["detail"]
        .as_str()
        .is_some_and(|d| d.contains("guessed at")));
    assert_eq!(out[0].subtype(), Some("windows_profile_unread"));
}

/// A file past the staging ceiling is refused with the number it declared,
/// rather than read or passed over.
#[test]
fn a_file_past_the_staging_ceiling_is_refused_with_its_size() {
    let mut bytes = document("hunter2", false).into_bytes();
    bytes.resize((MAX_PROFILE_BYTES + 1) as usize, b' ');
    let artifact = evidence(bytes, "huge.xml", None);
    let out = WlanProfiles.process(&artifact).expect("process");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "WifiNetworkIncomplete");
    assert_eq!(m["content_incomplete_reason"], "cap_reached");
    assert!(m["detail"]
        .as_str()
        .is_some_and(|d| d.contains(&MAX_PROFILE_BYTES.to_string())));
}

/// An element the build does not read is counted on the record, so a profile
/// carrying something new never presents as one read in full.
#[test]
fn an_element_this_build_does_not_read_is_counted_on_the_record() {
    let document = document("hunter2", false).replace(
        "<connectionType>ESS</connectionType>",
        "<connectionType>ESS</connectionType><FIPSMode>true</FIPSMode>",
    );
    let artifact = evidence(document.into_bytes(), "profile.xml", None);
    let out = WlanProfiles.process(&artifact).expect("process");
    let m = &out[0].metadata;
    assert_eq!(m["unread_elements"]["FIPSMode"], 1);
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unmapped");
    let detail = m["content_incomplete_detail"].as_str().expect("a detail");
    assert!(detail.contains("FIPSMode"), "{detail}");
}

/// Every record this module emits carries a `type` and a `name`, which is what
/// the Analysis surface and the search index key off.
#[test]
fn every_record_carries_a_type_and_a_name() {
    for bytes in [
        document("hunter2", false).into_bytes(),
        br#"<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            <MSM/></WLANProfile>"#
            .to_vec(),
    ] {
        let artifact = evidence(bytes, "profile.xml", None);
        for record in WlanProfiles.process(&artifact).expect("process") {
            assert!(record.metadata["type"].as_str().is_some());
            assert!(record.metadata["name"].as_str().is_some());
            assert!(matches!(record.metadata["short_desc"], Value::String(_)));
        }
    }
}

/// HUNT-277. A profile held in a shadow-copy prior version is read, named by
/// its own file name, and everything it yields repeats the snapshot identity;
/// a `ParsedRecord` that is not a prior version is not read. SYNTHETIC: the
/// document is written by `document`, not taken from a machine.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    let bytes = document("hunter2", false).into_bytes();
    let source = || -> Arc<dyn seance_core::data_source::DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes.clone()))
    };
    let prior = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source()),
        json!({
            "type": "VssPriorVersion",
            "name": "{11112222-3333-4444-5555-666677778888}.xml [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "{11112222-3333-4444-5555-666677778888}.xml",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = WlanProfiles.process(&prior).expect("process");
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["is_snapshot_version"], json!(true));
    assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

    let plain = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source()),
        json!({ "type": "SomethingElse", "name": "profile.xml" }),
    );
    assert!(WlanProfiles.process(&plain).expect("process").is_empty());
}
