use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fn artifact_at(path: &str, bytes: &[u8]) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
    let name = path.rsplit('/').next().unwrap_or(path);
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": path}),
    )
}

/// `SystemVersion.plist` as the Magnet 2021 macOS image holds it.
const SYSTEM_VERSION: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ProductBuildVersion</key>
    <string>20D74</string>
    <key>ProductCopyright</key>
    <string>1983-2021 Apple Inc.</string>
    <key>ProductName</key>
    <string>macOS</string>
    <key>ProductUserVisibleVersion</key>
    <string>11.2.1</string>
    <key>ProductVersion</key>
    <string>11.2.1</string>
</dict>
</plist>
"#;

/// The shape `SystemConfiguration/preferences.plist` keeps the names in.
const PREFERENCES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>System</key>
    <dict>
        <key>System</key>
        <dict>
            <key>ComputerName</key>
            <string>Eli&#8217;s Mac mini</string>
            <key>HostName</key>
            <string>Elis-Mac-mini.local</string>
        </dict>
        <key>Network</key>
        <dict>
            <key>HostNames</key>
            <dict>
                <key>LocalHostName</key>
                <string>Elis-Mac-mini</string>
            </dict>
        </dict>
    </dict>
</dict>
</plist>
"#;

fn facts(a: &Artifact) -> &serde_json::Map<String, serde_json::Value> {
    a.metadata["facts"].as_object().expect("facts object")
}

#[test]
fn a_system_version_plist_states_the_macos_build() {
    let out = MacHostParser::new()
        .process(&artifact_at(
            "/943CAEE3-8306-426A-A65E-4E0F4B52EBDB/System/Library/CoreServices/SystemVersion.plist",
            SYSTEM_VERSION,
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "HostDeviceInfo");
    assert_eq!(m["platform"], "macos");
    let f = facts(&out[0]);
    assert_eq!(f["os_name"], "macOS");
    assert_eq!(f["os_version"], "11.2.1");
    assert_eq!(f["build_id"], "20D74");
    assert_eq!(m["fact_sources"]["build_id"], "ProductBuildVersion");
}

#[test]
fn the_configuration_preferences_name_the_machine() {
    let out = MacHostParser::new()
        .process(&artifact_at(
            "/Library/Preferences/SystemConfiguration/preferences.plist",
            PREFERENCES,
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let f = facts(&out[0]);
    // The local host name is the Bonjour name, and it is not the computer name:
    // the two differ on this very machine ("Eli's Mac mini" against
    // "Elis-Mac-mini"), so both are reported, each under its own fact.
    assert_eq!(f["host_name"], "Elis-Mac-mini");
    assert_eq!(f["computer_name"], "Eli\u{2019}s Mac mini");
    assert_eq!(
        out[0].metadata["fact_sources"]["host_name"],
        "System.Network.HostNames.LocalHostName"
    );
}

#[test]
fn a_plist_at_another_path_states_nothing_about_the_host() {
    let out = MacHostParser::new()
        .process(&artifact_at(
            "/Users/eli/Library/Preferences/com.apple.dock.plist",
            SYSTEM_VERSION,
        ))
        .expect("parsed");
    assert!(
        out.is_empty(),
        "only the system's own paths state host facts"
    );
}

#[test]
fn a_binary_plist_is_read_as_readily_as_an_xml_one() {
    // Big Sur writes most of these in Apple's binary format.
    let mut binary = Vec::new();
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "ProductBuildVersion".into(),
        plist::Value::String("20D74".into()),
    );
    dict.insert("ProductName".into(), plist::Value::String("macOS".into()));
    plist::to_writer_binary(&mut binary, &plist::Value::Dictionary(dict)).expect("written");
    let out = MacHostParser::new()
        .process(&artifact_at(
            "/System/Library/CoreServices/SystemVersion.plist",
            &binary,
        ))
        .expect("parsed");
    assert_eq!(facts(&out[0])["build_id"], "20D74");
}

#[test]
fn a_plist_that_will_not_parse_is_reported_rather_than_passed_over() {
    let out = MacHostParser::new()
        .process(&artifact_at(
            "/System/Library/CoreServices/SystemVersion.plist",
            b"not a plist at all",
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1, "the file must not vanish from the case");
    let m = &out[0].metadata;
    assert_eq!(m["subtype"], "identity_unread");
    assert_eq!(m[CONTENT_INCOMPLETE], true);
}
