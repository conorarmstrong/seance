use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fn info_plist(entries: Vec<(&str, &str)>) -> Vec<u8> {
    let mut dict = plist::Dictionary::new();
    for (k, v) in entries {
        dict.insert(k.to_string(), plist::Value::String(v.to_string()));
    }
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dict)).expect("written");
    out
}

fn artifact_at(path: &str, bytes: Vec<u8>) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "Info.plist", "path": path}),
    )
}

/// Finder as the Magnet 2021 macOS image holds it — the CTF asks for
/// `1350.2.10`, which is the bundle's build version, not its marketing one.
#[test]
fn an_application_bundle_states_its_version() {
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/System/Library/CoreServices/Finder.app/Contents/Info.plist",
            info_plist(vec![
                ("CFBundleName", "Finder"),
                ("CFBundleIdentifier", "com.apple.finder"),
                ("CFBundleShortVersionString", "11.1"),
                ("CFBundleVersion", "1350.2.10"),
                ("CFBundleExecutable", "Finder"),
            ]),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "InstalledApp");
    assert_eq!(m["platform"], "macOS");
    assert_eq!(m["name"], "Finder");
    assert_eq!(m["package"], "com.apple.finder");
    assert_eq!(m["version"], "11.1");
    assert_eq!(m["build_version"], "1350.2.10");
    assert_eq!(m["installed_in"], "system");
    assert_eq!(m["bundle_path"], "/System/Library/CoreServices/Finder.app");
}

#[test]
fn where_it_was_installed_is_part_of_what_it_is() {
    let cases = [
        (
            "/Applications/checkra1n.app/Contents/Info.plist",
            "applications",
        ),
        (
            "/Users/eliflatt/Downloads/Sketchy.app/Contents/Info.plist",
            "user",
        ),
        (
            "/System/Applications/Chess.app/Contents/Info.plist",
            "system",
        ),
    ];
    for (path, expected) in cases {
        let out = MacInstalledAppsParser::new()
            .process(&artifact_at(path, info_plist(vec![("CFBundleName", "X")])))
            .expect("parsed");
        assert_eq!(out[0].metadata["installed_in"], expected, "{path}");
    }
}

#[test]
fn a_path_that_does_not_say_where_it_was_installed_does_not_guess() {
    // A subtree ingested on its own — /Applications walked as a root — gives
    // `/Safari.app/Contents/Info.plist`, which says nothing about where the
    // folder sat. "elsewhere" there would be a finding drawn from silence.
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/Safari.app/Contents/Info.plist",
            info_plist(vec![("CFBundleName", "Safari")]),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert!(
        out[0].metadata.get("installed_in").is_none(),
        "the path does not say, so the record does not either"
    );
}

#[test]
fn a_helper_inside_an_application_is_not_a_second_application() {
    // Safari ships XPC services and frameworks, each with its own Info.plist.
    // Counting them would make one application read as thirty.
    for path in [
        "/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist",
        "/Applications/Safari.app/Contents/Frameworks/Helper.app/Contents/Info.plist",
        "/System/Library/Frameworks/Foo.framework/Versions/A/Resources/Bar.app/Contents/Info.plist",
    ] {
        assert!(
            application_bundle(path).is_none(),
            "{path} is part of an application, not one"
        );
    }
    assert!(application_bundle("/Applications/Safari.app/Contents/Info.plist").is_some());
}

#[test]
fn an_ordinary_plist_is_not_an_application() {
    assert!(application_bundle("/Users/eli/Library/Preferences/com.apple.dock.plist").is_none());
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/Users/eli/Library/Preferences/com.apple.dock.plist",
            info_plist(vec![("CFBundleName", "not an app")]),
        ))
        .expect("parsed");
    assert!(out.is_empty());
}

#[test]
fn a_bundle_whose_plist_will_not_parse_is_still_inventoried() {
    // It is installed; what could not be read is its description of itself.
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/Applications/Broken.app/Contents/Info.plist",
            b"not a plist".to_vec(),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["name"], "Broken");
    assert_eq!(m["package"], "Broken");
    assert_eq!(m["content_incomplete"], true);
}

#[test]
fn an_application_with_no_identifier_is_named_by_its_folder() {
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/Applications/Utilities/Odd Tool.app/Contents/Info.plist",
            info_plist(vec![("CFBundleVersion", "3")]),
        ))
        .expect("parsed");
    assert_eq!(out[0].metadata["name"], "Odd Tool");
    assert_eq!(out[0].metadata["package"], "Odd Tool");
    assert_eq!(out[0].metadata["package_source"], "bundle folder name");
}

#[test]
fn the_display_name_wins_where_a_bundle_has_both() {
    let out = MacInstalledAppsParser::new()
        .process(&artifact_at(
            "/Applications/Thing.app/Contents/Info.plist",
            info_plist(vec![
                ("CFBundleName", "Thing"),
                ("CFBundleDisplayName", "The Thing"),
            ]),
        ))
        .expect("parsed");
    assert_eq!(out[0].metadata["name"], "The Thing");
}
