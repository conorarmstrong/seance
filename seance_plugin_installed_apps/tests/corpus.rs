//! The corpus-diff half of ROADMAP §1.4a for this crate: the real
//! `applicationState.db` stores the validated range was read from, parsed
//! through the product path (`FileDataSource`, so the `-wal` sidecar is taken),
//! so a parser that falls behind their schema fails here rather than going
//! quiet.
//!
//! Gates (each skips loudly when unset and panics when it names a missing path):
//!
//! * `SEANCE_IOS2022_TREE` — the root of the Magnet 2022 iOS full-file-system
//!   extraction; 145 bundle ids, `schema.version` 1.
//! * `SEANCE_MACOS2021_TREE` — the root of the Magnet 2021 macOS tree; its
//!   FrontBoard store's main file is one empty page and the two bundle ids and
//!   the schema live in the WAL, `schema.version` 1.
//! * `SEANCE_ANDROID14_PACKAGES_XML` — the file itself: `data/system/packages.xml`
//!   from Josh Hickman's Android 14 (Pixel 7a) public image, 701,599 bytes of
//!   ABX, SHA-256 `261e59fc…9b2ef4` (streamed out of `EXTRACTION_FFS.zip`; see
//!   `hickman_android14/PROVENANCE.md`). The counts it is graded against were
//!   taken by an independent ABX reader written from AOSP's
//!   `BinaryXmlSerializer`, not from `seance_xml_util::abx`.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_installed_apps::InstalledAppsParser;
use seance_sqlite_util::{check_corpus, CorpusExpectation};
use std::sync::Arc;

fn parse(path: &std::path::Path) -> Vec<Artifact> {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name, "path": path.display().to_string() }),
    );
    InstalledAppsParser::new().process(&artifact).unwrap()
}

fn check(out: &[Artifact], label: &str, min_apps: usize) {
    let stale: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .map(|a| a.metadata["message"].to_string())
        .collect();
    assert!(stale.is_empty(), "{label}: {stale:?}");
    let apps = out
        .iter()
        .filter(|a| a.metadata["type"] == "InstalledApp")
        .count();
    check_corpus(
        &CorpusExpectation {
            label: label.into(),
            min_records: min_apps,
        },
        apps,
    )
    .unwrap();
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "InstalledAppSummary")
        .unwrap();
    assert_eq!(summary.metadata["app_count"], apps);
    assert!(
        summary.metadata.get("content_incomplete").is_none(),
        "{label}"
    );
}

#[test]
fn the_ios2022_application_state_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_IOS2022_TREE",
        "private/var/mobile/Library/FrontBoard/applicationState.db",
    ) else {
        return;
    };
    check(
        &parse(&path),
        "ios2022ffs applicationState.db schema 1",
        145,
    );
}

#[test]
fn the_macos2021_application_state_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_MACOS2021_TREE",
        "Users/eliflatt/Library/FrontBoard/applicationState.db",
    ) else {
        return;
    };
    assert!(
        path.with_extension("db-wal").is_file(),
        "the inventory lives in the WAL"
    );
    check(&parse(&path), "macos2021 applicationState.db schema 1", 2);
}

/// ROADMAP §1.4: Android 14's `installInitiator` / `updateOwner` split, graded on
/// a device that writes it. Every figure below was counted by
/// `hickman_android14/packages/abx_count.py`, an ABX reader written from AOSP's
/// serializer and sharing no code with the product.
#[test]
fn the_pixel_7a_android_14_packages_xml_reports_the_install_initiator_and_update_owner_the_device_wrote(
) {
    let Some(path) = corpus::path("SEANCE_ANDROID14_PACKAGES_XML") else {
        return;
    };
    let out = parse(&path);
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "InstalledAppSummary")
        .unwrap();
    assert_eq!(summary.metadata["encoding"], "abx");
    assert_eq!(summary.metadata["app_count"], 369);
    assert!(summary.metadata.get("content_incomplete").is_none());

    let apps: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "InstalledApp")
        .collect();
    assert_eq!(apps.len(), 369);
    let count = |key: &str, value: serde_json::Value| {
        apps.iter()
            .filter(|a| a.metadata.get(key) == Some(&value))
            .count()
    };
    let play = serde_json::json!("com.android.vending");
    assert_eq!(count("installer_package", play.clone()), 123);
    assert_eq!(count("install_initiator_package", play.clone()), 123);
    assert_eq!(count("update_owner_package", play.clone()), 56);
    // No other value appears in either attribute.
    assert_eq!(
        apps.iter()
            .filter(|a| a.metadata.get("install_initiator_package").is_some())
            .count(),
        123
    );
    assert_eq!(
        apps.iter()
            .filter(|a| a.metadata.get("update_owner_package").is_some())
            .count(),
        56
    );
    assert_eq!(count("is_orphaned", serde_json::json!(true)), 305);
    assert_eq!(
        apps.iter()
            .filter(|a| a.metadata.get("is_orphaned").is_some())
            .count(),
        305
    );

    let pkg = |name: &str| {
        apps.iter()
            .find(|a| a.metadata["package"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    };
    // A user-installed app: all three name the Play Store, no orphan flag.
    let bereal = pkg("com.bereal.ft");
    assert_eq!(bereal.metadata["installer_package"], play);
    assert_eq!(bereal.metadata["install_initiator_package"], play);
    assert_eq!(bereal.metadata["update_owner_package"], play);
    assert!(bereal.metadata.get("is_orphaned").is_none());
    // A Play-updated system app: installer and initiator, no update owner, and
    // the orphan flag set while the Play Store is installed.
    let youtube = pkg("com.google.android.youtube");
    assert_eq!(youtube.metadata["install_initiator_package"], play);
    assert!(youtube.metadata.get("update_owner_package").is_none());
    assert_eq!(youtube.metadata["is_orphaned"], true);
    // The note states what this device shows too, not only the first one.
    let note = youtube.metadata["is_orphaned_note"].as_str().unwrap();
    assert!(note.contains("59 of the 123"), "{note}");
}
