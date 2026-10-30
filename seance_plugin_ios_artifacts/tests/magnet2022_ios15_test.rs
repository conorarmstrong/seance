//! Known-answer tests over the real databases of the Magnet User Summit 2022
//! CTF iPhone 8 (iOS 15.0, build 19A404) full-file-system extraction.
//!
//! The fixtures under `tests/fixtures/magnet2022_ios15/` are the device's own
//! files, byte for byte, with their `-wal` siblings (see the README beside
//! them). Every count below was read from the file with `sqlite3` before the
//! parser existed, so a parser that regresses fails on an exact number rather
//! than passing on `> 0`.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_ios_artifacts::{
    HealthKitParser, NotesParser, PhotosParser, SafariBookmarksParser, SafariSearchesParser,
    SafariTabsParser, VoicemailParser,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// Where a fixture lives, if it is present.
///
/// `None` is announced on its own `SKIPPED` line and the test returns: a tree
/// without the corpus must say it could not look, not panic seventeen times
/// and read as seventeen parser failures.
fn fixture(rel: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/magnet2022_ios15")
        .join(rel);
    if path.is_file() {
        Some(path)
    } else {
        eprintln!(
            "SKIPPED (no fixture): {} is not present; see tests/fixtures/magnet2022_ios15/README.md",
            path.display()
        );
        None
    }
}

/// The fixture's path, or return from the test with the skip announced.
macro_rules! fixture_or_skip {
    ($rel:expr) => {
        match fixture($rel) {
            Some(path) => path,
            None => return,
        }
    };
}

/// Run `module` over a real fixture through a file-backed source, so the
/// `-wal` sibling and any neighbour database resolve exactly as they do for
/// a directory of evidence. `None` when the fixture is absent (announced).
fn run(module: &dyn ForensicsModule, rel: &str) -> Option<Vec<Artifact>> {
    let path = fixture(rel)?;
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.clone()).expect("fixture"));
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name, "path": path.display().to_string() }),
    );
    Some(module.process(&art).expect("process"))
}

/// The module's output over the fixture, or return with the skip announced.
macro_rules! run_or_skip {
    ($module:expr, $rel:expr) => {
        match run($module, $rel) {
            Some(out) => out,
            None => return,
        }
    };
}

fn of_type<'a>(arts: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    arts.iter()
        .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some(ty))
        .collect()
}

fn one<'a>(arts: &'a [Artifact], ty: &str) -> &'a Artifact {
    let v = of_type(arts, ty);
    assert_eq!(v.len(), 1, "expected exactly one {ty}, got {}", v.len());
    v[0]
}

// --- Safari bookmarks --------------------------------------------------------

#[test]
fn safari_bookmarks_are_the_six_the_device_holds_and_the_four_folders_it_keeps_them_in() {
    let out = run_or_skip!(&SafariBookmarksParser, "Library/Safari/Bookmarks.db");
    let leaves = of_type(&out, "SafariBookmark");
    let folders = of_type(&out, "SafariBookmarkFolder");
    assert_eq!(leaves.len(), 6);
    assert_eq!(folders.len(), 4);

    let mut titles: Vec<&str> = leaves
        .iter()
        .map(|a| a.metadata["title"].as_str().unwrap())
        .collect();
    titles.sort_unstable();
    assert_eq!(
        titles,
        [
            "Apple",
            "Bing",
            "Google",
            "Tracfone",
            "Yahoo",
            "iPhone User Guide"
        ]
    );
    let tracfone = leaves
        .iter()
        .find(|a| a.metadata["title"] == "Tracfone")
        .unwrap();
    assert_eq!(tracfone.metadata["url"], "http://m.tracfone.com/");
    assert_eq!(tracfone.metadata["bookmark_id"], 4);
    assert_eq!(tracfone.metadata["folder_path"], "Root");
    assert_eq!(tracfone.metadata["reading_list"], false);
    assert_eq!(tracfone.metadata["deleted"], false);
    let google = leaves
        .iter()
        .find(|a| a.metadata["title"] == "Google")
        .unwrap();
    assert_eq!(google.metadata["folder_path"], "Root/BookmarksBar");
    assert_eq!(google.metadata["parent_id"], 1);
    // `last_modified` is NULL on every row of this file: no date is invented.
    assert!(leaves
        .iter()
        .all(|a| a.metadata.get("last_modified").is_none()));
    // `read` is NULL on every row: the tri-state has no positive instance here
    // and the record says it was not recorded rather than defaulting it.
    assert!(leaves.iter().all(|a| a.metadata.get("read").is_none()));

    let mut folder_titles: Vec<&str> = folders
        .iter()
        .map(|a| a.metadata["title"].as_str().unwrap())
        .collect();
    folder_titles.sort_unstable();
    assert_eq!(
        folder_titles,
        [
            "BookmarksBar",
            "Root",
            "com.apple.FrequentlyVisitedSites",
            "com.apple.ReadingList"
        ]
    );
    let reading_list = folders
        .iter()
        .find(|a| a.metadata["title"] == "com.apple.ReadingList")
        .unwrap();
    assert_eq!(reading_list.metadata["special_id"], 3);
    assert_eq!(reading_list.metadata["special_role"], "reading_list");
    assert_eq!(reading_list.metadata["num_children"], 0);
    assert_eq!(reading_list.metadata["hidden"], true);

    let summary = one(&out, "SafariBookmarksSummary");
    assert_eq!(summary.metadata["bookmarks"], 6);
    assert_eq!(summary.metadata["folders"], 4);
    assert_eq!(summary.metadata["reading_list_items"], 0);
    assert_eq!(summary.metadata["deleted_rows"], 0);
    assert_eq!(summary.metadata["rows_with_last_modified"], 0);
    assert_eq!(summary.metadata["schema_version"], 43);
    // The attribute blobs are in the evidence and not decoded; say so.
    assert_eq!(summary.metadata["attribute_blobs_decoded"], false);
    // extra_attributes 80+80, local_attributes 138+93+87*4, sync_data
    // 2570+2569+2903+2912*3, as measured with length() on the file.
    assert_eq!(summary.metadata["attribute_blob_bytes"], 17_517);
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

#[test]
fn safaritabs_db_is_not_parsed_as_a_bookmarks_file_even_though_its_bookmarks_table_is_identical() {
    let path = fixture_or_skip!("Library/Safari/SafariTabs.db");
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    // Present the tabs database under the bookmarks name: the table set, not
    // the filename, is what tells them apart.
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Bookmarks.db" }),
    );
    let out = SafariBookmarksParser.process(&art).unwrap();
    assert!(
        of_type(&out, "SafariBookmark").is_empty(),
        "three open tabs must not become three saved bookmarks"
    );
    let summary = one(&out, "SafariBookmarksSummary");
    assert_eq!(summary.metadata["not_a_bookmarks_store"], true);
    assert_eq!(summary.metadata["records_recovered"], 0);
}

// --- Safari open tabs --------------------------------------------------------

#[test]
fn the_three_open_tabs_are_read_and_the_one_private_tab_is_reported_as_private() {
    let out = run_or_skip!(&SafariTabsParser, "Library/Safari/SafariTabs.db");
    let tabs = of_type(&out, "SafariOpenTab");
    assert_eq!(tabs.len(), 3);
    assert!(tabs
        .iter()
        .all(|t| t.metadata["source_schema"] == "SafariTabs.db"));

    let private: Vec<_> = tabs
        .iter()
        .filter(|t| t.metadata["private_browsing"] == true)
        .collect();
    assert_eq!(private.len(), 1);
    assert_eq!(private[0].metadata["tab_id"], 16);
    assert_eq!(private[0].metadata["title"], "Start Page");
    assert_eq!(private[0].metadata["tab_group"], "Private");
    assert_eq!(private[0].metadata["tab_group_id"], 13);
    assert!(private[0].metadata.get("url").is_none());

    let bbb = tabs.iter().find(|t| t.metadata["tab_id"] == 14).unwrap();
    assert_eq!(bbb.metadata["url"], "https://www.bedbathandbeyond.com/");
    assert_eq!(bbb.metadata["tab_group"], "Local");
    assert_eq!(bbb.metadata["private_browsing"], false);
    assert_eq!(bbb.metadata["is_active_tab"], false);
    assert_eq!(
        bbb.metadata["window_uuid"],
        "243EE7A6-57E0-46C5-90B9-070910A9A08F"
    );
    // LastVisitTime lives in the local_attributes bplist as a double of Cocoa
    // seconds, 2022-02-11T03:59:25.732305Z; the nanoseconds are what that
    // double decodes to, and its own precision at this magnitude is ~120 ns.
    assert_eq!(bbb.metadata["last_visit"], 1_644_551_965);
    assert_eq!(bbb.metadata["last_visit_ns"], 1_644_551_965_732_305_049i64);
    assert_eq!(
        bbb.metadata["last_visit_source"],
        "bookmarks.local_attributes[LastVisitTime] (plist date, Apple Cocoa seconds since 2001-01-01, converted to Unix)"
    );
    assert_eq!(bbb.metadata["opened_from_link"], false);
    assert_eq!(bbb.metadata["showing_reader"], false);
    // The tab's back/forward list is a bplist inside SessionState, uncompressed
    // on this generation, and the whole trail is evidence: a Google search for
    // plant shops, a Maps direction request, then the shop that was open.
    assert_eq!(bbb.metadata["session_history_decoded"], true);
    assert_eq!(bbb.metadata["session_history_current_index"], 4);
    let history = bbb.metadata["session_history"].as_array().unwrap();
    assert_eq!(history.len(), 5);
    assert!(history[0]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://www.google.com/search?q=plant+shops+near+me"));
    assert_eq!(
        history[2]["title"],
        "Your location to Gardener's Supply Company, 472 Marshall Ave, Williston, VT 05495 - Google Maps"
    );
    assert_eq!(history[4]["url"], "https://www.bedbathandbeyond.com/");

    let active = tabs.iter().find(|t| t.metadata["tab_id"] == 18).unwrap();
    assert_eq!(active.metadata["is_active_tab"], true);
    assert!(active.metadata["url"]
        .as_str()
        .unwrap()
        .starts_with("https://preyproject.com/blog/en/my-computer-was-hacked"));

    let summary = one(&out, "SafariTabsSummary");
    assert_eq!(summary.metadata["source_schema"], "SafariTabs.db");
    assert_eq!(summary.metadata["tabs"], 3);
    assert_eq!(summary.metadata["private_tabs"], 1);
    assert_eq!(summary.metadata["windows"], 1);
    assert_eq!(summary.metadata["tab_groups"], 2);
    assert_eq!(summary.metadata["schema_version"], 43);
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

#[test]
fn an_empty_browserstate_tabs_table_is_reported_as_a_superseded_generation_not_as_no_open_tabs() {
    let out = run_or_skip!(&SafariTabsParser, "Library/Safari/BrowserState.db");
    assert!(of_type(&out, "SafariOpenTab").is_empty());
    let summary = one(&out, "SafariTabsSummary");
    assert_eq!(summary.metadata["source_schema"], "BrowserState.db");
    assert_eq!(summary.metadata["tabs"], 0);
    assert_eq!(summary.metadata["windows"], 2);
    assert_eq!(summary.metadata["tabs_table_empty"], true);
    assert_eq!(summary.metadata["schema_version"], 5);
    let note = summary.metadata["generation_note"].as_str().unwrap();
    assert!(note.contains("SafariTabs.db"), "{note}");
    // The `-wal` of this file (24,752 bytes) was reachable and staged.
    assert!(summary.metadata.get("wal_incomplete_reason").is_none());
}

// --- Safari recent searches --------------------------------------------------

#[test]
fn a_recent_search_keeps_the_microseconds_the_plist_recorded() {
    let out = run_or_skip!(
        &SafariSearchesParser,
        "Library/Preferences/com.apple.mobilesafari.plist"
    );
    let searches = of_type(&out, "WebSearchQuery");
    assert_eq!(searches.len(), 3);
    let expected: [(&str, i64, i64); 3] = [
        (
            "what to do if you get hacked",
            1_644_551_979,
            1_644_551_979_993_625_998,
        ),
        (
            "when does bed bath and beyond close",
            1_642_341_682,
            1_642_341_682_563_681_960,
        ),
        (
            "plant shops near me",
            1_642_258_149,
            1_642_258_149_421_574_950,
        ),
    ];
    for (i, (q, secs, ns)) in expected.iter().enumerate() {
        let m = &searches[i].metadata;
        assert_eq!(m["query"], *q);
        assert_eq!(m["timestamp"], *secs);
        assert_eq!(m["timestamp_ns"], *ns);
        assert_eq!(m["browser"], "Safari");
        assert_eq!(m["search_engine_not_recorded"], true);
        assert_eq!(
            m["timestamp_source"],
            "RecentWebSearches[].Date (plist date, Apple Cocoa seconds since 2001-01-01, converted to Unix)"
        );
    }
    let summary = one(&out, "SafariSearchesSummary");
    assert_eq!(summary.metadata["searches"], 3);
    assert_eq!(
        summary.metadata["device_udid"],
        "fb028ddefa8af7df5b12d3e729f075d150637a31"
    );
    assert_eq!(summary.metadata["build_version"], "19A404");
    assert_eq!(summary.metadata["hardware_model"], "D20AP");
    assert_eq!(summary.metadata["device_type_number"], 157);
    assert_eq!(summary.metadata["cloud_tabs_enabled"], true);
    assert_eq!(summary.metadata["extensions_installed"], false);
    assert_eq!(
        summary.metadata["browser_window_uuids"],
        json!(["243EE7A6-57E0-46C5-90B9-070910A9A08F"])
    );
}

#[test]
fn the_searches_parser_selects_on_the_key_not_on_a_preferences_path() {
    // Same basename, no RecentWebSearches key: nothing is claimed, and nothing
    // says "no searches" either — the file simply is not the search store.
    let bytes = plist_bytes(&plist::Value::Dictionary({
        let mut d = plist::Dictionary::new();
        d.insert("CloudTabsEnabled".into(), plist::Value::Boolean(true));
        d
    }));
    let ds: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "com.apple.mobilesafari.plist" }),
    );
    let out = SafariSearchesParser.process(&art).unwrap();
    assert!(out.is_empty());
}

fn plist_bytes(v: &plist::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    v.to_writer_binary(&mut buf).unwrap();
    buf
}

// --- HealthKit ---------------------------------------------------------------

#[test]
fn six_hundred_and_eighty_eight_health_samples_with_the_histogram_the_device_holds() {
    let out = run_or_skip!(&HealthKitParser, "Library/Health/healthdb_secure.sqlite");
    let samples = of_type(&out, "HealthSample");
    assert_eq!(samples.len(), 688);

    let mut hist: BTreeMap<i64, usize> = BTreeMap::new();
    for s in &samples {
        *hist
            .entry(s.metadata["data_type"].as_i64().unwrap())
            .or_default() += 1;
    }
    let expected: BTreeMap<i64, usize> = [
        (7, 131),
        (8, 133),
        (12, 20),
        (182, 110),
        (187, 118),
        (188, 118),
        (194, 58),
    ]
    .into_iter()
    .collect();
    assert_eq!(hist, expected);

    for s in &samples {
        let m = &s.metadata;
        assert_eq!(m["recording_timezone"], "America/New_York");
        assert_eq!(m["origin_product_type"], "iPhone10,1");
        assert_eq!(m["origin_build"], "19A404");
        assert_eq!(m["origin_os_version"], "15.0.2");
        assert_eq!(m["source_name"], "iPhone 8");
        assert_eq!(
            m["source_bundle_id"],
            "com.apple.health.577D348F-D75E-4CA0-99A3-94A619D5D440"
        );
        assert_eq!(m["deleted"], false);
        // `unit_strings` is empty on this device: no unit is invented.
        assert!(m.get("unit").is_none());
        assert_eq!(m["unit_not_recorded"], true);
        assert_eq!(
            m["start_source"],
            "samples.start_date (Apple Cocoa seconds since 2001-01-01, converted to Unix)"
        );
        assert!(m["start_ns"].as_i64().is_some());
        assert!(m["end_ns"].as_i64().is_some());
        assert!(m["created_ns"].as_i64().is_some());
    }

    // The first sample on the device, by start date: data_id 1, type 8,
    // start 663940245.4151295 Cocoa = 2022-01-15T11:50:45.4151295Z, 9.48.
    let first = samples.iter().find(|s| s.metadata["data_id"] == 1).unwrap();
    assert_eq!(first.metadata["data_type"], 8);
    assert_eq!(first.metadata["data_type_name"], "distance_walking_running");
    assert_eq!(first.metadata["start"], 1_642_247_445);
    assert_eq!(first.metadata["start_ns"], 1_642_247_445_415_129_542i64);
    assert_eq!(first.metadata["end"], 1_642_247_455);
    assert_eq!(first.metadata["quantity"], 9.48);
    assert_eq!(first.metadata["uuid"], "63CEEBE8D4204E32910D38F41DA7EBF1");

    // The 58 type-194 samples are the only ones with metadata on this device.
    let with_meta: Vec<_> = samples
        .iter()
        .filter(|s| s.metadata.get("metadata").is_some())
        .collect();
    assert_eq!(with_meta.len(), 58);
    assert!(with_meta.iter().all(|s| s.metadata["data_type"] == 194));
    assert!(with_meta
        .iter()
        .all(|s| s.metadata["metadata"]["HKMetadataKeyDevicePlacementSide"].is_number()));
}

#[test]
fn a_health_data_type_is_named_only_from_the_asserted_table_and_otherwise_kept_as_a_number() {
    let out = run_or_skip!(&HealthKitParser, "Library/Health/healthdb_secure.sqlite");
    let samples = of_type(&out, "HealthSample");
    let steps = samples
        .iter()
        .find(|s| s.metadata["data_type"] == 7)
        .unwrap();
    assert_eq!(steps.metadata["data_type_name"], "step_count");
    assert_eq!(steps.metadata["data_type_name_basis"], "asserted");
    let unnamed = samples
        .iter()
        .find(|s| s.metadata["data_type"] == 187)
        .unwrap();
    assert!(unnamed.metadata.get("data_type_name").is_none());
    assert_eq!(unnamed.metadata["data_type_name_unknown"], true);

    let summary = one(&out, "HealthKitSummary");
    assert_eq!(summary.metadata["samples"], 688);
    assert_eq!(
        summary.metadata["data_type_histogram"],
        json!({"7": 131, "8": 133, "12": 20, "182": 110, "187": 118, "188": 118, "194": 58})
    );
    assert_eq!(summary.metadata["named_data_types"], json!([7, 8, 12]));
    assert_eq!(
        summary.metadata["unnamed_data_types"],
        json!([182, 187, 188, 194])
    );
    assert_eq!(summary.metadata["deleted_samples"], 0);
    // HUNT-236: both censuses ran over the whole table on the real store.
    assert_eq!(summary.metadata["deleted_samples_basis"], "whole_table");
    assert!(summary
        .metadata
        .get("deleted_samples_census_error")
        .is_none());
    assert!(summary
        .metadata
        .get("deleted_objects_census_error")
        .is_none());
    // HUNT-237 / HUNT-238: every census completed on the real store — no
    // partial histogram, no count failure standing in for an absent table.
    assert_eq!(summary.metadata["data_type_histogram_status"], "counted");
    assert_eq!(summary.metadata["sample_rows"], 688);
    assert!(summary.metadata.get("lookup_failures").is_none());
    assert_eq!(summary.metadata["workout_rows"], 0);
    // §1.5: the workout reader ran over the table and found no row.
    assert_eq!(summary.metadata["workouts_decoded"], true);
    assert_eq!(summary.metadata["workouts"], 0);
    assert_eq!(summary.metadata["category_sample_rows"], 0);
    assert_eq!(summary.metadata["unit_strings_rows"], 0);
    assert_eq!(summary.metadata["metadata_rows"], 58);
    assert_eq!(summary.metadata["provenance_rows"], 1);
    assert_eq!(summary.metadata["schema_version"], 15043);
    assert_eq!(summary.metadata["source_name_resolution"], "resolved");
    assert_eq!(summary.metadata["sources_rows"], 1);
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

#[test]
fn the_health_source_name_is_read_from_the_sibling_database_and_a_source_that_cannot_look_says_so()
{
    let bytes = std::fs::read(fixture_or_skip!("Library/Health/healthdb_secure.sqlite")).unwrap();
    let ds: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "healthdb_secure.sqlite" }),
    );
    let out = HealthKitParser.process(&art).unwrap();
    let samples = of_type(&out, "HealthSample");
    assert_eq!(samples.len(), 688);
    for s in &samples {
        assert!(s.metadata.get("source_name").is_none());
        assert_eq!(s.metadata["source_name_unresolved"], true);
        assert_eq!(
            s.metadata["source_name_unresolved_reason"],
            "source_cannot_open_neighbours"
        );
        // Provenance from the secure store itself is still there.
        assert_eq!(s.metadata["origin_build"], "19A404");
    }
    let summary = one(&out, "HealthKitSummary");
    assert_eq!(
        summary.metadata["source_name_resolution"],
        "source_cannot_open_neighbours"
    );
    // A bare byte source cannot reach the `-wal` either, and the file is in
    // WAL mode, so that is stated rather than silently read without it.
    assert_eq!(
        summary.metadata["wal_incomplete_reason"],
        "wal_not_reachable"
    );
}

// --- Notes -------------------------------------------------------------------

#[test]
fn the_grocery_list_note_body_is_the_four_items_the_device_stored() {
    let out = run_or_skip!(&NotesParser, "Notes/NoteStore.sqlite");
    let notes = of_type(&out, "Note");
    assert_eq!(notes.len(), 2);
    let grocery = notes
        .iter()
        .find(|n| n.metadata["title"] == "Grocery list")
        .unwrap();
    assert_eq!(
        grocery.metadata["body"],
        "Grocery list \nEnergy drinks\nBread\nHand soap\nBirthday card "
    );
    assert_eq!(grocery.metadata["body_source"], "notestore_protobuf");
    assert_eq!(grocery.metadata["body_decoded"], true);
    assert_eq!(grocery.metadata["folder"], "Notes");
    assert_eq!(grocery.metadata["deleted"], false);
    assert_eq!(grocery.metadata["note_id"], 4);
    assert_eq!(
        grocery.metadata["identifier"],
        "A9247171-B2F3-4B18-B17F-B4C2FC117327"
    );
    assert_eq!(grocery.metadata["account"], "LocalAccount");
    assert_eq!(grocery.metadata["password_protected"], false);
    let hike = notes
        .iter()
        .find(|n| n.metadata["title"] == "East Woods Hike")
        .unwrap();
    assert_eq!(
        hike.metadata["body"],
        "East Woods Hike\n\n44.44545, -73.19659 "
    );

    let folders = of_type(&out, "NotesFolder");
    assert_eq!(folders.len(), 4);
    let trash: Vec<_> = folders
        .iter()
        .filter(|f| f.metadata["title"] == "Recently Deleted")
        .collect();
    assert_eq!(trash.len(), 2);
    assert!(trash.iter().all(|f| f.metadata["folder_type"] == 1));
    assert!(trash.iter().all(|f| f.metadata["is_trash"] == true));

    let summary = one(&out, "NotesSummary");
    assert_eq!(summary.metadata["notes"], 2);
    assert_eq!(summary.metadata["deleted_notes"], 0);
    assert_eq!(summary.metadata["folders"], 4);
    assert_eq!(summary.metadata["bodies_decoded"], 2);
    assert_eq!(summary.metadata["bodies_undecoded"], 0);
    assert_eq!(summary.metadata["attachment_rows"], 0);
    assert_eq!(summary.metadata["entity_resolution"], "z_primarykey");
    assert_eq!(summary.metadata["note_entity"], 11);
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
    // HUNT-232: every folder and account lookup read on the real store, so
    // no note is marked unresolved and the summary names no failure.
    assert!(summary.metadata.get("lookup_failures").is_none());
    assert!(summary.metadata.get("deleted_notes_unresolved").is_none());
    assert!(notes
        .iter()
        .all(|n| n.metadata.get("folder_unresolved").is_none()
            && n.metadata.get("account_unresolved").is_none()));
}

// --- Photos albums -----------------------------------------------------------

#[test]
fn the_album_join_table_is_found_by_entity_number_and_an_empty_one_is_reported_as_empty() {
    let out = run_or_skip!(&PhotosParser, "Media/PhotoData/Photos.sqlite");
    assert_eq!(of_type(&out, "PhotoAsset").len(), 13);
    let albums = of_type(&out, "PhotoAlbum");
    assert_eq!(albums.len(), 41);
    let titled: Vec<_> = albums
        .iter()
        .filter(|a| a.metadata.get("title").is_some())
        .collect();
    assert_eq!(titled.len(), 3);
    let sync = albums
        .iter()
        .find(|a| a.metadata["title"] == "progress-sync")
        .unwrap();
    assert_eq!(sync.metadata["album_id"], 24);
    assert_eq!(sync.metadata["kind"], 3571);
    assert_eq!(sync.metadata["entity"], "Album");
    assert_eq!(sync.metadata["asset_count"], 0);
    assert_eq!(sync.metadata["trashed"], false);
    assert_eq!(
        sync.metadata["uuid"],
        "DAB002AF-2323-4BD6-835F-61F557A95D0B"
    );
    assert_eq!(
        sync.metadata["created_source"],
        "ZGENERICALBUM.ZCREATIONDATE (Apple Cocoa seconds since 2001-01-01, converted to Unix)"
    );
    // An album whose own entity has no join table is published with its
    // membership stated as unresolved, never as zero.
    let folder = albums
        .iter()
        .find(|a| a.metadata["entity"] == "Folder")
        .unwrap();
    assert!(folder.metadata.get("asset_count").is_none());
    assert_eq!(folder.metadata["asset_count_unresolved"], true);

    let summary = one(&out, "PhotosSummary");
    assert_eq!(summary.metadata["assets"], 13);
    assert_eq!(summary.metadata["albums"], 41);
    assert_eq!(
        summary.metadata["album_entity_histogram"],
        json!({"Album": 6, "FetchingAlbum": 30, "Folder": 5})
    );
    assert_eq!(summary.metadata["album_membership_present"], true);
    assert_eq!(summary.metadata["album_membership_table"], "Z_27ASSETS");
    assert_eq!(summary.metadata["album_memberships"], 0);
    assert_eq!(summary.metadata["face_rows"], 0);
    assert_eq!(summary.metadata["person_rows"], 0);
    assert_eq!(summary.metadata["faces_decoded"], false);
    // HUNT-214's control on the real library: every lookup read, so the
    // summary names no failure.
    assert!(summary.metadata.get("lookup_failures").is_none());
    assert!(summary.metadata.get("content_incomplete").is_none());
}

#[test]
fn the_second_photo_library_on_the_device_is_its_own_summary() {
    let out = run_or_skip!(&PhotosParser, "Library/Photos/Syndication/Photos.sqlite");
    assert!(of_type(&out, "PhotoAsset").is_empty());
    assert_eq!(of_type(&out, "PhotoAlbum").len(), 48);
    let summary = one(&out, "PhotosSummary");
    assert_eq!(summary.metadata["assets"], 0);
    assert_eq!(summary.metadata["albums"], 48);
    assert_eq!(summary.metadata["album_membership_present"], true);
    assert_eq!(summary.metadata["album_memberships"], 0);
    assert!(summary.metadata.get("lookup_failures").is_none());
}

// --- The honesty invariants, on the real files ------------------------------

use seance_core::test_support::TruncatedSource;

/// A source that declares twice the bytes it can deliver. SQLite opens the
/// prefix and answers from the pages it can reach, so without the stamp a
/// partial recovery would read exactly like a complete one.
fn truncated_run(module: &dyn ForensicsModule, rel: &str) -> Option<Vec<Artifact>> {
    let path = fixture(rel)?;
    let bytes = std::fs::read(&path).unwrap();
    let declared = (bytes.len() as u64) * 2;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    Some(module.process(&art).unwrap())
}

#[test]
fn every_new_parser_marks_each_record_when_its_source_was_truncated() {
    let cases: [(&dyn ForensicsModule, &str, &str); 5] = [
        (
            &SafariBookmarksParser,
            "Library/Safari/Bookmarks.db",
            "SafariBookmark",
        ),
        (
            &SafariTabsParser,
            "Library/Safari/SafariTabs.db",
            "SafariOpenTab",
        ),
        (
            &HealthKitParser,
            "Library/Health/healthdb_secure.sqlite",
            "HealthSample",
        ),
        (&NotesParser, "Notes/NoteStore.sqlite", "Note"),
        (&PhotosParser, "Media/PhotoData/Photos.sqlite", "PhotoAlbum"),
    ];
    for (module, rel, ty) in cases {
        // An absent fixture skips its own case (announced) and the rest run.
        let Some(out) = truncated_run(module, rel) else {
            continue;
        };
        assert!(
            !of_type(&out, ty).is_empty(),
            "{rel}: the readable prefix still parses"
        );
        for a in &out {
            assert_eq!(
                a.metadata["content_incomplete"], true,
                "{rel}: {} carries no incompleteness mark",
                a.metadata["type"]
            );
            assert_eq!(
                a.metadata["content_incomplete_reason"], "short_read",
                "{rel}"
            );
        }
        assert_eq!(
            out.iter()
                .filter(|a| a.metadata["status"] == "DatabaseNotStagedInFull")
                .count(),
            1,
            "{rel}: exactly one parse_incomplete marker"
        );
    }
}

#[test]
fn a_schema_version_outside_the_validated_range_is_warned_about_and_still_parsed() {
    // The real file with its user_version moved: the same rows, and one
    // ParserStaleWarning saying the parser predates this generation.
    let real = fixture_or_skip!("Library/Safari/Bookmarks.db");
    let dir = std::env::temp_dir().join(format!("seance_ios_stale_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Bookmarks.db");
    std::fs::copy(real, &path).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 44;").unwrap();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "Bookmarks.db" }),
    );
    let out = SafariBookmarksParser.process(&art).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(of_type(&out, "SafariBookmark").len(), 6);
    let warn = one(&out, "ParserStaleWarning");
    assert_eq!(warn.metadata["seen_schema_version"], 44);
    assert_eq!(warn.metadata["supported_range"], "43..=43");
    // §1.4a (decided 2026-09-26): outside the validated range is a
    // disclosure, not an incompleteness claim — all six bookmarks were read.
    assert!(warn.metadata.get("content_incomplete").is_none());
    assert!(warn.metadata.get("content_incomplete_reason").is_none());
    assert_eq!(warn.metadata["status"], "SchemaOutsideValidated");
    assert!(warn.metadata["detail"].as_str().unwrap().contains("NEWER"));
    assert!(warn.metadata["validated_against"]
        .as_str()
        .unwrap()
        .contains("19A404"));
}

/// The real file with its `user_version` cleared to 0 — SQLite's unset
/// default, true of every Chromium store and several Apple ones. Copies a
/// real store to a scratch directory, sets the pragma, and runs `module`.
fn with_user_version(
    rel: &str,
    name: &str,
    version: i64,
    module: &dyn ForensicsModule,
) -> Option<Vec<Artifact>> {
    let real = fixture(rel)?;
    let dir = std::env::temp_dir().join(format!("seance_ios_uv_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::copy(&real, &path).unwrap();
    let wal = real.with_file_name(format!("{name}-wal"));
    if wal.is_file() {
        std::fs::copy(&wal, dir.join(format!("{name}-wal"))).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(&format!("PRAGMA user_version = {version};"))
            .unwrap();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    let out = module.process(&art).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

/// HUNT-186: a `PRAGMA user_version` of 0 went through the shared
/// `check_schema_version` and was told it was "OLDER than the supported range
/// 43..=43" — a finding manufactured out of an unset field.
#[test]
fn a_bookmarks_store_that_records_no_version_is_not_called_older() {
    let Some(out) = with_user_version(
        "Library/Safari/Bookmarks.db",
        "Bookmarks.db",
        0,
        &SafariBookmarksParser,
    ) else {
        return;
    };
    assert_eq!(of_type(&out, "SafariBookmark").len(), 6);
    let warn = one(&out, "ParserStaleWarning");
    let msg = warn.metadata["message"].as_str().unwrap();
    assert!(
        !msg.contains("OLDER"),
        "0 was ranked against the range: {msg}"
    );
    assert_eq!(warn.metadata["status"], "SchemaVersionNotRecorded");
    assert!(warn.metadata.get("content_incomplete").is_none());
}

/// The same at the HealthKit call site (`health.rs`, `15043..=15043`).
#[test]
fn a_health_store_that_records_no_version_is_not_called_older() {
    let Some(out) = with_user_version(
        "Library/Health/healthdb_secure.sqlite",
        "healthdb_secure.sqlite",
        0,
        &HealthKitParser,
    ) else {
        return;
    };
    assert!(!of_type(&out, "HealthSample").is_empty());
    let warn = one(&out, "ParserStaleWarning");
    let msg = warn.metadata["message"].as_str().unwrap();
    assert!(
        !msg.contains("OLDER"),
        "0 was ranked against the range: {msg}"
    );
    assert_eq!(warn.metadata["status"], "SchemaVersionNotRecorded");
}

#[test]
fn a_health_store_with_no_sibling_beside_it_says_the_sibling_was_not_found() {
    // The real secure store alone in a directory: the source CAN look, and
    // the answer is "not there" — a different finding from "cannot look".
    let secure = fixture_or_skip!("Library/Health/healthdb_secure.sqlite");
    let wal = fixture_or_skip!("Library/Health/healthdb_secure.sqlite-wal");
    let dir = std::env::temp_dir().join(format!("seance_ios_health_alone_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(secure, dir.join("healthdb_secure.sqlite")).unwrap();
    std::fs::copy(wal, dir.join("healthdb_secure.sqlite-wal")).unwrap();
    let ds: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(dir.join("healthdb_secure.sqlite")).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "healthdb_secure.sqlite" }),
    );
    let out = HealthKitParser.process(&art).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let samples = of_type(&out, "HealthSample");
    assert_eq!(samples.len(), 688);
    assert!(samples
        .iter()
        .all(|s| s.metadata["source_name_unresolved_reason"] == "sibling_not_found"));
    let summary = one(&out, "HealthKitSummary");
    assert_eq!(
        summary.metadata["source_name_resolution"],
        "sibling_not_found"
    );
    assert!(summary.metadata.get("wal_incomplete_reason").is_none());
}

#[test]
fn a_tab_whose_session_state_does_not_parse_says_its_history_is_unread() {
    // The real tabs file with one tab's SessionState replaced by bytes that
    // are not a plist: the tab is still a tab, and its back/forward list is
    // reported present-and-undecoded rather than absent.
    let real = fixture_or_skip!("Library/Safari/SafariTabs.db");
    let dir = std::env::temp_dir().join(format!("seance_ios_tabs_garbage_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("SafariTabs.db");
    std::fs::copy(real, &path).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT local_attributes FROM bookmarks WHERE id = 14",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut v = plist::Value::from_reader(std::io::Cursor::new(&blob)).unwrap();
        v.as_dictionary_mut().unwrap().insert(
            "SessionState".into(),
            plist::Value::Data(vec![0, 0, 0, 2, 0xff, 0xfe, 0xfd]),
        );
        let mut buf = Vec::new();
        v.to_writer_binary(&mut buf).unwrap();
        conn.execute(
            "UPDATE bookmarks SET local_attributes = ?1 WHERE id = 14",
            [buf],
        )
        .unwrap();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "SafariTabs.db" }),
    );
    let out = SafariTabsParser.process(&art).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let tabs = of_type(&out, "SafariOpenTab");
    assert_eq!(tabs.len(), 3);
    let bbb = tabs.iter().find(|t| t.metadata["tab_id"] == 14).unwrap();
    assert_eq!(bbb.metadata["session_state_present"], true);
    assert_eq!(bbb.metadata["session_state_bytes"], 7);
    assert_eq!(bbb.metadata["session_history_decoded"], false);
    assert_eq!(bbb.metadata["content_incomplete"], true);
    assert_eq!(
        bbb.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(bbb.metadata.get("session_history").is_none());
    // The other two tabs are untouched.
    let active = tabs.iter().find(|t| t.metadata["tab_id"] == 18).unwrap();
    assert_eq!(active.metadata["session_history_decoded"], true);
}

#[test]
fn a_browserstate_tab_row_is_read_with_its_cocoa_last_viewed_time() {
    // No device held has a row in BrowserState.db's `tabs` table, so this
    // row is written from the real file's own DDL — the shape of the DDL is
    // evidence, the row is not. The branch is therefore validated for its
    // column mapping only.
    let real = fixture_or_skip!("Library/Safari/BrowserState.db");
    let real_wal = fixture_or_skip!("Library/Safari/BrowserState.db-wal");
    let dir = std::env::temp_dir().join(format!("seance_ios_bs_row_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("BrowserState.db");
    std::fs::copy(real, &path).unwrap();
    std::fs::copy(real_wal, dir.join("BrowserState.db-wal")).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "INSERT INTO tabs (uuid, title, url, user_visible_url, order_index, last_viewed_time, \
                               private_browsing, browser_window_uuid, browser_window_id) \
             VALUES ('11111111-2222-3333-4444-555555555555', 'Example', 'https://example.com/a', \
                     'https://example.com/a', 0, 663940245.5, 1, \
                     '2D9ADFCE-CD29-402E-9CCB-DDBAC70B09B5', 1);",
        )
        .unwrap();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "BrowserState.db" }),
    );
    let out = SafariTabsParser.process(&art).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let tabs = of_type(&out, "SafariOpenTab");
    assert_eq!(tabs.len(), 1);
    let t = &tabs[0].metadata;
    assert_eq!(t["source_schema"], "BrowserState.db");
    assert_eq!(t["title"], "Example");
    assert_eq!(t["private_browsing"], true);
    assert_eq!(t["last_visit"], 1_642_247_445);
    assert_eq!(t["last_visit_ns"], 1_642_247_445_500_000_000i64);
    assert_eq!(
        t["last_visit_source"],
        "tabs.last_viewed_time (Apple Cocoa seconds since 2001-01-01, converted to Unix)"
    );
    assert_eq!(t["session_state_present"], false);
    let summary = one(&out, "SafariTabsSummary");
    assert_eq!(summary.metadata["tabs"], 1);
    assert!(summary.metadata.get("tabs_table_empty").is_none());
}

// --- Voicemail ---------------------------------------------------------------

/// HUNT-233. The device's top-level `voicemail.db` has a `deleted` table with
/// the `voicemail` table's twelve columns; both are empty (read with `sqlite3`
/// on a copy: `SELECT count(*)` is 0 for each). The count is published, and
/// that no row has ever been seen to establish what one means.
#[test]
fn the_real_voicemail_deleted_table_is_read_and_its_empty_count_published() {
    let out = run_or_skip!(&VoicemailParser, "Library/Voicemail/voicemail.db");
    assert!(of_type(&out, "Voicemail").is_empty());
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s.metadata["voicemails"], 0);
    assert_eq!(s.metadata["deleted_table_present"], true);
    assert_eq!(s.metadata["deleted_table_rows"], 0);
    assert_eq!(s.metadata["deleted_table_semantics_validated"], false);
    assert!(s.metadata.get("content_incomplete").is_none());
}

/// The per-account store beside it has no `deleted` table, and says so.
#[test]
fn the_real_per_account_voicemail_store_has_no_deleted_table() {
    let out = run_or_skip!(
        &VoicemailParser,
        "Library/Voicemail/A-90650135-26E7-5671-906A-A5D30473128E/voicemail.db"
    );
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s.metadata["voicemails"], 0);
    assert_eq!(s.metadata["deleted_table_present"], false);
    assert!(s.metadata.get("content_incomplete").is_none());
}
