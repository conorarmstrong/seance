//! Windows Search — stated before it was read.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SYSTEM`, measured: `Services\WSearch` in **both**
//! control sets, with `Start = 2`, `DelayedAutoStart = 1`,
//! `ObjectName = "LocalSystem"` and
//! `ImagePath = "%systemroot%\system32\SearchIndexer.exe /Embedding"`.
//!
//! So on that machine the indexer was configured to start automatically, with a
//! delayed start — which is what Windows shows as "Automatic (Delayed Start)"
//! and is a different configuration from plain automatic.
//!
//! # And the hive that does not hold the key
//!
//! The CFReDS Hacking Case `SYSTEM` hive (Windows XP) holds **no** `WSearch`
//! key: the byte string does not occur in the file, while `cisvc` — the name
//! XP's Indexing Service used — occurs twice, once per control set. Driven
//! through the module on 2026-09-15 that hive yields two records,
//! `ControlSet001` and `ControlSet002`, each `service_key_present: false` with
//! the absence stated; the Windows 7 hive above yields two records with
//! `service_key_present: true` and no absence note. That pair is the
//! measurement the absence tests below stand on. The XP hive is not in any
//! provisioned corpus, so the tests here build the capture directly rather than
//! gating on a file nobody else has.

use super::winsearch::*;

// --- The start type -------------------------------------------------------

/// The five start types, and a value outside them.
#[test]
fn the_five_service_start_types_are_named_and_anything_else_is_not() {
    assert_eq!(start_type_label(0), Some("boot"));
    assert_eq!(start_type_label(1), Some("system"));
    assert_eq!(start_type_label(2), Some("automatic"));
    assert_eq!(start_type_label(3), Some("manual"));
    assert_eq!(start_type_label(4), Some("disabled"));
    for raw in [5u32, 9, 0xFFFF_FFFF] {
        assert_eq!(
            start_type_label(raw),
            None,
            "a value outside the set gets no name"
        );
    }
}

/// `Automatic` and `automatic (delayed start)` are different configurations,
/// and the record distinguishes them.
#[test]
fn a_delayed_automatic_start_is_not_reported_as_plain_automatic() {
    let delayed = WindowsSearchState {
        start_raw: Some(2),
        delayed_auto_start: Some(true),
        ..Default::default()
    }
    .to_json();
    assert_eq!(delayed["start_type"], "automatic");
    assert_eq!(
        delayed["start_type_effective"], "automatic (delayed start)",
        "which is what Windows itself shows"
    );
    assert_eq!(
        delayed["indexing_configured_to_run"],
        serde_json::json!(true)
    );

    let plain = WindowsSearchState {
        start_raw: Some(2),
        delayed_auto_start: Some(false),
        ..Default::default()
    }
    .to_json();
    assert_eq!(plain["start_type_effective"], "automatic");
}

/// A disabled service is reported as not configured to run.
#[test]
fn a_disabled_indexer_is_reported_as_not_configured_to_run() {
    let j = WindowsSearchState {
        start_raw: Some(4),
        ..Default::default()
    }
    .to_json();
    assert_eq!(j["start_type"], "disabled");
    assert_eq!(j["indexing_configured_to_run"], serde_json::json!(false));
}

/// A `Start` value outside the five gets **no** start type claimed for it.
#[test]
fn an_unknown_start_value_is_reported_as_a_number_and_not_named() {
    let j = WindowsSearchState {
        start_raw: Some(77),
        ..Default::default()
    }
    .to_json();
    assert_eq!(j["start_raw"], serde_json::json!(77));
    assert!(j["start_type"].is_null());
    assert!(j["indexing_configured_to_run"].is_null());
    assert!(
        j["start_type_note"]
            .as_str()
            .unwrap_or("")
            .contains("no start type is claimed for it"),
        "got {:?}",
        j["start_type_note"]
    );
}

// --- What it will not say -------------------------------------------------

/// **Configured to run is not indexed.**
///
/// A service set to automatic on a machine imaged shortly after installation
/// has indexed nothing. Without this, "indexing was on" invites "so the index
/// has the deleted file names in it".
#[test]
fn the_record_does_not_claim_the_index_holds_anything() {
    let j = WindowsSearchState {
        start_raw: Some(2),
        delayed_auto_start: Some(true),
        setup_completed: Some(true),
        data_directory: Some(r"%ProgramData%\Microsoft\Search\Data\".into()),
        ..Default::default()
    }
    .to_json();
    assert_eq!(j["index_populated"], serde_json::json!(false));
    assert!(
        j["index_populated_basis"]
            .as_str()
            .unwrap_or("")
            .contains("a question for Windows.edb itself"),
        "got {:?}",
        j["index_populated_basis"]
    );
    // And it says why the index is worth finding.
    assert!(
        j["index_file_note"]
            .as_str()
            .unwrap_or("")
            .contains("files that have since been deleted"),
        "got {:?}",
        j["index_file_note"]
    );
}

// --- Anchoring -----------------------------------------------------------

/// Both keys are recognised, and neighbours are not.
#[test]
fn both_windows_search_keys_are_recognised_and_nothing_near_them_is() {
    assert_eq!(
        wsearch_service_key(r"ROOT\ControlSet001\Services\WSearch").as_deref(),
        Some("ControlSet001")
    );
    assert_eq!(
        wsearch_service_key(r"ROOT\CurrentControlSet\services\wsearch").as_deref(),
        Some("CurrentControlSet")
    );
    assert!(wsearch_software_key(r"ROOT\Microsoft\Windows Search"));

    for k in [
        r"ROOT\ControlSet001\Services\WSearch\Parameters",
        r"ROOT\ControlSet001\Services\WSearchIdxPi",
        r"ROOT\Microsoft\Windows Search\Gather",
        r"ROOT\Microsoft\Windows",
    ] {
        assert!(
            wsearch_service_key(k).is_none() && !wsearch_software_key(k),
            "for {k}"
        );
    }
}

// --- End to end, on the real hive ----------------------------------------

/// The real Windows 7 hive reports the indexer as automatic, delayed, in both
/// control sets.
#[test]
fn the_real_windows_seven_hive_reports_a_delayed_automatic_indexer() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let states: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "WindowsSearchState")
        .collect();
    assert_eq!(
        states.len(),
        2,
        "this hive has a WSearch key in both control sets, and both are reported -- \
         collapsing them would hide which configuration the machine booted"
    );
    for s in &states {
        assert_eq!(s["start_raw"], serde_json::json!(2));
        assert_eq!(s["start_type"], "automatic");
        assert_eq!(s["start_type_effective"], "automatic (delayed start)");
        assert_eq!(s["delayed_auto_start"], serde_json::json!(true));
        assert_eq!(s["indexing_configured_to_run"], serde_json::json!(true));
        assert_eq!(s["runs_as"], "LocalSystem");
        assert!(
            s["image_path"]
                .as_str()
                .unwrap_or("")
                .contains("SearchIndexer.exe"),
            "got {:?}",
            s["image_path"]
        );
        // And never a claim about the index's contents.
        assert_eq!(s["index_populated"], serde_json::json!(false));
    }
    let sets: std::collections::BTreeSet<&str> = states
        .iter()
        .filter_map(|s| s["control_set"].as_str())
        .collect();
    assert_eq!(sets.len(), 2, "one per control set: {sets:?}");
}

/// The real `SOFTWARE` hive reports setup completed and where the index lives.
#[test]
fn the_real_software_hive_reports_the_index_location() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SOFTWARE") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SOFTWARE", bytes);
    let s = all
        .iter()
        .find(|r| r["type"] == "WindowsSearchState")
        .expect("the SOFTWARE side is an answer on its own and must be emitted");
    assert_eq!(s["setup_completed"], serde_json::json!(true));
    assert!(
        s["data_directory"]
            .as_str()
            .unwrap_or("")
            .contains("Search"),
        "got {:?}",
        s["data_directory"]
    );
    // No service key in this hive, so no start type is claimed.
    assert!(s["start_type"].is_null());
    assert!(s["start_raw"].is_null());
}

// --- The absence of the key ----------------------------------------------

/// A hive whose control sets hold no `WSearch` key at all is reported as an
/// absence, per control set, rather than as silence.
///
/// Measured on the CFReDS Hacking Case `SYSTEM` hive (Windows XP, extracted
/// 2026-09-15): the byte string `WSearch` occurs **0** times in the file, while
/// `cisvc` — the name XP's Indexing Service used — occurs twice, once per
/// control set. So the key is genuinely not there, and a screen that says
/// nothing about Windows Search on that machine is read as "indexing was off"
/// rather than as "this build of Windows kept no key of that name".
#[test]
fn a_control_set_with_no_wsearch_key_is_reported_as_an_absence_not_as_silence() {
    let capture = crate::resident::ResidentCapture::default();
    let records = emit(
        &capture,
        &["ControlSet001".to_string(), "ControlSet002".to_string()],
    );
    assert_eq!(
        records.len(),
        2,
        "one record per control set the hive holds, not one for the hive: {records:?}"
    );
    for r in &records {
        assert_eq!(r["type"], "WindowsSearchState");
        assert_eq!(r["service_key_present"], serde_json::json!(false));
        // The absence must never be dressed as a configuration.
        assert!(
            r["start_raw"].is_null(),
            "no start type may be claimed for a key that is not there"
        );
        assert!(r["start_type"].is_null());
        assert!(r["indexing_configured_to_run"].is_null());
        let note = r["service_key_absent_note"]
            .as_str()
            .expect("the absence carries its own sentence");
        assert!(
            note.contains("read") && note.contains("no WSearch"),
            "the note must say the control set WAS read and held no such key: {note}"
        );
    }
    let sets: std::collections::BTreeSet<&str> = records
        .iter()
        .filter_map(|r| r["control_set"].as_str())
        .collect();
    assert_eq!(
        sets,
        ["ControlSet001", "ControlSet002"].into_iter().collect(),
        "each control set is a separate place the answer could have been"
    );
}

/// A control set that DOES hold the key gets no absence record for it.
#[test]
fn a_control_set_that_holds_the_key_gets_no_absence_record() {
    let mut capture = crate::resident::ResidentCapture::default();
    let idx = capture
        .begin_key(
            "\\ROOT\\ControlSet001\\Services\\WSearch",
            crate::resident::Anchor::WindowsSearchService {
                control_set: "ControlSet001".to_string(),
            },
            0,
        )
        .expect("a fresh capture accepts a key");
    capture.push_value(
        idx,
        "Start",
        Some(seance_hive::KeyValueDataType::RegDWord),
        &2u32.to_le_bytes(),
    );
    let records = emit(
        &capture,
        &["ControlSet001".to_string(), "ControlSet002".to_string()],
    );
    assert_eq!(records.len(), 2, "one present, one absent: {records:?}");
    let present = records
        .iter()
        .find(|r| r["control_set"] == "ControlSet001")
        .expect("the control set that holds the key");
    assert_eq!(present["service_key_present"], serde_json::json!(true));
    assert_eq!(present["start_raw"], serde_json::json!(2));
    assert!(
        present["service_key_absent_note"].is_null(),
        "a key that is there does not carry an absence note"
    );
    let absent = records
        .iter()
        .find(|r| r["control_set"] == "ControlSet002")
        .expect("the control set that does not");
    assert_eq!(absent["service_key_present"], serde_json::json!(false));
}

/// A hive with no control sets at all — an `NTUSER.DAT`, say — gets no absence
/// records, because it was never a place this key could have been.
#[test]
fn a_hive_with_no_control_sets_claims_nothing_about_windows_search() {
    let capture = crate::resident::ResidentCapture::default();
    assert!(
        emit(&capture, &[]).is_empty(),
        "a hive that could not hold the key makes no statement about it"
    );
}

#[test]
fn tmp_probe_mounted() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    for r in all.iter().filter(|r| r["type"] == "MountedDevice") {
        eprintln!("MD {}", serde_json::to_string(r).unwrap_or_default());
    }
}
