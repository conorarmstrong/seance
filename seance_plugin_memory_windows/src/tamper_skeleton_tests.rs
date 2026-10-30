//! The skeleton-key check: what it claims, and the two ways it must not claim
//! a clean machine.
//!
//! The classifier itself is `tamper_etw`'s and is tested there. What is tested
//! here is the part specific to this group: which process it looks in, and
//! what it says when it could not look.

use super::tamper_skeleton::*;
use crate::tamper_etw::Classification;

/// **`lsass.exe` is matched whole, never as a substring.**
///
/// A substring match is how a check comes to examine the wrong process and
/// report the right one's name.
#[test]
fn only_lsass_itself_is_the_lsa() {
    assert!(is_lsass("lsass.exe"));
    assert!(
        is_lsass("LSASS.EXE"),
        "the name is compared case-insensitively"
    );
    assert!(is_lsass("lsass.exe\0\0\0"), "ImageFileName is NUL-padded");
    for other in [
        "notlsass.exe",
        "lsass.exe.old",
        "lsass",
        "lsassx.exe",
        "lsm.exe",
        "",
    ] {
        assert!(!is_lsass(other), "{other:?} is not the LSA");
    }
}

fn row(classification: Classification) -> LsassProcess {
    LsassProcess {
        process: 0xFFFF_9B01_D000_0000,
        pid: Some(700),
        cryptdll_base: 0x7FFC_0000_0000,
        image_mapped: Some(true),
        export_address: 0x7FFC_0000_1234,
        prologue: vec![0x48, 0x83, 0xEC, 0x28],
        classification,
    }
}

fn outcome(
    examined: Vec<LsassProcess>,
    found: u64,
    unassessed: Vec<(u64, String)>,
) -> SkeletonOutcome {
    SkeletonOutcome {
        examined,
        lsass_found: found,
        unassessed,
        notes: Vec::new(),
    }
}

/// A patched `CDLocateCSystem` is the signal this route exists for.
#[test]
fn a_patched_export_is_the_signal() {
    let out = outcome(
        vec![row(Classification::ReturnsImmediately {
            detail: "ret".into(),
        })],
        1,
        Vec::new(),
    );
    assert_eq!(out.signals(), 1);
    assert!(out.assessed_anything());
    let j = out.examined[0].to_json();
    assert_eq!(j["is_signal"], serde_json::json!(true));
    assert_eq!(j["export"], serde_json::json!("CDLocateCSystem"));
    assert_eq!(j["module"], serde_json::json!("cryptdll.dll"));
}

/// An ordinary prologue is zero signals — the expected answer on a clean
/// machine — and is **not** a statement that there is no skeleton key, because
/// the second route did not run.
#[test]
fn an_ordinary_export_is_zero_signals_and_still_not_an_all_clear() {
    let out = outcome(vec![row(Classification::Ordinary)], 1, Vec::new());
    assert_eq!(out.signals(), 0);
    let said = out.describe();
    assert!(
        said.contains("did not run on this or any build"),
        "the statement names the route that did not run: {said}"
    );
    let j = out.to_json();
    // The whole check is stamped incomplete on every build, because one of its
    // two routes never runs.
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    assert_eq!(
        j["route_not_run"],
        serde_json::json!("csystems_descriptor_table")
    );
}

/// **A machine whose `lsass` was never reached is not a clean machine**, and
/// the record says so in as many words.
#[test]
fn no_lsass_examined_is_not_an_answer_about_the_machine() {
    let out = outcome(
        Vec::new(),
        1,
        vec![(0x1000, "no readable address space".into())],
    );
    assert!(!out.assessed_anything());
    assert_eq!(out.signals(), 0);
    let said = out.describe();
    assert!(said.contains("NOTHING here is a statement"), "got {said}");
    assert!(said.contains("the question was not reached"), "got {said}");
    let j = out.to_json();
    assert_eq!(j["assessed_anything"], serde_json::json!(false));
    assert_eq!(j["lsass_examined"], serde_json::json!(0));
    assert_eq!(j["lsass_found"], serde_json::json!(1));
    assert_eq!(j["unassessed"].as_array().map(|a| a.len()), Some(1));
}

/// **The `CSystems` route is named permanently, not as a pending item**, and
/// the reason is that nobody publishes the layout — not that an ISF has yet to
/// be supplied.
#[test]
fn the_unrun_route_says_why_it_will_not_run_rather_than_promising_it_later() {
    let detail = CSYSTEMS_ROUTE;
    assert!(detail.contains("NOT RUN"), "got {detail}");
    assert!(
        detail.contains("not pending an ISF"),
        "an ISF of a public PDB would not enable it, and the record must not imply it would: \
         {detail}"
    );
    assert!(
        detail.contains("PUBLIC PDB") && detail.contains("ZERO types"),
        "the reason is the published evidence, cited: {detail}"
    );
    assert!(
        detail.contains("What it would have established"),
        "an unrun route must say what is lost: {detail}"
    );
    // And it is on every record, not only the summary.
    let out = outcome(vec![row(Classification::Ordinary)], 1, Vec::new());
    assert_eq!(
        out.examined[0].to_json()["route_not_run_detail"],
        serde_json::json!(detail)
    );
    assert_eq!(
        out.to_json()["route_not_run_detail"],
        serde_json::json!(detail)
    );
}

/// Both routes are named on the record, so a reader can see that one of two
/// was run rather than inferring that one was all there is.
#[test]
fn the_record_names_the_route_it_ran_as_well_as_the_one_it_did_not() {
    let out = outcome(vec![row(Classification::Traps)], 1, Vec::new());
    let j = out.examined[0].to_json();
    assert_eq!(j["route_run"], serde_json::json!("export_prologue"));
    assert_eq!(
        j["route_not_run"],
        serde_json::json!("csystems_descriptor_table")
    );
}
