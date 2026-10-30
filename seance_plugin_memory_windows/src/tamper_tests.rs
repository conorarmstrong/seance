//! The tamper stage's floor: a stage that runs nothing and says so per group.
//!
//! These tests exist because the alternative shape — a stage that appears when
//! its first group lands — would have the earlier groups' silence read as their
//! absence from the evidence rather than from the build. `HUNT-051` is this
//! project's own lesson in the other direction: 4,054 false timestomps on a
//! stock XP machine, from a rule that fired before anybody measured what a
//! clean capture looks like.

use super::tamper::*;
use crate::kernel_hooks::test_support::{hook_isf, hook_profile, populated_image};

fn profile() -> crate::profile::WindowsProfile {
    hook_profile(populated_image(), &hook_isf())
}

/// **Every one of the seven groups is reported, whether or not it ran.**
///
/// A stage that listed only the groups it could run would let a group landing
/// later have the earlier silence read as a clean machine.
#[test]
fn every_group_is_reported_and_none_of_them_ran() {
    let outcome = examine_tamper(&profile(), &TamperConfig::defaults(), None)
        .expect("at least one group's entry symbols resolve on this fixture");
    assert_eq!(
        outcome.groups.len(),
        GROUPS.len(),
        "one status per group, in group order"
    );
    assert_eq!(
        outcome.groups.iter().map(|g| g.group).collect::<Vec<_>>(),
        GROUPS.to_vec()
    );
    for g in &outcome.groups {
        assert!(!g.ran, "{} must not report having run", g.group);
        assert_eq!(g.found, 0);
        assert!(
            g.detail.is_some(),
            "{} must carry the reason it did not run",
            g.group
        );
    }
    assert_eq!(outcome.ran(), 0);
    assert!(outcome.established_nothing());
}

/// **A stage where no group ran is not a clean machine**, and the record says
/// that in as many words rather than leaving it to be inferred from a zero.
#[test]
fn a_stage_that_ran_nothing_says_it_established_nothing() {
    let outcome = examine_tamper(&profile(), &TamperConfig::defaults(), None).expect("stage");
    let said = outcome.describe();
    assert!(
        said.contains("nothing here is a statement about whether the kernel was tampered with"),
        "got {said}"
    );
    let json = outcome.to_json();
    assert_eq!(json["groups_ran"], serde_json::json!(0));
    assert_eq!(json["established_nothing"], serde_json::json!(true));
    // And the whole stage is stamped incomplete, so a consumer cannot read its
    // emptiness as a negative result. The reason is the groups that did not
    // run, which on this fixture is all seven: `unvalidated` was the reason
    // while groups were unwritten, and every group's detection is written now.
    assert_eq!(json["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        json["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    let detail = json["content_incomplete_detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        detail.contains("7 of this stage's 7 groups did not run"),
        "got {detail}"
    );
    assert!(
        detail.contains("establishes NOTHING"),
        "and says what that means: {detail}"
    );
}

/// **Different sentences, and the record carries whichever is true.**
///
/// "This build's symbols do not carry what the group needs", "there was no
/// process list to walk" and "the detection is not written yet" are different
/// facts. Conflating any two of them would let one read to an examiner as
/// another — "not implemented" as "your image does not support this", or an
/// absent process list as an absent symbol.
#[test]
fn a_group_whose_symbols_are_present_says_so_rather_than_blaming_the_build() {
    let outcome = examine_tamper(&profile(), &TamperConfig::defaults(), None).expect("stage");
    let by_group = |name: &str| {
        outcome
            .groups
            .iter()
            .find(|g| g.group == name)
            .and_then(|g| g.detail.clone())
            .unwrap_or_default()
    };

    // Every group's detection is written today, so no group may claim
    // otherwise. This is asserted from the lists rather than by naming groups,
    // so adding an unwritten group moves the test with it.
    for group in GROUPS {
        assert!(
            group_is_implemented(group),
            "{group} has no detection: the sentences below need re-reading, not just this assertion"
        );
    }
    assert_eq!(IMPLEMENTED_GROUPS.len(), GROUPS.len());

    // The two thread-side groups: this fixture has no process list, so the
    // reason is the absent list and NOT an absent symbol.
    let suspended = by_group(GROUP_SUSPENDED_THREADS);
    assert!(
        suspended.contains("no process list"),
        "an absent list is named as such: {suspended}"
    );
    assert!(
        suspended.contains("The detection is written"),
        "and is distinguished from an unwritten detection: {suspended}"
    );

    // A group whose symbols are absent names the symbol and what is lost.
    let unloaded = by_group(GROUP_UNLOADED_MODULES);
    assert!(
        unloaded.contains("MmUnloadedDrivers"),
        "the absent symbol is named: {unloaded}"
    );
    assert!(
        unloaded.contains("Without it"),
        "and what it costs: {unloaded}"
    );
    assert!(
        !unloaded.contains("not implemented"),
        "the detection exists, so the reason must not say otherwise: {unloaded}"
    );

    // And the unwritten-detection sentence is still there for the next group
    // to be added: a group not on IMPLEMENTED_GROUPS whose symbols are absent
    // says both. Proved by asking the stage for a group that is not one of its
    // own, which is the only way to reach that branch now.
    assert!(
        !group_is_implemented("a_group_that_does_not_exist"),
        "the guard answers for a name that is not in the list"
    );
}

/// A `Required`-class absence is justified in writing, and the justification
/// says what is LOST rather than that something is needed.
#[test]
fn every_unavailable_reason_says_what_is_lost_and_not_merely_that_it_is_needed() {
    let symbols = TamperSymbols::from_profile(&profile()).expect("symbols");
    let reasons = symbols.unavailable_reasons();
    assert!(!reasons.is_empty(), "this fixture is missing some groups");
    for why in &reasons {
        assert!(
            why.contains("Without it"),
            "a reason must say what is lost: {why}"
        );
        assert!(
            why.len() > 80,
            "\"needed for parsing\" tells an examiner nothing: {why}"
        );
    }
}

/// The module map is SHARED rather than rebuilt, because two independent walks
/// are two chances for two records to disagree about which driver owns an
/// address.
#[test]
fn a_supplied_module_map_is_used_rather_than_a_second_walk() {
    use crate::kernel_hooks::{ModuleMap, ModuleRange};
    use std::sync::Arc;

    let shared = Arc::new(ModuleMap::from_ranges(vec![ModuleRange {
        base: 0xFFFF_F800_0000_0000,
        end: 0xFFFF_F800_0010_0000,
        name: Some("shared.sys".to_string()),
        entry: 0,
    }]));
    let config = TamperConfig {
        modules: Some(Arc::clone(&shared)),
        ..TamperConfig::defaults()
    };
    let outcome = examine_tamper(&profile(), &config, None).expect("stage");
    assert_eq!(
        outcome.modules.len(),
        1,
        "the supplied map is the one used, not a fresh walk"
    );
    assert_eq!(
        outcome.modules.ranges()[0].name.as_deref(),
        Some("shared.sys")
    );
}

/// The caps are declared rather than implied, so a group landing later cannot
/// invent its own ceiling.
#[test]
fn the_caps_are_declared_and_finite() {
    let c = TamperConfig::defaults();
    assert_eq!(c.max_unloaded_drivers, MAX_UNLOADED_DRIVERS);
    assert_eq!(c.max_timers, MAX_TIMERS);
    assert_eq!(c.max_threads, MAX_THREADS);
    assert_eq!(c.max_notes, MAX_RECORDED_NOTES);
    // The unloaded-driver table's documented capacity is 50; a ceiling an
    // order of magnitude above it is generous and finite.
    const { assert!(MAX_UNLOADED_DRIVERS >= 50 && MAX_UNLOADED_DRIVERS < 10_000) };
}

/// An error class maps to one incompleteness word, and the two are different
/// words for different failures.
#[test]
fn an_error_class_maps_to_the_right_incompleteness_word() {
    let unsupported = TamperError::unsupported("no group can run");
    assert_eq!(unsupported.class(), "unsupported_build");
    assert_eq!(
        unsupported.incomplete_reason().as_str(),
        "unresolved_structure",
        "nothing was resolved, so nothing was read"
    );
    let read = TamperError::read("the address space would not answer");
    assert_eq!(read.class(), "address_space_unreadable");
    assert_eq!(read.incomplete_reason().as_str(), "short_read");
    assert_eq!(
        read.to_incomplete().detail,
        "the address space would not answer"
    );
}

/// **A build carrying none of the seven groups' symbols is a stage failure,
/// not an empty result.**
///
/// An empty result there would assert that the kernel has unloaded no drivers,
/// holds no timers and runs no threads, which no Windows kernel has ever been
/// true of.
#[test]
fn a_build_that_can_run_no_group_is_a_failure_and_not_an_empty_answer() {
    // An ISF with the base types and no symbols at all.
    let bare = format!(
        r#"{{"metadata": {{"format": "6.2.0",
             "producer": {{"name": "seance-test", "version": "1.0.0"}},
             "windows": {{"pdb": {{"GUID": "3A4B5C6D7E8F90A1B2C3D4E5F6071829", "age": 1,
                          "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}}},
           "base_types": {},
           "user_types": {{}}, "enums": {{}}, "symbols": {{}}}}"#,
        crate::image_fixture::BASE_TYPES_X64
    );
    let profile = hook_profile(populated_image(), &bare);
    let err = TamperSymbols::from_profile(&profile)
        .expect_err("a build with no symbols cannot run a single group");
    assert_eq!(err.class(), "unsupported_build");
    let detail = err.detail();
    assert!(
        detail.contains("not one of this stage's 7 groups can run"),
        "got {detail}"
    );
    // And every group's own reason is in it, so the failure names what is
    // missing rather than saying "unsupported".
    for symbol in [
        "MmUnloadedDrivers",
        "KiProcessorBlock",
        "PsActiveProcessHead",
        // The ETW and skeleton-key routes are user-mode: what they need is
        // this build's loader entries, not a kernel symbol.
        "_LDR_DATA_TABLE_ENTRY",
        "cryptdll",
    ] {
        assert!(detail.contains(symbol), "{symbol} is not named: {detail}");
    }
}

// --- the unloaded-modules group, once its detection exists -----------------
//
// The rest of this file pins the floor: a stage that runs nothing and says so
// per group. These pin the transition, which is the part with a way to go
// wrong — a group that lands must stop claiming its detection is missing, and
// the six that have not landed must go on saying so.

mod unloaded_group {
    use super::*;
    use crate::image_fixture::Image;
    use crate::kernel_hooks::{ModuleMap, ModuleRange};
    use crate::tamper_unloaded::Fields;
    use std::sync::Arc;

    /// Where the fixture puts the table, its name buffers and its two symbols.
    ///
    /// Plain image offsets: `poolscan::test_support::profile` hands the same
    /// layer as both the kernel space and the physical one, so a pointer value
    /// is also an image offset.
    const TABLE: u64 = 0x2_0000;
    const NAMES: u64 = 0x2_8000;
    const TABLE_PTR: u64 = 0x1_0000;
    const COUNTER: u64 = 0x1_0008;

    /// FILETIME for 2026-09-15T10:00:00Z.
    const UNLOAD_TIME: u64 = 134_339_400_000_000_000;

    /// The hook fixture's ISF with the two symbols this group needs named.
    ///
    /// Derived from `hook_isf` rather than written fresh, so the other groups'
    /// symbols stay exactly as they are and the contrast between "symbols
    /// present, detection missing" and "detection present" is the only thing
    /// that changes.
    fn isf_with_unloaded_symbols() -> String {
        hook_isf().replace(
            "\"symbols\": {",
            &format!(
                "\"symbols\": {{\n    \"MmUnloadedDrivers\": {{\"address\": {TABLE_PTR}}},\n    \
                 \"MmLastUnloadedDriver\": {{\"address\": {COUNTER}}},"
            ),
        )
    }

    /// An image holding a table of `(name, start, end)` triples.
    fn image_with(entries: &[(&str, u64, u64)], write_count: u64, table_at: u64) -> Image {
        let mut img = Image::sized(0x4_0000);
        img.put_u64(TABLE_PTR, table_at);
        img.put_u64(COUNTER, write_count);
        for (i, (name, start, end)) in entries.iter().enumerate() {
            let at = TABLE + (i * Fields::X64.size) as u64;
            let name_at = NAMES + (i * 0x100) as u64;
            let bytes = name.encode_utf16().count() * 2;
            img.put_u16(at, bytes as u16);
            img.put_u16(at + 2, bytes as u16);
            img.put_u64(at + 8, name_at);
            img.put_utf16(name_at, name);
            img.put_u64(at + Fields::X64.start as u64, *start);
            img.put_u64(at + Fields::X64.end as u64, *end);
            img.put_u64(at + Fields::X64.time as u64, UNLOAD_TIME);
        }
        img
    }

    fn profile_with(
        entries: &[(&str, u64, u64)],
        write_count: u64,
    ) -> crate::profile::WindowsProfile {
        hook_profile(
            image_with(entries, write_count, TABLE),
            &isf_with_unloaded_symbols(),
        )
    }

    /// A config that supplies its own module map, so no test here depends on
    /// what a loaded-module walk over a bare fixture would find.
    fn config_with(candidates: Vec<(String, u64)>) -> TamperConfig {
        TamperConfig {
            modules: Some(Arc::new(ModuleMap::from_ranges(vec![ModuleRange {
                base: 0xFFFF_F800_0000_0000,
                end: 0xFFFF_F800_0010_0000,
                name: Some("loaded.sys".to_string()),
                entry: 0,
            }]))),
            candidates,
            ..TamperConfig::defaults()
        }
    }

    /// **The group runs when the build declares its symbols**, and the stage
    /// no longer establishes nothing.
    #[test]
    fn the_group_runs_when_the_build_declares_its_symbols() {
        let outcome = examine_tamper(
            &profile_with(
                &[("tdrv.sys", 0xFFFF_F800_2000_0000, 0xFFFF_F800_2000_8000)],
                1,
            ),
            &config_with(Vec::new()),
            None,
        )
        .expect("stage");
        let group = outcome
            .groups
            .iter()
            .find(|g| g.group == GROUP_UNLOADED_MODULES)
            .expect("the group is reported");
        assert!(group.ran, "it ran: {:?}", group.detail);
        assert_eq!(group.found, 1);
        assert!(!outcome.established_nothing());
        assert_eq!(outcome.ran(), 1);

        let table = outcome.unloaded.as_ref().expect("the table is carried");
        assert_eq!(table.drivers.len(), 1);
        assert_eq!(table.drivers[0].name.as_deref(), Some("tdrv.sys"));
        assert_eq!(outcome.to_json()["unloaded_modules"]["drivers_total"], 1);
    }

    /// **A group that did not run says why, and the stage is incomplete
    /// because of it.**
    ///
    /// This fixture has the unloaded-driver symbols and no process list, so the
    /// groups split: some run, some name the absent list, and the stage carries
    /// the ones that did not run as its own incompleteness.
    #[test]
    fn a_group_that_did_not_run_says_why_and_the_stage_stays_incomplete() {
        let outcome =
            examine_tamper(&profile_with(&[], 0), &config_with(Vec::new()), None).expect("stage");
        let silent: Vec<&str> = outcome
            .groups
            .iter()
            .filter(|g| !g.ran)
            .map(|g| g.group)
            .collect();
        assert!(!silent.is_empty(), "this fixture cannot run every group");
        for g in outcome.groups.iter().filter(|g| !g.ran) {
            let detail = g.detail.clone().unwrap_or_default();
            assert!(
                detail.len() > 60,
                "{} must carry a real reason, not a token: {detail}",
                g.group
            );
        }
        let json = outcome.to_json();
        assert_eq!(json["content_incomplete"], serde_json::json!(true));
        assert_eq!(
            json["content_incomplete_reason"],
            serde_json::json!("unresolved_structure")
        );
        let detail = json["content_incomplete_detail"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        for group in &silent {
            assert!(
                detail.contains(group),
                "the stage's own detail names {group}: {detail}"
            );
        }
    }

    /// **A group whose detection exists must stop claiming it is missing.**
    ///
    /// On a build whose symbols are absent the reason is the absent symbol and
    /// nothing else — the old sentence would have told an examiner the check
    /// was unwritten after it had been written.
    #[test]
    fn a_landed_group_without_symbols_blames_the_symbols_and_not_the_detection() {
        // The plain hook fixture does not declare `MmUnloadedDrivers`.
        let outcome = examine_tamper(
            &hook_profile(populated_image(), &hook_isf()),
            &TamperConfig::defaults(),
            None,
        )
        .expect("stage");
        let detail = outcome
            .groups
            .iter()
            .find(|g| g.group == GROUP_UNLOADED_MODULES)
            .and_then(|g| g.detail.clone())
            .unwrap_or_default();
        assert!(detail.contains("MmUnloadedDrivers"), "got {detail}");
        assert!(
            !detail.contains("not implemented"),
            "the detection exists now, so the reason must not say otherwise: {detail}"
        );
    }

    /// **The cross-reference is the point of the group**, and it runs against
    /// the addresses the caller could not attribute.
    #[test]
    fn candidate_addresses_are_cross_referenced_against_the_unloaded_ranges() {
        let start = 0xFFFF_F800_3000_0000;
        let end = start + 0x8000;
        let outcome = examine_tamper(
            &profile_with(&[("gone.sys", start, end)], 1),
            &config_with(vec![
                ("an image-load callback".to_string(), start + 0x40),
                ("a registry callback".to_string(), 0xFFFF_F800_9000_0000),
            ]),
            None,
        )
        .expect("stage");
        let table = outcome.unloaded.as_ref().expect("table");
        assert_eq!(
            table.hits.len(),
            1,
            "only the address inside the range hits"
        );
        let hit = &table.hits[0];
        assert_eq!(hit.what, "an image-load callback");
        assert_eq!(hit.driver, "gone.sys");
        assert_eq!(hit.to_json()["is_a_verdict"], serde_json::json!(false));
    }

    /// A table the address space will not answer for **fails the group, not
    /// the stage**: the other six groups' reasons still ship.
    #[test]
    fn an_unreadable_table_fails_the_group_and_not_the_stage() {
        // The pointer names an address past the end of the image.
        let mut img = image_with(&[], 1, TABLE);
        img.put_u64(TABLE_PTR, 0xFFFF_FFFF_0000_0000);
        let profile = hook_profile(img, &isf_with_unloaded_symbols());
        let outcome =
            examine_tamper(&profile, &config_with(Vec::new()), None).expect("the stage runs");
        let group = outcome
            .groups
            .iter()
            .find(|g| g.group == GROUP_UNLOADED_MODULES)
            .expect("reported");
        assert!(!group.ran);
        let detail = group.detail.clone().unwrap_or_default();
        assert!(
            detail.contains("would not read") || detail.contains("address space"),
            "the reason is the read failure: {detail}"
        );
        assert_eq!(
            outcome.groups.len(),
            GROUPS.len(),
            "every group still reported"
        );
        assert!(outcome.unloaded.is_none());
        // And the failure is a note, so a reader of the stage sees it without
        // opening the group list.
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("MmUnloadedDrivers")),
            "got {:?}",
            outcome.notes
        );
    }
}

// --- the timers group, and the cross-reference between the two ------------
//
// The forensic claim these pin is the one the two groups make together: a DPC
// routine the loaded-module map cannot account for, which falls inside the
// range of a driver the kernel has unloaded. Neither group can state that
// alone.

mod timers_group {
    use super::*;
    use crate::kernel_hooks::{ModuleMap, ModuleRange};
    use crate::tamper_timers_tests as timer_fixture;
    use crate::tamper_unloaded::Fields;
    use std::sync::Arc;

    /// Where the unloaded table goes inside the timer fixture's image, clear of
    /// everything it writes.
    const TABLE: u64 = 0xB_0000;
    const NAMES: u64 = 0xC_0000;
    const TABLE_PTR: u64 = 0xD_0000;
    const COUNTER: u64 = 0xD_0008;

    /// The unloaded driver's range, and a DPC routine inside it. The routine is
    /// in no loaded module — which is what makes it a candidate at all — and
    /// the range is one the kernel freed.
    const GONE_START: u64 = 0xF_0000;
    const GONE_END: u64 = 0xF_8000;
    const ROUTINE_IN_GONE: u64 = 0xF_0040;

    /// The timer fixture's build, with the unloaded-driver symbols spliced in.
    fn isf() -> String {
        timer_fixture::isf(timer_fixture::NESTED).replace(
            "\"KiProcessorBlock\":",
            &format!(
                "\"MmUnloadedDrivers\": {{\"address\": {TABLE_PTR}}},\n    \
                 \"MmLastUnloadedDriver\": {{\"address\": {COUNTER}}},\n    \
                 \"KiProcessorBlock\":"
            ),
        )
    }

    /// One image holding both structures: one processor's timer table with a
    /// timer whose DPC routine is `routine`, and an unloaded-driver table with
    /// one entry covering `GONE_START..GONE_END`.
    fn image(routine: u64) -> crate::image_fixture::Image {
        let mut img = timer_fixture::image(1);
        timer_fixture::link_timer(
            &mut img,
            timer_fixture::table_base(timer_fixture::PRCB0),
            0,
            timer_fixture::TIMER_A,
            Some((timer_fixture::DPC_A, routine)),
            0,
        );

        img.put_u64(TABLE_PTR, TABLE);
        img.put_u64(COUNTER, 1);
        let name = "gone.sys";
        let bytes = name.encode_utf16().count() * 2;
        img.put_u16(TABLE, bytes as u16);
        img.put_u16(TABLE + 2, bytes as u16);
        img.put_u64(TABLE + 8, NAMES);
        img.put_utf16(NAMES, name);
        img.put_u64(TABLE + Fields::X64.start as u64, GONE_START);
        img.put_u64(TABLE + Fields::X64.end as u64, GONE_END);
        img.put_u64(TABLE + Fields::X64.time as u64, 0);
        img
    }

    /// A map that owns `loaded.sys` and nothing else, so the freed range is
    /// outside every loaded module and the map is authoritative.
    fn config() -> TamperConfig {
        TamperConfig {
            modules: Some(Arc::new(ModuleMap::from_ranges(vec![ModuleRange {
                base: timer_fixture::MODULE_BASE,
                end: timer_fixture::MODULE_END,
                name: Some("loaded.sys".to_string()),
                entry: 0,
            }]))),
            ..TamperConfig::defaults()
        }
    }

    /// **Both groups run**, and the stage says two of seven are written.
    #[test]
    fn the_timers_group_runs_beside_the_unloaded_group() {
        let profile = hook_profile(image(timer_fixture::IN_MODULE), &isf());
        let outcome = examine_tamper(&profile, &config(), None).expect("stage");
        for name in [GROUP_UNLOADED_MODULES, GROUP_TIMERS] {
            let g = outcome
                .groups
                .iter()
                .find(|g| g.group == name)
                .unwrap_or_else(|| panic!("{name} is reported"));
            assert!(g.ran, "{name} must run: {:?}", g.detail);
        }
        assert_eq!(
            outcome.ran(),
            2,
            "only these two: this fixture has no process list, so the thread groups cannot run"
        );
        assert!(!outcome.established_nothing());
        let timers = outcome.timers.as_ref().expect("the table is carried");
        assert_eq!(timers.timers.len(), 1);
        assert_eq!(outcome.to_json()["timers"]["timers_reported"], 1);
    }

    /// **The claim neither group can make alone.** A DPC routine in no loaded
    /// module, inside the range of a driver the kernel unloaded, is reported
    /// with both sides — and as a lead, not a verdict.
    #[test]
    fn a_dpc_routine_inside_an_unloaded_drivers_range_is_cross_referenced() {
        let profile = hook_profile(image(ROUTINE_IN_GONE), &isf());
        let outcome = examine_tamper(&profile, &config(), None).expect("stage");

        let timers = outcome.timers.as_ref().expect("timers");
        assert_eq!(timers.signals(), 1, "the routine is in no loaded module");

        let unloaded = outcome.unloaded.as_ref().expect("the unloaded table");
        assert_eq!(unloaded.hits.len(), 1, "and it is inside a freed range");
        let hit = &unloaded.hits[0];
        assert_eq!(hit.address, ROUTINE_IN_GONE);
        assert_eq!(hit.driver, "gone.sys");
        assert!(
            hit.what.contains("timer"),
            "the hit names what the address was: {}",
            hit.what
        );
        let j = hit.to_json();
        assert_eq!(j["is_a_verdict"], serde_json::json!(false));
        assert!(j["basis"].as_str().unwrap_or_default().contains("FREED"));
    }

    /// A routine inside a loaded module is not offered to the cross-reference
    /// at all: it has a current owner, and asking the unloaded table about it
    /// would offer a driver that unloaded as the explanation for a pointer
    /// something loaded already accounts for.
    #[test]
    fn a_routine_with_a_current_owner_is_not_cross_referenced() {
        let profile = hook_profile(image(timer_fixture::IN_MODULE), &isf());
        let outcome = examine_tamper(&profile, &config(), None).expect("stage");
        assert_eq!(outcome.timers.as_ref().expect("timers").signals(), 0);
        assert!(outcome.unloaded.as_ref().expect("table").hits.is_empty());
    }
}

// --- the three thread groups, at the stage ---------------------------------

mod threads_group {
    use super::*;
    use crate::process::{list_processes, ProcessListConfig, ProcessSymbols};
    use crate::tamper_threads_tests as thread_fixture;
    use std::sync::Arc;

    fn process_list(profile: &crate::profile::WindowsProfile) -> crate::process::ProcessList {
        let symbols = ProcessSymbols::from_profile(profile).expect("process symbols");
        list_processes(profile, &symbols, &ProcessListConfig::default()).expect("the list walks")
    }

    fn config() -> TamperConfig {
        TamperConfig {
            modules: Some(Arc::new(thread_fixture::three_group_modules())),
            ..TamperConfig::defaults()
        }
    }

    /// **All three thread groups run off one pass**, and each reports what it
    /// found.
    #[test]
    fn the_three_thread_groups_run_from_one_pass_over_the_threads() {
        let profile = thread_fixture::three_group_profile();
        let list = process_list(&profile);
        let outcome = examine_tamper(&profile, &config(), Some(&list)).expect("stage");

        let found = |name: &str| {
            let g = outcome
                .groups
                .iter()
                .find(|g| g.group == name)
                .unwrap_or_else(|| panic!("{name} is reported"));
            assert!(g.ran, "{name} must run: {:?}", g.detail);
            g.found
        };
        assert_eq!(found(GROUP_SUSPENDED_THREADS), 1);
        assert_eq!(found(GROUP_DEBUG_REGISTERS), 1);
        assert_eq!(found(GROUP_ORPHAN_KERNEL_THREADS), 1);
        let threads = outcome.threads.as_ref().expect("the pass is carried");
        assert_eq!(threads.threads_examined, 2, "one pass, not three");
        assert_eq!(threads.processes_walked, 1);
    }

    /// **Without a process list the three groups do not run**, and the reason
    /// is the absent list rather than an unwritten detection.
    #[test]
    fn without_a_process_list_the_thread_groups_name_the_absent_list() {
        let profile = thread_fixture::three_group_profile();
        let outcome = examine_tamper(&profile, &config(), None).expect("stage");
        for name in [
            GROUP_SUSPENDED_THREADS,
            GROUP_DEBUG_REGISTERS,
            GROUP_ORPHAN_KERNEL_THREADS,
        ] {
            let g = outcome
                .groups
                .iter()
                .find(|g| g.group == name)
                .unwrap_or_else(|| panic!("{name} is reported"));
            assert!(!g.ran);
            let detail = g.detail.clone().unwrap_or_default();
            assert!(
                detail.contains("process list"),
                "{name} must name the absent list: {detail}"
            );
            assert!(
                !detail.contains("not implemented"),
                "{name}'s detection IS written, so the reason must not say otherwise: {detail}"
            );
        }
        assert!(outcome.threads.is_none());
    }

    /// The orphan's start address is offered to the unloaded-driver
    /// cross-reference, like every other pointer no module accounts for.
    #[test]
    fn an_orphan_start_address_becomes_a_cross_reference_candidate() {
        let profile = thread_fixture::three_group_profile();
        let list = process_list(&profile);
        let outcome = examine_tamper(&profile, &config(), Some(&list)).expect("stage");
        // This build declares no `MmUnloadedDrivers`, so there is no table to
        // hit -- which is exactly why the orphan is an observation and not a
        // finding, and the candidate is recorded for when a table exists.
        assert!(outcome.unloaded.is_none());
        let threads = outcome.threads.as_ref().expect("threads");
        assert_eq!(threads.graded_orphans(), 0);
        assert_eq!(threads.ungraded_orphans(), 1);
        assert_eq!(
            threads.orphans[0].start_address,
            thread_fixture::ORPHAN_START
        );
    }
}
