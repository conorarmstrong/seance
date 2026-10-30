//! What the kernel-tamper leads claim, and the four rows they must not raise.

use super::kernel_tamper::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::Confidence;
use serde_json::json;
use uuid::Uuid;

fn record(metadata: serde_json::Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata)
}

fn stage(extra: serde_json::Value) -> Artifact {
    let mut metadata = json!({
        "type": "MemoryTamperChecks",
        "record_type": "MemoryTamperChecks",
        "groups": [],
    });
    if let (Some(base), Some(extra)) = (metadata.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    record(metadata)
}

fn kinds(findings: &[seance_core::finding::Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.kind.as_str()).collect()
}

/// **A record of some other type raises nothing.** The module subscribes to
/// every parsed record, so this is the guard that keeps it to its own.
#[test]
fn only_the_tamper_stages_own_record_is_read() {
    let other = record(json!({"type": "MemoryProcessList", "record_type": "MemoryProcessList"}));
    assert!(KernelTamperFindings::new().findings_for(&other).is_empty());
}

/// A stage that ran every group and found nothing raises nothing.
#[test]
fn a_clean_stage_record_raises_nothing() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "unloaded_modules": {"range_hits": [], "drivers": []},
        "timers": {"timers": []},
        "threads": {
            "orphan_kernel_threads": [],
            "debug_register_threads": [],
            "suspended_threads": [],
        },
        "etw": {"exports": []},
        "skeleton_key": {"lsass_processes": []},
    })));
    assert!(found.is_empty(), "got {:?}", kinds(&found));
}

/// **A suspended thread raises nothing at all**, whatever its count. The stage
/// reports it as a listing with `is_a_finding: false`, and promoting it here is
/// the `HUNT-051` mistake.
#[test]
fn a_suspended_thread_is_never_a_lead() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "threads": {
            "suspended_threads": [
                {"tid": 900, "process_name": "calc.exe", "suspend_count": 3,
                 "is_a_finding": false},
                {"tid": 901, "process_name": "notepad.exe", "suspend_count": 1,
                 "is_a_finding": false},
            ],
            "orphan_kernel_threads": [],
            "debug_register_threads": [],
        },
    })));
    assert!(found.is_empty(), "got {:?}", kinds(&found));
}

/// An address inside an unloaded driver's range is a **weak** lead, and the
/// qualification says the range was freed.
#[test]
fn a_pointer_into_an_unloaded_range_is_a_weak_lead_that_says_the_range_was_freed() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "unloaded_modules": {
            "range_hits": [{
                "what": "an image-load callback",
                "address": "0xfffff80230000040",
                "unloaded_driver": "gone.sys",
                "unloaded_driver_start": "0xfffff80230000000",
                "unloaded_driver_end": "0xfffff80230008000",
                "unloaded_at": null,
                "also_owned_by": {"kind": "outside_any_module"},
                "is_a_verdict": false,
            }],
        },
    })));
    assert_eq!(kinds(&found), vec!["pointer_into_unloaded_driver"]);
    let lead = &found[0];
    assert_eq!(lead.confidence, Confidence::Weak);
    assert!(lead.title.contains("gone.sys"));
    assert!(
        lead.qualification.contains("FREED"),
        "got {}",
        lead.qualification
    );
    assert!(
        lead.qualification
            .contains("establishes nothing on its own"),
        "got {}",
        lead.qualification
    );
    // Both sides are in the evidence, so the lead can be checked without
    // opening the stage record.
    let keys: Vec<&str> = lead.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(keys.contains(&"address"));
    assert!(keys.contains(&"unloaded_driver"));
    assert!(keys.contains(&"loaded_modules_say"));
}

/// A timer whose DPC routine no module owns is **notable**, and the
/// qualification names the unloaded-driver explanation and the cross-reference.
#[test]
fn a_timer_routine_in_no_module_is_notable_and_names_the_innocent_cause() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "timers": {
            "timers": [
                {"timer_address": "0xfffff80240000000",
                 "deferred_routine": "0xffffc00012340000",
                 "dpc_address": "0xfffff80240001000",
                 "bucket": 7, "processor": 2, "period_ms": 0,
                 "is_signal": true},
                {"timer_address": "0xfffff80240002000",
                 "deferred_routine": "0xfffff80233000000",
                 "is_signal": false},
            ],
        },
    })));
    assert_eq!(kinds(&found), vec!["kernel_timer_routine_unattributed"]);
    let lead = &found[0];
    assert_eq!(lead.confidence, Confidence::Notable);
    assert!(
        lead.qualification.contains("has since unloaded"),
        "got {}",
        lead.qualification
    );
    assert!(
        lead.qualification.contains("PatchGuard")
            && lead.qualification.contains("Case 001")
            && lead.qualification.contains("0 of 52")
            && lead.qualification.contains("DPC routine was located")
            && lead.qualification.contains("distinct")
            // Rows walked (pre-`MEM-055` sightings) are not the graded
            // population and must not stand as the clean baseline.
            && !lead.qualification.contains("367")
            && !lead.qualification.contains("209 timers"),
        "the re-measured clean-capture counts and the PatchGuard shape are in the \
         qualification: {}",
        lead.qualification
    );
}

/// **`MEM-055`: a timer reached from two bucket lists is one lead.** The stage
/// now publishes it as one row whose `reached_from` names both places, and
/// that row raises one lead that carries both; a record from a producer that
/// still published one row per sighting raises one lead too, keyed on the
/// `_KTIMER` address, rather than one per row.
#[test]
fn a_signal_reached_twice_yields_one_finding() {
    let signal = |processor: u64| {
        json!({"timer_address": "0xfffff80240000000",
               "deferred_routine": "0xffffc00012340000",
               "bucket": 3, "processor": processor,
               "reached_from": [{"processor": 0, "bucket": 3},
                                {"processor": 1, "bucket": 3}],
               "is_signal": true})
    };
    let one_row = KernelTamperFindings::new()
        .findings_for(&stage(json!({"timers": {"timers": [signal(0)]}})));
    assert_eq!(kinds(&one_row), vec!["kernel_timer_routine_unattributed"]);
    assert!(
        one_row[0]
            .evidence
            .iter()
            .any(|e| e.name == "reached_from" && e.value.contains("\"processor\":1")),
        "the lead carries every place the timer was reached: {:?}",
        one_row[0].evidence
    );
    let stale = KernelTamperFindings::new().findings_for(&stage(
        json!({"timers": {"timers": [signal(0), signal(1)]}}),
    ));
    assert_eq!(kinds(&stale), vec!["kernel_timer_routine_unattributed"]);
}

/// **`MEM-054`: a PatchGuard-shaped timer raises no lead.** The stage publishes
/// it ungraded (`is_signal: false`, `patchguard_shaped: true`); the rule also
/// skips a row that says it has the shape even when a stale producer still
/// marks it a signal, so the owner's decision holds at both layers.
#[test]
fn a_patchguard_shaped_timer_raises_no_lead() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "timers": {
            "timers": [
                {"timer_address": "0xffffbe8e7105d5ab",
                 "deferred_routine": "0xffffbe8e70b622b1",
                 "deferred_context": "0x5a474314a0a22080",
                 "is_signal": false, "patchguard_shaped": true},
                {"timer_address": "0xffffbe8e7105d5ab",
                 "deferred_routine": "0xffffbe8e70b622b1",
                 "deferred_context": "0x5a474314a0a22080",
                 "is_signal": true, "patchguard_shaped": true},
            ],
        },
    })));
    assert!(
        !kinds(&found).contains(&"kernel_timer_routine_unattributed"),
        "got {:?}",
        kinds(&found)
    );
}

/// **An orphan observation is not a lead — only a graded finding is.** A row
/// one of whose exclusions could not be assessed has a control unapplied.
#[test]
fn an_orphan_observation_is_not_raised_and_a_graded_one_is() {
    let module = KernelTamperFindings::new();
    let observation = stage(json!({
        "threads": {
            "orphan_kernel_threads": [{
                "tid": 500, "start_address": "0xffffc00012340000",
                "is_graded_finding": false,
                "exclusions": {"not_in_an_unloaded_range": {"state": "not_assessed"}},
            }],
            "debug_register_threads": [],
        },
    }));
    assert!(
        module.findings_for(&observation).is_empty(),
        "an unassessed exclusion means the claim is not graded, so it is not a lead"
    );

    let graded = stage(json!({
        "threads": {
            "orphan_kernel_threads": [{
                "tid": 500,
                "thread_address": "0xffff9b0100000000",
                "start_address": "0xffffc00012340000",
                "kernel_thread_basis": "`_KTHREAD.SystemThread` is set on this build and on this thread.",
                "is_graded_finding": true,
            }],
            "debug_register_threads": [],
        },
    }));
    let found = module.findings_for(&graded);
    assert_eq!(kinds(&found), vec!["orphan_kernel_thread"]);
    assert_eq!(found[0].confidence, Confidence::Notable);
    assert!(
        found[0].observation.contains("had not terminated"),
        "the observation names the exclusions that were applied: {}",
        found[0].observation
    );
    assert!(
        found[0].qualification.contains("1,514"),
        "the clean-capture measurement is in the qualification: {}",
        found[0].qualification
    );
}

/// A debug-register row is a lead only when a slot is **armed and confirmed**.
#[test]
fn only_an_armed_and_confirmed_debug_register_row_is_a_lead() {
    let module = KernelTamperFindings::new();
    let stale = stage(json!({
        "threads": {
            "debug_register_threads": [{
                "tid": 700, "process_name": "app.exe",
                "armed_slots": 0, "stale_slots": [0, 1],
                "has_breakpoint": false,
                "claim": "unconfirmed: this build declares neither DebugActive nor ActiveDR7",
            }],
            "orphan_kernel_threads": [],
        },
    }));
    assert!(module.findings_for(&stale).is_empty());

    let armed = stage(json!({
        "threads": {
            "debug_register_threads": [{
                "tid": 700, "process_name": "app.exe",
                "armed_slots": 2,
                "dr7": "0x0000000000000081",
                "has_breakpoint": true,
                "claim": "confirmed_by_the_thread's_own_flags",
                "breakpoints": [
                    {"slot": 0, "address": "0x00007ff800001000", "enable": "local",
                     "ownership": {"kind": "in_module", "module": "ntdll.dll"}},
                    {"slot": 3, "address": "0x00007ff800002000", "enable": "global",
                     "ownership": {"kind": "outside_any_module"}},
                ],
            }],
            "orphan_kernel_threads": [],
        },
    }));
    let found = module.findings_for(&armed);
    assert_eq!(kinds(&found), vec!["thread_hardware_breakpoint"]);
    assert_eq!(found[0].confidence, Confidence::Notable);
    assert!(
        found[0].qualification.contains("A debugger sets these"),
        "got {}",
        found[0].qualification
    );
    let keys: Vec<&str> = found[0].evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(keys.iter().any(|k| k.starts_with("slot ")), "got {keys:?}");
}

/// An ETW export marked by either route is a lead that names the route.
#[test]
fn an_etw_signal_names_the_route_that_marked_it() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "etw": {
            "exports": [
                {"export": "EtwEventWrite", "process_name": "evil.exe",
                 "route": "both", "is_signal": true,
                 "prologue": "c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                 "classification": "returns_immediately",
                 "classification_detail": "the function returns after 1 instruction(s): ret",
                 "mode_agreed": 122, "mode_population": 123},
                {"export": "EtwEventWrite", "process_name": "ordinary.exe",
                 "is_signal": false, "classification": "ordinary"},
            ],
        },
    })));
    assert_eq!(kinds(&found), vec!["etw_write_path_patched"]);
    let lead = &found[0];
    assert!(lead.title.contains("evil.exe"));
    let keys: Vec<&str> = lead.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(keys.contains(&"route"));
    assert!(keys.contains(&"prologue"));
    assert!(keys.contains(&"decoded"));
    assert!(keys.contains(&"mode_agreed"));
    assert!(
        lead.qualification.contains("hooking product"),
        "got {}",
        lead.qualification
    );
    assert!(
        lead.qualification
            .contains("`ordinary` on the other rows is not a claim"),
        "got {}",
        lead.qualification
    );
}

/// A patched `CDLocateCSystem` is a lead whose qualification states that the
/// check's other route never runs.
#[test]
fn a_patched_lsa_export_is_a_lead_that_admits_the_other_route_never_runs() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "skeleton_key": {
            "lsass_processes": [{
                "pid": 968, "module": "cryptdll.dll", "export": "CDLocateCSystem",
                "export_address": "0x00007ffcd9943150",
                "prologue": "c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "classification": "returns_immediately",
                "is_signal": true,
            }],
        },
    })));
    assert_eq!(kinds(&found), vec!["lsa_crypto_export_patched"]);
    let lead = &found[0];
    assert!(lead.title.contains("968"));
    assert!(
        lead.qualification.contains("DOES NOT RUN"),
        "got {}",
        lead.qualification
    );
}

/// **Nothing here is `Strong`.** Every one of these has a documented innocent
/// cause, and the grades say so.
#[test]
fn no_kernel_tamper_lead_claims_a_strong_grade() {
    let found = KernelTamperFindings::new().findings_for(&stage(json!({
        "unloaded_modules": {"range_hits": [{
            "what": "a callback", "address": "0x1000", "unloaded_driver": "gone.sys",
            "also_owned_by": {"kind": "outside_any_module"}}]},
        "timers": {"timers": [{"timer_address": "0x2000",
            "deferred_routine": "0x3000", "is_signal": true}]},
        "threads": {
            "orphan_kernel_threads": [{"tid": 1, "start_address": "0x4000",
                "is_graded_finding": true}],
            "debug_register_threads": [{"tid": 2, "armed_slots": 1,
                "has_breakpoint": true, "breakpoints": []}],
        },
        "etw": {"exports": [{"export": "EtwEventWrite", "is_signal": true}]},
        "skeleton_key": {"lsass_processes": [{"pid": 9, "is_signal": true}]},
    })));
    assert_eq!(found.len(), 6, "one of each: {:?}", kinds(&found));
    for lead in &found {
        assert_ne!(
            lead.confidence,
            Confidence::Strong,
            "{} claims a strong grade: none of these is hard to produce innocently",
            lead.kind
        );
        assert!(
            !lead.qualification.is_empty() && lead.qualification.len() > 80,
            "{} must say what it does not establish: {}",
            lead.kind,
            lead.qualification
        );
        assert_eq!(lead.source_module, MODULE_ID);
    }
}
