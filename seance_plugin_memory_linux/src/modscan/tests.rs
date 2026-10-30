//! What the module scan must find, and what it must refuse.
//!
//! A fabricated module is a worse finding than a missed one: "an unlinked
//! kernel module" is close to an accusation, and an examiner shown one that
//! never existed has no way to check.

use super::*;
use crate::lsmod::ModuleList;

fn name_field(name: &str, residue: u8) -> Vec<u8> {
    let mut out = vec![residue; MODULE_NAME_LEN];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out[name.len()] = 0;
    out
}

// ── state ──────────────────────────────────────────────────────────────────

/// `enum module_state` has exactly four values, and it is the first member of
/// `struct module` — so this is the cheapest and strongest filter available.
#[test]
fn only_the_four_states_the_kernel_defines_are_accepted() {
    for state in 0..=MAX_MODULE_STATE {
        assert!(plausible_state(state), "{state} is a state the kernel sets");
        assert!(
            state_label(state).is_some(),
            "a state the scan accepts must have a name it can print"
        );
    }
    for state in [4u32, 5, 0xFFFF, u32::MAX] {
        assert!(!plausible_state(state), "{state} is not a module state");
        assert_eq!(
            state_label(state),
            None,
            "a value the kernel does not define must not be given a label"
        );
    }
}

// ── name ───────────────────────────────────────────────────────────────────

#[test]
fn real_module_names_are_accepted() {
    for name in [
        "ext4",
        "nf_tables",
        "snd_hda_intel",
        "i2c-core",
        "kvm_intel",
    ] {
        assert_eq!(
            plausible_module_name(&name_field(name, 0)).as_deref(),
            Some(name),
            "{name} is a module name Linux really loads"
        );
    }
}

#[test]
fn residue_after_the_terminator_is_ignored() {
    assert_eq!(
        plausible_module_name(&name_field("ext4", 0xFF)).as_deref(),
        Some("ext4")
    );
}

/// **The filter that matters.** A module name is not merely "printable": the
/// kernel and `modprobe` constrain it. Accepting ordinary text would match
/// most of memory, since memory is full of short printable strings.
#[test]
fn ordinary_text_is_not_a_module_name() {
    for text in [
        "hello world",      // a space
        "/usr/lib/modules", // slashes
        "GET /index.html",  // punctuation
        "name=value",       // an equals sign
        "a.b.c",            // dots
    ] {
        assert_eq!(
            plausible_module_name(&name_field(text, 0)),
            None,
            "{text:?} is text, not a module name"
        );
    }
    // Structural refusals.
    assert_eq!(
        plausible_module_name(&[b'a'; MODULE_NAME_LEN]),
        None,
        "no terminator"
    );
    assert_eq!(
        plausible_module_name(&name_field("", 0)),
        None,
        "empty name"
    );
    assert_eq!(plausible_module_name(&[0u8; 8]), None, "field too short");
    assert_eq!(plausible_module_name(&[]), None);
}

/// Both conditions together are what make the signature strong. Either alone
/// is weak, and a candidate must satisfy both.
#[test]
fn a_candidate_needs_both_a_valid_state_and_a_valid_name() {
    // state at 0, name at 16 — the shape `struct module` actually has.
    let mut bytes = vec![0u8; 128];
    bytes[..4].copy_from_slice(&0u32.to_le_bytes()); // MODULE_STATE_LIVE
    bytes[16..16 + MODULE_NAME_LEN].copy_from_slice(&name_field("ext4", 0xAA));

    let (name, state) = candidate_from_bytes(&bytes, 0, 16).expect("a plausible module");
    assert_eq!(name, "ext4");
    assert_eq!(state, 0);

    // A valid name with an impossible state is refused.
    let mut bad_state = bytes.clone();
    bad_state[..4].copy_from_slice(&99u32.to_le_bytes());
    assert!(candidate_from_bytes(&bad_state, 0, 16).is_none());

    // A valid state with text where the name should be is refused.
    let mut bad_name = bytes.clone();
    bad_name[16..16 + MODULE_NAME_LEN].copy_from_slice(&name_field("not a name", 0));
    assert!(candidate_from_bytes(&bad_name, 0, 16).is_none());

    // Truncated buffers are refused, not read past.
    assert!(candidate_from_bytes(&bytes[..8], 0, 16).is_none());
    assert!(candidate_from_bytes(&[], 0, 16).is_none());
}

/// Pseudo-random memory must essentially never pass. Without this the scan
/// would report noise across a 15 GiB image and bury any real finding.
#[test]
fn random_bytes_almost_never_pass_both_conditions() {
    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut accepted = 0usize;
    const TRIALS: usize = 20_000;
    for _ in 0..TRIALS {
        let bytes: Vec<u8> = (0..128)
            .map(|_| {
                lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (lcg >> 33) as u8
            })
            .collect();
        if candidate_from_bytes(&bytes, 0, 16).is_some() {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 0,
        "{accepted} of {TRIALS} random buffers passed; requiring a state below four AND a \
         constrained name should make this essentially impossible"
    );
}

// ── cross-view ─────────────────────────────────────────────────────────────

fn list_with(addresses: &[u64]) -> ModuleList {
    ModuleList {
        head: 0xffff_ffff_8fc4_0000,
        links_offset: 0x08,
        modules: addresses
            .iter()
            .map(|a| crate::lsmod::ModuleRecord::address_only_for_test(*a))
            .collect(),
        stop: seance_memory::object::ListStop::Wrapped,
        layout: serde_json::json!({}),
    }
}

fn scanned(address: u64, name: &str) -> ScannedModule {
    ScannedModule {
        address,
        name: name.to_string(),
        state: 0,
    }
}

/// **The point of the module.** A structure the scan finds and the list does
/// not is what a hidden module looks like, and it must surface.
#[test]
fn a_module_the_list_does_not_contain_is_reported_as_scan_only() {
    let list = list_with(&[0x1000, 0x2000]);
    let found = vec![
        scanned(0x1000, "ext4"),
        scanned(0x2000, "kvm_intel"),
        scanned(0x9000, "rootkit"),
    ];

    let view = ModuleCrossView::build(&list, &found, true);
    assert_eq!(view.scan_only, 1);

    let hidden = view.rows.iter().find(|r| r.address == 0x9000).unwrap();
    assert_eq!(hidden.verdict, ModuleVerdict::ScanOnly);
    assert_eq!(hidden.name.as_deref(), Some("rootkit"));
    assert_eq!(hidden.scanned_state, Some(0));
}

/// **This is close to an accusation, so it must carry every reading.**
///
/// A module absent from the list is what a rootkit looks like — and equally
/// what a module mid-load, mid-unload, or already unloaded looks like. A record
/// naming only the first would put a conclusion in front of an examiner that
/// the evidence does not support on its own.
#[test]
fn a_scan_only_module_states_the_innocent_explanations_too() {
    let meaning = ModuleVerdict::ScanOnly.meaning();
    assert!(meaning.contains("UNLINKING"), "the finding must be named");
    assert!(
        meaning.contains("part-way through loading or unloading"),
        "a module mid-transition looks identical: {meaning}"
    );
    assert!(
        meaning.contains("stale structure"),
        "so does a structure left by a module already unloaded: {meaning}"
    );
    assert!(
        meaning.contains("not by itself proof"),
        "the record must refuse to draw the conclusion for the examiner"
    );
}

#[test]
fn a_module_the_scan_did_not_reach_is_not_reported_as_suspicious() {
    let list = list_with(&[0x1000, 0x2000]);
    let view = ModuleCrossView::build(&list, &[scanned(0x1000, "ext4")], true);
    let missed = view.rows.iter().find(|r| r.address == 0x2000).unwrap();
    assert_eq!(missed.verdict, ModuleVerdict::ListOnly);
    assert!(missed
        .verdict
        .meaning()
        .contains("not a finding about the module"));
    assert_eq!(view.scan_only, 0);
}

/// A cross-view over a scan that did not run corroborates nothing, and must
/// say so rather than implying a check happened.
#[test]
fn a_cross_view_whose_scan_did_not_run_says_it_corroborates_nothing() {
    let view = ModuleCrossView::build(&list_with(&[0x1000]), &[], false);
    let json = view.to_json();
    assert_eq!(json["scan_ran"], serde_json::json!(false));
    assert!(json["corroboration_note"]
        .as_str()
        .unwrap()
        .contains("NOT corroborated"));
    assert_eq!(
        view.rows.len(),
        1,
        "the list's own modules are still reported"
    );
}

#[test]
fn both_methods_finding_a_module_is_the_ordinary_case() {
    let view = ModuleCrossView::build(&list_with(&[0x1000]), &[scanned(0x1000, "ext4")], true);
    assert_eq!(view.rows.len(), 1);
    assert_eq!(view.rows[0].verdict, ModuleVerdict::Both);
    assert_eq!(view.scan_only, 0);
}

/// A state the kernel does not define must never be printed as a label — the
/// scan refuses such candidates, and a row that somehow carried one must not
/// invent a lifecycle stage for it.
#[test]
fn an_undefined_state_is_reported_without_a_label() {
    let row = ModuleCrossRow {
        address: 0x1000,
        name: Some("x".into()),
        verdict: ModuleVerdict::ScanOnly,
        scanned_state: Some(42),
    };
    let json = row.to_json();
    assert_eq!(json["scanned_state"], serde_json::json!(42));
    assert!(
        json["scanned_state_label"].is_null(),
        "a value with no kernel meaning must not be given one"
    );
}

// ── links ──────────────────────────────────────────────────────────────────

/// **What makes the signature usable.**
///
/// A name and a four-value enum are cheap to satisfy by accident. The task scan
/// measured what a comparable signature admits across a real capture — tens of
/// thousands of structures — and the fix was to require the candidate's own
/// list links to be a `list_head`. Two aligned canonical kernel pointers are
/// not something arbitrary memory produces.
#[test]
fn only_a_plausible_list_head_is_treated_as_one() {
    let mut bytes = vec![0u8; 64];
    let put = |b: &mut [u8], next: u64, prev: u64| {
        b[16..24].copy_from_slice(&next.to_le_bytes());
        b[24..32].copy_from_slice(&prev.to_le_bytes());
    };

    put(&mut bytes, 0xffff_ffff_c012_3458, 0xffff_ffff_c045_6788);
    assert!(matches!(
        classify_links(&bytes, 16),
        LinkShape::Kernel { .. }
    ));

    put(
        &mut bytes,
        crate::taskscan::LIST_POISON1,
        crate::taskscan::LIST_POISON2,
    );
    assert_eq!(classify_links(&bytes, 16), LinkShape::Poisoned);

    for (next, prev) in [
        (0u64, 0u64),                                   // zeros, the commonest bytes there are
        (0x1000, 0x2000),                               // user-space addresses
        (0xffff_ffff_c012_3458, 0x1000),                // one kernel, one not
        (0xffff_ffff_c012_3451, 0xffff_ffff_c045_6788), // unaligned
        (crate::taskscan::LIST_POISON1, 0),             // half-poisoned
    ] {
        put(&mut bytes, next, prev);
        assert_eq!(
            classify_links(&bytes, 16),
            LinkShape::NotLinks,
            "next={next:#x} prev={prev:#x} are not a module's list links"
        );
    }

    // Buffers too short are refused, not read past.
    assert_eq!(classify_links(&bytes[..20], 16), LinkShape::NotLinks);
    assert_eq!(classify_links(&[], 0), LinkShape::NotLinks);
}

#[test]
fn a_zeroed_buffer_is_never_a_module_link() {
    let bytes = vec![0u8; 4096];
    for offset in (0..4000).step_by(8) {
        assert_eq!(
            classify_links(&bytes, offset),
            LinkShape::NotLinks,
            "zeros at offset {offset} were treated as list links"
        );
    }
}

/// **The scan corroborates; it does not accuse.**
///
/// A structure the scan finds and the list does not is what a hidden module
/// looks like — and also what this signature's own noise looks like. Reporting
/// each as a candidate would bury a real one among them, so the count is given
/// and the structures are not, and the record says the detection did not
/// happen.
#[test]
fn scan_only_structures_are_counted_but_never_reported_as_findings() {
    let list = list_with(&[0x1000, 0x2000]);
    let found = vec![
        scanned(0x1000, "ext4"),
        scanned(0x2000, "kvm_intel"),
        scanned(0x9000, "noise"),
        scanned(0xA000, "more_noise"),
    ];
    let view = ModuleCrossView::build(&list, &found, true);
    let json = view.to_json();

    assert_eq!(view.corroborated(), 2);
    assert_eq!(json["corroborated_by_scan"], serde_json::json!(2));
    assert_eq!(json["modules_from_list"], serde_json::json!(2));
    assert_eq!(json["scan_only_count"], serde_json::json!(2));

    let rows = json["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "only the list's own modules may be rows");
    for row in rows {
        assert_ne!(
            row["verdict"],
            serde_json::json!("scan_only"),
            "a scan-only structure was reported as a finding: {row}"
        );
    }

    let statement = json["hidden_module_detection"].as_str().expect("stated");
    assert!(
        statement.contains("NOT PERFORMED"),
        "the record must say hidden-module detection did not happen: {statement}"
    );
    assert!(
        statement.contains("NOT be surfaced here"),
        "it must say what that costs: {statement}"
    );
}
