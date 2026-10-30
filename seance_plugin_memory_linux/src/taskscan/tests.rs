//! What the scan must find, and — more importantly — what it must refuse.
//!
//! A scanner that fabricates a process is worse than one that finds none: an
//! examiner shown a process that never existed has no way to tell. So most of
//! what is here is refusal.

use super::*;
use crate::tasks::TaskList;
use std::sync::Arc;

/// A 16-byte `comm` field holding `name`, then a NUL, then whatever was there
/// before — which is what the kernel actually leaves.
fn comm_field(name: &str, residue: u8) -> Vec<u8> {
    let mut out = vec![residue; TASK_COMM_LEN];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out[name.len()] = 0;
    out
}

// ── comm ───────────────────────────────────────────────────────────────────

#[test]
fn an_ordinary_process_name_is_accepted() {
    for name in ["init", "systemd", "kworker/0:1", "sshd", "a"] {
        assert_eq!(
            plausible_comm(&comm_field(name, 0)).as_deref(),
            Some(name),
            "{name} is a name Linux really uses"
        );
    }
}

/// The kernel does not clear the field before writing a shorter name, so bytes
/// after the NUL are residue and must not be read as part of the name.
#[test]
fn residue_after_the_terminator_is_ignored() {
    assert_eq!(
        plausible_comm(&comm_field("sh", 0xFF)).as_deref(),
        Some("sh"),
        "the name ends at its NUL; what follows belonged to a previous name"
    );
}

/// **The main filter.** Arbitrary bytes must not read as a process name.
#[test]
fn arbitrary_bytes_are_not_a_process_name() {
    // No NUL anywhere in the field: not a terminated name.
    assert_eq!(plausible_comm(&[b'A'; TASK_COMM_LEN]), None);
    // Leading NUL: an empty name is not a process name.
    assert_eq!(plausible_comm(&comm_field("", 0)), None);
    // Unprintable bytes before the terminator.
    let mut binary = vec![0u8; TASK_COMM_LEN];
    binary[..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    binary[4] = 0;
    assert_eq!(plausible_comm(&binary), None);
    // Too short a field to be one at all.
    assert_eq!(plausible_comm(&[0u8; 8]), None);
    assert_eq!(plausible_comm(&[]), None);
}

/// Pseudo-random bytes must essentially never pass. This is what stops the scan
/// reporting thousands of candidates across a 15 GiB image.
#[test]
fn random_bytes_almost_never_read_as_a_process_name() {
    let mut lcg: u64 = 0x2545_F491_4F6C_DD1D;
    let mut accepted = 0usize;
    const TRIALS: usize = 20_000;
    for _ in 0..TRIALS {
        let field: Vec<u8> = (0..TASK_COMM_LEN)
            .map(|_| {
                lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (lcg >> 33) as u8
            })
            .collect();
        if plausible_comm(&field).is_some() {
            accepted += 1;
        }
    }
    // Random bytes need a NUL AND only printable bytes before it. That is rare,
    // and a rate above a few per cent would mean the filter is not filtering.
    assert!(
        accepted * 100 < TRIALS,
        "{accepted} of {TRIALS} random fields read as process names, which is too many \
         for this to be a useful filter"
    );
}

// ── identifiers ────────────────────────────────────────────────────────────

#[test]
fn plausible_identifiers_are_accepted_and_impossible_ones_are_not() {
    assert!(plausible_pid(1));
    assert!(plausible_pid(0), "the swapper task really is pid 0");
    assert!(plausible_pid(PID_MAX_LIMIT));
    assert!(!plausible_pid(-1), "a negative pid is not a pid");
    assert!(!plausible_pid(PID_MAX_LIMIT + 1));
    assert!(!plausible_pid(i64::MAX));
}

/// A thread's `tgid` names its group leader, created first, so it is never
/// above the thread's own id. Bytes that violate that are not a task.
#[test]
fn a_thread_group_id_above_its_own_id_is_refused() {
    assert!(plausible_id_pair(1000, 1000), "a group leader");
    assert!(plausible_id_pair(1005, 1000), "a thread of that leader");
    assert!(
        !plausible_id_pair(1000, 1005),
        "a leader created after its own thread is not a pairing the kernel produces"
    );
    assert!(!plausible_id_pair(-1, -1));
}

#[test]
fn a_candidate_is_read_only_when_every_field_is_plausible() {
    // comm at 0, pid at 24, tgid at 28.
    let mut bytes = vec![0u8; 64];
    bytes[..TASK_COMM_LEN].copy_from_slice(&comm_field("bash", 0xAA));
    bytes[24..28].copy_from_slice(&1234i32.to_le_bytes());
    bytes[28..32].copy_from_slice(&1234i32.to_le_bytes());

    let (comm, tid, pid) = candidate_from_bytes(&bytes, 0, 24, 28).expect("a plausible task");
    assert_eq!(comm, "bash");
    assert_eq!((tid, pid), (1234, 1234));

    // One implausible field is enough to refuse the whole candidate.
    let mut bad_pid = bytes.clone();
    bad_pid[24..28].copy_from_slice(&(-5i32).to_le_bytes());
    assert!(candidate_from_bytes(&bad_pid, 0, 24, 28).is_none());

    let mut bad_comm = bytes.clone();
    bad_comm[..4].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    assert!(candidate_from_bytes(&bad_comm, 0, 24, 28).is_none());

    // Truncated buffer: refused, not read past its end.
    assert!(candidate_from_bytes(&bytes[..20], 0, 24, 28).is_none());
    assert!(candidate_from_bytes(&[], 0, 24, 28).is_none());
}

// ── cross-view ─────────────────────────────────────────────────────────────

fn list_with(addresses: &[u64]) -> TaskList {
    TaskList {
        init_task: 0xffff_ffff_8fc0_fb40,
        head: 0xffff_ffff_8fc0_fb98,
        links_offset: 0x58,
        tasks: addresses
            .iter()
            .map(|a| crate::tasks::TaskRecord::address_only_for_test(*a))
            .collect(),
        stop: seance_memory::object::ListStop::Wrapped,
        layout: serde_json::json!({}),
    }
}

/// A 16-byte `list_head` at `tasks_offset` inside a candidate buffer.
fn with_links(bytes: &mut [u8], tasks_offset: usize, next: u64, prev: u64) {
    bytes[tasks_offset..tasks_offset + 8].copy_from_slice(&next.to_le_bytes());
    bytes[tasks_offset + 8..tasks_offset + 16].copy_from_slice(&prev.to_le_bytes());
}

/// **The false positives that dominated a real capture were maildir filenames.**
///
/// The scan matched `,W=11420:2,S`, `W=1996:2,Sa` and `-2-37:2,Sc` out of the
/// page cache of a machine that stores mail: printable, NUL-terminated inside
/// sixteen bytes, and tens of thousands of them, every one becoming a candidate
/// hidden process. These are the strings themselves, from that capture.
#[test]
fn maildir_filenames_are_not_process_names() {
    for text in [
        ",W=11420:2,S",
        "W=1996:2,Sa",
        "-2-37:2,Sc",
        "W=10054:2,a",
        "470:2,Sa",
        "2,RSc",
        "@{+",
        "\"",
        "`",
    ] {
        assert_eq!(
            plausible_comm(&comm_field(text, 0)),
            None,
            "{text:?} was matched as a process name on a real capture"
        );
    }
}

/// The names Linux really writes must survive that filter — a filter that
/// refused `kworker/R-rcu_g` would trade one failure for a worse one.
#[test]
fn the_process_names_linux_really_writes_are_accepted() {
    for name in [
        "systemd",
        "kworker/R-rcu_g",
        "pool_workqueue_",
        "irq/9-acpi",
        "systemd-journal",
        "[kthreadd]",
        "postgres.bin",
        "node",
        "kworker/u16:3",
    ] {
        assert_eq!(
            plausible_comm(&comm_field(name, 0xFF)).as_deref(),
            Some(name),
            "{name} is a comm Linux really writes"
        );
    }
}

/// systemd names the helper it forks for a user session `(sd-pam)` (and its
/// other pre-exec children `(sd-executor)`, `(sd-sync)`), writing the name
/// with `prctl(PR_SET_NAME)`. A scan that refused parentheses missed the
/// helper on a real capture (the MMUShell AArch64 Debian dump), and with it
/// the `systemd --user` whose `tasks.next` points at it: two live processes
/// reported as out of the scan's reach.
#[test]
fn systemds_parenthesised_helper_names_are_process_names() {
    for name in ["(sd-pam)", "(sd-executor)", "(sd-sync)"] {
        assert_eq!(
            plausible_comm(&comm_field(name, 0xFF)).as_deref(),
            Some(name),
            "{name} is a comm systemd really writes"
        );
    }
}

/// **PID 0 belongs to the idle task and to nothing else.**
///
/// After the maildir strings were excluded, the false positives that remained
/// on a real capture were almost all of this shape: a one- or two-character
/// name with `tid == 0`. The kernel gives pid 0 to `swapper/N` only.
#[test]
fn only_the_idle_task_may_carry_pid_zero() {
    let mut bytes = vec![0u8; 128];
    bytes[..TASK_COMM_LEN].copy_from_slice(&comm_field("swapper/0", 0));
    // tid and tgid both zero, at 64 and 68.
    assert!(
        candidate_from_bytes(&bytes, 0, 64, 68).is_some(),
        "swapper/0 really does carry pid 0 and must still be found"
    );

    for name in ["systemd", "bash", "kworker/u16:3"] {
        bytes[..TASK_COMM_LEN].copy_from_slice(&comm_field(name, 0));
        assert!(
            candidate_from_bytes(&bytes, 0, 64, 68).is_none(),
            "{name} with pid 0 is not a task — only the idle task carries it"
        );
    }
}

/// A single printable character followed by a NUL is one of the commonest
/// patterns in memory; a one-character program name essentially does not occur.
#[test]
fn a_one_character_name_is_not_a_process() {
    let mut bytes = vec![0u8; 128];
    bytes[64..68].copy_from_slice(&42i32.to_le_bytes());
    bytes[68..72].copy_from_slice(&42i32.to_le_bytes());

    for name in ["h", "N", "9", "G", "l"] {
        bytes[..TASK_COMM_LEN].copy_from_slice(&comm_field(name, 0));
        assert!(
            candidate_from_bytes(&bytes, 0, 64, 68).is_none(),
            "{name:?} was matched as a process name on a real capture"
        );
    }
    // Two characters is a real program name and must survive.
    for name in ["sh", "ps", "vi"] {
        bytes[..TASK_COMM_LEN].copy_from_slice(&comm_field(name, 0));
        assert!(
            candidate_from_bytes(&bytes, 0, 64, 68).is_some(),
            "{name} is a real program and must not be filtered out"
        );
    }
}

// ── link shape ─────────────────────────────────────────────────────────────

/// **The filter that makes the scan usable.**
///
/// `comm` plus a plausible identifier pair admits far too much: measured on a
/// real capture it produced 65,525 candidates and filled the scan's own cap
/// before reaching the memory where the real `task_struct`s live, so it found
/// none of them. Two canonical kernel pointers, sixteen bytes apart and both
/// aligned, is a far narrower thing.
#[test]
fn only_a_plausible_list_head_is_treated_as_one() {
    let mut bytes = vec![0u8; 64];

    // Two kernel pointers: worth following.
    with_links(&mut bytes, 16, 0xffff_8ea3_0039_8058, 0xffff_8ea3_0039_af58);
    assert!(matches!(
        classify_links(&bytes, 16),
        LinkShape::Kernel { .. }
    ));

    // The poison `list_del` writes: certainly a list_head, certainly removed.
    with_links(&mut bytes, 16, LIST_POISON1, LIST_POISON2);
    assert_eq!(classify_links(&bytes, 16), LinkShape::Poisoned);

    // Everything else is refused.
    for (next, prev) in [
        (0u64, 0u64),                                   // zeros — the commonest bytes there are
        (0x1000, 0x2000),                               // user-space addresses
        (0xffff_8ea3_0039_8058, 0x1000),                // one kernel, one not
        (0xffff_8ea3_0039_8051, 0xffff_8ea3_0039_af58), // unaligned
        (LIST_POISON1, 0),                              // half-poisoned
    ] {
        with_links(&mut bytes, 16, next, prev);
        assert_eq!(
            classify_links(&bytes, 16),
            LinkShape::NotLinks,
            "next={next:#x} prev={prev:#x} are not a task_struct's list links"
        );
    }

    // A buffer too short to hold the links is refused, not read past.
    assert_eq!(classify_links(&bytes[..20], 16), LinkShape::NotLinks);
    assert_eq!(classify_links(&[], 0), LinkShape::NotLinks);
}

/// Zeros are the single commonest thing in memory, and they must not pass.
#[test]
fn a_zeroed_buffer_is_never_a_list_head() {
    let bytes = vec![0u8; 4096];
    for offset in (0..4000).step_by(8) {
        assert_eq!(
            classify_links(&bytes, offset),
            LinkShape::NotLinks,
            "zeros at offset {offset} were treated as list links"
        );
    }
}

/// Random memory must essentially never produce a list-head shape.
#[test]
fn random_bytes_almost_never_look_like_list_links() {
    let mut lcg: u64 = 0x2545_F491_4F6C_DD1D;
    let mut accepted = 0usize;
    const TRIALS: usize = 20_000;
    for _ in 0..TRIALS {
        let bytes: Vec<u8> = (0..64)
            .map(|_| {
                lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (lcg >> 33) as u8
            })
            .collect();
        if classify_links(&bytes, 16) != LinkShape::NotLinks {
            accepted += 1;
        }
    }
    // Two aligned canonical kernel pointers is roughly a 1-in-2^38 event.
    assert_eq!(
        accepted, 0,
        "{accepted} of {TRIALS} random buffers looked like list links"
    );
}

fn scanned(address: u64, confidence: Confidence) -> ScannedTask {
    ScannedTask {
        address,
        comm: "hidden".to_string(),
        tid: 4242,
        pid: 4242,
        confidence,
    }
}

/// **The point of the whole module.** A structure the scan finds and the list
/// does not is what a hidden process looks like, and it must surface.
#[test]
fn a_structure_the_list_does_not_contain_is_reported_as_scan_only() {
    let list = list_with(&[0x1000, 0x2000]);
    let found = vec![
        scanned(0x1000, Confidence::LinksConsistent),
        scanned(0x2000, Confidence::LinksConsistent),
        scanned(0x9000, Confidence::Unlinked),
    ];

    let view = CrossView::build(&list, &found, true);
    assert_eq!(view.scan_only, 1);

    let hidden = view
        .rows
        .iter()
        .find(|r| r.address == 0x9000)
        .expect("the unlinked structure must appear in the cross-view");
    assert_eq!(hidden.verdict, CrossViewVerdict::ScanOnly);
    assert_eq!(hidden.comm.as_deref(), Some("hidden"));
}

/// The alarming reading must not be asserted as the only one.
#[test]
fn a_scan_only_row_states_the_innocent_explanation_too() {
    let meaning = CrossViewVerdict::ScanOnly.meaning();
    assert!(meaning.contains("UNLINKED"), "the finding must be named");
    assert!(
        meaning.contains("stale remnant"),
        "an exited process leaves a structure that looks the same, and a record that omitted \
         that would read as proof of a rootkit: {meaning}"
    );
    assert!(
        meaning.contains("not by itself proof"),
        "the record must refuse to draw the conclusion for the examiner"
    );
}

/// A process the list has and the scan missed is not a finding about the
/// process — the scan only covers what it was given.
#[test]
fn a_process_the_scan_did_not_reach_is_not_reported_as_suspicious() {
    let list = list_with(&[0x1000, 0x2000]);
    let view = CrossView::build(&list, &[scanned(0x1000, Confidence::LinksConsistent)], true);

    let missed = view.rows.iter().find(|r| r.address == 0x2000).unwrap();
    assert_eq!(missed.verdict, CrossViewVerdict::ListOnly);
    assert!(
        missed
            .verdict
            .meaning()
            .contains("not a finding about the process"),
        "a region the scan did not cover must not read as an anomaly"
    );
    assert_eq!(view.scan_only, 0);
}

/// **A cross-view over a scan that did not run is not a corroboration.**
///
/// This is the failure this whole module exists to prevent, appearing one level
/// up: an artifact that says "cross-checked" when nothing was checked is worse
/// than one that says nothing.
#[test]
fn a_cross_view_whose_scan_did_not_run_says_it_corroborates_nothing() {
    let list = list_with(&[0x1000]);
    let view = CrossView::build(&list, &[], false);
    let json = view.to_json();

    assert_eq!(json["scan_ran"], serde_json::json!(false));
    let note = json["corroboration_note"].as_str().unwrap();
    assert!(
        note.contains("NOT corroborated"),
        "a list with no scan behind it must say so plainly: {note}"
    );
    assert!(
        !view.rows.is_empty(),
        "the list's own processes are still reported; only the corroboration is absent"
    );
}

#[test]
fn both_methods_finding_a_process_is_the_ordinary_case() {
    let list = list_with(&[0x1000]);
    let view = CrossView::build(&list, &[scanned(0x1000, Confidence::LinksConsistent)], true);
    assert_eq!(view.rows.len(), 1);
    assert_eq!(view.rows[0].verdict, CrossViewVerdict::Both);
    assert_eq!(view.scan_only, 0);
    assert!(view.to_json()["corroboration_note"]
        .as_str()
        .unwrap()
        .contains("looked for a second time"));
}

/// The two grades are different findings, not a strong and a weak one, and
/// must not read alike.
#[test]
fn the_confidence_grades_say_different_things() {
    assert_ne!(
        Confidence::LinksConsistent.meaning(),
        Confidence::Unlinked.meaning()
    );
    assert!(Confidence::LinksConsistent
        .meaning()
        .contains("not satisfy that by chance"));
    let unlinked = Confidence::Unlinked.meaning();
    assert!(
        unlinked.contains("LIST_POISON"),
        "the grade must name the evidence it rests on: {unlinked}"
    );
    assert!(
        unlinked.contains("exited normally"),
        "an exited process leaves the same trace, and a grade that omitted that would \
         read as proof of a rootkit: {unlinked}"
    );
}

/// **The scan corroborates; it does not accuse.**
///
/// Measured against a known-good capture the signature confirmed 576 of 587
/// real processes — a genuine second opinion on the task list — but also
/// matched several thousand structures that are not tasks, page-cache text
/// sitting at the right offsets. Those two facts have different consequences,
/// and conflating them is what makes a scanner dangerous: reporting each
/// scan-only structure as a candidate hidden process would put thousands of
/// unfounded findings in a report and bury any real one.
///
/// So the count is reported and the structures are not, and the record says
/// plainly that hidden-process detection was NOT performed.
#[test]
fn scan_only_structures_are_counted_but_never_reported_as_findings() {
    let list = list_with(&[0x1000, 0x2000]);
    let found = vec![
        scanned(0x1000, Confidence::LinksConsistent),
        scanned(0x2000, Confidence::LinksConsistent),
        // Noise, of the kind a real sweep produces in quantity.
        scanned(0x9000, Confidence::LinksConsistent),
        scanned(0xA000, Confidence::LinksConsistent),
    ];
    let view = CrossView::build(&list, &found, true);
    let json = view.to_json();

    assert_eq!(
        view.corroborated(),
        2,
        "both listed processes were confirmed"
    );
    assert_eq!(json["corroborated_by_scan"], serde_json::json!(2));
    assert_eq!(json["processes_from_list"], serde_json::json!(2));

    // The noise is counted...
    assert_eq!(json["scan_only_count"], serde_json::json!(2));
    // ...and not one of those structures appears as a row.
    let rows = json["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "only the list's own processes may be rows");
    for row in rows {
        assert_ne!(
            row["verdict"],
            serde_json::json!("scan_only"),
            "a scan-only structure was reported as a finding: {row}"
        );
    }

    // And the record must say the detection did not happen, so an examiner
    // never reads a corroborated list as a swept-for-rootkits one.
    let statement = json["hidden_process_detection"].as_str().expect("stated");
    assert!(
        statement.contains("NOT PERFORMED"),
        "the record must say hidden-process detection did not happen: {statement}"
    );
    assert!(
        statement.contains("NOT be surfaced here"),
        "it must say what that costs — an unlinked process does not appear: {statement}"
    );
}

/// A synthetic two-structure image, laid out the way Linux lays out the tail of
/// its task list: the last process is slab-allocated in the direct map, and its
/// `tasks.next` points at `init_task`, a static in the kernel image mapping.
/// Offsets: `comm` 0, `pid` 24, `tgid` 28, `tasks` 40, size 64.
///
/// Synthetic by design: it pins the address arithmetic. The real-data evidence
/// is `tests/arm64_debian_profile_real_test.rs`, where `bash` (the last task on
/// the MMUShell AArch64 Debian dump's list) read as out of the scan's reach.
fn tail_of_the_list() -> (
    Arc<dyn seance_memory::layer::MemoryLayer>,
    ScanOffsets,
    u64,
    u64,
) {
    use seance_core::data_source::ByteSliceDataSource;
    const DIRECT: u64 = 0xffff_8880_0000_0000;
    const IMAGE: u64 = 0xffff_ffff_8100_0000;
    const LAST: u64 = 0x1000;
    const INIT: u64 = 0x8000;
    const LINKS: u64 = 40;
    let mut bytes = vec![0u8; 0x10000];
    let mut task = |at: u64, name: &str, pid: i32, next: u64, prev: u64| {
        let at = at as usize;
        bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
        bytes[at + 24..at + 28].copy_from_slice(&pid.to_le_bytes());
        bytes[at + 28..at + 32].copy_from_slice(&pid.to_le_bytes());
        bytes[at + 40..at + 48].copy_from_slice(&next.to_le_bytes());
        bytes[at + 48..at + 56].copy_from_slice(&prev.to_le_bytes());
    };
    let last_links = DIRECT + LAST + LINKS;
    let init_links = IMAGE + INIT + LINKS;
    task(LAST, "bash", 378, init_links, init_links);
    task(INIT, "swapper/0", 0, last_links, last_links);
    let layer = Arc::new(
        seance_memory::PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
            .expect("a non-empty image"),
    );
    let offsets = ScanOffsets {
        comm: 0,
        pid: 24,
        tgid: 28,
        tasks: LINKS as usize,
        size: 64,
    };
    (layer, offsets, DIRECT, IMAGE)
}

#[test]
fn the_last_task_links_to_init_task_in_the_image_mapping_and_is_still_found() {
    let (layer, offsets, direct, image) = tail_of_the_list();
    let found = |image_shift| {
        scan_physical(
            &*layer,
            offsets,
            direct,
            &ScanConfig {
                image_shift,
                ..ScanConfig::default()
            },
        )
        .tasks
        .into_iter()
        .filter(|t| t.comm == "bash")
        .map(|t| (t.address, t.confidence))
        .collect::<Vec<_>>()
    };
    // Without the image mapping the neighbour cannot be reached, and nothing
    // is claimed about the task: it is simply not corroborated.
    assert!(found(None).is_empty());
    assert_eq!(
        found(Some(image)),
        vec![(direct + 0x1000, Confidence::LinksConsistent)]
    );
}
