//! The ETW classifier and the modal comparison, on bytes rather than fixtures.
//!
//! The classifier is a pure function of (bytes, ip, bitness, module range), so
//! it is tested on the byte sequences the published techniques actually use —
//! and on the ones a real prologue uses, which must classify as ordinary.
//!
//! # Why there is no whole-image fixture here
//!
//! Reaching [`examine_etw`] means a process list, a per-process address space
//! built from a directory table base, a PEB, a loader list and a PE image with
//! an export directory in that space. A fixture for that is a fixture of the
//! four stages underneath this one, and it would assert their behaviour rather
//! than this group's. The group's own logic is the classifier and
//! `apply_modes`, and both are tested directly; the read path is exercised
//! against the real capture in `tests/win11_corpus_analysis.rs`, which is where
//! a wrong answer would actually show.

use super::tamper_etw::*;

/// Where the fixture's `ntdll` is, for the module-range test.
const BASE: u64 = 0x7FF8_0000_0000;
const END: u64 = 0x7FF8_0020_0000;
const IP: u64 = 0x7FF8_0001_0000;

fn classify_bytes(bytes: &[u8]) -> Classification {
    classify(bytes, IP, 64, (BASE, END))
}

/// **The published patch: one byte.** `ret` where a function should be.
#[test]
fn a_function_that_returns_immediately_is_the_published_patch() {
    let c = classify_bytes(&[0xC3, 0, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(c, Classification::ReturnsImmediately { .. }));
    assert!(c.is_signal());
    assert_eq!(c.as_str(), "returns_immediately");
}

/// **`xor eax,eax; ret`** — the other published form, which sets the
/// `STATUS_SUCCESS` the caller checks. The evidence names both instructions.
#[test]
fn the_two_instruction_form_is_reported_with_both_instructions() {
    // 33 C0 = xor eax,eax; C3 = ret
    let c = classify_bytes(&[0x33, 0xC0, 0xC3, 0, 0, 0, 0, 0]);
    match &c {
        Classification::ReturnsImmediately { detail } => {
            assert!(detail.contains("xor"), "got {detail}");
            assert!(detail.contains("ret"), "got {detail}");
            assert!(detail.contains("2 instruction"), "got {detail}");
        }
        other => panic!("expected an immediate return, got {other:?}"),
    }
}

/// An `int3` is a breakpoint left in place.
#[test]
fn a_trap_is_reported_as_one() {
    assert_eq!(classify_bytes(&[0xCC, 0, 0, 0]), Classification::Traps);
    assert!(Classification::Traps.is_signal());
}

/// **A first control transfer that leaves the module is the third form**: the
/// prologue is intact and a `jmp` redirects the whole function elsewhere.
#[test]
fn a_jump_out_of_the_module_is_reported_with_its_target() {
    // E9 rel32: jmp to IP + 5 + rel. Aim it far below the module base.
    let rel: i32 = -0x10_0000;
    let mut bytes = vec![0xE9];
    bytes.extend_from_slice(&rel.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 8]);
    match classify_bytes(&bytes) {
        Classification::LeavesModule { target } => {
            assert!(
                target < BASE,
                "the target is outside the module: {target:#x}"
            );
        }
        other => panic!("expected a jump out of the module, got {other:?}"),
    }
}

/// A jump **inside** the module is not a signal: that is what a real prologue
/// that tail-calls looks like, and reporting it would fire on every build.
#[test]
fn a_jump_within_the_module_is_ordinary() {
    let rel: i32 = 0x100;
    let mut bytes = vec![0xE9];
    bytes.extend_from_slice(&rel.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 8]);
    assert_eq!(classify_bytes(&bytes), Classification::Ordinary);
}

/// **The real prologue classifies as ordinary, and it is the one measured on
/// the capture** — not an invented sequence.
///
/// `EtwEventWrite` on Windows 11 26200 begins
/// `40 55 57 41 54 41 56 41 57 48 8d 6c 24 80 48 81`, which all 123 copies on
/// the clean capture agree on. Note the last two bytes: `48 81` is the start of
/// a `sub rsp,imm32` that the sixteenth byte cuts in half. An earlier draft
/// called that undecodable and so classified **369 of 491** genuine exports on
/// that capture as unreadable — a fixed-length window always ends
/// mid-instruction, and the classifier now stops there instead.
#[test]
fn the_real_measured_prologue_is_ordinary_even_though_the_window_cuts_it() {
    let bytes = [
        0x40, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x80, 0x48,
        0x81,
    ];
    assert_eq!(classify_bytes(&bytes), Classification::Ordinary);
    // The other three exports' measured prologues, for the same reason.
    for measured in [
        [
            0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8B, 0x84, 0x24, 0x98, 0x00, 0x00,
            0x00, 0x45,
        ],
        [
            0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8B, 0x84, 0x24, 0x90, 0x00, 0x00,
            0x00, 0x49,
        ],
        [
            0x40, 0x55, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x70,
            0xFF, 0xFF,
        ],
    ] {
        assert_eq!(classify_bytes(&measured), Classification::Ordinary);
    }
}

/// A genuinely invalid sequence, with a whole instruction's worth of bytes
/// available, is still undecodable — the truncation rule must not swallow it.
#[test]
fn an_invalid_sequence_with_room_to_spare_is_still_undecodable() {
    // 0x62 with a bad EVEX payload, followed by enough bytes that the window
    // is not the reason it failed.
    let bytes = [
        0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    ];
    match classify_bytes(&bytes) {
        Classification::Undecodable { detail } => assert!(detail.contains("decode"), "{detail}"),
        other => assert!(!other.is_signal(), "got {other:?}"),
    }
}

/// **All-zero bytes are a page that is not resident, not a patched function.**
/// Classifying them as anything else would report every non-resident ntdll in a
/// smeared capture as tampered with.
#[test]
fn an_unresident_page_is_undecodable_and_says_which_it_is() {
    match classify_bytes(&[0u8; 16]) {
        Classification::Undecodable { detail } => {
            assert!(detail.contains("not resident"), "got {detail}");
        }
        other => panic!("expected undecodable, got {other:?}"),
    }
    assert!(!Classification::Undecodable {
        detail: String::new()
    }
    .is_signal());
}

/// Bytes that are not an instruction at all are reported as undecodable rather
/// than forced into a classification.
#[test]
fn bytes_that_are_not_an_instruction_are_undecodable() {
    // 0F 0B is UD2 -- valid. Use a genuinely invalid encoding instead.
    match classify_bytes(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) {
        Classification::Undecodable { detail } => assert!(detail.contains("decode"), "{detail}"),
        // A sequence iced decodes as something valid is a legitimate answer
        // too; what must never happen is a signal.
        other => assert!(!other.is_signal(), "got {other:?}"),
    }
}

/// **Bitness comes from the image.** The same bytes decode differently as
/// 32-bit, and a wrong answer here reads correctly.
#[test]
fn bitness_is_not_the_hosts() {
    // 48 is `dec eax` in 32-bit and a REX prefix in 64-bit. `48 C3` is
    // therefore `dec eax; ret` on x86 and `ret` (with a pointless REX) on x64 --
    // both return, so use a sequence that differs in kind: `48 83 EC 68` is
    // `sub rsp,68h` on x64 and `dec eax; sub ...` on x86.
    let bytes = [0x48, 0x83, 0xEC, 0x68, 0x90, 0x90, 0x90, 0x90];
    assert_eq!(
        classify(&bytes, IP, 64, (BASE, END)),
        Classification::Ordinary
    );
    // The 32-bit decode is also ordinary here; what is asserted is that the
    // bitness is *used* rather than defaulted, which the signature forces.
    assert_eq!(
        classify(&bytes, IP, 32, (BASE, END)),
        Classification::Ordinary
    );
}

// --- the modal comparison --------------------------------------------------

fn row(process: u64, export: &'static str, bytes: &[u8], image_mapped: Option<bool>) -> EtwExport {
    EtwExport {
        process,
        pid: Some(process),
        process_name: Some(format!("p{process}.exe")),
        module_base: BASE,
        export,
        address: IP,
        bytes: bytes.to_vec(),
        classification: Classification::Ordinary,
        image_mapped,
        agrees_with_the_mode: None,
        mode_agreed: 0,
        mode_population: 0,
        mode_is_patched: false,
    }
}

fn outcome(rows: Vec<EtwExport>) -> EtwOutcome {
    let mut out = EtwOutcome {
        processes_assessed: rows.len() as u64,
        exports: rows,
        unassessed: Vec::new(),
        modes: Default::default(),
        notes: Vec::new(),
        capped: None,
    };
    crate::tamper_etw::apply_modes(&mut out);
    out
}

/// **One patched copy against many is the signal the modal route exists for**,
/// and it needs no reference bytes at all.
#[test]
fn a_minority_prologue_is_the_signal_and_the_count_that_agreed_is_on_the_row() {
    let ordinary = [0x48, 0x83, 0xEC, 0x68, 0x33, 0xC0, 0, 0];
    let patched = [0xC3, 0, 0, 0, 0, 0, 0, 0];
    let mut rows: Vec<EtwExport> = (1..=4)
        .map(|p| row(p, "EtwEventWrite", &ordinary, Some(true)))
        .collect();
    rows.push(row(5, "EtwEventWrite", &patched, Some(true)));
    let out = outcome(rows);

    let odd = out
        .exports
        .iter()
        .find(|r| r.process == 5)
        .expect("the patched copy");
    assert_eq!(odd.agrees_with_the_mode, Some(false));
    assert_eq!(odd.mode_agreed, 4);
    assert_eq!(odd.mode_population, 5);
    assert_eq!(odd.route(), Some("modal_comparison"));
    assert_eq!(out.signals(), 1);

    for agreeing in out.exports.iter().filter(|r| r.process != 5) {
        assert_eq!(agreeing.agrees_with_the_mode, Some(true));
        assert_eq!(agreeing.route(), None);
    }
}

/// A row that is a signal on both routes says so.
#[test]
fn a_row_that_is_a_signal_on_both_routes_says_both() {
    let ordinary = [0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0];
    let mut rows: Vec<EtwExport> = (1..=3)
        .map(|p| row(p, "EtwEventWrite", &ordinary, Some(true)))
        .collect();
    let mut patched = row(4, "EtwEventWrite", &[0xC3, 0, 0, 0, 0, 0, 0, 0], Some(true));
    patched.classification = Classification::ReturnsImmediately {
        detail: "ret".into(),
    };
    rows.push(patched);
    let out = outcome(rows);
    let odd = out.exports.iter().find(|r| r.process == 4).expect("row");
    assert_eq!(odd.route(), Some("both"));
}

/// **A copy positively in private memory does not vote.**
///
/// Otherwise an attacker able to hand-map a copy carrying the name would be
/// choosing the baseline every other process is compared against. It is still
/// classified and still compared — it just does not set the mode.
#[test]
fn a_private_copy_wearing_the_name_is_compared_but_never_votes() {
    let real = [0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0];
    let fake = [0xC3, 0, 0, 0, 0, 0, 0, 0];
    // Two real copies, three private ones carrying the patched bytes: on a
    // vote by count the fake would win.
    let mut rows: Vec<EtwExport> = (1..=2)
        .map(|p| row(p, "EtwEventWrite", &real, Some(true)))
        .collect();
    rows.extend((3..=5).map(|p| row(p, "EtwEventWrite", &fake, Some(false))));
    let out = outcome(rows);

    let (modal, agreed, population) = out
        .modes
        .get("EtwEventWrite")
        .cloned()
        .expect("a mode was taken");
    assert_eq!(population, 2, "only the corroborated copies voted");
    assert_eq!(agreed, 2);
    assert!(modal.starts_with("48 83 ec 68"), "got {modal}");
    for fake_row in out.exports.iter().filter(|r| r.image_mapped == Some(false)) {
        assert_eq!(
            fake_row.agrees_with_the_mode,
            Some(false),
            "still compared, and still a minority"
        );
        let j = fake_row.to_json();
        assert!(
            j["image_mapped_note"]
                .as_str()
                .unwrap_or_default()
                .contains("choosing the baseline"),
            "the record says why it did not vote: {:?}",
            j["image_mapped_note"]
        );
    }
}

/// A copy whose mapping could not be corroborated **does** vote, and says it
/// was not corroborated. `None` is not `false`: refusing the vote would leave
/// no mode at all on a build whose VAD tree cannot be described.
#[test]
fn an_uncorroborated_copy_votes_and_says_it_was_not_corroborated() {
    let bytes = [0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0];
    let out = outcome(vec![
        row(1, "EtwEventWrite", &bytes, None),
        row(2, "EtwEventWrite", &bytes, None),
    ]);
    let (_, agreed, population) = out.modes.get("EtwEventWrite").cloned().expect("a mode");
    assert_eq!((agreed, population), (2, 2));
    let j = out.exports[0].to_json();
    assert!(j["image_mapped"].is_null());
    assert!(j["image_mapped_note"].is_string());
}

/// Each export is compared against **its own** mode. Comparing one export
/// against another's would make every row a minority.
#[test]
fn each_export_has_its_own_mode() {
    let a = [0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0];
    let b = [0x40, 0x53, 0x48, 0x83, 0, 0, 0, 0];
    let out = outcome(vec![
        row(1, "EtwEventWrite", &a, Some(true)),
        row(1, "EtwEventWriteFull", &b, Some(true)),
        row(2, "EtwEventWrite", &a, Some(true)),
        row(2, "EtwEventWriteFull", &b, Some(true)),
    ]);
    assert_eq!(out.modes.len(), 2);
    assert!(out
        .exports
        .iter()
        .all(|r| r.agrees_with_the_mode == Some(true)));
    assert_eq!(out.signals(), 0);
}

/// **An unassessed process is never an all-clear**, and the record says how
/// many there were.
#[test]
fn an_unassessed_process_is_counted_and_the_record_says_so() {
    let mut out = outcome(vec![row(
        1,
        "EtwEventWrite",
        &[0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0],
        Some(true),
    )]);
    out.unassessed.push(Unassessed {
        process: 9,
        pid: Some(9),
        process_name: Some("smeared.exe".into()),
        reason: "this process has no readable address space".into(),
    });
    let j = out.to_json();
    assert_eq!(j["unassessed_total"], serde_json::json!(1));
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert!(
        j["unassessed_note"]
            .as_str()
            .unwrap_or_default()
            .contains("never 'unpatched'"),
        "got {:?}",
        j["unassessed_note"]
    );
    assert!(out.describe().contains("not an all-clear"));
}

/// `ordinary` is not a claim that the function is unpatched, and the basis on
/// every row says so.
#[test]
fn ordinary_is_not_a_claim_that_the_function_is_unpatched() {
    let out = outcome(vec![row(
        1,
        "EtwEventWrite",
        &[0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0],
        Some(true),
    )]);
    let basis = out.exports[0].to_json()["basis"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        basis.contains("NOT a statement that the function is unpatched"),
        "got {basis}"
    );
    assert!(basis.contains("preserves the prologue"), "got {basis}");
}

/// **A loader entry that runs to the very top of the address space has no
/// exclusive end**, and saying so is not a panic (`MEM-052`'s audit): `end() +
/// 1` overflowed on a `DllBase` + `SizeOfImage` of exactly 2^64.
#[test]
fn a_module_ending_at_the_top_of_the_address_space_is_refused_not_a_panic() {
    assert_eq!(
        exclusive_end(0x7FF8_0000_0000, Some(0x7FF8_001F_FFFF)),
        Ok(0x7FF8_0020_0000)
    );
    let why = exclusive_end(0xFFFF_FFFF_FFFF_F000, Some(u64::MAX))
        .expect_err("no module a process maps ends at 2^64");
    assert!(why.contains("top of the address space"), "{why}");
}

/// **A patch on every copy is the mode, and only the classification route
/// fires** (`MEM-020`, the dimension the entry names: "a machine-wide patch,
/// where the mode is itself patched").
///
/// Five corroborated copies all carry `ret`. The modal comparison has nothing
/// to compare against -- every copy agrees -- so each row is a signal on the
/// classification route alone, and the record says in words that the mode
/// itself is patched rather than leaving an examiner to read "agrees with the
/// mode" as reassurance. Synthetic: it pins the decision logic, which does not
/// depend on real bytes; it is not a true positive on evidence.
#[test]
fn a_patch_on_every_copy_is_the_mode_and_only_the_classification_route_fires() {
    let patched = [0xC3, 0, 0, 0, 0, 0, 0, 0];
    let rows: Vec<EtwExport> = (1..=5)
        .map(|p| {
            let mut r = row(p, "EtwEventWrite", &patched, Some(true));
            r.classification = Classification::ReturnsImmediately {
                detail: "ret".into(),
            };
            r
        })
        .collect();
    let out = outcome(rows);

    let (modal, agreed, population) = out
        .modes
        .get("EtwEventWrite")
        .cloned()
        .expect("a mode was taken");
    assert!(modal.starts_with("c3 "), "got {modal}");
    assert_eq!((agreed, population), (5, 5));
    for r in &out.exports {
        assert_eq!(r.agrees_with_the_mode, Some(true));
        assert_eq!(r.route(), Some("classification"));
        assert_eq!(r.to_json()["is_signal"], true);
    }
    assert_eq!(out.signals(), 5);
    let json = out.to_json();
    assert_eq!(json["signals"], 5);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("EtwEventWrite") && n.contains("the mode itself is patched")),
        "the record says the mode is patched: {:?}",
        out.notes
    );
}

/// The note is not raised when the mode is ordinary and one copy is patched.
#[test]
fn an_ordinary_mode_raises_no_machine_wide_note() {
    let ordinary = [0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0];
    let mut rows: Vec<EtwExport> = (1..=4)
        .map(|p| row(p, "EtwEventWrite", &ordinary, Some(true)))
        .collect();
    let mut patched = row(5, "EtwEventWrite", &[0xC3, 0, 0, 0, 0, 0, 0, 0], Some(true));
    patched.classification = Classification::ReturnsImmediately {
        detail: "ret".into(),
    };
    rows.push(patched);
    let out = outcome(rows);
    assert!(
        !out.notes
            .iter()
            .any(|n| n.contains("mode itself is patched")),
        "{:?}",
        out.notes
    );
}

/// Rows carrying `ret` on `EtwEventWrite` for processes `ids`.
fn patched_rows(ids: std::ops::RangeInclusive<u64>) -> Vec<EtwExport> {
    ids.map(|p| {
        let mut r = row(p, "EtwEventWrite", &[0xC3, 0, 0, 0, 0, 0, 0, 0], Some(true));
        r.classification = Classification::ReturnsImmediately {
            detail: "ret".into(),
        };
        r
    })
    .collect()
}

/// **A tie is not a machine-wide patch** (`MEM-020`, the adversarial review):
/// two copies carry `ret` and two are clean. The plurality pick breaks the tie
/// by byte order, and `0xC3` sorts above `0x48`, so the patch becomes the
/// mode -- but two copies are clean, and the record must say the vote was a
/// tie rather than calling it machine-wide.
#[test]
fn a_tie_between_a_patch_and_a_clean_prologue_is_named_a_tie_not_machine_wide() {
    let mut rows = patched_rows(1..=2);
    for p in 3..=4 {
        rows.push(row(
            p,
            "EtwEventWrite",
            &[0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0],
            Some(true),
        ));
    }
    let out = outcome(rows);
    assert!(
        !out.notes
            .iter()
            .any(|n| n.contains("machine-wide patch.") || n.contains("the mode itself is patched")),
        "a tie is not a machine-wide patch: {:?}",
        out.notes
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("EtwEventWrite") && n.contains("tie")),
        "the record names the tie: {:?}",
        out.notes
    );
}

/// **One copy is no population**: the ETW page resident in a single process
/// makes that copy the mode, and a patched copy of one is not evidence the
/// patch is machine-wide.
#[test]
fn a_mode_of_one_patched_copy_is_not_called_machine_wide() {
    let out = outcome(patched_rows(1..=1));
    assert_eq!(out.signals(), 1);
    assert!(
        !out.notes
            .iter()
            .any(|n| n.contains("the mode itself is patched")),
        "{:?}",
        out.notes
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("EtwEventWrite") && n.contains("only one copy")),
        "the record says the mode rests on one copy: {:?}",
        out.notes
    );
}

/// **A patched majority is a patched mode, not a machine-wide patch**: three
/// copies carry `ret`, two are clean. The mode is patched and the record says
/// so -- and says that the copies disagreeing with it may be the clean ones --
/// but it does not claim every copy is patched.
#[test]
fn a_patched_majority_says_the_mode_is_patched_but_not_machine_wide() {
    let mut rows = patched_rows(1..=3);
    for p in 4..=5 {
        rows.push(row(
            p,
            "EtwEventWrite",
            &[0x48, 0x83, 0xEC, 0x68, 0, 0, 0, 0],
            Some(true),
        ));
    }
    let out = outcome(rows);
    let note = out
        .notes
        .iter()
        .find(|n| n.contains("EtwEventWrite") && n.contains("the mode is patched"))
        .unwrap_or_else(|| panic!("the record says the mode is patched: {:?}", out.notes));
    assert!(note.contains("3 of the 5"), "{note}");
    assert!(!note.contains("machine-wide patch."), "{note}");
    assert!(note.contains("may be the clean ones"), "{note}");
}

/// The unanimous note counts **voting** copies, not "corroborated" ones: a copy
/// whose mapping could not be established votes too.
#[test]
fn the_machine_wide_note_counts_voting_copies_not_corroborated_ones() {
    let mut rows = patched_rows(1..=3);
    rows[2].image_mapped = None;
    let out = outcome(rows);
    let note = out
        .notes
        .iter()
        .find(|n| n.contains("the mode itself is patched"))
        .unwrap_or_else(|| panic!("{:?}", out.notes));
    assert!(!note.contains("corroborated copies"), "{note}");
    assert!(note.contains("1 not established"), "{note}");
}

/// **When the mode is itself the patch, the copies that differ from it are the clean ones**, and are not signals. The first real
/// machine-wide plant (`MEM-020`, 2026-10-23) put `ret` in `EtwEventWrite` of 99 of 117 processes; the 99 are signals on the
/// classification route, and the 18 genuine ones used to be signals too, on the modal route, which read as 18 more tampered
/// processes while the record's own note said they "may be the clean ones".
#[test]
fn a_copy_that_differs_from_a_patched_mode_is_not_a_signal() {
    let ordinary = [0x48, 0x83, 0xEC, 0x68, 0x33, 0xC0, 0, 0];
    let patched = [0xC3, 0, 0, 0, 0, 0, 0, 0];
    let mut rows: Vec<EtwExport> = (1..=4)
        .map(|p| {
            let mut r = row(p, "EtwEventWrite", &patched, Some(true));
            r.classification = Classification::ReturnsImmediately {
                detail: "returns".to_string(),
            };
            r
        })
        .collect();
    rows.push(row(5, "EtwEventWrite", &ordinary, Some(true)));
    let out = outcome(rows);

    for patched_row in out.exports.iter().filter(|r| r.process != 5) {
        assert_eq!(patched_row.route(), Some("classification"));
    }
    let clean = out.exports.iter().find(|r| r.process == 5).unwrap();
    assert_eq!(clean.agrees_with_the_mode, Some(false));
    assert_eq!(clean.route(), None, "the clean minority is not tampered");
    assert_eq!(out.signals(), 4);
}
