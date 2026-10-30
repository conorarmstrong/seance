//! UserAssist — what the decoder has to do, stated before it did any of it.
//!
//! # What this artifact is
//!
//! Explorer counts how often a user launches each program, and how long it held
//! focus. It is the closest thing Windows keeps to "this person ran this, this
//! many times, and last at this moment", and it survives the program's
//! deletion.
//!
//! # Where every fixture below comes from
//!
//! Real hives on this machine, decoded byte by byte while planning this work —
//! `LoneWolf`'s `jcloudy` `NTUSER.DAT` (Windows 10) and the plaso corpus
//! `NTUSER.DAT` (Windows XP). The two ground-truth entries are quoted verbatim
//! in the tests that use them.
//!
//! That is not decoration. `HUNT-122` raised 788 false leads from fixtures
//! carrying a value shape no enumerator produces, and `HUNT-123` raised 232
//! false tampering findings because its fixture put a structure where a signing
//! tool always puts it, so the wrong branch never ran. A UserAssist fixture
//! invented from the published layout would agree with the code about both.
//!
//! # The trap this decoder is written around
//!
//! In `LoneWolf`'s `{CEBFF5CD-…}\Count` the key declares `Version = 5` and 55
//! of its 56 values are 72 bytes — and `UEME_CTLSESSION` is **1,612 bytes**. A
//! decoder that dispatched on `Version` and read the FILETIME at `0x3C` would
//! publish a timestamp lifted from the middle of a session blob: a fabricated
//! execution time, in the one entry no examiner would think to check. So the
//! dispatch is on the **data length**, and `Version` is cross-checked against
//! it rather than believed.

use super::userassist::*;

/// The Windows 10 ground truth, verbatim from `LoneWolf` `jcloudy`
/// `NTUSER.DAT`, `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`, value
/// `Microsoft.Getstarted_8wekyb3d8bbwe!App`:
///
/// ```text
/// 000000000e00000015000000a0680600
/// 000080bf × 10
/// ffffffff 3a671889acc5d301 00000000
/// ```
///
/// session 0, 14 runs, 21 focus events, 420,000 ms focused, last executed
/// 2018-03-27T09:18:14.900101Z.
fn win10_entry() -> Vec<u8> {
    let mut v = Vec::with_capacity(0x48);
    v.extend_from_slice(&0u32.to_le_bytes()); // session id
    v.extend_from_slice(&14u32.to_le_bytes()); // run count
    v.extend_from_slice(&21u32.to_le_bytes()); // focus count
    v.extend_from_slice(&420_000u32.to_le_bytes()); // focus time, ms
    for _ in 0..10 {
        v.extend_from_slice(&0xBF80_0000u32.to_le_bytes()); // -1.0f32, every one
    }
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    v.extend_from_slice(&0x01D3_C5AC_8918_673Au64.to_le_bytes()); // FILETIME
    v.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(v.len(), 0x48, "the Win7+ form is 72 bytes");
    v
}

/// The Windows XP ground truth, verbatim from the plaso corpus `NTUSER.DAT`,
/// value `UEME_RUNPIDL:%csidl2%\MSN.lnk`: `0100000013000000544bf6d31515ca01`
/// — session 1, run_count 19, a 2004 FILETIME.
fn xp_entry() -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&19u32.to_le_bytes());
    v.extend_from_slice(&0x01CA_1515_D3F6_4B54u64.to_le_bytes());
    assert_eq!(v.len(), 16);
    v
}

/// ROT13, as Explorer stores every value name.
fn rot13(s: &str) -> Vec<u8> {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            other => other,
        })
        .collect()
}

// --- The 72-byte form ------------------------------------------------------

/// The Windows 10 entry decodes to its known answer, field for field.
#[test]
fn a_win10_userassist_entry_decodes_its_counts_focus_time_and_last_execution() {
    let name = rot13("Microsoft.Getstarted_8wekyb3d8bbwe!App");
    let e = decode_entry(&name, &win10_entry(), Some(5));

    assert_eq!(e.decode_status, DecodeStatus::Decoded);
    assert_eq!(e.entry_length, 0x48);
    assert_eq!(e.session_id, Some(0));
    assert_eq!(e.run_count, Some(14));
    assert_eq!(e.focus_count, Some(21));
    assert_eq!(e.focus_time_ms, Some(420_000));
    // The full 100-nanosecond FILETIME resolution, through the shared
    // converter. `0x01D3C5AC8918673A` is 2018-03-27T09:18:14.9001018Z exactly,
    // and the trailing 800 ns is in the evidence -- truncating it to
    // microseconds would be this tool rounding the hive.
    assert_eq!(
        e.last_executed.as_deref(),
        Some("2018-03-27T09:18:14.900101800+00:00"),
        "the FILETIME at 0x3C, at the resolution the hive stores it"
    );
    assert!(e.is_execution, "this is a program launch");
    assert_eq!(e.name_decoded, "Microsoft.Getstarted_8wekyb3d8bbwe!App");
    assert_eq!(
        e.value_name_raw,
        String::from_utf8_lossy(&name),
        "the stored name is always kept, whatever the decode did"
    );
}

/// A UWP application identity is not a file path and must never be presented
/// as one.
///
/// `Microsoft.Getstarted_8wekyb3d8bbwe!App` is a package family name, a
/// publisher hash and an app id. Correlating it against the filesystem would
/// find nothing and the absence would read as a deleted program.
#[test]
fn an_app_identity_is_not_reported_as_a_file_path() {
    let e = decode_entry(
        &rot13("Microsoft.Getstarted_8wekyb3d8bbwe!App"),
        &win10_entry(),
        Some(5),
    );
    assert_eq!(e.target_kind, TargetKind::AppIdentity);
    assert!(
        e.known_folder.is_none(),
        "an app identity has no known folder"
    );
}

/// The ten floats and the two spare dwords are kept as bytes and **not named**.
///
/// Microsoft documents none of this layout. The field names this decoder does
/// use come from published DFIR research, and the record says so once. Naming
/// the rest would dress a guess as a reading.
#[test]
fn the_undocumented_fields_are_kept_as_bytes_and_not_named() {
    let e = decode_entry(&rot13("Foo.exe"), &win10_entry(), Some(5));
    let hex = e.unknown_bytes_hex.as_deref().unwrap_or("");
    assert!(
        hex.contains("000080bf"),
        "the ten -1.0 floats must survive as bytes: {hex:?}"
    );
    assert!(hex.contains("ffffffff"), "got {hex:?}");
    assert_eq!(
        e.layout_source,
        "published format research, not vendor documentation"
    );
}

// --- The 16-byte XP form ---------------------------------------------------

/// The XP entry decodes through the 16-byte layout, and its counter is
/// reported as **stored**.
///
/// The XP-era counter is documented as starting at 5. Subtracting it silently
/// would have a report say 14 runs where the hive says 19 — asserting a
/// convention as a fact. So the stored number is published with the convention
/// stated beside it.
#[test]
fn an_xp_entry_decodes_through_the_sixteen_byte_layout_and_reports_the_stored_counter() {
    let name = rot13(r"UEME_RUNPIDL:%csidl2%\MSN.lnk");
    let e = decode_entry(&name, &xp_entry(), Some(3));

    assert_eq!(e.decode_status, DecodeStatus::Decoded);
    assert_eq!(e.entry_length, 16);
    assert_eq!(e.session_id, Some(1));
    assert_eq!(e.run_count, Some(19), "the stored value, not 19 - 5");
    assert!(
        e.run_count_note
            .as_deref()
            .unwrap_or("")
            .contains("starting at 5"),
        "the convention must be stated rather than applied"
    );
    assert!(
        e.focus_count.is_none() && e.focus_time_ms.is_none(),
        "the XP layout holds neither, and a zero would be a fabrication"
    );
    assert!(e.last_executed.is_some());
    assert_eq!(e.entry_kind, EntryKind::ShellLink);
    assert_eq!(
        e.target.as_deref(),
        Some(r"%csidl2%\MSN.lnk"),
        "the UEME_RUNPIDL: prefix is stripped into the target"
    );
}

/// The three XP prefixes each name what kind of thing ran.
#[test]
fn the_xp_prefixes_are_classified_and_stripped() {
    for (raw, kind, target) in [
        (
            r"UEME_RUNPATH:C:\WINDOWS\notepad.exe",
            EntryKind::ExecutablePath,
            r"C:\WINDOWS\notepad.exe",
        ),
        (
            r"UEME_RUNPIDL:%csidl2%\MSN.lnk",
            EntryKind::ShellLink,
            r"%csidl2%\MSN.lnk",
        ),
        (
            "UEME_RUNCPL:timedate.cpl",
            EntryKind::ControlPanel,
            "timedate.cpl",
        ),
    ] {
        let e = decode_entry(&rot13(raw), &xp_entry(), Some(3));
        assert_eq!(e.entry_kind, kind, "for {raw}");
        assert_eq!(e.target.as_deref(), Some(target), "for {raw}");
        assert!(e.is_execution, "for {raw}");
    }
}

// --- What must never be reported as a program run --------------------------

/// Explorer's own bookkeeping entries are not program executions.
///
/// Every non-empty `Count` key in `LoneWolf` holds two of these. Emitting them
/// as programs would put `UEME_CTLSESSION` at the top of an execution list on
/// every Windows machine ever examined — which is `HUNT-122` exactly: a rule
/// that fires on the ordinary state of the system.
#[test]
fn explorer_bookkeeping_is_not_reported_as_a_program_execution() {
    for raw in ["UEME_CTLSESSION", "UEME_CTLCUACount:ctor"] {
        let e = decode_entry(&rot13(raw), &xp_entry(), Some(3));
        assert_eq!(e.entry_kind, EntryKind::ExplorerBookkeeping, "for {raw}");
        assert!(!e.is_execution, "for {raw}");
        assert!(e.target.is_none(), "bookkeeping names no target: {raw}");
    }
}

/// **The trap.** A 1,612-byte value under a key declaring `Version = 5` must
/// not be read at the 72-byte offsets.
///
/// This is the real shape from `LoneWolf`: `UEME_CTLSESSION` in a
/// `{CEBFF5CD-…}\Count` key whose `Version` is 5. A decoder keyed on the
/// declared version would take bytes `0x3C..0x44` out of the middle of a
/// session blob and publish them as an execution time. Nothing about the
/// result would look wrong.
#[test]
fn a_long_session_blob_under_a_version_five_key_is_not_read_at_the_seventy_two_byte_offsets() {
    let blob = vec![0xAAu8; 1612];
    let e = decode_entry(&rot13("UEME_CTLSESSION"), &blob, Some(5));

    assert_eq!(e.decode_status, DecodeStatus::UnrecognisedLength);
    assert_eq!(e.entry_length, 1612);
    assert!(
        e.last_executed.is_none(),
        "no timestamp may be taken from a length this decoder does not recognise"
    );
    assert!(e.run_count.is_none() && e.focus_count.is_none() && e.session_id.is_none());
    assert!(!e.is_execution, "and it raises no timeline event");
    assert_eq!(
        e.content_incomplete_reason.as_deref(),
        Some("unresolved_structure"),
        "the record is still emitted, and says why nothing was decoded"
    );
}

/// Any other unrecognised length is recorded undecoded rather than guessed at,
/// and the record is still emitted — silence would file the value as absent.
#[test]
fn an_unrecognised_length_is_recorded_undecoded_and_still_emitted() {
    for len in [1usize, 7, 9, 15, 17, 71, 73, 100] {
        let e = decode_entry(&rot13("Foo.exe"), &vec![0u8; len], Some(5));
        assert_eq!(
            e.decode_status,
            DecodeStatus::UnrecognisedLength,
            "len {len}"
        );
        assert_eq!(e.entry_length, len as u64);
        assert!(e.last_executed.is_none(), "len {len}");
        assert_eq!(
            e.name_decoded, "Foo.exe",
            "the name still decodes — only the payload is in doubt"
        );
    }
}

/// The 8-byte XP `UEME_CTLSESSION` shape is bookkeeping with no timestamp.
///
/// Verbatim from the corpus: `b7a8500e01000000`.
#[test]
fn the_eight_byte_form_is_bookkeeping_with_no_timestamp() {
    let data = vec![0xb7, 0xa8, 0x50, 0x0e, 0x01, 0x00, 0x00, 0x00];
    let e = decode_entry(&rot13("UEME_CTLSESSION"), &data, Some(3));
    assert_eq!(e.decode_status, DecodeStatus::Decoded);
    assert_eq!(e.entry_length, 8);
    assert!(e.last_executed.is_none(), "there is no FILETIME in 8 bytes");
    assert!(!e.is_execution);
}

/// A zero FILETIME is the absence of a time, not 1601-01-01.
#[test]
fn a_zero_filetime_carries_no_last_executed_time() {
    let mut data = win10_entry();
    data[0x3C..0x44].copy_from_slice(&0u64.to_le_bytes());
    let e = decode_entry(&rot13("Foo.exe"), &data, Some(5));
    assert_eq!(e.decode_status, DecodeStatus::Decoded);
    assert!(
        e.last_executed.is_none(),
        "1601-01-01 is what a zero FILETIME formats to, and it is not a time this program ran"
    );
    assert_eq!(e.run_count, Some(14), "the counts are still good");
}

// --- Names -----------------------------------------------------------------

/// ROT13 touches ASCII letters only, and the raw name is always kept.
///
/// A UTF-16 or mojibake name must survive to the record even when the decode
/// makes no sense of it: the stored bytes are the evidence.
#[test]
fn rot13_leaves_non_ascii_untouched_and_the_raw_name_is_always_kept() {
    // `Nb` rotates to `Ao`, `rkr` to `exe`; the two UTF-8 continuation bytes of
    // `\u{e9}` are not letters and must pass through untouched.
    let raw = vec![b'N', b'b', 0xC3, 0xA9, b'.', b'r', b'k', b'r'];
    let e = decode_entry(&raw, &win10_entry(), Some(5));
    assert!(
        e.name_decoded.starts_with("Ao"),
        "ASCII letters rotate and keep their case: {:?}",
        e.name_decoded
    );
    assert!(
        e.name_decoded.ends_with(".exe"),
        "letters rotate: {:?}",
        e.name_decoded
    );
    assert_eq!(
        e.value_name_raw,
        String::from_utf8_lossy(&raw),
        "the stored name is kept verbatim"
    );
    // The non-ASCII bytes are not rotated into something else.
    assert!(e.name_decoded.contains('\u{e9}') || e.name_decoded.contains('\u{fffd}'));
}

/// A `{KNOWNFOLDERID}` prefix is resolved only from a published table, and an
/// unknown GUID keeps its GUID and claims nothing.
#[test]
fn a_known_folder_guid_is_named_only_from_the_published_table() {
    let named = decode_entry(
        &rot13(r"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Notepad.lnk"),
        &win10_entry(),
        Some(5),
    );
    assert_eq!(named.known_folder.as_deref(), Some("Common Programs"));
    assert_eq!(named.target_kind, TargetKind::ShellLink);

    let unknown = decode_entry(
        &rot13(r"{DEADBEEF-0000-0000-0000-000000000000}\Thing.lnk"),
        &win10_entry(),
        Some(5),
    );
    assert!(
        unknown.known_folder.is_none(),
        "a GUID this build cannot name must claim no role"
    );
    assert!(
        unknown.target.as_deref().unwrap_or("").contains("DEADBEEF"),
        "and the GUID is kept verbatim"
    );
}

/// A drive-lettered path is a DOS path.
#[test]
fn a_drive_lettered_target_is_a_dos_path() {
    let e = decode_entry(
        &rot13(r"C:\Windows\System32\cmd.exe"),
        &win10_entry(),
        Some(5),
    );
    assert_eq!(e.target_kind, TargetKind::DosPath);
    assert_eq!(e.target.as_deref(), Some(r"C:\Windows\System32\cmd.exe"));
}

// --- The GUID roles --------------------------------------------------------

/// Only the two documented GUIDs are given a role; the rest are reported in
/// full and classified as unclassified.
///
/// `LoneWolf` holds nine GUIDs under `UserAssist`. Asserting a meaning for the
/// seven nobody has published is how a tool comes to state something it cannot
/// support.
#[test]
fn only_the_two_documented_guids_are_given_a_role() {
    assert_eq!(
        guid_role("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"),
        "executable_execution"
    );
    assert_eq!(
        guid_role("{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"),
        "shortcut_execution"
    );
    // Case-insensitively, since a hive may hold either spelling.
    assert_eq!(
        guid_role("{cebff5cd-ace2-4f4f-9178-9926f41749ea}"),
        "executable_execution"
    );
    for other in [
        "{0D6D4F41-2994-4BA0-8FEF-620E43CD2812}",
        "{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}",
        "{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}",
    ] {
        assert_eq!(guid_role(other), "unclassified", "for {other}");
    }
}

// --- Coverage: the absence that is an answer -------------------------------

/// A `Count` key that exists and holds nothing means **Windows recorded nothing
/// here** — which is a different sentence from *this build did not look*.
///
/// Seven of `LoneWolf`'s nine `Count` keys are empty, so this is the common
/// case and not a curiosity.
#[test]
fn an_empty_count_key_reads_as_windows_recorded_nothing_not_as_unexamined() {
    let c = UserAssistCoverage {
        guid: "{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}".into(),
        declared_version: Some(5),
        count_key_present: true,
        values_total: 0,
        entries_decoded: 0,
        entries_undecodable: 0,
        bookkeeping_values: 0,
    };
    let j = c.to_json();
    assert_eq!(j["count_key_present"], serde_json::json!(true));
    assert_eq!(j["values_total"], serde_json::json!(0));
    let note = j["coverage_note"].as_str().unwrap_or("");
    assert!(
        note.contains("recorded nothing"),
        "an empty Count key must say Windows recorded nothing: {note:?}"
    );
    assert!(
        !note.contains("not examined") && !note.contains("did not look"),
        "and it must not say this build failed to look: {note:?}"
    );

    // A GUID whose Count key is absent is the other sentence.
    let absent = UserAssistCoverage {
        count_key_present: false,
        ..c
    };
    let j = absent.to_json();
    assert!(
        j["coverage_note"]
            .as_str()
            .unwrap_or("")
            .contains("no Count key"),
        "got {:?}",
        j["coverage_note"]
    );
}

/// A declared `Version` that disagrees with the entry lengths is stated, not
/// resolved.
///
/// The decoder dispatches on length, so a disagreement changes no field — but
/// it is a fact about the hive and the coverage record carries it.
#[test]
fn a_version_that_disagrees_with_the_entry_lengths_is_stated() {
    // Version 3 declares the XP layout; a 72-byte entry is the Win7+ one.
    let e = decode_entry(&rot13("Foo.exe"), &win10_entry(), Some(3));
    assert_eq!(
        e.decode_status,
        DecodeStatus::Decoded,
        "the length is what is believed, so the entry still decodes"
    );
    assert_eq!(e.run_count, Some(14));
    assert!(
        e.version_disagreement
            .as_deref()
            .unwrap_or("")
            .contains("declares version 3"),
        "the disagreement must be on the record: {:?}",
        e.version_disagreement
    );
}

// --- End to end, on the real hives -----------------------------------------

/// A hive from the corpus named by `SEANCE_REGISTRY_CORPUS`, or `None` when the
/// gate is not provisioned. Named-but-missing panics.
pub(crate) fn corpus_hive_for_tests(name: &str) -> Option<Vec<u8>> {
    corpus_hive(name)
}

fn corpus_hive(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var("SEANCE_REGISTRY_CORPUS").ok()?;
    let path = std::path::Path::new(&dir).join(name);
    assert!(
        path.is_file(),
        "{} is missing from the corpus named by SEANCE_REGISTRY_CORPUS. The gate is ON and \
         cannot open — a pass here would report a comparison that never ran.",
        path.display()
    );
    Some(std::fs::read(&path).expect("read the corpus hive"))
}

/// Drive the whole parser and return every record it produced.
pub(crate) fn records_for_tests(name: &str, bytes: Vec<u8>) -> Vec<serde_json::Value> {
    records(name, bytes)
}

/// Drive the whole parser and return every artifact it produced, type and
/// all -- for the tests that must check *how* a record was emitted, not just
/// what it says.
pub(crate) fn artifacts_for_tests(
    name: &str,
    bytes: Vec<u8>,
) -> Vec<seance_core::artifact::Artifact> {
    artifacts(name, bytes)
}

fn records(name: &str, bytes: Vec<u8>) -> Vec<serde_json::Value> {
    artifacts(name, bytes)
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

fn artifacts(name: &str, bytes: Vec<u8>) -> Vec<seance_core::artifact::Artifact> {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::DataSource;
    use seance_core::module::ForensicsModule;
    use std::sync::Arc;

    let src: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": name }),
    );
    crate::RegistryParser
        .process(&art)
        .expect("the parser runs")
}

/// The real XP `NTUSER.DAT` yields UserAssist entries, and its bookkeeping is
/// not among the executions.
///
/// Ground truth from the corpus hive: two GUIDs, both `Version = 3`, and
/// `UEME_RUNPIDL:%csidl2%\MSN.lnk` with a run count of 19.
#[test]
fn the_real_xp_ntuser_hive_yields_userassist_entries() {
    let Some(bytes) = corpus_hive("NTUSER.DAT") else {
        return;
    };
    let all = records("NTUSER.DAT", bytes);

    let entries: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "UserAssistEntry")
        .collect();
    let coverage: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "UserAssistCoverage")
        .collect();
    assert!(
        !entries.is_empty(),
        "the XP hive holds UserAssist entries and the walk must reach them"
    );
    assert_eq!(
        coverage.len(),
        2,
        "two GUIDs, each with a coverage record — including any whose Count key is empty"
    );
    for c in &coverage {
        assert_eq!(
            c["declared_version"],
            serde_json::json!(3),
            "both GUIDs in this hive declare version 3"
        );
    }

    // Every entry decoded through a known layout, or said why not.
    for e in &entries {
        let status = e["decode_status"].as_str().unwrap_or("");
        assert!(
            status == "decoded" || status == "unrecognised_length",
            "unexpected status {status:?}"
        );
        if status == "unrecognised_length" {
            assert_eq!(e["content_incomplete"], serde_json::json!(true));
            assert!(
                e["last_executed"].is_null(),
                "nothing may be timed from a length this build does not decode"
            );
        }
        assert!(
            e["value_name_raw"].is_string(),
            "the stored name is always kept"
        );
    }

    // Explorer's bookkeeping is present and is NOT an execution.
    let bookkeeping: Vec<_> = entries
        .iter()
        .filter(|e| e["entry_kind"] == "explorer_bookkeeping")
        .collect();
    assert!(
        !bookkeeping.is_empty(),
        "a real Count key holds UEME_CTL* entries; if none is here the classifier missed them"
    );
    for b in bookkeeping {
        assert_eq!(
            b["is_execution"],
            serde_json::json!(false),
            "UEME_CTLSESSION must never be reported as a program run: {:?}",
            b["name"]
        );
    }
}

/// A timeline event is raised for an execution with a time, and for nothing
/// else.
///
/// The count must equal the number of entries that are both executions and
/// carry a decoded last-execution time — no more, and no fewer.
#[test]
fn a_timeline_event_is_raised_only_for_a_timed_execution() {
    let Some(bytes) = corpus_hive("NTUSER.DAT") else {
        return;
    };
    let all = records("NTUSER.DAT", bytes);
    let expected = all
        .iter()
        .filter(|r| {
            r["type"] == "UserAssistEntry"
                && r["is_execution"] == serde_json::json!(true)
                && r["last_executed"].is_string()
        })
        .count();
    let events: Vec<_> = all
        .iter()
        .filter(|r| r["timestamp_desc"] == "Program last executed (UserAssist)")
        .collect();
    assert_eq!(
        events.len(),
        expected,
        "one event per timed execution, and none for bookkeeping or an undecoded payload"
    );
    assert!(expected > 0, "the XP hive does hold timed executions");
    for e in events {
        assert!(e["timestamp"].is_string());
        assert_eq!(e["source"], "Registry");
    }
}

/// The capture is complete on a real hive, and the record says so.
#[test]
fn the_resident_capture_is_complete_on_a_real_hive() {
    let Some(bytes) = corpus_hive("NTUSER.DAT") else {
        return;
    };
    let all = records("NTUSER.DAT", bytes);
    let hive = all
        .iter()
        .find(|r| r["type"] == "RegistryHive")
        .expect("a hive record");
    assert_eq!(
        hive["resident_capture_complete"],
        serde_json::json!(true),
        "nothing was capped, and the record must say so rather than leave it to be inferred"
    );
    assert!(hive["resident_capture_cap_reason"].is_null());
}

/// A `SOFTWARE` hive holds no UserAssist at all, and that is an answer: no
/// entries, no coverage records, and a complete capture.
///
/// This is the anchoring working. `SOFTWARE` has 117,488 keys; if the matcher
/// were loose, this is where it would show.
#[test]
fn a_software_hive_yields_no_userassist_and_captures_nothing() {
    let Some(bytes) = corpus_hive("SOFTWARE") else {
        return;
    };
    let all = records("SOFTWARE", bytes);
    assert!(
        !all.iter()
            .any(|r| r["type"] == "UserAssistEntry" || r["type"] == "UserAssistCoverage"),
        "UserAssist is a user-hive artifact; SOFTWARE must yield none"
    );
    let hive = all
        .iter()
        .find(|r| r["type"] == "RegistryHive")
        .expect("a hive record");
    assert_eq!(hive["resident_capture_complete"], serde_json::json!(true));
}
