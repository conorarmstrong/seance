//! BAM/DAM — what the decoder has to do, stated before it did any of it.
//!
//! # What this artifact is
//!
//! Background Activity Moderator (and its desktop sibling DAM) records, per
//! user SID, the last time each program executed. Windows 10 1709 and later.
//! It is one of the few artifacts that survives a program's deletion **and**
//! names the user it ran as.
//!
//! # Where the fixtures come from
//!
//! `LoneWolf`'s `SYSTEM` hive (Windows 10 1803), read key by key while planning
//! §2.5, and the plaso corpus `SYSTEM` (Windows XP, which predates BAM and so
//! provides the absence case). The two ground-truth entries are quoted verbatim.

use super::bam::*;

/// `\Device\HarddiskVolume4\Windows\System32\cmd.exe` on LoneWolf:
/// last executed **2018-04-05T02:05:02.333385Z**, with the device-path trailing
/// pattern.
///
/// Note the difference from the UserAssist fixtures, and it is worth being
/// exact about: those carry the raw hex read off the hive. Here the ground
/// truth recorded while planning was the **decoded time**, so the FILETIME
/// below is derived back from it — `0x01D3CC82820939DA` is
/// 2018-04-05T02:05:02.333385Z exactly. That makes this a weaker fixture: it
/// pins that the decoder reads a FILETIME at offset 0 correctly, and it cannot
/// catch a decoder that reads the right bytes for the wrong reason.
fn cmd_entry() -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&0x01D3_CC82_8209_39DAu64.to_le_bytes());
    // Sixteen undocumented bytes. The device-path pattern, observed exactly.
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(v.len(), 24);
    v
}

/// The package-identity trailing pattern, the other of the two observed.
fn package_entry() -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    // `notepad.exe`'s time on the same hive, 2018-03-27T09:26:36.418728Z,
    // likewise derived from the decoded ground truth.
    v.extend_from_slice(&0x01D3_C5AD_B406_1290u64.to_le_bytes());
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]);
    v
}

// --- The 24-byte entry -----------------------------------------------------

/// A BAM entry decodes its execution time, and keeps its undocumented bytes as
/// bytes.
#[test]
fn a_bam_entry_decodes_its_last_execution_time() {
    let e = decode_entry(
        r"\Device\HarddiskVolume4\Windows\System32\cmd.exe",
        &cmd_entry(),
    );
    assert_eq!(e.decode_status, BamDecodeStatus::Decoded);
    assert_eq!(e.entry_length, 24);
    assert!(
        e.last_executed
            .as_deref()
            .unwrap_or("")
            .starts_with("2018-04-05T02:05:02"),
        "got {:?}",
        e.last_executed
    );
    let hex = e.trailing_bytes_hex.as_deref().unwrap_or("");
    assert_eq!(
        hex.len(),
        32,
        "all sixteen undocumented bytes are kept: {hex:?}"
    );
}

/// The sixteen bytes after the FILETIME are **not** used to classify anything.
///
/// Only two patterns were ever observed and they correlate with the target's
/// shape — but the classification comes from the value NAME, which is
/// documented, and never from bytes nobody has published a meaning for.
#[test]
fn the_undocumented_trailing_bytes_do_not_decide_the_target_kind() {
    // A device path carrying the *package* trailing pattern must still classify
    // as a device path.
    let e = decode_entry(r"\Device\HarddiskVolume4\a.exe", &package_entry());
    assert_eq!(e.target_kind, BamTargetKind::NtDevicePath);
    // And a package identity carrying the *device* pattern is still a package.
    let e = decode_entry("Microsoft.MicrosoftEdge_8wekyb3d8bbwe", &cmd_entry());
    assert_eq!(e.target_kind, BamTargetKind::AppIdentity);
}

/// An NT device path is reported as stored and **not** translated to a drive
/// letter.
///
/// `MountedDevices` is in the same hive and §2.6 owns that mapping. Guessing
/// `HarddiskVolume4` = `C:` would put a drive letter in a report that the
/// evidence does not support.
#[test]
fn an_nt_device_path_is_not_translated_to_a_drive_letter() {
    let e = decode_entry(
        r"\Device\HarddiskVolume4\Windows\System32\cmd.exe",
        &cmd_entry(),
    );
    assert_eq!(e.target_kind, BamTargetKind::NtDevicePath);
    assert_eq!(
        e.target, r"\Device\HarddiskVolume4\Windows\System32\cmd.exe",
        "stored verbatim"
    );
    assert!(!e.volume_resolved);
    assert!(
        e.volume_note
            .as_deref()
            .unwrap_or("")
            .contains("does not map it to a drive letter"),
        "got {:?}",
        e.volume_note
    );
}

/// Half of what BAM records is not a file path at all.
///
/// Thirteen of LoneWolf's 26 executions are package family names. A consumer
/// that assumed every BAM name is a path would be wrong half the time on that
/// hive, so the kind is on the record.
#[test]
fn a_package_family_name_is_not_reported_as_a_path() {
    for name in [
        "Microsoft.Windows.Cortana_cw5n1h2txyewy",
        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe",
        "windows.immersivecontrolpanel_cw5n1h2txyewy",
    ] {
        let e = decode_entry(name, &package_entry());
        assert_eq!(e.target_kind, BamTargetKind::AppIdentity, "for {name}");
        assert!(!e.volume_resolved);
    }
}

/// A drive-lettered name is a DOS path.
#[test]
fn a_drive_lettered_name_is_a_dos_path() {
    let e = decode_entry(r"C:\Windows\System32\cmd.exe", &cmd_entry());
    assert_eq!(e.target_kind, BamTargetKind::DosPath);
}

// --- Lengths ---------------------------------------------------------------

/// A length that is not 24 but holds a FILETIME reads the time and says the
/// length was unexpected.
#[test]
fn an_unexpected_length_still_reads_its_filetime_and_says_so() {
    let mut data = cmd_entry();
    data.truncate(16);
    let e = decode_entry(r"\Device\HarddiskVolume4\a.exe", &data);
    assert_eq!(e.decode_status, BamDecodeStatus::UnexpectedLength);
    assert_eq!(e.entry_length, 16);
    assert!(
        e.last_executed.is_some(),
        "the first eight bytes are still a FILETIME"
    );
    assert_eq!(e.content_incomplete_reason.as_deref(), Some("unvalidated"));
}

/// Shorter than a FILETIME: no timestamp, a short read, and the record is
/// still emitted — silence would file the value as absent.
#[test]
fn a_value_shorter_than_a_filetime_carries_no_time_and_is_still_emitted() {
    for len in [0usize, 1, 7] {
        let e = decode_entry(r"\Device\HarddiskVolume4\a.exe", &vec![0u8; len]);
        assert_eq!(e.decode_status, BamDecodeStatus::ShortRead, "len {len}");
        assert!(e.last_executed.is_none(), "len {len}");
        assert_eq!(
            e.content_incomplete_reason.as_deref(),
            Some("short_read"),
            "len {len}"
        );
    }
}

/// A zero FILETIME is the absence of a time.
#[test]
fn a_zero_filetime_carries_no_execution_time() {
    let mut data = cmd_entry();
    data[..8].copy_from_slice(&0u64.to_le_bytes());
    let e = decode_entry(r"\Device\HarddiskVolume4\a.exe", &data);
    assert!(
        e.last_executed.is_none(),
        "1601-01-01 is not a time this program ran"
    );
}

// --- What is not an execution ----------------------------------------------

/// `Version` and `SequenceNumber` are on every SID key and are **not**
/// programs.
///
/// On LoneWolf, SID …-1001 holds 28 values of which exactly 2 are these. A
/// builder that treated every value as an execution would publish `Version`
/// and `SequenceNumber` as executed binaries on every Windows 10 machine ever
/// examined — `HUNT-122`'s shape for the third time in this sprint.
#[test]
fn version_and_sequencenumber_are_not_executions() {
    for name in ["Version", "SequenceNumber", "version", "sequencenumber"] {
        assert!(
            !is_execution_value(name),
            "{name} is BAM's own bookkeeping, not a program"
        );
    }
    for name in [
        r"\Device\HarddiskVolume4\Windows\System32\cmd.exe",
        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe",
    ] {
        assert!(is_execution_value(name), "{name} is a program");
    }
}

// --- The three absences, each its own sentence -----------------------------

/// `Services\bam` absent: the hive predates BAM, or it was never written.
///
/// The plaso XP `SYSTEM` hive has none — BAM is Windows 10 1709+ — and that
/// must read as "this hive records no BAM" and not as "no programs ran".
#[test]
fn a_hive_without_a_bam_key_says_the_key_is_absent() {
    let c = BamCoverage {
        service: "bam".into(),
        control_set: "ControlSet001".into(),
        is_current_control_set: true,
        service_key_present: false,
        usersettings_present: false,
        sid: None,
        values_total: 0,
        executions: 0,
        undecodable: 0,
    };
    let note = c.to_json()["coverage_note"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(note.contains("no bam key"), "got {note:?}");
    assert!(
        !note.contains("no programs"),
        "the absence of the key is not the absence of executions: {note:?}"
    );
}

/// `Services\dam` present with zero subkeys — verified on LoneWolf.
///
/// Windows created the key and recorded nothing under it. A different fact
/// from the key being absent, and from a SID key being empty.
#[test]
fn a_service_key_with_no_usersettings_says_so_distinctly() {
    let c = BamCoverage {
        service: "dam".into(),
        control_set: "ControlSet001".into(),
        is_current_control_set: true,
        service_key_present: true,
        usersettings_present: false,
        sid: None,
        values_total: 0,
        executions: 0,
        undecodable: 0,
    };
    let note = c.to_json()["coverage_note"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(note.contains("recorded nothing under it"), "got {note:?}");
    assert!(!note.contains("no dam key"), "the key IS present: {note:?}");
}

/// A SID key holding only bookkeeping reports zero executions **beside** the
/// value count, so the reader can see that values were present and none was a
/// program.
///
/// Verified on LoneWolf's `S-1-5-90-0-1` and `S-1-5-90-0-2`.
#[test]
fn a_sid_key_holding_only_bookkeeping_reports_zero_executions_beside_its_value_count() {
    let c = BamCoverage {
        service: "bam".into(),
        control_set: "ControlSet001".into(),
        is_current_control_set: true,
        service_key_present: true,
        usersettings_present: true,
        sid: Some("S-1-5-90-0-1".into()),
        values_total: 2,
        executions: 0,
        undecodable: 0,
    };
    let j = c.to_json();
    assert_eq!(j["executions"], serde_json::json!(0));
    assert_eq!(j["values_total"], serde_json::json!(2));
    assert!(
        j["coverage_note"]
            .as_str()
            .unwrap_or("")
            .contains("none of them an execution"),
        "got {:?}",
        j["coverage_note"]
    );
}

// --- Control sets ----------------------------------------------------------

/// Both layouts must match, or half the Windows 10 estate reports nothing.
///
/// LoneWolf (1803) has `Services\bam\UserSettings\<SID>` with **no** `State`
/// segment; 1809 and later insert one.
#[test]
fn both_the_pre_1809_and_the_state_layouts_are_recognised() {
    for (path, layout) in [
        (
            r"ROOT\ControlSet001\Services\bam\UserSettings\S-1-5-21-1-2-3-1001",
            BamLayout::UserSettings,
        ),
        (
            r"ROOT\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001",
            BamLayout::StateUserSettings,
        ),
    ] {
        let a = bam_sid_key(path).unwrap_or_else(|| panic!("{path} must be recognised"));
        assert_eq!(a.layout, layout, "for {path}");
        assert_eq!(a.service, "bam");
        assert_eq!(a.control_set, "ControlSet001");
        assert_eq!(a.sid, "S-1-5-21-1-2-3-1001");
    }
}

/// `dam` as well as `bam`, and `CurrentControlSet` as well as a numbered one.
#[test]
fn dam_and_currentcontrolset_are_recognised() {
    let a = bam_sid_key(r"ROOT\CurrentControlSet\Services\dam\UserSettings\S-1-5-18")
        .expect("recognised");
    assert_eq!(a.service, "dam");
    assert_eq!(a.control_set, "CurrentControlSet");
    assert_eq!(a.sid, "S-1-5-18");
}

/// Nothing else is a BAM SID key.
#[test]
fn an_unrelated_key_is_not_a_bam_sid_key() {
    for p in [
        r"ROOT\ControlSet001\Services\bam",
        r"ROOT\ControlSet001\Services\bam\UserSettings",
        r"ROOT\ControlSet001\Services\bam\UserSettings\S-1-5-18\Deeper",
        r"ROOT\ControlSet001\Services\bits\UserSettings\S-1-5-18",
    ] {
        assert!(bam_sid_key(p).is_none(), "for {p}");
    }
}

/// Two control sets holding `bam` are **both** emitted and distinguished, never
/// deduplicated.
///
/// `HUNT-062`'s lesson: two copies of the same machine's state are one machine,
/// and the consumer must be able to see which copy it is reading. Collapsing
/// them would hide that an entry came from the control set the machine did not
/// boot.
#[test]
fn two_control_sets_are_distinguished_rather_than_deduplicated() {
    let a = bam_sid_key(r"ROOT\ControlSet001\Services\bam\UserSettings\S-1-5-18").unwrap();
    let b = bam_sid_key(r"ROOT\ControlSet002\Services\bam\UserSettings\S-1-5-18").unwrap();
    assert_ne!(a.control_set, b.control_set);
    assert_eq!(a.sid, b.sid, "the same SID, in two control sets");
}

// --- The container keys, whose existence is the answer ----------------------

/// The service key, its `UserSettings` container, and the `State` variants are
/// all recognised — because their **existence** is what separates "this hive
/// predates BAM" from "BAM exists and recorded nothing".
///
/// Without this, a Windows 7 or XP `SYSTEM` hive yields silence, and silence
/// reads as "no programs ran".
#[test]
fn the_service_container_keys_are_recognised_so_their_absence_can_be_stated() {
    for (path, service, usersettings) in [
        (r"ROOT\ControlSet001\Services\bam", "bam", false),
        (r"ROOT\ControlSet001\Services\bam\UserSettings", "bam", true),
        (r"ROOT\ControlSet001\Services\bam\State", "bam", false),
        (
            r"ROOT\ControlSet001\Services\bam\State\UserSettings",
            "bam",
            true,
        ),
        (r"ROOT\CurrentControlSet\Services\dam", "dam", false),
    ] {
        let (svc, cs, is_us) =
            bam_service_key(path).unwrap_or_else(|| panic!("{path} must be recognised"));
        assert_eq!(svc, service, "for {path}");
        assert_eq!(is_us, usersettings, "for {path}");
        assert!(!cs.is_empty(), "for {path}");
    }
}

/// A per-SID leaf is not a container key, and an unrelated service is neither.
#[test]
fn a_sid_leaf_and_an_unrelated_service_are_not_container_keys() {
    assert!(
        bam_service_key(r"ROOT\ControlSet001\Services\bam\UserSettings\S-1-5-18").is_none(),
        "the per-SID leaf is `bam_sid_key`'s"
    );
    assert!(bam_service_key(r"ROOT\ControlSet001\Services\bits").is_none());
    assert!(bam_service_key(r"ROOT\Software\Microsoft\bam").is_none());
}

// --- End to end: the absence, on a real hive --------------------------------

/// A hive from the corpus named by `SEANCE_REGISTRY_CORPUS`.
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

/// The real XP `SYSTEM` hive holds no BAM, and must **say so** rather than fall
/// silent.
///
/// This is the whole reason the coverage record exists. BAM arrived in Windows
/// 10 1709; an XP hive records none, and an examiner asking "what ran?" must be
/// told that this build of Windows kept no such record — not handed silence,
/// which reads as "nothing ran".
///
/// The per-SID decode on real Windows 10 hives is `real_hive_tests.rs`
/// (`BAM-1`, 2026-09-24); this is the absence half.
#[test]
fn the_real_xp_system_hive_states_that_it_holds_no_bam() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::DataSource;
    use seance_core::module::ForensicsModule;
    use std::sync::Arc;

    let Some(bytes) = corpus_hive("SYSTEM") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": "SYSTEM" }),
    );
    let out: Vec<serde_json::Value> = crate::RegistryParser
        .process(&art)
        .expect("the parser runs")
        .into_iter()
        .map(|a| a.metadata)
        .collect();

    assert!(
        !out.iter().any(|r| r["type"] == "BamEntry"),
        "an XP hive records no BAM executions"
    );
    let coverage: Vec<_> = out.iter().filter(|r| r["type"] == "BamCoverage").collect();
    assert!(
        !coverage.is_empty(),
        "the absence of BAM must be STATED. Silence here reads as 'no programs ran', which \
         is the failure this record exists to prevent."
    );
    for c in &coverage {
        assert_eq!(c["service_key_present"], serde_json::json!(false));
        assert_eq!(c["executions"], serde_json::json!(0));
        let note = c["coverage_note"].as_str().unwrap_or("");
        assert!(
            note.contains("Windows 10"),
            "the note must say why the key is absent: {note:?}"
        );
        assert!(
            !note.contains("no programs"),
            "and must not say nothing ran: {note:?}"
        );
    }
    // One per control set per service, so the reader can see every place the
    // answer could have been.
    let services: std::collections::BTreeSet<&str> = coverage
        .iter()
        .filter_map(|c| c["service"].as_str())
        .collect();
    assert_eq!(
        services,
        ["bam", "dam"].into_iter().collect(),
        "both services are reported absent, not just the one anybody remembers"
    );
}

// --- Which control set is current, as the walk renders `Select\Current` ------

/// `Select\Current` is a `REG_DWORD`, and the walk renders a DWORD as
/// `0x00000001 (1)`. The reader parsed that rendering as a bare decimal, which
/// never succeeds, so on every real `SYSTEM` hive — Case 001's desktop,
/// BelkaCTF 6 and LoneWolf, all `Current = 1` — every BAM record said
/// `is_current_control_set: false`, including the records from the control set
/// the machine booted. Found by the first real-hive BAM run (`BAM-1` in
/// `documentation/VALIDATION.md`); the synthetic fixtures passed the number in
/// directly and could not see it.
#[test]
fn select_current_is_read_from_the_dword_as_the_walk_renders_it() {
    for (n, bytes) in [(1u32, 1u32.to_le_bytes()), (2, 2u32.to_le_bytes())] {
        let rendered = crate::display_value_data("RegDWord", &bytes);
        let values = vec![serde_json::json!({
            "key_path": r"ROOT\Select",
            "value_name": "Current",
            "value_type": "RegDWord",
            "value_data": rendered,
        })];
        assert_eq!(
            crate::select_current(&values),
            Some(n),
            "Select\\Current rendered as {rendered:?} must read as control set {n}"
        );
    }
}
