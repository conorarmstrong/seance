//! The raw-value collector — stated before it was built.
//!
//! Every path below was verified against a real hive on this machine while
//! planning §2.5: `LoneWolf`'s `jcloudy` `NTUSER.DAT` (9 UserAssist GUIDs, all
//! `Version = 5`, 7 of 9 `Count` keys empty) and the plaso corpus `NTUSER.DAT`
//! (2 GUIDs, both `Version = 3`).

use super::resident::*;

/// The walk's synthetic root segment is ignored, and a GUID key is recognised.
#[test]
fn a_userassist_guid_key_is_anchored_under_either_root_spelling() {
    for root in [
        "ROOT",
        "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}",
    ] {
        let p = format!(
            r"{root}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}"
        );
        assert_eq!(
            anchor_of(&p),
            Some(Anchor::UserAssistGuid {
                guid: "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}".to_string()
            }),
            "for root {root}"
        );
    }
}

/// The `Count` subkey is a different anchor from its GUID parent: one holds
/// `Version`, the other holds the entries.
#[test]
fn the_count_subkey_is_a_distinct_anchor() {
    let p = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count";
    assert_eq!(
        anchor_of(p),
        Some(Anchor::UserAssistCount {
            guid: "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}".to_string()
        })
    );
}

/// Matching is case-insensitive, because a hive holds either casing.
#[test]
fn the_match_is_case_insensitive_on_segments() {
    let p = r"ROOT\software\microsoft\windows\currentversion\explorer\userassist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\COUNT";
    assert!(matches!(anchor_of(p), Some(Anchor::UserAssistCount { .. })));
}

/// Nothing else is anchored, so an ordinary hive captures no bytes at all.
///
/// This is the memory decision: `SOFTWARE` holds 117,488 keys, and capturing
/// their values to decode a few hundred UserAssist entries would trade a real
/// ceiling for a convenience. `HUNT-125` is this project already OOM-killed by
/// ingest memory that scaled with the evidence.
#[test]
fn an_unanchored_key_is_not_captured() {
    for p in [
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        // BAM's own keys ARE anchored -- both the per-SID leaves and the
        // containers whose existence separates "this hive predates BAM" from
        // "BAM recorded nothing". `bam_tests` covers them.
        r"ROOT\ControlSet001\Services\bits",
        r"ROOT\ControlSet001\Services\bam\UserSettings\S-1-5-18\Deeper",
        // MUICache IS anchored now; `muicache_tests` owns its matcher. Its
        // parent and any subkey of it are not.
        r"ROOT\Software\Microsoft\Windows\ShellNoRoam",
        r"ROOT\Software\Microsoft\Windows\ShellNoRoam\MUICache\Deeper",
    ] {
        assert_eq!(anchor_of(p), None, "for {p}");
    }
}

/// A subkey that is not a brace-delimited GUID is not a UserAssist GUID key.
///
/// A matcher that accepted any segment here would classify unrelated subkeys as
/// GUIDs and then report their values as UserAssist entries.
#[test]
fn a_non_guid_segment_under_userassist_is_not_anchored() {
    for tail in ["Settings", "NotAGuid", "{unterminated"] {
        let p =
            format!(r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{tail}");
        assert_eq!(anchor_of(&p), None, "for {tail}");
    }
}

/// A key deeper than `Count` is not anchored: the entries live directly under
/// it, and anything below is something else.
#[test]
fn a_key_deeper_than_count_is_not_anchored() {
    let p = r"ROOT\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count\Extra";
    assert_eq!(anchor_of(p), None);
}

// --- The caps ---------------------------------------------------------------

/// A value cap stops the capture and **says so**, rather than returning a short
/// list that reads as complete.
#[test]
fn the_value_cap_is_stamped_rather_than_silently_truncating() {
    let mut cap = ResidentCapture::default();
    let idx = cap
        .begin_key(
            r"ROOT\Explorer\UserAssist\{G}\Count",
            Anchor::UserAssistCount { guid: "{G}".into() },
            0,
        )
        .expect("a fresh capture accepts a key");
    assert!(cap.complete());
    for i in 0..MAX_RESIDENT_VALUES + 2 {
        cap.push_value(idx, &format!("v{i}"), None, &[0u8; 4]);
    }
    assert!(!cap.complete(), "the cap must be visible");
    assert!(
        cap.capped.unwrap_or("").contains("value cap"),
        "and must name which cap: {:?}",
        cap.capped
    );
}

/// The byte cap likewise, and it is checked **before** the bytes are taken, so
/// the ceiling is a ceiling.
#[test]
fn the_byte_cap_refuses_before_it_is_exceeded() {
    let mut cap = ResidentCapture::default();
    let idx = cap
        .begin_key(
            r"ROOT\Explorer\UserAssist\{G}\Count",
            Anchor::UserAssistCount { guid: "{G}".into() },
            0,
        )
        .expect("accepts");
    cap.push_value(idx, "big", None, &vec![0u8; MAX_RESIDENT_BYTES + 1]);
    assert!(!cap.complete());
    assert!(
        cap.capped.unwrap_or("").contains("byte cap"),
        "got {:?}",
        cap.capped
    );
    assert!(
        cap.keys[idx].values.is_empty(),
        "nothing over the ceiling is kept"
    );
}

/// Once capped, nothing more is captured — a partial capture must not keep
/// growing unevenly and read as a choice.
#[test]
fn a_capped_capture_accepts_no_further_keys_or_values() {
    let mut cap = ResidentCapture::default();
    let idx = cap
        .begin_key(
            r"ROOT\Explorer\UserAssist\{G}\Count",
            Anchor::UserAssistCount { guid: "{G}".into() },
            0,
        )
        .expect("accepts");
    cap.push_value(idx, "big", None, &vec![0u8; MAX_RESIDENT_BYTES + 1]);
    assert!(cap
        .begin_key(
            r"ROOT\Explorer\UserAssist\{H}\Count",
            Anchor::UserAssistCount { guid: "{H}".into() },
            0
        )
        .is_none());
    cap.push_value(idx, "small", None, &[1, 2, 3]);
    assert!(cap.keys[idx].values.is_empty());
}
