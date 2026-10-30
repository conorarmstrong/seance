//! MUICache — stated before it was built.
//!
//! # What it is, and what it is not
//!
//! The shell caches an application's display name so Explorer need not reload
//! it from the binary's resources. Its presence means **the shell displayed
//! that application's friendly name**, which most often follows from running
//! it — but it is also written by a properties dialog, a context menu, and a
//! shell-extension enumeration.
//!
//! Over-claiming MUICache as execution evidence is the standard error with this
//! artifact, and this module is written not to make it.
//!
//! # Where the fixtures come from
//!
//! Real hives, read while planning §2.5: `LoneWolf`'s `UsrClass.dat` (31 values,
//! the Windows 7+ form) and the plaso corpus `NTUSER.DAT` (131 values, the XP
//! form). Both ground-truth pairs are quoted verbatim.

use super::muicache::*;

// --- The Windows 7+ form ---------------------------------------------------

/// A `.FriendlyAppName` and `.ApplicationCompany` for the same path pair into
/// one record, rather than becoming two half-records.
///
/// Verbatim from `LoneWolf` `UsrClass.dat`:
/// `C:\Windows\Explorer.exe.FriendlyAppName` = "Windows Explorer" and
/// `C:\Windows\Explorer.exe.ApplicationCompany` = "Microsoft Corporation".
#[test]
fn the_friendly_name_and_company_of_one_path_pair_into_one_entry() {
    let entries = pair_values(
        SourceForm::UsrClassShell,
        &[
            (
                r"C:\Windows\Explorer.exe.FriendlyAppName".to_string(),
                "Windows Explorer".to_string(),
            ),
            (
                r"C:\Windows\Explorer.exe.ApplicationCompany".to_string(),
                "Microsoft Corporation".to_string(),
            ),
        ],
    );
    assert_eq!(entries.len(), 1, "one application, one record");
    let e = &entries[0];
    assert_eq!(
        e.application_path.as_deref(),
        Some(r"C:\Windows\Explorer.exe")
    );
    assert_eq!(e.friendly_name.as_deref(), Some("Windows Explorer"));
    assert_eq!(e.company.as_deref(), Some("Microsoft Corporation"));
    assert_eq!(e.target_kind, MuiTargetKind::DosPath);
    assert_eq!(
        e.value_names.len(),
        2,
        "both raw names are kept, so the pairing can be checked"
    );
}

/// A suffix that is neither known is kept verbatim with **no field claimed for
/// it**.
#[test]
fn an_unknown_suffix_is_kept_and_claims_no_field() {
    let entries = pair_values(
        SourceForm::UsrClassShell,
        &[(
            r"C:\Tool\thing.exe.SomethingElse".to_string(),
            "value".to_string(),
        )],
    );
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert!(
        e.friendly_name.is_none() && e.company.is_none(),
        "an unrecognised suffix must not be read as either field"
    );
    assert!(
        e.value_names.iter().any(|n| n.contains("SomethingElse")),
        "and the raw name is kept: {:?}",
        e.value_names
    );
}

// --- The XP form -----------------------------------------------------------

/// A localised-resource reference is **not** an application path.
///
/// Verbatim from the plaso `NTUSER.DAT`: `@xpsp1res.dll,-11004` = "Outlook
/// Express" and `@C:\WINDOWS\system32\SHELL32.dll,-9216` = "My Computer".
/// Reporting `@shell32.dll,-22075` as a program on the machine would be a
/// fabricated finding — there is no such file, and an examiner correlating it
/// against the filesystem would find nothing and read the absence as deletion.
#[test]
fn a_localised_resource_reference_is_not_reported_as_an_application_path() {
    for (name, display, dll, id) in [
        (
            "@xpsp1res.dll,-11004",
            "Outlook Express",
            "xpsp1res.dll",
            -11004i64,
        ),
        (
            r"@C:\WINDOWS\system32\SHELL32.dll,-9216",
            "My Computer",
            r"C:\WINDOWS\system32\SHELL32.dll",
            -9216,
        ),
    ] {
        let entries = pair_values(
            SourceForm::ShellNoRoam,
            &[(name.to_string(), display.to_string())],
        );
        assert_eq!(entries.len(), 1, "for {name}");
        let e = &entries[0];
        assert!(
            e.application_path.is_none(),
            "a resource reference names no file: {name}"
        );
        assert_eq!(
            e.target_kind,
            MuiTargetKind::ResourceReference,
            "for {name}"
        );
        assert_eq!(e.resource_dll.as_deref(), Some(dll), "for {name}");
        assert_eq!(e.resource_id, Some(id), "for {name}");
        assert_eq!(e.friendly_name.as_deref(), Some(display), "for {name}");
    }
}

/// The XP form's plain-path names are application paths.
#[test]
fn an_xp_plain_path_is_an_application_path() {
    let entries = pair_values(
        SourceForm::ShellNoRoam,
        &[(
            r"C:\WINDOWS\system32\notepad.exe".to_string(),
            "Notepad".to_string(),
        )],
    );
    let e = &entries[0];
    assert_eq!(
        e.application_path.as_deref(),
        Some(r"C:\WINDOWS\system32\notepad.exe")
    );
    assert_eq!(e.target_kind, MuiTargetKind::DosPath);
    assert_eq!(e.friendly_name.as_deref(), Some("Notepad"));
}

// --- What is not an application --------------------------------------------

/// `LangID` is in **both** forms and is not an application.
///
/// REG_BINARY, two bytes. The third instance of `HUNT-122`'s shape in this one
/// roadmap item: a value that sits on every machine, which a builder taking
/// every value as a program would publish as an installed application
/// everywhere.
#[test]
fn langid_is_excluded_as_bookkeeping() {
    for name in ["LangID", "langid"] {
        assert!(!is_application_value(name), "{name} is bookkeeping");
    }
    for name in [
        r"C:\Windows\Explorer.exe.FriendlyAppName",
        "@xpsp1res.dll,-11004",
    ] {
        assert!(is_application_value(name), "{name} is an application");
    }
}

/// And it is **counted**, not merely dropped, so the coverage line accounts for
/// every value on the key.
#[test]
fn excluded_bookkeeping_is_counted_on_the_coverage_record() {
    let c = MuiCacheCoverage {
        source_form: SourceForm::ShellNoRoam,
        key_path: r"ROOT\Software\Microsoft\Windows\ShellNoRoam\MUICache".into(),
        values_total: 131,
        applications: 130,
        bookkeeping_values: 1,
    };
    let j = c.to_json();
    assert_eq!(j["values_total"], serde_json::json!(131));
    assert_eq!(j["bookkeeping_values"], serde_json::json!(1));
    assert_eq!(
        j["applications"].as_u64().unwrap_or(0) + j["bookkeeping_values"].as_u64().unwrap_or(0),
        131,
        "every value on the key must be accounted for in one bucket or the other"
    );
}

// --- The claim, and the timestamp ------------------------------------------

/// MUICache is **not** execution evidence, and every record says so.
///
/// This is the whole point of the module. The shell caches a display name for
/// reasons that include running the program and also include a properties
/// dialog, a context menu and a shell-extension enumeration.
#[test]
fn no_entry_claims_to_be_evidence_of_execution() {
    let entries = pair_values(
        SourceForm::UsrClassShell,
        &[(
            r"C:\Windows\Explorer.exe.FriendlyAppName".to_string(),
            "Windows Explorer".to_string(),
        )],
    );
    let j = entries[0].to_json();
    assert_eq!(j["execution_evidence"], serde_json::json!(false));
    let basis = j["basis"].as_str().unwrap_or("");
    assert!(
        basis.contains("not by itself a record of execution"),
        "got {basis:?}"
    );
}

/// The key's write time belongs to the **key**, and is scoped as such.
///
/// MUICache carries no per-entry timestamp. Presenting the key's time on each
/// entry without saying whose it is would date all 131 entries to the most
/// recent one.
#[test]
fn the_key_write_time_is_scoped_to_the_key_and_raises_no_event() {
    let mut e = pair_values(
        SourceForm::UsrClassShell,
        &[(
            r"C:\Windows\Explorer.exe.FriendlyAppName".to_string(),
            "Windows Explorer".to_string(),
        )],
    )
    .remove(0);
    e.key_last_written = Some("2018-03-27T09:18:14Z".into());
    let j = e.to_json();
    assert_eq!(
        j["key_last_written_scope"],
        serde_json::json!("the MUICache key, not this entry"),
        "whose time it is must be on the record"
    );
    // No timeline event: there is no per-entry date to place one at.
    assert!(
        j["timestamp"].is_null() && j["timestamp_desc"].is_null(),
        "a per-entry event at the key's time would date every entry to the newest"
    );
}

// --- Anchoring -------------------------------------------------------------

/// Both key forms are recognised, and the casing difference between them is
/// real: `MUICache` in `ShellNoRoam`, `MuiCache` in `UsrClass.dat`.
#[test]
fn both_muicache_key_forms_are_recognised_despite_the_casing_difference() {
    let xp =
        muicache_key(r"ROOT\Software\Microsoft\Windows\ShellNoRoam\MUICache").expect("the XP form");
    assert_eq!(xp, SourceForm::ShellNoRoam);
    let win7 = muicache_key(r"ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
        .expect("the Win7+ form");
    assert_eq!(win7, SourceForm::UsrClassShell);
    // And case-insensitively, since a hive holds either spelling.
    assert!(muicache_key(r"ROOT\software\microsoft\windows\shellnoroam\muicache").is_some());
}

/// Nothing else is a MUICache key.
#[test]
fn an_unrelated_key_is_not_a_muicache_key() {
    for p in [
        r"ROOT\Software\Microsoft\Windows\ShellNoRoam",
        r"ROOT\Software\Microsoft\Windows\ShellNoRoam\MUICache\Deeper",
        r"ROOT\Software\Microsoft\Windows\Shell\BagMRU",
    ] {
        assert!(muicache_key(p).is_none(), "for {p}");
    }
}

// --- End to end, on the real XP hive ---------------------------------------

/// The real plaso `NTUSER.DAT` holds a 131-value `MUICache`, and it must come
/// through paired, classified, and claiming nothing about execution.
#[test]
fn the_real_xp_muicache_comes_through_classified_and_claims_no_execution() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER.DAT", bytes);

    let coverage = all
        .iter()
        .find(|r| r["type"] == "MuiCacheCoverage")
        .expect("a real XP hive has a MUICache key, and its coverage must be reported");
    assert_eq!(coverage["source_form"], "shellnoroam");
    let total = coverage["values_total"].as_u64().unwrap_or(0);
    assert!(total > 100, "the real key holds 131 values, got {total}");
    assert_eq!(
        coverage["applications"].as_u64().unwrap_or(0)
            + coverage["bookkeeping_values"].as_u64().unwrap_or(0),
        total,
        "every value must land in one bucket or the other"
    );

    let entries: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "MuiCacheEntry")
        .collect();
    assert!(!entries.is_empty());

    // Resource references are present in this hive and none may be reported as
    // a path on the machine.
    let refs: Vec<_> = entries
        .iter()
        .filter(|e| e["target_kind"] == "resource_reference")
        .collect();
    assert!(
        !refs.is_empty(),
        "the XP form uses @dll,-id references and they must be classified as such"
    );
    for r in &refs {
        assert!(
            r["application_path"].is_null(),
            "a resource reference names no file: {:?}",
            r["value_names"]
        );
        assert!(r["resource_dll"].is_string());
    }

    // Not one entry claims execution, and not one raises a timeline event.
    for e in &entries {
        assert_eq!(
            e["execution_evidence"],
            serde_json::json!(false),
            "MUICache is not execution evidence: {:?}",
            e["name"]
        );
        assert_eq!(
            e["key_last_written_scope"],
            "the MUICache key, not this entry"
        );
    }
    assert!(
        !all.iter().any(|r| r["timestamp_desc"]
            .as_str()
            .unwrap_or("")
            .contains("MUICache")),
        "MUICache has no per-entry date, so it raises no timeline event"
    );
}
