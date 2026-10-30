//! What the ASEP detections must and must not raise.
//!
//! The division of labour is the thing under test.
//! `seance_plugin_asep` establishes where an autostart entry points and refuses
//! to judge it; this module judges the directory and nothing else. So the
//! assertions fall into three groups: the system directories raise nothing
//! ([`software_installed_where_software_belongs_raises_nothing`]), a path this
//! build cannot resolve raises nothing
//! ([`an_unresolved_path_is_never_classified`] — a classification of a path we
//! do not have is a guess), and the two tiers that do fire are pinned at
//! different confidences, because an Electron app in `\AppData\Roaming` and a
//! service running out of `\Temp` are not the same lead.

use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::{Confidence, FINDING_RECORD_TYPE};
use seance_core::module::ForensicsModule;
use serde_json::json;
use uuid::Uuid;

/// An `AsepEntry` record as the enumerator writes one, resolved against a
/// healthy file index.
fn asep_record(extra: serde_json::Value) -> Artifact {
    let mut m = json!({
        "type": "AsepEntry",
        "category": "run_key",
        "category_label": "Run key",
        "entry_name": "Updater",
        "asep_location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "asep_value_name": "Updater",
        "scope": "HKLM",
        "read_status": "parsed",
        "runs_when": "At every interactive logon.",
        "mitre_technique": "T1547.001",
        "enabled": true,
        "target_exists": "observed_at_path",
        "target_index_executable_names": 41_233,
        "target_index_capped": false,
    });
    let obj = m.as_object_mut().unwrap();
    for (k, v) in extra.as_object().unwrap() {
        obj.insert(k.clone(), v.clone());
    }
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, m)
}

/// An entry naming an image at `path`, whose normalised lookup is `lookup`.
fn at(path: &str, lookup: &str) -> Artifact {
    asep_record(json!({ "image_path": path, "target_lookup_path": lookup }))
}

/// An entry whose `image_path` is the Windows spelling of `lookup`.
///
/// The fixture that was missing, and its absence is why the classifier shipped
/// with a defect that fired 742 times on the first real image it saw: `at("x",
/// "/dropper.exe")` passed an `image_path` no enumerator would ever produce, so
/// every test exercised a shape the evidence does not have. This one derives
/// the raw value from the lookup the way `normalize_target` derives the lookup
/// from the raw value, so a test is about the same pair of strings the product
/// sees.
fn at_path(lookup: &str) -> Artifact {
    let windows = format!("C:{}", lookup.replace('/', "\\"));
    at(&windows, lookup)
}

fn kinds(a: &Artifact) -> Vec<String> {
    AsepFindings::new()
        .findings_for(a)
        .into_iter()
        .map(|f| f.kind)
        .collect()
}

#[test]
fn software_installed_where_software_belongs_raises_nothing() {
    for (path, lookup) in [
        (
            "C:\\Windows\\System32\\svchost.exe",
            "/windows/system32/svchost.exe",
        ),
        (
            "C:\\Program Files\\Vendor\\app.exe",
            "/program files/vendor/app.exe",
        ),
        (
            "C:\\Program Files (x86)\\Vendor\\app.exe",
            "/program files (x86)/vendor/app.exe",
        ),
        (
            "C:\\Windows\\SysWOW64\\thing.exe",
            "/windows/syswow64/thing.exe",
        ),
        ("C:\\Windows\\explorer.exe", "/windows/explorer.exe"),
    ] {
        assert!(kinds(&at(path, lookup)).is_empty(), "{lookup}");
    }
}

/// A path we do not have cannot be classified, and a sentence about it would
/// be a guess with a finding wrapped round it.
#[test]
fn an_unresolved_path_is_never_classified() {
    for lookup in [
        "%userprofile%/thing.exe", // no live environment to expand against
        "",
        "scecli.dll", // a bare DLL name: Windows resolves it from System32
    ] {
        let a = asep_record(json!({
            "image_path": "whatever",
            "target_lookup_path": lookup,
        }));
        assert!(kinds(&a).is_empty(), "{lookup:?}");
    }
    // And with no lookup path at all — an entry that names no image.
    let a = asep_record(json!({ "image_path": serde_json::Value::Null }));
    assert!(kinds(&a).is_empty());
}

#[test]
fn a_service_running_from_a_temporary_directory_is_a_notable_lead() {
    let a = asep_record(json!({
        "category": "service",
        "category_label": "Windows service",
        "image_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe",
        "target_lookup_path": "/users/jsmith/appdata/local/temp/svchost.exe",
        "user": "jsmith",
    }));

    let findings = AsepFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "persistence_in_unexpected_location");
    assert_eq!(f.confidence, Confidence::Notable);
    // The observation states the path and what is wrong with it, both
    // checkable against the record it points at.
    assert!(
        f.observation.contains("temporary directory"),
        "{}",
        f.observation
    );
    assert!(f
        .observation
        .contains("/users/jsmith/appdata/local/temp/svchost.exe"));
    // The inference is separate and is about installers, not about intent.
    assert!(f.inference.as_ref().unwrap().contains("installer"));
    // And the qualification concedes what Séance actually judged.
    assert!(
        f.qualification.contains("judged the directory"),
        "{}",
        f.qualification
    );
    assert!(f.qualification.contains("ever ran"));
    // The address of the persistence travels with it: without the key and the
    // value name the finding cannot be checked.
    let named: Vec<&str> = f.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(named.contains(&"asep_location"));
    assert!(named.contains(&"runs_when"));
    assert!(named.contains(&"mitre_technique"));
}

#[test]
fn the_recycle_bin_the_volume_root_and_a_download_are_all_notable() {
    for (lookup, expect) in [
        ("/$recycle.bin/s-1-5-21-1001/$ria4j2k.exe", "recycle bin"),
        ("/dropper.exe", "root of the volume"),
        ("/users/jsmith/downloads/setup.exe", "downloads"),
        ("/perflogs/a.exe", "performance-log"),
        ("/users/public/x.exe", "Public"),
        ("/windows/temp/x.exe", "temporary"),
    ] {
        let findings = AsepFindings::new().findings_for(&at_path(lookup));
        assert_eq!(findings.len(), 1, "{lookup}");
        assert_eq!(findings[0].confidence, Confidence::Notable, "{lookup}");
        assert!(
            findings[0].observation.contains(expect),
            "{lookup}: {}",
            findings[0].observation
        );
    }
}

/// The reason the weak tier exists. Every Electron application on earth
/// persists from `\AppData\Roaming`, so this must not rank beside a service
/// running out of `\Temp`.
#[test]
fn an_application_persisting_from_appdata_is_the_weak_tier_and_says_so() {
    let a = at(
        "C:\\Users\\jsmith\\AppData\\Roaming\\Vendor\\chat.exe",
        "/users/jsmith/appdata/roaming/vendor/chat.exe",
    );
    let findings = AsepFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.confidence, Confidence::Weak);
    // No inference: any reading of "an app persists from AppData" would be
    // this tool's invention, and the honest answer is that it means little.
    assert_eq!(f.inference, None);
    // The qualification says outright that this is expected on a healthy
    // machine, which is what an examiner ranking leads needs to know.
    assert!(
        f.qualification.contains("healthy machine"),
        "{}",
        f.qualification
    );
    assert!(f.qualification.contains("ranked last"));
}

/// `\AppData\Local\Temp` must not be read as `\AppData\Local`: longest match
/// wins or the interesting tier collapses into the noisy one.
#[test]
fn a_temporary_directory_under_appdata_keeps_its_higher_rank() {
    let notable =
        AsepFindings::new().findings_for(&at_path("/users/jsmith/appdata/local/temp/thing.exe"));
    let weak =
        AsepFindings::new().findings_for(&at_path("/users/jsmith/appdata/local/vendor/thing.exe"));
    assert_eq!(notable[0].confidence, Confidence::Notable);
    assert_eq!(weak[0].confidence, Confidence::Weak);
}

// --- what the CFReDS Hacking Case taught, 2026-09-14 --------------------------
//
// The first real image these detections were run against produced **1,186
// leads** on a 25,018-file XP volume. 742 of them came from one arm of the
// classifier and 42 from another, and both are here as fixtures now. A
// detection that fires on a thousand files does not add noise to a triage list
// — it buries the row that matters and teaches its reader to stop opening the
// screen. `HUNT-051` recorded that once already.

/// **742 leads on one image.** `normalize_target` guarantees its output a
/// leading `/`, so a bare program name arrives as `/regsvr32.exe` — shaped
/// exactly like a file at the root of the volume. COM in-process servers,
/// `KnownDLLs`, shell extensions, netsh helpers, Winlogon notify packages,
/// print monitors and LSA packages all name a DLL Windows resolves **by name
/// from the system directory**, and every one of them was reported as
/// persistence running from the root of the volume.
///
/// The raw values below are verbatim from that run.
#[test]
fn a_bare_program_name_is_not_a_file_at_the_root_of_the_volume() {
    for raw in [
        "regsvr32.exe",
        "rundll32 iesetup.dll,IEAccessUserInst",
        "RunDLL32 IEDKCS32.DLL,BrandIE4 SIGNUP",
        "scecli.dll",
        "shell32.dll",
    ] {
        // What the ASEP normaliser hands the classifier for each of them.
        let lookup = format!("/{}", raw.to_ascii_lowercase());
        let a = asep_record(json!({
            "category": "com_server",
            "category_label": "COM server",
            "image_path": raw,
            "target_lookup_path": lookup,
        }));
        assert!(
            kinds(&a).is_empty(),
            "{raw:?} is a name Windows resolves, not a location: {:?}",
            AsepFindings::new()
                .findings_for(&a)
                .iter()
                .map(|f| f.observation.clone())
                .collect::<Vec<_>>()
        );
    }
}

/// And the arm still works for the thing it exists to catch: a real path at the
/// root of the volume. The raw value is what separates the two — it carries a
/// drive letter or a separator, and a bare name carries neither.
#[test]
fn a_real_path_at_the_root_of_the_volume_is_still_notable() {
    let a = asep_record(json!({
        "image_path": "C:\\dropper.exe",
        "target_lookup_path": "/dropper.exe",
    }));
    let findings = AsepFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    assert_eq!(findings[0].confidence, Confidence::Notable);
    assert!(findings[0].observation.contains("root of the volume"));

    // A forward-slash path and a UNC path are paths too.
    for raw in ["C:/dropper.exe", "\\\\host\\share\\dropper.exe"] {
        let a = asep_record(json!({
            "image_path": raw,
            "target_lookup_path": "/dropper.exe",
        }));
        assert_eq!(kinds(&a).len(), 1, "{raw:?}");
    }
}

/// **42 leads on one image.** The registry writes 8.3 short names as often as
/// long ones, and `/progra~1/common~1/micros~1/msinfo/ieinfo5.ocx` is
/// `C:\Program Files\Common Files\Microsoft Shared\MSInfo\…` — a genuine
/// program directory, graded "outside the system and program directories".
#[test]
fn an_eight_dot_three_program_files_path_is_a_program_directory() {
    for lookup in [
        "/progra~1/common~1/micros~1/msinfo/ieinfo5.ocx",
        "/progra~1/anonym~1/core/anonym~1.dll",
        "/progra~2/vendor/app.exe",
    ] {
        assert!(
            kinds(&at_path(lookup)).is_empty(),
            "{lookup} is a program directory in 8.3 form"
        );
    }
    // The pre-Vista profile root, long and short, is the weak tier — not
    // "somewhere outside the system and program directories", which read as a
    // stronger statement than it is.
    for lookup in [
        "/documents and settings/jsmith/app/x.exe",
        "/docume~1/jsmith/app/x.exe",
    ] {
        let f = AsepFindings::new().findings_for(&at_path(lookup));
        assert_eq!(f.len(), 1, "{lookup}");
        assert_eq!(f[0].confidence, Confidence::Weak, "{lookup}");
        assert!(f[0].observation.contains("user profile"), "{lookup}");
    }
}

/// `WINNT` is the Windows directory on an upgraded 2000/XP install, and its
/// temporary and debug directories keep the higher rank the way `\Windows`'s
/// do.
#[test]
fn the_winnt_directory_is_a_system_directory_and_its_temp_is_not() {
    assert!(kinds(&at_path("/winnt/system32/svchost.exe")).is_empty());
    assert!(kinds(&at_path("/winnt/explorer.exe")).is_empty());
    let f = AsepFindings::new().findings_for(&at_path("/winnt/temp/x.exe"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, Confidence::Notable);
    assert!(f[0].observation.contains("temporary directory"));
}

/// The second false positive from the same run, and the subtler one: an
/// argument can carry separators while the image does not. `BootExecute` holds
/// `autoconv \??\Volume{…} /fs:ntfs` — reading the whole string called it a
/// path and reported the root of the volume.
#[test]
fn an_argument_that_looks_like_a_path_does_not_make_the_image_one() {
    for raw in [
        "autoconv \\??\\Volume{aa630442-f1ff-11d8-8a13-806d6172696f} /fs:ntfs",
        "autocheck autochk *",
        "regsvr32.exe /s /n /i:U shell32.dll",
        "rundll32 setupapi,InstallHinfSection DefaultInstall 128 C:\\WINNT\\inf\\x.inf",
    ] {
        let a = asep_record(json!({
            "category": "boot_execute",
            "image_path": raw,
            // Whatever the normaliser made of it.
            "target_lookup_path": "/autoconv /??/volume{aa630442}",
        }));
        assert!(kinds(&a).is_empty(), "{raw:?}");
    }
    // And a quoted path IS an image, quotes and all.
    let a = asep_record(json!({
        "image_path": "\"C:\\Windows\\Temp\\thing.exe\" -silent",
        "target_lookup_path": "/windows/temp/thing.exe",
    }));
    assert_eq!(kinds(&a).len(), 1, "a quoted path is still a path");
}

/// The Startup folder is where startup items belong, so the default location
/// is not a lead. Five rows on the Hacking Case said nothing more than
/// "Windows is installed"; where a redirect points somewhere else,
/// `seance_plugin_asep` says so with its own observation.
#[test]
fn the_default_startup_folder_is_not_an_unexpected_location() {
    for lookup in [
        "/documents and settings/all users/start menu/programs/startup",
        "/documents and settings/mr. evil/start menu/programs/startup",
        "/documents and settings/networkservice/start menu/programs/startup",
        "/users/jsmith/appdata/roaming/microsoft/windows/start menu/programs/startup",
        "/programdata/microsoft/windows/start menu/programs/startup",
    ] {
        assert!(
            kinds(&at_path(lookup)).is_empty(),
            "{lookup} is the default Startup folder"
        );
    }
    // A redirect pointing at a temporary directory is still a lead: the
    // Startup exemption is for the Startup folder, not for anything a
    // `startup_folder_redirect` value happens to name.
    let f = AsepFindings::new().findings_for(&at_path("/windows/temp/start menu/programs/startup"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, Confidence::Notable);
}

/// An entry that names no image at all has nothing to classify, and a command
/// line is not offered as a substitute: `regsvr32.exe /s /n /i:U shell32.dll`
/// is not a path either.
#[test]
fn a_command_line_is_not_accepted_as_an_image_path() {
    let a = asep_record(json!({
        "command": "regsvr32.exe /s /n /i:U shell32.dll",
        "target_lookup_path": "/regsvr32.exe",
    }));
    assert!(kinds(&a).is_empty());
}

#[test]
fn persistence_pointing_at_a_file_that_was_not_recovered_is_a_weak_lead() {
    let a = asep_record(json!({
        "image_path": "C:\\Program Files\\Gone\\gone.exe",
        "target_lookup_path": "/program files/gone/gone.exe",
        "target_exists": "not_observed",
        "target_exists_basis": "No file was recovered at that path among the 41233 executable \
                                names enumerated. This is not proof the file is absent.",
    }));

    let findings = AsepFindings::new().findings_for(&a);
    // The image is in Program Files, so the location detection is silent and
    // this is the only finding.
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "persistence_target_not_recovered");
    assert_eq!(f.confidence, Confidence::Weak);
    // The size of the search is in the observation, because the answer is
    // worth exactly as much as the search behind it.
    assert!(f.observation.contains("41233"), "{}", f.observation);
    assert_eq!(f.inference, None);
    // The ordinary cause is named, and so is the limit of the comparison.
    assert!(
        f.qualification.contains("uninstaller"),
        "{}",
        f.qualification
    );
    assert!(
        f.qualification.contains("not the whole volume")
            || f.qualification.contains("not the \n whole volume")
            || f.qualification.contains("whole volume")
    );
    // The enumerator's own basis sentence is the one to quote, so it travels.
    assert!(f.evidence.iter().any(|e| e.name == "target_exists_basis"));
}

/// "Not observed" is only worth raising when the search behind it meant
/// something. Each of these is a question that was not asked.
#[test]
fn a_target_question_that_was_not_asked_raises_nothing() {
    for extra in [
        // The index filled up before the volume was exhausted.
        json!({
            "target_exists": "not_observed",
            "target_index_capped": true,
        }),
        // No filesystem was enumerated at all.
        json!({ "target_exists": "no_file_index", "target_index_executable_names": 0 }),
        json!({ "target_exists": "not_observed", "target_index_executable_names": 0 }),
        // A name match elsewhere is a different, weaker answer.
        json!({ "target_exists": "observed_by_name_only" }),
        json!({ "target_exists": "unresolved_environment_variable" }),
        json!({ "target_exists": "not_applicable" }),
    ] {
        let mut m = json!({
            "image_path": "C:\\Program Files\\Gone\\gone.exe",
            "target_lookup_path": "/program files/gone/gone.exe",
        });
        for (k, v) in extra.as_object().unwrap() {
            m.as_object_mut().unwrap().insert(k.clone(), v.clone());
        }
        let a = asep_record(m);
        assert!(kinds(&a).is_empty(), "{extra}");
    }
}

/// An entry the enumerator could not read has no image to judge. The record
/// already says so; a finding from it would be a claim about a value nobody
/// has seen.
#[test]
fn an_unread_entry_raises_nothing() {
    let a = asep_record(json!({
        "read_status": "unread",
        "read_status_reason": "the task XML could not be parsed",
        "image_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\x.exe",
        "target_lookup_path": "/users/jsmith/appdata/local/temp/x.exe",
    }));
    assert!(kinds(&a).is_empty());
}

#[test]
fn only_an_asep_record_is_examined() {
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "NtfsFileName",
            "target_lookup_path": "/users/jsmith/appdata/local/temp/x.exe",
        }),
    );
    assert!(kinds(&a).is_empty());
}

/// Both detections can fire on one entry, and the triage list wants both.
#[test]
fn an_absent_image_in_a_temporary_directory_raises_both_leads() {
    let a = asep_record(json!({
        "image_path": "C:\\Windows\\Temp\\gone.exe",
        "target_lookup_path": "/windows/temp/gone.exe",
        "target_exists": "not_observed",
    }));
    let out = AsepFindings::new().process(&a).expect("processed");
    assert_eq!(out.len(), 2);
    for rec in &out {
        assert_eq!(rec.metadata["type"], FINDING_RECORD_TYPE);
        assert_eq!(rec.metadata["grade"], "investigative_lead");
        assert!(!rec.metadata["qualification"].as_str().unwrap().is_empty());
    }
    assert_eq!(out[0].metadata["confidence"], "notable");
    assert_eq!(out[1].metadata["confidence"], "weak");
}

// ---------------------------------------------------------------------------
// HUNT-276: a registered service whose binary looks dropped into System32.
//
// The first fixture is a TRANSCRIPTION of the `coreupdater` AsepEntry the
// ingest wrote for the DFIR Madness Case 001 DESKTOP image (see VALIDATION.md,
// "HUNT-276 / C001-FIND-1 re-measure 2026-10-20"). It is not a synthetic grade;
// the others vary one field of it to show which field the rule reads.
// ---------------------------------------------------------------------------

fn case001_coreupdater(extra: serde_json::Value) -> Artifact {
    let mut base = json!({
        "category": "service",
        "category_label": "Service or driver",
        "entry_name": "coreupdater",
        "asep_location": "ROOT\\ControlSet001\\Services\\coreupdater",
        "scope": "HKLM",
        "image_path": "C:\\Windows\\System32\\coreupdater.exe",
        "target_lookup_path": "/windows/system32/coreupdater.exe",
        "service_start_type": 2,
        "service_type": 16,
        "service_account": "LocalSystem",
        "target_exists": "observed_at_path",
    });
    for (k, v) in extra.as_object().unwrap() {
        base.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    asep_record(base)
}

const UNRECOGNISED: &str = "service_binary_unrecognised_in_system_directory";

#[test]
fn case001_coreupdater_raises_a_weak_system_directory_service_lead() {
    let a = case001_coreupdater(json!({}));
    let findings = AsepFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, UNRECOGNISED);
    assert_eq!(f.confidence, Confidence::Weak);
    assert!(f.inference.is_none());
    assert!(
        f.observation.contains("coreupdater.exe"),
        "{}",
        f.observation
    );
    assert!(
        f.qualification.contains("did not examine"),
        "{}",
        f.qualification
    );
    assert!(f.qualification.contains("evaded"), "{}", f.qualification);
}

#[test]
fn a_systemroot_spelled_service_raises_nothing() {
    let a = case001_coreupdater(json!({
        "entry_name": "Spooler",
        "image_path": "%SystemRoot%\\System32\\spoolsv.exe",
    }));
    assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()));
}

#[test]
fn a_literal_path_svchost_service_raises_nothing() {
    let a = case001_coreupdater(json!({
        "image_path": "C:\\Windows\\system32\\svchost.exe",
        "target_lookup_path": "/windows/system32/svchost.exe",
    }));
    assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()));
}

#[test]
fn a_manual_start_service_raises_nothing() {
    let a = case001_coreupdater(json!({ "service_start_type": 3 }));
    assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()));
}

#[test]
fn an_unobserved_target_raises_no_system_directory_lead() {
    for status in ["not_observed", "name_only", "no_file_index"] {
        let a = case001_coreupdater(json!({ "target_exists": status }));
        assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()), "{status}");
    }
}

#[test]
fn a_kernel_driver_raises_no_system_directory_lead() {
    let a = case001_coreupdater(json!({ "service_type": 1 }));
    assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()));
}

#[test]
fn an_unread_service_raises_no_system_directory_lead() {
    let a = case001_coreupdater(json!({ "read_status": "unread" }));
    assert!(kinds(&a).is_empty());
}

// --- HUNT-276: a file created before the system finished installing is a component of the install -----------

fn msdtc(created: &str, installed: &str) -> Artifact {
    case001_coreupdater(json!({
        "entry_name": "MSDTC",
        "image_path": "C:\\Windows\\System32\\msdtc.exe",
        "target_lookup_path": "/windows/system32/msdtc.exe",
        "target_created": created,
        "os_install_time": installed,
        "os_install_time_basis": "SOFTWARE hive Microsoft\\Windows NT\\CurrentVersion\\InstallDate",
    }))
}

/// The clean Windows Server 2003 R2 SP2 x64 install of `VALIDATION.md`: `msdtc.exe` was created at 16:20:16Z,
/// the SOFTWARE hive says setup finished at 16:27:45Z. A file in place before that is not a service added after
/// the install, so the lead the rule used to raise on it is not raised.
#[test]
fn a_service_file_created_before_the_install_finished_raises_no_lead() {
    let a = msdtc("2026-10-22T16:20:16.9057500Z", "2026-10-22T16:27:45Z");
    assert!(!kinds(&a).contains(&UNRECOGNISED.to_string()));
}

/// Case 001's implant was written at 03:24:12Z, after the OS install: the lead stays, and carries both times.
#[test]
fn a_service_file_created_after_the_install_keeps_its_lead_and_shows_both_times() {
    let a = msdtc("2020-09-19T03:24:12Z", "2020-09-17T19:34:46Z");
    let findings = AsepFindings::new().findings_for(&a);
    let f = findings
        .iter()
        .find(|f| f.kind == UNRECOGNISED)
        .expect("a lead");
    let has = |k: &str, v: &str| f.evidence.iter().any(|e| e.name == k && e.value == v);
    assert!(has("target_created", "2020-09-19T03:24:12Z"));
    assert!(has("os_install_time", "2020-09-17T19:34:46Z"));
}

/// Without both times, or with one that does not parse, nothing is compared and the lead stands as before.
#[test]
fn a_missing_or_unreadable_time_leaves_the_lead_in_place() {
    for (created, installed) in [
        ("", "2020-09-17T19:34:46Z"),
        ("2020-09-19T03:24:12Z", ""),
        ("yesterday", "2020-09-17T19:34:46Z"),
    ] {
        let mut a = msdtc(created, installed);
        let m = a.metadata.as_object_mut().unwrap();
        if created.is_empty() {
            m.remove("target_created");
        }
        if installed.is_empty() {
            m.remove("os_install_time");
        }
        assert!(
            kinds(&a).contains(&UNRECOGNISED.to_string()),
            "{created:?} {installed:?}"
        );
    }
}

/// A service read out of the setup-time copy of the SYSTEM hive under `\Windows\repair` was registered during setup, before the
/// install finished, whichever order the hives were read in: no lead (`HUNT-276`: the clean Server 2003's last false lead came
/// from that copy, read before the SOFTWARE hive held the install time). The live hive raises it as before.
#[test]
fn a_service_in_the_setup_time_repair_copy_of_the_system_hive_raises_no_lead() {
    let repair = case001_coreupdater(json!({
        "hive_path": "/Windows/repair/system",
        "os_install_time_basis": "no SOFTWARE hive InstallDate had been read when this entry was made",
    }));
    assert!(!kinds(&repair).contains(&UNRECOGNISED.to_string()));
    let live = case001_coreupdater(json!({ "hive_path": "/Windows/System32/config/SYSTEM" }));
    assert!(kinds(&live).contains(&UNRECOGNISED.to_string()));
    // A path that only mentions the word is not the repair directory.
    let other = case001_coreupdater(json!({ "hive_path": "/Users/repair/system" }));
    assert!(kinds(&other).contains(&UNRECOGNISED.to_string()));
}
