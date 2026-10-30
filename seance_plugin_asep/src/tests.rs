//! Tests for the ASEP enumerator.
//!
//! The failure paths get at least as much attention as the success paths,
//! because the defect this crate is built against is silent omission: a
//! category that never appears, an entry that is dropped because it would not
//! decode, a timestamp invented to fill a hole. Each of those has a test that
//! fails if it comes back.

use super::*;
use crate::coverage::{build_coverage_artifact, CoverageStatus, HiveScanSummary};
use crate::index::{EvidenceIndex, TargetStatus};
use crate::normalize::*;
use crate::record::{AsepEntry, EmitContext, InstalledTime, LocationKind, ReadStatus};
use crate::registry::{scan, RegistryScanInput};
use crate::rules::{category, CategorySource, HiveKind, CATEGORIES};
use crate::startup::{classify_startup_path, parse_lnk, LnkError};
use crate::task_xml::{
    decode, looks_like_task_xml, parse as parse_task, TaskAction, TaskParseError,
};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

// --- fixtures ----------------------------------------------------------------

/// An in-memory data source for an artifact under test.
fn source(bytes: Vec<u8>) -> Option<Arc<dyn DataSource>> {
    Some(Arc::new(ByteSliceDataSource::new(bytes)) as Arc<dyn DataSource>)
}

/// One-shot form of [`key_lower_into`], for readability in assertions.
fn key_lower(key_path: &str) -> String {
    let mut out = String::new();
    key_lower_into(key_path, &mut out);
    out
}

fn rv(key_path: &str, value_name: &str, value_data: &str) -> Value {
    json!({
        "key_path": key_path,
        "value_name": value_name,
        "value_type": "RegSZ",
        "value_data": value_data,
        "raw_data_size": value_data.len(),
    })
}

fn dword(key_path: &str, value_name: &str, v: u32) -> Value {
    json!({
        "key_path": key_path,
        "value_name": value_name,
        "value_type": "RegDword",
        "value_data": format!("0x{:08x} ({})", v, v),
        "raw_data_size": 4,
    })
}

fn run_scan(hive_name: &str, values: &[Value]) -> crate::registry::RegistryScanOutput {
    let kind = HiveKind::from_hive_name(hive_name);
    scan(&RegistryScanInput {
        hive_name,
        hive_kind: kind,
        hive_path: None,
        user: None,
        values,
        values_total: values.len(),
        keys_total: values.len(),
    })
}

fn find<'a>(entries: &'a [AsepEntry], category: &str) -> Vec<&'a AsepEntry> {
    entries.iter().filter(|e| e.category == category).collect()
}

// --- normalisation -----------------------------------------------------------

#[test]
fn key_lowering_normalises_separators_and_case() {
    assert_eq!(key_lower("HKLM/Software\\Foo"), "hklm\\software\\foo");
}

#[test]
fn a_suffix_only_matches_on_a_whole_key_segment() {
    let k = key_lower(r"ROOT\Microsoft\Windows\CurrentVersion\Run");
    assert!(ends_with_key(&k, "currentversion\\run"));
    let decoy = key_lower(r"ROOT\Microsoft\Windows\CurrentVersion\NotRun");
    assert!(
        !ends_with_key(&decoy, "currentversion\\run"),
        "a key named NotRun must not match the Run rule, or the report gains a \
         fabricated autostart entry"
    );
}

#[test]
fn the_segment_after_a_marker_is_returned_and_an_absent_marker_is_none() {
    let k = key_lower(r"ROOT\ControlSet001\Services\Spooler\Parameters");
    assert_eq!(segment_after(&k, "\\services\\"), Some("spooler"));
    assert_eq!(tail_after_segment(&k, "\\services\\"), Some("parameters"));
    assert_eq!(segment_after(&k, "\\nosuchmarker\\"), None);
}

#[test]
fn a_quoted_command_splits_at_the_closing_quote() {
    let split = split_command("\"C:\\Program Files\\App\\app.exe\" -silent").unwrap();
    assert_eq!(split.image, "C:\\Program Files\\App\\app.exe");
    assert_eq!(split.arguments.as_deref(), Some("-silent"));
    assert_eq!(split.basis, SplitBasis::QuotedImage);
}

#[test]
fn an_unquoted_command_splits_at_the_executable_extension_not_at_a_space() {
    let split = split_command("C:\\Program Files\\App\\app.exe -silent").unwrap();
    assert_eq!(
        split.image, "C:\\Program Files\\App\\app.exe",
        "splitting at the first space would report a non-existent 'C:\\Program' image"
    );
    assert_eq!(split.arguments.as_deref(), Some("-silent"));
    assert_eq!(split.basis, SplitBasis::ExecutableExtension);
}

/// A bare program name followed by a script is the program and its argument,
/// not one image with a space in it. Windows 7's stock WMI consumer
/// (`BVTConsumer`, `WMI-1` in `documentation/VALIDATION.md`) stores
/// `cscript KernCap.vbs`; the extension boundary fell after `.vbs`, so the
/// record's image was `cscript KernCap.vbs`, its arguments were none, and its
/// file lookup asked for `/cscript kerncap.vbs`. `CreateProcess` itself tries
/// the shortest space-delimited prefix first, and a first token with no
/// directory, drive or extension is a name resolved on the search path.
#[test]
fn a_bare_program_name_before_a_script_is_the_image_and_the_script_its_argument() {
    let split = split_command("cscript KernCap.vbs").unwrap();
    assert_eq!(split.image, "cscript");
    assert_eq!(split.arguments.as_deref(), Some("KernCap.vbs"));
    assert_eq!(split.basis, SplitBasis::BareProgramName);

    let split = split_command("wscript //B C:\\Tools\\run.vbs").unwrap();
    assert_eq!(split.image, "wscript");
    assert_eq!(split.arguments.as_deref(), Some("//B C:\\Tools\\run.vbs"));

    // A directory path with a space in it is still one image.
    let split = split_command("C:\\Program Files\\App\\app.exe -silent").unwrap();
    assert_eq!(split.image, "C:\\Program Files\\App\\app.exe");
    assert_eq!(split.basis, SplitBasis::ExecutableExtension);
}

#[test]
fn a_command_with_no_recognisable_boundary_keeps_the_whole_value_and_says_so() {
    let split = split_command("some opaque directive").unwrap();
    assert_eq!(split.image, "some opaque directive");
    assert!(split.arguments.is_none());
    assert_eq!(split.basis, SplitBasis::WholeValueNoBoundary);
}

#[test]
fn an_empty_command_yields_no_split_at_all() {
    assert!(split_command("   ").is_none());
    assert!(split_command("").is_none());
}

#[test]
fn a_drive_letter_and_the_nt_object_prefix_are_stripped_for_lookup() {
    let t = normalize_target("C:\\Windows\\System32\\svchost.exe").unwrap();
    assert_eq!(t.lookup, "/windows/system32/svchost.exe");
    let t = normalize_target("\\??\\C:\\Windows\\notepad.exe").unwrap();
    assert_eq!(t.lookup, "/windows/notepad.exe");
    assert!(t.expansion.is_some());
}

#[test]
fn the_documented_system_root_forms_expand_and_record_the_expansion() {
    for raw in [
        "%SystemRoot%\\System32\\x.exe",
        "%windir%\\System32\\x.exe",
        "\\SystemRoot\\System32\\x.exe",
        "System32\\x.exe",
    ] {
        let t = normalize_target(raw).unwrap();
        assert_eq!(t.lookup, "/windows/system32/x.exe", "for {raw}");
        assert!(
            t.expansion.is_some(),
            "an expansion must be recorded so the report never presents it as stored"
        );
        assert!(!t.has_unexpanded_variable);
    }
}

#[test]
fn an_unknown_environment_variable_is_flagged_rather_than_guessed_at() {
    let t = normalize_target("%TEMP%\\a.exe").unwrap();
    assert!(
        t.has_unexpanded_variable,
        "there is no live environment to expand %TEMP% against; guessing would make the \
         existence answer worthless"
    );
}

#[test]
fn a_dword_is_read_from_the_rendered_form_and_junk_yields_none() {
    assert_eq!(parse_dword("0x00000002 (2)"), Some(2));
    assert_eq!(parse_dword("4"), Some(4));
    assert_eq!(parse_dword("0x10"), Some(16));
    assert_eq!(
        parse_dword("(invalid DWORD)"),
        None,
        "a corrupt Start value must not decode to 0, which reads as a boot-start driver"
    );
}

#[test]
fn a_multi_sz_rendering_splits_back_into_its_elements() {
    assert_eq!(
        split_multi_sz("msv1_0 | kerberos |  "),
        vec!["msv1_0".to_string(), "kerberos".to_string()]
    );
    assert!(split_multi_sz("   ").is_empty());
}

#[test]
fn the_system_directory_boundary_is_recognised_for_both_bitnesses() {
    assert!(is_under_system_directory("/windows/system32/a.dll"));
    assert!(is_under_system_directory("/windows/syswow64/a.dll"));
    assert!(!is_under_system_directory("/programdata/a.dll"));
}

#[test]
fn only_executable_file_types_are_treated_as_plausible_asep_targets() {
    assert!(is_executable_like("a.exe"));
    assert!(is_executable_like("A.DLL"));
    assert!(!is_executable_like("notes.txt"));
    assert!(!is_executable_like("noextension"));
}

// --- the category table ------------------------------------------------------

#[test]
fn every_category_id_the_enumerators_emit_has_a_table_entry() {
    // Emitting a category with no table entry would put a record in the case
    // with no ATT&CK mapping and no "where we looked" statement.
    for id in [
        "run_key",
        "startup_folder",
        "startup_folder_redirect",
        "winlogon_shell",
        "winlogon_userinit",
        "winlogon_notify",
        "winlogon_other",
        "ifeo_debugger",
        "appinit_dlls",
        "appcert_dlls",
        "boot_execute",
        "known_dlls",
        "active_setup",
        "service",
        "lsa_authentication_package",
        "lsa_notification_package",
        "lsa_security_package",
        "print_monitor",
        "print_processor",
        "netsh_helper",
        "winsock_provider",
        "network_provider",
        "com_server",
        "shell_extension",
        "browser_helper_object",
        "scheduled_task",
        "scheduled_task_registration",
        "wmi_mof_autorecover",
        "wmi_event_subscription",
    ] {
        assert!(category(id).is_some(), "no table entry for category {id}");
    }
}

#[test]
fn a_category_without_an_exact_attack_mapping_carries_a_note_explaining_the_approximation() {
    for info in CATEGORIES {
        if info.technique == Some("T1547") {
            assert!(
                info.technique_note.is_some(),
                "{} maps to the parent technique and must say why",
                info.id
            );
        }
        assert!(
            info.technique.is_some(),
            "{} has no ATT&CK technique at all",
            info.id
        );
        assert!(
            !info.locations.is_empty(),
            "{} states no locations, so the report cannot say where we looked",
            info.id
        );
    }
}

#[test]
fn the_wmi_repository_category_states_what_the_record_scan_does_not_read() {
    let wmi = category("wmi_event_subscription").unwrap();
    assert_eq!(wmi.source, CategorySource::WmiRepository);
    assert!(wmi.unexamined_reason.is_none());
    let reason = wmi.partial_reason.expect("a partial reason");
    assert!(reason.contains("OBJECTS.DATA"));
    assert!(reason.contains("INDEX.BTR") && reason.contains("MAPPING"));
    assert!(wmi
        .locations
        .iter()
        .any(|l| l.contains("Repository\\FS\\OBJECTS.DATA")));
}

#[test]
fn hive_names_classify_including_the_default_profile_hive() {
    assert_eq!(HiveKind::from_hive_name("SOFTWARE"), HiveKind::Software);
    assert_eq!(HiveKind::from_hive_name("SYSTEM"), HiveKind::System);
    assert_eq!(HiveKind::from_hive_name("NTUSER.DAT"), HiveKind::NtUser);
    assert_eq!(HiveKind::from_hive_name("DEFAULT"), HiveKind::NtUser);
    assert_eq!(HiveKind::from_hive_name("USRCLASS.DAT"), HiveKind::UsrClass);
    assert_eq!(HiveKind::from_hive_name("SAM"), HiveKind::Other);
}

// --- target resolution -------------------------------------------------------

#[test]
fn an_entry_with_no_image_resolves_to_not_applicable_not_to_not_found() {
    let index = EvidenceIndex::new();
    let res = index.resolve(None);
    assert_eq!(res.status, TargetStatus::NotApplicable);
}

#[test]
fn with_no_files_enumerated_the_answer_is_no_index_rather_than_not_observed() {
    let index = EvidenceIndex::new();
    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert_eq!(
        res.status,
        TargetStatus::NoFileIndex,
        "reporting 'not observed' with an empty index would imply the file is missing"
    );
    assert!(res.basis.contains("not a statement"));
}

#[test]
fn a_target_recovered_at_the_named_path_resolves_exactly() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/svchost.exe");
    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert_eq!(res.status, TargetStatus::ObservedAtPath);
    assert_eq!(
        res.lookup_path.as_deref(),
        Some("/windows/system32/svchost.exe")
    );
}

#[test]
fn a_same_named_file_elsewhere_resolves_by_name_only_and_says_the_path_differs() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Users/alice/AppData/Local/svchost.exe");
    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert_eq!(res.status, TargetStatus::ObservedByNameOnly);
    assert!(res.basis.contains("the name matches but the path"));
}

#[test]
fn an_unseen_target_is_reported_as_not_observed_and_never_as_absent() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/svchost.exe");
    let res = index.resolve(Some("C:\\Temp\\implant.exe"));
    assert_eq!(res.status, TargetStatus::NotObserved);
    assert!(
        res.basis.contains("not proof that the target is absent"),
        "the index is partial by construction and the record must say so"
    );
}

#[test]
fn an_unexpandable_variable_prevents_a_path_comparison_and_is_reported_as_such() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/svchost.exe");
    let res = index.resolve(Some("%TEMP%\\implant.exe"));
    assert_eq!(res.status, TargetStatus::UnresolvedVariable);
    assert!(res.basis.contains("environment variable"));
}

/// `HUNT-241`: a bare program name (`cscript`, split from `cscript KernCap.vbs`)
/// is resolved on the Windows search path, not looked up at the volume root.
#[test]
fn a_bare_program_name_is_resolved_on_the_search_path_not_at_the_volume_root() {
    let t = normalize_target("cscript").unwrap();
    assert_ne!(
        t.lookup, "/cscript",
        "a bare name is not a file at the volume root; Windows finds it on the search path"
    );

    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/svchost.exe");
    index.note_file("/Windows/System32/cscript.exe");
    let res = index.resolve(Some("cscript"));
    assert_eq!(
        res.status,
        TargetStatus::ObservedAtPath,
        "cscript.exe was recovered in System32, the first search-path directory: {}",
        res.basis
    );
    assert_eq!(
        res.lookup_path.as_deref(),
        Some("/windows/system32/cscript.exe")
    );
    assert_eq!(
        res.search_path_directory.as_deref(),
        Some("\\Windows\\System32")
    );
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_OBSERVED)
    );
    assert!(res.basis.contains("search path"), "{}", res.basis);
}

#[test]
fn a_bare_name_tries_every_search_directory_and_pathext_extension_in_order() {
    let t = normalize_target("cscript").unwrap();
    assert_eq!(t.search_path_candidates.len(), 12);
    assert_eq!(t.search_path_candidates[0], "/windows/system32/cscript.com");
    assert_eq!(t.search_path_candidates[1], "/windows/system32/cscript.exe");
    assert_eq!(t.search_path_candidates[4], "/windows/syswow64/cscript.com");
    assert_eq!(t.search_path_candidates[11], "/windows/cscript.cmd");
    assert!(t.expansion.is_some_and(|e| e.contains("search path")));

    // A bare name with its own executable extension is not given another.
    let t = normalize_target("rundll32.exe").unwrap();
    assert_eq!(
        t.search_path_candidates,
        vec![
            "/windows/system32/rundll32.exe",
            "/windows/syswow64/rundll32.exe",
            "/windows/rundll32.exe",
        ]
    );

    // A path is not a bare name.
    for raw in ["C:\\Windows\\x.exe", "System32\\x.exe", "%TEMP%\\x.exe"] {
        assert!(
            normalize_target(raw)
                .unwrap()
                .search_path_candidates
                .is_empty(),
            "{raw}"
        );
    }
}

#[test]
fn a_bare_name_found_only_in_syswow64_says_syswow64_answered() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/SysWOW64/cscript.exe");
    let res = index.resolve(Some("cscript"));
    assert_eq!(res.status, TargetStatus::ObservedAtPath);
    assert_eq!(
        res.lookup_path.as_deref(),
        Some("/windows/syswow64/cscript.exe")
    );
    assert_eq!(
        res.search_path_directory.as_deref(),
        Some("\\Windows\\SysWOW64")
    );
}

#[test]
fn a_bare_name_not_on_the_search_path_is_not_observed_and_says_the_lookup_is_convention() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/svchost.exe");
    let res = index.resolve(Some("cscript"));
    assert_eq!(res.status, TargetStatus::NotObserved);
    assert!(res.basis.contains("not proof that the target is absent"));
    assert_eq!(res.search_path_directory, None);
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_CONVENTION)
    );

    // Same name elsewhere: a name match, and no search-path directory claimed.
    index.note_file("/tools/kernrate/cscript.exe");
    let res = index.resolve(Some("cscript"));
    assert_eq!(res.status, TargetStatus::ObservedByNameOnly);
    assert_eq!(res.search_path_directory, None);
    assert_eq!(res.observed_paths, vec!["/tools/kernrate/cscript.exe"]);

    // No index at all: no-file-index, with the lookup marked as convention.
    let res = EvidenceIndex::new().resolve(Some("cscript"));
    assert_eq!(res.status, TargetStatus::NoFileIndex);
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_CONVENTION)
    );
    assert_eq!(res.search_path_candidates.len(), 12);
}

/// `HUNT-244`: a copy planted in the working directory a WMI consumer records
/// is found there before the System32 copy, and the answer says it was found in
/// the working directory — not that it is the copy Windows loaded.
#[test]
fn a_bare_name_is_tried_in_the_recorded_working_directory_before_the_system_directories() {
    let ctx = SearchContext {
        rule: SearchRule::CreateProcessExeOnly,
        working_directory: Some("C:\\\\tools\\\\kernrate".to_string()),
    };
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/cscript.exe");
    index.note_file("/tools/kernrate/cscript.exe");
    let res = index.resolve_in(Some("cscript"), &ctx);
    assert_eq!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    assert_eq!(
        res.lookup_path.as_deref(),
        Some("/tools/kernrate/cscript.exe")
    );
    assert_eq!(
        res.search_path_directory.as_deref(),
        Some("C:\\tools\\kernrate")
    );
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_OBSERVED_IN_WORKING_DIRECTORY)
    );
    assert_eq!(res.search_rule, Some("create_process_exe_only"));
    assert!(res.basis.contains("not proof") || res.basis.contains("rather than proof"));
    assert!(res.basis.contains("CreateProcess's"), "{}", res.basis);
}

#[test]
fn the_create_process_rule_appends_only_exe_and_takes_any_extension_as_given() {
    let ctx = SearchContext {
        rule: SearchRule::CreateProcessExeOnly,
        working_directory: None,
    };
    let t = normalize_target_in("cscript", &ctx).unwrap();
    assert_eq!(
        t.search_path_candidates,
        vec![
            "/windows/system32/cscript.exe",
            "/windows/syswow64/cscript.exe",
            "/windows/cscript.exe",
        ]
    );
    // CreateProcess appends nothing to a name that has an extension.
    let t = normalize_target_in("kerncap.vbs", &ctx).unwrap();
    assert_eq!(t.search_path_candidates[0], "/windows/system32/kerncap.vbs");
    assert_eq!(t.search_path_candidates.len(), 3);
    // The default remains the shell's PATHEXT rule, and says so.
    let res = EvidenceIndex::new().resolve(Some("cscript"));
    assert_eq!(res.search_rule, Some("shell_pathext"));
}

#[test]
fn a_working_directory_that_cannot_be_searched_is_named_as_not_tried() {
    let ctx = SearchContext {
        rule: SearchRule::CreateProcessExeOnly,
        working_directory: Some("%TEMP%\\work".to_string()),
    };
    let t = normalize_target_in("cscript", &ctx).unwrap();
    assert_eq!(t.search_path_candidates.len(), 3);
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/cscript.exe");
    let res = index.resolve_in(Some("cscript"), &ctx);
    assert!(
        res.basis.contains("%TEMP%\\work") && res.basis.contains("was not searched"),
        "{}",
        res.basis
    );
    // A working directory that is itself a system directory is tried once.
    let ctx = SearchContext {
        rule: SearchRule::ShellPathext,
        working_directory: Some("C:\\Windows\\System32".to_string()),
    };
    assert_eq!(
        normalize_target_in("cscript", &ctx)
            .unwrap()
            .search_path_candidates
            .len(),
        12
    );
}

#[test]
fn non_executable_files_are_not_indexed_so_they_cannot_answer_target_questions() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Users/alice/notes.txt");
    assert_eq!(index.executable_count(), 0);
}

#[test]
fn a_target_whose_path_list_was_truncated_does_not_claim_the_path_differs() {
    // More copies of one name than the index retains paths for. The entry's own
    // path is among the copies but was dropped, so the honest answer is "not
    // established", never "the name matches but the path does not".
    let mut index = EvidenceIndex::new();
    for i in 0..(crate::index::MAX_PATHS_PER_BASENAME + 4) {
        index.note_file(&format!("/Users/alice/copy{i}/svchost.exe"));
    }
    index.note_file("/Windows/System32/svchost.exe");

    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert_eq!(res.status, TargetStatus::ObservedByNameOnly);
    assert!(
        res.observed_paths_truncated,
        "a cap that changed the verdict must reach the record"
    );
    assert!(
        !res.basis.contains("the name matches but the path does not"),
        "asserting the path differs is a claim the truncated index cannot support"
    );
    assert!(res.basis.contains("not established either way"));
    assert_eq!(
        res.observed_paths.len(),
        crate::index::MAX_PATHS_PER_BASENAME
    );
}

#[test]
fn a_path_list_that_stayed_inside_its_ceiling_is_not_flagged_truncated() {
    let mut index = EvidenceIndex::new();
    index.note_file("/Users/alice/AppData/Local/svchost.exe");
    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert!(!res.observed_paths_truncated);
    assert!(res.basis.contains("the name matches but the path"));
}

#[test]
fn the_same_path_seen_twice_does_not_count_against_the_per_name_ceiling() {
    let mut index = EvidenceIndex::new();
    for _ in 0..(crate::index::MAX_PATHS_PER_BASENAME + 4) {
        index.note_file("/Windows/System32/svchost.exe");
    }
    let res = index.resolve(Some("C:\\Windows\\System32\\svchost.exe"));
    assert_eq!(res.status, TargetStatus::ObservedAtPath);
    assert!(
        !res.observed_paths_truncated,
        "a repeated path is not a dropped one"
    );
}

// --- registry: run keys ------------------------------------------------------

#[test]
fn run_keys_are_found_in_the_machine_hive_the_user_hive_and_the_wow64_view() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(
                r"ROOT\Microsoft\Windows\CurrentVersion\Run",
                "OneDrive",
                "\"C:\\Users\\a\\OneDrive.exe\" /background",
            ),
            rv(
                r"ROOT\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                "Legacy",
                "C:\\legacy\\l.exe",
            ),
        ],
    );
    let runs = find(&out.entries, "run_key");
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].image.as_deref(), Some("C:\\Users\\a\\OneDrive.exe"));
    assert_eq!(runs[0].arguments.as_deref(), Some("/background"));
    assert!(runs[0].runs_when.contains("every user"));

    let user = run_scan(
        "NTUSER.DAT",
        &[rv(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
            "Thing",
            "C:\\t\\t.exe",
        )],
    );
    assert_eq!(find(&user.entries, "run_key").len(), 1);
    assert_eq!(user.entries[0].scope, "HKCU");
}

#[test]
fn a_runonce_entry_states_that_windows_deletes_it_after_one_run() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows\CurrentVersion\RunOnce",
            "Setup",
            "C:\\s\\setup.exe",
        )],
    );
    let runs = find(&out.entries, "run_key");
    assert_eq!(runs.len(), 1);
    assert!(runs[0].runs_when.contains("deletes"));
}

#[test]
fn an_empty_run_value_produces_no_entry_rather_than_a_nameless_one() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows\CurrentVersion\Run",
            "Blank",
            "  ",
        )],
    );
    assert!(
        find(&out.entries, "run_key").is_empty(),
        "an empty value is not an autostart entry and must not appear as one"
    );
}

#[test]
fn a_registry_entry_carries_no_install_time_and_states_why() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows\CurrentVersion\Run",
            "Thing",
            "C:\\t.exe",
        )],
    );
    let entry = &out.entries[0];
    assert!(entry.installed_time.is_none());
    assert!(entry
        .installed_time_unavailable_reason
        .expect("a reason")
        .contains("last-write"));
}

// --- registry: Winlogon ------------------------------------------------------

#[test]
fn the_shipped_winlogon_shell_value_is_reported_without_a_difference_observation() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
            "explorer.exe",
        )],
    );
    let shells = find(&out.entries, "winlogon_shell");
    assert_eq!(shells.len(), 1);
    assert!(shells[0]
        .observations
        .iter()
        .all(|o| o.code != "differs_from_windows_default"));
}

#[test]
fn an_appended_winlogon_shell_element_becomes_its_own_entry_and_is_flagged_as_different() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
            "explorer.exe,C:\\Temp\\extra.exe",
        )],
    );
    let shells = find(&out.entries, "winlogon_shell");
    assert_eq!(
        shells.len(),
        2,
        "reporting the raw list as one entry would bury the appended command"
    );
    let extra = shells
        .iter()
        .find(|e| e.image.as_deref() == Some("C:\\Temp\\extra.exe"))
        .expect("the appended element");
    assert!(extra
        .observations
        .iter()
        .any(|o| o.code == "differs_from_windows_default"));
    assert!(extra
        .observations
        .iter()
        .any(|o| o.code == "additional_element_in_list"));
}

#[test]
fn userinit_and_the_other_winlogon_values_land_in_their_own_categories() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(key, "Userinit", "C:\\Windows\\system32\\userinit.exe,"),
            rv(key, "Taskman", "C:\\Tools\\tm.exe"),
            rv(key, "GinaDLL", "evil.dll"),
        ],
    );
    assert_eq!(find(&out.entries, "winlogon_userinit").len(), 1);
    assert_eq!(find(&out.entries, "winlogon_other").len(), 2);
}

#[test]
fn a_winlogon_notification_package_names_the_dll_it_loads_into_winlogon() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\mypkg",
            "DllName",
            "C:\\Windows\\System32\\mypkg.dll",
        )],
    );
    let notify = find(&out.entries, "winlogon_notify");
    assert_eq!(notify.len(), 1);
    assert_eq!(notify[0].entry_name, "mypkg");
}

// --- registry: IFEO ----------------------------------------------------------

#[test]
fn an_ifeo_debugger_states_that_the_hijacked_image_is_replaced() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe",
            "Debugger",
            "C:\\Tools\\d.exe",
        )],
    );
    let ifeo = find(&out.entries, "ifeo_debugger");
    assert_eq!(ifeo.len(), 1);
    assert_eq!(ifeo[0].entry_name, "taskmgr.exe");
    assert!(ifeo[0].runs_when.contains("instead"));
}

#[test]
fn a_silent_process_exit_monitor_is_reported_with_its_own_mechanism() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe",
            "MonitorProcess",
            "C:\\Tools\\m.exe",
        )],
    );
    let ifeo = find(&out.entries, "ifeo_debugger");
    assert_eq!(ifeo.len(), 1);
    assert_eq!(
        ifeo[0].extra.get("ifeo_mechanism").and_then(Value::as_str),
        Some("silent_process_exit_monitor")
    );
}

// --- registry: AppInit, BootExecute, KnownDLLs, LSA --------------------------

#[test]
fn appinit_dlls_are_disabled_when_the_load_flag_is_zero_whatever_order_they_appear_in() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\Windows";
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(key, "AppInit_DLLs", "c:\\a.dll c:\\b.dll"),
            dword(key, "LoadAppInit_DLLs", 0),
        ],
    );
    let appinit = find(&out.entries, "appinit_dlls");
    assert_eq!(appinit.len(), 2);
    assert!(appinit.iter().all(|e| e.enabled == Some(false)));
    assert!(appinit[0].enabled_basis.contains("LoadAppInit_DLLs is 0"));
}

#[test]
fn an_appinit_list_with_no_load_flag_reports_enabled_as_unknown_rather_than_guessing() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\Windows";
    let out = run_scan("SOFTWARE", &[rv(key, "AppInit_DLLs", "c:\\a.dll")]);
    let appinit = find(&out.entries, "appinit_dlls");
    assert_eq!(appinit.len(), 1);
    assert_eq!(appinit[0].enabled, None);
    assert!(appinit[0].enabled_basis.contains("could not be determined"));
}

#[test]
fn boot_execute_splits_into_elements_and_flags_anything_beyond_the_shipped_default() {
    let key = r"ROOT\ControlSet001\Control\Session Manager";
    let out = run_scan(
        "SYSTEM",
        &[rv(
            key,
            "BootExecute",
            "autocheck autochk * | C:\\Temp\\x.exe",
        )],
    );
    let boot = find(&out.entries, "boot_execute");
    assert_eq!(boot.len(), 2);
    let extra = boot
        .iter()
        .find(|e| e.entry_name.contains("x.exe"))
        .expect("the added element");
    assert!(extra
        .observations
        .iter()
        .any(|o| o.code == "differs_from_windows_default"));
    assert!(boot[0].runs_when.contains("before any user logs on"));
}

/// `HUNT-208`: since `HUNT-159` a `REG_MULTI_SZ` record carries its elements
/// as the array `value_data_list`. The rendering joins them with `" | "`, a
/// separator an element may itself contain, so splitting the rendering turns
/// one element into two. The elements are read from the array.
#[test]
fn a_multi_sz_is_read_from_its_element_list_not_its_rendering() {
    let key = r"ROOT\ControlSet001\Control\Session Manager";
    let mut boot = rv(
        key,
        "BootExecute",
        "autocheck autochk * | C:\\Temp\\x.exe a | b",
    );
    boot["value_type"] = json!("RegMultiSZ");
    boot["value_data_list"] = json!(["autocheck autochk *", "C:\\Temp\\x.exe a | b"]);
    let lsa = r"ROOT\ControlSet001\Control\Lsa";
    let mut notify = rv(lsa, "Notification Packages", "scecli | ras | fm");
    notify["value_type"] = json!("RegMultiSZ");
    notify["value_data_list"] = json!(["scecli", "ras | fm"]);
    let out = run_scan("SYSTEM", &[boot, notify]);

    let boot = find(&out.entries, "boot_execute");
    let names: Vec<&str> = boot.iter().map(|e| e.entry_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["autocheck autochk *", "C:\\Temp\\x.exe a | b"],
        "the element that contains the separator is one entry"
    );
    assert_eq!(find(&out.entries, "lsa_notification_package").len(), 2);
}

#[test]
fn known_dlls_and_appcert_dlls_are_enumerated_from_the_session_manager_tree() {
    let out = run_scan(
        "SYSTEM",
        &[
            rv(
                r"ROOT\ControlSet001\Control\Session Manager\KnownDLLs",
                "ntdll",
                "ntdll.dll",
            ),
            rv(
                r"ROOT\ControlSet001\Control\Session Manager\AppCertDlls",
                "mine",
                "C:\\Tools\\cert.dll",
            ),
        ],
    );
    assert_eq!(find(&out.entries, "known_dlls").len(), 1);
    assert_eq!(find(&out.entries, "appcert_dlls").len(), 1);
}

#[test]
fn the_three_lsa_package_lists_land_in_three_distinct_categories() {
    let key = r"ROOT\ControlSet001\Control\Lsa";
    let out = run_scan(
        "SYSTEM",
        &[
            rv(key, "Authentication Packages", "msv1_0"),
            rv(key, "Notification Packages", "scecli | rassfm"),
            rv(key, "Security Packages", "kerberos"),
        ],
    );
    assert_eq!(find(&out.entries, "lsa_authentication_package").len(), 1);
    assert_eq!(find(&out.entries, "lsa_notification_package").len(), 2);
    assert_eq!(find(&out.entries, "lsa_security_package").len(), 1);
}

// --- registry: printing, netsh, active setup, WMI MOFs -----------------------

#[test]
fn print_monitors_and_processors_are_enumerated_with_their_spooler_context() {
    let out = run_scan(
        "SYSTEM",
        &[
            rv(
                r"ROOT\ControlSet001\Control\Print\Monitors\MyMon",
                "Driver",
                "mymon.dll",
            ),
            rv(
                r"ROOT\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\MyProc",
                "Driver",
                "myproc.dll",
            ),
        ],
    );
    let monitors = find(&out.entries, "print_monitor");
    assert_eq!(monitors.len(), 1);
    assert_eq!(monitors[0].entry_name, "MyMon");
    assert!(monitors[0].runs_when.contains("spoolsv.exe"));
    assert_eq!(find(&out.entries, "print_processor").len(), 1);
}

#[test]
fn netsh_helpers_active_setup_stubs_and_autorecover_mofs_are_all_enumerated() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(r"ROOT\Microsoft\NetSh", "myctx", "myhelper.dll"),
            rv(
                r"ROOT\Microsoft\Active Setup\Installed Components\{1234}",
                "StubPath",
                "C:\\Tools\\stub.exe",
            ),
            rv(
                r"ROOT\Microsoft\Wbem\CIMOM",
                "Autorecover MOFs",
                "C:\\Windows\\System32\\wbem\\a.mof | C:\\Temp\\b.mof",
            ),
        ],
    );
    assert_eq!(find(&out.entries, "netsh_helper").len(), 1);
    let active = find(&out.entries, "active_setup");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].entry_name, "{1234}");
    assert_eq!(find(&out.entries, "wmi_mof_autorecover").len(), 2);
}

// --- registry: services ------------------------------------------------------

#[test]
fn a_service_key_is_grouped_from_its_values_and_its_start_type_is_decoded() {
    let key = r"ROOT\ControlSet001\Services\Spooler";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x110),
            rv(key, "ImagePath", "C:\\Windows\\System32\\spoolsv.exe"),
            rv(key, "DisplayName", "Print Spooler"),
            rv(key, "ObjectName", "LocalSystem"),
        ],
    );
    let services = find(&out.entries, "service");
    assert_eq!(services.len(), 1);
    let s = services[0];
    assert_eq!(s.entry_name, "Spooler");
    assert_eq!(s.enabled, Some(true));
    assert_eq!(
        s.extra
            .get("service_start_type_label")
            .and_then(Value::as_str),
        Some("Automatic")
    );
    assert!(s.runs_when.contains("automatically at boot"));
    assert_eq!(
        s.extra.get("service_type_label").and_then(Value::as_str),
        Some("Own-process service (interactive)")
    );
}

#[test]
fn a_disabled_service_is_reported_as_not_starting_by_itself() {
    let key = r"ROOT\CurrentControlSet\Services\Dormant";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 4),
            rv(key, "ImagePath", "C:\\Windows\\System32\\dorm.exe"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(s.enabled, Some(false));
    assert!(s.runs_when.contains("Disabled"));
}

#[test]
fn a_service_with_an_unreadable_start_value_is_marked_unread_not_defaulted_to_boot() {
    let key = r"ROOT\ControlSet001\Services\Broken";
    let out = run_scan(
        "SYSTEM",
        &[
            json!({
                "key_path": key,
                "value_name": "Start",
                "value_type": "RegDword",
                "value_data": "(invalid DWORD)",
                "raw_data_size": 2,
            }),
            rv(key, "ImagePath", "C:\\Windows\\System32\\b.exe"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(s.enabled, None);
    assert!(matches!(s.read_status, ReadStatus::Unread(_)));
    assert!(s.enabled_basis.contains("could not be decoded"));
}

#[test]
fn a_shared_process_service_reports_its_service_dll_as_the_code_that_runs() {
    let key = r"ROOT\ControlSet001\Services\Shady";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(
                key,
                "ImagePath",
                "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            ),
            rv(
                &format!("{key}\\Parameters"),
                "ServiceDll",
                "C:\\Temp\\shady.dll",
            ),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(
        s.image.as_deref(),
        Some("C:\\Temp\\shady.dll"),
        "naming svchost.exe as the image would point the examiner at the wrong file"
    );
    assert!(s.observations.iter().any(|o| o.code == "service_loads_dll"));
}

#[test]
fn separate_control_sets_are_reported_separately_rather_than_collapsed() {
    let out = run_scan(
        "SYSTEM",
        &[
            dword(r"ROOT\ControlSet001\Services\Thing", "Start", 2),
            dword(r"ROOT\ControlSet002\Services\Thing", "Start", 4),
        ],
    );
    let services = find(&out.entries, "service");
    assert_eq!(
        services.len(),
        2,
        "collapsing control sets would hide which configuration the machine booted"
    );
}

#[test]
fn a_network_provider_registration_produces_its_own_entry_alongside_the_service() {
    let key = r"ROOT\ControlSet001\Services\MyProv";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            rv(
                &format!("{key}\\NetworkProvider"),
                "ProviderPath",
                "C:\\Windows\\System32\\myprov.dll",
            ),
        ],
    );
    assert_eq!(find(&out.entries, "network_provider").len(), 1);
    assert_eq!(find(&out.entries, "service").len(), 1);
}

// --- registry: COM, shell extensions, tasks, winsock -------------------------

#[test]
fn a_com_server_outside_the_system_directories_is_listed_and_one_inside_is_counted_not_listed() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(
                r"ROOT\Classes\CLSID\{aaaa}\InprocServer32",
                "(Default)",
                "C:\\Windows\\System32\\shell32.dll",
            ),
            rv(
                r"ROOT\Classes\CLSID\{bbbb}\InprocServer32",
                "(Default)",
                "C:\\Users\\a\\AppData\\Roaming\\x.dll",
            ),
        ],
    );
    let com = find(&out.entries, "com_server");
    assert_eq!(com.len(), 1);
    assert_eq!(com[0].entry_name, "{bbbb}");
    let note = out
        .summary
        .notes
        .get("com_server")
        .expect("the exclusion must be stated, not silent");
    assert!(note.contains("1 COM class registrations were examined and excluded"));
}

#[test]
fn a_per_user_class_registration_is_always_listed_even_inside_system32() {
    let out = run_scan(
        "USRCLASS.DAT",
        &[rv(
            r"ROOT\CLSID\{cccc}\InprocServer32",
            "(Default)",
            "C:\\Windows\\System32\\shell32.dll",
        )],
    );
    let com = find(&out.entries, "com_server");
    assert_eq!(com.len(), 1);
    assert!(com[0]
        .observations
        .iter()
        .any(|o| o.code == "per_user_class_registration"));
}

#[test]
fn a_shell_extension_resolves_to_the_dll_registered_for_its_clsid() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(
                r"ROOT\Classes\*\shellex\ContextMenuHandlers\MyHandler",
                "(Default)",
                "{11111111-2222-3333-4444-555555555555}",
            ),
            rv(
                r"ROOT\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
                "(Default)",
                "C:\\Tools\\handler.dll",
            ),
        ],
    );
    let ext = find(&out.entries, "shell_extension");
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].image.as_deref(), Some("C:\\Tools\\handler.dll"));
    assert_eq!(ext[0].read_status, ReadStatus::Parsed);
}

#[test]
fn a_shell_extension_whose_clsid_is_not_registered_here_is_marked_unread_not_dropped() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Classes\*\shellex\ContextMenuHandlers\Orphan",
            "(Default)",
            "{99999999-2222-3333-4444-555555555555}",
        )],
    );
    let ext = find(&out.entries, "shell_extension");
    assert_eq!(
        ext.len(),
        1,
        "an unresolvable handler is still a registered shell extension"
    );
    assert!(matches!(ext[0].read_status, ReadStatus::Unread(_)));
    assert!(ext[0].image.is_none());
}

#[test]
fn a_browser_helper_object_is_categorised_separately_from_other_shell_extensions() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{12345678-1234-1234-1234-123456789abc}",
            "(Default)",
            "My BHO",
        )],
    );
    assert_eq!(find(&out.entries, "browser_helper_object").len(), 1);
}

#[test]
fn a_taskcache_registration_is_reported_and_says_the_actions_live_in_the_xml() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Defrag\ScheduledDefrag",
            "Id",
            "{9d8e6a1b-0000-0000-0000-000000000001}",
        )],
    );
    let reg = find(&out.entries, "scheduled_task_registration");
    assert_eq!(reg.len(), 1);
    assert_eq!(reg[0].entry_name, "ScheduledDefrag");
    assert!(reg[0].runs_when.contains("task XML"));
    assert_eq!(reg[0].enabled, None);
}

#[test]
fn a_winsock_catalog_entry_is_recorded_as_present_but_marked_unread() {
    let out = run_scan(
        "SYSTEM",
        &[rv(
            r"ROOT\ControlSet001\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\000000000001",
            "PackedCatalogItem",
            "512 bytes (binary data)",
        )],
    );
    let ws = find(&out.entries, "winsock_provider");
    assert_eq!(ws.len(), 1);
    assert!(matches!(ws[0].read_status, ReadStatus::Unread(_)));
    assert!(ws[0].incomplete_reason.is_some());
}

#[test]
fn the_startup_folder_redirection_values_are_read_from_the_shell_folder_keys() {
    let out = run_scan(
        "NTUSER.DAT",
        &[rv(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "Startup",
            "C:\\Temp\\MyStartup",
        )],
    );
    let red = find(&out.entries, "startup_folder_redirect");
    assert_eq!(red.len(), 1);
    assert!(red[0]
        .observations
        .iter()
        .any(|o| o.code == "startup_folder_not_default_location"));
}

// --- coverage ----------------------------------------------------------------

fn coverage_rows(artifact: &Artifact) -> Vec<Value> {
    artifact
        .metadata
        .get("categories")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn row_for<'a>(rows: &'a [Value], id: &str) -> &'a Value {
    rows.iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("no coverage row for {id}"))
}

#[test]
fn every_category_appears_in_the_coverage_record_for_every_hive() {
    let summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    assert_eq!(
        rows.len(),
        CATEGORIES.len(),
        "a category missing from the coverage record is an invisible omission"
    );
}

#[test]
fn a_checked_and_empty_category_reads_differently_from_an_unexamined_one() {
    let summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);

    let run = row_for(&rows, "run_key");
    assert_eq!(
        run.get("status").and_then(Value::as_str),
        Some(CoverageStatus::Examined.as_str())
    );
    assert_eq!(run.get("entries").and_then(Value::as_u64), Some(0));

    // The unexamined form: a hive that would not yield its values.
    let mut unread = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    unread.values_unavailable_reason = Some("no all_values array".to_string());
    let art = build_coverage_artifact(&unread, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    let run = row_for(&rows, "run_key");
    assert_eq!(
        run.get("status").and_then(Value::as_str),
        Some(CoverageStatus::Unexamined.as_str())
    );
    assert_eq!(run.get("entries").and_then(Value::as_u64), Some(0));
    assert!(art
        .metadata
        .get("unexamined_categories")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v == "run_key"))
        .unwrap_or(false));
}

#[test]
fn a_category_that_cannot_live_in_this_hive_names_the_hive_that_carries_it() {
    let summary = HiveScanSummary::new("NTUSER.DAT".to_string(), HiveKind::NtUser);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    let service = row_for(&rows, "service");
    assert_eq!(
        service.get("status").and_then(Value::as_str),
        Some(CoverageStatus::NotApplicableToHive.as_str())
    );
    assert!(service
        .get("status_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("SYSTEM"));
    assert!(service.get("carried_by_hives").is_some());
}

#[test]
fn an_unrecognised_hive_reports_every_registry_category_as_unexamined() {
    let summary = HiveScanSummary::new("SAM".to_string(), HiveKind::Other);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    let run = row_for(&rows, "run_key");
    assert_eq!(
        run.get("status").and_then(Value::as_str),
        Some(CoverageStatus::Unexamined.as_str()),
        "an unrecognised hive was not searched, so its categories are unexamined, not empty"
    );
}

#[test]
fn a_hive_record_with_no_value_array_reports_unexamined_rather_than_empty() {
    let mut summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    summary.values_total = 5000;
    summary.values_unavailable_reason = Some("no all_values array".to_string());
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    assert_eq!(
        row_for(&rows, "run_key")
            .get("status")
            .and_then(Value::as_str),
        Some(CoverageStatus::Unexamined.as_str())
    );
    assert_eq!(
        art.metadata.get("incomplete").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn a_capped_scan_downgrades_every_registry_category_to_partial_and_says_so() {
    let mut summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    summary.values_total = 10;
    summary.values_scanned = 5;
    summary.scan_capped = true;
    summary.count("run_key");
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = coverage_rows(&art);
    let run = row_for(&rows, "run_key");
    assert_eq!(
        run.get("status").and_then(Value::as_str),
        Some(CoverageStatus::ExaminedPartial.as_str())
    );
    assert!(run
        .get("status_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("lower bound"));
}

#[test]
fn the_coverage_record_explains_the_difference_between_empty_and_unexamined() {
    let summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let note = art
        .metadata
        .get("reading_note")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(note.contains("says nothing about this machine"));
}

// --- scheduled task XML ------------------------------------------------------

const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2021-06-01T12:00:00</Date>
    <Author>CONTOSO\alice</Author>
    <Description>Keeps things running</Description>
    <URI>\Contoso\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>CONTOSO\alice</UserId>
    </LogonTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Tools\upd.exe</Command>
      <Arguments>--silent &amp; --now</Arguments>
      <WorkingDirectory>C:\Tools</WorkingDirectory>
    </Exec>
    <Exec><Command>C:\Tools\second.exe</Command></Exec>
  </Actions>
</Task>
"#;

fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

#[test]
fn a_utf16le_task_file_with_a_bom_is_detected_and_decoded() {
    let bytes = utf16le_with_bom(TASK_XML);
    assert!(looks_like_task_xml(&bytes));
    let text = decode(&bytes).expect("decode");
    assert!(text.contains("<Task"));
}

#[test]
fn a_utf8_task_file_without_an_xml_declaration_parses_identically() {
    let no_decl = TASK_XML
        .split_once('\n')
        .map(|(_, rest)| rest.to_string())
        .unwrap();
    assert!(looks_like_task_xml(no_decl.as_bytes()));
    let a = parse_task(&decode(&utf16le_with_bom(TASK_XML)).unwrap()).unwrap();
    let b = parse_task(&no_decl).unwrap();
    assert_eq!(a.actions, b.actions);
    assert_eq!(a.triggers, b.triggers);
}

#[test]
fn a_task_yields_its_triggers_actions_principal_and_settings() {
    let task = parse_task(TASK_XML).expect("parse");
    assert_eq!(task.uri.as_deref(), Some("\\Contoso\\Updater"));
    assert_eq!(task.author.as_deref(), Some("CONTOSO\\alice"));
    assert_eq!(task.principal_user.as_deref(), Some("S-1-5-18"));
    assert_eq!(task.run_level.as_deref(), Some("HighestAvailable"));
    assert_eq!(task.enabled, Some(true));
    assert_eq!(task.hidden, Some(true));
    assert_eq!(task.triggers.len(), 2);
    assert_eq!(task.triggers[0].kind, "LogonTrigger");
    assert_eq!(task.triggers[0].user.as_deref(), Some("CONTOSO\\alice"));
    assert_eq!(task.triggers[1].kind, "BootTrigger");
    assert_eq!(task.actions.len(), 2);
    match &task.actions[0] {
        TaskAction::Exec {
            command,
            arguments,
            working_dir,
        } => {
            assert_eq!(command.as_deref(), Some("C:\\Tools\\upd.exe"));
            assert_eq!(arguments.as_deref(), Some("--silent & --now"));
            assert_eq!(working_dir.as_deref(), Some("C:\\Tools"));
        }
        other => panic!("expected an Exec action, got {other:?}"),
    }
}

#[test]
fn a_task_entry_states_what_runs_and_when_and_tags_its_local_wall_clock_time() {
    let task = parse_task(TASK_XML).unwrap();
    let entry = task_xml::task_entry(&task, "/Windows/System32/Tasks/Contoso/Updater", "Updater");
    assert_eq!(entry.image.as_deref(), Some("C:\\Tools\\upd.exe"));
    assert!(entry.runs_when.contains("when CONTOSO\\alice logs on"));
    assert!(entry.runs_when.contains("at system boot"));
    assert!(entry.runs_when.contains("highest privileges"));
    let time = entry.installed_time.as_ref().expect("a registration date");
    assert_eq!(time.value, "2021-06-01T12:00:00");
    assert_eq!(
        time.timezone,
        Some("local"),
        "a task date with no offset must never be presented as UTC"
    );
    assert!(entry.observations.iter().any(|o| o.code == "task_hidden"));
    assert_eq!(
        entry
            .extra
            .get("task_actions_count")
            .and_then(Value::as_u64),
        Some(2)
    );
}

#[test]
fn a_task_date_carrying_an_explicit_offset_is_not_tagged_local() {
    let xml = TASK_XML.replace("2021-06-01T12:00:00", "2021-06-01T12:00:00Z");
    let task = parse_task(&xml).unwrap();
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert_eq!(entry.installed_time.as_ref().unwrap().timezone, None);
}

#[test]
fn a_malformed_registration_date_is_dropped_and_the_reason_recorded() {
    let xml = TASK_XML.replace("2021-06-01T12:00:00", "not a date");
    let task = parse_task(&xml).unwrap();
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert!(
        entry.installed_time.is_none(),
        "a malformed date promoted to a timeline event is a fabricated moment"
    );
    assert!(entry
        .installed_time_unavailable_reason
        .unwrap()
        .contains("well-formed"));
}

#[test]
fn a_com_handler_task_surfaces_the_class_id_and_claims_no_image() {
    let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Actions><ComHandler><ClassId>{abcd}</ClassId></ComHandler></Actions>
    </Task>"#;
    let task = parse_task(xml).unwrap();
    assert_eq!(task.actions.len(), 1);
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert!(entry.image.is_none());
    assert!(entry.runs_when.contains("{abcd}"));
}

#[test]
fn a_task_with_no_triggers_says_it_runs_only_when_something_starts_it() {
    let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers/>
      <Actions><Exec><Command>C:\a.exe</Command></Exec></Actions>
    </Task>"#;
    let task = parse_task(xml).unwrap();
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert!(entry.runs_when.contains("no triggers"));
    assert!(entry
        .observations
        .iter()
        .any(|o| o.code == "no_triggers_defined"));
}

#[test]
fn a_task_with_no_readable_action_is_marked_unread_rather_than_reported_as_benign() {
    let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Actions/>
    </Task>"#;
    let task = parse_task(xml).unwrap();
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert!(matches!(entry.read_status, ReadStatus::Unread(_)));
}

#[test]
fn xml_that_is_not_a_task_definition_is_rejected() {
    assert!(!looks_like_task_xml(
        b"<?xml version=\"1.0\"?><rss><channel/></rss>"
    ));
    assert_eq!(
        parse_task("<rss><channel/></rss>"),
        Err(TaskParseError::NotATask(
            "the Task Scheduler namespace is absent"
        ))
    );
}

#[test]
fn truncated_or_mismatched_task_markup_errors_instead_of_returning_a_partial_task() {
    let truncated = TASK_XML.get(..TASK_XML.len() / 2).unwrap();
    match parse_task(truncated) {
        Err(_) => {}
        Ok(task) => assert!(
            task.actions.len() < 2,
            "a truncated definition must not present itself as the complete task"
        ),
    }

    let mismatched = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Actions></Triggers></Task>"#;
    assert!(matches!(
        parse_task(mismatched),
        Err(TaskParseError::Malformed(_))
    ));
}

#[test]
fn an_undecodable_byte_sequence_is_an_error_rather_than_mojibake() {
    assert_eq!(
        decode(&[0xF8, 0x81, 0x81]),
        Err(TaskParseError::Undecodable)
    );
}

#[test]
fn a_doctype_declaration_is_skipped_and_no_entity_is_ever_expanded() {
    let xml = concat!(
        "<!DOCTYPE Task [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">",
        "<Actions><Exec><Command>&xxe;</Command></Exec></Actions></Task>"
    );
    let task = parse_task(xml).expect("parse");
    match &task.actions[0] {
        TaskAction::Exec { command, .. } => assert_eq!(
            command.as_deref(),
            Some("&xxe;"),
            "an unknown entity must be kept verbatim, never resolved"
        ),
        other => panic!("expected Exec, got {other:?}"),
    }
}

// --- startup folders ---------------------------------------------------------

#[test]
fn per_user_and_all_users_startup_folders_are_told_apart() {
    let classify = |p: &str| classify_startup_path(&normalize_evidence_path(p));

    let per_user = classify(
        "/Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk",
    )
    .expect("per-user startup");
    assert_eq!(per_user.user.as_deref(), Some("alice"));
    assert!(!per_user.all_users);

    let all = classify("/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk")
        .expect("all-users startup");
    assert!(all.all_users);
    assert!(all.user.is_none());

    let legacy = classify("C:\\Documents and Settings\\bob\\Start Menu\\Programs\\Startup\\x.lnk")
        .expect("legacy per-user startup");
    assert_eq!(legacy.user.as_deref(), Some("bob"));

    assert!(classify("/Users/alice/Desktop/x.lnk").is_none());
}

/// A minimal but structurally real shell link pointing at `C:\Tools\agent.exe`
/// with the arguments `--quiet`.
fn synthetic_lnk() -> Vec<u8> {
    let mut buf = vec![0u8; 76];
    buf[0..4].copy_from_slice(&76u32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0002_1401u32.to_le_bytes());
    // HasLinkInfo (0x02) | HasArguments (0x20)
    buf[20..24].copy_from_slice(&0x22u32.to_le_bytes());

    let base = b"C:\\Tools\\agent.exe\0";
    let suffix = b"\0";
    let header_size = 0x1Cu32;
    let base_offset = header_size;
    let suffix_offset = base_offset + base.len() as u32;
    let info_size = suffix_offset + suffix.len() as u32;

    let mut info = Vec::new();
    info.extend_from_slice(&info_size.to_le_bytes());
    info.extend_from_slice(&header_size.to_le_bytes());
    info.extend_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    info.extend_from_slice(&0u32.to_le_bytes()); // VolumeIDOffset
    info.extend_from_slice(&base_offset.to_le_bytes());
    info.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
    info.extend_from_slice(&suffix_offset.to_le_bytes());
    info.extend_from_slice(base);
    info.extend_from_slice(suffix);
    buf.extend_from_slice(&info);

    let args = b"--quiet";
    buf.extend_from_slice(&(args.len() as u16).to_le_bytes());
    buf.extend_from_slice(args);
    buf
}

#[test]
fn a_shell_link_yields_its_local_target_and_arguments() {
    let target = parse_lnk(&synthetic_lnk()).expect("parse");
    assert_eq!(target.target.as_deref(), Some("C:\\Tools\\agent.exe"));
    assert_eq!(target.arguments.as_deref(), Some("--quiet"));
}

#[test]
fn a_shortcut_with_a_bad_header_errors_and_a_short_one_is_reported_as_short() {
    assert_eq!(parse_lnk(&[0u8; 10]), Err(LnkError::TooShort));
    let mut buf = synthetic_lnk();
    buf[4] = 0xFF;
    assert!(matches!(parse_lnk(&buf), Err(LnkError::BadHeader { .. })));
}

#[test]
fn a_truncated_shortcut_errors_rather_than_reading_a_field_from_the_wrong_offset() {
    let buf = synthetic_lnk();
    let short = buf.get(..80).unwrap().to_vec();
    assert!(matches!(parse_lnk(&short), Err(LnkError::Truncated(_))));
}

#[test]
fn an_unreadable_startup_shortcut_still_produces_an_entry_marked_unread() {
    let location = startup::StartupLocation {
        user: Some("alice".to_string()),
        all_users: false,
    };
    let entry = startup::startup_entry(
        "/Users/alice/.../Startup/broken.lnk",
        "broken.lnk",
        &location,
        Some(Err(LnkError::TooShort)),
        None,
    );
    assert!(matches!(entry.read_status, ReadStatus::Unread(_)));
    assert_eq!(
        entry.enabled,
        Some(true),
        "the item is in the Startup folder and still runs; only its target is unknown"
    );
    assert!(entry.runs_when.contains("when alice logs on"));
}

#[test]
fn a_non_shortcut_file_in_a_startup_folder_is_reported_as_running_itself() {
    let location = startup::StartupLocation {
        user: None,
        all_users: true,
    };
    let entry = startup::startup_entry(
        "/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/go.bat",
        "go.bat",
        &location,
        None,
        Some("2024-01-01T00:00:00Z".to_string()),
    );
    assert_eq!(
        entry.image.as_deref(),
        Some("/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/go.bat")
    );
    assert!(entry.runs_when.contains("when any user logs on"));
    let time = entry
        .installed_time
        .as_ref()
        .expect("the file creation time");
    assert_eq!(time.source, "startup_item_file_created");
    assert_eq!(time.timezone, None);
}

// --- record emission ---------------------------------------------------------

fn ctx() -> EmitContext {
    EmitContext {
        case_id: Uuid::new_v4(),
        parent_id: Uuid::new_v4(),
        registry_record_id: None,
        file_artifact_id: None,
    }
}

#[test]
fn an_entry_without_an_install_time_produces_no_timeline_event() {
    let mut entry = AsepEntry::new("run_key", "Thing", "KEY", LocationKind::RegistryKey);
    entry.installed_time_unavailable_reason = Some(KEY_TIME_UNAVAILABLE);
    let arts = record::build_entry_artifacts(&entry, &ctx());
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(
        arts[0]
            .metadata
            .get("installed_time_status")
            .and_then(Value::as_str),
        Some("unavailable")
    );
}

#[test]
fn an_entry_with_an_install_time_produces_exactly_one_timeline_event_carrying_its_timezone() {
    let mut entry = AsepEntry::new("scheduled_task", "T", "/t", LocationKind::File);
    entry.installed_time = Some(InstalledTime {
        value: "2021-06-01T12:00:00".to_string(),
        source: "task_registration_date",
        timezone: Some("local"),
    });
    let arts = record::build_entry_artifacts(&entry, &ctx());
    assert_eq!(arts.len(), 2);
    let event = &arts[1];
    assert_eq!(event.artifact_type, ArtifactType::TimelineEvent);
    assert_eq!(
        event.metadata.get("timezone").and_then(Value::as_str),
        Some("local")
    );
    assert_eq!(
        event.metadata.get("source_module").and_then(Value::as_str),
        Some(MODULE_ID)
    );
    assert_eq!(event.parent_id, Some(arts[0].id));
}

#[test]
fn a_record_carries_its_attack_mapping_its_locations_and_the_no_judgement_note() {
    let entry = AsepEntry::new(
        "ifeo_debugger",
        "taskmgr.exe",
        "KEY",
        LocationKind::RegistryKey,
    );
    let arts = record::build_entry_artifacts(&entry, &ctx());
    let m = &arts[0].metadata;
    assert_eq!(
        m.get("mitre_technique").and_then(Value::as_str),
        Some("T1546.012")
    );
    assert!(m.get("category_locations").is_some());
    assert!(m
        .get("assessment_note")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("does not determine"));
}

// --- the module itself -------------------------------------------------------

#[test]
fn the_module_identifies_itself_and_subscribes_to_the_records_it_needs() {
    let module = AsepEnumerator::new();
    assert_eq!(module.id(), "plugin.windows.asep");
    let subs = module.subscribes_to();
    assert!(subs.contains(&ArtifactType::FileEntry));
    assert!(subs.contains(&ArtifactType::SystemArtifact));
    assert!(subs.contains(&ArtifactType::ParsedRecord));
}

#[test]
fn the_module_ignores_its_own_output_so_there_is_no_fan_out_loop() {
    let module = AsepEnumerator::new();
    for ty in ["AsepEntry", "AsepCoverage", "LnkFile", "UsbDevice"] {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": ty}),
        );
        assert!(module.process(&art).unwrap().is_empty(), "for {ty}");
    }
}

#[test]
fn a_parsed_hive_record_yields_entries_and_always_a_coverage_record() {
    let module = AsepEnumerator::new();
    let hive = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "total_values": 1,
            "total_keys": 1,
            "all_values": [rv(
                r"ROOT\Microsoft\Windows\CurrentVersion\Run",
                "Thing",
                "C:\\t\\t.exe",
            )],
        }),
    );
    let produced = module.process(&hive).expect("process");
    let types: Vec<&str> = produced
        .iter()
        .filter_map(|a| a.metadata.get("type").and_then(Value::as_str))
        .collect();
    assert!(types.contains(&"AsepEntry"));
    assert!(
        types.contains(&"AsepCoverage"),
        "every examined hive must state what was and was not looked for"
    );
}

#[test]
fn a_hive_record_with_no_values_still_yields_a_coverage_record_saying_nothing_was_read() {
    let module = AsepEnumerator::new();
    let hive = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({"type": "RegistryHive", "hive_type": "SOFTWARE", "total_values": 9000}),
    );
    let produced = module.process(&hive).expect("process");
    assert_eq!(produced.len(), 1);
    assert_eq!(
        produced[0]
            .metadata
            .get("values_unavailable_reason")
            .and_then(Value::as_str)
            .map(|s| s.contains("all_values")),
        Some(true)
    );
}

#[test]
fn a_task_definition_on_the_volume_becomes_an_entry_through_the_module() {
    let module = AsepEnumerator::new();
    let bytes = utf16le_with_bom(TASK_XML);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(bytes),
        json!({
            "name": "Updater",
            "path": "/Windows/System32/Tasks/Contoso/Updater",
        }),
    );
    let produced = module.process(&art).expect("process");
    let entry = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .expect("a scheduled task entry");
    assert_eq!(
        entry.metadata.get("category").and_then(Value::as_str),
        Some("scheduled_task")
    );
    assert_eq!(
        entry.metadata.get("image_path").and_then(Value::as_str),
        Some("C:\\Tools\\upd.exe")
    );
}

#[test]
fn a_file_in_the_task_store_that_is_not_a_task_definition_is_reported_as_unread() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(b"not xml at all".to_vec()),
        json!({"name": "Mystery", "path": "/Windows/System32/Tasks/Mystery"}),
    );
    let produced = module.process(&art).expect("process");
    let entry = &produced[0];
    assert_eq!(
        entry.metadata.get("read_status").and_then(Value::as_str),
        Some("unread"),
        "a file in the task store that will not decode must not vanish from the report"
    );
}

#[test]
fn a_legacy_job_file_is_reported_as_a_known_unread_format() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(vec![0u8; 64]),
        json!({"name": "Old.job", "path": "/Windows/Tasks/Old.job"}),
    );
    let produced = module.process(&art).expect("process");
    let reason = produced[0]
        .metadata
        .get("read_status_reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(reason.contains("Task Scheduler 1.0"));
}

#[test]
fn an_ordinary_file_produces_nothing_but_is_indexed_for_target_resolution() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "svchost.exe", "path": "/Windows/System32/svchost.exe"}),
    );
    assert!(module.process(&art).unwrap().is_empty());

    let hive = Artifact::new(
        art.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "total_values": 1,
            "all_values": [rv(
                r"ROOT\Microsoft\Windows\CurrentVersion\Run",
                "Thing",
                "C:\\Windows\\System32\\svchost.exe",
            )],
        }),
    );
    let produced = module.process(&hive).unwrap();
    let entry = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .unwrap();
    assert_eq!(
        entry.metadata.get("target_exists").and_then(Value::as_str),
        Some("observed_at_path")
    );
}

#[test]
fn a_per_user_hive_is_attributed_to_its_profile_through_the_hive_file_path() {
    let module = AsepEnumerator::new();
    let case_id = Uuid::new_v4();
    let hive_file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "NTUSER.DAT", "path": "/Users/alice/NTUSER.DAT"}),
    );
    assert!(module.process(&hive_file).unwrap().is_empty());

    let hive = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "NTUSER.DAT",
            "total_values": 1,
            "all_values": [rv(
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
                "Thing",
                "C:\\t.exe",
            )],
        }),
    )
    .with_parent(hive_file.id);

    let produced = module.process(&hive).unwrap();
    let entry = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .unwrap();
    assert_eq!(
        entry.metadata.get("user").and_then(Value::as_str),
        Some("alice")
    );
    assert!(entry
        .metadata
        .get("runs_when")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("when alice logs on"));
}

#[test]
fn a_startup_shortcut_reaches_an_entry_through_the_module() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(synthetic_lnk()),
        json!({
            "name": "agent.lnk",
            "path": "/Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/agent.lnk",
            "created": "2024-05-05T10:00:00Z",
        }),
    );
    let produced = module.process(&art).expect("process");
    let entry = &produced[0];
    assert_eq!(
        entry.metadata.get("category").and_then(Value::as_str),
        Some("startup_folder")
    );
    assert_eq!(
        entry.metadata.get("image_path").and_then(Value::as_str),
        Some("C:\\Tools\\agent.exe")
    );
    assert_eq!(
        entry.metadata.get("user").and_then(Value::as_str),
        Some("alice")
    );
    assert_eq!(
        produced.len(),
        2,
        "the shortcut's creation time is a real moment and belongs on the timeline"
    );
}

#[test]
fn a_hive_whose_own_file_was_never_seen_says_it_could_not_be_attributed_to_a_profile() {
    let module = AsepEnumerator::new();
    let hive = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({"type": "RegistryHive", "hive_type": "NTUSER.DAT", "total_values": 0,
               "all_values": []}),
    );
    let produced = module.process(&hive).expect("process");
    let coverage = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepCoverage"))
        .expect("a coverage record");
    let notes = coverage
        .metadata
        .get("scan_notes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        notes
            .iter()
            .filter_map(Value::as_str)
            .any(|n| n.contains("could not be attributed to a user profile")),
        "an unattributed per-user hive must say so; its Run keys otherwise read as \
         applying to every user"
    );
    assert_eq!(
        coverage.metadata.get("user").and_then(Value::as_str),
        None,
        "no profile may be guessed"
    );
}

#[test]
fn only_the_task_scheduler_stores_are_treated_as_task_locations() {
    assert!(is_task_store_path(
        "/windows/system32/tasks/contoso/updater"
    ));
    assert!(is_task_store_path("/windows/syswow64/tasks/thing"));
    assert!(is_task_store_path("/windows/tasks/old.job"));
    assert!(
        !is_task_store_path("/users/alice/downloads/tasks/updater"),
        "an identical XML elsewhere on the volume is not something the Task Scheduler runs"
    );
}

#[test]
fn a_machine_wide_hive_is_attributed_to_no_profile_and_the_default_hive_names_itself() {
    assert_eq!(
        profile_from_hive_path("/Windows/System32/config/SOFTWARE", "SOFTWARE"),
        None
    );
    assert_eq!(
        profile_from_hive_path("/Windows/System32/config/DEFAULT", "DEFAULT").as_deref(),
        Some(".DEFAULT profile")
    );
    assert_eq!(
        profile_from_hive_path(
            "/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat",
            "USRCLASS.DAT"
        )
        .as_deref(),
        Some("alice")
    );
}

#[test]
fn desktop_ini_in_a_startup_folder_is_not_reported_as_something_that_runs() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "desktop.ini",
            "path": "/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini",
        }),
    );
    assert!(module.process(&art).unwrap().is_empty());
}

/// B3-025: ASEP recorded partial entries under its own `incomplete` /
/// `incomplete_reason` keys, which the API, export and cross-plugin honesty
/// paths never read. What an examiner learns from the standard pair: this
/// autostart entry was only partly decoded, and in which way. A wrong answer
/// looks like a task with two of its fifty triggers listed, exported as a
/// complete autostart record.
#[test]
fn a_partial_entry_carries_the_standard_incompleteness_pair() {
    let mut entry = AsepEntry::new(
        "scheduled_task",
        "Partial",
        r"C:\Windows\System32\Tasks\Partial",
        LocationKind::File,
    );
    entry.incomplete_reason = Some("The task declares more triggers than were read.".to_string());
    entry.incomplete_code = Some(seance_core::io::IncompleteReason::CapReached);

    let ctx = EmitContext {
        case_id: Uuid::new_v4(),
        parent_id: Uuid::new_v4(),
        registry_record_id: None,
        file_artifact_id: None,
    };
    let arts = build_entry_artifacts(&entry, &ctx);
    let md = &arts[0].metadata;

    assert_eq!(md["incomplete"], json!(true), "the local key stays");
    assert_eq!(
        md["content_incomplete"],
        json!(true),
        "the standard flag must be set or downstream honesty tooling sees nothing"
    );
    assert_eq!(md["content_incomplete_reason"], json!("cap_reached"));
}

/// B3-025 control: a fully decoded entry must carry no standard flag at all, so
/// its absence really does mean "this is everything the evidence held".
#[test]
fn a_complete_entry_carries_no_standard_incompleteness_pair() {
    let entry = AsepEntry::new(
        "run_key",
        "Complete",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
        LocationKind::RegistryKey,
    );
    let ctx = EmitContext {
        case_id: Uuid::new_v4(),
        parent_id: Uuid::new_v4(),
        registry_record_id: None,
        file_artifact_id: None,
    };
    let arts = build_entry_artifacts(&entry, &ctx);
    let md = &arts[0].metadata;

    assert_eq!(md["incomplete"], json!(false));
    assert!(md.get("content_incomplete").is_none());
    assert!(md.get("content_incomplete_reason").is_none());
}

/// B3-025 swept: the hive coverage record used the same ASEP-local key. A
/// capped scan must be visible to the standard consumers too.
#[test]
fn a_capped_coverage_record_carries_the_standard_incompleteness_pair() {
    let mut summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    summary.values_total = 10;
    summary.values_scanned = 5;
    summary.scan_capped = true;
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

    assert_eq!(art.metadata["incomplete"], json!(true));
    assert_eq!(art.metadata["content_incomplete"], json!(true));
    assert_eq!(
        art.metadata["content_incomplete_reason"],
        json!("cap_reached")
    );
    assert_eq!(art.metadata["inventory_incomplete"], json!(true));
}

/// A source that declares more bytes than it will hand over, so the ASEP task
/// reader's short-read path can be exercised.
#[derive(Debug)]
struct ShortTaskSource {
    bytes: Vec<u8>,
    declared: u64,
}

impl DataSource for ShortTaskSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = offset as usize;
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.bytes.len() - start);
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.declared
    }
}

/// B7-017: a task definition the source could not deliver in full parsed as a
/// complete task, because incompleteness was only recorded when the read hit
/// the byte ceiling. A trigger declared past the shortfall would be absent with
/// nothing saying so.
#[test]
fn a_task_definition_read_short_of_its_declared_size_is_marked_incomplete() {
    let module = AsepEnumerator::new();
    let bytes = utf16le_with_bom(TASK_XML);
    let declared = bytes.len() as u64 + 4096;
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ShortTaskSource { bytes, declared }) as Arc<dyn DataSource>),
        json!({
            "name": "Updater",
            "path": "/Windows/System32/Tasks/Contoso/Updater",
        }),
    );
    let produced = module.process(&art).expect("process");
    let entry = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .expect("a scheduled task entry");
    assert_eq!(
        entry.metadata.get("content_incomplete"),
        Some(&json!(true)),
        "a task read short of its declared size is not a complete definition"
    );
    assert_eq!(
        entry
            .metadata
            .get("content_incomplete_reason")
            .and_then(Value::as_str),
        Some("short_read"),
        "a short read is not a cap: the follow-up differs"
    );
}

/// The counterpart: a task file read whole must stay unmarked, or the marker
/// means nothing. Previously a file exactly at the ceiling was marked capped
/// even though every byte of it had been read.
#[test]
fn a_task_definition_read_whole_carries_no_incompleteness() {
    let module = AsepEnumerator::new();
    let bytes = utf16le_with_bom(TASK_XML);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(bytes),
        json!({
            "name": "Updater",
            "path": "/Windows/System32/Tasks/Contoso/Updater",
        }),
    );
    let produced = module.process(&art).expect("process");
    let entry = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .expect("a scheduled task entry");
    assert_eq!(
        entry.metadata.get("content_incomplete"),
        None,
        "a task read whole must not carry an incompleteness marker"
    );
}

// --- File associations (T1546.001): the report, not the accusation ----------
//
// `ROADMAP` §2.5. The whole of this sub-item is what these records refuse to
// say. Windows writes `UserChoice` every time a user picks an application in
// the Open With dialog, so the key's presence is the ordinary state of the
// system — one real Windows 7 user hive, `NTUSER-WIN7.DAT`, carries
// `UserChoice` for **17** extensions and **138** `OpenWithProgids` candidates.
// A classifier that fired on presence would fire 155 times on that one hive, which is
// `HUNT-122` verbatim: a rule whose false-positive rate is the population.
//
// The counts above were measured through this project's own hive reader, not
// taken from the plan that scoped this work — which said 87, and was wrong.
// A number in a record is generated or verified here, never typed.

/// A `UserChoice` key yields the association in force, naming the extension and
/// the ProgId.
#[test]
fn a_userchoice_key_reports_the_association_in_force() {
    let out = run_scan(
        "NTUSER.DAT",
        &[rv(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice",
            "ProgId",
            "Applications\\notepad++.exe",
        )],
    );
    let hits = find(&out.entries, "file_association");
    assert_eq!(hits.len(), 1);
    let e = hits[0];
    assert_eq!(e.extra["extension"], json!(".txt"));
    assert_eq!(e.extra["prog_id"], json!("Applications\\notepad++.exe"));
    assert_eq!(e.extra["association_in_force"], json!(true));
    assert!(e.entry_name.contains(".txt"));
}

/// **No record says "hijack".**
///
/// Not in a field, not in an observation, not in the entry name. "Hijack" is a
/// comparison against a default and there is no baseline in the evidence to
/// make it against.
#[test]
fn no_file_association_record_uses_the_word_hijack_as_a_claim() {
    let out = run_scan(
        "NTUSER.DAT",
        &[rv(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice",
            "ProgId",
            "Applications\\evil.exe",
        )],
    );
    let e = find(&out.entries, "file_association")[0];
    assert_eq!(e.extra["hijack_claim"], json!(false));

    let text = serde_json::to_string(&e.extra).expect("serialise")
        + &e.entry_name
        + &e.observations
            .iter()
            .map(|o| o.statement.clone())
            .collect::<String>();
    // The word may appear only inside the sentence that refuses the claim.
    let lower = text.to_ascii_lowercase();
    for accusation in ["is a hijack", "hijacked", "hijacking"] {
        assert!(
            !lower.contains(accusation),
            "a file-association record must not accuse: found {accusation:?}"
        );
    }
    assert!(
        e.observations.iter().any(|o| o.code == "no_hijack_claim"),
        "and it must say in words why it makes no such claim"
    );
}

/// The `Hash` value's existence is reported, and that it was **not verified**.
///
/// It is a MAC over the user's SID, the extension and the ProgId, which Windows
/// verifies at logon and which cannot be recomputed from an image. Saying
/// nothing would let the absence of a verdict read as a passing one.
#[test]
fn the_userchoice_hash_is_reported_as_present_and_not_verified() {
    let out = run_scan(
        "NTUSER.DAT",
        &[
            rv(
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice",
                "ProgId",
                "txtfile",
            ),
            rv(
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice",
                "Hash",
                "xEQ0k5tCjXg=",
            ),
        ],
    );
    let hits = find(&out.entries, "file_association");
    assert_eq!(
        hits.len(),
        1,
        "the Hash is a fact about the key, not an association of its own"
    );
    let e = hits[0];
    assert_eq!(e.extra["hash_verified"], json!("not verifiable offline"));
    let note = e
        .observations
        .iter()
        .find(|o| o.code == "userchoice_hash_not_verified")
        .expect("the hash note");
    assert!(
        note.statement.contains("exists and was not made"),
        "the reader must know the check exists and was skipped: {:?}",
        note.statement
    );
}

/// `OpenWithProgids` is **not** the association in force.
///
/// It lists the candidates offered in the Open With dialog. Reading one as the
/// default would name the wrong program as the handler for the extension.
#[test]
fn openwithprogids_is_reported_as_a_candidate_and_not_as_the_default() {
    let out = run_scan(
        "NTUSER.DAT",
        &[rv(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids",
            "txtfile",
            "",
        )],
    );
    let hits = find(&out.entries, "file_association");
    assert_eq!(hits.len(), 1);
    let e = hits[0];
    assert_eq!(e.extra["association_in_force"], json!(false));
    assert_eq!(
        e.extra["prog_id"],
        json!("txtfile"),
        "the ProgId is the value NAME here"
    );
    assert!(
        e.observations
            .iter()
            .any(|o| o.code == "association_candidate_only"),
        "it must say it is a candidate and not the default"
    );
}

/// A segment that is not an extension is not a file-association key.
///
/// `FileExts` has non-extension subkeys, and a matcher that accepted any
/// segment would report them as associations for an extension that is not one.
#[test]
fn a_non_extension_segment_is_not_a_file_association() {
    let base = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
    for seg in ["txt", ".", "UserChoice"] {
        let out = run_scan(
            "NTUSER.DAT",
            &[rv(
                &format!(r"{base}\{seg}\UserChoice"),
                "ProgId",
                "txtfile",
            )],
        );
        assert!(
            find(&out.entries, "file_association").is_empty(),
            "segment {seg:?} is not an extension"
        );
    }
}

/// The category's own coverage statement carries the honesty constraint, so a
/// reader of the report — not just of one record — is told that presence is
/// normal and that the hash is not checkable.
#[test]
fn the_file_association_category_states_why_presence_is_not_the_technique() {
    let cat = crate::rules::category("file_association").expect("the category is registered");
    assert_eq!(cat.technique, Some("T1546.001"));
    let note = cat.technique_note.expect("a technique note");
    assert!(
        note.contains("Presence here is NOT the technique"),
        "got {note:?}"
    );
    assert!(
        note.contains("17 extensions") && note.contains("138"),
        "the MEASURED counts belong in it -- the plan said 87 and a check of the hive said \
         17 and 138, and a number here is verified rather than typed: {note:?}"
    );
    let partial = cat.partial_reason.expect("a partial reason");
    assert!(
        partial.contains("cannot be recomputed offline"),
        "the hash limit belongs on the category too: {partial:?}"
    );
}

// --- Installed shim databases (T1546.011) -----------------------------------
//
// `ROADMAP` §1.7. The `.sdb` parser reads a database's contents; this is what
// tells an examiner that one is **registered** on the machine, and against
// which executable. Before it, application shimming was not even listed as
// unexamined on the ASEP coverage record, so its absence was silent.

/// An `InstalledSDB` registration becomes an entry naming the database path.
#[test]
fn an_installed_shim_database_registration_becomes_an_entry() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{4dcd3b0a-cfd7-4d1e-9bbd-2c3f3e5f4c11}";
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(
                key,
                "DatabasePath",
                r"C:\Windows\AppPatch\Custom\{4dcd3b0a}.sdb",
            ),
            rv(key, "DatabaseDescription", "Totally Legitimate Fix"),
            dword(key, "DatabaseType", 0x10000),
        ],
    );
    let hits = find(&out.entries, "installed_sdb");
    assert_eq!(
        hits.len(),
        1,
        "one entry per registration, built from its DatabasePath -- the other values are not \
         entries of their own"
    );
    let e = hits[0];
    assert_eq!(
        e.extra["database_path"],
        json!(r"C:\Windows\AppPatch\Custom\{4dcd3b0a}.sdb")
    );
    // The link to the parsed database is a FIELD, not a finding.
    assert!(
        e.observations
            .iter()
            .any(|o| o.code == "database_path_recorded"
                && o.statement.contains("draws no conclusion")),
        "the link must be recorded without a conclusion: {:?}",
        e.observations
    );
    // And presence is not the technique.
    assert!(
        e.observations
            .iter()
            .any(|o| o.code == "presence_is_not_the_technique"),
        "Windows registers its own databases here too"
    );
}

/// A `Custom` key names the **executable** the shim is applied to, and decodes
/// its install time from a 64-bit value.
///
/// The executable is in the KEY NAME, not in a value, which is the detail that
/// yields an empty record when missed.
#[test]
fn a_custom_shim_key_names_the_executable_and_its_install_time() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\evil.exe\{4dcd3b0a-cfd7-4d1e-9bbd-2c3f3e5f4c11}.sdb";
    // The registry plugin renders a REG_QWORD as `0x%016x (n)`.
    let rendered = format!(
        "0x{:016x} ({})",
        132_635_232_000_000_000u64, 132_635_232_000_000_000u64
    );
    let out = run_scan("SOFTWARE", &[rv(key, "", &rendered)]);
    let hits = find(&out.entries, "installed_sdb");
    assert_eq!(hits.len(), 1);
    let e = hits[0];
    assert_eq!(e.extra["applied_to_executable"], json!("evil.exe"));
    assert_eq!(
        e.extra["install_filetime_raw"],
        json!(132_635_232_000_000_000u64)
    );
    assert!(
        e.extra["installed"]
            .as_str()
            .unwrap_or("")
            .starts_with("2021-"),
        "the FILETIME must decode: {:?}",
        e.extra["installed"]
    );
    assert!(
        e.observations
            .iter()
            .any(|o| o.code == "applied_to_recorded"),
        "the record must say what the key establishes"
    );
}

/// A 64-bit install time must not be parsed as a 32-bit one.
///
/// A FILETIME does not fit in 32 bits, and a `u32` parse of one yields `None`
/// — which would read as "no install time recorded" rather than "this build
/// could not read it". That is why `parse_qword` exists beside `parse_dword`
/// rather than the latter being reused.
#[test]
fn a_sixty_four_bit_install_time_is_not_parsed_as_a_thirty_two_bit_one() {
    let big = 132_635_232_000_000_000u64;
    assert!(big > u32::MAX as u64);
    let rendered = format!("0x{big:016x} ({big})");
    assert_eq!(crate::normalize::parse_qword(&rendered), Some(big));
    assert_eq!(
        crate::normalize::parse_dword(&rendered),
        None,
        "and the 32-bit parser cannot read it, which is the whole reason for the new one"
    );
    // The bare hex and bare decimal forms both work.
    assert_eq!(
        crate::normalize::parse_qword(&format!("0x{big:016x}")),
        Some(big)
    );
    assert_eq!(crate::normalize::parse_qword(&big.to_string()), Some(big));
}

/// An install time that will not read is **absent with a reason**, not absent.
#[test]
fn an_unreadable_install_time_says_why_it_is_absent() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\evil.exe\{g}.sdb";
    let out = run_scan("SOFTWARE", &[rv(key, "", "not a number at all")]);
    let e = find(&out.entries, "installed_sdb")[0];
    // `.get`, not indexing: `serde_json::Map` panics on a missing key, and the
    // point of this case is that the field is ABSENT.
    assert!(
        e.extra.get("installed").is_none(),
        "an install time that would not read must be absent, not zero or defaulted"
    );
    assert!(e.extra.get("install_filetime_raw").is_none());
    let note = e
        .observations
        .iter()
        .find(|o| o.code == "install_time_unreadable")
        .expect("a reason");
    assert!(
        note.statement.contains("present in the registry"),
        "absence here is this build's limit, not the registry's: {:?}",
        note.statement
    );
}

/// Nothing unrelated is an installed-shim key.
#[test]
fn an_unrelated_appcompatflags_key_is_not_an_installed_shim() {
    for key in [
        r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
        r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
        r"ROOT\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
    ] {
        let out = run_scan("SOFTWARE", &[rv(key, "DatabasePath", r"C:\x.sdb")]);
        assert!(find(&out.entries, "installed_sdb").is_empty(), "for {key}");
    }
}

/// The category is in the table, so the coverage record reports it for every
/// hive — and application shimming can never be silently missing again.
#[test]
fn the_installed_sdb_category_is_registered_so_its_absence_is_never_silent() {
    let cat = crate::rules::category("installed_sdb").expect("registered");
    assert_eq!(cat.technique, Some("T1546.011"));
    assert_eq!(cat.label, "Installed shim database");
    assert!(
        cat.technique_note
            .unwrap_or("")
            .contains("presence of an entry is not by itself the technique"),
        "got {:?}",
        cat.technique_note
    );
    assert_eq!(cat.hives, &[HiveKind::Software]);
    assert_eq!(cat.locations.len(), 2, "both registration forms");
}

// --- HUNT-249: per-source search rule from Microsoft's documentation ---------

/// `HUNT-249`: `CreateService` documents `lpBinaryPathName` (stored as
/// `ImagePath`) as "the fully qualified path to the service binary file", so a
/// bare `ImagePath` is outside the documented contract. The record says that,
/// and names the shell's list as leads rather than as the SCM's rule. The
/// fixture pins the mechanism only; no real service with a bare `ImagePath`
/// is held. A share-process service is the case: only an own-process service
/// was run on the observed build (`LAUNCH-1`), and that one is pinned below.
#[test]
fn a_service_image_path_bare_name_is_resolved_under_the_documented_full_path_contract() {
    let key = r"ROOT\ControlSet001\Services\Planted";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(
        s.search_context.rule,
        SearchRule::FullPathRequired(FullPathSource::ServiceImagePath)
    );
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/evilsvc.exe");
    let res = index.resolve_in(s.image.as_deref(), &s.search_context);
    // The launcher's resolution of a bare name is undocumented, so a file at a
    // candidate is a lead, never "observed at path" (`HUNT-249` review).
    assert_eq!(
        res.status,
        TargetStatus::ObservedByNameOnly,
        "{}",
        res.basis
    );
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_LEAD_OBSERVED)
    );
    assert_eq!(
        res.lookup_path.as_deref(),
        Some("/windows/system32/evilsvc.exe")
    );
    assert_eq!(res.search_rule, Some("full_path_required"));
    assert_eq!(res.search_path_candidates.len(), 12);
    assert!(
        res.basis.contains("fully qualified path") && res.basis.contains("CreateService"),
        "{}",
        res.basis
    );
    assert!(res.basis.contains("not documented"), "{}", res.basis);
    assert!(res.basis.contains("lead"), "{}", res.basis);
    assert!(
        !res.basis.contains("Windows resolves") && !res.basis.contains("search-path candidate"),
        "the basis must not claim the launcher's resolution: {}",
        res.basis
    );
    assert!(
        res.basis.contains("service control manager"),
        "a Type 0x10 service names its launcher: {}",
        res.basis
    );
}

/// The miss wording under `full_path_required` names the candidates as leads,
/// and `lookup_path` is not presented as a search-path convention.
#[test]
fn a_full_path_required_miss_names_its_candidates_as_leads() {
    let key = r"ROOT\ControlSet001\Services\Planted";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    let mut index = EvidenceIndex::new();
    index.note_file("/Windows/System32/other.exe");
    let res = index.resolve_in(s.image.as_deref(), &s.search_context);
    assert_eq!(res.status, TargetStatus::NotObserved, "{}", res.basis);
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_LEAD_NOT_OBSERVED)
    );
    assert!(res.basis.contains("lead"), "{}", res.basis);
    assert!(
        !res.basis.contains("search-path candidate"),
        "{}",
        res.basis
    );

    // A file of a candidate name elsewhere is still only a name match.
    let mut index = EvidenceIndex::new();
    index.note_file("/Users/Public/evilsvc.exe");
    let res = index.resolve_in(s.image.as_deref(), &s.search_context);
    assert_eq!(
        res.status,
        TargetStatus::ObservedByNameOnly,
        "{}",
        res.basis
    );
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_LEAD_NOT_OBSERVED)
    );
    assert!(!res.basis.contains("search-path"), "{}", res.basis);
}

/// A kernel driver's `ImagePath` is loaded by the kernel, not the service
/// control manager; the statement must not misname the launcher. `Start` 0/1
/// are defined for drivers only, so they mark a driver when `Type` is absent.
/// A service whose `Type` is absent and whose start type is not 0/1 names
/// either launcher. Synthetic fixtures: the mechanism only.
#[test]
fn a_driver_image_path_does_not_name_the_service_control_manager() {
    for (ty, start, want) in [
        (Some(1u32), Some(3u32), FullPathSource::DriverImagePath),
        (Some(2), Some(3), FullPathSource::DriverImagePath),
        (None, Some(0), FullPathSource::DriverImagePath),
        (None, Some(1), FullPathSource::DriverImagePath),
        (Some(0x10), Some(1), FullPathSource::ServiceImagePath),
        (None, Some(2), FullPathSource::UnknownTypeImagePath),
    ] {
        let key = r"ROOT\ControlSet001\Services\Planted";
        let mut vals = vec![rv(key, "ImagePath", "evildrv")];
        if let Some(t) = ty {
            vals.push(dword(key, "Type", t));
        }
        if let Some(st) = start {
            vals.push(dword(key, "Start", st));
        }
        let out = run_scan("SYSTEM", &vals);
        let s = find(&out.entries, "service")[0];
        assert_eq!(
            s.search_context.rule,
            SearchRule::FullPathRequired(want),
            "Type {ty:?} Start {start:?}"
        );
        let statement = s.search_context.rule.statement();
        match want {
            FullPathSource::DriverImagePath => {
                assert!(
                    !statement.contains("service control manager"),
                    "{statement}"
                );
                assert!(statement.contains("kernel"), "{statement}");
            }
            FullPathSource::UnknownTypeImagePath => {
                assert!(
                    statement.contains("service control manager") && statement.contains("kernel"),
                    "{statement}"
                );
            }
            _ => assert!(statement.contains("service control manager"), "{statement}"),
        }
    }
}

/// Per-user service templates and their instances are user-mode services the
/// service control manager starts. winnt.h defines `SERVICE_USER_SERVICE`
/// (0x40), `SERVICE_USER_OWN_PROCESS` (0x50), `SERVICE_USER_SHARE_PROCESS`
/// (0x60) and the `SERVICE_USERSERVICE_INSTANCE` bit (0x80), so 0xD0 and 0xE0
/// are per-user instances, not an unknown type. `SERVICE_ADAPTER` (0x4) is
/// documented only as "reserved", so it names no launcher and stays unknown.
/// Synthetic fixtures: the mechanism only.
#[test]
fn a_per_user_service_type_is_held_to_the_service_image_path_contract() {
    for (ty, want) in [
        (0x50u32, FullPathSource::ServiceImagePath),
        (0x60, FullPathSource::ServiceImagePath),
        (0xD0, FullPathSource::ServiceImagePath),
        (0xE0, FullPathSource::ServiceImagePath),
        (0x1D0, FullPathSource::ServiceImagePath),
        (0x4, FullPathSource::UnknownTypeImagePath),
    ] {
        let key = r"ROOT\ControlSet001\Services\PerUser";
        let out = run_scan(
            "SYSTEM",
            &[
                rv(key, "ImagePath", "evilsvc"),
                dword(key, "Type", ty),
                dword(key, "Start", 3),
            ],
        );
        let s = find(&out.entries, "service")[0];
        assert_eq!(
            s.search_context.rule,
            SearchRule::FullPathRequired(want),
            "Type {ty:#x}"
        );
    }
}

/// The labels follow winnt.h: 0x40 is the user-service flag, 0x50 and 0x60 are
/// the user own- and shared-process templates, and the 0x80 bit marks a
/// per-user instance of one. The earlier table called 0x60 an instance and 0x40
/// an own-process service.
#[test]
fn a_service_type_label_follows_the_winnt_definitions() {
    use crate::services::service_type_label;
    for (ty, want) in [
        (0x40u32, Some("User service")),
        (0x50, Some("User own-process service")),
        (0x60, Some("User shared-process service")),
        (0xD0, Some("User own-process service (per-user instance)")),
        (
            0xE0,
            Some("User shared-process service (per-user instance)"),
        ),
        (0x110, Some("Own-process service (interactive)")),
        (0x80, None),
        (0x90, None),
    ] {
        assert_eq!(service_type_label(ty).as_deref(), want, "Type {ty:#x}");
    }
}

/// A shared-process service reports its `ServiceDll`, which the service host
/// loads; `CreateService`'s `ImagePath` contract says nothing about it, so the
/// default rule and its "not established" statement stay.
#[test]
fn a_service_dll_is_not_held_to_the_image_path_contract() {
    let key = r"ROOT\ControlSet001\Services\Shared";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            rv(
                key,
                "ImagePath",
                "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            ),
            rv(&format!("{key}\\Parameters"), "ServiceDll", "shared.dll"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(s.search_context.rule, SearchRule::ShellPathext);
}

/// `HUNT-249`: an IFEO `Debugger` has an observed rule (pinned above);
/// `SilentProcessExit`'s `MonitorProcess` has neither documentation nor an
/// observation, so it keeps the default.
#[test]
fn a_silent_process_exit_monitor_keeps_the_default_rule_beside_an_observed_debugger() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(
                r"ROOT\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
                "Debugger",
                "cmd",
            ),
            rv(
                r"ROOT\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe",
                "MonitorProcess",
                "mon",
            ),
        ],
    );
    let ifeo = find(&out.entries, "ifeo_debugger");
    let monitor = ifeo
        .iter()
        .find(|e| e.entry_name == "notepad.exe")
        .expect("monitor entry");
    assert_eq!(monitor.search_context.rule, SearchRule::ShellPathext);
}

/// `HUNT-249` review: with no file index the record must still not call the
/// candidates the search-path convention. Under `full_path_required` the
/// resolution is `lead_candidate_not_observed`, as it is with an index.
#[test]
fn a_full_path_required_entry_with_no_file_index_is_not_called_the_search_path_convention() {
    let key = r"ROOT\ControlSet001\Services\Planted";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    let res = EvidenceIndex::new().resolve_in(s.image.as_deref(), &s.search_context);
    assert_eq!(res.status, TargetStatus::NoFileIndex, "{}", res.basis);
    assert_eq!(res.search_rule, Some("full_path_required"));
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_LEAD_NOT_OBSERVED)
    );
    // The default rule keeps its search-path wording.
    let res = EvidenceIndex::new().resolve_in(Some("evil"), &SearchContext::default());
    assert_eq!(
        res.search_path_resolution,
        Some(crate::index::SEARCH_PATH_CONVENTION)
    );
}

/// `HUNT-249` review: the expansion a `full_path_required` record carries
/// must not say Windows resolves the bare name on the search path, because
/// the basis says that resolution is undocumented. Checked on a hit, a miss
/// and with no index.
#[test]
fn a_full_path_required_expansion_does_not_claim_the_search_path() {
    let key = r"ROOT\ControlSet001\Services\Planted";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    let mut hit = EvidenceIndex::new();
    hit.note_file("/Windows/System32/evilsvc.exe");
    let mut miss = EvidenceIndex::new();
    miss.note_file("/Windows/System32/other.exe");
    for index in [hit, miss, EvidenceIndex::new()] {
        let res = index.resolve_in(s.image.as_deref(), &s.search_context);
        let exp = res.expansion.expect("a bare name records its expansion");
        assert!(!exp.contains("search path"), "{exp}");
        assert!(exp.contains("lead"), "{exp}");
        assert!(exp.contains("not documented"), "{exp}");
    }
    // The default rule keeps the search-path expansion.
    let res = EvidenceIndex::new().resolve_in(Some("evil"), &SearchContext::default());
    assert_eq!(res.expansion, Some(crate::normalize::BARE_NAME_EXPANSION));
}

/// `HUNT-249` review: a driver's lead candidates include the kernel's usual
/// driver directory and `.sys`, so a planted `evildrv.sys` under
/// `System32\drivers` is a lead observed, not a miss. The same holds when
/// `Type` does not say service or driver. A service's candidates do not
/// change. Synthetic fixtures: the mechanism only.
#[test]
fn a_driver_lead_list_includes_the_drivers_directory_and_sys() {
    for (ty, start) in [(Some(1u32), Some(0u32)), (None, Some(2))] {
        let key = r"ROOT\ControlSet001\Services\Planted";
        let mut vals = vec![rv(key, "ImagePath", "evildrv")];
        if let Some(t) = ty {
            vals.push(dword(key, "Type", t));
        }
        if let Some(st) = start {
            vals.push(dword(key, "Start", st));
        }
        let out = run_scan("SYSTEM", &vals);
        let s = find(&out.entries, "service")[0];
        let mut index = EvidenceIndex::new();
        index.note_file("/Windows/System32/drivers/evildrv.sys");
        let res = index.resolve_in(s.image.as_deref(), &s.search_context);
        assert_eq!(
            res.search_path_resolution,
            Some(crate::index::SEARCH_PATH_LEAD_OBSERVED),
            "Type {ty:?}: {}",
            res.basis
        );
        assert_eq!(
            res.lookup_path.as_deref(),
            Some("/windows/system32/drivers/evildrv.sys")
        );
        assert_eq!(res.status, TargetStatus::ObservedByNameOnly);
        assert!(
            s.search_context.rule.statement().contains(".sys"),
            "{}",
            s.search_context.rule.statement()
        );
    }
}

// --- PowerShell -EncodedCommand ------------------------------------------------

/// UTF-16LE base64 of `Write-Host 'hi'`, made with Python's
/// `base64.b64encode("Write-Host 'hi'".encode("utf-16-le"))`.
const ENC_WRITE_HOST: &str = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA";

#[test]
fn an_encoded_powershell_command_is_decoded_from_utf16le_base64() {
    for cmd in [
        format!("powershell.exe -enc {ENC_WRITE_HOST}"),
        format!("cmd /C powershell.exe -Sta -Nop -Window Hidden -enc {ENC_WRITE_HOST}"),
        format!("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoP -E {ENC_WRITE_HOST}"),
        format!("pwsh -EncodedCommand \"{ENC_WRITE_HOST}\""),
        format!("PowerShell /ec {ENC_WRITE_HOST}"),
    ] {
        match powershell_encoded_command(&cmd) {
            Some(EncodedCommand::Decoded { script, .. }) => {
                assert_eq!(script, "Write-Host 'hi'", "{cmd}")
            }
            other => panic!("{cmd}: {other:?}"),
        }
    }
}

#[test]
fn a_command_without_powershell_or_without_an_encoded_parameter_has_nothing_to_decode() {
    assert_eq!(
        powershell_encoded_command(&format!("cmd.exe -enc {ENC_WRITE_HOST}")),
        None
    );
    assert_eq!(
        powershell_encoded_command("powershell.exe -ExecutionPolicy Bypass -File a.ps1"),
        None
    );
    // -EncodedArguments is not -EncodedCommand.
    assert_eq!(
        powershell_encoded_command(&format!("powershell -EncodedArguments {ENC_WRITE_HOST}")),
        None
    );
    assert_eq!(powershell_encoded_command("cscript KernCap.vbs"), None);
}

#[test]
fn an_encoded_argument_that_does_not_decode_says_why_and_publishes_no_script() {
    for (cmd, why) in [
        ("powershell -enc", "no argument"),
        ("powershell -enc not*base64", "base64"),
        ("powershell -enc QUJD", "UTF-16LE"), // "ABC": three bytes, odd length
    ] {
        match powershell_encoded_command(cmd) {
            Some(EncodedCommand::Undecodable { reason, .. }) => {
                assert!(reason.contains(why), "{cmd}: {reason}")
            }
            other => panic!("{cmd}: {other:?}"),
        }
    }
}

#[test]
fn an_entry_whose_command_carries_an_encoded_powershell_command_publishes_the_decoded_script() {
    let mut e = AsepEntry::new(
        "run_key",
        "Updater",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        LocationKind::RegistryKey,
    );
    e.command = Some(format!("powershell.exe -w hidden -enc {ENC_WRITE_HOST}"));
    let arts = record::build_entry_artifacts(&e, &ctx());
    let m = &arts[0].metadata;
    assert_eq!(m["powershell_encoded_command_decoded"], "Write-Host 'hi'");
    assert_eq!(m["powershell_encoded_command_parameter"], "-enc");
}

// --- HUNT-249: launcher rules observed on a live Windows 11 25H2 -------------
//
// The rules below were established by running each launcher on Windows 11
// 25H2 build 26200.6584 (`tests/fixtures/launcher_rules/`, `VALIDATION.md`
// `LAUNCH-1`). These tests pin that the code applies what was observed; the
// synthetic hives here stand for no evidence of their own.

/// Resolve `image` under `entry`'s context against an index holding `files`.
fn resolve_with(entry: &AsepEntry, files: &[&str]) -> crate::index::TargetResolution {
    let mut index = EvidenceIndex::new();
    for f in files {
        index.note_file(f);
    }
    index.resolve_in(entry.image.as_deref(), &entry.search_context)
}

fn candidate_names(res: &crate::index::TargetResolution) -> Vec<String> {
    res.search_path_candidates
        .iter()
        .filter(|c| c.starts_with("/windows/system32/"))
        .map(|c| c.trim_start_matches("/windows/system32/").to_string())
        .collect()
}

/// The service control manager started an own-process service with a bare
/// `ImagePath` only from a `.exe`; `.com`, `.bat`, `.cmd` and `.vbs` copies
/// failed with error 2.
#[test]
fn an_own_process_service_bare_image_path_is_resolved_as_exe_only_as_observed() {
    let key = r"ROOT\ControlSet001\Services\Planted";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x10),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(
        s.search_context.rule,
        SearchRule::Observed(ObservedLauncher::ServiceOwnProcess)
    );
    // A .bat of the name is not what the SCM would start.
    let res = resolve_with(s, &["/Windows/System32/evilsvc.bat"]);
    assert_eq!(candidate_names(&res), vec!["evilsvc.exe"]);
    assert_ne!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    let res = resolve_with(s, &["/Windows/System32/evilsvc.exe"]);
    assert_eq!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    assert_eq!(res.search_rule, Some("observed_exe_only"));
    assert!(res.basis.contains("26200.6584"), "{}", res.basis);
    assert!(
        res.basis.contains("service control manager"),
        "{}",
        res.basis
    );
    assert!(
        res.basis.contains("Other Windows versions were not tested"),
        "{}",
        res.basis
    );
}

/// Only an own-process service was run; a share-process service keeps the
/// documented full-path contract and its leads.
#[test]
fn a_share_process_service_bare_image_path_keeps_the_documented_contract() {
    let key = r"ROOT\ControlSet001\Services\Shared";
    let out = run_scan(
        "SYSTEM",
        &[
            dword(key, "Start", 2),
            dword(key, "Type", 0x20),
            rv(key, "ImagePath", "evilsvc"),
        ],
    );
    let s = find(&out.entries, "service")[0];
    assert_eq!(
        s.search_context.rule,
        SearchRule::FullPathRequired(FullPathSource::ServiceImagePath)
    );
}

/// An IFEO `Debugger` bare name started only as `.exe` when the target was
/// launched through `CreateProcess`.
#[test]
fn an_ifeo_debugger_bare_name_is_resolved_as_exe_only_as_observed() {
    let out = run_scan(
        "SOFTWARE",
        &[rv(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
            "Debugger",
            "evil",
        )],
    );
    let d = find(&out.entries, "ifeo_debugger")[0];
    assert_eq!(
        d.search_context.rule,
        SearchRule::Observed(ObservedLauncher::IfeoDebugger)
    );
    let res = resolve_with(d, &["/Windows/System32/evil.exe"]);
    assert_eq!(candidate_names(&res), vec!["evil.exe"]);
    assert_eq!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    assert!(res.basis.contains("ShellExecute"), "{}", res.basis);
}

/// A bare element of Winlogon's `Userinit` list ran only as `.exe`; the rest
/// failed with Winlogon event 4006. `Shell` was not tested and keeps the
/// default.
#[test]
fn a_userinit_bare_element_is_resolved_as_exe_only_and_shell_keeps_the_default() {
    let key = r"ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(key, "Userinit", "C:\\Windows\\system32\\userinit.exe,evil"),
            rv(key, "Shell", "explorer.exe,evil2"),
        ],
    );
    let ui = find(&out.entries, "winlogon_userinit");
    let evil = ui
        .iter()
        .find(|e| e.image.as_deref() == Some("evil"))
        .expect("the appended element");
    assert_eq!(
        evil.search_context.rule,
        SearchRule::Observed(ObservedLauncher::WinlogonUserinit)
    );
    let res = resolve_with(evil, &["/Windows/System32/evil.cmd"]);
    assert_eq!(candidate_names(&res), vec!["evil.exe"]);
    assert!(res.basis.contains("4006"), "{}", res.basis);
    let shell = find(&out.entries, "winlogon_shell");
    let evil2 = shell
        .iter()
        .find(|e| e.image.as_deref() == Some("evil2"))
        .expect("the appended shell element");
    assert_eq!(evil2.search_context.rule, SearchRule::ShellPathext);
}

/// Explorer (`Run`) and `runonce.exe` (`RunOnce`) ran a bare name's `.com`,
/// `.exe`, `.bat`, `.cmd` and `.pif` copies, `.com` first, and never `.vbs`,
/// `.js` or `.lnk`. Keys not tested keep the default.
#[test]
fn a_run_key_bare_name_uses_the_observed_run_key_extensions() {
    let out = run_scan(
        "SOFTWARE",
        &[
            rv(r"ROOT\Microsoft\Windows\CurrentVersion\Run", "A", "evil"),
            rv(
                r"ROOT\Microsoft\Windows\CurrentVersion\RunOnce",
                "B",
                "evil",
            ),
            rv(
                r"ROOT\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                "C",
                "evil",
            ),
            rv(
                r"ROOT\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                "D",
                "evil",
            ),
        ],
    );
    let runs = find(&out.entries, "run_key");
    let by = |n: &str| *runs.iter().find(|e| e.entry_name == n).expect(n);
    for n in ["A", "B"] {
        assert_eq!(
            by(n).search_context.rule,
            SearchRule::Observed(ObservedLauncher::RunKey),
            "{n}"
        );
    }
    for n in ["C", "D"] {
        assert_eq!(by(n).search_context.rule, SearchRule::ShellPathext, "{n}");
    }
    let res = resolve_with(by("A"), &["/Windows/System32/evil.pif"]);
    assert_eq!(
        candidate_names(&res),
        vec!["evil.com", "evil.exe", "evil.bat", "evil.cmd", "evil.pif"]
    );
    assert_eq!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    assert_eq!(res.search_rule, Some("observed_run_key"));
    assert!(res.basis.contains("App Paths"), "{}", res.basis);
    // A .vbs of the name is not what Explorer would start.
    let res = resolve_with(by("A"), &["/Windows/System32/evil.vbs"]);
    assert_ne!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);

    let user = run_scan(
        "NTUSER.DAT",
        &[
            rv(
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
                "E",
                "evil",
            ),
            rv(
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "F",
                "evil",
            ),
        ],
    );
    let uruns = find(&user.entries, "run_key");
    let uby = |n: &str| *uruns.iter().find(|e| e.entry_name == n).expect(n);
    assert_eq!(
        uby("E").search_context.rule,
        SearchRule::Observed(ObservedLauncher::RunKey)
    );
    assert_eq!(uby("F").search_context.rule, SearchRule::ShellPathext);
}

/// Task Scheduler searched a bare `Exec` command with the machine's
/// `PATHEXT`: `.vbs` and `.js` ran, `.ps1`, `.pif` and `.lnk` did not.
#[test]
fn a_task_exec_bare_command_uses_the_windows_default_pathext() {
    let xml = TASK_XML.replace("C:\\Tools\\upd.exe", "evil");
    let task = parse_task(&xml).unwrap();
    let entry = task_xml::task_entry(&task, "/t", "t");
    assert_eq!(
        entry.search_context.rule,
        SearchRule::Observed(ObservedLauncher::TaskExec)
    );
    let res = resolve_with(&entry, &["/Windows/System32/evil.vbs"]);
    assert_eq!(candidate_names(&res).len(), 12);
    assert_eq!(candidate_names(&res)[4], "evil.vbs");
    assert_eq!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
    assert_eq!(res.search_rule, Some("observed_task_pathext"));
    assert!(res.basis.contains("SYSTEM hive"), "{}", res.basis);
    let res = resolve_with(&entry, &["/Windows/System32/evil.pif"]);
    assert_ne!(res.status, TargetStatus::ObservedAtPath, "{}", res.basis);
}

// --- HUNT-276: when the service's file was created, and when the system was installed -------------------

fn service_hive(name: &str, image: &str) -> Artifact {
    let key = format!(r"ROOT\ControlSet001\Services\{name}");
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SYSTEM",
            "total_values": 4,
            "total_keys": 1,
            "all_values": [
                dword(&key, "Start", 2),
                dword(&key, "Type", 0x10),
                rv(&key, "ImagePath", image),
                rv(&key, "ObjectName", "LocalSystem"),
            ],
        }),
    )
}

fn software_hive_installed(epoch: u32) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "total_values": 1,
            "total_keys": 1,
            "all_values": [dword(r"ROOT\Microsoft\Windows NT\CurrentVersion", "InstallDate", epoch)],
        }),
    )
}

fn system32_file(name: &str, created: &str) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({
            "name": name,
            "path": format!("/Windows/System32/{name}"),
            "created": created,
        }),
    )
}

fn entry_of(produced: &[Artifact]) -> Value {
    produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .expect("an AsepEntry")
        .metadata
        .clone()
}

/// The file index carries the creation time of a system-directory executable onto the service record that names
/// it, and the SOFTWARE hive's `InstallDate` onto the record as the time the system was installed, in the order
/// the evidence arrived: both are stamped only when seen, and say so when not.
#[test]
fn a_service_record_carries_its_files_creation_time_and_the_systems_install_time() {
    let module = AsepEnumerator::new();
    module
        .process(&system32_file("msdtc.exe", "2026-10-22T16:20:16.9057500Z"))
        .unwrap();
    // 2026-10-22T16:27:45Z
    module
        .process(&software_hive_installed(1_792_686_465))
        .unwrap();
    let produced = module
        .process(&service_hive("MSDTC", r"C:\Windows\System32\msdtc.exe"))
        .unwrap();
    let e = entry_of(&produced);
    assert_eq!(e["target_exists"], "observed_at_path");
    assert_eq!(e["target_created"], "2026-10-22T16:20:16.9057500Z");
    assert_eq!(e["os_install_time"], "2026-10-22T16:27:45Z");
    assert_eq!(
        e["os_install_time_basis"],
        "SOFTWARE hive Microsoft\\Windows NT\\CurrentVersion\\InstallDate"
    );
}

#[test]
fn without_the_software_hive_or_a_created_time_the_record_says_nothing_was_seen() {
    let module = AsepEnumerator::new();
    let mut file = system32_file("odd.exe", "");
    file.metadata.as_object_mut().unwrap().remove("created");
    module.process(&file).unwrap();
    let produced = module
        .process(&service_hive("Odd", r"C:\Windows\System32\odd.exe"))
        .unwrap();
    let e = entry_of(&produced);
    assert!(e.get("target_created").is_none_or(Value::is_null), "{e}");
    assert!(e.get("os_install_time").is_none_or(Value::is_null), "{e}");
    assert_eq!(
        e["os_install_time_basis"],
        "no SOFTWARE hive InstallDate had been read when this entry was made"
    );
}

/// A target in an ordinary directory carries no creation time (only system-directory files are remembered).
#[test]
fn a_file_outside_the_system_directories_is_not_remembered_by_creation_time() {
    let module = AsepEnumerator::new();
    let mut f = system32_file("x.exe", "2026-01-01T00:00:00Z");
    f.metadata["path"] = json!("/ProgramData/x.exe");
    module.process(&f).unwrap();
    let produced = module
        .process(&service_hive("X", r"C:\ProgramData\x.exe"))
        .unwrap();
    assert!(entry_of(&produced)
        .get("target_created")
        .is_none_or(Value::is_null));
}

/// A setup-time backup hive (`SOFTWARE.SAV`) records an InstallDate of 0 and is the same kind of hive to the
/// enumerator; neither it nor a zero is an install time, and the live hive read after it still counts.
#[test]
fn a_zero_or_backup_hive_install_date_is_not_an_install_time() {
    let module = AsepEnumerator::new();
    let mut sav = software_hive_installed(0);
    sav.metadata["hive_type"] = json!("SOFTWARE.SAV");
    module.process(&sav).unwrap();
    module.process(&software_hive_installed(0)).unwrap();
    module
        .process(&system32_file("a.exe", "2026-10-22T16:20:16Z"))
        .unwrap();
    let e = entry_of(
        &module
            .process(&service_hive("A", r"C:\Windows\System32\a.exe"))
            .unwrap(),
    );
    assert!(e.get("os_install_time").is_none_or(Value::is_null), "{e}");
    module
        .process(&software_hive_installed(1_792_686_465))
        .unwrap();
    let e = entry_of(
        &module
            .process(&service_hive("A", r"C:\Windows\System32\a.exe"))
            .unwrap(),
    );
    assert_eq!(e["os_install_time"], "2026-10-22T16:27:45Z");
}

/// An entry names the hive file it was read from when the ingest knew it, so a reader can tell the live hive from a copy.
#[test]
fn an_entry_carries_the_path_of_the_hive_it_was_read_from() {
    let module = AsepEnumerator::new();
    let mut file = system32_file("SYSTEM", "2026-10-22T16:20:16Z");
    file.metadata["path"] = json!("/Windows/repair/system");
    file.metadata["name"] = json!("system");
    module.process(&file).unwrap();
    let mut hive = service_hive("Svc", r"C:\Windows\System32\svc.exe");
    hive.parent_id = Some(file.id);
    let e = entry_of(&module.process(&hive).unwrap());
    assert_eq!(e["hive_path"], "/Windows/repair/system");
}
