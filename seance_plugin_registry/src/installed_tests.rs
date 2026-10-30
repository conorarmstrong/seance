//! Tests for the installed-program records derived from a hive's `Uninstall`
//! keys. Each one is fed the already-rendered key/value list the hive walk
//! produces, so it needs no hive bytes — the walk is tested on its own.

use super::{
    build_installed_program_records, emit_installed_programs, key_write_times, HiveContext,
};
use seance_core::artifact::{Artifact, ArtifactType};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

const ROOT: &str = "CMI-CreateHive{TEST}";

fn val(key_path: &str, name: &str, value_type: &str, data: &str) -> Value {
    json!({
        "key_path": key_path,
        "value_name": name,
        "value_type": value_type,
        "value_data": data,
        "raw_data_size": data.len(),
    })
}

fn sz(key_path: &str, name: &str, data: &str) -> Value {
    val(key_path, name, "RegSZ", data)
}

/// A REG_DWORD exactly as the hive walk renders it: `0x%08x (n)`.
fn dword(key_path: &str, name: &str, n: u32) -> Value {
    val(key_path, name, "RegDWord", &format!("0x{n:08x} ({n})"))
}

fn key(key_path: &str) -> Value {
    json!({
        "key_path": key_path,
        "key_name": key_path.rsplit('\\').next().unwrap_or(key_path),
        "depth": key_path.matches('\\').count(),
    })
}

fn machine_key(name: &str) -> String {
    format!("{ROOT}\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}")
}

fn wow64_key(name: &str) -> String {
    format!("{ROOT}\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}")
}

fn user_key(name: &str) -> String {
    format!("{ROOT}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}")
}

fn clean_replay() -> Value {
    json!({
        "recovered": false,
        "hive_dirty": false,
        "reason": "clean",
        "incomplete_reason": null,
    })
}

fn ctx<'a>(hive_type: &'a str, replay: &'a Value) -> HiveContext<'a> {
    HiveContext {
        case_id: Uuid::new_v4(),
        parent_id: Uuid::new_v4(),
        hive_type,
        source_path: Some("C:\\Windows\\System32\\config\\SOFTWARE"),
        hive_role: "live",
        replay,
        incomplete: None,
        key_scan_incomplete: None,
    }
}

fn programs(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "InstalledProgram")
        .collect()
}

fn events(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect()
}

fn program_named<'a>(out: &'a [Artifact], key_name: &str) -> &'a Artifact {
    programs(out)
        .into_iter()
        .find(|a| a.metadata["key_name"] == key_name)
        .unwrap_or_else(|| panic!("no InstalledProgram record for key {key_name}"))
}

/// A 64-bit SOFTWARE hive lists 32-bit programs under `Wow6432Node` and 64-bit
/// ones under the native path. An examiner asked "was Chrome installed?" needs
/// both lists, and needs to know which list each entry came from, because a
/// program appearing in both is two installs, not one.
#[test]
fn a_native_and_a_wow6432node_entry_are_both_emitted_and_each_says_which_it_is() {
    let chrome = machine_key("Google Chrome");
    let eraser = wow64_key("{ABCD-1234}");
    let values = vec![
        sz(&chrome, "DisplayName", "Google Chrome"),
        sz(&chrome, "DisplayVersion", "41.0.2272.118"),
        sz(&chrome, "Publisher", "Google Inc."),
        sz(&chrome, "InstallLocation", "C:\\Program Files\\Google\\Chrome\\Application"),
        sz(&chrome, "UninstallString", "\"C:\\Program Files\\Google\\Chrome\\Application\\41.0.2272.118\\Installer\\setup.exe\" --uninstall"),
        sz(&eraser, "DisplayName", "Eraser 6.2.0.2962"),
        sz(&eraser, "DisplayVersion", "6.2.2962"),
        sz(&eraser, "Publisher", "The Eraser Project"),
        sz(&eraser, "InstallSource", "C:\\Users\\informant\\Downloads\\"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    assert_eq!(
        programs(&out).len(),
        2,
        "two Uninstall subkeys, two records"
    );

    let c = program_named(&out, "Google Chrome");
    assert_eq!(c.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(c.metadata["display_name"], "Google Chrome");
    assert_eq!(c.metadata["display_version"], "41.0.2272.118");
    assert_eq!(c.metadata["publisher"], "Google Inc.");
    assert_eq!(
        c.metadata["install_location"],
        "C:\\Program Files\\Google\\Chrome\\Application"
    );
    assert!(c.metadata["uninstall_string"]
        .as_str()
        .is_some_and(|s| s.contains("setup.exe")));
    assert_eq!(c.metadata["wow64"], false);
    assert_eq!(c.metadata["scope"], "machine");
    assert_eq!(c.metadata["hive_type"], "SOFTWARE");
    assert_eq!(
        c.metadata["source_path"],
        "C:\\Windows\\System32\\config\\SOFTWARE"
    );
    assert_eq!(c.metadata["key_path"], chrome);
    assert_eq!(c.metadata["name"], "Installed program: Google Chrome");
    assert_eq!(c.metadata["replay"], replay);

    let e = program_named(&out, "{ABCD-1234}");
    assert_eq!(e.metadata["display_name"], "Eraser 6.2.0.2962");
    assert_eq!(e.metadata["wow64"], true);
    assert_eq!(e.metadata["scope"], "machine");
    assert_eq!(
        e.metadata["install_source"],
        "C:\\Users\\informant\\Downloads\\"
    );
    assert_eq!(e.metadata["key_path"], eraser);
}

/// Many Uninstall entries are a bare product GUID with an UninstallString and
/// nothing else — MSI components, redistributables, patches. Dropping them
/// because they have no DisplayName would make "the hive holds 40 entries"
/// and "Séance lists 31 programs" both true at once, and an examiner counting
/// installs would be wrong by the difference.
#[test]
fn a_guid_only_entry_is_kept_with_a_null_display_name_and_the_key_name_as_its_name() {
    let guid = machine_key("{90150000-0011-0000-0000-0000000FF1CE}");
    let values = vec![sz(
        &guid,
        "UninstallString",
        "MsiExec.exe /X{90150000-0011-0000-0000-0000000FF1CE}",
    )];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let p = program_named(&out, "{90150000-0011-0000-0000-0000000FF1CE}");
    assert_eq!(p.metadata["display_name"], Value::Null);
    assert_eq!(p.metadata["display_version"], Value::Null);
    assert_eq!(p.metadata["publisher"], Value::Null);
    assert_eq!(
        p.metadata["name"],
        "Installed program: {90150000-0011-0000-0000-0000000FF1CE}"
    );
    assert!(p.metadata["uninstall_string"]
        .as_str()
        .is_some_and(|s| s.starts_with("MsiExec.exe")));
}

/// An Uninstall subkey that carries no values at all is still an entry the
/// hive holds. It reaches the builder through the key list, not the value
/// list, and the count must include it.
#[test]
fn an_uninstall_subkey_with_no_values_is_still_a_record() {
    let empty = machine_key("{EMPTY-0000}");
    let keys = vec![key(&machine_key("")), key(&empty)];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&keys, &[], &HashMap::new(), &ctx("SOFTWARE", &replay));

    assert_eq!(programs(&out).len(), 1);
    let p = program_named(&out, "{EMPTY-0000}");
    assert_eq!(p.metadata["display_name"], Value::Null);
}

/// `InstallDate` is a REG_SZ of the form `YYYYMMDD`. The record states it as a
/// dated value and says where the date came from, so an examiner can cite
/// "installed 2015-03-22 (InstallDate value)" rather than a bare date whose
/// origin is unstated.
#[test]
fn an_install_date_in_yyyymmdd_form_is_decoded_and_its_source_stated() {
    let office = machine_key("Office15.PROPLUS");
    let values = vec![
        sz(
            &office,
            "DisplayName",
            "Microsoft Office Professional Plus 2013",
        ),
        sz(&office, "InstallDate", "20150322"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let p = program_named(&out, "Office15.PROPLUS");
    assert_eq!(p.metadata["install_date"], "2015-03-22");
    assert_eq!(p.metadata["install_date_source"], "InstallDate value");
    assert_eq!(p.metadata["install_date_raw"], "20150322");
}

/// An installer that wrote something other than `YYYYMMDD` into `InstallDate`
/// gets no invented date. The raw text is kept on the record and the source
/// says the value was there but did not decode, so "no InstallDate" and
/// "an InstallDate this build could not read" never render alike.
#[test]
fn a_malformed_install_date_yields_null_with_the_raw_text_kept_and_the_failure_stated() {
    let odd = machine_key("OddInstaller");
    let values = vec![
        sz(&odd, "DisplayName", "Odd Installer"),
        sz(&odd, "InstallDate", "3/22/2015"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let p = program_named(&out, "OddInstaller");
    assert_eq!(p.metadata["install_date"], Value::Null);
    assert_eq!(
        p.metadata["install_date_source"],
        "InstallDate value (not YYYYMMDD)"
    );
    assert_eq!(p.metadata["install_date_raw"], "3/22/2015");
    assert!(
        events(&out).is_empty(),
        "no date decoded means no dated event"
    );
}

/// An entry with no `InstallDate` value at all says so: null, source `absent`,
/// and no raw text — because there was none.
#[test]
fn an_absent_install_date_is_null_with_source_absent() {
    let k = machine_key("NoDate");
    let values = vec![sz(&k, "DisplayName", "No Date")];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let p = program_named(&out, "NoDate");
    assert_eq!(p.metadata["install_date"], Value::Null);
    assert_eq!(p.metadata["install_date_source"], "absent");
    assert_eq!(p.metadata["install_date_raw"], Value::Null);
}

/// A calendar-impossible `YYYYMMDD` (month 13, day 0) is eight digits and still
/// not a date. Decoding it by shape alone would put "2015-13-00" in a report.
#[test]
fn an_eight_digit_install_date_that_is_not_a_calendar_date_is_not_decoded() {
    let k = machine_key("BadCal");
    let values = vec![sz(&k, "InstallDate", "20151300")];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let p = program_named(&out, "BadCal");
    assert_eq!(p.metadata["install_date"], Value::Null);
    assert_eq!(
        p.metadata["install_date_source"],
        "InstallDate value (not YYYYMMDD)"
    );
}

/// The hive walk renders a REG_DWORD as `0x%08x (n)`; `EstimatedSize` is that
/// number in kilobytes. The record carries the integer, not the rendering, so
/// a size column sorts numerically. A REG_SZ size some installers write is not
/// that shape and is not guessed at.
#[test]
fn estimated_size_is_read_from_the_rendered_dword_shape_and_not_guessed_otherwise() {
    let a = machine_key("Sized");
    let b = machine_key("StringSized");
    let values = vec![
        dword(&a, "EstimatedSize", 1_048_576),
        sz(&b, "EstimatedSize", "1048576"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    assert_eq!(
        program_named(&out, "Sized").metadata["estimated_size_kb"],
        1_048_576
    );
    assert_eq!(
        program_named(&out, "StringSized").metadata["estimated_size_kb"],
        Value::Null
    );
}

/// `SystemComponent = 1` is how Windows hides an entry from Programs and
/// Features. An examiner comparing the hive against what the user would have
/// seen on screen needs the flag; absent or zero is `false`.
#[test]
fn system_component_is_true_only_when_the_dword_is_one() {
    let hidden = machine_key("Hidden");
    let shown = machine_key("Shown");
    let unset = machine_key("Unset");
    let values = vec![
        dword(&hidden, "SystemComponent", 1),
        dword(&shown, "SystemComponent", 0),
        sz(&unset, "DisplayName", "Unset"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    assert_eq!(
        program_named(&out, "Hidden").metadata["system_component"],
        true
    );
    assert_eq!(
        program_named(&out, "Shown").metadata["system_component"],
        false
    );
    assert_eq!(
        program_named(&out, "Unset").metadata["system_component"],
        false
    );
}

/// A per-user install (Chrome's user-level installer, OneDrive, Teams) lives in
/// NTUSER.DAT under `Software\...\Uninstall`. It is scoped `user` so an
/// examiner does not read it as a machine-wide install, and does not miss it
/// because it is not in SOFTWARE.
#[test]
fn a_user_hive_entry_is_scoped_user() {
    let k = user_key("Google Chrome");
    let values = vec![
        sz(&k, "DisplayName", "Google Chrome"),
        sz(
            &k,
            "InstallLocation",
            "C:\\Users\\informant\\AppData\\Local\\Google\\Chrome\\Application",
        ),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("NTUSER.DAT", &replay));

    let p = program_named(&out, "Google Chrome");
    assert_eq!(p.metadata["scope"], "user");
    assert_eq!(p.metadata["wow64"], false);
    assert_eq!(p.metadata["hive_type"], "NTUSER.DAT");
}

/// The install date is the only dated fact an Uninstall entry carries, so it
/// is the only one that goes on the timeline. An entry without one gets no
/// event: an invented midnight would be a moment the evidence does not hold.
#[test]
fn a_timeline_event_is_emitted_only_where_an_install_date_exists() {
    let dated = machine_key("Dated");
    let undated = machine_key("Undated");
    let values = vec![
        sz(&dated, "DisplayName", "Dated Program"),
        sz(&dated, "DisplayVersion", "1.2"),
        sz(&dated, "InstallDate", "20150407"),
        sz(&undated, "DisplayName", "Undated Program"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));

    let evs = events(&out);
    assert_eq!(evs.len(), 1, "one dated entry, one event");
    let ev = evs[0];
    assert_eq!(ev.metadata["timestamp"], "2015-04-07T00:00:00Z");
    assert_eq!(
        ev.metadata["timestamp_desc"],
        "Program installed (InstallDate)"
    );
    assert_eq!(
        ev.metadata["source_module"],
        "plugin.windows.registry_parser"
    );
    // InstallDate is a calendar day with no time and no zone; the event must
    // say so or the midnight reads as a clock reading.
    assert_eq!(ev.metadata["timestamp_precision"], "day");
    assert!(ev.metadata["short_desc"]
        .as_str()
        .is_some_and(|s| s.contains("Dated Program") && s.contains("1.2")));
    let details: Value =
        serde_json::from_str(ev.metadata["full_details"].as_str().unwrap()).unwrap();
    assert_eq!(details["key_path"], dated);
    assert_eq!(details["install_date_raw"], "20150407");
    // The event hangs off the program record, so the timeline row cites the
    // record and not just the hive file.
    let rec = program_named(&out, "Dated");
    assert_eq!(ev.parent_id, Some(rec.id));
}

/// A hive with no Uninstall key produces nothing — no record and no empty
/// summary. The absence of records is the statement, and the hive record's own
/// key count already proves the hive was walked.
#[test]
fn a_hive_with_no_uninstall_key_emits_nothing() {
    let elsewhere = format!("{ROOT}\\Microsoft\\Windows\\CurrentVersion\\Run");
    let keys = vec![key(&format!("{ROOT}\\Microsoft")), key(&elsewhere)];
    let values = vec![sz(
        &elsewhere,
        "OneDrive",
        "C:\\x\\OneDrive.exe /background",
    )];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&keys, &values, &HashMap::new(), &ctx("SOFTWARE", &replay));
    assert!(out.is_empty(), "got {} artifacts: {:?}", out.len(), out);
}

/// The `Uninstall` key itself and anything nested below an entry are not
/// programs. `...\Uninstall\Foo\SubKey` is Foo's private state, and counting
/// it would inflate the list.
#[test]
fn the_uninstall_key_itself_and_nested_subkeys_are_not_programs() {
    let foo = machine_key("Foo");
    let nested = format!("{foo}\\Private");
    let keys = vec![key(&machine_key("")), key(&foo), key(&nested)];
    let values = vec![
        sz(&machine_key(""), "SomeValueOnTheUninstallKey", "x"),
        sz(&nested, "State", "1"),
    ];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&keys, &values, &HashMap::new(), &ctx("SOFTWARE", &replay));
    let ps = programs(&out);
    assert_eq!(ps.len(), 1);
    assert_eq!(ps[0].metadata["key_name"], "Foo");
}

/// The NK scan supplies a last-write time per key path. Where it has one for
/// the entry's key it goes on the record with its source named; where it has
/// none — the scan was capped, or the path did not resolve — the record says
/// `absent` rather than carrying nothing, so a missing time is visibly missing.
#[test]
fn key_last_written_comes_from_the_nk_scan_when_present_and_is_stated_absent_otherwise() {
    let timed = machine_key("Timed");
    let untimed = machine_key("Untimed");
    let values = vec![
        sz(&timed, "DisplayName", "Timed"),
        sz(&untimed, "DisplayName", "Untimed"),
    ];
    // The scan rebuilds paths from NK parent chains, whose root name is not
    // guaranteed to spell the walk's root the same way; the lookup must not
    // depend on the root segment.
    let scan_events = vec![Artifact::new(
        Uuid::new_v4(),
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": "2015-03-22T14:05:09Z",
            "timestamp_desc": "Registry Key Last Written",
            "source_module": "plugin.windows.registry_parser",
            "key_path": "ROOT\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Timed",
        }),
    )];
    let times = key_write_times(&scan_events);
    let replay = clean_replay();
    let out = build_installed_program_records(&[], &values, &times, &ctx("SOFTWARE", &replay));

    let t = program_named(&out, "Timed");
    assert_eq!(t.metadata["key_last_written"], "2015-03-22T14:05:09Z");
    assert_eq!(
        t.metadata["key_last_written_source"],
        "NK last-write time (raw cell scan)"
    );
    let u = program_named(&out, "Untimed");
    assert_eq!(u.metadata["key_last_written"], Value::Null);
    assert_eq!(u.metadata["key_last_written_source"], "absent");
}

/// A program read out of a hive whose record is already `content_incomplete`
/// (short file, capped walk, unrecovered dirty hive) carries the same stamp,
/// because the list is a subset of what the hive held and each entry outlives
/// the hive record in exports.
#[test]
fn a_program_from_an_incomplete_hive_carries_the_hive_records_incomplete_stamp() {
    let k = machine_key("Partial");
    let values = vec![sz(&k, "DisplayName", "Partial")];
    let replay = json!({
        "recovered": false,
        "hive_dirty": true,
        "reason": "dirty_no_logs",
        "incomplete_reason": "unresolved_structure",
    });
    let mut c = ctx("SOFTWARE", &replay);
    c.incomplete = Some(super::Incomplete {
        reason: "short_read".to_string(),
        detail: Some(
            "the hive's base block declares 8192 bytes and the file holds 4096".to_string(),
        ),
    });
    let out = build_installed_program_records(&[], &values, &HashMap::new(), &c);

    let p = program_named(&out, "Partial");
    assert_eq!(p.metadata["content_incomplete"], true);
    assert_eq!(p.metadata["content_incomplete_reason"], "short_read");
    assert!(p.metadata["content_incomplete_detail"]
        .as_str()
        .is_some_and(|d| d.contains("4096")));
    assert_eq!(p.metadata["replay"]["hive_dirty"], true);
}

/// A program from a hive whose record carries no incomplete stamp carries
/// none either — the stamp is passed on, never invented.
#[test]
fn a_program_from_a_complete_hive_carries_no_incomplete_stamp() {
    let k = machine_key("Whole");
    let values = vec![sz(&k, "DisplayName", "Whole")];
    let replay = clean_replay();
    let out =
        build_installed_program_records(&[], &values, &HashMap::new(), &ctx("SOFTWARE", &replay));
    let p = program_named(&out, "Whole");
    assert!(p.metadata.get("content_incomplete").is_none());
}

/// The glue the hive parser calls: it reads the hive record for the hive's
/// type, path and incomplete stamp, takes the key-write events already on the
/// output list for last-write times, and appends the program records after
/// them. This is the one call site in `lib.rs`, so its contract is pinned here.
#[test]
fn emit_installed_programs_reads_the_hive_record_and_the_key_write_events_already_emitted() {
    let case_id = Uuid::new_v4();
    let file_id = Uuid::new_v4();
    let k = machine_key("Glued");
    let keys = vec![key(&k)];
    let values = vec![
        sz(&k, "DisplayName", "Glued"),
        sz(&k, "InstallDate", "20150322"),
    ];
    let hive = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "source_path": "C:\\Windows\\System32\\config\\SOFTWARE",
            "content_incomplete": true,
            "content_incomplete_reason": "cap_reached",
            "content_incomplete_detail": "the key walk stopped at depth 100",
        }),
    )
    .with_parent(file_id);
    let replay = clean_replay();
    let mut out = vec![Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": "2015-03-22T14:05:09Z",
            "timestamp_desc": "Registry Key Last Written",
            "source_module": "plugin.windows.registry_parser",
            "key_path": k,
        }),
    )
    .with_parent(file_id)];

    emit_installed_programs(&mut out, &keys, &values, &hive, &replay);

    let p = program_named(&out, "Glued");
    assert_eq!(p.case_id, case_id);
    assert_eq!(p.parent_id, Some(file_id));
    assert_eq!(p.metadata["hive_type"], "SOFTWARE");
    assert_eq!(
        p.metadata["source_path"],
        "C:\\Windows\\System32\\config\\SOFTWARE"
    );
    assert_eq!(p.metadata["key_last_written"], "2015-03-22T14:05:09Z");
    assert_eq!(p.metadata["content_incomplete"], true);
    assert_eq!(p.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(p.metadata["install_date"], "2015-03-22");
    // The key-write event that was already there is untouched, and the
    // program's own event was added.
    assert_eq!(events(&out).len(), 2);
}

/// When the raw NK scan stopped short of the whole hive — a cap, or a broken
/// bin chain — a key it never reached has no last-write time to give, and
/// the reason is the scan, not the key. The record names the scan's own
/// reason so "this key's time is not on the record because the scan was
/// capped" and "this key carries no usable time" do not both read `absent`.
#[test]
fn a_missing_last_write_time_names_the_key_scans_cap_when_the_scan_was_incomplete() {
    let case_id = Uuid::new_v4();
    let file_id = Uuid::new_v4();
    let k = machine_key("Unreached");
    let values = vec![sz(&k, "DisplayName", "Unreached")];
    let hive = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "key_timeline_complete": false,
            "key_timeline_cap_reason": "timeline_event_cap",
        }),
    )
    .with_parent(file_id);
    let replay = clean_replay();
    let mut out = Vec::new();

    emit_installed_programs(&mut out, &[], &values, &hive, &replay);

    let p = program_named(&out, "Unreached");
    assert_eq!(p.metadata["key_last_written"], Value::Null);
    assert_eq!(
        p.metadata["key_last_written_source"],
        "absent (key-write scan incomplete: timeline_event_cap)"
    );
}
