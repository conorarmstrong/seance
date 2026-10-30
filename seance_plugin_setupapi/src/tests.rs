//! The setupapi device-install log — stated before it was parsed.
//!
//! # Ground truth
//!
//! Three real logs on this machine, measured line by line on 2026-09-15:
//!
//! ```text
//! reference/plaso/test_data/setupapi.dev.log     847,758 B  10,653 lines  194 sections  12 boot sessions
//! reference/plaso/test_data/setupapi.setup.log    94,909 B   1,357 lines   16 sections   1 boot session
//! (LoneWolf, Windows 10 1709)                  1,454,780 B  19,321 lines  107 sections   3 boot sessions
//! ```
//!
//! All three are CRLF throughout with no lone CR and no lone LF, no BOM, no
//! NUL, no TAB and no non-ASCII byte, and all three end `\r\n\r\n`. All three
//! open with the byte string `[Device Install Log]`, five five-space-indented
//! `Key = Value` lines, **an empty line**, and `[BeginLog]`. None of them
//! contains an `[EndLog]`.
//!
//! The 194 and 16 section counts are independently asserted by plaso's own
//! checked-in test for the same two files, which is a second implementation
//! agreeing.
//!
//! # What the format does that a parser silently loses
//!
//! Every one of these is real, in one of the three files, and each has a test
//! below:
//!
//! * **Boot sessions are not in chronological order.** In `setupapi.dev.log`
//!   the session at line 88 is `2016/10/05 11:12:57.496` and the next, at line
//!   749, is `2016/10/05 01:53:52.487` — 9 h 19 m **earlier**. A parser that
//!   sorts or de-duplicates by time mis-attributes every section after it.
//! * **A section can start before the boot session it sits under.** Three of
//!   LoneWolf's 107 do, by nearly three hours; all three are Windows Update
//!   replaying an install under an earlier clock. Clamping or rejecting them
//!   loses three device installs.
//! * **A section can have no body at all.** Nine across the two plaso files. A
//!   parser requiring one body line drops all nine.
//! * **533 body lines begin with `!` or `!!!` in column 0**, not with
//!   indentation — including the only two records in any of the three files of
//!   a device that failed to start.
//! * **`cmd:` is indented six spaces**, where every other tag is indented
//!   five. It is the line that says which process drove the install.
//! * **The header subject is absent on 176 of 194 sections**, and on the rest
//!   it is an INF path, a bare GUID, a two-segment hardware id or a full
//!   device instance id. Taking it as a device id publishes INF paths as
//!   devices.
//! * **The instance id is sometimes only in the body.** LoneWolf's seven
//!   `Device Install (Install Windows Update driver)` sections name only
//!   `acpi\dellabce` in the header; the full `ACPI\DELLABCE\2&DABA3FF&0`
//!   appears on an `ndv:` line.
//! * **No timezone or offset appears anywhere in any of the three files** —
//!   checked for `UTC`, `GMT`, `timezone`, `Bias`, `daylight`, `DST` and the
//!   literal `+HH:MM` and `+HHMM` shapes. So every time here is local to a
//!   machine whose offset this file does not record.

use super::parse::*;

/// A minimal real-shaped log: the measured preamble, one boot session, one
/// section.
fn log_with(body: &str) -> String {
    format!(
        "[Device Install Log]\r\n     \
         OS Version = 10.0.10240\r\n     \
         Service Pack = 0.0\r\n     \
         Suite = 0x0100\r\n     \
         ProductType = 1\r\n     \
         Architecture = amd64\r\n\r\n\
         [BeginLog]\r\n\r\n\
         [Boot Session: 2015/11/22 17:58:03.498]\r\n\r\n{body}"
    )
}

/// One section, in the measured five-part shape.
fn section(kind: &str, subject: Option<&str>, start: &str, end: &str, status: &str) -> String {
    let head = match subject {
        Some(s) => format!(">>>  [{kind} - {s}]"),
        None => format!(">>>  [{kind}]"),
    };
    format!(
        // forensic-lint: allow RAGGED-STRING — real SetupAPI log content, indentation included.
        "{head}\r\n>>>  Section start {start}\r\n     dvi: {{Build Driver List}} \
         17:59:28.200\r\n<<<  Section end {end}\r\n<<<  [Exit status: {status}]\r\n"
    )
}

// --- Self-selection --------------------------------------------------------

/// The first line decides, not the file name — and it does not tell the `dev`
/// log from the `setup` log, which is why the file name rides on the record.
#[test]
fn a_log_is_recognised_by_its_first_line_and_not_by_its_name() {
    assert!(is_device_install_log(
        // forensic-lint: allow RAGGED-STRING — real SetupAPI log content, indentation included.
        b"[Device Install Log]\r\n     OS Version = 10.0.10240\r\n"
    ));
    // The measured first bytes.
    assert!(is_device_install_log(&[
        0x5b, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c,
        0x20, 0x4c, 0x6f, 0x67, 0x5d, 0x0d, 0x0a,
    ]));
    for not_one in [
        &b"[Something Else]\r\n"[..],
        &b"\xef\xbb\xbf[Device Install Log]\r\n"[..], // a BOM none of the three has
        &b""[..],
        &b"[Device Install"[..],
    ] {
        assert!(
            !is_device_install_log(not_one),
            "must not select: {:?}",
            String::from_utf8_lossy(not_one)
        );
    }
}

// --- The preamble ----------------------------------------------------------

/// The five keys, in order, and the empty line before `[BeginLog]` that the
/// plan's grammar omitted.
#[test]
fn the_header_keys_are_read_in_order_and_the_blank_line_is_not_a_surprise() {
    let parsed = parse(&log_with(""));
    assert_eq!(
        parsed.header.get("OS Version"),
        Some(&"10.0.10240".to_string())
    );
    assert_eq!(
        parsed.header.get("Architecture"),
        Some(&"amd64".to_string())
    );
    assert_eq!(
        parsed.header_order,
        vec![
            "OS Version",
            "Service Pack",
            "Suite",
            "ProductType",
            "Architecture"
        ]
    );
    assert!(parsed.begin_log_seen);
}

/// A header key this build has never seen is kept, not dropped: the format
/// does not fix the list at five.
#[test]
fn an_unfamiliar_header_key_is_kept() {
    // forensic-lint: allow RAGGED-STRING — real SetupAPI log content, indentation included.
    let s = "[Device Install Log]\r\n     OS Version = 10.0.19041\r\n     \
             Something New = 7\r\n\r\n[BeginLog]\r\n";
    let parsed = parse(s);
    assert_eq!(parsed.header.get("Something New"), Some(&"7".to_string()));
}

// --- Boot sessions ---------------------------------------------------------

/// **Boot sessions are kept in file order and never sorted.**
#[test]
fn boot_sessions_keep_file_order_even_when_the_clock_went_backwards() {
    let s = format!(
        "{}\r\n[Boot Session: 2016/10/05 01:53:52.487]\r\n\r\n{}",
        log_with(&section(
            "Device Install (Hardware initiated)",
            Some(r"SWD\IP_TUNNEL_VBUS\ISATAP_0"),
            "2016/10/05 11:12:57.600",
            "2016/10/05 11:16:04.247",
            "SUCCESS"
        ))
        .replace(
            "[Boot Session: 2015/11/22 17:58:03.498]",
            "[Boot Session: 2016/10/05 11:12:57.496]"
        ),
        section(
            "Device Install (Hardware initiated)",
            Some(r"SWD\IP_TUNNEL_VBUS\Teredo_Tunnel_Device"),
            "2016/10/05 01:55:14.190",
            "2016/10/05 01:55:20.000",
            "SUCCESS"
        )
    );
    let parsed = parse(&s);
    assert_eq!(parsed.boot_sessions.len(), 2);
    assert_eq!(
        parsed.boot_sessions[0].local_time, "2016/10/05 11:12:57.496",
        "file order, not time order"
    );
    assert_eq!(
        parsed.boot_sessions[1].local_time,
        "2016/10/05 01:53:52.487"
    );
    // And the fact is stated rather than left for a reader to notice.
    assert!(
        parsed
            .clock_anomalies
            .iter()
            .any(|a| a.contains("earlier") && a.contains("01:53:52.487")),
        "got {:?}",
        parsed.clock_anomalies
    );
}

/// **A section that starts before its own boot session is kept**, and said.
#[test]
fn a_section_starting_before_its_boot_session_is_kept_and_stated() {
    let s = log_with(&section(
        "Device Install (Install Windows Update driver)",
        Some(r"acpi\dellabce"),
        "2015/11/22 02:17:17.032",
        "2015/11/22 02:17:20.000",
        "SUCCESS",
    ));
    let parsed = parse(&s);
    assert_eq!(parsed.sections.len(), 1, "the section is not dropped");
    assert_eq!(
        parsed.sections[0].start_local.as_deref(),
        Some("2015/11/22 02:17:17.032")
    );
    assert!(
        parsed
            .clock_anomalies
            .iter()
            .any(|a| a.contains("before the boot session")),
        "got {:?}",
        parsed.clock_anomalies
    );
}

// --- Sections --------------------------------------------------------------

/// **A section with no body line at all is a section.**
#[test]
fn a_section_with_no_body_is_parsed_and_counted() {
    let s = log_with(
        ">>>  [Sysprep Respecialize - {804b345a-ffd7-854c-a1b5-ca9598907846}]\r\n\
         >>>  Section start 2015/11/22 17:59:00.000\r\n\
         <<<  Section end 2015/11/22 17:59:01.000\r\n\
         <<<  [Exit status: SUCCESS]\r\n",
    );
    let parsed = parse(&s);
    assert_eq!(parsed.sections.len(), 1);
    let sec = &parsed.sections[0];
    assert_eq!(sec.kind, "Sysprep Respecialize");
    assert_eq!(sec.body_lines, 0);
    assert_eq!(sec.exit_status.as_deref(), Some("SUCCESS"));
    assert_eq!(sec.subject_kind, SubjectKind::Guid);
}

/// The four subject shapes, and no device id claimed for the two that are not
/// one.
#[test]
fn the_header_subject_is_shape_classified_before_it_is_read_as_a_device() {
    let cases: &[(&str, SubjectKind, Option<&str>)] = &[
        // A full device instance id: three segments.
        (
            r"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Extreme&Rev_0001#AA010603160707470215&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            SubjectKind::DeviceInstanceId,
            Some(
                r"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Extreme&Rev_0001#AA010603160707470215&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            ),
        ),
        (
            r"HID\DELLABCE\3&14ed0212&0&0000",
            SubjectKind::DeviceInstanceId,
            Some(r"HID\DELLABCE\3&14ed0212&0&0000"),
        ),
        // A two-segment hardware id: a device KIND, not an instance.
        (
            r"PCI\VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00",
            SubjectKind::HardwareId,
            None,
        ),
        (r"acpi\dellabce", SubjectKind::HardwareId, None),
        // An INF path. Publishing this as a device is the failure.
        (
            r"C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_x86_8f17aac186c70ea6\prnms003.inf",
            SubjectKind::InfPath,
            None,
        ),
        (
            r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxGuest.inf",
            SubjectKind::InfPath,
            None,
        ),
        // A bare GUID.
        (
            "{804b345a-ffd7-854c-a1b5-ca9598907846}",
            SubjectKind::Guid,
            None,
        ),
    ];
    for (subject, kind, instance) in cases {
        assert_eq!(classify_subject(subject), *kind, "{subject}");
        assert_eq!(
            device_instance_id(subject).as_deref(),
            *instance,
            "{subject}"
        );
    }
}

/// A `!` or `!!!` line is a body line, and a `!!!` one is surfaced.
#[test]
fn a_bang_marked_line_is_a_body_line_and_a_triple_bang_is_surfaced() {
    let s = log_with(
        ">>>  [Device Install (Hardware initiated) - HID\\DELLABCE\\3&14ed0212&0&0000]\r\n\
         >>>  Section start 2015/11/22 17:59:00.000\r\n\
         !    dvi: A warning this build must not drop.\r\n\
         !!!  dvi:                     Device not started: Device has problem: 0x0a \
         (CM_PROB_FAILED_START), problem status: 0xc0000001.\r\n\
         \x20     cmd: C:\\Windows\\TEMP\\setup.exe install \r\n\
         <<<  Section end 2015/11/22 17:59:01.000\r\n\
         <<<  [Exit status: SUCCESS]\r\n",
    );
    let parsed = parse(&s);
    let sec = &parsed.sections[0];
    assert_eq!(
        sec.body_lines, 3,
        "a bang line and a six-space cmd line are body lines: {:?}",
        sec
    );
    assert_eq!(
        sec.warnings.len(),
        1,
        "the !!! line is surfaced, the single ! is counted: {:?}",
        sec.warnings
    );
    assert!(sec.warnings[0].contains("CM_PROB_FAILED_START"));
    // The command that drove the install, from the six-space `cmd:` line.
    assert_eq!(
        sec.command.as_deref(),
        Some("C:\\Windows\\TEMP\\setup.exe install"),
        "the trailing space the real file carries is trimmed, not kept"
    );
}

/// An exit status is captured as whatever is there, not compared to `SUCCESS`.
#[test]
fn an_exit_status_is_captured_and_not_compared() {
    for status in [
        "SUCCESS",
        "SUCCESS (REBOOT_REQUIRED)",
        // Neither of the three files holds a failure, so this build must not
        // assume the vocabulary is closed.
        "FAILURE(0x80070002)",
    ] {
        let parsed = parse(&log_with(&section(
            "Install Driver Updates",
            None,
            "2015/11/22 17:59:00.000",
            "2015/11/22 17:59:01.000",
            status,
        )));
        assert_eq!(parsed.sections[0].exit_status.as_deref(), Some(status));
    }
}

/// A section with no end line and no exit status is still a section, and says
/// what it is missing.
#[test]
fn a_section_the_log_never_closed_is_reported_as_unclosed() {
    let s = log_with(
        ">>>  [Device Install (Hardware initiated) - HID\\DELLABCE\\3&14ed0212&0&0000]\r\n\
         >>>  Section start 2015/11/22 17:59:00.000\r\n\
              dvi: The log ends mid-section, which is what a machine losing power \
         leaves behind.\r\n",
    );
    let parsed = parse(&s);
    assert_eq!(parsed.sections.len(), 1);
    let sec = &parsed.sections[0];
    assert!(sec.end_local.is_none());
    assert!(sec.exit_status.is_none());
    assert!(!sec.closed);
    assert_eq!(parsed.unclosed_sections, 1);
}

/// Removals are not arrivals.
#[test]
fn a_delete_device_section_is_a_removal_and_not_an_arrival() {
    let install = parse(&log_with(&section(
        "Device Install (Hardware initiated)",
        Some(r"HID\DELLABCE\3&14ed0212&0&0000"),
        "2015/11/22 17:59:00.000",
        "2015/11/22 17:59:01.000",
        "SUCCESS",
    )));
    assert_eq!(
        install.sections[0].device_action,
        Some(DeviceAction::Install)
    );

    let delete = parse(&log_with(&section(
        "Delete Device",
        Some(r"SWD\MMDEVAPI\{0.0.0.00000000}.{23A258D9-5E23-4401-ADB9-2BD1E81A057E}"),
        "2015/11/22 17:59:00.000",
        "2015/11/22 17:59:01.000",
        "SUCCESS",
    )));
    assert_eq!(delete.sections[0].device_action, Some(DeviceAction::Remove));

    // And a driver-store housekeeping section is neither.
    let housekeeping = parse(&log_with(&section(
        "Uninstall Driver Updates",
        None,
        "2015/11/22 17:59:00.000",
        "2015/11/22 17:59:01.000",
        "SUCCESS",
    )));
    assert_eq!(housekeeping.sections[0].device_action, None);
}

/// **The instance id is sometimes only in the body**, on an `ndv:` line.
#[test]
fn an_instance_id_that_is_only_in_the_body_is_still_found() {
    let s = log_with(
        ">>>  [Device Install (Install Windows Update driver) - acpi\\dellabce]\r\n\
         >>>  Section start 2018/03/27 02:17:17.032\r\n\
         \x20    ndv: {Update Device Driver - ACPI\\DELLABCE\\2&DABA3FF&0}\r\n\
         <<<  Section end 2018/03/27 02:17:20.000\r\n\
         <<<  [Exit status: SUCCESS]\r\n",
    );
    let parsed = parse(&s);
    let sec = &parsed.sections[0];
    assert_eq!(
        sec.subject_kind,
        SubjectKind::HardwareId,
        "the header names a device KIND"
    );
    assert_eq!(
        sec.body_device_ids,
        vec![r"ACPI\DELLABCE\2&DABA3FF&0".to_string()],
        "and the instance is on the ndv: line"
    );
    // The record must not present a body id as the header's subject.
    assert!(sec.instance_id_from_subject.is_none());
}

/// The kind histogram accounts for every section, including the majority kinds
/// that are driver-store housekeeping.
#[test]
fn every_section_is_in_the_kind_histogram() {
    let mut body = String::new();
    for _ in 0..3 {
        body.push_str(&section(
            "Uninstall Driver Updates",
            None,
            "2015/11/22 17:59:00.000",
            "2015/11/22 17:59:01.000",
            "SUCCESS",
        ));
    }
    body.push_str(&section(
        "Device Install (Hardware initiated)",
        Some(r"HID\DELLABCE\3&14ed0212&0&0000"),
        "2015/11/22 18:00:00.000",
        "2015/11/22 18:00:01.000",
        "SUCCESS",
    ));
    let parsed = parse(&log_with(&body));
    assert_eq!(parsed.sections.len(), 4);
    let hist = parsed.kind_histogram();
    assert_eq!(hist.get("Uninstall Driver Updates"), Some(&3));
    assert_eq!(hist.get("Device Install (Hardware initiated)"), Some(&1));
    assert_eq!(hist.values().sum::<usize>(), 4, "nothing is left out");
}

/// Lone-LF and lone-CR line endings parse, even though none of the three real
/// files has one — a log recovered from a carve or a text transfer may.
#[test]
fn a_log_with_unix_line_endings_still_parses() {
    let crlf = log_with(&section(
        "Device Install (Hardware initiated)",
        Some(r"HID\DELLABCE\3&14ed0212&0&0000"),
        "2015/11/22 17:59:00.000",
        "2015/11/22 17:59:01.000",
        "SUCCESS",
    ));
    let lf = crlf.replace("\r\n", "\n");
    let a = parse(&crlf);
    let b = parse(&lf);
    assert_eq!(a.sections.len(), b.sections.len());
    assert_eq!(a.sections[0].kind, b.sections[0].kind);
    assert_eq!(a.sections[0].exit_status, b.sections[0].exit_status);
    assert_eq!(
        a.sections[0].start_local, b.sections[0].start_local,
        "a stray CR must not end up inside a timestamp"
    );
}

/// A section count past the ceiling stops and says so, rather than reporting
/// fewer installs than the file holds without a word.
#[test]
fn a_log_past_the_section_ceiling_says_so() {
    let mut body = String::new();
    for _ in 0..(MAX_SECTIONS + 5) {
        body.push_str(&section(
            "Uninstall Driver Updates",
            None,
            "2015/11/22 17:59:00.000",
            "2015/11/22 17:59:01.000",
            "SUCCESS",
        ));
    }
    let parsed = parse(&log_with(&body));
    assert_eq!(parsed.sections.len(), MAX_SECTIONS);
    assert!(
        parsed
            .cap_reached
            .as_deref()
            .is_some_and(|c| c.contains("section")),
        "got {:?}",
        parsed.cap_reached
    );
}

// --- What the times are, and are not ---------------------------------------

/// No time in this file has a recorded offset, and every record says so.
#[test]
fn every_time_is_local_with_no_offset_claimed() {
    let parsed = parse(&log_with(&section(
        "Device Install (Hardware initiated)",
        Some(r"HID\DELLABCE\3&14ed0212&0&0000"),
        "2015/11/22 17:59:00.000",
        "2015/11/22 17:59:01.000",
        "SUCCESS",
    )));
    let j = parsed.sections[0].to_json("setupapi.dev.log", &parsed);
    assert_eq!(j["start_local"], "2015/11/22 17:59:00.000");
    // No UTC field, under any name.
    for utc in ["start_utc", "start", "timestamp", "start_time"] {
        assert!(j.get(utc).is_none(), "{utc} would be a converted time");
    }
    let basis = j["time_basis"].as_str().unwrap_or("").to_lowercase();
    assert!(
        basis.contains("local") && basis.contains("no timezone or offset"),
        "the record says what kind of time this is: {basis}"
    );
    // And no timeline event, because a local time on a UTC timeline is placed
    // wrong by the machine's own offset.
    assert!(j["timeline_eligible"] == serde_json::json!(false));
}

// --- The real logs ---------------------------------------------------------

/// The parser over `reference/plaso/test_data/setupapi.dev.log`, against the
/// counts measured off the file — the section count of which plaso's own
/// checked-in test independently asserts.
///
/// Corpus-gated on `SEANCE_SETUPAPI_CORPUS`, because `reference/` is in
/// `.gitignore`: these logs are on the machine that measured them and absent
/// from a fresh clone. An unset variable skips; a variable set to a path that
/// is not there panics, so a pass never reports a comparison that did not run.
#[test]
fn the_real_dev_log_yields_its_measured_counts() {
    let Some(path) =
        seance_core::test_support::corpus::file("SEANCE_SETUPAPI_CORPUS", "setupapi.dev.log")
    else {
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read the log");
    assert!(is_device_install_log(text.as_bytes()));
    let log = parse(&text);

    assert_eq!(
        log.lines_read, 10_654,
        "10,653 CRLF-terminated lines and the final empty one"
    );
    assert_eq!(
        log.sections.len(),
        194,
        "plaso's own test for this file asserts 194 event data, from a second implementation"
    );
    assert_eq!(log.boot_sessions.len(), 12);
    assert_eq!(log.boot_sessions[0].local_time, "2015/11/22 17:58:03.498");
    assert_eq!(log.boot_sessions[11].local_time, "2016/11/22 23:39:14.499");
    assert!(log.begin_log_seen);
    assert_eq!(
        log.header.get("OS Version"),
        Some(&"10.0.10240".to_string())
    );
    assert_eq!(log.header.get("Architecture"), Some(&"amd64".to_string()));
    assert_eq!(
        log.unclosed_sections, 0,
        "every section in this file closes"
    );
    assert!(log.cap_reached.is_none());

    // The kind histogram accounts for all 194, and the two commonest kinds are
    // driver-store housekeeping rather than device activity.
    let hist = log.kind_histogram();
    assert_eq!(hist.values().sum::<usize>(), 194);
    assert_eq!(hist.get("Uninstall Driver Updates"), Some(&77));
    assert_eq!(hist.get("Unstage Driver Updates"), Some(&77));
    assert_eq!(hist.get("Device Install (Hardware initiated)"), Some(&3));
    assert_eq!(
        hist.get("Device Install (UpdateDriverForPlugAndPlayDevices)"),
        Some(&2)
    );

    // Exit statuses: 191 SUCCESS and 3 SUCCESS (REBOOT_REQUIRED), all three of
    // the latter closing an `Install Driver Updates` section.
    let reboot: Vec<&Section> = log
        .sections
        .iter()
        .filter(|s| s.exit_status.as_deref() == Some("SUCCESS (REBOOT_REQUIRED)"))
        .collect();
    assert_eq!(
        reboot.len(),
        3,
        "the qualified status must not be folded into SUCCESS"
    );
    for s in &reboot {
        assert_eq!(s.kind, "Install Driver Updates");
    }
    assert_eq!(
        log.sections
            .iter()
            .filter(|s| s.exit_status.as_deref() == Some("SUCCESS"))
            .count(),
        191
    );

    // **The backwards clock**, stated rather than sorted away.
    assert_eq!(
        log.boot_sessions[1].local_time, "2016/10/05 11:12:57.496",
        "file order"
    );
    assert_eq!(log.boot_sessions[2].local_time, "2016/10/05 01:53:52.487");
    assert!(
        log.clock_anomalies
            .iter()
            .any(|a| a.contains("2016/10/05 01:53:52.487") && a.contains("earlier")),
        "got {:?}",
        log.clock_anomalies
    );

    // **The nine zero-body sections**, all present.
    assert_eq!(
        log.sections.iter().filter(|s| s.body_lines == 0).count(),
        8,
        "eight in this file; the ninth is in setupapi.setup.log"
    );

    // The first and last sections, measured.
    let first = &log.sections[0];
    assert_eq!(first.kind, "Device Install (Hardware initiated)");
    assert_eq!(
        first.subject.as_deref(),
        Some(r"SWD\IP_TUNNEL_VBUS\ISATAP_0")
    );
    assert_eq!(
        first.start_local.as_deref(),
        Some("2015/11/22 17:59:28.110")
    );
    assert_eq!(first.end_local.as_deref(), Some("2015/11/22 17:59:37.142"));

    let last = &log.sections[193];
    assert_eq!(last.kind, "Device Install (Hardware initiated)");
    assert_eq!(
        last.subject.as_deref(),
        Some(
            r"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07#99E2116A&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        ),
        "the only USB mass-storage section in this file"
    );
    assert_eq!(last.subject_kind, SubjectKind::DeviceInstanceId);
    assert_eq!(last.device_action, Some(DeviceAction::Install));
    assert_eq!(last.start_local.as_deref(), Some("2016/11/22 23:50:30.938"));

    // **The INF-path subject is not a device.** Section 29 (0-based 28) is the
    // row plaso's own test asserts, and its subject is an INF path.
    let inf = &log.sections[28];
    assert_eq!(inf.kind, "Device Install (DiInstallDriver)");
    assert_eq!(inf.subject_kind, SubjectKind::InfPath);
    assert!(
        inf.instance_id_from_subject.is_none(),
        "an INF path must never be published as a device id: {:?}",
        inf.subject
    );
    assert_eq!(inf.start_local.as_deref(), Some("2016/10/12 03:36:30.936"));

    // And no record carries a converted time, under any name.
    for sec in log.device_sections() {
        let j = sec.to_json("setupapi.dev.log", &log);
        for utc in ["start_utc", "start", "timestamp", "start_time"] {
            assert!(
                j.get(utc).is_none(),
                "{utc} on section at line {}",
                sec.line
            );
        }
        assert_eq!(j["timeline_eligible"], serde_json::json!(false));
    }
}

/// And the `setup` log, whose section vocabulary is different despite the
/// identical first line.
#[test]
fn the_real_setup_log_yields_its_measured_counts_and_its_own_vocabulary() {
    let Some(path) =
        seance_core::test_support::corpus::file("SEANCE_SETUPAPI_CORPUS", "setupapi.setup.log")
    else {
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read the log");
    let log = parse(&text);

    assert_eq!(log.sections.len(), 16, "plaso's own test asserts 16");
    assert_eq!(log.boot_sessions.len(), 1);
    assert_eq!(log.boot_sessions[0].local_time, "2015/11/22 17:52:29.492");
    assert_eq!(
        log.sections.iter().filter(|s| s.body_lines == 0).count(),
        1,
        "the ninth zero-body section"
    );

    // The first section: a Sysprep pass with a bare GUID subject and no body.
    let first = &log.sections[0];
    assert_eq!(first.kind, "Sysprep Specialize");
    assert_eq!(first.subject_kind, SubjectKind::Guid);
    assert_eq!(first.device_action, None, "a sysprep pass is not a device");
    assert_eq!(
        first.start_local.as_deref(),
        Some("2015/11/22 17:53:16.599")
    );
    assert_eq!(first.body_lines, 0);

    // The vocabulary this file uses and the dev log does not: the same first
    // line selects both, which is why the file NAME rides on every record.
    let hist = log.kind_histogram();
    assert_eq!(
        hist.get("Setup online Device Install (Hardware initiated)"),
        Some(&11)
    );
    assert_eq!(
        log.device_sections().count(),
        11,
        "and the prefixed kind is still recognised as a device install"
    );

    let last = &log.sections[15];
    assert_eq!(last.kind, "Setup Import Driver Package");
    assert_eq!(last.subject_kind, SubjectKind::InfPath);
    assert_eq!(last.start_local.as_deref(), Some("2015/11/22 17:57:17.502"));
}

/// HUNT-277: a device-install log inside a shadow copy is parsed and what it
/// yields says so; a `ParsedRecord` that is not a prior version is not read.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    use crate::SetupApiParser;
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::module::ForensicsModule;
    use std::sync::Arc;

    let body = section(
        "Device Install (Hardware initiated) - USB\\VID_0781&PID_5567\\1",
        None,
        "2015/11/22 18:00:00.000",
        "2015/11/22 18:00:01.000",
        "0x00000000",
    )
    .repeat(8);
    let source: Arc<dyn seance_core::data_source::DataSource> =
        Arc::new(ByteSliceDataSource::new(log_with(&body).into_bytes()));
    let prior = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source.clone()),
        serde_json::json!({
            "type": "VssPriorVersion",
            "name": "setupapi.dev.log [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "setupapi.dev.log",
            "is_snapshot_version": true,
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
        }),
    );
    let out = SetupApiParser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version is parsed");
    assert!(out
        .iter()
        .all(|a| a.metadata["vss_snapshot_id"] == serde_json::json!("snap-1")));

    let other = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({ "type": "SomethingElse", "name": "setupapi.dev.log" }),
    );
    assert!(SetupApiParser.process(&other).unwrap().is_empty());
}
