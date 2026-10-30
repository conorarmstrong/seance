//! The TaskCache blobs: an `Actions` blob decoded action by action, a
//! `DynamicInfo` blob decoded by its length, and the ways each refuses.

use super::scheduled_tasks::*;

fn bstr(text: &str) -> Vec<u8> {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = (units.len() as u32).to_le_bytes().to_vec();
    out.extend(units);
    out
}

fn exec_action(id: &str, command: &str, arguments: &str, working_dir: &str, flags: u16) -> Vec<u8> {
    let mut out = 0x6666u16.to_le_bytes().to_vec();
    out.extend(bstr(id));
    out.extend(bstr(command));
    out.extend(bstr(arguments));
    out.extend(bstr(working_dir));
    out.extend(flags.to_le_bytes());
    out
}

fn actions_blob(author: &str, actions: &[Vec<u8>]) -> Vec<u8> {
    let mut out = 3u16.to_le_bytes().to_vec();
    out.extend(bstr(author));
    for action in actions {
        out.extend_from_slice(action);
    }
    out
}

/// **An exec action is decoded whole**: the command, its arguments and the
/// working directory, with the author from the blob's header.
#[test]
fn an_exec_action_is_decoded_with_its_command_and_arguments() {
    let blob = actions_blob(
        "Author",
        &[exec_action(
            "",
            "%windir%\\system32\\defrag.exe",
            "-c -h -k -g -$",
            "",
            0,
        )],
    );
    let out = decode_actions(&blob).expect("decodes");
    assert_eq!(out.version, 3);
    assert_eq!(out.author, "Author");
    assert_eq!(out.actions.len(), 1);
    match &out.actions[0] {
        TaskAction::Exec {
            command,
            arguments,
            working_directory,
            ..
        } => {
            assert_eq!(command, "%windir%\\system32\\defrag.exe");
            assert_eq!(arguments, "-c -h -k -g -$");
            assert_eq!(working_directory, "");
        }
        other => panic!("expected an exec action, got {other:?}"),
    }
    assert!(out.trailing_bytes == 0);
}

/// **A COM handler action carries its class id**, rendered as a GUID in the
/// registry's own form, and its data string.
#[test]
fn a_com_handler_action_carries_its_class_id() {
    let mut action = 0x7777u16.to_le_bytes().to_vec();
    action.extend(bstr("handler"));
    // {01234567-89AB-CDEF-0123-456789ABCDEF} in its on-disk byte order.
    action.extend_from_slice(&[
        0x67, 0x45, 0x23, 0x01, 0xAB, 0x89, 0xEF, 0xCD, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF,
    ]);
    action.extend(bstr("data"));
    let blob = actions_blob("", &[action]);
    let out = decode_actions(&blob).expect("decodes");
    match &out.actions[0] {
        TaskAction::ComHandler { id, class_id, data } => {
            assert_eq!(id, "handler");
            assert_eq!(class_id, "{01234567-89AB-CDEF-0123-456789ABCDEF}");
            assert_eq!(data, "data");
        }
        other => panic!("expected a COM handler, got {other:?}"),
    }
}

/// **A blob that is not version 3 is refused by name** rather than decoded
/// under a layout it may not have.
#[test]
fn a_blob_of_another_version_is_refused() {
    let mut blob = actions_blob("x", &[]);
    blob[0] = 2;
    let err = decode_actions(&blob).expect_err("refused");
    assert!(err.contains("version 2"), "{err}");
}

/// **An unknown action magic stops the decode and is reported**, with the
/// actions before it kept and the bytes after it counted.
#[test]
fn an_unknown_action_kind_stops_the_decode_and_is_reported() {
    let mut blob = actions_blob("", &[exec_action("", "a.exe", "", "", 0)]);
    blob.extend_from_slice(&[0x12, 0x34, 0, 0, 0, 0]);
    let out = decode_actions(&blob).expect("the first action still decodes");
    assert_eq!(out.actions.len(), 1);
    assert_eq!(out.unknown_kind, Some(0x3412));
    assert_eq!(out.trailing_bytes, 6);
}

/// **A string that runs past the blob is refused**, not truncated into a
/// plausible command.
#[test]
fn a_string_that_runs_past_the_blob_is_refused() {
    let mut blob = actions_blob("", &[]);
    blob.extend_from_slice(&0x6666u16.to_le_bytes());
    blob.extend_from_slice(&1000u32.to_le_bytes());
    blob.extend_from_slice(b"ab");
    let out = decode_actions(&blob).expect("the header decodes");
    assert!(out.actions.is_empty());
    assert!(out
        .malformed
        .as_deref()
        .unwrap_or_default()
        .contains("past the end"));
}

/// **`DynamicInfo` is decoded by its length**: the 28-byte form carries the
/// creation and last-run times and the last result, the 36-byte form adds
/// the last successful run. A zero time is absent, never 1601.
#[test]
fn dynamic_info_is_decoded_by_length_and_zero_times_are_absent() {
    // 2026-08-06T12:00:00Z as a FILETIME.
    let creation: u64 = 134_304_912_000_000_000;
    let mut short = 3u32.to_le_bytes().to_vec();
    short.extend(creation.to_le_bytes());
    short.extend(0u64.to_le_bytes());
    short.extend(0u32.to_le_bytes());
    short.extend(0x8004_1303u32.to_le_bytes());
    let out = decode_dynamic_info(&short).expect("decodes");
    assert_eq!(out.magic, 3);
    assert_eq!(out.creation.as_ref().map(|t| t.filetime), Some(creation));
    assert!(out
        .creation
        .as_ref()
        .unwrap()
        .rfc3339
        .starts_with("2026-08-06T12:00:00"));
    assert!(out.last_run.is_none(), "a zero FILETIME is no time at all");
    assert_eq!(out.last_result, Some(0x8004_1303));
    assert!(out.last_successful_run.is_none());
    assert_eq!(out.length, 28);

    let mut long = short.clone();
    long.extend((creation + 10_000_000).to_le_bytes());
    let out = decode_dynamic_info(&long).expect("decodes");
    assert_eq!(out.length, 36);
    assert_eq!(
        out.last_successful_run.as_ref().map(|t| t.filetime),
        Some(creation + 10_000_000)
    );

    assert!(
        decode_dynamic_info(&short[..20]).is_err(),
        "too short to hold the fields"
    );
}
