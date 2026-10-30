//! Sleuth Kit "body file" (mactime) exporter.
//!
//! Autopsy ships a Body File report module; the body file is the canonical
//! TSK intermediate that `mactime` consumes to build a MAC-times timeline. The
//! pipe-delimited format is:
//!
//! ```text
//! MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
//! ```
//!
//! Times are Unix epoch seconds (0 when unknown). We leave `mode_as_string`,
//! `UID`, and `GID` empty when not captured, matching TSK's tolerance for
//! sparse rows.
//!
//! # Preamble and verdict
//!
//! `mactime` skips every line that begins with `#` (its body-file reader does
//! `next if /^#/` before splitting a line). That is the slot this export uses
//! to say what it is, which case it came from, how many files it expected to
//! write and — on the last line — whether it wrote them all. A row can never
//! begin with `#`: its first field is an MD5 (hex) or empty, so the verdict
//! line is unforgeable by content and a file without one is a fragment.

use serde_json::Value;

/// The marker every streamed export's verdict begins with, as the CSV and
/// JSON exports write it. Kept identical so one reader test covers all three.
pub const BODY_FILE_VERDICT_MARKER: &str = "### END OF EXPORT ### VERDICT:";

/// The eleven columns, in order, as TSK 3.x defines them.
pub const BODY_FILE_COLUMNS: &str =
    "MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime";

/// One file's metadata + MAC timestamps for the body file.
#[derive(Debug, Clone, Default)]
pub struct BodyFileEntry {
    pub md5: Option<String>,
    pub path: String,
    pub inode: Option<i64>,
    pub mode: Option<String>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub size: i64,
    /// Access, modify, change, birth times as Unix epoch seconds.
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub crtime: Option<i64>,
}

/// Sanitise a field so it cannot break the pipe-delimited row structure:
/// newlines and pipes are replaced with spaces.
fn clean(s: &str) -> String {
    s.replace(['|', '\n', '\r'], " ")
}

fn num(o: Option<i64>) -> String {
    o.map(|v| v.to_string()).unwrap_or_else(|| "0".to_string())
}

fn opt_str(o: &Option<String>) -> String {
    o.as_deref().map(clean).unwrap_or_default()
}

/// Render one body-file row (no trailing newline).
pub fn render_row(e: &BodyFileEntry) -> String {
    format!(
        "{md5}|{name}|{inode}|{mode}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}",
        md5 = opt_str(&e.md5),
        name = clean(&e.path),
        inode = num(e.inode),
        mode = opt_str(&e.mode),
        uid = num(e.uid),
        gid = num(e.gid),
        size = e.size,
        atime = num(e.atime),
        mtime = num(e.mtime),
        ctime = num(e.ctime),
        crtime = num(e.crtime),
    )
}

/// Render a complete body file (one row per entry, newline-terminated).
pub fn render_body_file(entries: &[BodyFileEntry]) -> String {
    let mut out = String::with_capacity(entries.len() * 96);
    for e in entries {
        out.push_str(&render_row(e));
        out.push('\n');
    }
    out
}

/// A `# name: value` line. `mactime` skips it; a person reads it.
fn comment_line(name: &str, value: &str) -> String {
    format!("# {name}: {}\n", value.replace(['\n', '\r'], " "))
}

/// Everything written before the first row of a case's body file.
///
/// `file_entries` is the population counted before the walk began; the verdict
/// line states how many rows were actually written, and the reader compares
/// the two. `timezone` is the same statement every timeline export carries.
pub fn render_body_file_preamble(
    case_id: &str,
    file_entries: i64,
    exported_at: &str,
    timezone: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&comment_line(
        "export",
        "mactime body file (Sleuth Kit 3.x format)",
    ));
    out.push_str(&comment_line("case_id", case_id));
    out.push_str(&comment_line("columns", BODY_FILE_COLUMNS));
    out.push_str(&comment_line(
        "population",
        "every FileEntry artifact in the case, in artifact-id order; one row per file, \
         whether or not it carries a timestamp. No timeline filter applies to this export.",
    ));
    out.push_str(&comment_line("file_entries", &file_entries.to_string()));
    out.push_str(&comment_line("timezone", timezone));
    out.push_str(&comment_line(
        "times",
        "atime=accessed, mtime=modified, ctime=changed (NTFS: $STANDARD_INFORMATION MFT \
         modified), crtime=created; 0 where the filesystem did not record the time. A row \
         whose four times are all 0 is skipped by mactime, and is here so the file names \
         every file the case holds.",
    ));
    out.push_str(&comment_line(
        "how_to_read",
        &format!(
            "A whole export from this server ends with a line beginning '# {BODY_FILE_VERDICT_MARKER}' \
             stating whether the file holds every FileEntry. No row can begin with '#': the first \
             field of a row is an MD5 or empty. If the last line is not that verdict, this file \
             was cut short in transit: it is a fragment, rows are missing from it, and it must \
             not be tendered as the file list of this case."
        ),
    ));
    out.push_str(&comment_line("exported_at", exported_at));
    out
}

/// The verdict line a body file ends with. `mactime` skips it; a reader
/// applies it. `failure` is the reason the walk stopped early, when it did.
pub fn render_body_file_verdict(written: usize, expected: i64, failure: Option<&str>) -> String {
    let verdict = match failure {
        None if written as i64 == expected => format!(
            "{BODY_FILE_VERDICT_MARKER} COMPLETE. This file holds all {written} of {expected} \
             FileEntry artifacts in the case."
        ),
        None => format!(
            "{BODY_FILE_VERDICT_MARKER} INCOMPLETE. This file holds {written} rows; the case held \
             {expected} FileEntry artifacts when the export began. The set changed while the walk \
             ran. Do not treat this file as the complete file list."
        ),
        Some(detail) => format!(
            "{BODY_FILE_VERDICT_MARKER} INCOMPLETE. This file holds {written} of {expected} \
             FileEntry artifacts; the walk stopped early: {detail}. Do not treat this file as the \
             complete file list."
        ),
    };
    format!("# {}\n", verdict.replace(['\n', '\r'], " "))
}

/// A `FileEntry` artifact's timestamp, as producers write it: RFC 3339 text or
/// bare Unix seconds. `None` for absent, null, empty, or unparseable — the
/// body file writes 0 for those, which is TSK's own "unknown".
fn epoch_seconds(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(n) = value.as_i64() {
        return Some(n);
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    // The filesystem parsers that feed the body file emit RFC 3339, but a
    // timestamp stored as bare epoch seconds in a JSON string would otherwise
    // be dropped to 0 ("unknown") though it is in fact known. Preserve it.
    if let Ok(secs) = text.parse::<i64>() {
        return Some(secs);
    }
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}

/// The first of `keys` present as a non-null value.
fn first<'a>(m: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|k| m.get(k)).find(|v| !v.is_null())
}

/// TSK renders `mode_as_string` as `<type>/<type><rwxrwxrwx>`, e.g.
/// `d/drwxr-xr-x` or `r/rrw-r--r--`. A numeric POSIX mode carries both the
/// type (its `S_IFMT` bits) and the permission bits, so it renders in full;
/// when the type bits are 0 the entry's own `is_directory` decides.
pub fn mode_as_string(mode: u32, is_directory: bool) -> String {
    let type_char = match mode & 0o170000 {
        0o040000 => 'd',
        0o100000 => 'r',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ if is_directory => 'd',
        _ => 'r',
    };
    let bit = |mask: u32, c: char| if mode & mask != 0 { c } else { '-' };
    let mut s = String::with_capacity(12);
    s.push(type_char);
    s.push('/');
    s.push(type_char);
    for (r, w, x) in [
        (0o400, 0o200, 0o100),
        (0o040, 0o020, 0o010),
        (0o004, 0o002, 0o001),
    ] {
        s.push(bit(r, 'r'));
        s.push(bit(w, 'w'));
        s.push(bit(x, 'x'));
    }
    s
}

/// Which of the four body-file time columns a timeline event's one time
/// belongs in, from what the event says the time is. The mapping is an
/// editorial choice and the export's preamble states it; an event whose kind
/// matches none of the words is `mtime`, the column `mactime` reads as "last
/// written".
fn event_time_column(timestamp_desc: &str) -> TimeColumn {
    let d = timestamp_desc.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| d.contains(w));
    if has(&["creat", "start", "birth", "born", "first "]) {
        TimeColumn::Crtime
    } else if has(&["access", "last used", "last run", "opened"]) {
        TimeColumn::Atime
    } else if has(&["exit", "terminat", "clos", "changed", "mft"]) {
        TimeColumn::Ctime
    } else {
        TimeColumn::Mtime
    }
}

#[derive(Clone, Copy)]
enum TimeColumn {
    Atime,
    Mtime,
    Ctime,
    Crtime,
}

/// The preamble of a body file built from timeline events rather than files.
///
/// Memory events (`timeliner --create-bodyfile` parity) and every other
/// module's events have one time each, not four, so each becomes one row
/// whose time sits in the column [`event_time_column`] chose.
pub fn render_event_body_file_preamble(
    case_id: &str,
    events: i64,
    exported_at: &str,
    timezone: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&comment_line(
        "export",
        "mactime body file (Sleuth Kit 3.x format) of timeline events",
    ));
    out.push_str(&comment_line("case_id", case_id));
    out.push_str(&comment_line("columns", BODY_FILE_COLUMNS));
    out.push_str(&comment_line(
        "population",
        "timeline events, one row each, from every module that produced one (memory events \
         included); not the file list of the case, which is the other body-file export.",
    ));
    out.push_str(&comment_line("events", &events.to_string()));
    out.push_str(&comment_line(
        "filters",
        "Filters from the request apply to the population above; the count is of the events \
         that matched them.",
    ));
    out.push_str(&comment_line("timezone", timezone));
    out.push_str(&comment_line(
        "times",
        "An event has one time. It is written in the column its kind names: crtime=created or \
         started, atime=accessed or last used, ctime=exited, closed or changed, mtime=anything \
         else; the other three columns are 0. The row's name is '[source module] subject kind'.",
    ));
    out.push_str(&comment_line(
        "how_to_read",
        &format!(
            "A whole export from this server ends with a line beginning '# {BODY_FILE_VERDICT_MARKER}' \
             stating whether the file holds every matching event. If the last line is not that \
             verdict, this file was cut short in transit and must not be tendered as the events \
             of this case."
        ),
    ));
    out.push_str(&comment_line("exported_at", exported_at));
    out
}

/// The verdict line an event body file ends with.
pub fn render_event_body_file_verdict(
    written: usize,
    expected: i64,
    failure: Option<&str>,
) -> String {
    let verdict = match failure {
        None if written as i64 == expected => format!(
            "{BODY_FILE_VERDICT_MARKER} COMPLETE. This file holds all {written} of {expected} \
             timeline events that matched."
        ),
        None => format!(
            "{BODY_FILE_VERDICT_MARKER} INCOMPLETE. This file holds {written} rows; {expected} \
             timeline events matched when the export began. The set changed while the walk ran."
        ),
        Some(detail) => format!(
            "{BODY_FILE_VERDICT_MARKER} INCOMPLETE. This file holds {written} of {expected} \
             timeline events; the walk stopped early: {detail}. Do not treat this file as the \
             complete event list."
        ),
    };
    format!("# {}\n", verdict.replace(['\n', '\r'], " "))
}

impl BodyFileEntry {
    /// Build a row from one timeline event: its source module, its subject,
    /// what kind of time it is, and the time (Unix seconds).
    pub fn from_timeline_event(
        timestamp: i64,
        source_module: &str,
        short_desc: &str,
        timestamp_desc: &str,
    ) -> Self {
        let mut e = BodyFileEntry {
            path: format!("[{source_module}] {short_desc} {timestamp_desc}"),
            ..Default::default()
        };
        let at = Some(timestamp);
        match event_time_column(timestamp_desc) {
            TimeColumn::Atime => e.atime = at,
            TimeColumn::Mtime => e.mtime = at,
            TimeColumn::Ctime => e.ctime = at,
            TimeColumn::Crtime => e.crtime = at,
        }
        e
    }

    /// Build a row from a `FileEntry` artifact's metadata document.
    ///
    /// The keys read are the ones every filesystem parser writes and the
    /// storage layer's timeline projection reads: `path` (or `relative_path`,
    /// or `name`), `size`, `inode` (or NTFS `record_number`), `mode`, `uid`,
    /// `gid`, `md5`, `deleted`, `is_directory`, and the timestamps `accessed`,
    /// `modified`, `changed` (or `mft_modified`), `created`. A deleted file's
    /// name carries TSK's ` (deleted)` suffix. Nothing absent is guessed: a
    /// missing time is 0 and a missing field is empty.
    pub fn from_file_entry_metadata(m: &Value) -> Self {
        let text = |keys: &[&str]| first(m, keys).and_then(Value::as_str).map(str::to_string);
        let int = |keys: &[&str]| first(m, keys).and_then(Value::as_i64);
        let flag = |key: &str| m.get(key).and_then(Value::as_bool).unwrap_or(false);

        let is_directory = flag("is_directory");
        let deleted = flag("deleted");
        let mut path = text(&["path", "relative_path", "name"]).unwrap_or_default();
        if deleted {
            path.push_str(" (deleted)");
        }
        let mode = match first(m, &["mode"]) {
            Some(Value::Number(n)) => n.as_u64().map(|n| mode_as_string(n as u32, is_directory)),
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };

        BodyFileEntry {
            md5: text(&["md5", "md5_hash"]),
            path,
            inode: int(&["inode", "record_number"]),
            mode,
            uid: int(&["uid"]),
            gid: int(&["gid"]),
            size: int(&["size"]).unwrap_or(0),
            atime: epoch_seconds(first(m, &["accessed"])),
            mtime: epoch_seconds(first(m, &["modified"])),
            ctime: epoch_seconds(first(m, &["changed", "mft_modified"])),
            crtime: epoch_seconds(first(m, &["created"])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- timeline events (memory and every other module's), §5.12 ---------

    #[test]
    fn an_event_row_puts_its_one_time_in_the_column_its_kind_names() {
        let at = 1_700_000_000;
        let row = |desc: &str| {
            render_row(&BodyFileEntry::from_timeline_event(
                at,
                "plugin.memory.processes",
                "System.exe PID 4",
                desc,
            ))
        };
        // |size|atime|mtime|ctime|crtime
        assert!(row("Process Created").ends_with("|0|0|0|0|1700000000"));
        assert!(row("Last Accessed").ends_with("|0|1700000000|0|0|0"));
        assert!(row("Process Exited").ends_with("|0|0|0|1700000000|0"));
        assert!(row("Key Last Write").ends_with("|0|0|1700000000|0|0"));
    }

    #[test]
    fn an_event_row_names_its_source_and_cannot_break_the_row() {
        let e = BodyFileEntry::from_timeline_event(
            1,
            "plugin.memory.netscan",
            "evil|name\nx",
            "Connection Created",
        );
        assert_eq!(
            e.path,
            "[plugin.memory.netscan] evil|name\nx Connection Created"
        );
        assert_eq!(render_row(&e).matches('|').count(), 10);
        assert!(!render_row(&e).contains('\n'));
    }

    #[test]
    fn the_event_preamble_states_its_population_and_the_time_mapping() {
        let p = render_event_body_file_preamble("case-1", 42, "2026-10-03T00:00:00Z", "UTC.");
        assert!(p.lines().all(|l| l.starts_with('#')));
        assert!(p.contains("timeline events"), "{p}");
        assert!(
            !p.contains("# file_entries"),
            "this is not the file list: {p}"
        );
        assert!(p.contains("events: 42"), "{p}");
        assert!(p.contains("crtime=created"), "{p}");
        assert!(
            p.contains("Filters"),
            "the filters that applied are stated: {p}"
        );
    }

    #[test]
    fn the_event_verdict_counts_events_not_files() {
        let ok = render_event_body_file_verdict(3, 3, None);
        assert!(
            ok.contains("COMPLETE") && ok.contains("3 of 3 timeline events"),
            "{ok}"
        );
        let short = render_event_body_file_verdict(2, 3, Some("store error"));
        assert!(
            short.contains("INCOMPLETE") && short.contains("store error"),
            "{short}"
        );
        assert!(!short.contains("FileEntry"));
    }

    #[test]
    fn row_has_eleven_pipe_delimited_fields() {
        let e = BodyFileEntry {
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".into()),
            path: "/etc/passwd".into(),
            inode: Some(1234),
            size: 512,
            mtime: Some(1_700_000_000),
            ..Default::default()
        };
        let row = render_row(&e);
        // 11 fields => 10 separators
        assert_eq!(row.matches('|').count(), 10);
        assert!(row.starts_with("d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|1234|"));
        assert!(row.ends_with("|512|0|1700000000|0|0"));
    }

    #[test]
    fn pipes_and_newlines_in_path_are_neutralised() {
        let e = BodyFileEntry {
            path: "/a|b\nc".into(),
            ..Default::default()
        };
        let row = render_row(&e);
        // only the 10 structural separators remain
        assert_eq!(row.matches('|').count(), 10);
        assert!(!row.contains('\n'));
    }

    #[test]
    fn missing_times_default_to_zero() {
        let e = BodyFileEntry {
            path: "/x".into(),
            ..Default::default()
        };
        let row = render_row(&e);
        assert!(row.ends_with("|0|0|0|0|0")); // size + 4 times all zero
    }

    #[test]
    fn a_file_entry_document_maps_onto_the_tsk_columns() {
        let m = serde_json::json!({
            "name": "passwd",
            "path": "/etc/passwd",
            "size": 1234,
            "inode": 17,
            "mode": 0o100644,
            "uid": 0,
            "gid": 0,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "created": "2024-01-15T12:30:00Z",
            "modified": "2024-01-15T12:30:00+00:00",
            "accessed": 1_700_000_000,
            "changed": "2024-01-15T12:31:00.5Z",
            "is_directory": false,
            "deleted": false,
        });
        let e = BodyFileEntry::from_file_entry_metadata(&m);
        assert_eq!(
            render_row(&e),
            "d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|17|r/rrw-r--r--|0|0|1234|\
             1700000000|1705321800|1705321860|1705321800"
        );
    }

    #[test]
    fn ntfs_keys_and_deleted_flag_are_honoured() {
        // NTFS entries carry record_number, not inode, and mft_modified where
        // POSIX has ctime. A deleted file carries TSK's suffix.
        let m = serde_json::json!({
            "path": "\\Users\\x\\gone.txt",
            "record_number": 4096,
            "mft_modified": "2024-01-15T12:30:00Z",
            "deleted": true,
            "is_directory": true,
        });
        let e = BodyFileEntry::from_file_entry_metadata(&m);
        assert_eq!(e.inode, Some(4096));
        assert_eq!(e.ctime, Some(1705321800));
        assert_eq!(e.path, "\\Users\\x\\gone.txt (deleted)");
        // No numeric mode: nothing is invented, not even from is_directory.
        assert_eq!(e.mode, None);
        assert_eq!(e.md5, None);
    }

    #[test]
    fn absent_null_empty_and_unparseable_times_are_zero_not_guessed() {
        let m = serde_json::json!({
            "path": "/x",
            "created": null,
            "modified": "",
            "accessed": "not a time",
        });
        let e = BodyFileEntry::from_file_entry_metadata(&m);
        assert!(render_row(&e).ends_with("|0|0|0|0|0"));
    }

    #[test]
    fn mode_string_follows_tsk_shape() {
        assert_eq!(mode_as_string(0o040755, false), "d/drwxr-xr-x");
        assert_eq!(mode_as_string(0o100600, false), "r/rrw-------");
        assert_eq!(mode_as_string(0o120777, false), "l/lrwxrwxrwx");
        // Type bits absent: the entry's own directory flag decides.
        assert_eq!(mode_as_string(0o755, true), "d/drwxr-xr-x");
        assert_eq!(mode_as_string(0o644, false), "r/rrw-r--r--");
    }

    #[test]
    fn preamble_and_verdict_are_comment_lines_mactime_skips() {
        let pre = render_body_file_preamble("case-1", 3, "2026-01-01T00:00:00Z", "UTC");
        assert!(pre.lines().all(|l| l.starts_with("# ")));
        assert!(pre.contains("# file_entries: 3\n"));
        assert!(pre.contains(BODY_FILE_COLUMNS));

        let whole = render_body_file_verdict(3, 3, None);
        assert!(whole.starts_with(&format!("# {BODY_FILE_VERDICT_MARKER} COMPLETE")));
        let short = render_body_file_verdict(2, 3, None);
        assert!(short.starts_with(&format!("# {BODY_FILE_VERDICT_MARKER} INCOMPLETE")));
        let failed = render_body_file_verdict(1, 3, Some("store\nerror"));
        assert!(failed.contains("INCOMPLETE"));
        assert!(failed.contains("store error"));
        assert_eq!(failed.lines().count(), 1, "a verdict is one line");
    }

    /// A MAC time held as bare epoch seconds in a JSON string is a known time
    /// and must survive to the body file, not be dropped to 0 ("unknown").
    #[test]
    fn a_numeric_seconds_string_is_a_known_time_not_unknown() {
        let m = serde_json::json!({
            "path": "/f",
            "modified": "1700000000",
            "accessed": 1_700_000_001,
            "created": "2024-01-15T12:30:00Z",
        });
        let e = BodyFileEntry::from_file_entry_metadata(&m);
        assert_eq!(
            e.mtime,
            Some(1_700_000_000),
            "the string form of epoch seconds is kept"
        );
        assert_eq!(e.atime, Some(1_700_000_001), "the numeric form still works");
        assert_eq!(e.crtime, Some(1_705_321_800), "and RFC 3339 still works");
        // A non-timestamp string is still "unknown" rather than a guess.
        let bad = BodyFileEntry::from_file_entry_metadata(
            &serde_json::json!({"path": "/f", "modified": "never"}),
        );
        assert_eq!(
            bad.mtime, None,
            "a non-timestamp string is unknown, not a guess"
        );
    }

    #[test]
    fn body_file_is_newline_terminated_per_row() {
        let out = render_body_file(&[
            BodyFileEntry {
                path: "/a".into(),
                ..Default::default()
            },
            BodyFileEntry {
                path: "/b".into(),
                ..Default::default()
            },
        ]);
        assert_eq!(out.lines().count(), 2);
        assert!(out.ends_with('\n'));
    }
}
