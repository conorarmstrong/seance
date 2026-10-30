#![forbid(unsafe_code)]
//! Desktop (macOS/Linux) forensic parsers implemented as [`ForensicsModule`]s:
//!
//! - **Shell history** (`.bash_history` / `.zsh_history` → [`ShellHistoryParser`]),
//!   including the zsh `EXTENDED_HISTORY` `: <epoch>:<dur>;<cmd>` form and the
//!   bash `#<epoch>` timestamp-comment form.
//! - **Freedesktop Trash** (`*.trashinfo` → [`LinuxTrashParser`]) — the
//!   `[Trash Info]` INI with a percent-encoded `Path` and an ISO-8601
//!   `DeletionDate`.
//! - **GTK recent files** (`recently-used.xbel` → [`RecentFilesParser`]) — a
//!   light-touch XBEL/XML scan for `<bookmark>` elements and their applications.
//!
//! Each self-selects by basename, reads its content in full, and never panics on
//! malformed input (returns an empty `Vec` instead).

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value};
use uuid::Uuid;

/// Upper bound on how much of a candidate file we read into memory. These are
/// small text artifacts; a runaway size is almost certainly a mis-selection.
const MAX_TEXT_BYTES: u64 = 64 * 1024 * 1024;

/// Read a candidate text artifact, reporting whether the bytes fell short of the
/// declared size (over the cap, or a truncated/broken source).
///
/// Forensic meaning: these files are inventories — every shell command a user
/// typed, every bookmark the desktop recorded. Reading a prefix and emitting its
/// entries produces a list that looks complete, so the tail commands and
/// bookmarks read as though they were never there. The caller must stamp the
/// shortfall (see [`text_incomplete_marker`]).
fn read_text_capped(data: &dyn seance_core::data_source::DataSource) -> (Vec<u8>, bool) {
    let declared = data.size();
    let bytes = read_capped(data, MAX_TEXT_BYTES);
    let short = (bytes.len() as u64) < declared;
    (bytes, short)
}

/// The reason a capped/short text read did not reach the end of the file:
/// over the parser cap, or a source that stopped early.
fn read_shortfall_reason(declared_size: u64) -> IncompleteReason {
    if declared_size > MAX_TEXT_BYTES {
        IncompleteReason::CapReached
    } else {
        IncompleteReason::ShortRead
    }
}

/// A record stating that a desktop inventory was only partly read.
///
/// `reason` is supplied by the caller rather than inferred, because not every
/// caller is short on BYTES: a PNG thumbnail can be delivered in full and still
/// end inside its own header, which is `unresolved_structure`, not a short read.
/// Reporting the wrong reason would send an examiner looking for an acquisition
/// fault that does not exist.
fn text_incomplete_marker(
    artifact: &Artifact,
    kind: &str,
    file_name: &str,
    reason: IncompleteReason,
    entries_emitted: usize,
    bytes_read: u64,
    declared_size: u64,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("DesktopArtifactParseStatus"));
    m.insert("subtype".into(), json!("desktop_artifact_incomplete"));
    m.insert("artifact_kind".into(), json!(kind));
    m.insert("file_name".into(), json!(file_name));
    m.insert("content_incomplete".into(), json!(true));
    m.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    m.insert("entries_emitted".into(), json!(entries_emitted));
    m.insert("bytes_read".into(), json!(bytes_read));
    m.insert("declared_size".into(), json!(declared_size));
    m.insert("max_text_bytes".into(), json!(MAX_TEXT_BYTES));
    // The sentence follows the reason. "Only part of this file was read" over a
    // file read whole — every declared byte in hand, the structure ending
    // inside itself — sent an examiner looking for an acquisition fault that
    // does not exist, and the record contradicted its own byte counts
    // (HUNT-064).
    let message = match reason {
        IncompleteReason::UnresolvedStructure => {
            "The whole file was read and its structure ends before the entries would; what \
             was not there could not be extracted"
        }
        _ => "Only part of this file was read; entries past that point were not extracted",
    };
    m.insert("message".into(), json!(message));
    m.insert(
        "name".into(),
        json!(format!("{kind} (partially parsed): {file_name}")),
    );
    record(artifact.case_id, artifact.id, m)
}

/// Longest command/URI kept for the human-readable `name` preview.
const PREVIEW_CHARS: usize = 80;

// --- shared helpers ----------------------------------------------------------

/// Last path component (splitting on `/`), preserving case.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Lower-cased basename, for case-insensitive self-selection.
fn basename_lower(name: &str) -> String {
    file_name(name).to_ascii_lowercase()
}

/// The artifact's declared `name` metadata, or an empty string.
fn artifact_name(a: &Artifact) -> String {
    a.metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Build a `ParsedRecord` child artifact carrying `map`, parented to the source.
fn record(case: Uuid, parent: Uuid, map: serde_json::Map<String, Value>) -> Artifact {
    Artifact::new(case, ArtifactType::ParsedRecord, None, Value::Object(map)).with_parent(parent)
}

/// Truncate to a short, char-boundary-safe preview.
fn preview(s: &str) -> String {
    if s.chars().count() <= PREVIEW_CHARS {
        s.to_string()
    } else {
        let head: String = s.chars().take(PREVIEW_CHARS).collect();
        format!("{head}...")
    }
}

/// Decode one hex nibble.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `%XX` escapes; malformed escapes are passed through verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Days from the Unix epoch (1970-01-01) for a proleptic Gregorian date.
/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Seconds to add to a naive (offset-treated-as-UTC) wall-clock reading to reach
/// true UTC, given the timezone designator carried in an ISO-8601 time field.
///
/// A wall clock of `HH:MM:SS±oh:om` corresponds to a UTC time that is the offset
/// earlier for `+` (east of UTC) and later for `-`; so the correction is
/// `-offset`. `Z`/`z` and a naive field (no designator) are UTC → `0`. The date
/// hyphens were already split off, so the only `+`/`-`/`Z` here is the zone
/// marker.
fn tz_correction_seconds(time_part: &str) -> i64 {
    if time_part.contains(['Z', 'z']) {
        return 0;
    }
    let (sign, rest) = if let Some(p) = time_part.find('+') {
        (1i64, &time_part[p + 1..])
    } else if let Some(p) = time_part.find('-') {
        (-1i64, &time_part[p + 1..])
    } else {
        return 0; // naive → treat as UTC
    };
    // `rest` is `oh:om`, `ohom`, or `oh`.
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    let (oh, om) = if digits.len() >= 4 {
        (
            digits[0..2].parse::<i64>().unwrap_or(0),
            digits[2..4].parse::<i64>().unwrap_or(0),
        )
    } else if digits.len() >= 2 {
        (digits[0..2].parse::<i64>().unwrap_or(0), 0)
    } else {
        return 0;
    };
    let offset = sign * (oh * 3_600 + om * 60);
    // Correction to apply to the wall-clock-as-UTC value: subtract the offset.
    -offset
}

/// Parse an ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SS`, optional `Z`/offset/
/// fractional seconds, `T` or space separator) to Unix seconds. A trailing
/// timezone offset (e.g. `+02:00`) is applied; a naive timestamp is treated as
/// UTC. Returns `None` if it does not parse.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date_part, time_part) = match s.split_once('T') {
        Some(x) => x,
        None => s.split_once(' ')?,
    };

    let mut d = date_part.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut t = time_part.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let minute: i64 = t.next().unwrap_or("0").parse().ok()?;
    // Seconds may carry a trailing `Z`, timezone, or fraction; keep the digits.
    let secs: i64 = t
        .next()
        .unwrap_or("0")
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    let naive = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + secs;
    Some(naive + tz_correction_seconds(time_part))
}

// --- 1) Shell history --------------------------------------------------------

const SHELL_HISTORY_NAMES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    "zsh_history",
    "bash_history",
];

pub struct ShellHistoryParser;

impl ForensicsModule for ShellHistoryParser {
    fn id(&self) -> &str {
        "plugin.os.shell_history"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(parse_shell_history(artifact))
    }
}

fn parse_shell_history(artifact: &Artifact) -> Vec<Artifact> {
    let name = artifact_name(artifact);
    if !SHELL_HISTORY_NAMES.contains(&basename_lower(&name).as_str()) {
        return Vec::new();
    }
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    let (bytes, short) = read_text_capped(data.as_ref());
    let text = String::from_utf8_lossy(&bytes);

    let default_shell = if basename_lower(&name).contains("zsh") {
        "zsh"
    } else {
        "bash"
    };

    let mut out = Vec::new();
    let mut pending_ts: Option<i64> = None;

    for (i, line) in text.lines().enumerate() {
        let line_number = (i + 1) as i64;
        if line.is_empty() {
            continue;
        }

        // zsh EXTENDED_HISTORY: `: <epoch>:<elapsed>;<command>`
        if let Some(rest) = line.strip_prefix(": ") {
            if let Some((meta, cmd)) = rest.split_once(';') {
                if !cmd.is_empty() {
                    let epoch = meta
                        .split(':')
                        .next()
                        .and_then(|s| s.trim().parse::<i64>().ok());
                    out.push(shell_record(artifact, "zsh", cmd, epoch, line_number));
                }
                continue;
            }
        }

        // bash HISTTIMEFORMAT: a `#<epoch>` comment applies to the NEXT command.
        if let Some(rest) = line.strip_prefix('#') {
            if let Ok(epoch) = rest.trim().parse::<i64>() {
                pending_ts = Some(epoch);
                continue;
            }
        }

        // Plain command line (no inline timestamp).
        let date = pending_ts.take();
        out.push(shell_record(
            artifact,
            default_shell,
            line,
            date,
            line_number,
        ));
    }

    if short {
        let emitted = out.len();
        out.push(text_incomplete_marker(
            artifact,
            "Shell history",
            &name,
            read_shortfall_reason(data.size()),
            emitted,
            bytes.len() as u64,
            data.size(),
        ));
    }

    out
}

fn shell_record(
    artifact: &Artifact,
    shell: &str,
    command: &str,
    date: Option<i64>,
    line_number: i64,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("ShellHistoryEntry"));
    m.insert("subtype".into(), json!("shell_history"));
    m.insert("shell".into(), json!(shell));
    m.insert("command".into(), json!(command));
    m.insert("line_number".into(), json!(line_number));
    if let Some(d) = date {
        m.insert("date".into(), json!(d));
    }
    m.insert("name".into(), json!(preview(command)));
    record(artifact.case_id, artifact.id, m)
}

// --- 2) Freedesktop Trash (*.trashinfo) --------------------------------------

pub struct LinuxTrashParser;

impl ForensicsModule for LinuxTrashParser {
    fn id(&self) -> &str {
        "plugin.os.linux_trash"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(parse_trashinfo(artifact))
    }
}

fn parse_trashinfo(artifact: &Artifact) -> Vec<Artifact> {
    let name = artifact_name(artifact);
    if !basename_lower(&name).ends_with(".trashinfo") {
        return Vec::new();
    }
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    let (bytes, short) = read_text_capped(data.as_ref());
    let text = String::from_utf8_lossy(&bytes);

    let mut raw_path: Option<String> = None;
    let mut deletion_date: Option<String> = None;
    for line in text.lines() {
        if let Some((key, val)) = line.split_once('=') {
            match key.trim() {
                "Path" => raw_path = Some(val.trim().to_string()),
                "DeletionDate" => deletion_date = Some(val.trim().to_string()),
                _ => {}
            }
        }
    }

    let Some(raw_path) = raw_path else {
        // No `Path=` line. On a file that was read whole this really is not a
        // trash record; on a short read the line may simply lie past the point
        // the source stopped, and returning nothing would erase a deleted file
        // from the case (B7-018).
        if short {
            return vec![text_incomplete_marker(
                artifact,
                "linux_trash",
                &name,
                read_shortfall_reason(data.size()),
                0,
                bytes.len() as u64,
                data.size(),
            )];
        }
        return Vec::new();
    };
    let original_path = percent_decode(&raw_path);

    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("TrashEntry"));
    m.insert("subtype".into(), json!("linux_trash"));
    m.insert("original_path".into(), json!(original_path));
    m.insert("name".into(), json!(file_name(&original_path)));
    if let Some(dd) = &deletion_date {
        m.insert("deletion_date".into(), json!(dd));
        if let Some(unix) = parse_iso8601_to_unix(dd) {
            m.insert("date".into(), json!(unix));
        }
    }
    // A short read may have cut the file before `DeletionDate`, so a missing
    // deletion time must not read as "the trash record had no date". The reason
    // comes from the shared helper: hard-coding `short_read` here reported an
    // acquisition fault for a file that was simply over the parser's own cap,
    // which sends an examiner looking for a broken image that does not exist.
    if short {
        m.insert("content_incomplete".into(), json!(true));
        m.insert(
            "content_incomplete_reason".into(),
            json!(read_shortfall_reason(data.size()).as_str()),
        );
        m.insert("bytes_read".into(), json!(bytes.len() as u64));
        m.insert("declared_size".into(), json!(data.size()));
    }
    vec![record(artifact.case_id, artifact.id, m)]
}

// --- 3) GTK recent files (recently-used.xbel) --------------------------------

pub struct RecentFilesParser;

impl ForensicsModule for RecentFilesParser {
    fn id(&self) -> &str {
        "plugin.os.recent_files"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(parse_recently_used(artifact))
    }
}

/// Minimal XML entity unescape for the handful of predefined entities.
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Pull a double-quoted attribute value out of a start-tag slice.
fn xml_attr(tag: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = tag.find(&needle)? + needle.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(xml_unescape(&rest[..end]))
}

fn parse_recently_used(artifact: &Artifact) -> Vec<Artifact> {
    let name = artifact_name(artifact);
    if basename_lower(&name) != "recently-used.xbel" {
        return Vec::new();
    }
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    let (bytes, short) = read_text_capped(data.as_ref());
    let cow = String::from_utf8_lossy(&bytes);
    let text: &str = &cow;

    let mut out = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = text[search_from..].find("<bookmark ") {
        let tag_start = search_from + rel;
        // End of the opening tag.
        let Some(gt_rel) = text[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + gt_rel;
        let open_tag = &text[tag_start..tag_end];

        let href = xml_attr(open_tag, "href");
        let added = xml_attr(open_tag, "added");
        let modified = xml_attr(open_tag, "modified");
        let visited = xml_attr(open_tag, "visited");

        // The application(s) live between here and whichever comes first: this
        // bookmark's `</bookmark>` or the next `<bookmark ` (self-closing case).
        let next_open = text[tag_end..].find("<bookmark ").map(|r| tag_end + r);
        let next_close = text[tag_end..].find("</bookmark>").map(|r| tag_end + r);
        let region_end = [next_open, next_close]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(text.len());
        let region = &text[tag_end..region_end];

        let application = region.find("<bookmark:application ").and_then(|r| {
            let app_tag = &region[r..];
            let end = app_tag.find('>')?;
            xml_attr(&app_tag[..end], "name")
        });

        let uri = href.as_ref().map(|h| {
            let path = h.strip_prefix("file://").unwrap_or(h);
            percent_decode(path)
        });

        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("RecentFileEntry"));
        m.insert("subtype".into(), json!("recent_file"));
        if let Some(u) = &uri {
            m.insert("uri".into(), json!(u));
        }
        if let Some(a) = added {
            m.insert("added".into(), json!(a));
        }
        if let Some(mo) = modified {
            m.insert("modified".into(), json!(mo));
        }
        if let Some(v) = visited {
            m.insert("visited".into(), json!(v));
        }
        if let Some(app) = application {
            m.insert("application".into(), json!(app));
        }
        let display = uri.as_deref().map(file_name).unwrap_or("recent file");
        m.insert("name".into(), json!(display));
        out.push(record(artifact.case_id, artifact.id, m));

        search_from = tag_end + 1;
    }

    if short {
        let emitted = out.len();
        out.push(text_incomplete_marker(
            artifact,
            "Recently-used bookmarks",
            &name,
            read_shortfall_reason(data.size()),
            emitted,
            bytes.len() as u64,
            data.size(),
        ));
    }

    out
}

// --- 4) Freedesktop thumbnail cache (~/.cache/thumbnails/**/*.png) ------------

pub struct ThumbnailsParser;

impl ForensicsModule for ThumbnailsParser {
    fn id(&self) -> &str {
        "plugin.os.freedesktop_thumbnails"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(parse_thumbnail(artifact))
    }
}

/// PNG magic. Freedesktop thumbnails are always PNGs.
const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// Why a thumbnail's PNG header was not read to the pixel data.
///
/// `short` distinguishes the two causes that look identical in the result: the
/// bytes never arrived (over the cap, or the source stopped), versus every
/// declared byte arriving and the file itself ending inside its own header. The
/// second is a property of the evidence, not of the acquisition, and saying
/// `short_read` there would point an examiner at the wrong fault.
fn thumbnail_incomplete_reason(short: bool, declared_size: u64) -> IncompleteReason {
    if short {
        read_shortfall_reason(declared_size)
    } else {
        IncompleteReason::UnresolvedStructure
    }
}

/// Extract the freedesktop thumbnail metadata carried in a PNG's `tEXt` chunks.
/// Detection is by content: any PNG that carries a `Thumb::URI` key is a
/// thumbnail (the file itself is named after the MD5 of that URI, so the name
/// alone tells us nothing). PNGs without it yield nothing, so an ordinary image
/// is never mis-parsed.
fn parse_thumbnail(artifact: &Artifact) -> Vec<Artifact> {
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    // `short` is the difference between "this PNG carried no thumbnail keys"
    // and "we never reached the bytes that would have carried them". The
    // thumbnail keys sit in the header, so a read that stops early produces the
    // same empty answer as an ordinary image (B2-172).
    let (buf, short) = read_text_capped(data.as_ref());
    if buf.len() < 8 || buf[..8] != PNG_SIG {
        return Vec::new();
    }

    let mut uri: Option<String> = None;
    let mut mtime: Option<String> = None;
    let mut mime: Option<String> = None;
    let mut software: Option<String> = None;

    let mut pos = 8usize;
    // True once the walk reaches the pixel data, which is what proves the whole
    // header — and therefore every thumbnail tEXt key — was present in `buf`.
    let mut reached_image_data = false;
    // Walk chunks until the pixel data (IDAT) or end; all thumbnail tEXt keys
    // sit in the header before IDAT.
    while pos + 8 <= buf.len() {
        let len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        let ctype = &buf[pos + 4..pos + 8];
        let data_start = pos + 8;
        let Some(data_end) = data_start.checked_add(len) else {
            break;
        };
        if data_end > buf.len() {
            // A chunk that runs past the bytes we hold: the header is cut, and
            // any tEXt key after this point is unreachable.
            break;
        }
        if ctype == b"IDAT" || ctype == b"IEND" {
            reached_image_data = true;
            break;
        }
        if ctype == b"tEXt" {
            let chunk = &buf[data_start..data_end];
            if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                let key = String::from_utf8_lossy(&chunk[..nul]);
                let val = String::from_utf8_lossy(&chunk[nul + 1..]).into_owned();
                match key.as_ref() {
                    "Thumb::URI" => uri = Some(val),
                    "Thumb::MTime" => mtime = Some(val),
                    "Thumb::Mimetype" => mime = Some(val),
                    "Software" => software = Some(val),
                    _ => {}
                }
            }
        }
        pos = data_end + 4; // skip the 4-byte CRC
    }

    // The header was cut short, either by our read or because the file itself
    // ends inside it.
    let header_truncated = short || !reached_image_data;

    let Some(uri) = uri else {
        // No `Thumb::URI`. For a whole PNG that is the ordinary answer — it is
        // simply not a thumbnail — and must stay silent, or every image in the
        // evidence gains a spurious finding. For a PNG whose header we did not
        // finish reading, we genuinely do not know, and saying nothing would let
        // a thumbnail of a deleted file disappear without trace — but only where
        // something says it could be one: a thumbnail-cache path, no path at
        // all (a loose or carved file), or a `Thumb::` key already read. A cut
        // PNG at a known path elsewhere is a cut PNG; on the NIST Data Leakage
        // image, Windows Installer's `/Config.Msi/*.rbf` rollback files each
        // gained a "freedesktop thumbnail" marker this way (HUNT-064).
        let could_be_thumbnail = mtime.is_some()
            || mime.is_some()
            || match artifact.metadata.get("path").and_then(|v| v.as_str()) {
                None => true,
                Some(path) => {
                    let lower = path.to_ascii_lowercase();
                    lower.contains("/.cache/thumbnails/") || lower.contains("/.thumbnails/")
                }
            };
        if header_truncated && could_be_thumbnail {
            return vec![text_incomplete_marker(
                artifact,
                "FreedesktopThumbnail",
                &artifact_name(artifact),
                thumbnail_incomplete_reason(short, data.size()),
                0,
                buf.len() as u64,
                data.size(),
            )];
        }
        return Vec::new();
    };
    let original_path = percent_decode(uri.strip_prefix("file://").unwrap_or(&uri));

    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("FreedesktopThumbnail"));
    m.insert("subtype".into(), json!("freedesktop_thumbnail"));
    m.insert("uri".into(), json!(uri));
    m.insert("original_path".into(), json!(original_path.clone()));
    m.insert("name".into(), json!(file_name(&original_path).to_string()));
    if let Some(mt) = mtime.as_ref().and_then(|s| s.trim().parse::<i64>().ok()) {
        m.insert("source_mtime".into(), json!(mt));
    }
    if let Some(mime) = mime {
        m.insert("mime_type".into(), json!(mime));
    }
    if let Some(sw) = software {
        m.insert("software".into(), json!(sw));
    }
    // The URI was found, but the header ended before the remaining keys could
    // be: a missing `Thumb::MTime` or `Thumb::Mimetype` here means "not read",
    // not "not recorded by the desktop".
    if header_truncated {
        m.insert("content_incomplete".into(), json!(true));
        m.insert(
            "content_incomplete_reason".into(),
            json!(thumbnail_incomplete_reason(short, data.size()).as_str()),
        );
        m.insert("bytes_read".into(), json!(buf.len() as u64));
        m.insert("declared_size".into(), json!(data.size()));
    }
    vec![record(artifact.case_id, artifact.id, m)]
}

#[cfg(test)]
mod tests;
