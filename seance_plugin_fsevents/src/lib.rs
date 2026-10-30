#![forbid(unsafe_code)]
//! macOS **FSEvents** parser for the per-volume `/.fseventsd/` DLS logs.
//!
//! Each log file is a GZIP stream that decompresses to a series of DLS **pages**.
//! A page is a 12-byte header (`1SLD`/`2SLD` magic, a u32 unknown, and a u32
//! page size) followed by packed records that fill out the page:
//!
//! - **DLS1** (`1SLD`): null-terminated path, `u64` event id, `u32` flags.
//! - **DLS2** (`2SLD`): the DLS1 fields plus a trailing `u64` node id.
//!
//! The parser self-selects purely by *content* (gzip magic, then a DLS page
//! magic after gunzip, or a raw DLS buffer), decodes the flag bitfield into the
//! well-known FSEvents names, and never panics on truncated or malformed data.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value};
use uuid::Uuid;

/// Cap on bytes read from the source before decompression.
const MAX_COMPRESSED: u64 = 256 * 1024 * 1024;
/// Cap on decompressed output (a defence against gzip bombs).
const MAX_DECOMPRESSED: u64 = 256 * 1024 * 1024;
/// Cap on the number of records emitted from a single log.
const MAX_RECORDS: usize = 500_000;

/// Well-known FSEvents flag bits, in ascending bit order.
const FLAG_TABLE: &[(u32, &str)] = &[
    (0x0000_0001, "FolderEvent"),
    (0x0000_0002, "Mount"),
    (0x0000_0004, "Unmount"),
    (0x0000_0020, "EndOfTransaction"),
    (0x0000_0800, "LastHardLinkRemoved"),
    (0x0000_1000, "HardLink"),
    (0x0000_4000, "SymbolicLink"),
    (0x0000_8000, "FileEvent"),
    (0x0001_0000, "PermissionChange"),
    (0x0002_0000, "ExtendedAttrModified"),
    (0x0004_0000, "ExtendedAttrRemoved"),
    (0x0010_0000, "DocumentRevision"),
    (0x0040_0000, "ItemCloned"),
    (0x0100_0000, "Created"),
    (0x0200_0000, "Removed"),
    (0x0400_0000, "InodeMetaMod"),
    (0x0800_0000, "Renamed"),
    (0x1000_0000, "Modified"),
    (0x2000_0000, "Exchange"),
    (0x4000_0000, "FinderInfoMod"),
    (0x8000_0000, "FolderCreated"),
];

fn flag_names(flags: u32) -> Vec<&'static str> {
    FLAG_TABLE
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Trailing path component (`/Users/x/dir` -> `dir`).
fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

fn is_dls_magic(b: &[u8]) -> bool {
    b.len() >= 4 && (&b[..4] == b"1SLD" || &b[..4] == b"2SLD")
}

/// Return a buffer that begins with a DLS page magic, or `None` if `content`
/// is neither a gzip stream wrapping DLS data nor a raw DLS buffer. The flag is
/// true when the gzip stream was longer than the cap and the returned buffer is
/// therefore only its beginning.
fn decompress(content: &[u8]) -> Option<(Vec<u8>, bool)> {
    decompress_capped(content, MAX_DECOMPRESSED)
}

/// [`decompress`] with an explicit cap, so the truncation path is testable
/// without materializing a 256 MiB stream.
fn decompress_capped(content: &[u8], cap: u64) -> Option<(Vec<u8>, bool)> {
    use std::io::Read;
    if content.len() >= 2 && content[0] == 0x1f && content[1] == 0x8b {
        // GZIP: FSEvents logs are sometimes several concatenated members.
        let mut out = Vec::new();
        let decoder = flate2::read::MultiGzDecoder::new(content);
        // Read ONE byte past the cap: `take(cap)` ends cleanly at the limit, so
        // a truncated decode is indistinguishable from a stream that simply
        // ended there. The extra byte is the tell (BUG-268).
        //
        // A decode ERROR is not a reason to discard what decoded. `read_to_end`
        // appends as it goes and leaves the bytes it managed in the buffer, and
        // the commonest cause of the error is that the INPUT was cut short —
        // `read_capped` stops at MAX_COMPRESSED, and a source can short-read —
        // so the stream ends mid-member through no fault of the evidence.
        // Throwing the buffer away made `decompress` answer `None`, which the
        // caller reads as "not an FSEvents log at all": a real macOS event
        // history over the cap vanished from the case with nothing recorded.
        // What decoded is kept, and marked truncated, so the pages that were
        // recovered reach the examiner and say they are partial.
        let decode_failed = decoder.take(cap + 1).read_to_end(&mut out).is_err();
        let truncated = decode_failed || out.len() as u64 > cap;
        if truncated {
            out.truncate(cap as usize);
        }
        is_dls_magic(&out).then_some((out, truncated))
    } else if is_dls_magic(content) {
        Some((content.to_vec(), false))
    } else {
        None
    }
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

fn make_record(
    case_id: Uuid,
    parent_id: Uuid,
    path: String,
    event_id: u64,
    flags: u32,
    node_id: Option<u64>,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("FSEventsRecord"));
    m.insert("subtype".into(), json!("fsevents"));
    m.insert("name".into(), json!(basename(&path)));
    m.insert("event_id".into(), json!(event_id));
    m.insert("flags".into(), json!(flags));
    m.insert("flag_names".into(), json!(flag_names(flags)));
    if let Some(nid) = node_id {
        m.insert("node_id".into(), json!(nid));
    }
    m.insert("path".into(), json!(path));
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
        .with_parent(parent_id)
}

/// True when everything in `data[from..to)` is zero.
///
/// The tail of a DLS page is zero-padded, so a walk that runs out of record
/// bytes on zeros reached the natural end of the page. Anything else means real
/// record bytes were left unread, and the difference decides whether the event
/// history is complete.
fn tail_is_padding(data: &[u8], from: usize, to: usize) -> bool {
    match data.get(from..to) {
        Some(rest) => rest.iter().all(|b| *b == 0),
        None => true,
    }
}

/// Decode the records packed into `data[rec_start..rec_end)` for one page.
///
/// Returns true when the walk stopped on record bytes it could not decode, as
/// opposed to reaching the page's zero padding.
#[allow(clippy::too_many_arguments)]
fn parse_page_records(
    data: &[u8],
    rec_start: usize,
    rec_end: usize,
    is_dls2: bool,
    case_id: Uuid,
    parent_id: Uuid,
    max_records: usize,
    out: &mut Vec<Artifact>,
) -> bool {
    // DLS1: u64 event_id + u32 flags. DLS2 adds a trailing u64 node_id.
    let fixed_len = if is_dls2 { 8 + 4 + 8 } else { 8 + 4 };
    let mut p = rec_start;
    while p < rec_end {
        // Null-terminated UTF-8 path.
        let mut q = p;
        while q < rec_end && data[q] != 0 {
            q += 1;
        }
        if q >= rec_end {
            // No terminator before the page ends: truncated record.
            return !tail_is_padding(data, p, rec_end);
        }
        let path_bytes = &data[p..q];
        let fixed_start = q + 1;
        if fixed_start + fixed_len > rec_end {
            // Fewer than the record's fixed bytes remain.
            return !tail_is_padding(data, p, rec_end);
        }
        let event_id = rd_u64(data, fixed_start);
        let flags = rd_u32(data, fixed_start + 8);
        let node_id = if is_dls2 {
            Some(rd_u64(data, fixed_start + 12))
        } else {
            None
        };
        p = fixed_start + fixed_len;

        if path_bytes.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(path_bytes).into_owned();
        out.push(make_record(
            case_id, parent_id, path, event_id, flags, node_id,
        ));
        if out.len() >= max_records {
            // The caller reports the cap; this is not a structural stop.
            return false;
        }
    }
    false
}

/// How a DLS walk ended.
#[derive(Default, Clone, Copy)]
struct DlsWalk {
    /// The record cap stopped the walk before the stream ended.
    capped: bool,
    /// The page/record structure ended before the buffer did, on bytes that are
    /// not padding: a truncated or corrupt log, with real events left unread.
    structure_stopped: bool,
}

/// Walk the DLS page stream, decoding every record until EOF or the cap.
/// The returned [`DlsWalk`] says whether later history exists in the log but is
/// not in the returned records, and why.
fn parse_dls(data: &[u8], case_id: Uuid, parent_id: Uuid) -> (Vec<Artifact>, DlsWalk) {
    parse_dls_capped(data, case_id, parent_id, MAX_RECORDS)
}

/// [`parse_dls`] with an explicit record cap, so the cap path is testable.
fn parse_dls_capped(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    max_records: usize,
) -> (Vec<Artifact>, DlsWalk) {
    let mut out = Vec::new();
    let mut walk = DlsWalk::default();
    let mut pos = 0usize;
    while pos + 12 <= data.len() {
        let is_dls2 = &data[pos..pos + 4] == b"2SLD";
        let is_dls1 = &data[pos..pos + 4] == b"1SLD";
        if !is_dls1 && !is_dls2 {
            // Anything but zero padding here is a page the walk could not enter:
            // the events in it, and in every page after it, are unread.
            walk.structure_stopped = !tail_is_padding(data, pos, data.len());
            return (out, walk);
        }
        let page_size = rd_u32(data, pos + 8) as usize;
        if page_size < 12 {
            // Malformed header: would not advance. Stop.
            walk.structure_stopped = true;
            return (out, walk);
        }
        let rec_start = pos + 12;
        let rec_end = (pos + page_size).min(data.len());
        // A page header claiming more bytes than the buffer holds is a log cut
        // off mid-page.
        if pos + page_size > data.len() {
            walk.structure_stopped = true;
        }
        if parse_page_records(
            data,
            rec_start,
            rec_end,
            is_dls2,
            case_id,
            parent_id,
            max_records,
            &mut out,
        ) {
            walk.structure_stopped = true;
        }
        if out.len() >= max_records {
            // The cap stopped the walk. Records may have been dropped inside this
            // page as well as in the pages after it, so the honest report is
            // "we stopped early", never "that was all there was".
            walk.capped = true;
            return (out, walk);
        }
        pos += page_size;
    }
    // Trailing bytes too short to hold a page header: padding is the normal end
    // of a log, anything else is a truncated final page.
    if pos < data.len() && !tail_is_padding(data, pos, data.len()) {
        walk.structure_stopped = true;
    }
    (out, walk)
}

/// FSEvents `/.fseventsd/` DLS log parser.
pub struct FsEventsParser;

impl ForensicsModule for FsEventsParser {
    fn id(&self) -> &str {
        "plugin.macos.fsevents"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let declared = data.size();
        let content = read_capped(data.as_ref(), MAX_COMPRESSED);
        // Self-select purely by content: gzip'd DLS, or a raw DLS buffer.
        let Some((decompressed, gzip_truncated)) = decompress(&content) else {
            return Ok(Vec::new());
        };
        let (mut records, walk) = parse_dls(&decompressed, artifact.case_id, artifact.id);

        // Every cap that stopped us short is reported: a log that was only
        // partly parsed must never look like a fully recovered event history
        // (BUG-268). A page or record structure that ended early counts too: a
        // damaged log after valid pages otherwise presents as the whole history
        // (B4-016).
        let input_truncated = declared > content.len() as u64;
        if input_truncated || gzip_truncated || walk.capped || walk.structure_stopped {
            // A source that could not deliver the bytes it declared is a
            // different fact from a parser cap, and only the source knows which
            // it was: `read_capped` stops at MAX_COMPRESSED, so a shortfall
            // below that ceiling is the evidence failing, not us capping.
            let source_short = input_truncated && declared <= MAX_COMPRESSED;
            records.push(incomplete_marker(
                artifact,
                records.len(),
                input_truncated,
                gzip_truncated,
                walk,
                source_short,
            ));
        }
        Ok(records)
    }
}

/// A record stating that this FSEvents log was only partly parsed, and why.
///
/// What an examiner learns from `content_incomplete_reason`: whether the event
/// history is short because a parser cap stopped it (the rest of the log exists
/// and could be recovered by raising the cap) or because the evidence source
/// could not deliver the bytes it declared (nothing will recover it from this
/// image). A wrong answer looks like `cap_reached` on a log that was never
/// capped at all, sending an examiner to re-run with a bigger limit for events
/// that are not in the image (B3-021).
fn incomplete_marker(
    artifact: &Artifact,
    records_emitted: usize,
    input_truncated: bool,
    gzip_truncated: bool,
    walk: DlsWalk,
    source_short: bool,
) -> Artifact {
    // A structural stop with no cap and no short source is a damaged log: the
    // follow-up is to recover the file, not to raise a limit.
    let reason = if source_short {
        IncompleteReason::ShortRead
    } else if walk.structure_stopped && !walk.capped && !gzip_truncated && !input_truncated {
        IncompleteReason::UnresolvedStructure
    } else {
        IncompleteReason::CapReached
    };
    // The sentence the examiner is shown beside the flag. The reader keys it
    // off `<flag>_detail` (`frontend/src/lib/incompleteness.ts`), and this
    // record carried none at all, so a stopped walk reached the person it
    // exists for as the bare token `unresolved_structure`. Which of the three
    // it was decides the follow-up: raise a cap, recover the file, or re-image.
    let detail = if source_short {
        format!(
            "the evidence delivered fewer bytes than this FSEvents log declares; \
             {records_emitted} event(s) were decoded and the rest of the log is \
             not in this image"
        )
    } else if reason == IncompleteReason::UnresolvedStructure {
        format!(
            "the page structure stopped early on bytes that are not padding, after \
             {records_emitted} event(s); the events beyond that point were never \
             read, and the log is damaged rather than merely long"
        )
    } else {
        format!(
            "the walk stopped at a parser cap after {records_emitted} event(s); \
             the events beyond it exist in the log and were not extracted"
        )
    };
    let metadata = json!({
        "type": "FSEventsParseStatus",
        "subtype": "fsevents_incomplete",
        "name": "FSEvents log (partially parsed)",
        "content_incomplete": true,
        "content_incomplete_reason": reason.as_str(),
        "inventory_incomplete": true,
        "inventory_incomplete_reason": reason.as_str(),
        "content_incomplete_detail": detail,
        "inventory_incomplete_detail": detail,
        "records_emitted": records_emitted,
        "compressed_input_truncated": input_truncated,
        "decompressed_output_truncated": gzip_truncated,
        "record_cap_reached": walk.capped,
        "page_structure_stopped_early": walk.structure_stopped,
        "max_compressed_bytes": MAX_COMPRESSED,
        "max_decompressed_bytes": MAX_DECOMPRESSED,
        "max_records": MAX_RECORDS,
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

#[cfg(test)]
mod tests;
