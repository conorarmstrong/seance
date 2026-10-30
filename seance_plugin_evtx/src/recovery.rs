//! Recovery of EVTX records the intact-file parser cannot read.
//!
//! The intact parser (`lib.rs`) walks a file from its `ElfFile` header, chunk
//! by aligned chunk, and stops at the first chunk the file header does not
//! account for. That loses every record in a chunk whose header was
//! overwritten, in a chunk cut short by truncation, in the slack of a chunk
//! Windows has since reused, and in any chunk that sits in unallocated space
//! with no file header in front of it. This module goes after those.
//!
//! Three stages, each bounded and each counted:
//!
//! 1. **Carve** `ElfChnk` chunks by signature anywhere in the input, validate
//!    the header and data CRC32s separately, and decode each chunk with a
//!    walker that does not trust the header's free-space offset or its
//!    string/template tables.
//! 2. **Pool templates** across chunks. A template definition is rendered
//!    once with every substitution replaced by a sentinel, so the rendered
//!    text is independent of the chunk's string-table offsets; it is keyed by
//!    the template identifier and a hash of that text. A record whose own
//!    chunk lost its definition is rendered from an identical definition
//!    found in another chunk, and says so.
//! 3. **Re-bind loose records.** The substitution array of a record whose
//!    template will not read is decoded value by value, each positioned from
//!    the descriptor table rather than from the previous value, so one
//!    corrupt value does not lose the rest. What cannot be rendered is named
//!    by substitution index.
//!
//! Nothing here is ever reported as a live event: every record leaves as a
//! [`RecoveredRecord`], which the caller turns into a distinct artifact type.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, TimeZone, Utc};
use seance_core::data_source::DataSource;

/// Bytes of input the signature scan will cover before stopping.
pub(crate) const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Chunk signatures the scan will act on.
pub(crate) const MAX_CHUNKS: usize = 16_384;
/// Records (complete, partial or header-only) the recovery will emit.
pub(crate) const MAX_RECORDS: usize = 500_000;
/// Distinct templates the cross-chunk pool will hold.
pub(crate) const MAX_POOLED_TEMPLATES: usize = 4_096;
/// Chunks of note the status record will list individually, by offset.
pub(crate) const MAX_LISTED_CHUNKS: usize = 1_024;

/// The bounds one recovery runs under. Tests narrow them to prove the
/// disclosure; production uses [`Limits::default`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub scan_bytes: u64,
    pub chunks: usize,
    pub records: usize,
    pub pooled_templates: usize,
    pub listed_chunks: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_bytes: MAX_SCAN_BYTES,
            chunks: MAX_CHUNKS,
            records: MAX_RECORDS,
            pooled_templates: MAX_POOLED_TEMPLATES,
            listed_chunks: MAX_LISTED_CHUNKS,
        }
    }
}

/// What the intact walk already emitted, so recovery neither repeats a live
/// record nor treats a chunk the intact parser decoded as lost.
#[derive(Debug, Default)]
pub(crate) struct LiveCoverage {
    pub chunks: HashMap<u64, LiveChunk>,
}

#[derive(Debug, Default)]
pub(crate) struct LiveChunk {
    /// Every record in this chunk below its free-space offset decoded and was
    /// emitted live, so recovery need only look at the chunk's slack.
    pub fully_decoded: bool,
    pub record_ids: HashSet<u64>,
}

impl LiveCoverage {
    pub fn note_chunk(&mut self, offset: u64, fully_decoded: bool, record_ids: HashSet<u64>) {
        self.chunks.insert(
            offset,
            LiveChunk {
                fully_decoded,
                record_ids,
            },
        );
    }
}

/// Where a recovered record's bytes were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoverySource {
    /// Inside a carved chunk, below its free-space offset, that the intact
    /// parser did not decode (or decoded only partly).
    CarvedChunk,
    /// Past a chunk's free-space offset: a record from an earlier use of the
    /// chunk, whose references into the chunk point at data since rewritten.
    ChunkSlack,
    /// Outside every carved chunk: its chunk header is gone, and the chunk
    /// window it is decoded against was inferred.
    LooseRecord,
}

impl RecoverySource {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoverySource::CarvedChunk => "carved_chunk",
            RecoverySource::ChunkSlack => "chunk_slack",
            RecoverySource::LooseRecord => "loose_record",
        }
    }
}

/// The state of the chunk header a record was decoded under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkHeaderState {
    /// The chunk's own header, as found.
    Present,
    /// The chunk's own header with its string and template tables discarded,
    /// because they could not be walked; names and templates were then read
    /// directly from the chunk data.
    TablesDiscarded,
    /// No usable header: a header was synthesised over an inferred window.
    Synthetic,
}

impl ChunkHeaderState {
    pub fn as_str(self) -> &'static str {
        match self {
            ChunkHeaderState::Present => "present",
            ChunkHeaderState::TablesDiscarded => "tables_discarded",
            ChunkHeaderState::Synthetic => "synthetic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChecksumState {
    Valid,
    Failed,
    /// The chunk's flags say no CRC32 was written.
    Absent,
    /// The bytes the checksum covers were not all present (a truncated chunk).
    Unverifiable,
    /// There was no header to hold one (a synthetic window).
    None,
    /// The chunk has checksums, but none of them covers the bytes this record
    /// was read from: a slack record lies past the free-space offset, and
    /// the data CRC stops there (`HUNT-165`).
    NotApplicable,
}

impl ChecksumState {
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumState::Valid => "valid",
            ChecksumState::Failed => "failed",
            ChecksumState::Absent => "absent",
            ChecksumState::Unverifiable => "unverifiable_truncated",
            ChecksumState::None => "none",
            ChecksumState::NotApplicable => "not_applicable",
        }
    }
}

/// The template a record was rendered with when its own would not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BorrowedTemplate {
    pub template_id: u32,
    pub guid: String,
    /// Hash of the rendered, name-resolved template text: the same template
    /// in two chunks hashes the same whatever its string-table offsets were.
    pub text_hash: String,
    pub from_chunk_offset: u64,
    /// How many distinct pooled renderings carried this template id; more
    /// than one means the choice between them was not certain.
    pub candidates: usize,
    /// The record's own template header was readable and its GUID equals the
    /// borrowed template's.
    pub guid_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncompleteSubstitution {
    pub index: u16,
    /// "text" or "attribute <name>".
    pub position: String,
    pub reason: String,
    /// Scalar values found inside an embedded fragment whose element names
    /// could not be resolved: the data without its structure.
    pub values_without_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredRecord {
    pub offset: u64,
    pub size: u32,
    pub chunk_offset: Option<u64>,
    pub source: RecoverySource,
    pub chunk_header: ChunkHeaderState,
    pub header_checksum: ChecksumState,
    pub data_checksum: ChecksumState,
    pub chunk_truncated: bool,
    pub trailer_valid: bool,
    pub event_record_id: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub template_id: Option<u32>,
    pub substitution_count: Option<u32>,
    pub xml: Option<String>,
    pub borrowed_template: Option<BorrowedTemplate>,
    pub incomplete: Vec<IncompleteSubstitution>,
    /// Why the record would not decode against its own window's names and
    /// templates, when it would not; the reason a template was borrowed.
    pub own_decode_failure: Option<String>,
    /// A live record with the same id left the same chunk: this is most
    /// likely an earlier write of that record, kept because that is an
    /// inference and the examiner decides it.
    pub also_read_live: bool,
    /// Why no XML at all could be produced, when `xml` is `None`.
    pub failure: Option<String>,
    /// For a slack record only: the header and data checksum states of the
    /// chunk it was found in. They are the containing chunk's, not the
    /// record's -- no checksum covers slack -- so they never travel under
    /// `header_checksum` / `data_checksum`.
    pub containing_chunk_checksums: Option<(ChecksumState, ChecksumState)>,
}

impl RecoveredRecord {
    pub fn is_partial(&self) -> bool {
        self.xml.is_none() || !self.incomplete.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RecoveryTally {
    /// What the source said it held. `bytes_scanned` is only meaningful
    /// against this: a scan that stopped short of it, with no bound hit, is a
    /// source that gave less than it declared.
    pub bytes_declared: u64,
    pub bytes_scanned: u64,
    pub scan_bound_hit: bool,
    /// The source returned fewer bytes than it declared; the bytes past the
    /// read were not scanned, and nothing can be said about them.
    pub short_read: bool,
    pub chunks_found: u64,
    pub chunks_checksum_valid: u64,
    pub chunks_checksum_failed: u64,
    pub chunks_checksum_absent: u64,
    /// Truncated chunks whose data checksum covers bytes that are not there.
    pub chunks_checksum_unverifiable: u64,
    pub chunks_truncated: u64,
    pub chunks_live_skipped: u64,
    pub chunks_nested_skipped: u64,
    pub chunks_tables_discarded: u64,
    pub chunks_unopenable: u64,
    pub chunks_bound_hit: bool,
    pub records_recovered: u64,
    pub records_partial: u64,
    pub records_header_only: u64,
    pub records_borrowed_template: u64,
    pub records_already_live: u64,
    pub records_bound_hit: bool,
    pub loose_records_found: u64,
    pub loose_windows: u64,
    pub loose_records_unlocatable: u64,
    pub templates_pooled: u64,
    pub template_pool_bound_hit: bool,
    /// The per-chunk listing stopped at its bound; `chunks_not_listed` chunks
    /// of note are counted above but not named below.
    pub chunk_listing_bound_hit: bool,
    pub chunks_not_listed: u64,
}

/// One carved chunk, named by offset, so a failed checksum or a truncation
/// is disclosed against the bytes it was found in rather than as a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChunkReport {
    pub offset: u64,
    pub header_checksum: ChecksumState,
    pub data_checksum: ChecksumState,
    pub truncated: bool,
    /// `Present` or `TablesDiscarded`: the state the chunk's own header was
    /// decoded under. A carved chunk never has a synthetic header.
    pub chunk_header: ChunkHeaderState,
    /// Too short to hold a header, or would not open even after its tables
    /// were discarded: no record could be read from it.
    pub unopenable: bool,
    /// The intact parser decoded every record below the free-space offset
    /// and emitted them live; recovery looked only at the slack.
    pub read_live_whole: bool,
    /// Records recovered from the chunk body and its slack together.
    pub records_recovered: u64,
    pub slack_records_recovered: u64,
}

impl ChunkReport {
    /// A chunk earns a line in the listing when there is something to say
    /// about it beyond the count: a checksum that did not verify, a cut,
    /// discarded tables, a failure to open, or a record recovered from it.
    /// A whole, verified chunk the intact parser read in full and that
    /// yielded nothing is counted, not listed.
    pub fn of_note(&self) -> bool {
        self.header_checksum != ChecksumState::Valid
            || self.data_checksum != ChecksumState::Valid
            || self.truncated
            || self.chunk_header != ChunkHeaderState::Present
            || self.unopenable
            || self.records_recovered > 0
    }
}

#[derive(Debug, Default)]
pub(crate) struct Recovery {
    pub records: Vec<RecoveredRecord>,
    pub tally: RecoveryTally,
    pub limits: Limits,
    /// Chunks of note in offset order, at most `limits.listed_chunks` of
    /// them; the tally says how many more there were.
    pub chunks: Vec<ChunkReport>,
}

const CHUNK_SIZE: usize = 65_536;
pub(crate) const CHUNK_HEADER_SIZE: usize = 512;
const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
const RECORD_HEADER_SIZE: usize = 24;
/// Header, trailing size copy, fragment header and template-instance token:
/// nothing shorter can be a record.
const RECORD_MIN_SIZE: usize = RECORD_HEADER_SIZE + 4 + 4 + 1;
/// The 24-byte template definition header: next offset, GUID, data size.
const TEMPLATE_DEF_HEADER_SIZE: usize = 24;
const FRAGMENT_HEADER: [u8; 4] = [0x0f, 0x01, 0x01, 0x00];
const TEMPLATE_INSTANCE_TOKEN: u8 = 0x0c;
/// Offset, within a record, of the template-instance token's fields.
const INSTANCE_TEMPLATE_ID_AT: usize = RECORD_HEADER_SIZE + 4 + 2;
const INSTANCE_DEF_OFFSET_AT: usize = INSTANCE_TEMPLATE_ID_AT + 4;
/// Where the substitution array starts when the definition is not inline.
const INSTANCE_BODY_AT: usize = INSTANCE_DEF_OFFSET_AT + 4;
/// How far into the input the gate probe looks for a chunk signature.
const PROBE_BYTES: usize = CHUNK_SIZE;
const SCAN_WINDOW: usize = 4 * 1024 * 1024;
/// Sentinels placed in a template rendering, one per possible substitution
/// index a real template uses; a template referencing an index at or above
/// this renders that index as empty and its pooled text hashes differently.
const SENTINEL_COUNT: usize = 256;
const SENTINEL_OPEN: char = '\u{E000}';
const SENTINEL_CLOSE: char = '\u{E001}';
/// Chunk header offsets.
const HDR_FREE_SPACE_OFFSET: usize = 48;
const HDR_DATA_CHECKSUM: usize = 52;
const HDR_FLAGS: usize = 120;
const HDR_HEADER_CHECKSUM: usize = 124;
const HDR_TABLES: std::ops::Range<usize> = 0x80..0x200;
const FLAG_NO_CRC32: u32 = 0x4;

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read up to `len` bytes at `offset`, looping because `read_at` may return
/// short; a source that ends early hands back what it had.
fn read_at(source: &dyn DataSource, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        match source.read_at(offset + got as u64, &mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    buf.truncate(got);
    buf
}

/// Whether the head of the input holds a chunk signature at all, so that a
/// file with no `ElfFile` header still reaches recovery when it carries
/// chunks. Bounded to the first 64 KiB: a fragment that starts mid-chunk has
/// its next signature within that distance, and a whole file with its header
/// zeroed has one at 4096.
pub(crate) fn holds_chunk_signature(source: &dyn DataSource) -> bool {
    if (source.size() as usize) < CHUNK_HEADER_SIZE + RECORD_MIN_SIZE {
        return false;
    }
    let head = read_at(source, 0, PROBE_BYTES);
    memchr::memmem::find(&head, CHUNK_MAGIC).is_some()
}

/// A Windows FILETIME as a UTC instant, or `None` when the value is outside
/// the range a real event could carry (before 1980 or after 2200), which is
/// what a garbage record header holds. Computed with checked arithmetic:
/// the upstream conversion adds a `Duration` to a `NaiveDateTime` and panics
/// on overflow, which a carved header can provoke at will.
pub(crate) fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    if !(315_532_800..=7_258_118_400).contains(&secs) {
        return None;
    }
    Utc.timestamp_opt(secs, nanos).single()
}

/// FNV-1a over the rendered template text: a stable identity for "the same
/// template" that does not depend on which Rust release built the binary.
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn guid_string(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

// ---------------------------------------------------------------------------
// Signature scanning
// ---------------------------------------------------------------------------

struct Scan {
    offsets: Vec<u64>,
    bytes_scanned: u64,
    scan_bound_hit: bool,
    count_bound_hit: bool,
    /// The source ran out before the bytes it declared.
    short_read: bool,
}

/// Every offset of `needle` in the input, up to `max_bytes` scanned and
/// `max_hits` collected. `accept` filters a hit given the bytes from it
/// onward (at least `lookahead` of them when the input has them).
fn scan_for(
    source: &dyn DataSource,
    needle: &[u8],
    max_bytes: u64,
    max_hits: usize,
    lookahead: usize,
    mut accept: impl FnMut(u64, &[u8]) -> bool,
) -> Scan {
    let total = source.size();
    let mut offsets = Vec::new();
    let mut pos = 0u64;
    let mut scan_bound_hit = false;
    let mut count_bound_hit = false;
    let mut short_read = false;
    let overlap = needle.len().max(lookahead) - 1;
    let finder = memchr::memmem::Finder::new(needle);
    'scan: while pos < total {
        if pos >= max_bytes {
            scan_bound_hit = true;
            break;
        }
        let want = SCAN_WINDOW.min((total - pos) as usize);
        let window = read_at(source, pos, want);
        if window.is_empty() {
            short_read = true;
            break;
        }
        // Hits whose lookahead would cross the window's end are re-examined
        // at the start of the next window, which begins `overlap` bytes
        // before this one ends.
        let searchable_end = if pos + window.len() as u64 >= total {
            window.len()
        } else {
            window.len().saturating_sub(overlap)
        };
        for hit in finder.find_iter(&window) {
            if hit >= searchable_end {
                break;
            }
            let abs = pos + hit as u64;
            if abs >= max_bytes {
                scan_bound_hit = true;
                break 'scan;
            }
            if !accept(abs, &window[hit..]) {
                continue;
            }
            if offsets.len() >= max_hits {
                count_bound_hit = true;
                break 'scan;
            }
            offsets.push(abs);
        }
        if window.len() < want {
            // The source gave less than it declared: what was not read was
            // not scanned. The count says how far the scan got and the flag
            // says why it stopped there.
            pos += window.len() as u64;
            short_read = true;
            break;
        }
        if pos + window.len() as u64 >= total {
            pos = total;
            break;
        }
        pos += searchable_end as u64;
    }
    Scan {
        offsets,
        bytes_scanned: pos.min(total).min(max_bytes),
        scan_bound_hit,
        count_bound_hit,
        short_read,
    }
}

// ---------------------------------------------------------------------------
// Chunk windows
// ---------------------------------------------------------------------------

/// A 64 KiB (or shorter, at the end of the input) window the decoder reads
/// records against, with a header that is either the chunk's own or one
/// synthesised because the real one is gone or points at poisoned bytes.
struct Window {
    offset: u64,
    data: Vec<u8>,
    header: ChunkHeaderState,
    header_checksum: ChecksumState,
    data_checksum: ChecksumState,
    truncated: bool,
    /// Set on a slack window: the real chunk's checksum states, which cover
    /// its header and its live region but not the slack being decoded.
    containing_chunk_checksums: Option<(ChecksumState, ChecksumState)>,
}

fn checksum_states(data: &[u8]) -> (ChecksumState, ChecksumState, bool) {
    let flags = u32_at(data, HDR_FLAGS).unwrap_or(0);
    let fso = u32_at(data, HDR_FREE_SPACE_OFFSET).unwrap_or(0) as usize;
    let truncated = data.len() < CHUNK_SIZE;
    if flags & FLAG_NO_CRC32 != 0 {
        return (ChecksumState::Absent, ChecksumState::Absent, truncated);
    }
    let header = if data.len() >= CHUNK_HEADER_SIZE {
        let mut covered = Vec::with_capacity(CHUNK_HEADER_SIZE - 8);
        covered.extend_from_slice(&data[..HDR_FLAGS]);
        covered.extend_from_slice(&data[128..CHUNK_HEADER_SIZE]);
        if evtx::checksum_ieee(&covered) == u32_at(data, HDR_HEADER_CHECKSUM).unwrap_or(0) {
            ChecksumState::Valid
        } else {
            ChecksumState::Failed
        }
    } else {
        ChecksumState::Unverifiable
    };
    let body = if fso >= CHUNK_HEADER_SIZE && fso <= data.len() {
        if evtx::checksum_ieee(&data[CHUNK_HEADER_SIZE..fso])
            == u32_at(data, HDR_DATA_CHECKSUM).unwrap_or(0)
        {
            ChecksumState::Valid
        } else {
            ChecksumState::Failed
        }
    } else if fso > data.len() && truncated {
        ChecksumState::Unverifiable
    } else {
        // A free-space offset the chunk cannot hold is a corrupt header field,
        // not a truncation.
        ChecksumState::Failed
    };
    (header, body, truncated)
}

/// Overwrite the chunk header with one that says nothing: magic, free space
/// at the end, no tables, no checksums. Every name and template is then read
/// from the data directly, and a reference into bytes that are not there
/// fails instead of resolving.
fn synthesise_header(data: &mut [u8]) {
    let len = data.len().min(CHUNK_SIZE) as u32;
    let head_len = CHUNK_HEADER_SIZE.min(data.len());
    let head = &mut data[..head_len];
    head.fill(0);
    if head.len() >= CHUNK_HEADER_SIZE {
        head[..8].copy_from_slice(CHUNK_MAGIC);
        head[40..44].copy_from_slice(&128u32.to_le_bytes());
        head[HDR_FREE_SPACE_OFFSET..HDR_FREE_SPACE_OFFSET + 4].copy_from_slice(&len.to_le_bytes());
        head[HDR_FLAGS..HDR_FLAGS + 4].copy_from_slice(&FLAG_NO_CRC32.to_le_bytes());
    }
}

/// Fill a range with 0xFF so that a name length, a template size or a token
/// read from it is refused by the decoder rather than read as a value.
fn poison(data: &mut [u8], range: std::ops::Range<usize>) {
    let end = range.end.min(data.len());
    if range.start < end {
        data[range.start..end].fill(0xff);
    }
}

/// Whether the decoder can build this window's string and template caches
/// from its header tables.
fn tables_usable(data: &[u8], settings: &std::sync::Arc<evtx::ParserSettings>) -> bool {
    if data.len() < CHUNK_HEADER_SIZE || super::chunk_tables_walkable(data).is_err() {
        return false;
    }
    let probe = data.to_vec();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evtx::EvtxChunkData::new(probe, false)
            .ok()
            .is_some_and(|mut cd| cd.parse(settings.clone()).is_ok())
    }))
    .unwrap_or(false)
}

/// Build the decoder's view of a chunk, contained against its panics. The
/// returned chunk borrows `chunk_data` for as long as it is used.
fn parse_chunk<'a>(
    chunk_data: &'a mut evtx::EvtxChunkData,
    settings: &std::sync::Arc<evtx::ParserSettings>,
) -> std::thread::Result<Option<evtx::EvtxChunk<'a>>> {
    let settings = settings.clone();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        evtx::EvtxChunkData::parse(chunk_data, settings).ok()
    }))
}

// ---------------------------------------------------------------------------
// Records inside a window
// ---------------------------------------------------------------------------

/// The header facts of one record as found, before any decoding.
#[derive(Debug, Clone, Copy)]
struct RecordHead {
    pos: usize,
    size: usize,
    /// The record's declared size reaches past the window.
    cut: bool,
    trailer_valid: bool,
    record_id: u64,
    filetime: u64,
}

fn record_head(data: &[u8], pos: usize) -> Option<RecordHead> {
    if data.get(pos..pos + 4)? != RECORD_MAGIC {
        return None;
    }
    let size = u32_at(data, pos + 4)? as usize;
    if !(RECORD_MIN_SIZE..=CHUNK_SIZE - CHUNK_HEADER_SIZE).contains(&size) {
        return None;
    }
    let record_id = u64_at(data, pos + 8)?;
    let filetime = u64_at(data, pos + 16)?;
    let cut = pos + size > data.len();
    let trailer_valid = !cut && u32_at(data, pos + size - 4) == Some(size as u32);
    Some(RecordHead {
        pos,
        size,
        cut,
        trailer_valid,
        record_id,
        filetime,
    })
}

/// A record that starts with the fragment header and template-instance token
/// every real event record starts with; the test that separates a record from
/// four bytes that happen to read `**\0\0`.
fn looks_like_event_record(data: &[u8], pos: usize) -> bool {
    data.get(pos + RECORD_HEADER_SIZE..pos + RECORD_HEADER_SIZE + 5)
        .is_some_and(|b| b[..4] == FRAGMENT_HEADER && b[4] == TEMPLATE_INSTANCE_TOKEN)
}

/// Walk every record head in `data[from..to)`, resynchronising on the record
/// magic after a record whose size does not lead to the next one.
fn record_heads(data: &[u8], from: usize, to: usize) -> Vec<RecordHead> {
    let to = to.min(data.len());
    let mut heads = Vec::new();
    let mut pos = from;
    while pos + RECORD_HEADER_SIZE <= to {
        match record_head(data, pos) {
            Some(head) if looks_like_event_record(data, pos) => {
                heads.push(head);
                if head.cut {
                    break;
                }
                pos += head.size;
            }
            _ => match memchr::memmem::find(&data[pos + 1..to], RECORD_MAGIC) {
                Some(i) => pos += 1 + i,
                None => break,
            },
        }
    }
    heads
}

/// The template-instance facts at the head of a record's binary XML.
#[derive(Debug, Clone, Copy)]
struct Instance {
    template_id: u32,
    def_offset: usize,
    inline: bool,
}

fn instance_at(data: &[u8], pos: usize) -> Option<Instance> {
    if !looks_like_event_record(data, pos) {
        return None;
    }
    let template_id = u32_at(data, pos + INSTANCE_TEMPLATE_ID_AT)?;
    let def_offset = u32_at(data, pos + INSTANCE_DEF_OFFSET_AT)? as usize;
    Some(Instance {
        template_id,
        def_offset,
        inline: def_offset == pos + INSTANCE_BODY_AT,
    })
}

/// Where a record's substitution array begins: after the inline template
/// definition when the record carries one, else right after the instance
/// token.
fn substitution_array_start(
    data: &[u8],
    head: &RecordHead,
    instance: &Instance,
) -> Result<usize, String> {
    let record_end = (head.pos + head.size).min(data.len());
    let subs_start = if instance.inline {
        let size = u32_at(data, instance.def_offset + 20)
            .ok_or("the inline template definition's size field is beyond the window")?
            as usize;
        instance.def_offset + TEMPLATE_DEF_HEADER_SIZE + size
    } else {
        head.pos + INSTANCE_BODY_AT
    };
    if subs_start + 4 > record_end {
        return Err(format!(
            "the substitution array would start at {subs_start}, past the record's end at \
             {record_end}"
        ));
    }
    Ok(subs_start)
}

/// Whether `data[at..]` reads as a template definition header followed by a
/// fragment header: the check that confirms an inferred chunk window.
fn plausible_template_definition(data: &[u8], at: usize) -> bool {
    let Some(size) = u32_at(data, at + 20) else {
        return false;
    };
    (size as usize) < CHUNK_SIZE
        && data
            .get(at + TEMPLATE_DEF_HEADER_SIZE..at + TEMPLATE_DEF_HEADER_SIZE + 4)
            .is_some_and(|b| b == FRAGMENT_HEADER)
}

// ---------------------------------------------------------------------------
// The template pool
// ---------------------------------------------------------------------------

/// One piece of a pooled template's rendered text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    Text(String),
    /// A substitution in text position.
    Sub(u16),
    /// A substitution that is the whole value of an attribute; an empty or
    /// unbound value omits the attribute, as the intact renderer does.
    AttrSub {
        name: String,
        index: u16,
    },
}

/// Split a sentinel-rendered template into text and substitution slots.
pub(crate) fn split_sentinels(rendered: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut text = String::new();
    let mut rest = rendered;
    while let Some(open) = rest.find(SENTINEL_OPEN) {
        let before = &rest[..open];
        let after = &rest[open + SENTINEL_OPEN.len_utf8()..];
        let Some(close) = after.find(SENTINEL_CLOSE) else {
            break;
        };
        let Ok(index) = after[..close].parse::<u16>() else {
            text.push_str(before);
            text.push(SENTINEL_OPEN);
            rest = after;
            continue;
        };
        let tail = &after[close + SENTINEL_CLOSE.len_utf8()..];
        // ` Name="<sentinel>"`: the sentinel is the whole attribute value.
        let attribute = before.strip_suffix("=\"").and_then(|head| {
            let name_start = head
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':' || c == '-'))
                .map(|i| i + 1)
                .unwrap_or(0);
            let name = &head[name_start..];
            let preceded_by_space = head[..name_start].ends_with(' ');
            (!name.is_empty() && preceded_by_space && tail.starts_with('"'))
                .then(|| (head[..name_start - 1].to_string(), name.to_string()))
        });
        match attribute {
            Some((head, name)) => {
                text.push_str(&head);
                if !text.is_empty() {
                    segments.push(Segment::Text(std::mem::take(&mut text)));
                }
                segments.push(Segment::AttrSub { name, index });
                rest = &tail[1..];
            }
            None => {
                text.push_str(before);
                if !text.is_empty() {
                    segments.push(Segment::Text(std::mem::take(&mut text)));
                }
                segments.push(Segment::Sub(index));
                rest = tail;
            }
        }
    }
    text.push_str(rest);
    if !text.is_empty() {
        segments.push(Segment::Text(text));
    }
    segments
}

pub(crate) fn max_substitution_index(segments: &[Segment]) -> Option<u16> {
    segments
        .iter()
        .filter_map(|s| match s {
            Segment::Sub(i) | Segment::AttrSub { index: i, .. } => Some(*i),
            Segment::Text(_) => None,
        })
        .max()
}

#[derive(Debug, Clone)]
struct PooledTemplate {
    template_id: u32,
    guid: [u8; 16],
    text_hash: u64,
    segments: Vec<Segment>,
    max_index: Option<u16>,
    from_chunk_offset: u64,
}

#[derive(Default)]
struct TemplatePool {
    by_id: HashMap<u32, Vec<PooledTemplate>>,
    len: usize,
    bound_hit: bool,
}

impl TemplatePool {
    fn insert(&mut self, template: PooledTemplate, limit: usize) {
        let entry = self.by_id.entry(template.template_id).or_default();
        if entry.iter().any(|t| t.text_hash == template.text_hash) {
            return;
        }
        if self.len >= limit {
            self.bound_hit = true;
            return;
        }
        entry.push(template);
        self.len += 1;
    }

    /// The pooled renderings of `template_id` a record with
    /// `substitution_count` values could be rendered with.
    fn candidates(&self, template_id: u32, substitution_count: u32) -> Vec<&PooledTemplate> {
        self.by_id
            .get(&template_id)
            .map(|v| {
                v.iter()
                    .filter(|t| {
                        t.max_index
                            .is_none_or(|m| u32::from(m) < substitution_count)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Render the template defined at `def_offset` with a sentinel in every
/// substitution slot, through the same renderer live records go through.
fn render_template_with_sentinels(
    chunk: &evtx::EvtxChunk<'_>,
    def_offset: usize,
) -> Result<String, String> {
    let sentinels: Vec<evtx::model::deserialized::BinXMLDeserializedTokens<'_>> = (0
        ..SENTINEL_COUNT)
        .map(|i| {
            evtx::model::deserialized::BinXMLDeserializedTokens::Value(
                evtx::binxml::value_variant::BinXmlValue::StringType(format!(
                    "{SENTINEL_OPEN}{i}{SENTINEL_CLOSE}"
                )),
            )
        })
        .collect();
    let tokens = vec![
        evtx::model::deserialized::BinXMLDeserializedTokens::TemplateInstance(
            evtx::model::deserialized::BinXmlTemplateRef {
                template_def_offset: def_offset as u32,
                substitution_array: sentinels,
            },
        ),
    ];
    render_tokens(chunk, tokens)
}

/// Render a token tree to XML through the upstream renderer, contained
/// against its panics.
fn render_tokens<'a>(
    chunk: &'a evtx::EvtxChunk<'a>,
    tokens: Vec<evtx::model::deserialized::BinXMLDeserializedTokens<'a>>,
) -> Result<String, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let record = evtx::EvtxRecord {
            chunk,
            event_record_id: 0,
            timestamp: Utc.timestamp_opt(0, 0).single().unwrap_or_default(),
            tokens,
            settings: chunk.settings.clone(),
        };
        record
            .into_xml()
            .map(|r| r.data)
            .map_err(|e| format!("render: {}", error_chain(&e)))
    }))
    .unwrap_or_else(|_| Err("the renderer panicked on this token tree".to_string()))
}

/// An error and every cause beneath it, because the upstream decoder's
/// top-level message ("Failed to parse record number N") names the record
/// and not the fault.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(" <- ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn strip_xml_declaration(xml: &str) -> &str {
    let rest = xml.trim_start();
    match rest.strip_prefix("<?xml") {
        Some(after) => match after.find("?>") {
            Some(i) => after[i + 2..].trim_start_matches(['\r', '\n']),
            None => xml,
        },
        None => xml,
    }
}

// ---------------------------------------------------------------------------
// Decoding one record
// ---------------------------------------------------------------------------

/// A record decoded exactly as the intact parser would decode it, against
/// the window's own names and templates.
fn decode_record<'a>(chunk: &'a evtx::EvtxChunk<'a>, head: &RecordHead) -> Result<String, String> {
    let data_size = (head.size - RECORD_HEADER_SIZE - 4) as u32;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deserializer = evtx::binxml::deserializer::BinXmlDeserializer::init(
            chunk.data,
            (head.pos + RECORD_HEADER_SIZE) as u64,
            Some(chunk),
            false,
            chunk.settings.get_ansi_codec(),
        );
        let tokens = deserializer
            .iter_tokens(Some(data_size))
            .map_err(|e| format!("token stream: {}", error_chain(&e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("token: {}", error_chain(&e)))?;
        let record = evtx::EvtxRecord {
            chunk,
            event_record_id: head.record_id,
            timestamp: filetime_to_datetime(head.filetime).unwrap_or_default(),
            tokens,
            settings: chunk.settings.clone(),
        };
        record
            .into_xml()
            .map(|r| r.data)
            .map_err(|e| format!("render: {}", error_chain(&e)))
    }))
    .unwrap_or_else(|_| Err("the decoder panicked on this record".to_string()))
}

/// One decoded substitution value, or why it could not be decoded.
enum Bound<'a> {
    Value(evtx::binxml::value_variant::BinXmlValue<'a>),
    Failed(String),
}

struct PoolRender {
    xml: String,
    borrowed: BorrowedTemplate,
    incomplete: Vec<IncompleteSubstitution>,
}

/// Render a record whose own template will not read, with a template from
/// the pool and the record's own substitution array, bound value by value.
fn render_with_pool<'a>(
    chunk: &'a evtx::EvtxChunk<'a>,
    head: &RecordHead,
    instance: &Instance,
    pool: &TemplatePool,
) -> Result<PoolRender, String> {
    let data = chunk.data;
    let record_end = (head.pos + head.size).min(data.len());
    let subs_start = substitution_array_start(data, head, instance)?;
    let count = u32_at(data, subs_start).unwrap_or(0);
    let descriptors_end = (count as usize)
        .checked_mul(4)
        .and_then(|n| n.checked_add(subs_start + 4))
        .filter(|end| *end <= record_end)
        .ok_or_else(|| {
            format!(
                "the record declares {count} substitutions, more than its {} remaining bytes \
                 can describe",
                record_end - subs_start
            )
        })?;
    let candidates = pool.candidates(instance.template_id, count);
    let Some(template) = candidates
        .iter()
        .max_by_key(|t| t.max_index.unwrap_or(0))
        .copied()
    else {
        return Err(format!(
            "template {:#010x} (with {count} substitutions) is not in the pool, which holds {} \
             template(s)",
            instance.template_id, pool.len
        ));
    };
    let guid_confirmed = data
        .get(instance.def_offset + 4..instance.def_offset + 20)
        .is_some_and(|g| g == template.guid);

    // Each value is positioned from the descriptor table, so a value that
    // will not decode costs itself and nothing after it.
    let mut values: Vec<Bound<'a>> = Vec::with_capacity(count as usize);
    let mut value_at = descriptors_end;
    for i in 0..count as usize {
        let size = u16::from_le_bytes([data[subs_start + 4 + i * 4], data[subs_start + 5 + i * 4]]);
        let type_byte = data[subs_start + 6 + i * 4];
        let start = value_at;
        value_at += size as usize;
        if value_at > record_end {
            values.push(Bound::Failed(format!(
                "the record's data ends at {record_end}, before this substitution's {size} \
                 byte(s) at {start}"
            )));
            continue;
        }
        let Some(value_type) = evtx::binxml::value_variant::BinXmlValueType::from_u8(type_byte)
        else {
            values.push(Bound::Failed(format!(
                "unknown value type {type_byte:#04x}"
            )));
            continue;
        };
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cursor = std::io::Cursor::new(data);
            cursor.set_position(start as u64);
            evtx::binxml::value_variant::BinXmlValue::deserialize_value_type(
                &value_type,
                &mut cursor,
                Some(chunk),
                Some(size),
                chunk.settings.get_ansi_codec(),
            )
            .map_err(|e| error_chain(&e))
        }))
        .unwrap_or_else(|_| Err("the value decoder panicked".to_string()));
        values.push(match decoded {
            Ok(v) => Bound::Value(v),
            Err(e) => Bound::Failed(e),
        });
    }

    let mut xml = String::new();
    let mut incomplete = Vec::new();
    for segment in &template.segments {
        match segment {
            Segment::Text(t) => xml.push_str(t),
            Segment::Sub(i) => match render_value(chunk, &values, *i) {
                Ok(text) => xml.push_str(&text),
                Err(mut why) => {
                    xml.push_str(&format!(
                        "<SeanceIncomplete substitution=\"{i}\" reason=\"{}\"/>",
                        escape_attribute(&why.reason)
                    ));
                    why.position = "text".to_string();
                    incomplete.push(why);
                }
            },
            Segment::AttrSub { name, index } => match render_value(chunk, &values, *index) {
                Ok(text) if text.is_empty() => {}
                Ok(text) => xml.push_str(&format!(" {name}=\"{}\"", text.replace('"', "&quot;"))),
                Err(mut why) => {
                    why.position = format!("attribute {name}");
                    incomplete.push(why);
                }
            },
        }
    }
    Ok(PoolRender {
        xml,
        borrowed: BorrowedTemplate {
            template_id: template.template_id,
            guid: guid_string(&template.guid),
            text_hash: format!("{:016x}", template.text_hash),
            from_chunk_offset: template.from_chunk_offset,
            candidates: candidates.len(),
            guid_confirmed,
        },
        incomplete,
    })
}

/// The text a substitution value renders as: escaped scalar text, or an
/// embedded fragment rendered through the upstream renderer.
fn render_value<'a>(
    chunk: &'a evtx::EvtxChunk<'a>,
    values: &[Bound<'a>],
    index: u16,
) -> Result<String, IncompleteSubstitution> {
    use evtx::binxml::value_variant::BinXmlValue;
    let fail = |reason: String, values_without_names: Vec<String>| IncompleteSubstitution {
        index,
        position: String::new(),
        reason,
        values_without_names,
    };
    let Some(bound) = values.get(index as usize) else {
        return Err(fail(
            format!(
                "the template needs substitution {index} but the record holds only {}",
                values.len()
            ),
            Vec::new(),
        ));
    };
    match bound {
        Bound::Failed(why) => Err(fail(why.clone(), Vec::new())),
        Bound::Value(BinXmlValue::NullType) => Ok(String::new()),
        Bound::Value(BinXmlValue::BinXmlType(tokens)) => {
            match render_tokens(chunk, tokens.clone()) {
                Ok(xml) => Ok(strip_xml_declaration(&xml).to_string()),
                Err(why) => Err(fail(
                    format!(
                        "the embedded fragment could not be rendered against this window: {why}"
                    ),
                    scalar_values_in(tokens),
                )),
            }
        }
        Bound::Value(BinXmlValue::EvtXml) | Bound::Value(BinXmlValue::EvtHandle) => Err(fail(
            "a value type the renderer does not support".to_string(),
            Vec::new(),
        )),
        Bound::Value(v) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            escape_text(&v.as_cow_str())
        }))
        .map_err(|_| fail("the value would not format as text".to_string(), Vec::new())),
    }
}

/// The scalar values inside a token tree, in order: what an embedded
/// fragment still yields when its element names cannot be resolved.
fn scalar_values_in(
    tokens: &[evtx::model::deserialized::BinXMLDeserializedTokens<'_>],
) -> Vec<String> {
    use evtx::binxml::value_variant::BinXmlValue;
    use evtx::model::deserialized::BinXMLDeserializedTokens as T;
    let mut out = Vec::new();
    for token in tokens {
        match token {
            T::Value(BinXmlValue::BinXmlType(inner)) => out.extend(scalar_values_in(inner)),
            T::Value(BinXmlValue::NullType)
            | T::Value(BinXmlValue::EvtXml)
            | T::Value(BinXmlValue::EvtHandle) => {}
            T::Value(v) => {
                if let Ok(text) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    v.as_cow_str().to_string()
                })) {
                    out.push(text);
                }
            }
            T::TemplateInstance(t) => out.extend(scalar_values_in(&t.substitution_array)),
            _ => {}
        }
    }
    out
}

fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_attribute(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The recovery itself
// ---------------------------------------------------------------------------

/// Which records a walk leaves out, and how they are counted.
#[derive(Clone, Copy)]
enum Skip<'a> {
    Nothing,
    /// Records with these ids left live already; each one met is counted
    /// under `records_already_live`.
    Live(&'a HashSet<u64>),
    /// The chunk was decoded whole and live: nothing is decoded here (the
    /// walk only pools its templates), and nothing is counted.
    Whole,
    /// Records are decoded, but one whose id is in the set is flagged as a
    /// duplicate of a live record rather than skipped.
    Flag(Option<&'a HashSet<u64>>),
}

/// A record the primary decode refused, held until the pool is complete.
struct Deferred {
    window: usize,
    head: RecordHead,
    source: RecoverySource,
    also_live: bool,
    why: String,
}

struct Run<'l> {
    live: &'l LiveCoverage,
    limits: Limits,
    settings: std::sync::Arc<evtx::ParserSettings>,
    pool: TemplatePool,
    windows: Vec<Window>,
    deferred: Vec<Deferred>,
    records: Vec<RecoveredRecord>,
    tally: RecoveryTally,
    /// Indices into `windows` of chunks that would not open for a walk.
    unopenable_windows: HashSet<usize>,
}

impl Run<'_> {
    fn record_bound_reached(&mut self) -> bool {
        if self.records.len() >= self.limits.records {
            self.tally.records_bound_hit = true;
            return true;
        }
        false
    }

    fn push(&mut self, record: RecoveredRecord) {
        if record.borrowed_template.is_some() {
            self.tally.records_borrowed_template += 1;
        }
        if record.is_partial() {
            self.tally.records_partial += 1;
            if record.xml.is_none() {
                self.tally.records_header_only += 1;
            }
        } else {
            self.tally.records_recovered += 1;
        }
        self.records.push(record);
    }

    /// Open a window's chunk for decoding; `None` when even a synthesised
    /// header will not open it.
    fn open(&mut self, window_index: usize) -> Option<evtx::EvtxChunkData> {
        let window = &mut self.windows[window_index];
        if window.data.len() < CHUNK_HEADER_SIZE {
            return None;
        }
        if window.header != ChunkHeaderState::Synthetic
            && !tables_usable(&window.data, &self.settings)
        {
            window.data[HDR_TABLES].fill(0);
            window.header = ChunkHeaderState::TablesDiscarded;
            self.tally.chunks_tables_discarded += 1;
        }
        let data = window.data.clone();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evtx::EvtxChunkData::new(data, false).ok()
        }))
        .ok()
        .flatten()
    }

    /// Decode every record in `heads` against the window, pooling inline
    /// template definitions and deferring what will not decode.
    fn walk(
        &mut self,
        window_index: usize,
        heads: &[RecordHead],
        source: RecoverySource,
        skip: Skip<'_>,
    ) {
        let Some(mut chunk_data) = self.open(window_index) else {
            self.tally.chunks_unopenable += 1;
            self.unopenable_windows.insert(window_index);
            return;
        };
        let parsed = parse_chunk(&mut chunk_data, &self.settings);
        let Ok(Some(chunk)) = parsed else {
            self.tally.chunks_unopenable += 1;
            self.unopenable_windows.insert(window_index);
            return;
        };
        let window_offset = self.windows[window_index].offset;
        let mut pooled = Vec::new();
        let mut decoded = Vec::new();
        for head in heads {
            if let Some(instance) = instance_at(chunk.data, head.pos) {
                if instance.inline {
                    if let Ok(rendered) =
                        render_template_with_sentinels(&chunk, instance.def_offset)
                    {
                        let segments = split_sentinels(&rendered);
                        let normalised: String = rendered
                            .chars()
                            .map(|c| {
                                if c == SENTINEL_OPEN {
                                    '{'
                                } else if c == SENTINEL_CLOSE {
                                    '}'
                                } else {
                                    c
                                }
                            })
                            .collect();
                        let mut guid = [0u8; 16];
                        if let Some(g) = chunk
                            .data
                            .get(instance.def_offset + 4..instance.def_offset + 20)
                        {
                            guid.copy_from_slice(g);
                        }
                        pooled.push(PooledTemplate {
                            template_id: instance.template_id,
                            guid,
                            text_hash: fnv1a(&normalised),
                            max_index: max_substitution_index(&segments),
                            segments,
                            from_chunk_offset: window_offset,
                        });
                    }
                }
            }
            let also_live = match skip {
                Skip::Nothing => false,
                Skip::Whole => continue,
                Skip::Live(ids) => {
                    if ids.contains(&head.record_id) {
                        self.tally.records_already_live += 1;
                        continue;
                    }
                    false
                }
                Skip::Flag(ids) => ids.is_some_and(|ids| ids.contains(&head.record_id)),
            };
            decoded.push((*head, also_live, decode_record(&chunk, head)));
        }
        drop(chunk);
        for template in pooled {
            self.pool.insert(template, self.limits.pooled_templates);
        }
        for (head, also_live, result) in decoded {
            match result {
                Ok(xml) => {
                    if self.record_bound_reached() {
                        return;
                    }
                    let mut record = self.record_from(
                        window_index,
                        &head,
                        source,
                        Some(xml),
                        None,
                        Vec::new(),
                        None,
                    );
                    record.also_read_live = also_live;
                    self.push(record);
                }
                Err(why) => self.deferred.push(Deferred {
                    window: window_index,
                    head,
                    source,
                    also_live,
                    why,
                }),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_from(
        &self,
        window_index: usize,
        head: &RecordHead,
        source: RecoverySource,
        xml: Option<String>,
        borrowed: Option<BorrowedTemplate>,
        incomplete: Vec<IncompleteSubstitution>,
        failure: Option<String>,
    ) -> RecoveredRecord {
        let window = &self.windows[window_index];
        let instance = instance_at(&window.data, head.pos);
        let substitution_count = instance
            .and_then(|i| substitution_array_start(&window.data, head, &i).ok())
            .and_then(|at| u32_at(&window.data, at));
        RecoveredRecord {
            offset: window.offset + head.pos as u64,
            size: head.size as u32,
            chunk_offset: Some(window.offset),
            source,
            chunk_header: window.header,
            header_checksum: window.header_checksum,
            data_checksum: window.data_checksum,
            containing_chunk_checksums: window.containing_chunk_checksums,
            chunk_truncated: window.truncated,
            trailer_valid: head.trailer_valid,
            event_record_id: head.record_id,
            timestamp: filetime_to_datetime(head.filetime),
            template_id: instance.map(|i| i.template_id),
            substitution_count,
            xml,
            borrowed_template: borrowed,
            incomplete,
            own_decode_failure: None,
            also_read_live: false,
            failure,
        }
    }

    /// Render every deferred record from the pool, now that every window has
    /// contributed its templates.
    fn render_deferred(&mut self) {
        let deferred = std::mem::take(&mut self.deferred);
        let mut by_window: HashMap<usize, Vec<Deferred>> = HashMap::new();
        for d in deferred {
            by_window.entry(d.window).or_default().push(d);
        }
        let mut order: Vec<usize> = by_window.keys().copied().collect();
        order.sort_unstable();
        for window_index in order {
            let items = by_window.remove(&window_index).unwrap_or_default();
            let Some(mut chunk_data) = self.open(window_index) else {
                for d in items {
                    if self.record_bound_reached() {
                        return;
                    }
                    let mut record = self.record_from(
                        window_index,
                        &d.head,
                        d.source,
                        None,
                        None,
                        Vec::new(),
                        Some(d.why),
                    );
                    record.also_read_live = d.also_live;
                    self.push(record);
                }
                continue;
            };
            let mut results = Vec::new();
            {
                let parsed = parse_chunk(&mut chunk_data, &self.settings);
                let chunk = match parsed {
                    Ok(Some(c)) => Some(c),
                    _ => None,
                };
                for d in items {
                    let instance = chunk.as_ref().and_then(|c| instance_at(c.data, d.head.pos));
                    let rendered = match (&chunk, instance) {
                        (Some(chunk), Some(instance)) => {
                            render_with_pool(chunk, &d.head, &instance, &self.pool)
                        }
                        (None, _) => Err("the window would not open for decoding".to_string()),
                        (_, None) => Err(
                            "no template-instance token at the start of the record's binary XML"
                                .to_string(),
                        ),
                    };
                    results.push((d, rendered));
                }
            }
            for (d, rendered) in results {
                if self.record_bound_reached() {
                    return;
                }
                let mut record = match rendered {
                    Ok(render) => {
                        let mut r = self.record_from(
                            window_index,
                            &d.head,
                            d.source,
                            Some(render.xml),
                            Some(render.borrowed),
                            render.incomplete,
                            None,
                        );
                        r.own_decode_failure = Some(d.why);
                        r
                    }
                    Err(pool_why) => self.record_from(
                        window_index,
                        &d.head,
                        d.source,
                        None,
                        None,
                        Vec::new(),
                        Some(format!(
                            "its own template would not read ({}), and it could not be rendered \
                             from the pool ({pool_why})",
                            d.why
                        )),
                    ),
                };
                record.also_read_live = d.also_live;
                self.push(record);
            }
        }
    }
}

pub(crate) fn recover(source: &dyn DataSource, live: &LiveCoverage) -> Recovery {
    recover_with_limits(source, live, Limits::default())
}

pub(crate) fn recover_with_limits(
    source: &dyn DataSource,
    live: &LiveCoverage,
    limits: Limits,
) -> Recovery {
    let mut run = Run {
        live,
        limits,
        settings: std::sync::Arc::new(evtx::ParserSettings::default()),
        pool: TemplatePool::default(),
        windows: Vec::new(),
        deferred: Vec::new(),
        records: Vec::new(),
        tally: RecoveryTally::default(),
        unopenable_windows: HashSet::new(),
    };

    // 1. Carve chunks by signature.
    let scan = scan_for(
        source,
        CHUNK_MAGIC,
        limits.scan_bytes,
        limits.chunks,
        8,
        |_, _| true,
    );
    run.tally.bytes_declared = source.size();
    run.tally.bytes_scanned = scan.bytes_scanned;
    run.tally.scan_bound_hit = scan.scan_bound_hit;
    run.tally.short_read = scan.short_read;
    run.tally.chunks_bound_hit = scan.count_bound_hit;

    // Spans of the input that belong to a carved chunk, so loose-record
    // scanning stays outside them.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let mut last_valid_end = 0u64;
    // Every chunk found, with the window it was decoded against, so the
    // listing can be filled in once the walk has run.
    let mut reports: Vec<(ChunkReport, Option<usize>)> = Vec::new();
    for offset in scan.offsets {
        if offset < last_valid_end {
            run.tally.chunks_nested_skipped += 1;
            continue;
        }
        let data = read_at(source, offset, CHUNK_SIZE);
        if data.len() < CHUNK_HEADER_SIZE {
            run.tally.chunks_found += 1;
            run.tally.chunks_unopenable += 1;
            reports.push((
                ChunkReport {
                    offset,
                    header_checksum: ChecksumState::Unverifiable,
                    data_checksum: ChecksumState::Unverifiable,
                    truncated: true,
                    chunk_header: ChunkHeaderState::Present,
                    unopenable: true,
                    read_live_whole: false,
                    records_recovered: 0,
                    slack_records_recovered: 0,
                },
                None,
            ));
            continue;
        }
        run.tally.chunks_found += 1;
        let (header_checksum, data_checksum, truncated) = checksum_states(&data);
        // One chunk, one verdict: a chunk counts as checksum-valid only when
        // both its header and its data verified.
        match (header_checksum, data_checksum) {
            (ChecksumState::Absent, _) => run.tally.chunks_checksum_absent += 1,
            (ChecksumState::Failed, _) | (_, ChecksumState::Failed) => {
                run.tally.chunks_checksum_failed += 1
            }
            (ChecksumState::Unverifiable, _) | (_, ChecksumState::Unverifiable) => {
                run.tally.chunks_checksum_unverifiable += 1
            }
            (ChecksumState::Valid, ChecksumState::Valid) => run.tally.chunks_checksum_valid += 1,
            _ => {}
        }
        if truncated {
            run.tally.chunks_truncated += 1;
        }
        if header_checksum == ChecksumState::Valid {
            last_valid_end = offset + data.len() as u64;
        }
        spans.push((offset, offset + data.len() as u64));
        let fso = u32_at(&data, HDR_FREE_SPACE_OFFSET).unwrap_or(0) as usize;
        let free_space_offset = if (CHUNK_HEADER_SIZE..=data.len()).contains(&fso) {
            fso
        } else {
            data.len()
        };
        let window_index = run.windows.len();
        run.windows.push(Window {
            offset,
            data,
            header: ChunkHeaderState::Present,
            header_checksum,
            data_checksum,
            truncated,
            containing_chunk_checksums: None,
        });

        let live_chunk = run.live.chunks.get(&offset);
        reports.push((
            ChunkReport {
                offset,
                header_checksum,
                data_checksum,
                truncated,
                chunk_header: ChunkHeaderState::Present,
                unopenable: false,
                read_live_whole: live_chunk.is_some_and(|l| l.fully_decoded),
                records_recovered: 0,
                slack_records_recovered: 0,
            },
            Some(window_index),
        ));
        let heads = record_heads(
            &run.windows[window_index].data,
            CHUNK_HEADER_SIZE,
            free_space_offset,
        );
        match live_chunk {
            Some(l) if l.fully_decoded => {
                run.tally.chunks_live_skipped += 1;
                // Still pool the live chunk's templates: they are what revive
                // an orphan elsewhere in the file.
                run.walk(
                    window_index,
                    &heads,
                    RecoverySource::CarvedChunk,
                    Skip::Whole,
                );
            }
            Some(l) => {
                run.walk(
                    window_index,
                    &heads,
                    RecoverySource::CarvedChunk,
                    Skip::Live(&l.record_ids),
                );
            }
            None => run.walk(
                window_index,
                &heads,
                RecoverySource::CarvedChunk,
                Skip::Nothing,
            ),
        }
        if run.tally.records_bound_hit {
            break;
        }

        // Slack: records from an earlier use of the chunk. Decoded against a
        // window whose live region is poisoned, so a reference into rewritten
        // bytes fails rather than reads.
        let slack_heads = {
            let data = &run.windows[window_index].data;
            if free_space_offset >= data.len() {
                Vec::new()
            } else {
                record_heads(data, free_space_offset, data.len())
            }
        };
        if !slack_heads.is_empty() {
            let mut slack = run.windows[window_index].data.clone();
            poison(&mut slack, CHUNK_HEADER_SIZE..free_space_offset);
            synthesise_header(&mut slack);
            let slack_index = run.windows.len();
            // The chunk's CRCs cover its header and bytes 512..free-space
            // offset. The slack record is read from past that offset under a
            // synthesised header, so neither checksum says anything about it:
            // publishing the live chunk's `valid` here would claim a
            // verification no checksum made (`HUNT-165`). The real states
            // travel beside it, named as the containing chunk's.
            run.windows.push(Window {
                offset,
                data: slack,
                header: ChunkHeaderState::Synthetic,
                header_checksum: ChecksumState::NotApplicable,
                data_checksum: ChecksumState::NotApplicable,
                truncated,
                containing_chunk_checksums: Some((header_checksum, data_checksum)),
            });
            run.walk(
                slack_index,
                &slack_heads,
                RecoverySource::ChunkSlack,
                Skip::Flag(live_chunk.map(|l| &l.record_ids)),
            );
            if run.tally.records_bound_hit {
                break;
            }
        }
    }

    // 2. Loose records outside every carved chunk.
    if !run.tally.records_bound_hit {
        recover_loose(source, &mut run, &spans);
    }

    // 3. Everything that would not decode against its own window, from the
    // pool.
    run.render_deferred();

    run.tally.templates_pooled = run.pool.len as u64;
    run.tally.template_pool_bound_hit = run.pool.bound_hit;
    run.records.sort_by_key(|r| r.offset);

    // 4. The per-chunk listing: what the walk learned about each chunk, and
    // how many records left it.
    // (chunk offset) -> (records from its body and slack, of which slack).
    let mut per_chunk: HashMap<u64, (u64, u64)> = HashMap::new();
    for record in &run.records {
        let Some(chunk_offset) = record.chunk_offset else {
            continue;
        };
        let counts = per_chunk.entry(chunk_offset).or_default();
        match record.source {
            RecoverySource::CarvedChunk => counts.0 += 1,
            RecoverySource::ChunkSlack => {
                counts.0 += 1;
                counts.1 += 1;
            }
            RecoverySource::LooseRecord => {}
        }
    }
    let mut chunks: Vec<ChunkReport> = Vec::with_capacity(reports.len().min(limits.listed_chunks));
    for (mut report, window_index) in reports {
        if let Some(i) = window_index {
            report.chunk_header = run.windows[i].header;
            report.unopenable |= run.unopenable_windows.contains(&i);
        }
        if let Some((all, slack)) = per_chunk.get(&report.offset) {
            report.records_recovered = *all;
            report.slack_records_recovered = *slack;
        }
        if !report.of_note() {
            continue;
        }
        if chunks.len() >= limits.listed_chunks {
            run.tally.chunk_listing_bound_hit = true;
            run.tally.chunks_not_listed += 1;
            continue;
        }
        chunks.push(report);
    }
    chunks.sort_by_key(|c| c.offset);

    Recovery {
        records: run.records,
        tally: run.tally,
        limits,
        chunks,
    }
}

/// Find records outside every carved chunk, infer the 64 KiB window each
/// belongs to, and decode each window under a synthesised header.
fn recover_loose(source: &dyn DataSource, run: &mut Run<'_>, spans: &[(u64, u64)]) {
    let total = source.size();
    let in_span = |at: u64| spans.iter().any(|(s, e)| at >= *s && at < *e);
    let scan = scan_for(
        source,
        RECORD_MAGIC,
        run.limits.scan_bytes,
        run.limits.records,
        INSTANCE_BODY_AT,
        |abs, bytes| {
            if in_span(abs) {
                return false;
            }
            record_head(bytes, 0).is_some_and(|h| filetime_to_datetime(h.filetime).is_some())
                && looks_like_event_record(bytes, 0)
        },
    );
    run.tally.scan_bound_hit |= scan.scan_bound_hit;
    run.tally.short_read |= scan.short_read;
    if scan.count_bound_hit {
        run.tally.records_bound_hit = true;
    }
    if scan.offsets.is_empty() {
        return;
    }

    // The chunk grid the carved chunks lie on, when they agree on one.
    let phases: HashSet<u64> = spans.iter().map(|(s, _)| s % CHUNK_SIZE as u64).collect();
    let grid_phase = (phases.len() == 1).then(|| *phases.iter().next().unwrap_or(&0));

    // Group hits by the window they resolve to.
    let mut windows: std::collections::BTreeMap<u64, Vec<u64>> = std::collections::BTreeMap::new();
    let mut covered_until = 0u64;
    for hit in scan.offsets {
        if hit < covered_until {
            // Inside a window already claimed: its walk finds this record.
            continue;
        }
        run.tally.loose_records_found += 1;
        let bytes = read_at(source, hit, INSTANCE_BODY_AT + TEMPLATE_DEF_HEADER_SIZE + 4);
        let Some(def_offset) = u32_at(&bytes, INSTANCE_DEF_OFFSET_AT).map(|v| v as u64) else {
            run.tally.loose_records_unlocatable += 1;
            continue;
        };
        let inline_here = plausible_template_definition(&bytes, INSTANCE_BODY_AT)
            && def_offset >= CHUNK_HEADER_SIZE as u64
            && def_offset <= hit + INSTANCE_BODY_AT as u64;
        let base = if inline_here {
            Some(hit + INSTANCE_BODY_AT as u64 - def_offset)
        } else {
            grid_phase.and_then(|phase| {
                let rel = (hit + CHUNK_SIZE as u64 - phase) % CHUNK_SIZE as u64;
                let base = hit.checked_sub(rel)?;
                let probe = read_at(source, base + def_offset, TEMPLATE_DEF_HEADER_SIZE + 4);
                plausible_template_definition(&probe, 0).then_some(base)
            })
        };
        match base {
            Some(base) if base + (CHUNK_HEADER_SIZE as u64) <= hit => {
                windows.entry(base).or_default().push(hit);
                covered_until = base + CHUNK_SIZE as u64;
            }
            _ => {
                run.tally.loose_records_unlocatable += 1;
                let Some(head) = record_head(&bytes, 0) else {
                    // The scan accepted it from a longer read; a source that
                    // now returns short has nothing to say about it.
                    continue;
                };
                if run.record_bound_reached() {
                    return;
                }
                run.push(RecoveredRecord {
                    offset: hit,
                    size: head.size as u32,
                    chunk_offset: None,
                    source: RecoverySource::LooseRecord,
                    chunk_header: ChunkHeaderState::Synthetic,
                    header_checksum: ChecksumState::None,
                    data_checksum: ChecksumState::None,
                    chunk_truncated: false,
                    trailer_valid: false,
                    event_record_id: head.record_id,
                    timestamp: filetime_to_datetime(head.filetime),
                    template_id: u32_at(&bytes, INSTANCE_TEMPLATE_ID_AT),
                    substitution_count: None,
                    xml: None,
                    borrowed_template: None,
                    incomplete: Vec::new(),
                    own_decode_failure: None,
                    also_read_live: false,
                    containing_chunk_checksums: None,
                    failure: Some(format!(
                        "no chunk window could be inferred: the record's template is a \
                         back-reference to chunk offset {def_offset} and no chunk grid puts a \
                         template definition there"
                    )),
                });
            }
        }
    }

    for (base, hits) in windows {
        run.tally.loose_windows += 1;
        let len = CHUNK_SIZE.min((total.saturating_sub(base)) as usize);
        let mut data = read_at(source, base, len);
        // Bytes of this window that belong to a carved chunk are another
        // chunk's, not this one's.
        for (s, e) in spans {
            let start = s.saturating_sub(base) as usize;
            let end = e.saturating_sub(base) as usize;
            if *e > base && *s < base + len as u64 {
                poison(&mut data, start.min(len)..end.min(len));
            }
        }
        synthesise_header(&mut data);
        let first = hits.iter().min().copied().unwrap_or(base) - base;
        let heads = record_heads(&data, (first as usize).max(CHUNK_HEADER_SIZE), data.len());
        // Every record the walk found past the first hit is a loose record
        // the scan would have found too.
        run.tally.loose_records_found += heads.len().saturating_sub(hits.len()) as u64;
        let truncated = len < CHUNK_SIZE;
        let window_index = run.windows.len();
        run.windows.push(Window {
            offset: base,
            data,
            header: ChunkHeaderState::Synthetic,
            header_checksum: ChecksumState::None,
            data_checksum: ChecksumState::None,
            truncated,
            containing_chunk_checksums: None,
        });
        run.walk(
            window_index,
            &heads,
            RecoverySource::LooseRecord,
            Skip::Nothing,
        );
        if run.tally.records_bound_hit {
            return;
        }
    }
}
